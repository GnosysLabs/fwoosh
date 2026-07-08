//! Tauri IPC commands: the bridge between the Svelte UI and the Rust backend.
//!
//! State is held in `AppState` (managed by Tauri). Commands are async where
//! they touch the network (ntfy) or do non-trivial work.
//!
//! Design notes:
//! - The device keypairs + roster + history store live in `AppState`, created
//!   once at startup from the OS keychain.
//! - Sending a clip: seal_clip -> publish manifest + chunks (each <=3KB).
//! - Receiving: the ntfy subscriber task pushes decoded payloads here; we
//!   reassemble manifests + chunks, verify, decrypt, then emit a Tauri event
//!   the frontend listens to.

use crate::crypto::{self, DeviceKeypairs, StorePolicy};
use crate::ntfy::{self, RelayMessage};
use crate::roster::{self, VerifiedRoster};
use crate::store::{HistoryClip, HistoryStore};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{Emitter, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_notification::NotificationExt;
use tokio::sync::Mutex;

const PAIRING_SECRET_TTL_SECS: u64 = 10 * 60;
const MAX_RECOMMENDED_BYTES: usize = 100_000;
const MAX_INBOUND_CHUNKS: u32 = 64;
const MAX_PENDING_CLIPS: usize = 128;
const ROSTER_MOVE_PREFIX: &str = "fwoosh-roster-move-v1:";
const DELETE_SIG_DOMAIN: &[u8] = b"Fwoosh delete v1";

/// App-wide shared state.
pub struct AppState {
    pub device: DeviceKeypairs,
    pub store: HistoryStore,
    /// The current verified roster (None until the device joins/creates a room).
    pub roster: Mutex<Option<VerifiedRoster>>,
    /// ntfy base URL (default public relay; configurable).
    pub ntfy_base: Mutex<String>,
    /// In-flight partial clips keyed by msg_id: (manifest, received chunks).
    pub pending: Mutex<HashMap<[u8; 16], PendingClip>>,
    /// Last ntfy message id per topic, for `since=` catch-up.
    pub last_msg_ids: Mutex<HashMap<String, String>>,
    /// Handle to the subscriber task (so we can shut it down on topic change).
    pub subscriber_shutdown: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// A pending join: (topic, admin_pub) trusted from a pairing URI, until the
    /// admin's signed genesis roster arrives and is verified.
    pub pending_admin: Mutex<Option<(String, crate::crypto::Ed25519PubKey)>>,
    /// The admin's one-time pairing secret (set on create_room). Used to verify
    /// incoming JoinRequest proofs. Cleared after first use (single-use).
    pub pairing_secret: Mutex<Option<PendingPairingSecret>>,
    /// Path to the persisted roster file (set at startup).
    pub roster_path: Mutex<Option<std::path::PathBuf>>,
}

/// A partially-received clip awaiting all its chunks.
pub struct PendingClip {
    manifest: crypto::Manifest,
    chunks: Vec<Option<crypto::Chunk>>,
}

pub struct PendingPairingSecret {
    secret: [u8; 32],
    expires_at: u64,
}

impl AppState {
    pub fn new(device: DeviceKeypairs, store: HistoryStore) -> Self {
        Self {
            device,
            store,
            roster: Mutex::new(None),
            ntfy_base: Mutex::new(ntfy::DEFAULT_BASE.to_string()),
            pending: Mutex::new(HashMap::new()),
            last_msg_ids: Mutex::new(HashMap::new()),
            subscriber_shutdown: Mutex::new(None),
            pending_admin: Mutex::new(None),
            pairing_secret: Mutex::new(None),
            roster_path: Mutex::new(None),
        }
    }
}

// ---- Wire message kinds (postcard-encoded, then base64 by ntfy.rs) ----

/// A message published to the relay. Either a clip manifest, a chunk, a
/// roster epoch broadcast, or a join request. Distinguished by a tag byte.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub enum WireMessage {
    /// Tag 0: a clip manifest (published first).
    Manifest(crypto::Manifest),
    /// Tag 1: a clip chunk (references msg_id).
    Chunk(crypto::Chunk),
    /// Tag 2: a roster epoch broadcast (signed, tamper-evident).
    Roster(roster::RosterEntry),
    /// Tag 3: a device proving knowledge of the pairing secret and asking to join.
    JoinRequest(crate::pairing::JoinRequest),
    /// Tag 4: a signed request to delete a history row for a clip message.
    DeleteClip(DeleteClipMessage),
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct DeleteClipMessage {
    pub msg_id: [u8; 16],
    pub room_id: String,
    pub roster_epoch: u64,
    pub sender_id: crypto::Ed25519PubKey,
    pub ts: u64,
    pub signature: Vec<u8>,
}

#[derive(serde::Serialize)]
struct DeleteClipForSigning<'a> {
    msg_id: &'a [u8; 16],
    room_id: &'a str,
    roster_epoch: u64,
    sender_id: &'a crypto::Ed25519PubKey,
    ts: u64,
}

fn delete_clip_signing_bytes(msg: &DeleteClipMessage) -> Vec<u8> {
    let view = DeleteClipForSigning {
        msg_id: &msg.msg_id,
        room_id: &msg.room_id,
        roster_epoch: msg.roster_epoch,
        sender_id: &msg.sender_id,
        ts: msg.ts,
    };
    let mut buf = DELETE_SIG_DOMAIN.to_vec();
    buf.extend_from_slice(&postcard::to_allocvec(&view).expect("postcard encode delete message"));
    buf
}

fn sign_delete_clip(
    device: &DeviceKeypairs,
    msg_id: [u8; 16],
    room_id: String,
    roster_epoch: u64,
    ts: u64,
) -> DeleteClipMessage {
    let mut msg = DeleteClipMessage {
        msg_id,
        room_id,
        roster_epoch,
        sender_id: device.signing_pub.clone(),
        ts,
        signature: Vec::new(),
    };
    let bytes = delete_clip_signing_bytes(&msg);
    msg.signature = device.signing.sign(&bytes).to_bytes().to_vec();
    msg
}

fn verify_delete_clip_sig(msg: &DeleteClipMessage) -> Result<(), String> {
    let vk = VerifyingKey::from_bytes(&msg.sender_id.0)
        .map_err(|_| "bad delete sender key".to_string())?;
    let sig =
        Signature::from_slice(&msg.signature).map_err(|_| "bad delete signature".to_string())?;
    vk.verify(&delete_clip_signing_bytes(msg), &sig)
        .map_err(|_| "delete signature verification failed".to_string())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// =========================================================================
//  Commands callable from the frontend
// =========================================================================

/// Returns the device's identity (Ed25519 pubkey hex + label) for display.
#[tauri::command]
pub fn device_identity(state: State<'_, Arc<AppState>>) -> String {
    hex::encode(state.device.signing_pub.0)
}

/// Returns whether the device is currently in a room (roster loaded) + the
/// member count, so the frontend can show the right UI on startup.
#[derive(serde::Serialize)]
pub struct RoomState {
    pub in_room: bool,
    pub member_count: usize,
    pub topic: String,
}

#[derive(serde::Serialize)]
pub struct DeviceDto {
    pub id: String,
    pub label: String,
    pub is_self: bool,
    pub is_admin: bool,
    pub can_revoke: bool,
}

#[tauri::command]
pub async fn room_state(state: State<'_, Arc<AppState>>) -> Result<RoomState, String> {
    let guard = state.roster.lock().await;
    match guard.as_ref() {
        Some(v) => Ok(RoomState {
            in_room: true,
            member_count: v.entry.devices.len(),
            topic: v.topic().to_string(),
        }),
        None => Ok(RoomState {
            in_room: false,
            member_count: 0,
            topic: String::new(),
        }),
    }
}

#[tauri::command]
pub async fn roster_devices(state: State<'_, Arc<AppState>>) -> Result<Vec<DeviceDto>, String> {
    let guard = state.roster.lock().await;
    let verified = guard.as_ref().ok_or("not in a room")?;
    let am_admin = state.device.signing_pub == verified.entry.admin_id;
    Ok(verified
        .entry
        .devices
        .iter()
        .map(|d| {
            let is_self = d.signing_pub == state.device.signing_pub;
            let is_admin = d.signing_pub == verified.entry.admin_id;
            DeviceDto {
                id: hex::encode(d.signing_pub.0),
                label: d.label.clone(),
                is_self,
                is_admin,
                can_revoke: am_admin && !is_self && !is_admin,
            }
        })
        .collect())
}

/// Create a new room: generate topic + genesis roster epoch (this device is
/// admin). Returns the pairing URI for other devices.
#[tauri::command]
pub async fn create_room(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    label: String,
) -> Result<String, String> {
    let topic = roster::new_topic();
    let genesis = roster::build_genesis(&state.device, &label, &topic);
    let signed = roster::sign_and_chain(&state.device, genesis, None).map_err(|e| e.to_string())?;
    let verified = VerifiedRoster::verify_first(signed.clone()).map_err(|e| e.to_string())?;
    *state.roster.lock().await = Some(verified);
    persist_roster(&state, &signed).await;

    // Spawn the subscriber so we receive clips + join requests from others.
    start_subscriber(&state, app.clone(), &topic).await;

    // Broadcast the genesis roster so joiners can adopt it.
    eprintln!("[room] created room, broadcasting genesis roster");
    broadcast_roster(&state, &signed, &topic).await;

    // Generate the one-time pairing secret. Stored so we can verify join proofs.
    let secret = crate::pairing::random_secret();
    *state.pairing_secret.lock().await = Some(PendingPairingSecret {
        secret,
        expires_at: now_unix() + PAIRING_SECRET_TTL_SECS,
    });
    let uri = crate::pairing::build_uri(&topic, &state.device.signing_pub, &secret);
    Ok(uri)
}

#[tauri::command]
pub async fn new_pairing_code(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    let guard = state.roster.lock().await;
    let verified = guard.as_ref().ok_or("not in a room")?;
    if state.device.signing_pub != verified.entry.admin_id {
        return Err("only the room admin can create pairing codes".to_string());
    }
    let topic = verified.topic().to_string();
    drop(guard);

    let secret = crate::pairing::random_secret();
    *state.pairing_secret.lock().await = Some(PendingPairingSecret {
        secret,
        expires_at: now_unix() + PAIRING_SECRET_TTL_SECS,
    });
    Ok(crate::pairing::build_uri(
        &topic,
        &state.device.signing_pub,
        &secret,
    ))
}

/// Spawn (or replace) the ntfy subscriber for the given topic. Messages are
/// reassembled + verified + decrypted via `handle_relay_message`.
pub async fn start_subscriber(state: &Arc<AppState>, app: tauri::AppHandle, topic: &str) {
    // Shut down any existing subscriber (e.g. on topic rotation).
    if let Some(tx) = state.subscriber_shutdown.lock().await.take() {
        let _ = tx.send(());
    }

    let base = state.ntfy_base.lock().await.clone();
    let since = state.last_msg_ids.lock().await.get(topic).cloned();
    let cfg = ntfy::SubscribeConfig {
        base,
        topic: topic.to_string(),
        since,
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ntfy::RelayMessage>(64);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    ntfy::spawn_subscriber(cfg, tx, shutdown_rx);

    // Pump received messages into handle_relay_message, capturing the app
    // handle + state for the task.
    let state_clone = state.clone();
    let app_clone = app.clone();
    let topic_for_cursor = topic.to_string();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if !msg.payload.is_empty() {
                state_clone
                    .last_msg_ids
                    .lock()
                    .await
                    .insert(topic_for_cursor.clone(), msg.id.clone());
                handle_relay_message(&state_clone, &app_clone, msg).await;
            }
        }
    });

    *state.subscriber_shutdown.lock().await = Some(shutdown_tx);
}

fn schedule_subscriber_switch(state: &Arc<AppState>, app: &tauri::AppHandle, topic: String) {
    let state_clone = state.clone();
    let app_clone = app.clone();
    tokio::spawn(async move {
        start_subscriber(&state_clone, app_clone, &topic).await;
    });
}

/// Broadcast a roster entry to the relay so other devices can adopt/update.
async fn broadcast_roster(state: &Arc<AppState>, entry: &roster::RosterEntry, topic: &str) {
    let msg = match postcard::to_allocvec(&WireMessage::Roster(entry.clone())) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("failed to encode roster: {e}");
            return;
        }
    };
    let base = state.ntfy_base.lock().await.clone();
    if let Err(e) = ntfy::publish(&base, topic, &msg, "roster").await {
        eprintln!("failed to broadcast roster: {e}");
    }
}

/// Persist the current roster entry to disk so it survives restarts.
async fn persist_roster(state: &Arc<AppState>, entry: &roster::RosterEntry) {
    if let Some(path) = state.roster_path.lock().await.clone() {
        match postcard::to_allocvec(entry) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(&path, &bytes) {
                    eprintln!("failed to persist roster: {e}");
                }
            }
            Err(e) => eprintln!("failed to encode roster for persistence: {e}"),
        }
    }
}

/// Load a persisted roster from disk (called at startup).
pub fn load_persisted_roster(path: &std::path::Path) -> Option<roster::RosterEntry> {
    let bytes = std::fs::read(path).ok()?;
    postcard::from_bytes(&bytes).ok()
}

/// Leave the current room: clear the in-memory roster, stop the subscriber,
/// delete the persisted roster file. The frontend then shows create/join again.
#[tauri::command]
pub async fn leave_room(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    // Stop the subscriber.
    if let Some(tx) = state.subscriber_shutdown.lock().await.take() {
        let _ = tx.send(());
    }
    // Clear in-memory state.
    *state.roster.lock().await = None;
    *state.pending_admin.lock().await = None;
    *state.pairing_secret.lock().await = None;
    state.last_msg_ids.lock().await.clear();
    state.pending.lock().await.clear();
    // Delete the persisted roster so restart doesn't rejoin.
    if let Some(path) = state.roster_path.lock().await.clone() {
        let _ = std::fs::remove_file(&path);
    }
    Ok(())
}

/// Join an existing room from a pairing URI. Parses the URI, subscribes to the
/// topic, and announces our identity to the admin via a JoinRequest. The admin
/// will then add us to the roster and broadcast the updated signed epoch.
#[tauri::command]
pub async fn join_room(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    uri: String,
    label: String,
) -> Result<(), String> {
    let invite = crate::pairing::parse_uri(&uri).map_err(|e| e.to_string())?;
    // Record the trusted admin identity so we can verify the genesis entry when
    // it arrives over the relay.
    *state.pending_admin.lock().await = Some((invite.topic.clone(), invite.admin_pub.clone()));
    start_subscriber(&state, app.clone(), &invite.topic).await;

    eprintln!("[room] joined topic, publishing JoinRequest");
    // Announce our identity to the admin. The admin adds us to a new roster
    // epoch and broadcasts it back after verifying proof-of-knowledge for the
    // one-time secret embedded in the pairing URI.
    let my_identity = roster::DeviceIdentity::from_keypairs(&state.device, &label);
    let join_req = crate::pairing::build_join_request(my_identity, &invite.secret);
    let join_msg =
        postcard::to_allocvec(&WireMessage::JoinRequest(join_req)).map_err(|e| e.to_string())?;
    let base = state.ntfy_base.lock().await.clone();
    ntfy::publish(&base, &invite.topic, &join_msg, "join")
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

async fn publish_wire(
    base: &str,
    topic: &str,
    wire: WireMessage,
    title: &str,
) -> Result<(), String> {
    let msg = postcard::to_allocvec(&wire).map_err(|e| e.to_string())?;
    ntfy::publish(base, topic, &msg, title)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

async fn publish_sealed_clip(
    base: &str,
    topic: &str,
    sealed: crypto::SealedClip,
) -> Result<(), String> {
    publish_wire(base, topic, WireMessage::Manifest(sealed.manifest), "clip").await?;
    for chunk in sealed.chunks {
        publish_wire(base, topic, WireMessage::Chunk(chunk), "clip").await?;
    }
    Ok(())
}

/// Send a clip to all devices in the current roster. Manual-send only (no auto
/// clipboard monitoring in MVP). `private` = sync once, don't store.
#[tauri::command]
pub async fn send_clip(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    text: String,
    private: bool,
) -> Result<(), String> {
    let guard = state.roster.lock().await;
    let verified = guard.as_ref().ok_or("not in a room")?;
    let recipients = verified.recipients();
    let epoch = verified.epoch();
    let topic = verified.topic().to_string();
    drop(guard);

    // Max-size guard: warn (don't hard-block) on very large clips. The chunking
    // handles it, but huge clips eat the daily ntfy quota fast.
    if text.len() > MAX_RECOMMENDED_BYTES {
        return Err(format!(
            "Clip is {} KB — that's a lot to sync over the free relay. Trim it or use a self-hosted server.",
            text.len() / 1024
        ));
    }

    let policy = if private {
        StorePolicy::Private
    } else {
        StorePolicy::History
    };
    let now = now_unix();

    let sealed = crypto::seal_clip(
        &state.device,
        &recipients,
        &text,
        &topic,
        epoch,
        policy,
        now,
    )
    .map_err(|e| e.to_string())?;

    let msg_id = sealed.manifest.msg_id;
    let base = state.ntfy_base.lock().await.clone();
    publish_sealed_clip(&base, &topic, sealed).await?;

    // Also store locally (history) unless private.
    if !private {
        state
            .store
            .insert_with_msg_id(&state.device.signing_pub, now, &text, Some(&msg_id))
            .map_err(|e| e.to_string())?;
        let _ = app.emit("clip-stored", ());
    }
    Ok(())
}

#[tauri::command]
pub async fn revoke_device(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    device_id: String,
) -> Result<(), String> {
    let decoded = hex::decode(device_id.trim()).map_err(|_| "bad device id".to_string())?;
    if decoded.len() != 32 {
        return Err("bad device id".to_string());
    }
    let mut victim = [0u8; 32];
    victim.copy_from_slice(&decoded);
    let victim = crypto::Ed25519PubKey(victim);

    let verified = state.roster.lock().await.clone().ok_or("not in a room")?;
    if state.device.signing_pub != verified.entry.admin_id {
        return Err("only the room admin can revoke devices".to_string());
    }
    if victim == state.device.signing_pub {
        return Err("cannot revoke this device".to_string());
    }

    let old_topic = verified.topic().to_string();
    let new_topic = roster::new_topic();
    let unsigned = roster::build_revoke_device(&verified.entry, &victim, &new_topic)
        .map_err(|e| e.to_string())?;
    let signed = roster::sign_and_chain(&state.device, unsigned, Some(&verified.entry))
        .map_err(|e| e.to_string())?;
    let next = verified
        .verify_next(signed.clone())
        .map_err(|e| e.to_string())?;

    let move_text = encode_roster_move(&signed)?;
    let recipients = next.recipients();
    let sealed = crypto::seal_clip(
        &state.device,
        &recipients,
        &move_text,
        &old_topic,
        verified.epoch(),
        StorePolicy::Private,
        now_unix(),
    )
    .map_err(|e| e.to_string())?;

    let base = state.ntfy_base.lock().await.clone();
    publish_sealed_clip(&base, &old_topic, sealed).await?;

    *state.roster.lock().await = Some(next);
    state.pending.lock().await.clear();
    persist_roster(&state, &signed).await;
    start_subscriber(&state, app.clone(), &new_topic).await;
    broadcast_roster(&state, &signed, &new_topic).await;
    let _ = app.emit("roster-updated", ());
    Ok(())
}

/// Get the most recent N clips from local history.
#[tauri::command]
pub fn recent_clips(
    state: State<'_, Arc<AppState>>,
    limit: Option<i64>,
) -> Result<Vec<ClipDto>, String> {
    let clips = state
        .store
        .recent(limit.unwrap_or(50))
        .map_err(|e| e.to_string())?;
    Ok(clips.into_iter().map(ClipDto::from).collect())
}

/// Search local history.
#[tauri::command]
pub fn search_clips(
    state: State<'_, Arc<AppState>>,
    query: String,
) -> Result<Vec<ClipDto>, String> {
    let clips = state
        .store
        .search(&query, 50_i64)
        .map_err(|e| e.to_string())?;
    Ok(clips.into_iter().map(ClipDto::from).collect())
}

/// Delete a clip from local history by id, and ask paired devices to remove
/// their matching history row when this row is tied to a relay message id.
#[tauri::command]
pub async fn delete_clip(state: State<'_, Arc<AppState>>, id: i64) -> Result<(), String> {
    let msg_id = state.store.msg_id_for_clip(id).map_err(|e| e.to_string())?;

    if let Some(msg_id) = msg_id {
        let room = {
            let guard = state.roster.lock().await;
            guard
                .as_ref()
                .map(|verified| (verified.topic().to_string(), verified.epoch()))
        };
        if let Some((topic, epoch)) = room {
            let delete_msg =
                sign_delete_clip(&state.device, msg_id, topic.clone(), epoch, now_unix());
            let base = state.ntfy_base.lock().await.clone();
            publish_wire(&base, &topic, WireMessage::DeleteClip(delete_msg), "delete").await?;
        }
    }

    state.store.delete(id).map_err(|e| e.to_string())
}

/// Delete all clips from local history, broadcasting per-clip delete messages
/// for rows that can be matched on paired devices.
#[tauri::command]
pub async fn delete_all_clips(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let msg_ids = state.store.all_msg_ids().map_err(|e| e.to_string())?;
    let room = {
        let guard = state.roster.lock().await;
        guard
            .as_ref()
            .map(|verified| (verified.topic().to_string(), verified.epoch()))
    };

    if let Some((topic, epoch)) = room {
        let base = state.ntfy_base.lock().await.clone();
        for msg_id in msg_ids {
            let delete_msg =
                sign_delete_clip(&state.device, msg_id, topic.clone(), epoch, now_unix());
            publish_wire(&base, &topic, WireMessage::DeleteClip(delete_msg), "delete").await?;
        }
    }

    state.store.delete_all().map_err(|e| e.to_string())?;
    let _ = app.emit("clip-stored", ());
    Ok(())
}

pub fn reveal_main_window(app: &tauri::AppHandle) -> Result<(), String> {
    let win = app
        .get_webview_window("main")
        .ok_or_else(|| "main window not found".to_string())?;

    let _ = win.unminimize();
    win.show().map_err(|e| e.to_string())?;
    win.set_focus().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn show_main_window(app: tauri::AppHandle) -> Result<(), String> {
    reveal_main_window(&app)
}

#[tauri::command]
pub fn notify_incoming_clip(
    app: tauri::AppHandle,
    sender: String,
    preview: String,
) -> Result<(), String> {
    app.notification()
        .builder()
        .title("Fwoosh")
        .body(format!("{sender}: {preview}\nOpen Fwoosh to copy"))
        .show()
        .map_err(|e| e.to_string())
}

/// A clip DTO for the frontend (no raw key bytes; sender shown as short hex).
#[derive(serde::Serialize)]
pub struct ClipDto {
    pub id: i64,
    pub sender: String,
    pub ts: u64,
    pub text: String,
}

impl From<HistoryClip> for ClipDto {
    fn from(c: HistoryClip) -> Self {
        Self {
            id: c.id,
            sender: hex::encode(&c.sender_id.0[..4]),
            ts: c.ts,
            text: c.text,
        }
    }
}

/// Process an incoming relay message: reassemble manifest+chunks, verify,
/// decrypt, emit a Tauri event. Called from the subscriber pump.
pub async fn handle_relay_message(
    state: &Arc<AppState>,
    app: &tauri::AppHandle,
    msg: RelayMessage,
) {
    let wire: WireMessage = match postcard::from_bytes(&msg.payload) {
        Ok(w) => {
            eprintln!("[relay] decoded wire message ({} bytes)", msg.payload.len());
            w
        }
        Err(e) => {
            eprintln!(
                "[relay] failed to decode wire message: {e} ({} bytes)",
                msg.payload.len()
            );
            return;
        }
    };
    match wire {
        WireMessage::Manifest(manifest) => {
            if manifest.chunk_count == 0
                || manifest.chunk_count > MAX_INBOUND_CHUNKS
                || manifest.declared_size > MAX_RECOMMENDED_BYTES as u64
            {
                eprintln!(
                    "[relay] rejecting manifest with unsafe size/count: {} bytes, {} chunks",
                    manifest.declared_size, manifest.chunk_count
                );
                return;
            }
            match state.store.has_seen_message(&manifest.msg_id) {
                Ok(true) => return,
                Ok(false) => {}
                Err(e) => {
                    eprintln!("[relay] replay cache check failed: {e}");
                    return;
                }
            }
            let mut pending = state.pending.lock().await;
            if pending.len() >= MAX_PENDING_CLIPS {
                eprintln!("[relay] rejecting manifest: too many pending clips");
                return;
            }
            pending.insert(
                manifest.msg_id,
                PendingClip {
                    chunks: vec![None; manifest.chunk_count as usize],
                    manifest,
                },
            );
        }
        WireMessage::Chunk(chunk) => {
            // Insert under the lock; if complete, extract the full clip and
            // drop the lock BEFORE calling try_open_clip (which re-locks).
            let completed = {
                let mut pending = state.pending.lock().await;
                let p = match pending.get_mut(&chunk.msg_id) {
                    Some(p) => p,
                    None => return,
                };
                let idx = chunk.index as usize;
                if idx < p.chunks.len() {
                    p.chunks[idx] = Some(chunk);
                }
                if p.chunks.iter().all(|c| c.is_some()) {
                    let manifest = p.manifest.clone();
                    let chunks: Vec<crypto::Chunk> =
                        p.chunks.iter().cloned().map(Option::unwrap).collect();
                    pending.remove(&manifest.msg_id);
                    Some((manifest, chunks))
                } else {
                    None
                }
            };
            if let Some((manifest, chunks)) = completed {
                try_open_clip(state, app, manifest, chunks).await;
            }
        }
        WireMessage::JoinRequest(req) => {
            let identity = req.identity.clone();
            eprintln!(
                "[relay] JoinRequest from {} ({})",
                identity.label,
                hex::encode(&identity.signing_pub.0[..4])
            );
            // Only the admin handles join requests (it's the only one that can
            // sign new roster epochs). Gate on a valid, unexpired one-time
            // pairing secret and consume it only after a valid proof.
            {
                let mut secret_guard = state.pairing_secret.lock().await;
                let Some(pending_secret) = secret_guard.as_ref() else {
                    eprintln!("[relay] not the admin or no active pairing secret, ignoring join");
                    return;
                };
                if pending_secret.expires_at < now_unix() {
                    eprintln!("[relay] pairing secret expired, ignoring join");
                    *secret_guard = None;
                    return;
                }
                if let Err(e) = crate::pairing::verify_join_request(&req, &pending_secret.secret) {
                    eprintln!("[relay] join proof rejected: {e}");
                    return;
                }
                *secret_guard = None;
            }

            let current = state.roster.lock().await.clone();
            let verified = match current {
                Some(v) => v,
                None => return, // admin somehow has no roster
            };

            // Don't re-add a device already in the roster.
            if verified
                .entry
                .devices
                .iter()
                .any(|d| d.signing_pub == identity.signing_pub)
            {
                return;
            }

            // Build + sign a new epoch adding this device, then broadcast it.
            let unsigned = roster::build_add_device(&verified.entry, identity);
            match roster::sign_and_chain(&state.device, unsigned, Some(&verified.entry)) {
                Ok(signed) => match verified.verify_next(signed.clone()) {
                    Ok(next) => {
                        let topic = next.topic().to_string();
                        *state.roster.lock().await = Some(next);
                        persist_roster(state, &signed).await;
                        broadcast_roster(state, &signed, &topic).await;
                        let _ = app.emit("roster-updated", ());
                    }
                    Err(e) => eprintln!("roster verify_next failed: {e}"),
                },
                Err(e) => eprintln!("roster sign failed: {e}"),
            }
        }
        WireMessage::DeleteClip(msg) => {
            handle_delete_clip(state, app, msg).await;
        }
        WireMessage::Roster(entry) => {
            eprintln!(
                "[relay] Roster epoch {} ({} devices)",
                entry.epoch,
                entry.devices.len()
            );
            let current = state.roster.lock().await.clone();
            match current {
                Some(prev) => {
                    // Normal update: only accept strictly newer epochs.
                    if entry.epoch > prev.epoch() {
                        let old_topic = prev.topic().to_string();
                        match prev.verify_next(entry.clone()) {
                            Ok(next) => {
                                let new_topic = next.topic().to_string();
                                *state.roster.lock().await = Some(next);
                                persist_roster(state, &entry).await;
                                if new_topic != old_topic {
                                    state.pending.lock().await.clear();
                                    schedule_subscriber_switch(state, app, new_topic);
                                }
                                let _ = app.emit("roster-updated", ());
                            }
                            Err(e) => eprintln!("roster update rejected: {e}"),
                        }
                    }
                }
                None => {
                    // Joiner path: we have no roster yet. We missed the genesis
                    // broadcast (we joined after it was sent), so we accept ANY
                    // roster epoch signed by the admin we trust from the pairing
                    // URI. The signature proves authenticity; the epoch number
                    // doesn't matter for first adoption. We can't chain-verify
                    // (we don't have the previous entry), but the admin's
                    // Ed25519 signature is the trust root.
                    let pending = state.pending_admin.lock().await.clone();
                    if let Some((topic, admin_pub)) = pending {
                        if entry.topic != topic {
                            eprintln!("[relay] roster topic doesn't match pairing; ignoring");
                            return;
                        }
                        if entry.admin_id == admin_pub {
                            if !entry
                                .devices
                                .iter()
                                .any(|d| d.signing_pub == state.device.signing_pub)
                            {
                                eprintln!(
                                    "[relay] roster does not include this device yet; ignoring"
                                );
                                return;
                            }
                            // Verify the signature is valid for this entry.
                            match roster::verify_entry_sig_only(&entry) {
                                Ok(()) => {
                                    eprintln!(
                                        "[relay] adopting roster epoch {} from admin",
                                        entry.epoch
                                    );
                                    let verified = VerifiedRoster::from_entry(entry.clone());
                                    *state.roster.lock().await = Some(verified);
                                    *state.pending_admin.lock().await = None;
                                    persist_roster(state, &entry).await;
                                    let _ = app.emit("roster-updated", ());
                                }
                                Err(e) => eprintln!("[relay] roster signature rejected: {e}"),
                            }
                        } else {
                            eprintln!("[relay] roster admin doesn't match pairing; ignoring");
                        }
                    } else {
                        eprintln!("[relay] got roster but no pending admin; ignoring");
                    }
                }
            }
        }
    }
}

async fn handle_delete_clip(state: &Arc<AppState>, app: &tauri::AppHandle, msg: DeleteClipMessage) {
    let roster_guard = state.roster.lock().await;
    let verified = match roster_guard.as_ref() {
        Some(v) => v,
        None => return,
    };
    if msg.room_id != verified.topic() || msg.roster_epoch != verified.epoch() {
        eprintln!("[relay] delete rejected: room or epoch mismatch");
        return;
    }
    if !verified.is_active(&msg.sender_id) {
        eprintln!("[relay] delete rejected: sender is not active");
        return;
    }
    drop(roster_guard);

    if let Err(e) = verify_delete_clip_sig(&msg) {
        eprintln!("[relay] delete rejected: {e}");
        return;
    }

    match state.store.delete_by_msg_id(&msg.msg_id) {
        Ok(changed) => {
            if changed > 0 {
                let _ = app.emit("clip-stored", ());
            }
        }
        Err(e) => eprintln!("[relay] delete failed: {e}"),
    }
}

/// Attempt to verify + decrypt a complete clip, then emit + store.
async fn try_open_clip(
    state: &Arc<AppState>,
    app: &tauri::AppHandle,
    manifest: crypto::Manifest,
    chunks: Vec<crypto::Chunk>,
) {
    let roster_guard = state.roster.lock().await;
    let verified = match roster_guard.as_ref() {
        Some(v) => v,
        None => return,
    };
    let current_epoch = verified.epoch();
    let current_topic = verified.topic().to_string();
    let admin_id = verified.entry.admin_id.clone();
    // Snapshot the active-member check.
    let active: Vec<crypto::Ed25519PubKey> = verified
        .entry
        .devices
        .iter()
        .map(|d| d.signing_pub.clone())
        .collect();
    drop(roster_guard);

    let my_id = state.device.signing_pub.clone();
    // Skip our own echoed messages (the subscriber receives what we publish).
    if manifest.sender_id == my_id {
        return;
    }
    if manifest.room_id != current_topic {
        eprintln!("clip open failed: envelope topic does not match current roster");
        return;
    }
    match state.store.has_seen_message(&manifest.msg_id) {
        Ok(true) => return,
        Ok(false) => {}
        Err(e) => {
            eprintln!("clip open failed: replay cache check failed: {e}");
            return;
        }
    }
    let opened = crypto::open_clip(&manifest, &chunks, &state.device, current_epoch, |id, _| {
        active.contains(id)
    });

    match opened {
        Ok(o) => {
            if let Err(e) = state.store.mark_seen_message(&manifest.msg_id, o.ts) {
                eprintln!("clip open failed: replay cache update failed: {e}");
                return;
            }
            match decode_roster_move(&o.plaintext) {
                Ok(Some(entry)) => {
                    if o.sender_id != admin_id {
                        eprintln!("roster move rejected: sender is not admin");
                        return;
                    }
                    if let Err(e) = apply_roster_update(state, app, entry, true).await {
                        eprintln!("roster move rejected: {e}");
                    }
                    return;
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("roster move decode failed: {e}");
                    return;
                }
            }
            // Default inbound = toast + click-to-copy (NOT auto-copy).
            let _ = app.emit(
                "clip-received",
                serde_json::json!({
                    "sender": hex::encode(&o.sender_id.0[..4]),
                    "preview": preview(&o.plaintext),
                    "text": o.plaintext,
                    "ts": o.ts,
                }),
            );
            // Persist to history unless the sender marked it Private.
            if o.store_policy == StorePolicy::History {
                let _ = state.store.insert_with_msg_id(
                    &o.sender_id,
                    o.ts,
                    &o.plaintext,
                    Some(&manifest.msg_id),
                );
                let _ = app.emit("clip-stored", ());
            }
        }
        Err(e) => {
            eprintln!("clip open failed: {e}");
        }
    }

    // Remove from pending regardless.
    state.pending.lock().await.remove(&manifest.msg_id);
}

fn preview(s: &str) -> String {
    let s = s.replace('\n', " ");
    if s.len() > 80 {
        format!(
            "{}…",
            &s[..s
                .char_indices()
                .take(80)
                .last()
                .map(|(i, c)| i + c.len_utf8())
                .unwrap_or(80)]
        )
    } else {
        s.to_string()
    }
}

fn encode_roster_move(entry: &roster::RosterEntry) -> Result<String, String> {
    let bytes = postcard::to_allocvec(entry).map_err(|e| e.to_string())?;
    Ok(format!(
        "{}{}",
        ROSTER_MOVE_PREFIX,
        base64::engine::general_purpose::STANDARD.encode(bytes)
    ))
}

fn decode_roster_move(text: &str) -> Result<Option<roster::RosterEntry>, String> {
    let Some(b64) = text.strip_prefix(ROSTER_MOVE_PREFIX) else {
        return Ok(None);
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| e.to_string())?;
    let entry = postcard::from_bytes(&bytes).map_err(|e| e.to_string())?;
    Ok(Some(entry))
}

async fn apply_roster_update(
    state: &Arc<AppState>,
    app: &tauri::AppHandle,
    entry: roster::RosterEntry,
    republish_on_new_topic: bool,
) -> Result<(), String> {
    let current = state.roster.lock().await.clone().ok_or("not in a room")?;
    if entry.epoch <= current.epoch() {
        return Ok(());
    }
    let old_topic = current.topic().to_string();
    let next = current
        .verify_next(entry.clone())
        .map_err(|e| e.to_string())?;
    let new_topic = next.topic().to_string();

    *state.roster.lock().await = Some(next);
    persist_roster(state, &entry).await;
    if new_topic != old_topic {
        state.pending.lock().await.clear();
        schedule_subscriber_switch(state, app, new_topic.clone());
    }
    if republish_on_new_topic {
        broadcast_roster(state, &entry, &new_topic).await;
    }
    let _ = app.emit("roster-updated", ());
    Ok(())
}

/// Copy text to the system clipboard (called from frontend on click-to-copy).
#[tauri::command]
pub async fn copy_to_clipboard(app: tauri::AppHandle, text: String) -> Result<(), String> {
    app.clipboard().write_text(text).map_err(|e| e.to_string())
}

/// History DB path helper (kept for external/test use; the main app inlines
/// the same computation in lib.rs setup).
pub fn history_db_path(app: &tauri::AppHandle) -> PathBuf {
    let dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| std::env::temp_dir());
    let _ = std::fs::create_dir_all(&dir);
    dir.join("history.db")
}
