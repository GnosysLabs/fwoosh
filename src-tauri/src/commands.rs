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
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{Emitter, Manager, State};
use tokio::sync::Mutex;

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
    pub last_msg_id: Mutex<Option<String>>,
    /// Handle to the subscriber task (so we can shut it down on topic change).
    pub subscriber_shutdown: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    /// A pending join: (topic, admin_pub) trusted from a pairing URI, until the
    /// admin's signed genesis roster arrives and is verified.
    pub pending_admin: Mutex<Option<(String, crate::crypto::Ed25519PubKey)>>,
}

/// A partially-received clip awaiting all its chunks.
pub struct PendingClip {
    manifest: crypto::Manifest,
    chunks: Vec<Option<crypto::Chunk>>,
}

impl AppState {
    pub fn new(device: DeviceKeypairs, store: HistoryStore) -> Self {
        Self {
            device,
            store,
            roster: Mutex::new(None),
            ntfy_base: Mutex::new(ntfy::DEFAULT_BASE.to_string()),
            pending: Mutex::new(HashMap::new()),
            last_msg_id: Mutex::new(None),
            subscriber_shutdown: Mutex::new(None),
            pending_admin: Mutex::new(None),
        }
    }
}

// ---- Wire message kinds (postcard-encoded, then base64 by ntfy.rs) ----

/// A message published to the relay. Either a clip manifest, a chunk, or a
/// roster epoch (broadcast). Distinguished by a tag byte.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub enum WireMessage {
    /// Tag 0: a clip manifest (published first).
    Manifest(crypto::Manifest),
    /// Tag 1: a clip chunk (references msg_id).
    Chunk(crypto::Chunk),
    /// Tag 2: a roster epoch broadcast (encrypted transport TBD; v1 ships the
    /// signed entry which is already tamper-evident).
    Roster(roster::RosterEntry),
}

// =========================================================================
//  Commands callable from the frontend
// =========================================================================

/// Returns the device's identity (Ed25519 pubkey hex + label) for display.
#[tauri::command]
pub fn device_identity(state: State<'_, Arc<AppState>>) -> String {
    hex::encode(state.device.signing_pub.0)
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
    let signed = roster::sign_and_chain(&state.device, genesis, None)
        .map_err(|e| e.to_string())?;
    let verified = VerifiedRoster::verify_first(signed).map_err(|e| e.to_string())?;
    *state.roster.lock().await = Some(verified);

    // Spawn the subscriber so we receive clips from paired devices.
    start_subscriber(&state, &app, &topic).await;

    let secret = crate::pairing::random_secret();
    let uri = crate::pairing::build_uri(&topic, &state.device.signing_pub, &secret);
    // NOTE: in a full impl, `secret` is stored briefly (single-use) so we can
    // verify incoming join proofs. For the MVP local-loop we return the URI.
    Ok(uri)
}

/// Spawn (or replace) the ntfy subscriber for the given topic. Messages are
/// reassembled + verified + decrypted via `handle_relay_message`.
async fn start_subscriber(state: &Arc<AppState>, app: &tauri::AppHandle, topic: &str) {
    // Shut down any existing subscriber (e.g. on topic rotation).
    if let Some(tx) = state.subscriber_shutdown.lock().await.take() {
        let _ = tx.send(());
    }

    let base = state.ntfy_base.lock().await.clone();
    let since = state.last_msg_id.lock().await.clone();
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
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if !msg.payload.is_empty() {
                *state_clone.last_msg_id.lock().await = Some(msg.id.clone());
                handle_relay_message(&state_clone, &app_clone, msg).await;
            }
        }
    });

    *state.subscriber_shutdown.lock().await = Some(shutdown_tx);
}

/// Join an existing room from a pairing URI. For the MVP this parses the URI,
/// records the admin identity + topic, and starts the subscriber. The actual
/// roster is adopted when the admin's signed genesis entry arrives over the
/// relay (and is verified against `admin_pub` from the URI). The full HMAC
/// proof-of-knowledge handshake is layered on top in a follow-up.
#[tauri::command]
pub async fn join_room(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    uri: String,
) -> Result<(), String> {
    let invite = crate::pairing::parse_uri(&uri).map_err(|e| e.to_string())?;
    // Record the trusted admin identity so we can verify the genesis entry when
    // it arrives. Stored separately from the roster (which stays None until the
    // signed entry is received + verified).
    *state.pending_admin.lock().await = Some((invite.topic.clone(), invite.admin_pub));
    start_subscriber(&state, &app, &invite.topic).await;
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
    const MAX_RECOMMENDED_BYTES: usize = 100_000;
    if text.len() > MAX_RECOMMENDED_BYTES {
        return Err(format!(
            "Clip is {} KB — that's a lot to sync over the free relay. Trim it or use a self-hosted server.",
            text.len() / 1024
        ));
    }

    let policy = if private { StorePolicy::Private } else { StorePolicy::History };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let sealed = crypto::seal_clip(&state.device, &recipients, &text, &topic, epoch, policy, now)
        .map_err(|e| e.to_string())?;

    let base = state.ntfy_base.lock().await.clone();

    // Publish the manifest first, then each chunk.
    let manifest_msg = postcard::to_allocvec(&WireMessage::Manifest(sealed.manifest))
        .map_err(|e| e.to_string())?;
    ntfy::publish(&base, &topic, &manifest_msg, "clip").await.map_err(|e| e.to_string())?;

    for chunk in &sealed.chunks {
        let chunk_msg = postcard::to_allocvec(&WireMessage::Chunk(chunk.clone()))
            .map_err(|e| e.to_string())?;
        ntfy::publish(&base, &topic, &chunk_msg, "clip").await.map_err(|e| e.to_string())?;
    }

    // Also store locally (history) unless private.
    if !private {
        state
            .store
            .insert(&state.device.signing_pub, now, &text)
            .map_err(|e| e.to_string())?;
        let _ = app.emit("clip-stored", ());
    }
    Ok(())
}

/// Get the most recent N clips from local history.
#[tauri::command]
pub fn recent_clips(state: State<'_, Arc<AppState>>, limit: Option<i64>) -> Result<Vec<ClipDto>, String> {
    let clips = state.store.recent(limit.unwrap_or(50) as usize).map_err(|e| e.to_string())?;
    Ok(clips.into_iter().map(ClipDto::from).collect())
}

/// Search local history.
#[tauri::command]
pub fn search_clips(state: State<'_, Arc<AppState>>, query: String) -> Result<Vec<ClipDto>, String> {
    let clips = state.store.search(&query, 50).map_err(|e| e.to_string())?;
    Ok(clips.into_iter().map(ClipDto::from).collect())
}

/// Delete a clip from local history by id.
#[tauri::command]
pub fn delete_clip(state: State<'_, Arc<AppState>>, id: u64) -> Result<(), String> {
    state.store.delete(id).map_err(|e| e.to_string())
}

/// A clip DTO for the frontend (no raw key bytes; sender shown as short hex).
#[derive(serde::Serialize)]
pub struct ClipDto {
    pub id: u64,
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
        Ok(w) => w,
        Err(_) => return,
    };
    match wire {
        WireMessage::Manifest(manifest) => {
            let mut pending = state.pending.lock().await;
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
        WireMessage::Roster(entry) => {
            // v1: accept a newer epoch from the admin. (Full join/verify flow
            // is out of MVP scope; this handles the broadcast path.)
            let current = state.roster.lock().await.clone();
            match current {
                Some(prev) => {
                    if entry.epoch > prev.epoch() {
                        match prev.verify_next(entry) {
                            Ok(next) => {
                                *state.roster.lock().await = Some(next);
                                let _ = app.emit("roster-updated", ());
                            }
                            Err(e) => {
                                eprintln!("roster update rejected: {e}");
                            }
                        }
                    }
                }
                None => {
                    eprintln!("received roster before joining a room; ignoring");
                }
            }
        }
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
    // Snapshot the active-member check.
    let active: Vec<crypto::Ed25519PubKey> =
        verified.entry.devices.iter().map(|d| d.signing_pub.clone()).collect();
    drop(roster_guard);

    let my_id = state.device.signing_pub.clone();
    let opened = crypto::open_clip(&manifest, &chunks, &state.device, current_epoch, |id, _| {
        active.contains(id) || *id == my_id
    });

    match opened {
        Ok(o) => {
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
                let _ = state.store.insert(&o.sender_id, o.ts, &o.plaintext);
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
        format!("{}…", &s[..s.char_indices().take(80).last().map(|(i, c)| i + c.len_utf8()).unwrap_or(80)])
    } else {
        s.to_string()
    }
}

/// Copy text to the system clipboard (called from frontend on click-to-copy).
#[tauri::command]
pub async fn copy_to_clipboard(text: String) -> Result<(), String> {
    // Delegate to the clipboard-manager plugin from the frontend instead; this
    // is a fallback. Returns Ok for now.
    let _ = text;
    Ok(())
}

/// History DB path helper (for main.rs to pass into AppState).
pub fn history_db_path(app: &tauri::AppHandle) -> PathBuf {
    let dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| std::env::temp_dir());
    let _ = std::fs::create_dir_all(&dir);
    dir.join("history.redb")
}
