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

pub mod pairing_commands;
pub mod sync_groups;

pub use pairing_commands::{
    approve_join_request, create_temporary_pairing_code, join_room, join_sync_group,
    load_invitations_from_keychain, new_pairing_code, pending_join_requests, reject_join_request,
    revoke_pairing_code, revoke_permanent_pairing_code, rotate_pairing_code,
};
use pairing_commands::{issue_pairing_code, persist_invitations};
use sync_groups::{
    activate_sync_group, add_sync_group_config, broadcast_roster, current_sync_group_id,
    decode_persisted_roster_entries, detected_device_label, ensure_active_sync_group,
    ensure_expected_active_group, load_active_roster_chain_entries, load_sync_group_roster,
    normalize_stun_servers, persist_roster, persist_settings, persist_sync_group_roster_checked,
    remove_sync_group_from_device, sanitize_device_label, sanitize_sync_group_name,
    verify_persisted_roster_entries,
};
pub use sync_groups::{
    create_room, create_sync_group, leave_room, load_persisted_roster, load_settings,
    network_settings, prepare_sync_groups, rename_device, rename_sync_group, revoke_device,
    room_state, roster_devices, save_settings, set_default_sync_group, set_network_settings,
    suggest_device_label, switch_sync_group, sync_groups,
};
pub mod state;

pub use state::*;
pub mod relay;

use relay::{
    encode_group_removal_notice, encode_roster_move, parse_device_id, publish_sealed_clip,
    publish_sealed_clip_attachment, publish_wire, start_auxiliary_subscriber,
    stop_auxiliary_subscriber,
};
pub use relay::{
    handle_relay_message, reconnect_relay, relay_status, restart_subscribers,
    start_invitation_subscribers, start_subscriber,
};
pub mod history_commands;

pub use history_commands::{
    copy_to_clipboard, delete_all_clips, delete_clip, recent_clips, search_clips, ClipDto,
};
pub mod transfer;

use crate::crypto::{self, DeviceKeypairs, StorePolicy};
use crate::network::{self, InvitationRecord, InvitationStore};
use crate::ntfy::{self, RelayMessage};
use crate::roster::{self, VerifiedRoster};
use crate::store::{HistoryClip, HistoryStore};
use base64::Engine;
use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use tauri::{Emitter, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_notification::NotificationExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
pub use transfer::{
    accept_file_transfer, cancel_file_transfer, diagnose_file_transfer_connectivity,
    grant_dropped_file, pending_file_offers, reject_file_transfer, reveal_received_file,
    start_file_send,
};
use transfer::{
    cancel_all_transfers, cancel_transfers_not_in_roster, decode_file_signal,
    fail_stale_epoch_outgoing_transfers, handle_file_signal, normalize_transfer_timeout_minutes,
};
#[cfg(test)]
use transfer::{
    cleanup_transfer, cleanup_transfer_if_timeout_token, completed_received_file_path,
    ensure_receive_destination_available, finalize_received_file_no_overwrite,
    remember_completed_received_file, safe_default_file_name, take_transfer,
};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

/// Return the active roster after verifying that this device is its admin.
///
/// Cloning under the lock ensures callers never retain the roster mutex across
/// later awaits.
async fn require_admin_roster(
    state: &Arc<AppState>,
    action: &str,
) -> Result<VerifiedRoster, String> {
    let verified = state
        .roster
        .lock()
        .await
        .clone()
        .ok_or_else(|| "not in a group".to_string())?;
    if state.device.signing_pub != verified.entry.admin_id {
        return Err(format!("only the group admin can {action}"));
    }
    Ok(verified)
}

const JOIN_REQUEST_MAX_AGE_SECS: u64 = 10 * 60;
const MAX_DURABLE_INVITATIONS: usize = 16;
const MAX_RELAY_CLIP_CHUNKS: u32 = 15;
const MAX_ATTACHMENT_CLIP_CHUNKS: u32 =
    (crypto::MAX_TEXT_BYTES.div_ceil(crypto::CHUNK_SIZE)) as u32;
const MAX_PENDING_CLIPS: usize = 128;
const PENDING_CLIP_TTL_SECS: u64 = 5 * 60;
const ROSTER_MOVE_PREFIX: &str = "fwoosh-roster-move-v1:";
const DELETE_SIG_DOMAIN: &[u8] = b"Fwoosh delete v1";
const FILE_SIGNAL_PREFIX: &str = "fwoosh-file-signal-v1:";
const DEFAULT_STUN_SERVER: &str = "stun:stun.cloudflare.com:3478";
const MAX_STUN_SERVERS: usize = 4;
const MAX_DEVICE_LABEL_CHARS: usize = 48;
const MAX_SYNC_GROUP_NAME_CHARS: usize = 48;
const FILE_CHUNK_SIZE: usize = 8 * 1024;
const MAX_ACTIVE_FILE_TRANSFERS: usize = 8;
const FILE_GRANT_TTL_SECS: u64 = 60;
const DEFAULT_FILE_TRANSFER_TIMEOUT_MINUTES: u64 = 60;
const MIN_FILE_TRANSFER_TIMEOUT_MINUTES: u64 = 1;
const MAX_FILE_TRANSFER_TIMEOUT_MINUTES: u64 = 7 * 24 * 60;
const FILE_BACKPRESSURE_TIMEOUT_SECS: u64 = 30;
const ICE_GATHER_TIMEOUT_SECS: u64 = 20;
const FILE_CONNECTION_TIMEOUT_SECS: u64 = 30;
const FILE_DISCONNECTED_GRACE_SECS: u64 = 10;
const FILE_IDLE_TIMEOUT_SECS: u64 = 45;
const MAX_FILE_NAME_CHARS: usize = 255;
const MAX_SDP_JSON_BYTES: usize = 256 * 1024;
const MAX_FILE_FRAME_BYTES: usize = FILE_CHUNK_SIZE + 1024;
const FILE_NONCE_PREFIX_LEN: usize = 16;
const FILE_NONCE_LEN: usize = 24;
const MAX_COMPLETED_RECEIVED_FILES: usize = 256;

#[derive(serde::Serialize)]
struct DeleteClipForSigning<'a> {
    msg_id: &'a [u8; 16],
    room_id: &'a str,
    roster_epoch: u64,
    sender_id: &'a crypto::Ed25519PubKey,
    ts: u64,
}

#[derive(serde::Serialize)]
struct RenameDeviceForSigning<'a> {
    device_id: &'a crypto::Ed25519PubKey,
    room_id: &'a str,
    roster_epoch: u64,
    label: &'a str,
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

fn rename_device_signing_bytes(msg: &RenameDeviceMessage) -> Vec<u8> {
    let view = RenameDeviceForSigning {
        device_id: &msg.device_id,
        room_id: &msg.room_id,
        roster_epoch: msg.roster_epoch,
        label: &msg.label,
        ts: msg.ts,
    };
    let mut buf = b"Fwoosh rename device v1".to_vec();
    buf.extend_from_slice(&postcard::to_allocvec(&view).expect("postcard encode rename message"));
    buf
}

fn sign_rename_device(
    device: &DeviceKeypairs,
    room_id: String,
    roster_epoch: u64,
    label: String,
    ts: u64,
) -> RenameDeviceMessage {
    let mut msg = RenameDeviceMessage {
        device_id: device.signing_pub.clone(),
        room_id,
        roster_epoch,
        label,
        ts,
        signature: Vec::new(),
    };
    let bytes = rename_device_signing_bytes(&msg);
    msg.signature = device.signing.sign(&bytes).to_bytes().to_vec();
    msg
}

fn verify_rename_device_sig(msg: &RenameDeviceMessage) -> Result<(), String> {
    let vk = VerifyingKey::from_bytes(&msg.device_id.0)
        .map_err(|_| "bad rename sender key".to_string())?;
    let sig =
        Signature::from_slice(&msg.signature).map_err(|_| "bad rename signature".to_string())?;
    vk.verify(&rename_device_signing_bytes(msg), &sig)
        .map_err(|_| "rename signature verification failed".to_string())
}

#[derive(serde::Serialize)]
struct RosterSyncRequestForSigning<'a> {
    requester_id: &'a crypto::Ed25519PubKey,
    room_id: &'a str,
    current_epoch: u64,
    ts: u64,
}

fn roster_sync_request_signing_bytes(msg: &RosterSyncRequestMessage) -> Vec<u8> {
    let view = RosterSyncRequestForSigning {
        requester_id: &msg.requester_id,
        room_id: &msg.room_id,
        current_epoch: msg.current_epoch,
        ts: msg.ts,
    };
    let mut buf = b"Fwoosh roster sync v1".to_vec();
    buf.extend_from_slice(
        &postcard::to_allocvec(&view).expect("postcard encode roster sync request"),
    );
    buf
}

fn sign_roster_sync_request(
    device: &DeviceKeypairs,
    room_id: String,
    current_epoch: u64,
    ts: u64,
) -> RosterSyncRequestMessage {
    let mut msg = RosterSyncRequestMessage {
        requester_id: device.signing_pub.clone(),
        room_id,
        current_epoch,
        ts,
        signature: Vec::new(),
    };
    let bytes = roster_sync_request_signing_bytes(&msg);
    msg.signature = device.signing.sign(&bytes).to_bytes().to_vec();
    msg
}

fn verify_roster_sync_request_sig(msg: &RosterSyncRequestMessage) -> Result<(), String> {
    let vk = VerifyingKey::from_bytes(&msg.requester_id.0)
        .map_err(|_| "bad roster sync requester key".to_string())?;
    let sig = Signature::from_slice(&msg.signature)
        .map_err(|_| "bad roster sync signature".to_string())?;
    vk.verify(&roster_sync_request_signing_bytes(msg), &sig)
        .map_err(|_| "roster sync signature verification failed".to_string())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn pairing_bootstrap_info(invite_id: &str, kind: &str) -> Vec<u8> {
    format!("Fwoosh pairing v2\0{kind}\0{invite_id}").into_bytes()
}

fn default_file_transfer_timeout_minutes() -> u64 {
    DEFAULT_FILE_TRANSFER_TIMEOUT_MINUTES
}

/// Send a clip to all devices in the current roster. Manual-send only (no auto
/// clipboard monitoring in MVP). `private` = sync once, don't store.
#[tauri::command]
pub async fn send_clip(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    text: String,
    private: bool,
    network_id: Option<String>,
) -> Result<(), String> {
    let active_group_id = state
        .settings
        .lock()
        .await
        .active_sync_group_id
        .clone()
        .ok_or_else(|| "no sync group is active".to_string())?;
    if network_id
        .as_ref()
        .is_some_and(|requested| requested != &active_group_id)
    {
        return Err("selected group is not available".to_string());
    }
    let guard = state.roster.lock().await;
    let verified = guard.as_ref().ok_or("not in a room")?;
    let recipients = verified.recipients();
    let epoch = verified.epoch();
    let topic = verified.topic().to_string();
    drop(guard);

    if text.len() > crypto::MAX_TEXT_BYTES {
        return Err(format!(
            "Clip is {} KB. Clipboard text is limited to 1 MiB; send this as a file instead.",
            text.len().div_ceil(1024)
        ));
    }

    let policy = if private {
        StorePolicy::Private
    } else {
        StorePolicy::History
    };
    let now = now_unix();

    let sealed = crypto::seal_compressed_clip(
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
    let publish_options = if private {
        ntfy::PublishOptions::no_cache()
    } else {
        ntfy::PublishOptions::default()
    };
    if sealed.manifest.chunk_count <= MAX_RELAY_CLIP_CHUNKS {
        publish_sealed_clip(&base, &topic, sealed, publish_options).await?;
    } else {
        if private {
            return Err(
                "This private clip is too large for no-cache relay delivery; send it as a file instead."
                    .to_string(),
            );
        }
        publish_sealed_clip_attachment(&base, &topic, sealed, publish_options).await?;
    }

    *state.last_outbound_epoch.lock().await =
        Some((topic.clone(), epoch, std::time::Instant::now()));
    state.reconnect_notify.notify_waiters();

    // Also store locally (history) unless private.
    if !private {
        let group_id = current_sync_group_id(state.inner()).await?;
        state
            .store
            .insert_with_msg_id_in_group(
                &group_id,
                &state.device.signing_pub,
                now,
                &text,
                Some(&msg_id),
            )
            .map_err(|e| e.to_string())?;
        let _ = app.emit("clip-stored", ());
    }
    Ok(())
}

pub fn reveal_main_window(app: &tauri::AppHandle) -> Result<(), String> {
    if let Some(state) = app.try_state::<Arc<AppState>>() {
        let state = state.inner().clone();
        let app_clone = app.clone();
        tauri::async_runtime::spawn(async move {
            relay::nudge_or_ensure_subscriber(&state, app_clone).await;
        });
    }

    #[cfg(desktop)]
    {
        let win = app
            .get_webview_window("main")
            .ok_or_else(|| "main window not found".to_string())?;

        let _ = win.unminimize();
        win.show().map_err(|e| e.to_string())?;
        win.set_focus().map_err(|e| e.to_string())
    }

    // Mobile owns its normal activity/window lifecycle. In particular, do
    // not force a show or focus when a file offer arrives.
    #[cfg(mobile)]
    {
        let _ = app;
        Ok(())
    }
}

#[tauri::command]
pub fn dismiss_main_window(app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(desktop)]
    {
        let win = app
            .get_webview_window("main")
            .ok_or_else(|| "main window not found".to_string())?;

        #[cfg(target_os = "macos")]
        return win.minimize().map_err(|e| e.to_string());

        #[cfg(not(target_os = "macos"))]
        return win.hide().map_err(|e| e.to_string());
    }

    #[cfg(mobile)]
    {
        let _ = app;
        Ok(())
    }
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

#[cfg(test)]
mod tests;
