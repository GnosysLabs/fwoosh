//! WebRTC setup, data-channel framing, file finalization, and transfer cleanup.

use super::*;

pub(crate) async fn new_peer_connection(
    stun_servers: Vec<String>,
) -> Result<Arc<RTCPeerConnection>, String> {
    let servers = normalize_stun_servers(stun_servers)?;
    let mut media = MediaEngine::default();
    media.register_default_codecs().map_err(|e| e.to_string())?;
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut media).map_err(|e| e.to_string())?;
    let api = APIBuilder::new()
        .with_media_engine(media)
        .with_interceptor_registry(registry)
        .build();
    let config = RTCConfiguration {
        ice_servers: vec![RTCIceServer {
            urls: servers,
            ..Default::default()
        }],
        ..Default::default()
    };
    api.new_peer_connection(config)
        .await
        .map(Arc::new)
        .map_err(|e| e.to_string())
}

pub(crate) fn install_peer_state_handler(
    peer: &Arc<RTCPeerConnection>,
    app: tauri::AppHandle,
    state: Arc<AppState>,
    session_id: String,
    total: u64,
) {
    peer.on_peer_connection_state_change(Box::new(move |s: RTCPeerConnectionState| {
        let app = app.clone();
        let state = state.clone();
        let session_id = session_id.clone();
        Box::pin(async move {
            match s {
                RTCPeerConnectionState::Connected => {
                    let _ = app.emit(
                        "file-transfer-progress",
                        FileTransferProgressDto {
                            session_id,
                            transferred: 0,
                            total,
                            status: "connected".to_string(),
                            message: "Direct connection established".to_string(),
                        },
                    );
                }
                RTCPeerConnectionState::Failed => {
                    emit_file_failed(&app, &state, &session_id, "Direct connection unavailable")
                        .await;
                }
                _ => {}
            }
        })
    }));
}

pub(crate) fn install_sender_channel(
    data_channel: Arc<RTCDataChannel>,
    app: tauri::AppHandle,
    state: Arc<AppState>,
    session_id: String,
    payload: OutgoingFilePayload,
) {
    let open_channel = data_channel.clone();
    data_channel.on_open(Box::new(move || {
        let dc = open_channel.clone();
        let app = app.clone();
        let state = state.clone();
        let session_id = session_id.clone();
        let payload = payload.clone();
        Box::pin(async move {
            if let Err(e) =
                send_file_over_channel(dc, app.clone(), state.clone(), session_id.clone(), payload)
                    .await
            {
                emit_file_failed(&app, &state, &session_id, &e).await;
            }
        })
    }));
}

pub(crate) fn install_receiver_channel(
    peer: &Arc<RTCPeerConnection>,
    app: tauri::AppHandle,
    state: Arc<AppState>,
    receiver_state: ReceiverWriteState,
) {
    let write_state = Arc::new(Mutex::new(receiver_state));
    peer.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
        let app = app.clone();
        let state = state.clone();
        let write_state = write_state.clone();
        Box::pin(async move {
            dc.on_message(Box::new(move |msg: DataChannelMessage| {
                let app = app.clone();
                let state = state.clone();
                let write_state = write_state.clone();
                Box::pin(async move {
                    if let Err(e) =
                        handle_file_frame(app.clone(), state.clone(), write_state.clone(), msg)
                            .await
                    {
                        let session_id = write_state.lock().await.session_id.clone();
                        emit_file_failed(&app, &state, &session_id, &e).await;
                    }
                })
            }));
        })
    }));
}

pub(crate) async fn send_file_over_channel(
    dc: Arc<RTCDataChannel>,
    app: tauri::AppHandle,
    state: Arc<AppState>,
    session_id: String,
    payload: OutgoingFilePayload,
) -> Result<(), String> {
    let mut file = tokio::fs::File::open(&payload.path)
        .await
        .map_err(|e| e.to_string())?;
    let cipher = XChaCha20Poly1305::new(&payload.content_key.into());
    let mut buf = vec![0u8; FILE_CHUNK_SIZE];
    let mut index = 0u64;
    let mut sent = 0u64;
    let mut hasher = Sha256::new();
    loop {
        let n = file.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        if sent.saturating_add(n as u64) > payload.total {
            return Err("source file size changed during transfer".to_string());
        }
        let nonce = file_chunk_nonce(&payload.nonce_prefix, index);
        let aad = file_chunk_aad(&session_id, index);
        let ct = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &buf[..n],
                    aad: &aad,
                },
            )
            .map_err(|_| "file chunk encryption failed".to_string())?;
        let frame =
            postcard::to_allocvec(&FileFrame::Chunk { index, ct }).map_err(|e| e.to_string())?;
        let wait_started = std::time::Instant::now();
        while dc.buffered_amount().await > 512 * 1024 {
            if wait_started.elapsed()
                > std::time::Duration::from_secs(FILE_BACKPRESSURE_TIMEOUT_SECS)
            {
                return Err("file transfer stalled".to_string());
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        dc.send(&Bytes::from(frame))
            .await
            .map_err(|e| e.to_string())?;
        hasher.update(&buf[..n]);
        sent += n as u64;
        index += 1;
        let _ = app.emit(
            "file-transfer-progress",
            FileTransferProgressDto {
                session_id: session_id.clone(),
                transferred: sent,
                total: payload.total,
                status: "sending".to_string(),
                message: payload.file_name.clone(),
            },
        );
    }
    if sent != payload.total {
        return Err("source file size changed during transfer".to_string());
    }
    let sha256: [u8; 32] = hasher.finalize().into();
    let frame = postcard::to_allocvec(&FileFrame::Finish { sha256 }).map_err(|e| e.to_string())?;
    dc.send(&Bytes::from(frame))
        .await
        .map_err(|e| e.to_string())?;
    // Completion is a terminal state. Claim the active transfer before
    // notifying the UI so a simultaneous peer failure or roster update cannot
    // emit a second terminal event for this session.
    if take_transfer(&state, &session_id).await.is_none() {
        return Ok(());
    }
    let _ = app.emit(
        "file-transfer-complete",
        serde_json::json!({
            "session_id": session_id,
            "file_name": payload.file_name,
            "size": payload.total,
            "sha256": hex::encode(sha256),
            "direction": "outgoing"
        }),
    );
    Ok(())
}

pub(crate) async fn handle_file_frame(
    app: tauri::AppHandle,
    state: Arc<AppState>,
    write_state: Arc<Mutex<ReceiverWriteState>>,
    msg: DataChannelMessage,
) -> Result<(), String> {
    if msg.data.len() > MAX_FILE_FRAME_BYTES {
        return Err("file transfer frame is too large".to_string());
    }
    let frame: FileFrame = postcard::from_bytes(&msg.data).map_err(|e| e.to_string())?;
    match frame {
        FileFrame::Chunk { index, ct } => {
            let mut guard = write_state.lock().await;
            if guard.done {
                return Ok(());
            }
            if index != guard.next_index {
                return Err("file chunks arrived out of order".to_string());
            }
            let nonce = file_chunk_nonce(&guard.nonce_prefix, index);
            let aad = file_chunk_aad(&guard.session_id, index);
            let cipher = XChaCha20Poly1305::new(&guard.content_key.into());
            let pt = cipher
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &ct,
                        aad: &aad,
                    },
                )
                .map_err(|_| "file chunk decryption failed".to_string())?;
            if guard.received.saturating_add(pt.len() as u64) > guard.total {
                return Err("received file exceeded offered size".to_string());
            }
            let file = guard
                .file
                .as_mut()
                .ok_or_else(|| "receive file is already closed".to_string())?;
            file.write_all(&pt).await.map_err(|e| e.to_string())?;
            guard.hasher.update(&pt);
            guard.received += pt.len() as u64;
            guard.next_index += 1;
            let _ = app.emit(
                "file-transfer-progress",
                FileTransferProgressDto {
                    session_id: guard.session_id.clone(),
                    transferred: guard.received,
                    total: guard.total,
                    status: "receiving".to_string(),
                    message: guard.file_name.clone(),
                },
            );
            Ok(())
        }
        FileFrame::Finish { sha256: expected } => {
            let (session_id, final_path, part_path, file_name, total, computed) = {
                let mut guard = write_state.lock().await;
                if guard.done {
                    return Ok(());
                }
                if guard.received != guard.total {
                    return Err("received file size did not match offer".to_string());
                }
                let mut file = guard
                    .file
                    .take()
                    .ok_or_else(|| "receive file is already closed".to_string())?;
                file.flush().await.map_err(|e| e.to_string())?;
                drop(file);
                let hasher = std::mem::replace(&mut guard.hasher, Sha256::new());
                let computed: [u8; 32] = hasher.finalize().into();
                guard.done = true;
                (
                    guard.session_id.clone(),
                    guard.final_path.clone(),
                    guard.part_path.clone(),
                    guard.file_name.clone(),
                    guard.total,
                    computed,
                )
            };
            if computed != expected {
                let _ = tokio::fs::remove_file(&part_path).await;
                return Err("received file checksum did not match".to_string());
            }
            finalize_received_file_no_overwrite(&part_path, &final_path).await?;
            state.file_transfers.lock().await.remove(&session_id);
            remember_completed_received_file(&state, &session_id, final_path.clone()).await;
            let _ = app.emit(
                "file-transfer-complete",
                serde_json::json!({
                    "session_id": session_id,
                    "file_name": file_name,
                    "size": total,
                    "sha256": hex::encode(expected),
                    "path": final_path.to_string_lossy(),
                    "direction": "incoming"
                }),
            );
            Ok(())
        }
        FileFrame::Cancel { reason } => {
            let session_id = write_state.lock().await.session_id.clone();
            if cleanup_transfer(&state, &session_id).await {
                let _ = app.emit(
                    "file-transfer-cancelled",
                    FileTransferProgressDto {
                        session_id,
                        transferred: 0,
                        total: 0,
                        status: "cancelled".to_string(),
                        message: reason,
                    },
                );
            }
            Ok(())
        }
    }
}

pub(crate) fn file_chunk_nonce(
    prefix: &[u8; FILE_NONCE_PREFIX_LEN],
    index: u64,
) -> [u8; FILE_NONCE_LEN] {
    let mut out = [0u8; FILE_NONCE_LEN];
    out[..FILE_NONCE_PREFIX_LEN].copy_from_slice(prefix);
    out[FILE_NONCE_PREFIX_LEN..].copy_from_slice(&index.to_be_bytes());
    out
}

pub(crate) fn file_chunk_aad(session_id: &str, index: u64) -> Vec<u8> {
    let mut aad = b"Fwoosh file transfer v1\0".to_vec();
    aad.extend_from_slice(session_id.as_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

pub(crate) fn part_path_for(path: &Path) -> PathBuf {
    let mut part = path.as_os_str().to_os_string();
    part.push(".fwoosh-part");
    PathBuf::from(part)
}

pub(crate) fn ensure_receive_destination_available(path: &Path) -> Result<(), String> {
    if path.exists() {
        if path.is_dir() {
            return Err("save path points to a folder".to_string());
        }
        return Err("a file already exists at that path; choose a new name".to_string());
    }
    let Some(parent) = path.parent() else {
        return Err("save path has no parent folder".to_string());
    };
    if !parent.exists() || !parent.is_dir() {
        return Err("save folder does not exist".to_string());
    }
    Ok(())
}

pub(crate) async fn create_new_file(path: &Path) -> Result<tokio::fs::File, String> {
    tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
        .map_err(|e| {
            if e.kind() == ErrorKind::AlreadyExists {
                "a file already exists at that path; choose a new name".to_string()
            } else {
                e.to_string()
            }
        })
}

pub(crate) async fn finalize_received_file_no_overwrite(
    part_path: &Path,
    final_path: &Path,
) -> Result<(), String> {
    let mut source = tokio::fs::File::open(part_path)
        .await
        .map_err(|e| e.to_string())?;
    let mut dest = create_new_file(final_path).await?;
    if let Err(e) = tokio::io::copy(&mut source, &mut dest).await {
        let _ = tokio::fs::remove_file(final_path).await;
        return Err(e.to_string());
    }
    if let Err(e) = dest.flush().await {
        let _ = tokio::fs::remove_file(final_path).await;
        return Err(e.to_string());
    }
    drop(dest);
    drop(source);
    tokio::fs::remove_file(part_path)
        .await
        .map_err(|e| e.to_string())
}

pub(crate) fn spawn_transfer_timeout(
    app: tauri::AppHandle,
    state: Arc<AppState>,
    session_id: String,
    timeout_token: u64,
    timeout_minutes: u64,
) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(
            timeout_minutes.saturating_mul(60),
        ))
        .await;
        emit_file_failed_if_active(
            &app,
            &state,
            &session_id,
            timeout_token,
            "File transfer timed out",
        )
        .await;
    });
}

pub(crate) async fn emit_file_failed(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    session_id: &str,
    message: &str,
) {
    // Async WebRTC callbacks can outlive a successful transfer. Only an
    // active session may transition to failed; completed sessions have
    // already been removed from file_transfers.
    if !cleanup_transfer(state, session_id).await {
        return;
    }
    let _ = app.emit(
        "file-transfer-failed",
        FileTransferProgressDto {
            session_id: session_id.to_string(),
            transferred: 0,
            total: 0,
            status: "failed".to_string(),
            message: message.to_string(),
        },
    );
}

pub(crate) async fn emit_file_failed_if_active(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    session_id: &str,
    timeout_token: u64,
    message: &str,
) {
    if cleanup_transfer_if_timeout_token(state, session_id, timeout_token).await {
        let _ = app.emit(
            "file-transfer-failed",
            FileTransferProgressDto {
                session_id: session_id.to_string(),
                transferred: 0,
                total: 0,
                status: "failed".to_string(),
                message: message.to_string(),
            },
        );
    }
}

pub(crate) fn transfer_timeout_token(record: &TransferRecord) -> u64 {
    match record {
        TransferRecord::PendingIncoming(pending) => pending.timeout_token,
        TransferRecord::Outgoing(outgoing) => outgoing.timeout_token,
        TransferRecord::Incoming(incoming) => incoming.timeout_token,
    }
}

pub(crate) async fn cleanup_transfer_if_timeout_token(
    state: &Arc<AppState>,
    session_id: &str,
    timeout_token: u64,
) -> bool {
    let record = {
        let mut transfers = state.file_transfers.lock().await;
        match transfers.get(session_id) {
            Some(record) if transfer_timeout_token(record) == timeout_token => {
                transfers.remove(session_id)
            }
            _ => None,
        }
    };
    let had_record = record.is_some();
    cleanup_transfer_record(record).await;
    had_record
}

pub(crate) async fn take_transfer(
    state: &Arc<AppState>,
    session_id: &str,
) -> Option<TransferRecord> {
    state.file_transfers.lock().await.remove(session_id)
}

pub(crate) async fn cleanup_transfer(state: &Arc<AppState>, session_id: &str) -> bool {
    let record = take_transfer(state, session_id).await;
    let had_record = record.is_some();
    cleanup_transfer_record(record).await;
    had_record
}

pub(crate) async fn remember_completed_received_file(
    state: &Arc<AppState>,
    session_id: &str,
    path: PathBuf,
) {
    let mut files = state.completed_received_files.lock().await;
    files.retain(|(id, _)| id != session_id);
    files.push_back((session_id.to_string(), path));
    while files.len() > MAX_COMPLETED_RECEIVED_FILES {
        files.pop_front();
    }
}

pub(crate) async fn completed_received_file_path(
    state: &Arc<AppState>,
    requested_path: &Path,
) -> Result<PathBuf, String> {
    state
        .completed_received_files
        .lock()
        .await
        .iter()
        .find_map(|(_, path)| (path == requested_path).then(|| path.clone()))
        .ok_or_else(|| "Received file is not available to reveal".to_string())
}

#[cfg(target_os = "macos")]
pub(crate) fn reveal_path_in_file_manager(path: &Path) -> Result<(), String> {
    std::process::Command::new("open")
        .arg("-R")
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Could not open Finder: {e}"))
}

#[cfg(target_os = "windows")]
pub(crate) fn reveal_path_in_file_manager(path: &Path) -> Result<(), String> {
    std::process::Command::new("explorer.exe")
        .arg(format!("/select,{}", path.to_string_lossy()))
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Could not open File Explorer: {e}"))
}

#[cfg(target_os = "linux")]
pub(crate) fn reveal_path_in_file_manager(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "Received file has no containing folder".to_string())?;
    std::process::Command::new("xdg-open")
        .arg(parent)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Could not open the file manager: {e}"))
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub(crate) fn reveal_path_in_file_manager(_path: &Path) -> Result<(), String> {
    Err("Revealing files is not supported on this platform".to_string())
}

pub(crate) async fn remove_transfer_matching_sender(
    state: &Arc<AppState>,
    session_id: &str,
    sender_id: &crypto::Ed25519PubKey,
) -> Option<TransferRecord> {
    let mut transfers = state.file_transfers.lock().await;
    let matches_sender = match transfers.get(session_id) {
        Some(TransferRecord::Outgoing(outgoing)) => &outgoing.recipient_id == sender_id,
        Some(TransferRecord::Incoming(incoming)) => &incoming.sender_id == sender_id,
        Some(TransferRecord::PendingIncoming(pending)) => &pending.sender_id == sender_id,
        None => false,
    };
    if matches_sender {
        transfers.remove(session_id)
    } else {
        None
    }
}

pub(crate) async fn cancel_transfers_not_in_roster(
    state: &Arc<AppState>,
    app: &tauri::AppHandle,
    roster: &VerifiedRoster,
) {
    let stale = {
        let mut transfers = state.file_transfers.lock().await;
        let stale_ids: Vec<String> = transfers
            .iter()
            .filter_map(|(session_id, record)| {
                if transfer_is_stale_for_roster(record, roster, &state.device.signing_pub) {
                    Some(session_id.clone())
                } else {
                    None
                }
            })
            .collect();
        stale_ids
            .into_iter()
            .filter_map(|session_id| {
                transfers
                    .remove(&session_id)
                    .map(|record| (session_id, record))
            })
            .collect::<Vec<_>>()
    };

    for (session_id, record) in stale {
        cleanup_transfer_record(Some(record)).await;
        let _ = app.emit(
            "file-transfer-cancelled",
            FileTransferProgressDto {
                session_id,
                transferred: 0,
                total: 0,
                status: "cancelled".to_string(),
                message: "Peer is no longer in this room".to_string(),
            },
        );
    }
}

pub(crate) fn transfer_is_stale_for_roster(
    record: &TransferRecord,
    roster: &VerifiedRoster,
    self_id: &crypto::Ed25519PubKey,
) -> bool {
    if !roster.is_active(self_id) {
        return true;
    }
    let peer_id = match record {
        TransferRecord::PendingIncoming(pending) => &pending.sender_id,
        TransferRecord::Outgoing(outgoing) => &outgoing.recipient_id,
        TransferRecord::Incoming(incoming) => &incoming.sender_id,
    };
    !roster.is_active(peer_id)
}

pub(crate) async fn cleanup_transfer_record(record: Option<TransferRecord>) {
    match record {
        Some(TransferRecord::Incoming(incoming)) => {
            let _ = incoming.peer.close().await;
            let _ = tokio::fs::remove_file(incoming.part_path).await;
        }
        Some(TransferRecord::Outgoing(outgoing)) => {
            let _ = outgoing.peer.close().await;
        }
        Some(TransferRecord::PendingIncoming(_)) | None => {}
    }
}
