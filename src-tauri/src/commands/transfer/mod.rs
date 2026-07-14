//! Large-file transfer commands and the WebRTC transfer state machine.

use super::*;

mod webrtc;

use webrtc::*;
pub(super) use webrtc::{cancel_all_transfers, cancel_transfers_not_in_roster};
#[cfg(test)]
pub(super) use webrtc::{
    cleanup_transfer, cleanup_transfer_if_timeout_token, completed_received_file_path,
    ensure_receive_destination_available, finalize_received_file_no_overwrite,
    remember_completed_received_file, take_transfer,
};

pub(super) fn safe_default_file_name(file_name: &str) -> String {
    let raw_name = file_name
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or(file_name);
    let mut out = String::new();
    for ch in raw_name.chars().take(MAX_FILE_NAME_CHARS) {
        if ch.is_control() || matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
            out.push('_');
        } else {
            out.push(ch);
        }
    }
    let trimmed = out.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        "fwoosh-file".to_string()
    } else {
        trimmed.to_string()
    }
}

fn is_valid_session_id(session_id: &str) -> bool {
    session_id.len() == 32 && session_id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn validate_sdp_json(sdp_json: &str) -> Result<(), String> {
    if sdp_json.len() > MAX_SDP_JSON_BYTES {
        return Err("file transfer signal is too large".to_string());
    }
    Ok(())
}

fn inspect_local_file(path: PathBuf) -> Result<(PathBuf, String, u64), String> {
    let path = std::fs::canonicalize(&path).map_err(|e| e.to_string())?;
    let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("Only single files can be sent".to_string());
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(safe_default_file_name)
        .ok_or_else(|| "file name is not valid UTF-8".to_string())?;
    Ok((path, file_name, meta.len()))
}

fn prune_file_grants(grants: &mut HashMap<String, FileGrant>, now: u64) {
    grants.retain(|_, grant| now.saturating_sub(grant.created_at) <= FILE_GRANT_TTL_SECS);
}

pub async fn grant_dropped_file(
    state: &Arc<AppState>,
    path: PathBuf,
) -> Result<FileDropGrantDto, String> {
    let (path, file_name, size) = inspect_local_file(path)?;
    let grant_id = new_session_id();
    let mut grants = state.file_grants.lock().await;
    let now = now_unix();
    prune_file_grants(&mut grants, now);
    if grants.len() >= MAX_ACTIVE_FILE_TRANSFERS * 2 {
        return Err("too many pending dropped files".to_string());
    }
    grants.insert(
        grant_id.clone(),
        FileGrant {
            path,
            created_at: now,
        },
    );
    Ok(FileDropGrantDto {
        grant_id,
        file_name,
        size,
    })
}

async fn consume_file_grant(state: &Arc<AppState>, grant_id: &str) -> Result<PathBuf, String> {
    if !is_valid_session_id(grant_id) {
        return Err("file drop grant is invalid".to_string());
    }
    let mut grants = state.file_grants.lock().await;
    let now = now_unix();
    prune_file_grants(&mut grants, now);
    let grant = grants
        .remove(grant_id)
        .ok_or_else(|| "file drop grant expired".to_string())?;
    Ok(grant.path)
}

fn dialog_file_path_to_pathbuf(path: tauri_plugin_dialog::FilePath) -> Result<PathBuf, String> {
    path.into_path()
        .map_err(|_| "dialog returned an invalid local file path".to_string())
}

fn pick_file_for_send(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let selected = app
        .dialog()
        .file()
        .set_title("Choose file to send")
        .blocking_pick_file()
        .ok_or_else(|| "File selection cancelled".to_string())?;
    dialog_file_path_to_pathbuf(selected)
}

fn pick_save_path(app: &tauri::AppHandle, file_name: &str) -> Result<PathBuf, String> {
    let selected = app
        .dialog()
        .file()
        .set_title("Save incoming file")
        .set_file_name(safe_default_file_name(file_name))
        .blocking_save_file()
        .ok_or_else(|| "Save cancelled".to_string())?;
    dialog_file_path_to_pathbuf(selected)
}

fn ensure_transfer_capacity(transfers: &HashMap<String, TransferRecord>) -> Result<(), String> {
    if transfers.len() >= MAX_ACTIVE_FILE_TRANSFERS {
        return Err("too many active file transfers".to_string());
    }
    Ok(())
}

pub(super) fn normalize_transfer_timeout_minutes(minutes: u64) -> Result<u64, String> {
    if !(MIN_FILE_TRANSFER_TIMEOUT_MINUTES..=MAX_FILE_TRANSFER_TIMEOUT_MINUTES).contains(&minutes) {
        return Err(format!(
            "transfer timeout must be between {} minute and {} minutes",
            MIN_FILE_TRANSFER_TIMEOUT_MINUTES, MAX_FILE_TRANSFER_TIMEOUT_MINUTES
        ));
    }
    Ok(minutes)
}

#[tauri::command]
pub async fn start_file_send(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    network_id: String,
    recipient_id: String,
    grant_id: Option<String>,
) -> Result<TransferDto, String> {
    let network_id = network_id.trim().to_string();
    {
        let settings = state.settings.lock().await;
        ensure_expected_active_group(&settings, &network_id, "starting the file transfer")?;
    }
    let path = match grant_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        Some(id) => consume_file_grant(state.inner(), id).await?,
        None => pick_file_for_send(&app)?,
    };
    let (path, file_name, size) = inspect_local_file(path)?;
    let recipient = parse_device_id(&recipient_id)?;
    {
        let settings = state.settings.lock().await;
        ensure_expected_active_group(&settings, &network_id, "starting the file transfer")?;
    }
    let (recipient_label, recipient_identity, topic, epoch) =
        recipient_for_transfer(state.inner(), &recipient).await?;

    let mut content_key = [0u8; 32];
    rand::rng().fill_bytes(&mut content_key);
    let mut nonce_prefix = [0u8; FILE_NONCE_PREFIX_LEN];
    rand::rng().fill_bytes(&mut nonce_prefix);
    let session_id = new_session_id();
    let timeout_token = new_timeout_token();
    let (stun_servers, transfer_timeout_minutes) = {
        let settings = state.settings.lock().await;
        (
            settings.stun_servers.clone(),
            settings.transfer_timeout_minutes,
        )
    };
    let peer = new_peer_connection(stun_servers).await?;
    install_peer_state_handler(
        &peer,
        app.clone(),
        state.inner().clone(),
        session_id.clone(),
        size,
    );
    let data_channel = peer
        .create_data_channel("fwoosh-file", None)
        .await
        .map_err(|e| e.to_string())?;
    let outgoing_file = OutgoingFilePayload {
        path: path.clone(),
        file_name: file_name.clone(),
        total: size,
        content_key,
        nonce_prefix,
    };
    install_sender_channel(
        data_channel,
        app.clone(),
        state.inner().clone(),
        session_id.clone(),
        outgoing_file,
    );

    let offer = peer.create_offer(None).await.map_err(|e| e.to_string())?;
    let mut gather_complete = peer.gathering_complete_promise().await;
    peer.set_local_description(offer)
        .await
        .map_err(|e| e.to_string())?;
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(ICE_GATHER_TIMEOUT_SECS),
        gather_complete.recv(),
    )
    .await;
    let local = peer
        .local_description()
        .await
        .ok_or_else(|| "failed to create local WebRTC offer".to_string())?;
    let sdp_json = serde_json::to_string(&local).map_err(|e| e.to_string())?;
    validate_sdp_json(&sdp_json)?;

    let group_error = {
        let settings = state.settings.lock().await;
        ensure_expected_active_group(&settings, &network_id, "starting the file transfer").err()
    };
    if let Some(error) = group_error {
        let _ = peer.close().await;
        return Err(error);
    }
    {
        let mut transfers = state.file_transfers.lock().await;
        if let Err(e) = ensure_transfer_capacity(&transfers) {
            let _ = peer.close().await;
            return Err(e);
        }
        transfers.insert(
            session_id.clone(),
            TransferRecord::Outgoing(OutgoingTransfer {
                recipient_id: recipient.clone(),
                peer: peer.clone(),
                timeout_token,
            }),
        );
    }
    spawn_transfer_timeout(
        app.clone(),
        state.inner().clone(),
        session_id.clone(),
        timeout_token,
        transfer_timeout_minutes,
    );

    let signal = FileSignal::Offer {
        session_id: session_id.clone(),
        file_name: file_name.clone(),
        size,
        content_key,
        nonce_prefix,
        sdp_json,
    };
    publish_file_signal(
        state.inner(),
        &topic,
        epoch,
        &recipient_identity,
        signal,
        "file-offer",
    )
    .await?;

    Ok(TransferDto {
        session_id,
        file_name,
        size,
        peer_label: recipient_label,
        direction: "outgoing".to_string(),
        status: "waiting".to_string(),
    })
}

#[tauri::command]
pub async fn accept_file_transfer(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    network_id: String,
    session_id: String,
) -> Result<TransferDto, String> {
    let network_id = network_id.trim().to_string();
    {
        let settings = state.settings.lock().await;
        ensure_expected_active_group(&settings, &network_id, "accepting the file transfer")?;
    }
    if !is_valid_session_id(&session_id) {
        return Err("transfer id is invalid".to_string());
    }
    let pending_for_dialog = {
        let transfers = state.file_transfers.lock().await;
        match transfers.get(&session_id) {
            Some(TransferRecord::PendingIncoming(pending)) if pending.network_id == network_id => {
                pending.clone()
            }
            Some(TransferRecord::PendingIncoming(_)) => {
                return Err("file offer belongs to another sync group".to_string())
            }
            Some(_) => return Err("transfer is not waiting for acceptance".to_string()),
            None => return Err("transfer not found".to_string()),
        }
    };
    let save_path = pick_save_path(&app, &pending_for_dialog.file_name)?;
    ensure_receive_destination_available(&save_path)?;
    let part_path = part_path_for(&save_path);
    ensure_receive_destination_available(&part_path)?;
    {
        let settings = state.settings.lock().await;
        ensure_expected_active_group(&settings, &network_id, "accepting the file transfer")?;
    }

    let pending = {
        let mut transfers = state.file_transfers.lock().await;
        match transfers.remove(&session_id) {
            Some(TransferRecord::PendingIncoming(pending)) => pending,
            Some(other) => {
                transfers.insert(session_id.clone(), other);
                return Err("transfer is not waiting for acceptance".to_string());
            }
            None => return Err("transfer not found".to_string()),
        }
    };

    let timeout_token = new_timeout_token();
    let (stun_servers, transfer_timeout_minutes) = {
        let settings = state.settings.lock().await;
        (
            settings.stun_servers.clone(),
            settings.transfer_timeout_minutes,
        )
    };
    let peer = match new_peer_connection(stun_servers).await {
        Ok(peer) => peer,
        Err(e) => {
            state
                .file_transfers
                .lock()
                .await
                .insert(session_id.clone(), TransferRecord::PendingIncoming(pending));
            return Err(e);
        }
    };
    {
        let transfers = state.file_transfers.lock().await;
        if let Err(e) = ensure_transfer_capacity(&transfers) {
            state
                .file_transfers
                .lock()
                .await
                .insert(session_id.clone(), TransferRecord::PendingIncoming(pending));
            let _ = peer.close().await;
            return Err(e);
        }
    }
    install_peer_state_handler(
        &peer,
        app.clone(),
        state.inner().clone(),
        session_id.clone(),
        pending.size,
    );

    let offer: RTCSessionDescription = match serde_json::from_str(&pending.offer_sdp_json) {
        Ok(offer) => offer,
        Err(e) => {
            let _ = peer.close().await;
            state
                .file_transfers
                .lock()
                .await
                .insert(session_id.clone(), TransferRecord::PendingIncoming(pending));
            return Err(e.to_string());
        }
    };
    if let Err(e) = peer.set_remote_description(offer).await {
        let _ = peer.close().await;
        state
            .file_transfers
            .lock()
            .await
            .insert(session_id.clone(), TransferRecord::PendingIncoming(pending));
        return Err(e.to_string());
    }
    let answer = match peer.create_answer(None).await {
        Ok(answer) => answer,
        Err(e) => {
            let _ = peer.close().await;
            state
                .file_transfers
                .lock()
                .await
                .insert(session_id.clone(), TransferRecord::PendingIncoming(pending));
            return Err(e.to_string());
        }
    };
    let mut gather_complete = peer.gathering_complete_promise().await;
    if let Err(e) = peer.set_local_description(answer).await {
        let _ = peer.close().await;
        state
            .file_transfers
            .lock()
            .await
            .insert(session_id.clone(), TransferRecord::PendingIncoming(pending));
        return Err(e.to_string());
    }
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(ICE_GATHER_TIMEOUT_SECS),
        gather_complete.recv(),
    )
    .await;
    let Some(local) = peer.local_description().await else {
        let _ = peer.close().await;
        state
            .file_transfers
            .lock()
            .await
            .insert(session_id.clone(), TransferRecord::PendingIncoming(pending));
        return Err("failed to create local WebRTC answer".to_string());
    };
    let sdp_json = match serde_json::to_string(&local) {
        Ok(sdp_json) => sdp_json,
        Err(e) => {
            let _ = peer.close().await;
            state
                .file_transfers
                .lock()
                .await
                .insert(session_id.clone(), TransferRecord::PendingIncoming(pending));
            return Err(e.to_string());
        }
    };
    if let Err(e) = validate_sdp_json(&sdp_json) {
        let _ = peer.close().await;
        state
            .file_transfers
            .lock()
            .await
            .insert(session_id.clone(), TransferRecord::PendingIncoming(pending));
        return Err(e);
    }

    let file = match create_new_file(&part_path).await {
        Ok(file) => file,
        Err(e) => {
            let _ = peer.close().await;
            state
                .file_transfers
                .lock()
                .await
                .insert(session_id.clone(), TransferRecord::PendingIncoming(pending));
            return Err(e);
        }
    };
    install_receiver_channel(
        &peer,
        app.clone(),
        state.inner().clone(),
        ReceiverWriteState {
            session_id: session_id.clone(),
            file_name: pending.file_name.clone(),
            total: pending.size,
            received: 0,
            next_index: 0,
            content_key: pending.content_key,
            nonce_prefix: pending.nonce_prefix,
            file: Some(file),
            final_path: save_path.clone(),
            part_path: part_path.clone(),
            hasher: Sha256::new(),
            done: false,
        },
    );

    state.file_transfers.lock().await.insert(
        session_id.clone(),
        TransferRecord::Incoming(IncomingTransfer {
            sender_id: pending.sender_id.clone(),
            peer: peer.clone(),
            part_path,
            timeout_token,
        }),
    );
    spawn_transfer_timeout(
        app.clone(),
        state.inner().clone(),
        session_id.clone(),
        timeout_token,
        transfer_timeout_minutes,
    );

    let (topic, epoch) = current_room_topic_epoch(state.inner()).await?;
    let recipient = active_device_identity(state.inner(), &pending.sender_id).await?;
    let peer_label = recipient.label.clone();
    if let Err(e) = publish_file_signal(
        state.inner(),
        &topic,
        epoch,
        &recipient,
        FileSignal::Answer {
            session_id: session_id.clone(),
            sdp_json,
        },
        "file-answer",
    )
    .await
    {
        cleanup_transfer(state.inner(), &session_id).await;
        return Err(e);
    }

    Ok(TransferDto {
        session_id,
        file_name: pending.file_name,
        size: pending.size,
        peer_label,
        direction: "incoming".to_string(),
        status: "connecting".to_string(),
    })
}

#[tauri::command]
pub async fn reject_file_transfer(
    state: State<'_, Arc<AppState>>,
    session_id: String,
) -> Result<(), String> {
    let pending = {
        let mut transfers = state.file_transfers.lock().await;
        match transfers.remove(&session_id) {
            Some(TransferRecord::PendingIncoming(pending)) => pending,
            Some(other) => {
                transfers.insert(session_id.clone(), other);
                return Err("transfer is not waiting for rejection".to_string());
            }
            None => return Ok(()),
        }
    };
    let (topic, epoch) = current_room_topic_epoch(state.inner()).await?;
    let recipient = active_device_identity(state.inner(), &pending.sender_id).await?;
    publish_file_signal(
        state.inner(),
        &topic,
        epoch,
        &recipient,
        FileSignal::Reject {
            session_id,
            reason: "Declined".to_string(),
        },
        "file-reject",
    )
    .await
}

#[tauri::command]
pub async fn cancel_file_transfer(
    state: State<'_, Arc<AppState>>,
    session_id: String,
) -> Result<(), String> {
    let record = state.file_transfers.lock().await.remove(&session_id);
    match record {
        Some(TransferRecord::Outgoing(outgoing)) => {
            let _ = outgoing.peer.close().await;
            let (topic, epoch) = current_room_topic_epoch(state.inner()).await?;
            let recipient = active_device_identity(state.inner(), &outgoing.recipient_id).await?;
            publish_file_signal(
                state.inner(),
                &topic,
                epoch,
                &recipient,
                FileSignal::Cancel {
                    session_id,
                    reason: "Cancelled".to_string(),
                },
                "file-cancel",
            )
            .await
        }
        Some(TransferRecord::Incoming(incoming)) => {
            let _ = incoming.peer.close().await;
            let _ = tokio::fs::remove_file(&incoming.part_path).await;
            let (topic, epoch) = current_room_topic_epoch(state.inner()).await?;
            let recipient = active_device_identity(state.inner(), &incoming.sender_id).await?;
            publish_file_signal(
                state.inner(),
                &topic,
                epoch,
                &recipient,
                FileSignal::Cancel {
                    session_id,
                    reason: "Cancelled".to_string(),
                },
                "file-cancel",
            )
            .await
        }
        Some(TransferRecord::PendingIncoming(_)) | None => Ok(()),
    }
}

#[tauri::command]
pub async fn reveal_received_file(
    state: State<'_, Arc<AppState>>,
    path: String,
) -> Result<(), String> {
    let path = completed_received_file_path(state.inner(), Path::new(&path)).await?;
    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|_| "Received file no longer exists at its saved location".to_string())?;
    if !metadata.is_file() {
        return Err("Received file no longer exists at its saved location".to_string());
    }
    reveal_path_in_file_manager(&path)
}

fn new_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn new_timeout_token() -> u64 {
    let mut bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut bytes);
    u64::from_be_bytes(bytes)
}

async fn current_room_topic_epoch(state: &Arc<AppState>) -> Result<(String, u64), String> {
    let guard = state.roster.lock().await;
    let verified = guard.as_ref().ok_or("not in a room")?;
    Ok((verified.topic().to_string(), verified.epoch()))
}

async fn active_device_identity(
    state: &Arc<AppState>,
    device_id: &crypto::Ed25519PubKey,
) -> Result<roster::DeviceIdentity, String> {
    let guard = state.roster.lock().await;
    let verified = guard.as_ref().ok_or("not in a room")?;
    verified
        .entry
        .devices
        .iter()
        .find(|d| &d.signing_pub == device_id)
        .cloned()
        .ok_or_else(|| "recipient is not an active device".to_string())
}

async fn recipient_for_transfer(
    state: &Arc<AppState>,
    recipient: &crypto::Ed25519PubKey,
) -> Result<(String, roster::DeviceIdentity, String, u64), String> {
    let guard = state.roster.lock().await;
    let verified = guard.as_ref().ok_or("not in a room")?;
    if recipient == &state.device.signing_pub {
        return Err("choose another device".to_string());
    }
    let identity = verified
        .entry
        .devices
        .iter()
        .find(|d| &d.signing_pub == recipient)
        .cloned()
        .ok_or_else(|| "recipient is not an active device".to_string())?;
    Ok((
        identity.label.clone(),
        identity,
        verified.topic().to_string(),
        verified.epoch(),
    ))
}

async fn publish_file_signal(
    state: &Arc<AppState>,
    topic: &str,
    epoch: u64,
    recipient: &roster::DeviceIdentity,
    signal: FileSignal,
    title: &str,
) -> Result<(), String> {
    let bytes = postcard::to_allocvec(&signal).map_err(|e| e.to_string())?;
    let text = format!(
        "{}{}",
        FILE_SIGNAL_PREFIX,
        base64::engine::general_purpose::STANDARD.encode(bytes)
    );
    let sealed = crypto::seal_clip(
        &state.device,
        &[crypto::Recipient {
            id: recipient.signing_pub.clone(),
            x25519: recipient.x25519_pub.clone(),
        }],
        &text,
        topic,
        epoch,
        StorePolicy::Private,
        now_unix(),
    )
    .map_err(|e| e.to_string())?;
    let base = state.ntfy_base.lock().await.clone();
    publish_sealed_clip(&base, topic, sealed, ntfy::PublishOptions::default())
        .await
        .map_err(|e| format!("{title}: {e}"))
}

pub(super) fn decode_file_signal(text: &str) -> Result<Option<FileSignal>, String> {
    let Some(b64) = text.strip_prefix(FILE_SIGNAL_PREFIX) else {
        return Ok(None);
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| e.to_string())?;
    postcard::from_bytes(&bytes)
        .map(Some)
        .map_err(|e| e.to_string())
}

pub(super) async fn handle_file_signal(
    state: &Arc<AppState>,
    app: &tauri::AppHandle,
    network_id: String,
    sender_id: crypto::Ed25519PubKey,
    signal: FileSignal,
) {
    match signal {
        FileSignal::Offer {
            session_id,
            file_name,
            size,
            content_key,
            nonce_prefix,
            sdp_json,
        } => {
            if !is_valid_session_id(&session_id) {
                eprintln!("file offer ignored: invalid session id");
                return;
            }
            if let Err(e) = validate_sdp_json(&sdp_json) {
                eprintln!("file offer ignored: {e}");
                return;
            }
            let file_name = safe_default_file_name(&file_name);
            let sender_label = active_device_identity(state, &sender_id)
                .await
                .map(|d| d.label)
                .unwrap_or_else(|_| hex::encode(&sender_id.0[..4]));
            let timeout_token = new_timeout_token();
            let transfer_timeout_minutes = state.settings.lock().await.transfer_timeout_minutes;
            {
                let mut transfers = state.file_transfers.lock().await;
                if transfers.contains_key(&session_id) {
                    eprintln!("file offer ignored: duplicate session id");
                    return;
                }
                if let Err(e) = ensure_transfer_capacity(&transfers) {
                    eprintln!("file offer ignored: {e}");
                    return;
                }
                transfers.insert(
                    session_id.clone(),
                    TransferRecord::PendingIncoming(PendingIncomingTransfer {
                        network_id: network_id.clone(),
                        sender_id: sender_id.clone(),
                        file_name: file_name.clone(),
                        size,
                        content_key,
                        nonce_prefix,
                        offer_sdp_json: sdp_json,
                        timeout_token,
                    }),
                );
            }
            spawn_transfer_timeout(
                app.clone(),
                state.clone(),
                session_id.clone(),
                timeout_token,
                transfer_timeout_minutes,
            );
            let _ = app.emit(
                "file-offer-received",
                FileOfferDto {
                    session_id,
                    network_id,
                    sender_id: hex::encode(sender_id.0),
                    sender_label,
                    file_name,
                    size,
                },
            );
            let _ = reveal_main_window(app);
        }
        FileSignal::Answer {
            session_id,
            sdp_json,
        } => {
            if !is_valid_session_id(&session_id) {
                return;
            }
            if let Err(e) = validate_sdp_json(&sdp_json) {
                emit_file_failed(app, state, &session_id, &e).await;
                return;
            }
            let peer = {
                let transfers = state.file_transfers.lock().await;
                match transfers.get(&session_id) {
                    Some(TransferRecord::Outgoing(outgoing))
                        if outgoing.recipient_id == sender_id =>
                    {
                        Some(outgoing.peer.clone())
                    }
                    Some(TransferRecord::Outgoing(_)) => {
                        eprintln!("file answer ignored: sender did not match transfer");
                        None
                    }
                    _ => None,
                }
            };
            let Some(peer) = peer else {
                return;
            };
            match serde_json::from_str::<RTCSessionDescription>(&sdp_json) {
                Ok(answer) => {
                    if let Err(e) = peer.set_remote_description(answer).await {
                        emit_file_failed(app, state, &session_id, &format!("{e}")).await;
                    }
                }
                Err(e) => emit_file_failed(app, state, &session_id, &e.to_string()).await,
            }
        }
        FileSignal::Reject { session_id, reason } => {
            if !is_valid_session_id(&session_id) {
                return;
            }
            let record = {
                let mut transfers = state.file_transfers.lock().await;
                let matches_sender = matches!(
                    transfers.get(&session_id),
                    Some(TransferRecord::Outgoing(outgoing)) if outgoing.recipient_id == sender_id
                );
                if matches_sender {
                    transfers.remove(&session_id)
                } else {
                    None
                }
            };
            if record.is_none() {
                return;
            }
            cleanup_transfer_record(record).await;
            let _ = app.emit(
                "file-transfer-cancelled",
                FileTransferProgressDto {
                    session_id,
                    transferred: 0,
                    total: 0,
                    status: "rejected".to_string(),
                    message: reason,
                },
            );
        }
        FileSignal::Cancel { session_id, reason } => {
            if !is_valid_session_id(&session_id) {
                return;
            }
            let record = remove_transfer_matching_sender(state, &session_id, &sender_id).await;
            if record.is_none() {
                return;
            }
            cleanup_transfer_record(record).await;
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
    }
}
