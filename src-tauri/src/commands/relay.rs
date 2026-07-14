//! Relay subscriptions, wire publishing, and incoming-message dispatch.

use super::*;

async fn spawn_relay_message_pump(
    state: &Arc<AppState>,
    app: tauri::AppHandle,
    topic: String,
) -> tokio::sync::oneshot::Sender<()> {
    let base = state.ntfy_base.lock().await.clone();
    let since = state.last_msg_ids.lock().await.get(&topic).cloned();
    let cfg = ntfy::SubscribeConfig {
        base,
        topic: topic.clone(),
        since,
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ntfy::RelayMessage>(64);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    ntfy::spawn_subscriber(cfg, tx, shutdown_rx);

    let state_clone = state.clone();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if msg.payload.is_empty() {
                continue;
            }
            state_clone
                .last_msg_ids
                .lock()
                .await
                .insert(topic.clone(), msg.id.clone());
            handle_relay_message(&state_clone, &app, &topic, msg).await;
        }
    });

    shutdown_tx
}

/// Spawn (or replace) the ntfy subscriber for the given topic. Messages are
/// reassembled + verified + decrypted via `handle_relay_message`.
pub async fn start_subscriber(state: &Arc<AppState>, app: tauri::AppHandle, topic: &str) {
    // Shut down any existing subscriber (e.g. on topic rotation).
    if let Some(tx) = state.subscriber_shutdown.lock().await.take() {
        let _ = tx.send(());
    }

    let shutdown_tx = spawn_relay_message_pump(state, app, topic.to_string()).await;
    *state.subscriber_shutdown.lock().await = Some(shutdown_tx);
}

/// Start a subscriber that coexists with the active room subscription. Used
/// for durable invitation rendezvous and a joiner's pending approval channel.
pub(super) async fn start_auxiliary_subscriber(
    state: &Arc<AppState>,
    app: tauri::AppHandle,
    key: String,
    topic: String,
) {
    stop_auxiliary_subscriber(state, &key).await;

    let shutdown_tx = spawn_relay_message_pump(state, app, topic).await;
    state
        .auxiliary_subscriber_shutdowns
        .lock()
        .await
        .insert(key, shutdown_tx);
}

pub(super) async fn stop_auxiliary_subscriber(state: &Arc<AppState>, key: &str) {
    if let Some(tx) = state
        .auxiliary_subscriber_shutdowns
        .lock()
        .await
        .remove(key)
    {
        let _ = tx.send(());
    }
}

pub async fn start_invitation_subscribers(state: &Arc<AppState>, app: tauri::AppHandle) {
    let now = now_unix();
    let active_network_id = current_network_identity(state).await.ok().map(|(id, _)| id);
    let invites: Vec<InvitationRecord> = state
        .invitations
        .lock()
        .await
        .values()
        .filter(|invite| {
            active_network_id.as_ref() == Some(&invite.network_id) && invite.is_active_at(now)
        })
        .cloned()
        .collect();
    let desired_keys: HashSet<String> = invites
        .iter()
        .map(|invite| format!("invite:{}", invite.id))
        .collect();
    let stale = {
        let mut shutdowns = state.auxiliary_subscriber_shutdowns.lock().await;
        let keys: Vec<String> = shutdowns
            .keys()
            .filter(|key| key.starts_with("invite:") && !desired_keys.contains(*key))
            .cloned()
            .collect();
        keys.into_iter()
            .filter_map(|key| shutdowns.remove(&key))
            .collect::<Vec<_>>()
    };
    for tx in stale {
        let _ = tx.send(());
    }

    for invite in invites {
        let key = format!("invite:{}", invite.id);
        if state
            .auxiliary_subscriber_shutdowns
            .lock()
            .await
            .contains_key(&key)
        {
            continue;
        }
        start_auxiliary_subscriber(
            state,
            app.clone(),
            key.clone(),
            crate::pairing::rendezvous_topic(&invite.secret),
        )
        .await;
        if let Some(expires_at) = invite.expires_at {
            let state_clone = state.clone();
            let invite_id = invite.id.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(
                    expires_at.saturating_sub(now_unix()),
                ))
                .await;
                let removed = state_clone
                    .invitations
                    .lock()
                    .await
                    .remove(&invite_id)
                    .is_some();
                if removed {
                    let _ = persist_invitations(&state_clone).await;
                }
                state_clone
                    .pending_joins
                    .lock()
                    .await
                    .retain(|_, pending| pending.request.invite_id != invite_id);
                stop_auxiliary_subscriber(&state_clone, &format!("invite:{invite_id}")).await;
            });
        }
    }
}

pub(super) fn schedule_subscriber_switch(
    state: &Arc<AppState>,
    app: &tauri::AppHandle,
    topic: String,
) {
    let state_clone = state.clone();
    let app_clone = app.clone();
    tokio::spawn(async move {
        start_subscriber(&state_clone, app_clone, &topic).await;
    });
}

pub(super) async fn publish_wire(
    base: &str,
    topic: &str,
    wire: WireMessage,
    title: &str,
) -> Result<(), String> {
    publish_wire_with_options(base, topic, wire, title, ntfy::PublishOptions::default()).await
}

async fn publish_wire_with_options(
    base: &str,
    topic: &str,
    wire: WireMessage,
    title: &str,
    options: ntfy::PublishOptions,
) -> Result<(), String> {
    let msg = postcard::to_allocvec(&wire).map_err(|e| e.to_string())?;
    ntfy::publish_with_options(base, topic, &msg, title, options)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

pub(super) async fn publish_sealed_clip(
    base: &str,
    topic: &str,
    sealed: crypto::SealedClip,
    options: ntfy::PublishOptions,
) -> Result<(), String> {
    publish_wire_with_options(
        base,
        topic,
        WireMessage::Manifest(sealed.manifest),
        "clip",
        options,
    )
    .await?;
    for chunk in sealed.chunks {
        publish_wire_with_options(base, topic, WireMessage::Chunk(chunk), "clip", options).await?;
    }
    Ok(())
}

pub(super) async fn publish_sealed_clip_attachment(
    base: &str,
    topic: &str,
    sealed: crypto::SealedClip,
    options: ntfy::PublishOptions,
) -> Result<(), String> {
    let notice = postcard::to_allocvec(&WireMessage::ClipAttachment(sealed.manifest))
        .map_err(|e| e.to_string())?;
    let attachment = encode_attachment_chunks(&sealed.chunks)?;
    ntfy::publish_attachment_with_options(base, topic, &notice, attachment, options)
        .await
        .map_err(|e| e.to_string())
}

fn encode_attachment_chunks(chunks: &[crypto::Chunk]) -> Result<Vec<u8>, String> {
    if chunks.is_empty() || chunks.len() > MAX_ATTACHMENT_CLIP_CHUNKS as usize {
        return Err("encrypted clip has an invalid attachment chunk count".to_string());
    }
    let mut encoded = Vec::new();
    for chunk in chunks {
        let ct_len = u32::try_from(chunk.ct.len()).map_err(|_| "clip chunk is too large")?;
        encoded.extend_from_slice(&chunk.msg_id);
        encoded.extend_from_slice(&chunk.index.to_be_bytes());
        encoded.extend_from_slice(&chunk.nonce);
        encoded.extend_from_slice(&ct_len.to_be_bytes());
        encoded.extend_from_slice(&chunk.ct);
    }
    if encoded.len() > ntfy::MAX_ATTACHMENT_BYTES {
        return Err("encrypted clip exceeds the relay attachment limit".to_string());
    }
    Ok(encoded)
}

fn decode_attachment_chunks(
    encoded: &[u8],
    expected_count: u32,
) -> Result<Vec<crypto::Chunk>, String> {
    const HEADER_BYTES: usize = 16 + 4 + 24 + 4;
    if expected_count == 0 || expected_count > MAX_ATTACHMENT_CLIP_CHUNKS {
        return Err("encrypted clip has an invalid attachment chunk count".to_string());
    }
    let mut remaining = encoded;
    let mut chunks = Vec::with_capacity(expected_count as usize);
    for _ in 0..expected_count {
        if remaining.len() < HEADER_BYTES {
            return Err("encrypted clip attachment is truncated".to_string());
        }
        let mut msg_id = [0u8; 16];
        msg_id.copy_from_slice(&remaining[..16]);
        let index = u32::from_be_bytes(remaining[16..20].try_into().unwrap());
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&remaining[20..44]);
        let ct_len = u32::from_be_bytes(remaining[44..48].try_into().unwrap()) as usize;
        remaining = &remaining[HEADER_BYTES..];
        if ct_len > crypto::CHUNK_SIZE + 16 || remaining.len() < ct_len {
            return Err("encrypted clip attachment has an invalid chunk size".to_string());
        }
        let ct = remaining[..ct_len].to_vec();
        remaining = &remaining[ct_len..];
        chunks.push(crypto::Chunk {
            msg_id,
            index,
            nonce,
            ct,
        });
    }
    if !remaining.is_empty() {
        return Err("encrypted clip attachment has trailing data".to_string());
    }
    Ok(chunks)
}

async fn validate_inbound_manifest(
    state: &Arc<AppState>,
    source_topic: &str,
    manifest: &crypto::Manifest,
    max_chunks: u32,
) -> bool {
    let output_size = match manifest.payload_type {
        crypto::PayloadType::Text => manifest.declared_size,
        crypto::PayloadType::DeflateText { original_size } => original_size,
    };
    if manifest.chunk_count == 0
        || manifest.chunk_count > max_chunks
        || manifest.declared_size > crypto::MAX_TEXT_BYTES as u64
        || output_size > crypto::MAX_TEXT_BYTES as u64
    {
        eprintln!(
            "[relay] rejecting manifest with unsafe size/count: {} bytes, {} chunks",
            manifest.declared_size, manifest.chunk_count
        );
        return false;
    }
    let verified = match state.roster.lock().await.clone() {
        Some(verified) => verified,
        None => return false,
    };
    if source_topic != verified.topic()
        || manifest.room_id != verified.topic()
        || manifest.roster_epoch != verified.epoch()
        || manifest.sender_id == state.device.signing_pub
        || !verified.is_active(&manifest.sender_id)
        || !manifest
            .recipients
            .iter()
            .any(|wrap| wrap.recipient_id == state.device.signing_pub)
    {
        return false;
    }
    if let Err(error) = crypto::verify_manifest_sig(manifest) {
        eprintln!("[relay] rejecting unauthenticated manifest: {error}");
        return false;
    }
    match state.store.has_seen_message(&manifest.msg_id) {
        Ok(seen) => !seen,
        Err(error) => {
            eprintln!("[relay] replay cache check failed: {error}");
            false
        }
    }
}

/// Process an incoming relay message: reassemble manifest+chunks, verify,
/// decrypt, emit a Tauri event. Called from the subscriber pump.
pub async fn handle_relay_message(
    state: &Arc<AppState>,
    app: &tauri::AppHandle,
    source_topic: &str,
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
            if !validate_inbound_manifest(state, source_topic, &manifest, MAX_RELAY_CLIP_CHUNKS)
                .await
            {
                return;
            }
            let msg_id = manifest.msg_id;
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
            drop(pending);
            let state_clone = state.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(PENDING_CLIP_TTL_SECS)).await;
                state_clone.pending.lock().await.remove(&msg_id);
            });
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
        WireMessage::ClipAttachment(manifest) => {
            if !validate_inbound_manifest(
                state,
                source_topic,
                &manifest,
                MAX_ATTACHMENT_CLIP_CHUNKS,
            )
            .await
            {
                return;
            }
            let attachment = match msg.attachment.as_ref() {
                Some(attachment) => attachment,
                None => {
                    eprintln!("[relay] clip attachment notice has no attachment metadata");
                    return;
                }
            };
            let base = state.ntfy_base.lock().await.clone();
            let mut downloaded = None;
            for attempt in 0..3 {
                match ntfy::download_attachment(&base, attachment).await {
                    Ok(bytes) => {
                        downloaded = Some(bytes);
                        break;
                    }
                    Err(error) if attempt < 2 => {
                        eprintln!("[relay] clip attachment download retry: {error}");
                        tokio::time::sleep(std::time::Duration::from_secs(1 << attempt)).await;
                    }
                    Err(error) => {
                        eprintln!("[relay] clip attachment download failed: {error}");
                    }
                }
            }
            let Some(downloaded) = downloaded else {
                return;
            };
            let chunks = match decode_attachment_chunks(&downloaded, manifest.chunk_count) {
                Ok(chunks) => chunks,
                Err(error) => {
                    eprintln!("[relay] clip attachment decode failed: {error}");
                    return;
                }
            };
            try_open_clip(state, app, manifest, chunks).await;
        }
        WireMessage::PairingJoin(envelope) => {
            let now = now_unix();
            let invite = match state
                .invitations
                .lock()
                .await
                .get(&envelope.invite_id)
                .cloned()
            {
                Some(invite) if invite.is_active_at(now) => invite,
                _ => return,
            };
            if source_topic != crate::pairing::rendezvous_topic(&invite.secret) {
                return;
            }
            let current_network_id = match current_network_identity(state).await {
                Ok((id, _)) => id,
                Err(_) => return,
            };
            let verified = match state.roster.lock().await.clone() {
                Some(roster) if roster.entry.admin_id == state.device.signing_pub => roster,
                _ => return,
            };
            if invite.network_id != current_network_id {
                return;
            }
            let info = pairing_bootstrap_info(&invite.id, "join");
            let plaintext = match crypto::open_bootstrap(&state.device, &info, &envelope.sealed) {
                Ok(plaintext) => plaintext,
                Err(e) => {
                    eprintln!("[pairing] encrypted join rejected: {e}");
                    return;
                }
            };
            let request =
                match postcard::from_bytes::<crate::pairing::NetworkJoinRequest>(&plaintext) {
                    Ok(request) => request,
                    Err(_) => return,
                };
            if request.invite_id != invite.id
                || request.requested_at > now.saturating_add(60)
                || now.saturating_sub(request.requested_at) > JOIN_REQUEST_MAX_AGE_SECS
                || crate::pairing::verify_network_join_request(&request, &invite.secret).is_err()
            {
                return;
            }
            if verified
                .entry
                .devices
                .iter()
                .any(|device| device.signing_pub == request.identity.signing_pub)
            {
                return;
            }
            let request_id = hex::encode(request.identity.signing_pub.0);
            state.pending_joins.lock().await.insert(
                request_id.clone(),
                PendingJoinRecord {
                    request_id: request_id.clone(),
                    network_id: invite.network_id,
                    rendezvous_topic: source_topic.to_string(),
                    request,
                    received_at: now,
                },
            );
            let _ = app.emit("join-requested", request_id);
        }
        WireMessage::PairingGrant(grant) => {
            if grant.recipient_id != state.device.signing_pub {
                return;
            }
            let pending = match state.pending_network_join.lock().await.clone() {
                Some(pending)
                    if pending.invite_id == grant.invite_id
                        && pending.rendezvous_topic == source_topic =>
                {
                    pending
                }
                _ => return,
            };
            let info = pairing_bootstrap_info(&grant.invite_id, "grant");
            let plaintext = match crypto::open_bootstrap(&state.device, &info, &grant.sealed) {
                Ok(plaintext) => plaintext,
                Err(e) => {
                    eprintln!("[pairing] roster grant rejected: {e}");
                    return;
                }
            };
            let payload = match postcard::from_bytes::<PairingRosterPayload>(&plaintext) {
                Ok(payload) => payload,
                Err(_) => return,
            };
            let verified = match verify_persisted_roster_entries(payload.roster_chain.clone()) {
                Ok(verified) => verified,
                Err(e) => {
                    eprintln!("[pairing] roster chain rejected: {e}");
                    return;
                }
            };
            if verified.entry.admin_id != pending.admin_pub
                || !verified.is_active(&state.device.signing_pub)
            {
                return;
            }

            let chain = PersistedRosterChain {
                version: 2,
                entries: payload.roster_chain,
            };
            let bytes = match postcard::to_allocvec(&chain) {
                Ok(bytes) => bytes,
                Err(_) => return,
            };
            if let Some(path) = state.roster_path.lock().await.clone() {
                if std::fs::write(path, bytes).is_err() {
                    return;
                }
            }
            if current_sync_group_id(state).await.is_err() {
                return;
            }
            let topic = verified.topic().to_string();
            *state.roster.lock().await = Some(verified);
            *state.pending_network_join.lock().await = None;
            if let Some(tx) = state
                .auxiliary_subscriber_shutdowns
                .lock()
                .await
                .remove(&format!("pending:{}", grant.invite_id))
            {
                let _ = tx.send(());
            }
            schedule_subscriber_switch(state, app, topic);
            let _ = app.emit("roster-updated", ());
            let _ = app.emit("join-approved", ());
        }
        WireMessage::DeleteClip(msg) => {
            handle_delete_clip(state, app, msg).await;
        }
        WireMessage::RenameDevice(msg) => {
            handle_rename_device(state, app, msg).await;
        }
        WireMessage::Roster(entry) => {
            eprintln!(
                "[relay] Roster epoch {} ({} devices)",
                entry.epoch,
                entry.devices.len()
            );
            let current = state.roster.lock().await.clone();
            if let Some(prev) = current {
                // Normal update: only accept strictly newer epochs.
                if entry.epoch > prev.epoch() {
                    let old_topic = prev.topic().to_string();
                    match prev.verify_next(entry.clone()) {
                        Ok(next) => {
                            let new_topic = next.topic().to_string();
                            *state.roster.lock().await = Some(next.clone());
                            cancel_transfers_not_in_roster(state, app, &next).await;
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
        }
    }
}

async fn handle_rename_device(
    state: &Arc<AppState>,
    app: &tauri::AppHandle,
    msg: RenameDeviceMessage,
) {
    let label = match sanitize_device_label(&msg.label) {
        Ok(label) => label,
        Err(e) => {
            eprintln!("[relay] rename rejected: {e}");
            return;
        }
    };
    if let Err(e) = verify_rename_device_sig(&msg) {
        eprintln!("[relay] rename rejected: {e}");
        return;
    }

    let verified = match state.roster.lock().await.clone() {
        Some(v) => v,
        None => return,
    };
    if state.device.signing_pub != verified.entry.admin_id {
        return;
    }
    if msg.room_id != verified.topic() || msg.roster_epoch != verified.epoch() {
        eprintln!("[relay] rename rejected: room or epoch mismatch");
        return;
    }
    if !verified.is_active(&msg.device_id) {
        eprintln!("[relay] rename rejected: sender is not active");
        return;
    }

    let unsigned = match roster::build_update_device_label(&verified.entry, &msg.device_id, &label)
    {
        Ok(entry) => entry,
        Err(e) => {
            eprintln!("[relay] rename rejected: {e}");
            return;
        }
    };
    match roster::sign_and_chain(&state.device, unsigned, Some(&verified.entry)) {
        Ok(signed) => match verified.verify_next(signed.clone()) {
            Ok(next) => {
                let topic = next.topic().to_string();
                *state.roster.lock().await = Some(next.clone());
                cancel_transfers_not_in_roster(state, app, &next).await;
                persist_roster(state, &signed).await;
                broadcast_roster(state, &signed, &topic).await;
                let _ = app.emit("roster-updated", ());
            }
            Err(e) => eprintln!("roster verify_next failed: {e}"),
        },
        Err(e) => eprintln!("roster sign failed: {e}"),
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
            match decode_file_signal(&o.plaintext) {
                Ok(Some(signal)) => {
                    handle_file_signal(state, app, o.sender_id.clone(), signal).await;
                    return;
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("file signal decode failed: {e}");
                    return;
                }
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
                if let Ok(group_id) = current_sync_group_id(state).await {
                    let _ = state.store.insert_with_msg_id_in_group(
                        &group_id,
                        &o.sender_id,
                        o.ts,
                        &o.plaintext,
                        Some(&manifest.msg_id),
                    );
                }
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

pub(super) fn encode_roster_move(entry: &roster::RosterEntry) -> Result<String, String> {
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

pub(super) async fn apply_roster_update(
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

    *state.roster.lock().await = Some(next.clone());
    cancel_transfers_not_in_roster(state, app, &next).await;
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

pub(super) fn parse_device_id(device_id: &str) -> Result<crypto::Ed25519PubKey, String> {
    let decoded = hex::decode(device_id.trim()).map_err(|_| "bad device id".to_string())?;
    if decoded.len() != 32 {
        return Err("bad device id".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(crypto::Ed25519PubKey(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(index: u32, fill: u8) -> crypto::Chunk {
        crypto::Chunk {
            msg_id: [7; 16],
            index,
            nonce: [fill; 24],
            ct: vec![fill; crypto::CHUNK_SIZE + 16],
        }
    }

    #[test]
    fn attachment_chunk_framing_roundtrips_without_unbounded_lengths() {
        let chunks = vec![chunk(0, 1), chunk(1, 2)];
        let encoded = encode_attachment_chunks(&chunks).unwrap();
        let decoded = decode_attachment_chunks(&encoded, 2).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].msg_id, chunks[0].msg_id);
        assert_eq!(decoded[1].index, 1);
        assert_eq!(decoded[1].nonce, chunks[1].nonce);
        assert_eq!(decoded[1].ct, chunks[1].ct);
    }

    #[test]
    fn attachment_chunk_framing_rejects_truncation_and_trailing_data() {
        let encoded = encode_attachment_chunks(&[chunk(0, 3)]).unwrap();
        assert!(decode_attachment_chunks(&encoded[..encoded.len() - 1], 1).is_err());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_attachment_chunks(&trailing, 1).is_err());
        assert!(decode_attachment_chunks(&[], u32::MAX).is_err());
    }

    #[test]
    fn maximum_clip_attachment_stays_under_transport_ceiling() {
        let chunks = (0..MAX_ATTACHMENT_CLIP_CHUNKS)
            .map(|index| chunk(index, index as u8))
            .collect::<Vec<_>>();

        assert!(encode_attachment_chunks(&chunks).unwrap().len() <= ntfy::MAX_ATTACHMENT_BYTES);
    }
}
