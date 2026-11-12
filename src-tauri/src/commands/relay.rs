//! Relay subscriptions, wire publishing, and incoming-message dispatch.

use super::*;

const GROUP_REMOVAL_NOTICE_MARKER: &str = "fwoosh-group-removal-v1";
// A fresh process has no in-memory ntfy message cursor. Ask the relay for its
// normal cache window in that case; authenticated envelope/replay validation
// makes duplicate cached messages safe to process. Private sends still opt out
// of relay caching and therefore remain live-delivery only.
const COLD_START_CATCH_UP: &str = "12h";

const MAX_FUTURE_EPOCH_GAP: u64 = 32;
const MAX_DEFERRED_FUTURE_CLIPS: usize = 8;
const DEFERRED_FUTURE_CLIP_TTL: std::time::Duration = std::time::Duration::from_secs(30);
const ROSTER_SYNC_REQUEST_MAX_AGE_SECS: u64 = 5 * 60;
const ROSTER_SYNC_REQUEST_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(10);
const ROSTER_SYNC_BROADCAST_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(5);
const STALE_SEND_RESYNC_NOTICE_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) trait RelayRuntime: Send + Sync {
    fn emit_join_requested(&self, _request_id: String) {}
    fn emit_roster_updated(&self) {}
    fn emit_join_approved(&self) {}
    fn emit_clip_stored(&self) {}
    fn emit_roster_resynced_after_send(&self, _new_epoch: u64) {}
    fn on_clip_received(
        &self,
        _sender_label: String,
        _clip_preview: String,
        _text: String,
        _ts: u64,
    ) {
    }
    fn switch_subscriber(&self, _state: &Arc<AppState>, _topic: String) {}
    fn on_roster_changed<'a>(
        &'a self,
        _state: &'a Arc<AppState>,
        _next: &'a VerifiedRoster,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
    fn on_stale_epoch_transfers<'a>(
        &'a self,
        _state: &'a Arc<AppState>,
        _new_epoch: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
    fn on_file_signal<'a>(
        &'a self,
        _state: &'a Arc<AppState>,
        _network_id: String,
        _sender_id: crypto::Ed25519PubKey,
        _signal: FileSignal,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
    fn on_group_removal<'a>(
        &'a self,
        _state: &'a Arc<AppState>,
        _msg_id: [u8; 16],
        _ts: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

impl RelayRuntime for tauri::AppHandle {
    fn emit_join_requested(&self, request_id: String) {
        let _ = self.emit("join-requested", request_id);
    }

    fn emit_roster_updated(&self) {
        let _ = self.emit("roster-updated", ());
    }

    fn emit_join_approved(&self) {
        let _ = self.emit("join-approved", ());
    }

    fn emit_clip_stored(&self) {
        let _ = self.emit("clip-stored", ());
    }

    fn emit_roster_resynced_after_send(&self, new_epoch: u64) {
        let _ = self.emit("roster-resynced-after-send", new_epoch);
    }

    fn on_clip_received(&self, sender_label: String, clip_preview: String, text: String, ts: u64) {
        let mut desktop_attention_handled = false;
        #[cfg(desktop)]
        if let Some(win) = self.get_webview_window("main") {
            let visible = win.is_visible().unwrap_or(false);
            let minimized = win.is_minimized().unwrap_or(false);
            let focused = win.is_focused().unwrap_or(false);
            if !visible || minimized || !focused {
                let _ =
                    notify_incoming_clip(self.clone(), sender_label.clone(), clip_preview.clone());
                let _ = reveal_main_window(self);
                desktop_attention_handled = true;
            }
        }
        #[cfg(not(desktop))]
        let _ = &mut desktop_attention_handled;

        let _ = self.emit(
            "clip-received",
            serde_json::json!({
                "sender": sender_label,
                "preview": clip_preview,
                "text": text,
                "ts": ts,
                "desktop_attention_handled": desktop_attention_handled,
            }),
        );
    }

    fn switch_subscriber(&self, state: &Arc<AppState>, topic: String) {
        schedule_subscriber_switch(state, self, topic);
    }

    fn on_roster_changed<'a>(
        &'a self,
        state: &'a Arc<AppState>,
        next: &'a VerifiedRoster,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            cancel_transfers_not_in_roster(state, self, next).await;
        })
    }

    fn on_stale_epoch_transfers<'a>(
        &'a self,
        state: &'a Arc<AppState>,
        new_epoch: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            fail_stale_epoch_outgoing_transfers(state, self, new_epoch).await;
        })
    }

    fn on_file_signal<'a>(
        &'a self,
        state: &'a Arc<AppState>,
        network_id: String,
        sender_id: crypto::Ed25519PubKey,
        signal: FileSignal,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            handle_file_signal(state, self, network_id, sender_id, signal).await;
        })
    }

    fn on_group_removal<'a>(
        &'a self,
        state: &'a Arc<AppState>,
        msg_id: [u8; 16],
        ts: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let group_id = match current_sync_group_id(state).await {
                Ok(group_id) => group_id,
                Err(e) => {
                    eprintln!("group removal notice rejected: {e}");
                    return;
                }
            };
            let group_name = {
                let settings = state.settings.lock().await;
                if settings.active_sync_group_id.as_deref() != Some(group_id.as_str()) {
                    eprintln!("group removal notice rejected: group is not the active group");
                    return;
                }
                match settings
                    .sync_groups
                    .iter()
                    .find(|group| group.id == group_id)
                {
                    Some(group) => group.name.clone(),
                    None => {
                        eprintln!("group removal notice rejected: active group is not configured");
                        return;
                    }
                }
            };
            cancel_all_transfers(state, self, "This device was removed from the group").await;
            match remove_sync_group_from_device(state, self, &group_id, None).await {
                Ok(()) => {
                    if let Err(e) = state.store.mark_seen_message(&msg_id, ts) {
                        eprintln!(
                            "group removal notice replay-cache update failed after removal: {e}"
                        );
                    }
                    let _ = self.emit("sync-group-removed", group_name);
                }
                Err(e) => eprintln!("group removal notice failed: {e}"),
            }
        })
    }
}

fn invitation_is_subscribable(
    invite: &InvitationRecord,
    local_group_ids: &HashSet<String>,
    now: u64,
) -> bool {
    local_group_ids.contains(&invite.network_id) && invite.is_active_at(now)
}

fn file_signal_is_fresh(sent_at: u64, now: u64, timeout_minutes: u64) -> bool {
    now.saturating_sub(sent_at) <= timeout_minutes.saturating_mul(60)
}

#[tauri::command]
pub async fn relay_status(state: State<'_, Arc<AppState>>) -> Result<RelayStatusDto, String> {
    if state.roster.lock().await.is_none() {
        return Ok(RelayStatusDto::default());
    }
    Ok(state.relay_status.lock().await.clone())
}

#[tauri::command]
pub async fn reconnect_relay(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
) -> Result<RelayStatusDto, String> {
    restart_subscribers(state.inner(), app).await;
    if state.roster.lock().await.is_none() {
        return Ok(RelayStatusDto::default());
    }
    Ok(state.relay_status.lock().await.clone())
}

pub(super) async fn nudge_or_ensure_subscriber(state: &Arc<AppState>, app: tauri::AppHandle) {
    let missing_topic = {
        let has_shutdown = state.subscriber_shutdown.lock().await.is_some();
        if has_shutdown {
            None
        } else {
            state
                .roster
                .lock()
                .await
                .as_ref()
                .map(|verified| verified.topic().to_string())
        }
    };
    if let Some(topic) = missing_topic {
        start_subscriber(state, app, &topic).await;
    } else {
        state.reconnect_notify.notify_waiters();
    }
}

fn spawn_relay_message_pump<'a>(
    state: &'a Arc<AppState>,
    app: tauri::AppHandle,
    topic: String,
    track_primary_status: bool,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = tokio::sync::oneshot::Sender<()>> + Send + 'a>,
> {
    Box::pin(async move {
        let base = state.ntfy_base.lock().await.clone();
        let since = state
            .last_msg_ids
            .lock()
            .await
            .get(&topic)
            .cloned()
            .or_else(|| Some(COLD_START_CATCH_UP.to_string()));

        let status_tx = if track_primary_status {
            let generation = state.subscriber_generation.fetch_add(1, Ordering::SeqCst) + 1;
            let initial = {
                let mut guard = state.relay_status.lock().await;
                let next = RelayStatusDto {
                    state: "connecting".to_string(),
                    message: "Connecting to relay…".to_string(),
                    last_error: None,
                    last_healthy_at: guard.last_healthy_at,
                };
                *guard = next.clone();
                next
            };
            let _ = app.emit("relay-status-changed", initial);

            let (status_tx, mut status_rx) =
                tokio::sync::mpsc::unbounded_channel::<ntfy::SubscriberStatusEvent>();
            let state_for_status = state.clone();
            let app_for_status = app.clone();
            tokio::spawn(async move {
                while let Some(event) = status_rx.recv().await {
                    if state_for_status
                        .subscriber_generation
                        .load(Ordering::SeqCst)
                        != generation
                    {
                        break;
                    }
                    let next_status = {
                        let mut guard = state_for_status.relay_status.lock().await;
                        let prev_healthy = guard.last_healthy_at;
                        let prev_error = guard.last_error.clone();
                        let updated = match event {
                            ntfy::SubscriberStatusEvent::Connecting => RelayStatusDto {
                                state: if prev_error.is_some() {
                                    "reconnecting".to_string()
                                } else {
                                    "connecting".to_string()
                                },
                                message: match prev_error.as_deref() {
                                    Some(err) => format!("Reconnecting to relay ({err})"),
                                    None => "Connecting to relay…".to_string(),
                                },
                                last_error: prev_error,
                                last_healthy_at: prev_healthy,
                            },
                            ntfy::SubscriberStatusEvent::Connected
                            | ntfy::SubscriberStatusEvent::Healthy => RelayStatusDto {
                                state: "connected".to_string(),
                                message: "Connected".to_string(),
                                last_error: None,
                                last_healthy_at: Some(now_unix()),
                            },
                            ntfy::SubscriberStatusEvent::Reconnecting(reason) => RelayStatusDto {
                                state: "reconnecting".to_string(),
                                message: reason.clone(),
                                last_error: Some(reason),
                                last_healthy_at: prev_healthy,
                            },
                        };
                        *guard = updated.clone();
                        updated
                    };
                    let _ = app_for_status.emit("relay-status-changed", next_status);
                }
            });
            Some(status_tx)
        } else {
            None
        };

        let cfg = ntfy::SubscribeConfig {
            base,
            topic: topic.clone(),
            since,
            status_tx,
            reconnect_notify: Some(state.reconnect_notify.clone()),
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
                if !msg.id.is_empty() {
                    state_clone
                        .last_msg_ids
                        .lock()
                        .await
                        .insert(topic.clone(), msg.id.clone());
                }
                handle_relay_message(&state_clone, &app, &topic, msg).await;
            }
        });

        shutdown_tx
    })
}

/// Spawn (or replace) the ntfy subscriber for the given topic. Messages are
/// reassembled + verified + decrypted via `handle_relay_message`.
pub async fn start_subscriber(state: &Arc<AppState>, app: tauri::AppHandle, topic: &str) {
    // Shut down any existing subscriber (e.g. on topic rotation).
    if let Some(tx) = state.subscriber_shutdown.lock().await.take() {
        let _ = tx.send(());
    }

    let shutdown_tx = spawn_relay_message_pump(state, app, topic.to_string(), true).await;
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

    let shutdown_tx = spawn_relay_message_pump(state, app, topic, false).await;
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
    let local_group_ids: HashSet<String> = state
        .settings
        .lock()
        .await
        .sync_groups
        .iter()
        .map(|group| group.id.clone())
        .collect();
    let invites: Vec<InvitationRecord> = state
        .invitations
        .lock()
        .await
        .values()
        .filter(|invite| invitation_is_subscribable(invite, &local_group_ids, now))
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

/// Recreate relay subscriptions after a resume or explicit reconnect. ntfy
/// supplies `since` catch-up from the last observed message id (or a bounded
/// cold-start cache), so this does not require a push service or a separate backend.
pub async fn restart_subscribers(state: &Arc<AppState>, app: tauri::AppHandle) {
    state.subscriber_generation.fetch_add(1, Ordering::SeqCst);
    if let Some(tx) = state.subscriber_shutdown.lock().await.take() {
        let _ = tx.send(());
    }
    let auxiliary = state
        .auxiliary_subscriber_shutdowns
        .lock()
        .await
        .drain()
        .map(|(_, tx)| tx)
        .collect::<Vec<_>>();
    for tx in auxiliary {
        let _ = tx.send(());
    }

    let room_topic = state
        .roster
        .lock()
        .await
        .as_ref()
        .map(|roster| roster.topic().to_string());
    if let Some(topic) = room_topic {
        start_subscriber(state, app.clone(), &topic).await;
    } else {
        let reset = RelayStatusDto::default();
        *state.relay_status.lock().await = reset.clone();
        let _ = app.emit("relay-status-changed", reset);
    }
    start_invitation_subscribers(state, app.clone()).await;

    if let Some(pending) = state.pending_network_join.lock().await.clone() {
        start_auxiliary_subscriber(
            state,
            app,
            format!("pending:{}", pending.invite_id),
            pending.rendezvous_topic,
        )
        .await;
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

enum InboundManifestDisposition {
    AcceptCurrentEpoch,
    StaleSenderEpoch {
        verified: VerifiedRoster,
        sender_epoch: u64,
    },
    FutureSenderEpoch {
        verified: VerifiedRoster,
    },
    Reject,
}

async fn inspect_inbound_manifest(
    state: &Arc<AppState>,
    source_topic: &str,
    manifest: &crypto::Manifest,
    max_chunks: u32,
) -> InboundManifestDisposition {
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
        return InboundManifestDisposition::Reject;
    }
    let verified = match state.roster.lock().await.clone() {
        Some(verified) => verified,
        None => return InboundManifestDisposition::Reject,
    };
    if source_topic != verified.topic()
        || manifest.room_id != verified.topic()
        || manifest.sender_id == state.device.signing_pub
    {
        return InboundManifestDisposition::Reject;
    }
    if let Err(error) = crypto::verify_manifest_sig(manifest) {
        eprintln!("[relay] rejecting unauthenticated manifest: {error}");
        return InboundManifestDisposition::Reject;
    }
    match state.store.has_seen_message(&manifest.msg_id) {
        Ok(false) => {}
        Ok(true) => return InboundManifestDisposition::Reject,
        Err(error) => {
            eprintln!("[relay] replay cache check failed: {error}");
            return InboundManifestDisposition::Reject;
        }
    }

    let my_id = &state.device.signing_pub;
    let addressed_to_us = manifest
        .recipients
        .iter()
        .any(|wrap| &wrap.recipient_id == my_id);

    if manifest.roster_epoch == verified.epoch() {
        if verified.is_active(&manifest.sender_id) && addressed_to_us {
            InboundManifestDisposition::AcceptCurrentEpoch
        } else {
            InboundManifestDisposition::Reject
        }
    } else if manifest.roster_epoch < verified.epoch() {
        if verified.is_active(&manifest.sender_id) {
            InboundManifestDisposition::StaleSenderEpoch {
                verified,
                sender_epoch: manifest.roster_epoch,
            }
        } else {
            InboundManifestDisposition::Reject
        }
    } else if manifest.roster_epoch <= verified.epoch().saturating_add(MAX_FUTURE_EPOCH_GAP)
        && addressed_to_us
    {
        InboundManifestDisposition::FutureSenderEpoch { verified }
    } else {
        InboundManifestDisposition::Reject
    }
}

pub(crate) async fn collect_missing_roster_entries(
    state: &Arc<AppState>,
    verified: &VerifiedRoster,
    from_epoch: u64,
) -> Vec<roster::RosterEntry> {
    if from_epoch >= verified.epoch() {
        return Vec::new();
    }
    let mut entries: Vec<roster::RosterEntry> = load_active_roster_chain_entries(state, verified)
        .await
        .into_iter()
        .filter(|entry| entry.epoch > from_epoch && entry.epoch <= verified.epoch())
        .collect();
    entries.sort_by_key(|entry| entry.epoch);
    entries
}

async fn maybe_broadcast_missing_roster_chain(
    state: &Arc<AppState>,
    verified: &VerifiedRoster,
    from_epoch: u64,
) {
    if from_epoch >= verified.epoch() {
        return;
    }
    let topic = verified.topic().to_string();
    {
        let mut guard = state.last_roster_sync_broadcast.lock().await;
        if let Some((prev_from_epoch, last_sent)) = guard.get(&topic) {
            if last_sent.elapsed() < ROSTER_SYNC_BROADCAST_COOLDOWN
                && from_epoch >= *prev_from_epoch
            {
                return;
            }
        }
        guard.insert(topic.clone(), (from_epoch, std::time::Instant::now()));
    }

    let entries = collect_missing_roster_entries(state, verified, from_epoch).await;
    if entries.is_empty() {
        return;
    }
    eprintln!(
        "[relay] broadcasting {} missing roster epoch(s) ({}..={}) to catch up peer",
        entries.len(),
        from_epoch + 1,
        verified.epoch()
    );
    let state_clone = state.clone();
    tokio::spawn(async move {
        for entry in entries {
            broadcast_roster(&state_clone, &entry, &topic).await;
        }
    });
}

async fn maybe_request_roster_sync(state: &Arc<AppState>, verified: &VerifiedRoster) {
    let topic = verified.topic().to_string();
    {
        let mut guard = state.last_roster_sync_request.lock().await;
        if let Some(last_req) = guard.get(&topic) {
            if last_req.elapsed() < ROSTER_SYNC_REQUEST_COOLDOWN {
                return;
            }
        }
        guard.insert(topic.clone(), std::time::Instant::now());
    }
    let req = sign_roster_sync_request(&state.device, topic.clone(), verified.epoch(), now_unix());
    let base = state.ntfy_base.lock().await.clone();
    eprintln!(
        "[relay] requesting roster catch-up from peers (local epoch={})",
        verified.epoch()
    );
    tokio::spawn(async move {
        if let Err(error) = publish_wire_with_options(
            &base,
            &topic,
            WireMessage::RosterSyncRequest(req),
            "roster-sync",
            ntfy::PublishOptions::no_cache(),
        )
        .await
        {
            eprintln!("[relay] roster sync request publish failed: {error}");
        }
    });
}

async fn buffer_deferred_future_clip(
    state: &Arc<AppState>,
    manifest: crypto::Manifest,
    body: DeferredClipBody,
) {
    let now = std::time::Instant::now();
    let mut deferred = state.deferred_future_clips.lock().await;
    deferred.retain(|_, item| now.duration_since(item.received_at) <= DEFERRED_FUTURE_CLIP_TTL);
    if deferred.len() >= MAX_DEFERRED_FUTURE_CLIPS && !deferred.contains_key(&manifest.msg_id) {
        if let Some(oldest_id) = deferred
            .iter()
            .min_by_key(|(_, item)| item.received_at)
            .map(|(id, _)| *id)
        {
            deferred.remove(&oldest_id);
        }
    }
    deferred.insert(
        manifest.msg_id,
        DeferredFutureClip {
            manifest,
            body,
            received_at: now,
        },
    );
}

pub(crate) async fn validate_roster_sync_request(
    state: &Arc<AppState>,
    source_topic: &str,
    req: &RosterSyncRequestMessage,
    now: u64,
) -> Option<(VerifiedRoster, u64)> {
    let verified = state.roster.lock().await.clone()?;
    if source_topic != verified.topic()
        || req.room_id != verified.topic()
        || req.requester_id == state.device.signing_pub
        || req.current_epoch >= verified.epoch()
    {
        return None;
    }
    if req.ts > now.saturating_add(60)
        || now.saturating_sub(req.ts) > ROSTER_SYNC_REQUEST_MAX_AGE_SECS
    {
        eprintln!("[relay] ignoring expired roster sync request");
        return None;
    }
    if !verified.is_active(&req.requester_id) {
        eprintln!("[relay] ignoring roster sync request from inactive device");
        return None;
    }
    if let Err(error) = verify_roster_sync_request_sig(req) {
        eprintln!("[relay] ignoring unauthenticated roster sync request: {error}");
        return None;
    }
    Some((verified, req.current_epoch))
}

async fn download_and_decode_clip_attachment(
    state: &Arc<AppState>,
    attachment: &ntfy::RelayAttachment,
    chunk_count: u32,
) -> Option<Vec<crypto::Chunk>> {
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
    let downloaded = downloaded?;
    match decode_attachment_chunks(&downloaded, chunk_count) {
        Ok(chunks) => Some(chunks),
        Err(error) => {
            eprintln!("[relay] clip attachment decode failed: {error}");
            None
        }
    }
}

async fn on_roster_epoch_advanced<R: RelayRuntime>(
    state: &Arc<AppState>,
    runtime: &R,
    old_topic: &str,
    next: &VerifiedRoster,
) {
    let stale_recent_send = {
        let mut guard = state.last_outbound_epoch.lock().await;
        match *guard {
            Some((ref sent_topic, sent_epoch, sent_at))
                if sent_topic == old_topic
                    && sent_epoch < next.epoch()
                    && sent_at.elapsed() <= STALE_SEND_RESYNC_NOTICE_WINDOW =>
            {
                *guard = None;
                true
            }
            _ => false,
        }
    };
    if stale_recent_send {
        eprintln!(
            "[relay] roster advanced to epoch {} shortly after stale send; notifying UI",
            next.epoch()
        );
        runtime.emit_roster_resynced_after_send(next.epoch());
    }

    if next.topic() != old_topic {
        state.deferred_future_clips.lock().await.clear();
        return;
    }

    runtime.on_stale_epoch_transfers(state, next.epoch()).await;

    let ready_for_epoch = {
        let now = std::time::Instant::now();
        let mut deferred = state.deferred_future_clips.lock().await;
        let ids_to_take: Vec<[u8; 16]> = deferred
            .iter()
            .filter_map(|(id, item)| {
                if now.duration_since(item.received_at) > DEFERRED_FUTURE_CLIP_TTL
                    || item.manifest.roster_epoch <= next.epoch()
                {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();
        let mut matching = Vec::new();
        for id in ids_to_take {
            if let Some(item) = deferred.remove(&id) {
                if now.duration_since(item.received_at) <= DEFERRED_FUTURE_CLIP_TTL
                    && item.manifest.roster_epoch == next.epoch()
                {
                    matching.push(item);
                }
            }
        }
        matching
    };

    for item in ready_for_epoch {
        match item.body {
            DeferredClipBody::Chunks(chunks) => {
                if chunks.iter().all(Option::is_some) {
                    let ready: Vec<crypto::Chunk> =
                        chunks.into_iter().map(Option::unwrap).collect();
                    try_open_clip_with(state, runtime, item.manifest, ready).await;
                } else {
                    let msg_id = item.manifest.msg_id;
                    let mut pending = state.pending.lock().await;
                    if pending.len() < MAX_PENDING_CLIPS {
                        pending.insert(
                            msg_id,
                            PendingClip {
                                manifest: item.manifest,
                                chunks,
                            },
                        );
                        drop(pending);
                        let state_clone = state.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_secs(
                                PENDING_CLIP_TTL_SECS,
                            ))
                            .await;
                            state_clone.pending.lock().await.remove(&msg_id);
                        });
                    }
                }
            }
            DeferredClipBody::Attachment(attachment) => {
                if let Some(chunks) = download_and_decode_clip_attachment(
                    state,
                    &attachment,
                    item.manifest.chunk_count,
                )
                .await
                {
                    try_open_clip_with(state, runtime, item.manifest, chunks).await;
                }
            }
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
    process_relay_message_with(state, app, source_topic, msg).await;
}

pub(crate) async fn process_relay_message_with<R: RelayRuntime>(
    state: &Arc<AppState>,
    runtime: &R,
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
            match inspect_inbound_manifest(state, source_topic, &manifest, MAX_RELAY_CLIP_CHUNKS)
                .await
            {
                InboundManifestDisposition::AcceptCurrentEpoch => {}
                InboundManifestDisposition::StaleSenderEpoch {
                    verified,
                    sender_epoch,
                } => {
                    eprintln!(
                        "[relay] received manifest at stale epoch {} (local={}); pushing roster chain",
                        sender_epoch,
                        verified.epoch()
                    );
                    maybe_broadcast_missing_roster_chain(state, &verified, sender_epoch).await;
                    return;
                }
                InboundManifestDisposition::FutureSenderEpoch { verified } => {
                    eprintln!(
                        "[relay] deferring manifest at future epoch {} (local={}) and requesting sync",
                        manifest.roster_epoch,
                        verified.epoch()
                    );
                    let chunk_count = manifest.chunk_count as usize;
                    buffer_deferred_future_clip(
                        state,
                        manifest,
                        DeferredClipBody::Chunks(vec![None; chunk_count]),
                    )
                    .await;
                    maybe_request_roster_sync(state, &verified).await;
                    return;
                }
                InboundManifestDisposition::Reject => return,
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
            let mut found_in_pending = false;
            let completed = {
                let mut pending = state.pending.lock().await;
                if let Some(p) = pending.get_mut(&chunk.msg_id) {
                    found_in_pending = true;
                    let idx = chunk.index as usize;
                    if idx < p.chunks.len() {
                        p.chunks[idx] = Some(chunk.clone());
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
                } else {
                    None
                }
            };
            if let Some((manifest, chunks)) = completed {
                try_open_clip_with(state, runtime, manifest, chunks).await;
            } else if !found_in_pending {
                let mut deferred = state.deferred_future_clips.lock().await;
                if let Some(item) = deferred.get_mut(&chunk.msg_id) {
                    if let DeferredClipBody::Chunks(ref mut chunks) = item.body {
                        let idx = chunk.index as usize;
                        if idx < chunks.len() {
                            chunks[idx] = Some(chunk);
                        }
                    }
                }
            }
        }
        WireMessage::ClipAttachment(manifest) => {
            let attachment = match msg.attachment.as_ref() {
                Some(attachment) => attachment,
                None => {
                    eprintln!("[relay] clip attachment notice has no attachment metadata");
                    return;
                }
            };
            match inspect_inbound_manifest(
                state,
                source_topic,
                &manifest,
                MAX_ATTACHMENT_CLIP_CHUNKS,
            )
            .await
            {
                InboundManifestDisposition::AcceptCurrentEpoch => {}
                InboundManifestDisposition::StaleSenderEpoch {
                    verified,
                    sender_epoch,
                } => {
                    maybe_broadcast_missing_roster_chain(state, &verified, sender_epoch).await;
                    return;
                }
                InboundManifestDisposition::FutureSenderEpoch { verified } => {
                    buffer_deferred_future_clip(
                        state,
                        manifest,
                        DeferredClipBody::Attachment(attachment.clone()),
                    )
                    .await;
                    maybe_request_roster_sync(state, &verified).await;
                    return;
                }
                InboundManifestDisposition::Reject => return,
            }
            let Some(chunks) =
                download_and_decode_clip_attachment(state, attachment, manifest.chunk_count).await
            else {
                return;
            };
            try_open_clip_with(state, runtime, manifest, chunks).await;
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
            let verified = match load_sync_group_roster(state, &invite.network_id).await {
                Ok(Some(roster)) if roster.entry.admin_id == state.device.signing_pub => roster,
                _ => return,
            };
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
            let request_key =
                match pairing_commands::pairing_request_key(&invite.network_id, &request) {
                    Ok(key) => key,
                    Err(e) => {
                        eprintln!("[pairing] failed to identify join request: {e}");
                        return;
                    }
                };
            match state.store.has_seen_message(&request_key) {
                Ok(true) => return,
                Ok(false) => {}
                Err(e) => {
                    eprintln!("[pairing] join-request replay check failed: {e}");
                    return;
                }
            }
            if let Some(existing) = verified
                .entry
                .devices
                .iter()
                .find(|device| device.signing_pub == request.identity.signing_pub)
            {
                // An unseen request from an already committed device is a
                // retry after a grant/persistence interruption. Only permit it
                // when the encryption identity is unchanged; otherwise an
                // invitation holder could redirect that device's roster grant.
                if existing.x25519_pub != request.identity.x25519_pub {
                    return;
                }
            }
            let request_id = hex::encode(request_key);
            state.pending_joins.lock().await.insert(
                request_id.clone(),
                PendingJoinRecord {
                    request_id: request_id.clone(),
                    request_key,
                    network_id: invite.network_id,
                    rendezvous_topic: source_topic.to_string(),
                    request,
                    received_at: now,
                },
            );
            runtime.emit_join_requested(request_id);
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
            runtime.switch_subscriber(state, topic);
            runtime.emit_roster_updated();
            runtime.emit_join_approved();
        }
        WireMessage::DeleteClip(msg) => {
            handle_delete_clip(state, runtime, msg).await;
        }
        WireMessage::RenameDevice(msg) => {
            handle_rename_device(state, runtime, msg).await;
        }
        WireMessage::RosterSyncRequest(req) => {
            if let Some((verified, from_epoch)) =
                validate_roster_sync_request(state, source_topic, &req, now_unix()).await
            {
                maybe_broadcast_missing_roster_chain(state, &verified, from_epoch).await;
            }
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
                            runtime.on_roster_changed(state, &next).await;
                            persist_roster(state, &entry).await;
                            if new_topic != old_topic {
                                state.pending.lock().await.clear();
                                runtime.switch_subscriber(state, new_topic);
                            }
                            runtime.emit_roster_updated();
                            on_roster_epoch_advanced(state, runtime, &old_topic, &next).await;
                        }
                        Err(e) => {
                            eprintln!("roster update rejected: {e}");
                            // If a peer skipped ahead more than one epoch, ask
                            // for the missing intermediate links from our epoch.
                            if entry.epoch > prev.epoch().saturating_add(1)
                                && entry.epoch <= prev.epoch().saturating_add(MAX_FUTURE_EPOCH_GAP)
                                && entry.admin_id == prev.entry.admin_id
                            {
                                maybe_request_roster_sync(state, &prev).await;
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn handle_rename_device<R: RelayRuntime>(
    state: &Arc<AppState>,
    runtime: &R,
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
    if msg.room_id != verified.topic() {
        eprintln!("[relay] rename rejected: room mismatch");
        return;
    }
    if !verified.is_active(&msg.device_id) {
        eprintln!("[relay] rename rejected: sender is not active");
        return;
    }
    if msg.roster_epoch < verified.epoch() {
        eprintln!(
            "[relay] rename arrived with stale epoch {} (local={}); pushing roster chain",
            msg.roster_epoch,
            verified.epoch()
        );
        maybe_broadcast_missing_roster_chain(state, &verified, msg.roster_epoch).await;
    } else if msg.roster_epoch > verified.epoch() {
        eprintln!("[relay] rename rejected: epoch mismatch");
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
                runtime.on_roster_changed(state, &next).await;
                persist_roster(state, &signed).await;
                broadcast_roster(state, &signed, &topic).await;
                runtime.emit_roster_updated();
            }
            Err(e) => eprintln!("roster verify_next failed: {e}"),
        },
        Err(e) => eprintln!("roster sign failed: {e}"),
    }
}

async fn handle_delete_clip<R: RelayRuntime>(
    state: &Arc<AppState>,
    runtime: &R,
    msg: DeleteClipMessage,
) {
    if let Err(e) = verify_delete_clip_sig(&msg) {
        eprintln!("[relay] delete rejected: {e}");
        return;
    }

    let verified = match state.roster.lock().await.clone() {
        Some(v) => v,
        None => return,
    };
    if msg.room_id != verified.topic() {
        eprintln!("[relay] delete rejected: room mismatch");
        return;
    }
    if msg.roster_epoch != verified.epoch() {
        if msg.roster_epoch < verified.epoch() && verified.is_active(&msg.sender_id) {
            maybe_broadcast_missing_roster_chain(state, &verified, msg.roster_epoch).await;
        } else if msg.roster_epoch > verified.epoch()
            && msg.roster_epoch <= verified.epoch().saturating_add(MAX_FUTURE_EPOCH_GAP)
        {
            maybe_request_roster_sync(state, &verified).await;
        }
        eprintln!("[relay] delete rejected: epoch mismatch");
        return;
    }
    if !verified.is_active(&msg.sender_id) {
        eprintln!("[relay] delete rejected: sender is not active");
        return;
    }

    match state.store.delete_by_msg_id(&msg.msg_id) {
        Ok(changed) => {
            if changed > 0 {
                runtime.emit_clip_stored();
            }
        }
        Err(e) => eprintln!("[relay] delete failed: {e}"),
    }
}

/// Attempt to verify + decrypt a complete clip, then emit + store.
async fn try_open_clip_with<R: RelayRuntime>(
    state: &Arc<AppState>,
    runtime: &R,
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
    let active_devices = verified.entry.devices.clone();
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
        active_devices.iter().any(|d| &d.signing_pub == id)
    });

    match opened {
        Ok(o) => {
            match decode_group_removal_notice(&o.plaintext) {
                Ok(true) => {
                    if o.sender_id != admin_id {
                        eprintln!("group removal notice rejected: sender is not admin");
                        return;
                    }
                    runtime.on_group_removal(state, manifest.msg_id, o.ts).await;
                    return;
                }
                Ok(false) => {}
                Err(e) => {
                    eprintln!("group removal notice decode failed: {e}");
                    return;
                }
            }
            if let Err(e) = state.store.mark_seen_message(&manifest.msg_id, o.ts) {
                eprintln!("clip open failed: replay cache update failed: {e}");
                return;
            }
            match decode_file_signal(&o.plaintext) {
                Ok(Some(signal)) => {
                    let network_id = match current_sync_group_id(state).await {
                        Ok(network_id) => network_id,
                        Err(_) => return,
                    };
                    let runtime_topic = state
                        .roster
                        .lock()
                        .await
                        .as_ref()
                        .map(|verified| verified.topic().to_string());
                    if runtime_topic.as_deref() != Some(current_topic.as_str()) {
                        eprintln!("file signal ignored: active group changed while opening it");
                        return;
                    }
                    let transfer_timeout_minutes =
                        state.settings.lock().await.transfer_timeout_minutes;
                    if !file_signal_is_fresh(o.ts, now_unix(), transfer_timeout_minutes) {
                        eprintln!("file signal ignored: transfer window expired");
                        return;
                    }
                    runtime
                        .on_file_signal(state, network_id, o.sender_id.clone(), signal)
                        .await;
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
                    if let Err(e) = apply_roster_update_with(state, runtime, entry, true).await {
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

            // Persist to history first so waking windows immediately read the
            // stored clip on visibility refresh.
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
                runtime.emit_clip_stored();
            }

            let sender_label = active_devices
                .iter()
                .find(|d| d.signing_pub == o.sender_id)
                .map(|d| d.label.trim().to_string())
                .filter(|label| !label.is_empty())
                .unwrap_or_else(|| hex::encode(&o.sender_id.0[..4]));
            let clip_preview = preview(&o.plaintext);
            runtime.on_clip_received(sender_label, clip_preview, o.plaintext, o.ts);
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

pub(super) fn encode_group_removal_notice() -> String {
    GROUP_REMOVAL_NOTICE_MARKER.to_string()
}

fn decode_group_removal_notice(text: &str) -> Result<bool, String> {
    if text == GROUP_REMOVAL_NOTICE_MARKER {
        return Ok(true);
    }
    if text.starts_with(GROUP_REMOVAL_NOTICE_MARKER) {
        return Err("malformed group removal notice".to_string());
    }
    Ok(false)
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

#[allow(dead_code)]
pub(super) async fn apply_roster_update(
    state: &Arc<AppState>,
    app: &tauri::AppHandle,
    entry: roster::RosterEntry,
    republish_on_new_topic: bool,
) -> Result<(), String> {
    apply_roster_update_with(state, app, entry, republish_on_new_topic).await
}

async fn apply_roster_update_with<R: RelayRuntime>(
    state: &Arc<AppState>,
    runtime: &R,
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
    runtime.on_roster_changed(state, &next).await;
    persist_roster(state, &entry).await;
    if new_topic != old_topic {
        state.pending.lock().await.clear();
        runtime.switch_subscriber(state, new_topic.clone());
    }
    if republish_on_new_topic {
        broadcast_roster(state, &entry, &new_topic).await;
    }
    runtime.emit_roster_updated();
    Box::pin(on_roster_epoch_advanced(state, runtime, &old_topic, &next)).await;
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

    fn invitation(
        network_id: &str,
        expires_at: Option<u64>,
        revoked_at: Option<u64>,
    ) -> InvitationRecord {
        InvitationRecord {
            id: "invite-id".to_string(),
            network_id: network_id.to_string(),
            secret: [1; 32],
            created_at: 1,
            expires_at,
            revoked_at,
        }
    }

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

    #[test]
    fn group_removal_notice_roundtrips() {
        let encoded = encode_group_removal_notice();

        assert!(decode_group_removal_notice(&encoded).unwrap());
        assert!(!decode_group_removal_notice("ordinary clip").unwrap());
    }

    #[test]
    fn group_removal_notice_rejects_suffixes() {
        assert!(decode_group_removal_notice(&format!("{GROUP_REMOVAL_NOTICE_MARKER}:")).is_err());
        assert!(
            decode_group_removal_notice(&format!("{GROUP_REMOVAL_NOTICE_MARKER}extra")).is_err()
        );
    }

    #[test]
    fn invitation_subscription_accepts_active_invites_for_any_local_group() {
        let local_group_ids = HashSet::from(["active".to_string(), "inactive".to_string()]);

        assert!(invitation_is_subscribable(
            &invitation("active", None, None),
            &local_group_ids,
            100
        ));
        assert!(invitation_is_subscribable(
            &invitation("inactive", Some(101), None),
            &local_group_ids,
            100
        ));
        assert!(!invitation_is_subscribable(
            &invitation("missing", None, None),
            &local_group_ids,
            100
        ));
        assert!(!invitation_is_subscribable(
            &invitation("inactive", Some(100), None),
            &local_group_ids,
            100
        ));
        assert!(!invitation_is_subscribable(
            &invitation("inactive", None, Some(99)),
            &local_group_ids,
            100
        ));
    }

    #[test]
    fn cached_file_signals_respect_the_transfer_window() {
        assert!(file_signal_is_fresh(1_000, 1_060, 1));
        assert!(!file_signal_is_fresh(1_000, 1_061, 1));
        assert!(file_signal_is_fresh(1_060, 1_000, 1));
    }
}
