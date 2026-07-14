//! Durable invitation, admin-approval, and pairing bootstrap commands.

use super::*;

pub fn load_invitations_from_keychain() -> HashMap<String, InvitationRecord> {
    let Ok(Some(blob)) = crate::keychain::load_invitation_blob() else {
        return HashMap::new();
    };
    let Ok(store) = postcard::from_bytes::<InvitationStore>(&blob) else {
        eprintln!("ignoring corrupt invitation store");
        return HashMap::new();
    };
    if store.version != network::INVITATION_STORE_VERSION {
        eprintln!("ignoring unsupported invitation store version");
        return HashMap::new();
    }
    store
        .invitations
        .into_iter()
        .filter(|invite| network::valid_id(&invite.id) && network::valid_id(&invite.network_id))
        .map(|invite| (invite.id.clone(), invite))
        .collect()
}

pub(super) async fn persist_invitations(state: &Arc<AppState>) -> Result<(), String> {
    let invitations = state.invitations.lock().await.values().cloned().collect();
    let store = InvitationStore {
        version: network::INVITATION_STORE_VERSION,
        invitations,
    };
    let blob = postcard::to_allocvec(&store).map_err(|e| e.to_string())?;
    crate::keychain::save_invitation_blob(&blob).map_err(|e| e.to_string())
}

pub(super) fn pairing_request_key(
    network_id: &str,
    request: &crate::pairing::NetworkJoinRequest,
) -> Result<[u8; 16], String> {
    let encoded = postcard::to_allocvec(request).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(b"Fwoosh pairing request decision v1\0");
    hasher.update((network_id.len() as u64).to_le_bytes());
    hasher.update(network_id.as_bytes());
    hasher.update(encoded);
    let digest = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    Ok(key)
}

fn mark_pairing_request_decided(
    state: &Arc<AppState>,
    pending: &PendingJoinRecord,
) -> Result<(), String> {
    state
        .store
        .mark_seen_message(&pending.request_key, now_unix())
        .map_err(|e| format!("failed to persist the join-request decision: {e}"))
}

async fn remove_pairing_invitations(
    state: &Arc<AppState>,
    invite_ids: Vec<String>,
) -> Result<usize, String> {
    let removed_ids = {
        let mut invitations = state.invitations.lock().await;
        invite_ids
            .into_iter()
            .filter(|id| invitations.remove(id).is_some())
            .collect::<Vec<_>>()
    };
    if removed_ids.is_empty() {
        return Ok(0);
    }
    for id in &removed_ids {
        stop_auxiliary_subscriber(state, &format!("invite:{id}")).await;
    }
    persist_invitations(state).await?;
    Ok(removed_ids.len())
}

pub(super) async fn current_network_identity(
    state: &Arc<AppState>,
) -> Result<(String, String), String> {
    let settings = state.settings.lock().await;
    let id = settings
        .active_sync_group_id
        .clone()
        .ok_or_else(|| "group has no stable id".to_string())?;
    let name = settings
        .sync_groups
        .iter()
        .find(|group| group.id == id)
        .map(|group| group.name.clone())
        .ok_or_else(|| "active group metadata is missing".to_string())?;
    Ok((id, name))
}

fn pairing_code_dto(state: &Arc<AppState>, invite: &InvitationRecord) -> PairingCodeDto {
    PairingCodeDto {
        uri: crate::pairing::build_network_uri(
            &invite.id,
            &state.device.signing_pub,
            &state.device.x25519_pub,
            &invite.secret,
        ),
        invite_id: invite.id.clone(),
        network_id: invite.network_id.clone(),
        expires_at: invite.expires_at,
        is_permanent: invite.expires_at.is_none(),
    }
}

pub(super) async fn issue_pairing_code(
    state: &Arc<AppState>,
    network_id: &str,
    expires_in_seconds: Option<u64>,
    reuse_permanent: bool,
) -> Result<PairingCodeDto, String> {
    if !network::valid_id(network_id) {
        return Err("invalid sync group id".to_string());
    }
    let now = now_unix();

    if expires_in_seconds.is_none() && reuse_permanent {
        let invitations = state.invitations.lock().await;
        if let Some(invite) = invitations.values().find(|invite| {
            invite.network_id == network_id
                && invite.expires_at.is_none()
                && invite.is_active_at(now)
        }) {
            return Ok(pairing_code_dto(state, invite));
        }
    }

    let expires_at = expires_in_seconds.map(|seconds| now.saturating_add(seconds.max(1)));
    let invite = InvitationRecord {
        id: network::new_id(),
        network_id: network_id.to_string(),
        secret: crate::pairing::random_secret(),
        created_at: now,
        expires_at,
        revoked_at: None,
    };
    let dto = pairing_code_dto(state, &invite);
    {
        let mut invitations = state.invitations.lock().await;
        invitations.retain(|_, existing| existing.is_active_at(now));
        if invitations.len() >= MAX_DURABLE_INVITATIONS {
            return Err("too many active invitations; revoke one first".to_string());
        }
        invitations.insert(invite.id.clone(), invite.clone());
    }
    persist_invitations(state).await?;
    Ok(dto)
}

// =========================================================================
//  Commands callable from the frontend
// =========================================================================

#[tauri::command]
pub async fn new_pairing_code(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    group_id: String,
) -> Result<PairingCodeDto, String> {
    let group_id = group_id.trim().to_string();
    {
        let settings = state.settings.lock().await;
        ensure_expected_active_group(&settings, &group_id, "creating the invitation")?;
    }
    require_admin_roster(state.inner(), "create pairing codes").await?;
    let code = issue_pairing_code(&state, &group_id, None, true).await?;
    start_invitation_subscribers(&state, app).await;
    Ok(code)
}

#[tauri::command]
pub async fn create_temporary_pairing_code(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    group_id: String,
    expires_in_seconds: u64,
) -> Result<PairingCodeDto, String> {
    let group_id = group_id.trim().to_string();
    {
        let settings = state.settings.lock().await;
        ensure_expected_active_group(&settings, &group_id, "creating the invitation")?;
    }
    require_admin_roster(state.inner(), "create invitations").await?;
    if !(60..=30 * 24 * 60 * 60).contains(&expires_in_seconds) {
        return Err("temporary invitation must last between 1 minute and 30 days".to_string());
    }
    let code = issue_pairing_code(&state, &group_id, Some(expires_in_seconds), false).await?;
    start_invitation_subscribers(&state, app).await;
    Ok(code)
}

#[tauri::command]
pub async fn rotate_pairing_code(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
) -> Result<PairingCodeDto, String> {
    require_admin_roster(state.inner(), "rotate invitations").await?;
    let (network_id, _) = current_network_identity(state.inner()).await?;
    let revoked_ids = {
        let invitations = state.invitations.lock().await;
        invitations
            .values()
            .filter(|invite| invite.network_id == network_id && invite.expires_at.is_none())
            .map(|invite| invite.id.clone())
            .collect()
    };
    remove_pairing_invitations(state.inner(), revoked_ids).await?;
    let code = issue_pairing_code(state.inner(), &network_id, None, false).await?;
    start_invitation_subscribers(state.inner(), app).await;
    Ok(code)
}

#[tauri::command]
pub async fn revoke_permanent_pairing_code(
    state: State<'_, Arc<AppState>>,
    group_id: String,
) -> Result<bool, String> {
    let group_id = group_id.trim().to_string();
    {
        let settings = state.settings.lock().await;
        ensure_expected_active_group(&settings, &group_id, "revoking the reusable invitation")?;
    }
    require_admin_roster(state.inner(), "revoke invitations").await?;
    let invite_ids = {
        let settings = state.settings.lock().await;
        ensure_expected_active_group(&settings, &group_id, "revoking the reusable invitation")?;
        let invitations = state.invitations.lock().await;
        invitations
            .values()
            .filter(|invite| invite.network_id == group_id && invite.expires_at.is_none())
            .map(|invite| invite.id.clone())
            .collect()
    };
    Ok(remove_pairing_invitations(state.inner(), invite_ids).await? > 0)
}

#[tauri::command]
pub async fn revoke_pairing_code(
    state: State<'_, Arc<AppState>>,
    invite_id: String,
) -> Result<(), String> {
    require_admin_roster(state.inner(), "revoke invitations").await?;
    remove_pairing_invitations(state.inner(), vec![invite_id]).await?;
    Ok(())
}

#[tauri::command]
pub async fn pending_join_requests(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<PendingJoinDto>, String> {
    let mut out: Vec<_> = state
        .pending_joins
        .lock()
        .await
        .values()
        .map(|pending| PendingJoinDto {
            request_id: pending.request_id.clone(),
            invite_id: pending.request.invite_id.clone(),
            network_id: pending.network_id.clone(),
            label: pending.request.identity.label.clone(),
            fingerprint: hex::encode(&pending.request.identity.signing_pub.0[..4]),
            received_at: pending.received_at,
        })
        .collect();
    out.sort_by_key(|request| request.received_at);
    Ok(out)
}

pub(super) async fn require_pending_group_active(
    state: &Arc<AppState>,
    pending: &PendingJoinRecord,
    action: &str,
) -> Result<(), String> {
    let settings = state.settings.lock().await;
    if settings.active_sync_group_id.as_deref() == Some(pending.network_id.as_str()) {
        return Ok(());
    }
    let name = settings
        .sync_groups
        .iter()
        .find(|group| group.id == pending.network_id)
        .map(|group| group.name.as_str())
        .unwrap_or("the requested");
    Err(format!(
        "Switch to the \"{name}\" group before {action} this join request."
    ))
}

#[tauri::command]
pub async fn reject_join_request(
    state: State<'_, Arc<AppState>>,
    request_id: String,
) -> Result<(), String> {
    let pending = state
        .pending_joins
        .lock()
        .await
        .get(&request_id)
        .cloned()
        .ok_or_else(|| "join request not found".to_string())?;
    require_pending_group_active(state.inner(), &pending, "rejecting").await?;
    let verified = require_admin_roster(state.inner(), "reject join requests").await?;
    if verified.is_active(&pending.request.identity.signing_pub) {
        return Err(
            "This device was already committed to the group. Retry approval to deliver its access, or remove the device from the group."
                .to_string(),
        );
    }
    mark_pairing_request_decided(state.inner(), &pending)?;
    state.pending_joins.lock().await.remove(&request_id);
    Ok(())
}

#[tauri::command]
pub async fn approve_join_request(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    request_id: String,
) -> Result<(), String> {
    let pending = state
        .pending_joins
        .lock()
        .await
        .get(&request_id)
        .cloned()
        .ok_or_else(|| "join request not found".to_string())?;
    require_pending_group_active(state.inner(), &pending, "approving").await?;
    let now = now_unix();
    if now.saturating_sub(pending.request.requested_at) > JOIN_REQUEST_MAX_AGE_SECS {
        state.pending_joins.lock().await.remove(&request_id);
        return Err("join request expired; ask the device to try again".to_string());
    }
    let invite = state
        .invitations
        .lock()
        .await
        .get(&pending.request.invite_id)
        .cloned()
        .ok_or_else(|| "invitation no longer exists".to_string())?;
    if !invite.is_active_at(now) || invite.network_id != pending.network_id {
        return Err("invitation is expired or revoked".to_string());
    }

    let verified = require_admin_roster(state.inner(), "approve join requests").await?;
    let existing_identity = verified
        .entry
        .devices
        .iter()
        .find(|device| device.signing_pub == pending.request.identity.signing_pub);
    let (next, roster_changed) = if let Some(existing) = existing_identity {
        if existing.x25519_pub != pending.request.identity.x25519_pub {
            return Err(
                "The retry identity does not match the device already committed to the group."
                    .to_string(),
            );
        }
        (verified, false)
    } else {
        let unsigned = roster::build_add_device(&verified.entry, pending.request.identity.clone());
        let signed = roster::sign_and_chain(&state.device, unsigned, Some(&verified.entry))
            .map_err(|e| e.to_string())?;
        let next = verified
            .verify_next(signed.clone())
            .map_err(|e| e.to_string())?;
        (next, true)
    };

    // Commit before granting access. On a write failure the in-memory roster
    // remains unchanged and this pending request can be approved again. If a
    // prior attempt committed but failed to publish its grant, writing the
    // current entry again is idempotent and repairs a one-epoch disk lag.
    let roster_path =
        persist_sync_group_roster_checked(state.inner(), &pending.network_id, &next.entry).await?;
    require_pending_group_active(state.inner(), &pending, "approving").await?;
    *state.roster.lock().await = Some(next.clone());
    if roster_changed {
        cancel_transfers_not_in_roster(&state, &app, &next).await;
        broadcast_roster(&state, &next.entry, next.topic()).await;
    }

    let roster_chain = std::fs::read(&roster_path)
        .ok()
        .and_then(|bytes| decode_persisted_roster_entries(&bytes))
        .ok_or_else(|| "failed to load roster chain for the joining device".to_string())?;
    let persisted = verify_persisted_roster_entries(roster_chain.clone())?;
    if persisted.epoch() != next.epoch()
        || !persisted.is_active(&pending.request.identity.signing_pub)
    {
        return Err("joining device was not committed to the roster chain".to_string());
    }
    let network_name = state
        .settings
        .lock()
        .await
        .sync_groups
        .iter()
        .find(|group| group.id == pending.network_id)
        .map(|group| group.name.clone())
        .ok_or_else(|| "join request group metadata is missing".to_string())?;
    let payload = PairingRosterPayload {
        network_id: pending.network_id.clone(),
        network_name,
        roster_chain,
    };
    let plaintext = postcard::to_allocvec(&payload).map_err(|e| e.to_string())?;
    let info = pairing_bootstrap_info(&pending.request.invite_id, "grant");
    let sealed = crypto::seal_bootstrap(&pending.request.identity.x25519_pub, &info, &plaintext)
        .map_err(|e| e.to_string())?;
    let grant = PairingRosterGrant {
        invite_id: pending.request.invite_id.clone(),
        recipient_id: pending.request.identity.signing_pub.clone(),
        sealed,
    };
    let base = state.ntfy_base.lock().await.clone();
    publish_wire(
        &base,
        &pending.rendezvous_topic,
        WireMessage::PairingGrant(grant),
        "join-approved",
    )
    .await?;
    mark_pairing_request_decided(state.inner(), &pending)?;
    state.pending_joins.lock().await.remove(&request_id);
    let _ = app.emit("roster-updated", ());
    let _ = app.emit("join-request-resolved", request_id);
    let _ = next;
    Ok(())
}

async fn join_active_sync_group(
    state: &Arc<AppState>,
    app: tauri::AppHandle,
    invite: crate::pairing::PairingInvite,
    label: String,
) -> Result<(), String> {
    let label = sanitize_device_label(&label).unwrap_or_else(|_| detected_device_label());
    let my_identity = roster::DeviceIdentity::from_keypairs(&state.device, &label);
    let base = state.ntfy_base.lock().await.clone();
    let invite_id = invite.invite_id.clone();
    let requested_at = now_unix();
    let join_req = crate::pairing::build_network_join_request(
        invite_id.clone(),
        my_identity,
        &invite.secret,
        requested_at,
    );
    let plaintext = postcard::to_allocvec(&join_req).map_err(|e| e.to_string())?;
    let info = pairing_bootstrap_info(&invite_id, "join");
    let sealed = crypto::seal_bootstrap(&invite.admin_x25519, &info, &plaintext)
        .map_err(|e| e.to_string())?;
    let envelope = PairingJoinEnvelope {
        invite_id: invite_id.clone(),
        sealed,
    };
    *state.pending_network_join.lock().await = Some(PendingNetworkJoin {
        invite_id: invite_id.clone(),
        rendezvous_topic: invite.rendezvous_topic.clone(),
        admin_pub: invite.admin_pub,
        requested_at,
    });
    start_auxiliary_subscriber(
        state,
        app,
        format!("pending:{invite_id}"),
        invite.rendezvous_topic.clone(),
    )
    .await;
    let timeout_state = state.clone();
    let timeout_invite_id = invite_id.clone();
    let timeout_requested_at = requested_at;
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(
            JOIN_REQUEST_MAX_AGE_SECS + 60,
        ))
        .await;
        let should_stop = {
            let mut pending = timeout_state.pending_network_join.lock().await;
            if pending.as_ref().is_some_and(|pending| {
                pending.invite_id == timeout_invite_id
                    && pending.requested_at == timeout_requested_at
            }) {
                *pending = None;
                true
            } else {
                false
            }
        };
        if should_stop {
            stop_auxiliary_subscriber(&timeout_state, &format!("pending:{timeout_invite_id}"))
                .await;
        }
    });
    if let Err(error) = publish_wire(
        &base,
        &invite.rendezvous_topic,
        WireMessage::PairingJoin(envelope),
        "join-request",
    )
    .await
    {
        *state.pending_network_join.lock().await = None;
        stop_auxiliary_subscriber(state, &format!("pending:{invite_id}")).await;
        return Err(error);
    }

    Ok(())
}

/// Join an existing room from a pairing URI. Used by the first group onboarding flow.
#[tauri::command]
pub async fn join_room(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    uri: String,
    label: String,
) -> Result<(), String> {
    let invite = crate::pairing::parse_uri(&uri).map_err(|e| e.to_string())?;
    let previous_id = state.settings.lock().await.active_sync_group_id.clone();
    let group_id = ensure_active_sync_group(state.inner(), "My devices").await?;
    if let Err(error) = join_active_sync_group(state.inner(), app.clone(), invite, label).await {
        if previous_id.is_none() {
            remove_sync_group_from_device(state.inner(), &app, &group_id, None).await?;
        }
        return Err(error);
    }
    Ok(())
}

#[tauri::command]
pub async fn join_sync_group(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    name: String,
    uri: String,
    label: String,
) -> Result<(), String> {
    let name = sanitize_sync_group_name(&name)?;
    let invite = crate::pairing::parse_uri(&uri).map_err(|e| e.to_string())?;
    let id = network::new_id();
    let (previous_id, previous_default_id) = {
        let mut settings = state.settings.lock().await;
        add_sync_group_config(&mut settings, id.clone(), name)?
    };
    if let Err(error) = persist_settings(state.inner()).await {
        let mut settings = state.settings.lock().await;
        settings.sync_groups.retain(|group| group.id != id);
        settings.default_sync_group_id = previous_default_id;
        return Err(error);
    }
    if let Err(error) = activate_sync_group(state.inner(), &app, &id).await {
        let mut settings = state.settings.lock().await;
        settings.sync_groups.retain(|group| group.id != id);
        settings.active_sync_group_id = previous_id;
        settings.default_sync_group_id = previous_default_id;
        drop(settings);
        let _ = persist_settings(state.inner()).await;
        return Err(error);
    }
    if let Err(error) = join_active_sync_group(state.inner(), app.clone(), invite, label).await {
        remove_sync_group_from_device(state.inner(), &app, &id, previous_id.as_deref()).await?;
        return Err(error);
    }
    Ok(())
}
