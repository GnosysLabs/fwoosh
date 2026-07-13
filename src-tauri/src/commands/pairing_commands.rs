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
    expires_in_seconds: Option<u64>,
    reuse_permanent: bool,
) -> Result<PairingCodeDto, String> {
    let (network_id, _) = current_network_identity(state).await?;
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
        network_id,
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
) -> Result<PairingCodeDto, String> {
    require_admin_roster(state.inner(), "create pairing codes").await?;
    let code = issue_pairing_code(&state, None, true).await?;
    start_invitation_subscribers(&state, app).await;
    Ok(code)
}

#[tauri::command]
pub async fn create_temporary_pairing_code(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    expires_in_seconds: u64,
) -> Result<PairingCodeDto, String> {
    require_admin_roster(state.inner(), "create invitations").await?;
    if !(60..=30 * 24 * 60 * 60).contains(&expires_in_seconds) {
        return Err("temporary invitation must last between 1 minute and 30 days".to_string());
    }
    let code = issue_pairing_code(&state, Some(expires_in_seconds), false).await?;
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
    let code = issue_pairing_code(state.inner(), None, false).await?;
    start_invitation_subscribers(state.inner(), app).await;
    Ok(code)
}

#[tauri::command]
pub async fn revoke_permanent_pairing_code(
    state: State<'_, Arc<AppState>>,
) -> Result<bool, String> {
    require_admin_roster(state.inner(), "revoke invitations").await?;
    let (network_id, _) = current_network_identity(state.inner()).await?;
    let invite_ids = {
        let invitations = state.invitations.lock().await;
        invitations
            .values()
            .filter(|invite| invite.network_id == network_id && invite.expires_at.is_none())
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

#[tauri::command]
pub async fn reject_join_request(
    state: State<'_, Arc<AppState>>,
    request_id: String,
) -> Result<(), String> {
    require_admin_roster(state.inner(), "reject join requests").await?;
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
    let next = if verified
        .entry
        .devices
        .iter()
        .any(|device| device.signing_pub == pending.request.identity.signing_pub)
    {
        verified
    } else {
        let unsigned = roster::build_add_device(&verified.entry, pending.request.identity.clone());
        let signed = roster::sign_and_chain(&state.device, unsigned, Some(&verified.entry))
            .map_err(|e| e.to_string())?;
        let next = verified
            .verify_next(signed.clone())
            .map_err(|e| e.to_string())?;
        *state.roster.lock().await = Some(next.clone());
        cancel_transfers_not_in_roster(&state, &app, &next).await;
        persist_roster(&state, &signed).await;
        broadcast_roster(&state, &signed, next.topic()).await;
        next
    };

    let roster_path = state
        .roster_path
        .lock()
        .await
        .clone()
        .ok_or_else(|| "roster persistence is unavailable".to_string())?;
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
    let (_, network_name) = current_network_identity(state.inner()).await?;
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
    let previous_id;
    {
        let mut settings = state.settings.lock().await;
        if settings.sync_groups.len() >= 32 {
            return Err("at most 32 sync groups are supported".to_string());
        }
        settings.sync_groups.push(SyncGroupConfig {
            id: id.clone(),
            name,
        });
        previous_id = settings.active_sync_group_id.clone();
    }
    if let Err(error) = persist_settings(state.inner()).await {
        state
            .settings
            .lock()
            .await
            .sync_groups
            .retain(|group| group.id != id);
        return Err(error);
    }
    if let Err(error) = activate_sync_group(state.inner(), &app, &id).await {
        let mut settings = state.settings.lock().await;
        settings.sync_groups.retain(|group| group.id != id);
        settings.active_sync_group_id = previous_id;
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
