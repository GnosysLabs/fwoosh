//! Sync Group settings, roster persistence, membership, and lifecycle commands.

use super::*;

pub fn load_settings(path: &Path) -> AppSettings {
    let Ok(bytes) = std::fs::read(path) else {
        return AppSettings::default();
    };
    match serde_json::from_slice::<AppSettings>(&bytes) {
        Ok(mut settings) => {
            if settings.stun_servers.is_empty()
                || normalize_stun_servers(settings.stun_servers.clone()).is_err()
            {
                settings.stun_servers = AppSettings::default().stun_servers;
            }
            settings.device_label = settings
                .device_label
                .and_then(|label| sanitize_device_label(&label).ok());
            if normalize_transfer_timeout_minutes(settings.transfer_timeout_minutes).is_err() {
                settings.transfer_timeout_minutes = DEFAULT_FILE_TRANSFER_TIMEOUT_MINUTES;
            }
            settings.sync_groups.retain(|group| {
                network::valid_id(&group.id) && sanitize_sync_group_name(&group.name).is_ok()
            });
            for group in &mut settings.sync_groups {
                if let Ok(name) = sanitize_sync_group_name(&group.name) {
                    group.name = name;
                }
            }
            if settings
                .active_sync_group_id
                .as_ref()
                .is_none_or(|active| !settings.sync_groups.iter().any(|group| &group.id == active))
            {
                settings.active_sync_group_id =
                    settings.sync_groups.first().map(|group| group.id.clone());
            }
            settings
        }
        Err(_) => AppSettings::default(),
    }
}

pub fn save_settings(path: &Path, settings: &AppSettings) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(settings).map_err(|e| e.to_string())?;
    std::fs::write(path, bytes).map_err(|e| e.to_string())
}

pub(super) async fn persist_settings(state: &Arc<AppState>) -> Result<(), String> {
    let Some(path) = state.settings_path.lock().await.clone() else {
        return Ok(());
    };
    let settings = state.settings.lock().await.clone();
    save_settings(&path, &settings)
}

pub(super) fn sanitize_sync_group_name(name: &str) -> Result<String, String> {
    let compact = name.split_whitespace().collect::<Vec<_>>().join(" ");
    let name: String = compact.chars().take(MAX_SYNC_GROUP_NAME_CHARS).collect();
    if name.is_empty() {
        return Err("sync group name cannot be empty".to_string());
    }
    Ok(name)
}

fn group_roster_path(groups_dir: &Path, group_id: &str) -> Result<PathBuf, String> {
    if !network::valid_id(group_id) {
        return Err("invalid sync group id".to_string());
    }
    Ok(groups_dir.join(format!("{group_id}.bin")))
}

pub fn prepare_sync_groups(
    settings: &mut AppSettings,
    groups_dir: &Path,
    legacy_roster_path: &Path,
) -> Result<Option<(PathBuf, Option<VerifiedRoster>)>, String> {
    std::fs::create_dir_all(groups_dir).map_err(|e| e.to_string())?;

    if settings.sync_groups.is_empty() {
        if let Some(legacy_roster) = load_persisted_roster(legacy_roster_path) {
            let id = network::new_id();
            let path = group_roster_path(groups_dir, &id)?;
            std::fs::copy(legacy_roster_path, &path).map_err(|e| e.to_string())?;
            settings.sync_groups.push(SyncGroupConfig {
                id: id.clone(),
                name: "My devices".to_string(),
            });
            settings.active_sync_group_id = Some(id);
            return Ok(Some((path, Some(legacy_roster))));
        }
        return Ok(None);
    }

    let active_id = settings
        .active_sync_group_id
        .clone()
        .filter(|id| settings.sync_groups.iter().any(|group| &group.id == id))
        .unwrap_or_else(|| settings.sync_groups[0].id.clone());
    settings.active_sync_group_id = Some(active_id.clone());
    let path = group_roster_path(groups_dir, &active_id)?;
    let roster = load_persisted_roster(&path);
    Ok(Some((path, roster)))
}

pub(super) fn sanitize_device_label(label: &str) -> Result<String, String> {
    let compact = label.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = compact.trim();
    if trimmed.is_empty() {
        return Err("device name cannot be empty".to_string());
    }
    let label: String = trimmed.chars().take(MAX_DEVICE_LABEL_CHARS).collect();
    Ok(label)
}

pub(super) fn detected_device_label() -> String {
    let label = whoami::devicename()
        .or_else(|_| whoami::hostname())
        .unwrap_or_else(|_| "This device".to_string());
    sanitize_device_label(&label).unwrap_or_else(|_| "This device".to_string())
}

pub(super) async fn configured_device_label(state: &Arc<AppState>) -> String {
    state
        .settings
        .lock()
        .await
        .device_label
        .clone()
        .unwrap_or_else(detected_device_label)
}

pub(super) fn normalize_stun_servers(input: Vec<String>) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for raw in input {
        let value = raw.trim().trim_end_matches('/').to_string();
        if value.is_empty() {
            continue;
        }
        let lower = value.to_ascii_lowercase();
        if lower.starts_with("turn:") || lower.starts_with("turns:") {
            return Err("TURN servers are not supported".to_string());
        }
        if !lower.starts_with("stun:") {
            return Err("STUN server URLs must start with stun:".to_string());
        }
        let host = value.trim_start_matches("stun:");
        if host.is_empty() || host.contains('@') || host.contains(' ') {
            return Err("invalid STUN server URL".to_string());
        }
        if !out.iter().any(|existing| existing == &value) {
            out.push(value);
        }
    }
    if out.is_empty() {
        return Err("at least one STUN server is required".to_string());
    }
    if out.len() > MAX_STUN_SERVERS {
        return Err(format!(
            "at most {MAX_STUN_SERVERS} STUN servers are supported"
        ));
    }
    Ok(out)
}

#[tauri::command]
pub async fn suggest_device_label(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    Ok(configured_device_label(state.inner()).await)
}

#[tauri::command]
pub async fn network_settings(
    state: State<'_, Arc<AppState>>,
) -> Result<NetworkSettingsDto, String> {
    let settings = state.settings.lock().await.clone();
    Ok(NetworkSettingsDto {
        stun_servers: settings.stun_servers,
        transfer_timeout_minutes: settings.transfer_timeout_minutes,
    })
}

#[tauri::command]
pub async fn set_network_settings(
    state: State<'_, Arc<AppState>>,
    stun_servers: Vec<String>,
    transfer_timeout_minutes: u64,
) -> Result<(), String> {
    let normalized_stun_servers = normalize_stun_servers(stun_servers)?;
    let normalized_timeout = normalize_transfer_timeout_minutes(transfer_timeout_minutes)?;
    {
        let mut settings = state.settings.lock().await;
        settings.stun_servers = normalized_stun_servers;
        settings.transfer_timeout_minutes = normalized_timeout;
    }
    persist_settings(state.inner()).await
}

/// Returns whether the device is currently in a room (roster loaded) + the
/// member count, so the frontend can show the right UI on startup.
#[derive(serde::Serialize)]
pub struct RoomState {
    pub in_room: bool,
    pub member_count: usize,
    pub topic: String,
    pub network_id: Option<String>,
    pub network_name: String,
}

#[derive(serde::Serialize)]
pub struct DeviceDto {
    pub id: String,
    pub label: String,
    pub is_self: bool,
    pub is_admin: bool,
    pub can_revoke: bool,
}

async fn configured_groups_dir(state: &Arc<AppState>) -> Result<PathBuf, String> {
    state
        .groups_dir
        .lock()
        .await
        .clone()
        .ok_or_else(|| "sync group storage is not initialized".to_string())
}

pub(super) async fn current_sync_group_id(state: &Arc<AppState>) -> Result<String, String> {
    state
        .settings
        .lock()
        .await
        .active_sync_group_id
        .clone()
        .ok_or_else(|| "no sync group is active".to_string())
}

pub(super) async fn ensure_active_sync_group(
    state: &Arc<AppState>,
    default_name: &str,
) -> Result<String, String> {
    let existing = {
        let settings = state.settings.lock().await;
        settings
            .active_sync_group_id
            .clone()
            .filter(|active| settings.sync_groups.iter().any(|group| &group.id == active))
    };
    if let Some(existing) = existing {
        return Ok(existing);
    }

    let groups_dir = configured_groups_dir(state).await?;
    let id = network::new_id();
    let name = sanitize_sync_group_name(default_name)?;
    {
        let mut settings = state.settings.lock().await;
        settings.sync_groups.push(SyncGroupConfig {
            id: id.clone(),
            name,
        });
        settings.active_sync_group_id = Some(id.clone());
    }
    *state.roster_path.lock().await = Some(group_roster_path(&groups_dir, &id)?);
    if let Err(error) = persist_settings(state).await {
        let mut settings = state.settings.lock().await;
        settings.sync_groups.retain(|group| group.id != id);
        settings.active_sync_group_id = None;
        *state.roster_path.lock().await = None;
        return Err(error);
    }
    Ok(id)
}

async fn stop_active_group_runtime(state: &Arc<AppState>) {
    if let Some(tx) = state.subscriber_shutdown.lock().await.take() {
        let _ = tx.send(());
    }
    *state.roster.lock().await = None;
    for (_, tx) in state.auxiliary_subscriber_shutdowns.lock().await.drain() {
        let _ = tx.send(());
    }
    state.pending_joins.lock().await.clear();
    *state.pending_network_join.lock().await = None;
    state.pending.lock().await.clear();
}

pub(super) async fn activate_sync_group(
    state: &Arc<AppState>,
    app: &tauri::AppHandle,
    group_id: &str,
) -> Result<(), String> {
    if !state.file_transfers.lock().await.is_empty() {
        return Err("finish or cancel active file transfers before switching groups".to_string());
    }
    let group_exists = state
        .settings
        .lock()
        .await
        .sync_groups
        .iter()
        .any(|group| group.id == group_id);
    if !group_exists {
        return Err("sync group not found".to_string());
    }

    stop_active_group_runtime(state).await;
    let groups_dir = configured_groups_dir(state).await?;
    let roster_path = group_roster_path(&groups_dir, group_id)?;
    let roster = load_persisted_roster(&roster_path);
    let topic = roster.as_ref().map(|verified| verified.topic().to_string());
    *state.roster_path.lock().await = Some(roster_path);
    *state.roster.lock().await = roster;
    state.settings.lock().await.active_sync_group_id = Some(group_id.to_string());
    persist_settings(state).await?;

    if let Some(topic) = topic {
        start_subscriber(state, app.clone(), &topic).await;
        start_invitation_subscribers(state, app.clone()).await;
    }
    let _ = app.emit("sync-group-changed", group_id);
    let _ = app.emit("roster-updated", ());
    Ok(())
}

#[tauri::command]
pub async fn sync_groups(state: State<'_, Arc<AppState>>) -> Result<Vec<SyncGroupDto>, String> {
    let settings = state.settings.lock().await.clone();
    let groups_dir = configured_groups_dir(state.inner()).await?;
    let active_id = settings.active_sync_group_id.as_deref();
    let mut out = Vec::with_capacity(settings.sync_groups.len());
    for group in settings.sync_groups {
        let active = active_id == Some(group.id.as_str());
        let roster = if active {
            state.roster.lock().await.clone()
        } else {
            let path = group_roster_path(&groups_dir, &group.id)?;
            load_persisted_roster(&path)
        };
        out.push(SyncGroupDto {
            id: group.id,
            name: group.name,
            active,
            connected: roster.is_some(),
            member_count: roster
                .as_ref()
                .map(|verified| verified.entry.devices.len())
                .unwrap_or(0),
        });
    }
    Ok(out)
}

#[tauri::command]
pub async fn switch_sync_group(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    group_id: String,
) -> Result<(), String> {
    activate_sync_group(state.inner(), &app, group_id.trim()).await
}

#[tauri::command]
pub async fn rename_sync_group(
    state: State<'_, Arc<AppState>>,
    group_id: String,
    name: String,
) -> Result<(), String> {
    let name = sanitize_sync_group_name(&name)?;
    let mut settings = state.settings.lock().await;
    let group = settings
        .sync_groups
        .iter_mut()
        .find(|group| group.id == group_id)
        .ok_or_else(|| "sync group not found".to_string())?;
    group.name = name;
    drop(settings);
    persist_settings(state.inner()).await
}

async fn create_roster_for_active_group(
    state: &Arc<AppState>,
    app: tauri::AppHandle,
    label: String,
) -> Result<PairingCodeDto, String> {
    let label = sanitize_device_label(&label).unwrap_or_else(|_| detected_device_label());
    let topic = roster::new_topic();
    let genesis = roster::build_genesis(&state.device, &label, &topic);
    let signed = roster::sign_and_chain(&state.device, genesis, None).map_err(|e| e.to_string())?;
    let verified = VerifiedRoster::verify_first(signed.clone()).map_err(|e| e.to_string())?;
    *state.roster.lock().await = Some(verified);
    persist_roster(state, &signed).await;
    start_subscriber(state, app.clone(), &topic).await;
    broadcast_roster(state, &signed, &topic).await;
    let _ = app.emit("sync-groups-updated", ());
    let code = issue_pairing_code(state, None, true).await?;
    start_invitation_subscribers(state, app).await;
    Ok(code)
}

#[tauri::command]
pub async fn create_sync_group(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    name: String,
    label: String,
) -> Result<PairingCodeDto, String> {
    let name = sanitize_sync_group_name(&name)?;
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
    match create_roster_for_active_group(state.inner(), app.clone(), label).await {
        Ok(code) => Ok(code),
        Err(error) => {
            remove_sync_group_from_device(state.inner(), &app, &id, previous_id.as_deref()).await?;
            Err(error)
        }
    }
}

#[tauri::command]
pub async fn room_state(state: State<'_, Arc<AppState>>) -> Result<RoomState, String> {
    let guard = state.roster.lock().await;
    let settings = state.settings.lock().await.clone();
    let active_id = settings.active_sync_group_id.clone();
    let active_name = active_id
        .as_ref()
        .and_then(|id| settings.sync_groups.iter().find(|group| &group.id == id))
        .map(|group| group.name.clone())
        .unwrap_or_else(|| "My devices".to_string());
    match guard.as_ref() {
        Some(v) => Ok(RoomState {
            in_room: true,
            member_count: v.entry.devices.len(),
            topic: v.topic().to_string(),
            network_id: active_id,
            network_name: active_name,
        }),
        None => Ok(RoomState {
            in_room: false,
            member_count: 0,
            topic: String::new(),
            network_id: None,
            network_name: active_name,
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
) -> Result<PairingCodeDto, String> {
    ensure_active_sync_group(state.inner(), "My devices").await?;
    create_roster_for_active_group(state.inner(), app, label).await
}

#[tauri::command]
pub async fn rename_device(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    label: String,
) -> Result<(), String> {
    let label = sanitize_device_label(&label)?;
    {
        let mut settings = state.settings.lock().await;
        settings.device_label = Some(label.clone());
    }
    persist_settings(state.inner()).await?;

    let Some(verified) = state.roster.lock().await.clone() else {
        return Ok(());
    };

    if !verified.is_active(&state.device.signing_pub) {
        return Ok(());
    }

    if state.device.signing_pub == verified.entry.admin_id {
        let unsigned =
            roster::build_update_device_label(&verified.entry, &state.device.signing_pub, &label)
                .map_err(|e| e.to_string())?;
        let signed = roster::sign_and_chain(&state.device, unsigned, Some(&verified.entry))
            .map_err(|e| e.to_string())?;
        let next = verified
            .verify_next(signed.clone())
            .map_err(|e| e.to_string())?;
        let topic = next.topic().to_string();
        *state.roster.lock().await = Some(next.clone());
        cancel_transfers_not_in_roster(&state, &app, &next).await;
        persist_roster(&state, &signed).await;
        broadcast_roster(&state, &signed, &topic).await;
        let _ = app.emit("roster-updated", ());
        return Ok(());
    }

    let msg = sign_rename_device(
        &state.device,
        verified.topic().to_string(),
        verified.epoch(),
        label,
        now_unix(),
    );
    let base = state.ntfy_base.lock().await.clone();
    publish_wire(
        &base,
        verified.topic(),
        WireMessage::RenameDevice(msg),
        "rename",
    )
    .await?;
    Ok(())
}

/// Broadcast a roster entry to the relay so other devices can adopt/update.
pub(super) async fn broadcast_roster(
    state: &Arc<AppState>,
    entry: &roster::RosterEntry,
    topic: &str,
) {
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

/// Persist the current roster chain to disk so it survives restarts without
/// trusting a lone non-genesis snapshot.
pub(super) async fn persist_roster(state: &Arc<AppState>, entry: &roster::RosterEntry) {
    if let Some(path) = state.roster_path.lock().await.clone() {
        match build_persisted_roster_chain(&path, entry) {
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
pub fn load_persisted_roster(path: &std::path::Path) -> Option<VerifiedRoster> {
    let bytes = std::fs::read(path).ok()?;
    let entries = decode_persisted_roster_entries(&bytes)?;
    verify_persisted_roster_entries(entries).ok()
}

fn build_persisted_roster_chain(
    path: &Path,
    entry: &roster::RosterEntry,
) -> Result<Vec<u8>, String> {
    let mut entries = if entry.epoch == 0 {
        Vec::new()
    } else if let Ok(bytes) = std::fs::read(path) {
        decode_persisted_roster_entries(&bytes).unwrap_or_default()
    } else {
        Vec::new()
    };

    if entry.epoch == 0 {
        entries.push(entry.clone());
    } else if let Ok(current) = verify_persisted_roster_entries(entries.clone()) {
        if entry.epoch == current.epoch() + 1 && current.verify_next(entry.clone()).is_ok() {
            entries.push(entry.clone());
        } else if entry.epoch == current.epoch() {
            entries.pop();
            entries.push(entry.clone());
        } else {
            return Err("refusing to persist roster without a verified chain".to_string());
        }
    } else {
        return Err("refusing to persist roster without a verified chain".to_string());
    }

    let verified = verify_persisted_roster_entries(entries.clone())?;
    if verified.epoch() != entry.epoch {
        return Err("persisted roster chain ended at the wrong epoch".to_string());
    }
    let chain = PersistedRosterChain {
        version: 2,
        entries,
    };
    postcard::to_allocvec(&chain).map_err(|e| e.to_string())
}

pub(super) fn decode_persisted_roster_entries(bytes: &[u8]) -> Option<Vec<roster::RosterEntry>> {
    if let Ok(chain) = postcard::from_bytes::<PersistedRosterChain>(bytes) {
        if chain.version == 2 {
            return Some(chain.entries);
        }
    }
    postcard::from_bytes::<roster::RosterEntry>(bytes)
        .ok()
        .map(|entry| vec![entry])
}

pub(super) fn verify_persisted_roster_entries(
    entries: Vec<roster::RosterEntry>,
) -> Result<VerifiedRoster, String> {
    let mut iter = entries.into_iter();
    let first = iter
        .next()
        .ok_or_else(|| "persisted roster chain is empty".to_string())?;
    let mut verified = VerifiedRoster::verify_first(first).map_err(|e| e.to_string())?;
    for entry in iter {
        verified = verified.verify_next(entry).map_err(|e| e.to_string())?;
    }
    Ok(verified)
}

pub(super) async fn remove_sync_group_from_device(
    state: &Arc<AppState>,
    app: &tauri::AppHandle,
    group_id: &str,
    preferred_next: Option<&str>,
) -> Result<(), String> {
    if !state.file_transfers.lock().await.is_empty() {
        return Err("finish or cancel active file transfers before leaving a group".to_string());
    }
    let current_path = state.roster_path.lock().await.clone();
    let next_id = {
        let mut settings = state.settings.lock().await;
        if settings.active_sync_group_id.as_deref() != Some(group_id) {
            return Err("sync group is not active".to_string());
        }
        settings.sync_groups.retain(|group| group.id != group_id);
        preferred_next
            .filter(|candidate| {
                settings
                    .sync_groups
                    .iter()
                    .any(|group| group.id == *candidate)
            })
            .map(str::to_string)
            .or_else(|| settings.sync_groups.first().map(|group| group.id.clone()))
    };

    if let Some(next_id) = next_id {
        activate_sync_group(state, app, &next_id).await?;
    } else {
        stop_active_group_runtime(state).await;
        state.settings.lock().await.active_sync_group_id = None;
        *state.roster_path.lock().await = None;
        persist_settings(state).await?;
        let _ = app.emit("sync-group-changed", "");
        let _ = app.emit("roster-updated", ());
    }

    if let Some(path) = current_path {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    state
        .store
        .delete_all_for_group(group_id)
        .map_err(|error| error.to_string())?;
    state
        .invitations
        .lock()
        .await
        .retain(|_, invite| invite.network_id != group_id);
    persist_invitations(state).await?;
    let _ = app.emit("sync-groups-updated", ());
    let _ = app.emit("clip-stored", ());
    Ok(())
}

/// Remove the active sync group from this device, then activate the next group
/// if one remains.
#[tauri::command]
pub async fn leave_room(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let active_id = state.settings.lock().await.active_sync_group_id.clone();
    let Some(active_id) = active_id else {
        stop_active_group_runtime(state.inner()).await;
        return Ok(());
    };
    remove_sync_group_from_device(state.inner(), &app, &active_id, None).await
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

    let verified = require_admin_roster(state.inner(), "revoke devices").await?;
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
    publish_sealed_clip(&base, &old_topic, sealed, ntfy::PublishOptions::default()).await?;

    *state.roster.lock().await = Some(next.clone());
    cancel_transfers_not_in_roster(&state, &app, &next).await;
    state.pending.lock().await.clear();
    persist_roster(&state, &signed).await;
    start_subscriber(&state, app.clone(), &new_topic).await;
    broadcast_roster(&state, &signed, &new_topic).await;
    let _ = app.emit("roster-updated", ());
    Ok(())
}
