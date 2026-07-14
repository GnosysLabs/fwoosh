//! Clipboard-history IPC commands and frontend DTOs.

use super::*;

/// Sign and publish deletion messages for clip IDs that the caller has
/// already authorized for the active group.
async fn broadcast_clip_deletions(
    state: &Arc<AppState>,
    msg_ids: &[[u8; 16]],
) -> Result<(), String> {
    if msg_ids.is_empty() {
        return Ok(());
    }
    let room = state
        .roster
        .lock()
        .await
        .as_ref()
        .map(|verified| (verified.topic().to_string(), verified.epoch()));
    let Some((topic, epoch)) = room else {
        return Ok(());
    };
    let base = state.ntfy_base.lock().await.clone();
    for msg_id in msg_ids {
        let delete_msg = sign_delete_clip(&state.device, *msg_id, topic.clone(), epoch, now_unix());
        publish_wire(&base, &topic, WireMessage::DeleteClip(delete_msg), "delete").await?;
    }
    Ok(())
}

/// Get the most recent N clips from local history.
#[tauri::command]
pub async fn recent_clips(
    state: State<'_, Arc<AppState>>,
    limit: Option<i64>,
) -> Result<Vec<ClipDto>, String> {
    let group_id = current_sync_group_id(state.inner()).await?;
    let clips = state
        .store
        .recent_for_group(&group_id, limit.unwrap_or(50))
        .map_err(|e| e.to_string())?;
    Ok(clips.into_iter().map(ClipDto::from).collect())
}

/// Search local history.
#[tauri::command]
pub async fn search_clips(
    state: State<'_, Arc<AppState>>,
    query: String,
) -> Result<Vec<ClipDto>, String> {
    let group_id = current_sync_group_id(state.inner()).await?;
    let clips = state
        .store
        .search_for_group(&group_id, &query, 50_i64)
        .map_err(|e| e.to_string())?;
    Ok(clips.into_iter().map(ClipDto::from).collect())
}

/// Delete a clip from local history by id, and ask paired devices to remove
/// their matching history row when this row is tied to a relay message id.
#[tauri::command]
pub async fn delete_clip(state: State<'_, Arc<AppState>>, id: i64) -> Result<(), String> {
    let active_group_id = current_sync_group_id(state.inner()).await?;
    let clip_group_id = state
        .store
        .group_id_for_clip(id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "clip not found".to_string())?;
    if clip_group_id != active_group_id {
        return Err("clip does not belong to the active sync group".to_string());
    }
    let msg_id = state.store.msg_id_for_clip(id).map_err(|e| e.to_string())?;

    if let Some(msg_id) = msg_id {
        broadcast_clip_deletions(state.inner(), std::slice::from_ref(&msg_id)).await?;
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
    let group_id = current_sync_group_id(state.inner()).await?;
    let msg_ids = state
        .store
        .all_msg_ids_for_group(&group_id)
        .map_err(|e| e.to_string())?;
    broadcast_clip_deletions(state.inner(), &msg_ids).await?;

    state
        .store
        .delete_all_for_group(&group_id)
        .map_err(|e| e.to_string())?;
    let _ = app.emit("clip-stored", ());
    Ok(())
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

/// Copy text to the system clipboard (called from frontend on click-to-copy).
#[tauri::command]
pub async fn copy_to_clipboard(app: tauri::AppHandle, text: String) -> Result<(), String> {
    app.clipboard().write_text(text).map_err(|e| e.to_string())
}
