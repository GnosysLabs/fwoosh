pub mod commands;
pub mod crypto;
pub mod keychain;
pub mod network;
pub mod ntfy;
pub mod pairing;
pub mod roster;
pub mod store;

use commands::AppState;
use std::sync::Arc;
use tauri::{Emitter, Manager};

#[cfg(desktop)]
use std::path::PathBuf;
#[cfg(all(desktop, not(target_os = "macos")))]
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
};
#[cfg(desktop)]
use tauri::{DragDropEvent, WebviewEvent, WindowEvent};
#[cfg(desktop)]
use tauri_plugin_global_shortcut::{Code, Modifiers, Shortcut, ShortcutState};

#[cfg(desktop)]
/// Toggle the popup window: show + focus, or dismiss if already visible.
fn toggle_popup(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let visible = win.is_visible().unwrap_or(false);
        let minimized = win.is_minimized().unwrap_or(false);
        let focused = win.is_focused().unwrap_or(false);

        if visible && !minimized && focused {
            let _ = commands::dismiss_main_window(app.clone());
        } else {
            let _ = commands::reveal_main_window(app);
        }
    }
}

#[cfg(desktop)]
/// Show and focus the popup window.
fn show_popup(app: &tauri::AppHandle) {
    let _ = commands::reveal_main_window(app);
}

#[cfg(desktop)]
fn grant_dropped_paths(app: tauri::AppHandle, paths: &[PathBuf]) {
    let path = match paths {
        [path] => path.clone(),
        _ => {
            let _ = app.emit("file-drop-rejected", "Drop one file at a time");
            return;
        }
    };
    let state = app.state::<Arc<AppState>>().inner().clone();
    tauri::async_runtime::spawn(async move {
        match commands::grant_dropped_file(&state, path).await {
            Ok(grant) => {
                let _ = app.emit("file-drop-granted", grant);
            }
            Err(e) => {
                let _ = app.emit("file-drop-rejected", e);
            }
        }
    });
}

fn restart_relay_subscribers(app: &tauri::AppHandle) {
    let state = app.state::<Arc<AppState>>().inner().clone();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        commands::restart_subscribers(&state, app).await;
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_os::init());
    #[cfg(desktop)]
    let builder = builder.plugin(
        tauri_plugin_global_shortcut::Builder::new()
            .with_shortcut(Shortcut::new(
                Some(Modifiers::SHIFT | Modifiers::CONTROL),
                Code::KeyV,
            ))
            .expect("invalid shortcut")
            .with_handler(move |app, _shortcut, event| {
                if event.state == ShortcutState::Pressed {
                    toggle_popup(app);
                }
            })
            .build(),
    );
    #[cfg(mobile)]
    let builder = builder.plugin(tauri_plugin_barcode_scanner::init());

    builder
        .setup(|app| {
            // --- Load device keypairs + history DB key ---
            // Set the file-fallback dir for tests or explicit development
            // opt-in. Normal runs fail closed if OS credential storage fails.
            let app_data = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| std::env::temp_dir());
            keychain::set_fallback_dir(app_data.clone());

            let (device, db_key) = keychain::load_or_create_core_secrets()
                .expect("failed to load app secrets (and no file fallback)");
            let db_path = app_data.join("history.db");
            let store =
                store::HistoryStore::open(&db_path, &db_key).expect("failed to open history store");

            let state = Arc::new(AppState::new(device, store));

            // Load settings and migrate the legacy single-room roster into the
            // named sync-group catalog. Each group keeps an independent,
            // verified roster chain under `groups/`.
            let legacy_roster_path = app_data.join("roster.bin");
            let groups_dir = app_data.join("groups");
            let settings_path = app_data.join("settings.json");
            #[cfg(target_os = "windows")]
            let is_first_launch = !settings_path.exists();
            if let Ok(mut gd) = state.groups_dir.try_lock() {
                *gd = Some(groups_dir.clone());
            }
            if let Ok(mut sp) = state.settings_path.try_lock() {
                *sp = Some(settings_path.clone());
            }
            let mut loaded_settings = commands::load_settings(&settings_path);
            if let Ok(mut invitations) = state.invitations.try_lock() {
                *invitations = commands::load_invitations_from_keychain();
            }
            if let Some((roster_path, verified)) = commands::prepare_sync_groups(
                &mut loaded_settings,
                &groups_dir,
                &legacy_roster_path,
            )
            .expect("failed to prepare sync groups")
            {
                if let Ok(mut rp) = state.roster_path.try_lock() {
                    *rp = Some(roster_path);
                }
                if let Some(verified) = verified {
                    if let Ok(mut r) = state.roster.try_lock() {
                        *r = Some(verified);
                    }
                }
            }
            commands::save_settings(&settings_path, &loaded_settings)
                .expect("failed to persist sync group settings");
            if let Some(active_group_id) = loaded_settings.active_sync_group_id.as_deref() {
                state
                    .store
                    .assign_legacy_group(active_group_id)
                    .expect("failed to migrate legacy clip history");
            }
            if let Ok(mut settings) = state.settings.try_lock() {
                *settings = loaded_settings;
            }

            app.manage(state.clone());

            // On mobile, this same helper is called on `RunEvent::Resumed`.
            // It reconnects through the normal relay catch-up path without a
            // push provider or a second backend.
            restart_relay_subscribers(app.handle());

            #[cfg(all(desktop, not(target_os = "macos")))]
            {
                // --- Tray icon + menu ---
                let show_item = MenuItem::with_id(app, "show", "Show Fwoosh", true, None::<&str>)?;
                let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
                let menu = Menu::with_items(app, &[&show_item, &quit_item])?;
                let _tray = TrayIconBuilder::new()
                    .icon(app.default_window_icon().unwrap().clone())
                    .menu(&menu)
                    // Let the click handler below open the popup; keep the menu
                    // accessible with a secondary click.
                    .show_menu_on_left_click(false)
                    .tooltip("Fwoosh")
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "show" => show_popup(app),
                        "quit" => app.exit(0),
                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let tauri::tray::TrayIconEvent::Click {
                            button: tauri::tray::MouseButton::Left,
                            button_state: tauri::tray::MouseButtonState::Up,
                            ..
                        } = event
                        {
                            toggle_popup(tray.app_handle());
                        }
                    })
                    .build(app)?;

                // Windows hides newly installed tray icons in the overflow
                // area by default. Make the first successful launch visible
                // so Store users know Fwoosh opened; later launches retain the
                // tray-first behavior.
                if let Some(win) = app.get_webview_window("main") {
                    #[cfg(target_os = "windows")]
                    let _ = win.set_shadow(false);

                    #[cfg(target_os = "windows")]
                    if is_first_launch {
                        show_popup(app.handle());
                    } else {
                        let _ = win.hide();
                    }

                    #[cfg(not(target_os = "windows"))]
                    let _ = win.hide();
                }
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            #[cfg(desktop)]
            {
                // Keep the process alive: macOS minimizes to its Dock, while
                // tray-oriented desktop platforms hide the popup.
                if let WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = commands::dismiss_main_window(window.app_handle().clone());
                }
                if let WindowEvent::DragDrop(DragDropEvent::Drop { paths, .. }) = event {
                    grant_dropped_paths(window.app_handle().clone(), paths);
                }
            }
            #[cfg(not(desktop))]
            let _ = (window, event);
        })
        .on_webview_event(|webview, event| {
            #[cfg(desktop)]
            {
                if let WebviewEvent::DragDrop(DragDropEvent::Drop { paths, .. }) = event {
                    grant_dropped_paths(webview.app_handle().clone(), paths);
                }
            }
            #[cfg(not(desktop))]
            let _ = (webview, event);
        })
        .invoke_handler(tauri::generate_handler![
            commands::sync_groups::create_room,
            commands::sync_groups::create_sync_group,
            commands::pairing_commands::new_pairing_code,
            commands::pairing_commands::create_temporary_pairing_code,
            commands::pairing_commands::rotate_pairing_code,
            commands::pairing_commands::revoke_pairing_code,
            commands::pairing_commands::revoke_permanent_pairing_code,
            commands::pairing_commands::pending_join_requests,
            commands::pairing_commands::approve_join_request,
            commands::pairing_commands::reject_join_request,
            commands::pairing_commands::join_room,
            commands::pairing_commands::join_sync_group,
            commands::sync_groups::leave_room,
            commands::sync_groups::sync_groups,
            commands::sync_groups::switch_sync_group,
            commands::sync_groups::set_default_sync_group,
            commands::sync_groups::rename_sync_group,
            commands::sync_groups::suggest_device_label,
            commands::sync_groups::rename_device,
            commands::sync_groups::network_settings,
            commands::sync_groups::set_network_settings,
            commands::sync_groups::room_state,
            commands::sync_groups::roster_devices,
            commands::sync_groups::revoke_device,
            commands::send_clip,
            commands::transfer::start_file_send,
            commands::transfer::pending_file_offers,
            commands::transfer::accept_file_transfer,
            commands::transfer::reject_file_transfer,
            commands::transfer::cancel_file_transfer,
            commands::transfer::reveal_received_file,
            commands::history_commands::recent_clips,
            commands::history_commands::search_clips,
            commands::history_commands::delete_clip,
            commands::history_commands::delete_all_clips,
            commands::history_commands::copy_to_clipboard,
            commands::dismiss_main_window,
            commands::show_main_window,
            commands::notify_incoming_clip,
        ])
        .build(tauri::generate_context!())
        .expect("error while building Fwoosh")
        .run(|app, event| {
            #[cfg(mobile)]
            if matches!(event, tauri::RunEvent::Resumed) {
                restart_relay_subscribers(app);
            }

            // Restore the window when the macOS Dock icon is clicked.
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = event {
                show_popup(app);
            }

            #[cfg(not(any(target_os = "macos", mobile)))]
            let _ = (app, event);
        });
}
