pub mod commands;
pub mod crypto;
pub mod keychain;
pub mod ntfy;
pub mod pairing;
pub mod roster;
pub mod store;

use commands::AppState;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    DragDropEvent, Emitter, Manager, WebviewEvent, WindowEvent,
};
use tauri_plugin_global_shortcut::{Code, Modifiers, Shortcut, ShortcutState};

/// Toggle the popup window: show + focus, or hide if already visible.
fn toggle_popup(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let visible = win.is_visible().unwrap_or(false);
        let minimized = win.is_minimized().unwrap_or(false);
        let focused = win.is_focused().unwrap_or(false);

        if visible && !minimized && focused {
            let _ = win.hide();
        } else {
            let _ = commands::reveal_main_window(app);
        }
    }
}

/// Show and focus the popup window.
fn show_popup(app: &tauri::AppHandle) {
    let _ = commands::reveal_main_window(app);
}

/// Hide the popup window.
fn hide_popup(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.hide();
    }
}

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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(
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
        )
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

            // Set the roster persistence path + load any saved room.
            let roster_path = app_data.join("roster.bin");
            let settings_path = app_data.join("settings.json");
            if let Ok(mut rp) = state.roster_path.try_lock() {
                *rp = Some(roster_path.clone());
            }
            if let Ok(mut sp) = state.settings_path.try_lock() {
                *sp = Some(settings_path.clone());
            }
            if let Ok(mut settings) = state.settings.try_lock() {
                *settings = commands::load_settings(&settings_path);
            }
            let mut startup_topic = None;
            if let Some(verified) = commands::load_persisted_roster(&roster_path) {
                startup_topic = Some(verified.topic().to_string());
                if let Ok(mut r) = state.roster.try_lock() {
                    *r = Some(verified);
                }
            }

            app.manage(state.clone());

            if let Some(topic) = startup_topic {
                let state_clone = state.clone();
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    commands::start_subscriber(&state_clone, app_handle, &topic).await;
                });
            }

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

            // Hide the window on startup; it lives in the tray.
            if let Some(win) = app.get_webview_window("main") {
                #[cfg(target_os = "windows")]
                let _ = win.set_shadow(false);
                let _ = win.hide();
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            // Hide instead of close so the app keeps running in the tray.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                hide_popup(window.app_handle());
            }
            if let WindowEvent::DragDrop(DragDropEvent::Drop { paths, .. }) = event {
                grant_dropped_paths(window.app_handle().clone(), paths);
            }
        })
        .on_webview_event(|webview, event| {
            if let WebviewEvent::DragDrop(DragDropEvent::Drop { paths, .. }) = event {
                grant_dropped_paths(webview.app_handle().clone(), paths);
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::create_room,
            commands::new_pairing_code,
            commands::join_room,
            commands::leave_room,
            commands::suggest_device_label,
            commands::rename_device,
            commands::network_settings,
            commands::set_network_settings,
            commands::set_stun_servers,
            commands::room_state,
            commands::roster_devices,
            commands::revoke_device,
            commands::send_clip,
            commands::start_file_send,
            commands::accept_file_transfer,
            commands::reject_file_transfer,
            commands::cancel_file_transfer,
            commands::reveal_received_file,
            commands::recent_clips,
            commands::search_clips,
            commands::delete_clip,
            commands::delete_all_clips,
            commands::copy_to_clipboard,
            commands::show_main_window,
            commands::notify_incoming_clip,
        ])
        .build(tauri::generate_context!())
        .expect("error while building Fwoosh")
        .run(|app, event| {
            // macOS emits this when the user clicks the Dock icon while every
            // app window is hidden. Restore our tray-style popup in response.
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = event {
                show_popup(app);
            }

            #[cfg(not(target_os = "macos"))]
            let _ = (app, event);
        });
}
