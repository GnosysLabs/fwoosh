pub mod commands;
pub mod crypto;
pub mod keychain;
pub mod ntfy;
pub mod pairing;
pub mod roster;
pub mod store;

use commands::AppState;
use std::sync::Arc;
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager, WindowEvent,
};
use tauri_plugin_global_shortcut::{Code, Modifiers, Shortcut, ShortcutState};

/// Toggle the popup window: show + focus, or hide if already visible.
fn toggle_popup(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        match win.is_visible() {
            Ok(true) => {
                let _ = win.hide();
            }
            _ => {
                let _ = win.show();
                let _ = win.set_focus();
            }
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
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
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .setup(|app| {
            // --- Load device keypairs + history DB from the OS keychain ---
            let device = keychain::load_or_create_device_keypairs()
                .expect("failed to load device keypairs from keychain");
            let db_key = keychain::load_or_create_db_key()
                .expect("failed to load history DB key from keychain");
            let db_path = commands::history_db_path(&app.handle());
            let store = store::HistoryStore::open(&db_path, &db_key)
                .expect("failed to open history store");

            let state = Arc::new(AppState::new(device, store));
            app.manage(state.clone());

            // --- Tray icon + menu ---
            let show_item = MenuItem::with_id(app, "show", "Show ClipVault", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_item, &quit_item])?;
            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .tooltip("ClipVault")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => toggle_popup(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::Click { button: tauri::tray::MouseButton::Left, button_state: tauri::tray::MouseButtonState::Up, .. } = event {
                        toggle_popup(tray.app_handle());
                    }
                })
                .build(app)?;

            // Hide the window on startup; it lives in the tray.
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.hide();
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            // Hide instead of close so the app keeps running in the tray.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::device_identity,
            commands::create_room,
            commands::send_clip,
            commands::recent_clips,
            commands::search_clips,
            commands::delete_clip,
            commands::copy_to_clipboard,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ClipVault");
}
