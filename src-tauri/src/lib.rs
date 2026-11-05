//! MyVault desktop application entry point.

pub mod commands;
pub mod state;

use tauri::Manager;

use state::AppState;

/// Disable the webview devtools in release builds (SEC-16).
fn harden_webview(window: &tauri::WebviewWindow) {
    #[cfg(not(debug_assertions))]
    {
        let _ = window;
        // Devtools are not compiled in without the `devtools` feature.
    }
    #[cfg(debug_assertions)]
    {
        let _ = window;
    }
}

pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let handle = app.handle().clone();
            let window = app
                .get_webview_window("main")
                .expect("the main window is declared in tauri.conf.json");
            harden_webview(&window);
            app.manage(AppState::new(handle));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault::app_info,
            commands::vault::create_vault,
            commands::vault::open_vault,
            commands::vault::unlock_vault,
            commands::vault::lock_vault,
            commands::vault::vault_info,
            commands::vault::change_password,
            commands::vault::verify_vault_integrity,
            commands::vault::backup_vault,
            commands::files::list_directory,
            commands::files::breadcrumbs,
            commands::files::search_entries,
            commands::files::list_directories,
            commands::files::create_directory,
            commands::files::rename_entry,
            commands::files::delete_entry,
            commands::files::move_entry,
            commands::files::import_files,
            commands::files::export_entries,
            commands::files::open_entry,
            commands::files::cancel_operation,
            commands::settings::get_settings,
            commands::settings::save_settings,
        ])
        .build(tauri::generate_context!())
        .expect("error while building MyVault");

    app.run(|_handle, event| {
        // Never leave decrypted copies behind when the application exits.
        if matches!(
            event,
            tauri::RunEvent::Exit | tauri::RunEvent::ExitRequested { .. }
        ) {
            let _ = myvault_core::TempOpenArea::default_area().remove_all();
        }
    });
}
