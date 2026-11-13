#[cfg(target_os = "android")]
mod android;
mod commands;
#[cfg(desktop)]
mod tray;

use std::sync::Arc;

use beamdrop_core::{BeamDropNode, NodeConfig};
#[cfg(desktop)]
use tauri::Emitter;
use tauri::Manager;

#[cfg(desktop)]
use tauri_plugin_autostart::MacosLauncher;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(desktop)]
    let (initial_send_paths, launched_minimized) = {
        let raw_args: Vec<String> = std::env::args().collect();
        let send_paths = commands::parse_send_paths_from_args(raw_args.iter());
        let minimized = raw_args.iter().skip(1).any(|arg| arg == "--minimized");
        (send_paths, minimized)
    };
    #[cfg(all(not(desktop), not(target_os = "android")))]
    let initial_send_paths: Vec<String> = Vec::new();

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init());

    #[cfg(desktop)]
    let builder = builder
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            let paths = commands::parse_send_paths_from_args(args.iter());
            if !paths.is_empty() {
                let state = app.state::<commands::AppState>();
                state.queue_send_paths(paths.clone());
                let _ = app.emit(commands::EVENT_SEND_PATHS, &paths);
            }
            tray::show_main_window(app);
        }))
        .plugin(
            tauri_plugin_autostart::Builder::new()
                .args(["--minimized"])
                .macos_launcher(MacosLauncher::LaunchAgent)
                .build(),
        )
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        });

    builder
        .setup(move |app| {
            #[cfg(target_os = "android")]
            let (node_config, initial_send_paths) = {
                let config_dir = app.path().app_config_dir()?;
                std::fs::create_dir_all(&config_dir)?;
                let app_local_data = app.path().app_local_data_dir().ok();
                let dl_dirs = android::resolve_download_dirs(app_local_data);
                let cfg = NodeConfig {
                    config_dir: Some(config_dir),
                    download_dir: Some(dl_dirs.engine_dir),
                    ..NodeConfig::default()
                };
                (cfg, android::take_initial_shared_paths())
            };
            #[cfg(not(target_os = "android"))]
            let node_config = NodeConfig::default();

            #[cfg(desktop)]
            let had_initial_sends = !initial_send_paths.is_empty();

            let node = tauri::async_runtime::block_on(async {
                BeamDropNode::start(node_config).await
            })?;
            let state = commands::AppState::new(Arc::new(node), initial_send_paths);

            app.manage(state.clone());
            #[cfg(target_os = "android")]
            android::bind_app_handle(app.handle().clone());
            commands::spawn_event_forwarder(app.handle().clone(), state);

            #[cfg(desktop)]
            {
                tray::setup_tray(app.handle())?;
                if launched_minimized && !had_initial_sends {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.hide();
                    }
                }
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_self_info,
            commands::list_peers,
            commands::start_pairing,
            commands::pair_with_peer,
            commands::remove_trusted_peer,
            commands::send_paths,
            commands::respond_to_offer,
            commands::get_transfer_history,
            commands::take_pending_send_paths,
            commands::open_downloads_folder,
            commands::check_windows_firewall,
            commands::fix_windows_firewall,
        ])
        .run(tauri::generate_context!())
        .expect("error while running BeamDrop Tauri application");
}
