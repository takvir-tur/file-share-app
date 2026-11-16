#[cfg(target_os = "android")]
mod android;
mod commands;
#[cfg(desktop)]
mod tray;
#[cfg(target_os = "windows")]
mod windows_sendto;

use std::sync::Arc;

use beamdrop_core::{BeamDropNode, NodeConfig};
#[cfg(desktop)]
use tauri::Emitter;
use tauri::Manager;

#[cfg(desktop)]
use tauri_plugin_autostart::MacosLauncher;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    beamdrop_core::raise_open_file_limit();
    #[cfg(desktop)]
    let (
        initial_send_paths,
        initial_targeted_send,
        initial_pairing_uris,
        launched_minimized,
    ) = {
        let raw_args: Vec<String> = std::env::args().collect();
        let parsed = commands::parse_cli_args(raw_args.iter());
        (
            parsed.send_paths,
            parsed.targeted_send,
            parsed.pairing_uris,
            parsed.launched_minimized,
        )
    };
    #[cfg(not(desktop))]
    let initial_send_paths: Vec<String> = Vec::new();

    let app_state = commands::AppState::new(initial_send_paths.clone());

    let builder = tauri::Builder::default()
        .manage(app_state.clone())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init());

    #[cfg(desktop)]
    let builder = builder
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            let parsed = commands::parse_cli_args(args.iter());
            let state = app.state::<commands::AppState>();
            if !parsed.send_paths.is_empty() {
                state.queue_send_paths(parsed.send_paths.clone());
                let _ = app.emit(commands::EVENT_SEND_PATHS, &parsed.send_paths);
            }
            if let Some(targeted) = parsed.targeted_send {
                commands::resolve_and_dispatch_targeted_send(
                    app.clone(),
                    state.inner().clone(),
                    targeted,
                );
            }
            for uri in parsed.pairing_uris {
                state.queue_pairing_uri(uri.clone());
                let _ = app.emit(commands::EVENT_PAIR_URI, &uri);
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

    let setup_state = app_state.clone();
    builder
        .setup(move |app| {
            let state = setup_state.clone();
            #[cfg(target_os = "android")]
            let node_config = {
                let config_dir = app.path().app_config_dir()?;
                std::fs::create_dir_all(&config_dir)?;
                android::set_config_dir(config_dir.clone());
                let app_local_data = app.path().app_local_data_dir().ok();
                let dl_dirs = android::resolve_download_dirs(app_local_data);
                state.queue_send_paths(android::take_initial_shared_paths());
                NodeConfig {
                    config_dir: Some(config_dir),
                    download_dir: Some(dl_dirs.engine_dir),
                    ..NodeConfig::default()
                }
            };
            #[cfg(not(target_os = "android"))]
            let node_config = NodeConfig::default();

            #[cfg(desktop)]
            let had_initial_sends = !initial_send_paths.is_empty()
                || initial_targeted_send.is_some()
                || !initial_pairing_uris.is_empty();

            #[cfg(desktop)]
            for uri in initial_pairing_uris {
                state.queue_pairing_uri(uri);
            }

            #[cfg(target_os = "android")]
            android::bind_app_handle(app.handle().clone());

            #[cfg(desktop)]
            if let Some(targeted) = initial_targeted_send {
                commands::resolve_and_dispatch_targeted_send(
                    app.handle().clone(),
                    state.clone(),
                    targeted,
                );
            }

            {
                let startup_app = app.handle().clone();
                let startup_state = state.clone();
                tauri::async_runtime::spawn(async move {
                    match BeamDropNode::start(node_config).await {
                        Ok(node) => {
                            let node = Arc::new(node);
                            startup_state.set_node(Arc::clone(&node)).await;
                            commands::spawn_event_forwarder(
                                startup_app.clone(),
                                startup_state.clone(),
                                Arc::clone(&node),
                            );
                            commands::sync_platform_trust_targets(&startup_app, &node).await;
                            #[cfg(desktop)]
                            tray::refresh_tray_menu(&startup_app).await;
                        }
                        Err(err) => {
                            startup_state.set_startup_error(err.to_string()).await;
                        }
                    }
                });
            }

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
            commands::refresh_peers,
            commands::start_pairing,
            commands::regenerate_pairing,
            commands::cancel_pairing,
            commands::parse_pairing_uri,
            commands::pair_with_peer,
            commands::remove_trusted_peer,
            commands::set_peer_wan_enabled,
            commands::set_peer_auto_accept,
            commands::is_on_metered_cellular,
            commands::measure_paths_bytes,
            commands::send_paths,
            commands::respond_to_offer,
            commands::open_main_window,
            commands::pause_transfer,
            commands::resume_transfer,
            commands::cancel_transfer,
            commands::get_transfer_history,
            commands::take_pending_send_paths,
            commands::take_pending_targeted_send,
            commands::take_pending_pairing_uri,
            commands::open_downloads_folder,
            commands::check_windows_firewall,
            commands::fix_windows_firewall,
        ])
        .build(tauri::generate_context!())
        .expect("error while building ZapDrop Tauri application")
        .run(|_app, _event| {
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Opened { urls } = _event {
                let state = _app.state::<commands::AppState>();
                let mut file_paths = Vec::new();
                for url in urls {
                    let s = url.as_str();
                    if s.to_ascii_lowercase().starts_with("beamdrop://") {
                        if let Some(send_paths) = commands::parse_send_uri(s) {
                            file_paths.extend(send_paths);
                        } else {
                            state.queue_pairing_uri(s.to_string());
                            let _ = _app.emit(commands::EVENT_PAIR_URI, s);
                        }
                    } else if url.scheme() == "file" {
                        if let Ok(path) = url.to_file_path() {
                            file_paths.push(path.to_string_lossy().into_owned());
                        }
                    }
                }
                if !file_paths.is_empty() {
                    state.queue_send_paths(file_paths.clone());
                    let _ = _app.emit(commands::EVENT_SEND_PATHS, &file_paths);
                }
                tray::show_main_window(_app);
            }
        });
}
