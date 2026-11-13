use std::str::FromStr;

use iroh::NodeId;
use tauri::menu::{CheckMenuItem, Menu, MenuBuilder, MenuItem, SubmenuBuilder};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Wry};
use tauri_plugin_autostart::ManagerExt as AutostartManagerExt;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;

use crate::commands::{collect_peer_entries, dispatch_send_paths, AppState};

pub const TRAY_ID: &str = "beamdrop-tray";

const MENU_OPEN_APP: &str = "open_beamdrop";
const MENU_OPEN_DOWNLOADS: &str = "open_downloads";
const MENU_AUTOSTART: &str = "toggle_autostart";
const MENU_QUIT: &str = "quit_beamdrop";
const MENU_SEND_PREFIX: &str = "send_peer:";

/// Brings the main BeamDrop window out of the tray, unminimizes it, and focuses it.
pub fn show_main_window(app: &AppHandle<Wry>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Constructs the dynamic tray menu reflecting currently online/paired devices and autostart state.
pub async fn build_tray_menu(app: &AppHandle<Wry>) -> tauri::Result<Menu<Wry>> {
    let state = app.state::<AppState>();
    let peers = collect_peer_entries(&state.node).await;

    let mut send_submenu = SubmenuBuilder::new(app, "Send File to");
    let available: Vec<_> = peers
        .into_iter()
        .filter(|peer| peer.online || peer.paired)
        .collect();

    if available.is_empty() {
        let empty = MenuItem::with_id(
            app,
            "send_empty",
            "No online or paired devices",
            false,
            None::<&str>,
        )?;
        send_submenu = send_submenu.item(&empty);
    } else {
        for peer in available {
            let status_suffix = if peer.online { "" } else { " (Offline)" };
            let label = format!("Send File to {}...{}", peer.display_name, status_suffix);
            let item = MenuItem::with_id(
                app,
                format!("{MENU_SEND_PREFIX}{}", peer.node_id),
                label,
                true,
                None::<&str>,
            )?;
            send_submenu = send_submenu.item(&item);
        }
    }

    let send_menu = send_submenu.build()?;
    let autostart_enabled = app.autolaunch().is_enabled().unwrap_or(false);

    let open_item = MenuItem::with_id(app, MENU_OPEN_APP, "Open BeamDrop", true, None::<&str>)?;
    let downloads_item = MenuItem::with_id(
        app,
        MENU_OPEN_DOWNLOADS,
        "Open Downloads Folder",
        true,
        None::<&str>,
    )?;
    let autostart_item = CheckMenuItem::with_id(
        app,
        MENU_AUTOSTART,
        "Launch at Login",
        true,
        autostart_enabled,
        None::<&str>,
    )?;
    let quit_item = MenuItem::with_id(app, MENU_QUIT, "Quit", true, None::<&str>)?;

    MenuBuilder::new(app)
        .item(&open_item)
        .separator()
        .item(&send_menu)
        .item(&downloads_item)
        .separator()
        .item(&autostart_item)
        .separator()
        .item(&quit_item)
        .build()
}

/// Rebuilds and applies the tray menu dynamically when peers join, leave, or pair.
pub async fn refresh_tray_menu(app: &AppHandle<Wry>) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    if let Ok(menu) = build_tray_menu(app).await {
        let _ = tray.set_menu(Some(menu));
    }
}

/// Initializes the system tray icon, menu actions, and double-click/left-click behavior.
pub fn setup_tray(app: &AppHandle<Wry>) -> tauri::Result<()> {
    let initial_menu = tauri::async_runtime::block_on(build_tray_menu(app))?;

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("BeamDrop — P2P LAN File Drop")
        .menu(&initial_menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| {
            handle_menu_event(app, event.id().as_ref());
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            } else if let TrayIconEvent::Click {
                button: MouseButton::Middle,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon().cloned() {
        builder = builder.icon(icon);
    }

    builder.build(app)?;
    Ok(())
}

fn handle_menu_event(app: &AppHandle<Wry>, id: &str) {
    match id {
        MENU_OPEN_APP => {
            show_main_window(app);
        }
        MENU_OPEN_DOWNLOADS => {
            let state = app.state::<AppState>();
            let dir = state.node.download_dir().to_path_buf();
            let _ = std::fs::create_dir_all(&dir);
            let _ = app
                .opener()
                .open_path(dir.to_string_lossy().into_owned(), None::<&str>);
        }
        MENU_AUTOSTART => {
            let manager = app.autolaunch();
            let currently_enabled = manager.is_enabled().unwrap_or(false);
            let _ = if currently_enabled {
                manager.disable()
            } else {
                manager.enable()
            };

            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                refresh_tray_menu(&app_handle).await;
            });
        }
        MENU_QUIT => {
            app.exit(0);
        }
        other => {
            if let Some(node_id_str) = other.strip_prefix(MENU_SEND_PREFIX) {
                let Ok(peer_node_id) = NodeId::from_str(node_id_str) else {
                    return;
                };
                let fallback_label = node_id_str.to_string();
                let app_handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let state = app_handle.state::<AppState>();
                    let peer_label = state
                        .node
                        .discovery()
                        .known_peers()
                        .await
                        .into_iter()
                        .find(|p| p.node_id == peer_node_id)
                        .map(|p| p.display_name)
                        .unwrap_or(fallback_label);

                    let picker_app = app_handle.clone();
                    app_handle
                        .dialog()
                        .file()
                        .set_title(&format!("Send File to {peer_label}"))
                        .pick_files(move |selected| {
                            let Some(file_paths) = selected else {
                                return;
                            };
                            let paths: Vec<_> = file_paths
                                .into_iter()
                                .filter_map(|fp| fp.into_path().ok())
                                .collect();
                            if paths.is_empty() {
                                return;
                            }
                            let dispatch_state = picker_app.state::<AppState>();
                            dispatch_send_paths(
                                &picker_app,
                                &dispatch_state,
                                peer_node_id,
                                peer_label,
                                paths,
                            );
                        });
                });
            }
        }
    }
}

