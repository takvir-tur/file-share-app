use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use beamdrop_core::{BeamDropNode, PeerEvent, PeerInfo, TransferEvent, TrustedPeer};
use iroh::NodeId;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_notification::NotificationExt;
#[cfg(not(target_os = "android"))]
use tauri_plugin_opener::OpenerExt;
use tokio::sync::RwLock;
use uuid::Uuid;

const MAX_HISTORY_ENTRIES: usize = 100;

/// Event channel emitted when discovered/paired peers change.
pub const EVENT_PEER: &str = "beamdrop://peer-event";
/// Event channel emitted on live transfer updates and state transitions.
pub const EVENT_TRANSFER: &str = "beamdrop://transfer-event";
/// Event channel emitted when OS Finder / Explorer forwards `--send` paths.
pub const EVENT_SEND_PATHS: &str = "beamdrop://send-paths";

/// Shared application state managed by Tauri.
#[derive(Clone)]
pub struct AppState {
    pub node: Arc<BeamDropNode>,
    pub history: Arc<RwLock<Vec<TransferRecordDto>>>,
    pub active_starts: Arc<RwLock<HashMap<Uuid, Instant>>>,
    pub pending_send_paths: Arc<Mutex<Vec<String>>>,
}

impl AppState {
    pub fn new(node: Arc<BeamDropNode>, initial_send_paths: Vec<String>) -> Self {
        Self {
            node,
            history: Arc::new(RwLock::new(Vec::new())),
            active_starts: Arc::new(RwLock::new(HashMap::new())),
            pending_send_paths: Arc::new(Mutex::new(initial_send_paths)),
        }
    }

    pub fn queue_send_paths(&self, paths: Vec<String>) {
        if paths.is_empty() {
            return;
        }
        if let Ok(mut guard) = self.pending_send_paths.lock() {
            guard.extend(paths);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfInfoDto {
    pub node_id: String,
    pub device_id: String,
    pub hostname: String,
    pub os_type: String,
    pub lan_ip: String,
    pub listen_port: u16,
    pub download_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerEntryDto {
    pub node_id: String,
    pub display_name: String,
    pub os_type: String,
    pub addr: Option<String>,
    pub port: Option<u16>,
    pub online: bool,
    pub paired: bool,
    pub auto_accept: bool,
    pub paired_at_unix: Option<u64>,
    pub last_seen_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingSessionDto {
    pub node_id: String,
    pub addr: String,
    pub pin: String,
    pub uri: String,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedPeerDto {
    pub node_id: String,
    pub friendly_alias: String,
    pub os_type: String,
    pub paired_at_unix: u64,
    pub auto_accept: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferRecordDto {
    pub transfer_id: String,
    pub direction: String,
    pub status: String,
    pub peer_node_id: Option<String>,
    pub peer_name: String,
    pub file_name: Option<String>,
    pub files: usize,
    pub bytes_transferred: u64,
    pub bytes_skipped_resumed: u64,
    pub total_bytes: u64,
    pub speed_mbps: f64,
    pub streams_active: usize,
    pub verified: Option<bool>,
    pub output_dir: Option<String>,
    pub reason: Option<String>,
    pub updated_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerEventDto {
    pub kind: String,
    pub peer: PeerEntryDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferEventDto {
    pub kind: String,
    pub record: TransferRecordDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallStatusDto {
    pub supported: bool,
    pub configured: bool,
    pub rule_name: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendDispatchDto {
    pub queued: usize,
    pub target_node_id: String,
}

/// Parses `--send <path>...` (or bare file arguments from Explorer/Finder actions) from raw process args.
#[cfg_attr(not(desktop), allow(dead_code))]
pub fn parse_send_paths_from_args<I, S>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut paths = Vec::new();
    let mut in_send_flag = false;

    for raw in args.into_iter().skip(1) {
        let arg = raw.as_ref();
        if let Some(inline) = arg.strip_prefix("--send=") {
            if !inline.is_empty() {
                paths.push(inline.to_string());
            }
            in_send_flag = true;
            continue;
        }
        if arg == "--send" || arg == "-s" {
            in_send_flag = true;
            continue;
        }
        if arg.starts_with('-') {
            in_send_flag = false;
            continue;
        }
        if in_send_flag || Path::new(arg).exists() {
            paths.push(arg.to_string());
        }
    }

    paths
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn compute_speed_mbps(bytes_moved: u64, started_at: Instant) -> f64 {
    let secs = started_at.elapsed().as_secs_f64();
    if secs <= 0.001 || bytes_moved == 0 {
        0.0
    } else {
        (bytes_moved as f64) / (1024.0 * 1024.0) / secs
    }
}

fn send_desktop_notification(app: &AppHandle, title: &str, body: &str) {
    let _ = app.notification().builder().title(title).body(body).show();
}

/// Merges discovered/known LAN peers and paired trusted peers into sorted frontend/tray DTOs.
pub async fn collect_peer_entries(node: &BeamDropNode) -> Vec<PeerEntryDto> {
    let known = node.discovery().known_peers().await;
    let trusted = node.trust_store().list_peers().await;

    let known_map: BTreeMap<NodeId, PeerInfo> =
        known.into_iter().map(|p| (p.node_id, p)).collect();
    let trusted_map: BTreeMap<NodeId, TrustedPeer> =
        trusted.into_iter().map(|t| (t.node_id, t)).collect();

    let mut combined: Vec<PeerEntryDto> = Vec::new();
    for (node_id, peer) in &known_map {
        let trust = trusted_map.get(node_id);
        combined.push(peer_entry_from_parts(Some(peer), trust));
    }
    for (node_id, trust) in &trusted_map {
        if !known_map.contains_key(node_id) {
            combined.push(peer_entry_from_parts(None, Some(trust)));
        }
    }

    combined.sort_by(|a, b| {
        b.online
            .cmp(&a.online)
            .then_with(|| b.paired.cmp(&a.paired))
            .then_with(|| {
                a.display_name
                    .to_ascii_lowercase()
                    .cmp(&b.display_name.to_ascii_lowercase())
            })
    });
    combined
}

fn peer_entry_from_parts(peer: Option<&PeerInfo>, trust: Option<&TrustedPeer>) -> PeerEntryDto {
    match (peer, trust) {
        (Some(p), Some(t)) => PeerEntryDto {
            node_id: p.node_id.to_string(),
            display_name: p.display_name.clone(),
            os_type: p.os_type.to_string(),
            addr: Some(p.addr.to_string()),
            port: Some(p.port),
            online: p.online,
            paired: true,
            auto_accept: t.auto_accept,
            paired_at_unix: Some(t.paired_at_unix),
            last_seen_unix_ms: Some(p.last_seen_unix_ms),
        },
        (Some(p), None) => PeerEntryDto {
            node_id: p.node_id.to_string(),
            display_name: p.display_name.clone(),
            os_type: p.os_type.to_string(),
            addr: Some(p.addr.to_string()),
            port: Some(p.port),
            online: p.online,
            paired: false,
            auto_accept: false,
            paired_at_unix: None,
            last_seen_unix_ms: Some(p.last_seen_unix_ms),
        },
        (None, Some(t)) => PeerEntryDto {
            node_id: t.node_id.to_string(),
            display_name: t.friendly_alias.clone(),
            os_type: t.os_type.to_string(),
            addr: None,
            port: None,
            online: false,
            paired: true,
            auto_accept: t.auto_accept,
            paired_at_unix: Some(t.paired_at_unix),
            last_seen_unix_ms: None,
        },
        (None, None) => unreachable!("at least one source exists"),
    }
}

async fn upsert_history(history: &RwLock<Vec<TransferRecordDto>>, record: TransferRecordDto) {
    let mut guard = history.write().await;
    if let Some(pos) = guard
        .iter()
        .position(|existing| existing.transfer_id == record.transfer_id)
    {
        guard[pos] = record;
    } else {
        guard.insert(0, record);
        if guard.len() > MAX_HISTORY_ENTRIES {
            guard.truncate(MAX_HISTORY_ENTRIES);
        }
    }
}

async fn get_history_entry(
    history: &RwLock<Vec<TransferRecordDto>>,
    transfer_id: &str,
) -> Option<TransferRecordDto> {
    history
        .read()
        .await
        .iter()
        .find(|r| r.transfer_id == transfer_id)
        .cloned()
}

/// Spawns outgoing transfer tasks for `paths` to `peer_node_id`, reused by IPC commands and tray picker.
pub fn dispatch_send_paths(
    app: &AppHandle,
    state: &AppState,
    peer_node_id: NodeId,
    peer_label: String,
    paths: Vec<PathBuf>,
) -> usize {
    let count = paths.len();
    for path in paths {
        let app_handle = app.clone();
        let node = Arc::clone(&state.node);
        let history = Arc::clone(&state.history);
        let label = peer_label.clone();

        tauri::async_runtime::spawn(async move {
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(ToString::to_string)
                .unwrap_or_else(|| path.display().to_string());

            if let Err(err) = node.send_path(peer_node_id, &path, None).await {
                let reason = err.to_string();
                let record = TransferRecordDto {
                    transfer_id: Uuid::new_v4().to_string(),
                    direction: "outgoing".to_string(),
                    status: "failed".to_string(),
                    peer_node_id: Some(peer_node_id.to_string()),
                    peer_name: label,
                    file_name: Some(file_name.clone()),
                    files: 1,
                    bytes_transferred: 0,
                    bytes_skipped_resumed: 0,
                    total_bytes: 0,
                    speed_mbps: 0.0,
                    streams_active: 0,
                    verified: Some(false),
                    output_dir: None,
                    reason: Some(reason.clone()),
                    updated_at_unix_ms: now_unix_ms(),
                };
                upsert_history(&history, record.clone()).await;
                let _ = app_handle.emit(
                    EVENT_TRANSFER,
                    TransferEventDto {
                        kind: "failed".to_string(),
                        record,
                    },
                );
                send_desktop_notification(
                    &app_handle,
                    "BeamDrop transfer failed",
                    &format!("Could not send {file_name}: {reason}"),
                );
            }
        });
    }
    count
}

/// Starts background listeners piping `PeerEvent` and `TransferEvent` to the frontend, tray, and OS notifications.
pub fn spawn_event_forwarder(app: AppHandle, state: AppState) {
    let mut peer_rx = state.node.subscribe_peers();
    let app_for_peers = app.clone();
    let node_for_peers = Arc::clone(&state.node);

    tauri::async_runtime::spawn(async move {
        loop {
            match peer_rx.recv().await {
                Ok(event) => {
                    let (kind, peer) = match event {
                        PeerEvent::Discovered(p) => ("discovered", p),
                        PeerEvent::Lost(p) => ("lost", p),
                        PeerEvent::Paired(p) => ("paired", p),
                    };
                    let trust = node_for_peers.trust_store().get_peer(&peer.node_id).await;
                    let dto = PeerEventDto {
                        kind: kind.to_string(),
                        peer: peer_entry_from_parts(Some(&peer), trust.as_ref()),
                    };
                    let _ = app_for_peers.emit(EVENT_PEER, &dto);

                    #[cfg(desktop)]
                    {
                        let tray_app = app_for_peers.clone();
                        tauri::async_runtime::spawn(async move {
                            crate::tray::refresh_tray_menu(&tray_app).await;
                        });
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let mut transfer_rx = state.node.subscribe_transfers();
    let app_for_transfers = app;
    let node_for_transfers = Arc::clone(&state.node);
    let history = Arc::clone(&state.history);
    let active_starts = Arc::clone(&state.active_starts);

    tauri::async_runtime::spawn(async move {
        loop {
            match transfer_rx.recv().await {
                Ok(event) => {
                    handle_transfer_event(
                        &app_for_transfers,
                        &node_for_transfers,
                        &history,
                        &active_starts,
                        event,
                    )
                    .await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

async fn handle_transfer_event(
    app: &AppHandle,
    node: &BeamDropNode,
    history: &RwLock<Vec<TransferRecordDto>>,
    active_starts: &RwLock<HashMap<Uuid, Instant>>,
    event: TransferEvent,
) {
    let now_ms = now_unix_ms();

    match event {
        TransferEvent::OfferReceived {
            transfer_id,
            sender_name,
            files,
            total_bytes,
        } => {
            active_starts.write().await.insert(transfer_id, Instant::now());
            let record = TransferRecordDto {
                transfer_id: transfer_id.to_string(),
                direction: "incoming".to_string(),
                status: "offer_received".to_string(),
                peer_node_id: None,
                peer_name: sender_name,
                file_name: None,
                files,
                bytes_transferred: 0,
                bytes_skipped_resumed: 0,
                total_bytes,
                speed_mbps: 0.0,
                streams_active: 0,
                verified: None,
                output_dir: None,
                reason: None,
                updated_at_unix_ms: now_ms,
            };
            upsert_history(history, record.clone()).await;
            let _ = app.emit(
                EVENT_TRANSFER,
                TransferEventDto {
                    kind: "offer_received".to_string(),
                    record,
                },
            );
        }
        TransferEvent::AutoAccepted {
            transfer_id,
            sender_node_id,
            sender_name,
            files,
            total_bytes,
        } => {
            active_starts.write().await.insert(transfer_id, Instant::now());
            let record = TransferRecordDto {
                transfer_id: transfer_id.to_string(),
                direction: "incoming".to_string(),
                status: "receiving".to_string(),
                peer_node_id: Some(sender_node_id.to_string()),
                peer_name: sender_name,
                file_name: None,
                files,
                bytes_transferred: 0,
                bytes_skipped_resumed: 0,
                total_bytes,
                speed_mbps: 0.0,
                streams_active: 0,
                verified: None,
                output_dir: None,
                reason: None,
                updated_at_unix_ms: now_ms,
            };
            upsert_history(history, record.clone()).await;
            let _ = app.emit(
                EVENT_TRANSFER,
                TransferEventDto {
                    kind: "auto_accepted".to_string(),
                    record,
                },
            );
        }
        TransferEvent::PendingApproval {
            transfer_id,
            sender_node_id,
            sender_name,
            files,
            total_bytes,
        } => {
            let record = TransferRecordDto {
                transfer_id: transfer_id.to_string(),
                direction: "incoming".to_string(),
                status: "pending_approval".to_string(),
                peer_node_id: Some(sender_node_id.to_string()),
                peer_name: sender_name.clone(),
                file_name: None,
                files,
                bytes_transferred: 0,
                bytes_skipped_resumed: 0,
                total_bytes,
                speed_mbps: 0.0,
                streams_active: 0,
                verified: None,
                output_dir: None,
                reason: None,
                updated_at_unix_ms: now_ms,
            };
            upsert_history(history, record.clone()).await;
            let _ = app.emit(
                EVENT_TRANSFER,
                TransferEventDto {
                    kind: "pending_approval".to_string(),
                    record,
                },
            );
            let mb = (total_bytes as f64) / (1024.0 * 1024.0);
            send_desktop_notification(
                app,
                "BeamDrop approval requested",
                &format!("{sender_name} wants to send {files} item(s) ({mb:.1} MiB). Open BeamDrop to accept or decline."),
            );
        }
        TransferEvent::Progress(p) => {
            let started = {
                let mut starts = active_starts.write().await;
                *starts.entry(p.transfer_id).or_insert_with(Instant::now)
            };
            let id_str = p.transfer_id.to_string();
            let existing = get_history_entry(history, &id_str).await;
            let direction = existing
                .as_ref()
                .map(|r| r.direction.clone())
                .unwrap_or_else(|| "outgoing".to_string());
            let peer_node_id = existing.as_ref().and_then(|r| r.peer_node_id.clone());
            let peer_name = existing
                .as_ref()
                .map(|r| r.peer_name.clone())
                .unwrap_or_else(|| "Peer".to_string());
            let files = existing.as_ref().map(|r| r.files).unwrap_or(1);

            let speed_mbps = compute_speed_mbps(p.bytes_transferred, started);
            let record = TransferRecordDto {
                transfer_id: id_str,
                direction: direction.clone(),
                status: if direction == "incoming" {
                    "receiving".to_string()
                } else {
                    "sending".to_string()
                },
                peer_node_id,
                peer_name,
                file_name: Some(p.file_name),
                files,
                bytes_transferred: p.bytes_transferred,
                bytes_skipped_resumed: p.bytes_skipped_resumed,
                total_bytes: p.total_bytes,
                speed_mbps,
                streams_active: p.streams_active,
                verified: None,
                output_dir: None,
                reason: None,
                updated_at_unix_ms: now_ms,
            };
            upsert_history(history, record.clone()).await;
            let _ = app.emit(
                EVENT_TRANSFER,
                TransferEventDto {
                    kind: "progress".to_string(),
                    record,
                },
            );
        }
        TransferEvent::Completed {
            transfer_id,
            files,
            total_bytes,
            bytes_transferred,
            bytes_skipped_resumed,
            verified,
            output_dir,
        } => {
            let started = active_starts
                .write()
                .await
                .remove(&transfer_id)
                .unwrap_or_else(Instant::now);
            let id_str = transfer_id.to_string();
            let existing = get_history_entry(history, &id_str).await;
            let direction = if output_dir.is_some() {
                "incoming".to_string()
            } else {
                existing
                    .as_ref()
                    .map(|r| r.direction.clone())
                    .unwrap_or_else(|| "outgoing".to_string())
            };
            let peer_node_id = existing.as_ref().and_then(|r| r.peer_node_id.clone());
            let peer_name = existing
                .as_ref()
                .map(|r| r.peer_name.clone())
                .unwrap_or_else(|| "Peer".to_string());
            let file_name = existing.as_ref().and_then(|r| r.file_name.clone());
            let speed_mbps = compute_speed_mbps(bytes_transferred, started);
            let effective_output_dir = if let Some(ref dir) = output_dir {
                let finalized_files = node.transfer().take_completed_files(transfer_id).await;
                #[cfg(target_os = "android")]
                {
                    let dir_clone = dir.clone();
                    let exported_dir = tokio::task::spawn_blocking(move || {
                        crate::android::finalize_completed_transfer(dir_clone, finalized_files)
                    })
                    .await
                    .ok()
                    .flatten();
                    Some(exported_dir.unwrap_or_else(|| dir.clone()))
                }
                #[cfg(not(target_os = "android"))]
                {
                    let _ = finalized_files;
                    Some(dir.clone())
                }
            } else {
                None
            };
            let output_dir_str = effective_output_dir
                .as_ref()
                .map(|p| p.display().to_string());

            let record = TransferRecordDto {
                transfer_id: id_str,
                direction: direction.clone(),
                status: "completed".to_string(),
                peer_node_id,
                peer_name: peer_name.clone(),
                file_name,
                files,
                bytes_transferred,
                bytes_skipped_resumed,
                total_bytes,
                speed_mbps,
                streams_active: 0,
                verified: Some(verified),
                output_dir: output_dir_str,
                reason: None,
                updated_at_unix_ms: now_ms,
            };
            upsert_history(history, record.clone()).await;
            let _ = app.emit(
                EVENT_TRANSFER,
                TransferEventDto {
                    kind: "completed".to_string(),
                    record,
                },
            );

            let mb = (total_bytes as f64) / (1024.0 * 1024.0);
            let notif_body = if output_dir.is_some() {
                format!("Received {files} item(s) ({mb:.1} MiB) from {peer_name}")
            } else {
                format!("Sent {files} item(s) ({mb:.1} MiB)")
            };
            send_desktop_notification(app, "BeamDrop transfer complete", &notif_body);
        }
        TransferEvent::Interrupted { transfer_id, reason } => {
            active_starts.write().await.remove(&transfer_id);
            let id_str = transfer_id.to_string();
            let existing = get_history_entry(history, &id_str).await;
            let record = TransferRecordDto {
                transfer_id: id_str,
                direction: existing
                    .as_ref()
                    .map(|r| r.direction.clone())
                    .unwrap_or_else(|| "incoming".to_string()),
                status: "interrupted".to_string(),
                peer_node_id: existing.as_ref().and_then(|r| r.peer_node_id.clone()),
                peer_name: existing
                    .as_ref()
                    .map(|r| r.peer_name.clone())
                    .unwrap_or_else(|| "Peer".to_string()),
                file_name: existing.as_ref().and_then(|r| r.file_name.clone()),
                files: existing.as_ref().map(|r| r.files).unwrap_or(0),
                bytes_transferred: existing.as_ref().map(|r| r.bytes_transferred).unwrap_or(0),
                bytes_skipped_resumed: existing
                    .as_ref()
                    .map(|r| r.bytes_skipped_resumed)
                    .unwrap_or(0),
                total_bytes: existing.as_ref().map(|r| r.total_bytes).unwrap_or(0),
                speed_mbps: 0.0,
                streams_active: 0,
                verified: Some(false),
                output_dir: None,
                reason: Some(reason),
                updated_at_unix_ms: now_ms,
            };
            upsert_history(history, record.clone()).await;
            let _ = app.emit(
                EVENT_TRANSFER,
                TransferEventDto {
                    kind: "interrupted".to_string(),
                    record,
                },
            );
        }
    }
}

#[tauri::command]
pub async fn get_self_info(state: State<'_, AppState>) -> Result<SelfInfoDto, String> {
    let id = state.node.identity();
    #[cfg(target_os = "android")]
    let download_dir = crate::android::public_download_dir()
        .unwrap_or_else(|| state.node.download_dir().to_path_buf())
        .display()
        .to_string();
    #[cfg(not(target_os = "android"))]
    let download_dir = state.node.download_dir().display().to_string();

    Ok(SelfInfoDto {
        node_id: id.node_id.to_string(),
        device_id: id.device_id.to_string(),
        hostname: id.hostname.clone(),
        os_type: id.os_type.to_string(),
        lan_ip: beamdrop_core::detect_lan_ip().to_string(),
        listen_port: state.node.listen_port(),
        download_dir,
    })
}

#[tauri::command]
pub async fn list_peers(state: State<'_, AppState>) -> Result<Vec<PeerEntryDto>, String> {
    Ok(collect_peer_entries(&state.node).await)
}

#[tauri::command]
pub async fn start_pairing(state: State<'_, AppState>) -> Result<PairingSessionDto, String> {
    let session = state
        .node
        .start_pairing_session()
        .await
        .map_err(|e| e.to_string())?;
    Ok(PairingSessionDto {
        node_id: session.node_id.to_string(),
        addr: session.addr.to_string(),
        pin: session.pin,
        uri: session.uri,
        expires_at_unix: session.expires_at_unix,
    })
}

#[tauri::command]
pub async fn pair_with_peer(
    app: AppHandle,
    state: State<'_, AppState>,
    target: String,
    pin: String,
) -> Result<TrustedPeerDto, String> {
    let paired = state
        .node
        .pair_with_peer(target.trim(), pin.trim())
        .await
        .map_err(|e| e.to_string())?;

    let known = state.node.discovery().known_peers().await;
    let matched_known = known.iter().find(|p| p.node_id == paired.node_id);
    let _ = app.emit(
        EVENT_PEER,
        PeerEventDto {
            kind: "paired".to_string(),
            peer: peer_entry_from_parts(matched_known, Some(&paired)),
        },
    );

    #[cfg(desktop)]
    {
        let tray_app = app.clone();
        tauri::async_runtime::spawn(async move {
            crate::tray::refresh_tray_menu(&tray_app).await;
        });
    }

    Ok(TrustedPeerDto {
        node_id: paired.node_id.to_string(),
        friendly_alias: paired.friendly_alias,
        os_type: paired.os_type.to_string(),
        paired_at_unix: paired.paired_at_unix,
        auto_accept: paired.auto_accept,
    })
}

#[tauri::command]
pub async fn remove_trusted_peer(
    #[cfg_attr(not(desktop), allow(unused_variables))] app: AppHandle,
    state: State<'_, AppState>,
    node_id: String,
) -> Result<bool, String> {
    let parsed = NodeId::from_str(node_id.trim())
        .map_err(|e| format!("Invalid NodeId '{node_id}': {e}"))?;
    let removed = state
        .node
        .trust_store()
        .remove_peer(&parsed)
        .await
        .map_err(|e| e.to_string())?;

    #[cfg(desktop)]
    {
        let tray_app = app.clone();
        tauri::async_runtime::spawn(async move {
            crate::tray::refresh_tray_menu(&tray_app).await;
        });
    }

    Ok(removed.is_some())
}

#[tauri::command]
pub async fn send_paths(
    app: AppHandle,
    state: State<'_, AppState>,
    target_node_id: String,
    paths: Vec<String>,
) -> Result<SendDispatchDto, String> {
    if paths.is_empty() {
        return Err("No file or folder paths provided".to_string());
    }

    let (peer_node_id, peer_label) = match NodeId::from_str(target_node_id.trim()) {
        Ok(id) => {
            let label = state
                .node
                .discovery()
                .known_peers()
                .await
                .into_iter()
                .find(|p| p.node_id == id)
                .map(|p| p.display_name)
                .unwrap_or_else(|| target_node_id.clone());
            (id, label)
        }
        Err(_) => {
            let peer = state
                .node
                .resolve_peer(target_node_id.trim(), Duration::from_secs(2))
                .await
                .map_err(|e| e.to_string())?;
            (peer.node_id, peer.display_name)
        }
    };

    let mut validated = Vec::with_capacity(paths.len());
    for raw in paths {
        let p = PathBuf::from(&raw);
        if !p.exists() {
            return Err(format!("Path does not exist: {}", p.display()));
        }
        validated.push(p);
    }

    let queued = dispatch_send_paths(&app, &state, peer_node_id, peer_label, validated);
    Ok(SendDispatchDto {
        queued,
        target_node_id: peer_node_id.to_string(),
    })
}

#[tauri::command]
pub async fn respond_to_offer(
    state: State<'_, AppState>,
    transfer_id: String,
    accept: bool,
) -> Result<(), String> {
    let parsed_id = Uuid::from_str(transfer_id.trim())
        .map_err(|e| format!("Invalid transfer UUID '{transfer_id}': {e}"))?;

    state
        .node
        .respond_to_offer(parsed_id, accept)
        .await
        .map_err(|e| e.to_string())?;

    let mut guard = state.history.write().await;
    if let Some(entry) = guard.iter_mut().find(|r| r.transfer_id == parsed_id.to_string()) {
        entry.status = if accept {
            "receiving".to_string()
        } else {
            "rejected".to_string()
        };
        entry.updated_at_unix_ms = now_unix_ms();
    }

    Ok(())
}

#[tauri::command]
pub async fn get_transfer_history(
    state: State<'_, AppState>,
) -> Result<Vec<TransferRecordDto>, String> {
    Ok(state.history.read().await.clone())
}

#[tauri::command]
pub async fn take_pending_send_paths(
    state: State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let mut guard = state
        .pending_send_paths
        .lock()
        .map_err(|_| "Failed to lock pending send paths".to_string())?;
    Ok(std::mem::take(&mut *guard))
}

#[tauri::command]
pub async fn open_downloads_folder(
    #[cfg_attr(target_os = "android", allow(unused_variables))] app: AppHandle,
    #[cfg_attr(target_os = "android", allow(unused_variables))] state: State<'_, AppState>,
) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        return tokio::task::spawn_blocking(crate::android::open_public_downloads)
            .await
            .map_err(|e| format!("Failed to join Downloads launcher: {e}"))?;
    }

    #[cfg(not(target_os = "android"))]
    {
        let dir = state.node.download_dir();
        if let Err(err) = std::fs::create_dir_all(dir) {
            return Err(format!("Failed to prepare downloads folder: {err}"));
        }
        app.opener()
            .open_path(dir.to_string_lossy().into_owned(), None::<&str>)
            .map_err(|e| e.to_string())
    }
}

#[tauri::command]
pub async fn check_windows_firewall() -> Result<FirewallStatusDto, String> {
    #[cfg(target_os = "windows")]
    {
        windows_firewall::check_windows_firewall_impl()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(FirewallStatusDto {
            supported: false,
            configured: true,
            rule_name: "BeamDrop".to_string(),
            details: "Windows Defender Firewall checks only run on Windows.".to_string(),
        })
    }
}

#[tauri::command]
pub async fn fix_windows_firewall() -> Result<FirewallStatusDto, String> {
    #[cfg(target_os = "windows")]
    {
        windows_firewall::fix_windows_firewall_impl()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(FirewallStatusDto {
            supported: false,
            configured: true,
            rule_name: "BeamDrop".to_string(),
            details: "Windows Defender Firewall configuration only runs on Windows.".to_string(),
        })
    }
}

#[cfg(target_os = "windows")]
mod windows_firewall {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    use super::FirewallStatusDto;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const RULE_NAME: &str = "BeamDrop";

    pub fn check_windows_firewall_impl() -> Result<FirewallStatusDto, String> {
        let output = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "show",
                "rule",
                &format!("name={RULE_NAME}"),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to invoke netsh: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let configured = output.status.success() && stdout.contains(RULE_NAME);

        let details = if configured {
            "Inbound rule 'BeamDrop' is present in Windows Defender Firewall.".to_string()
        } else if !stdout.is_empty() {
            stdout
        } else if !stderr.is_empty() {
            stderr
        } else {
            "No 'BeamDrop' Windows Defender Firewall rule found; LAN UDP discovery may be blocked."
                .to_string()
        };

        Ok(FirewallStatusDto {
            supported: true,
            configured,
            rule_name: RULE_NAME.to_string(),
            details,
        })
    }

    pub fn fix_windows_firewall_impl() -> Result<FirewallStatusDto, String> {
        let exe = std::env::current_exe()
            .map_err(|e| format!("Failed to locate executable path: {e}"))?;
        let program_arg = format!("program={}", exe.display());

        let direct = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={RULE_NAME}"),
                "dir=in",
                "action=allow",
                &program_arg,
                "enable=yes",
                "profile=private,domain",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to execute netsh: {e}"))?;

        if !direct.status.success() {
            // Standard users require UAC elevation to modify Windows Defender Firewall rules.
            let escaped_exe = exe.display().to_string().replace('\'', "''");
            let ps_script = format!(
                "Start-Process -FilePath 'netsh' -ArgumentList 'advfirewall','firewall','add','rule','name={RULE_NAME}','dir=in','action=allow','program=\"{escaped_exe}\"','enable=yes','profile=private,domain' -Verb RunAs -Wait"
            );
            let elevated = Command::new("powershell")
                .args(["-NoProfile", "-Command", &ps_script])
                .creation_flags(CREATE_NO_WINDOW)
                .status()
                .map_err(|e| format!("Failed to request Windows Firewall elevation: {e}"))?;

            if !elevated.success() {
                return Err(
                    "Administrator permission was declined or netsh failed to add the 'BeamDrop' firewall rule."
                        .to_string(),
                );
            }
        }

        check_windows_firewall_impl()
    }
}

