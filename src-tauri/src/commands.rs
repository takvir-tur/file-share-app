use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use beamdrop_core::{
    parse_pairing_uri as core_parse_pairing_uri, BeamDropNode, PeerEvent, PeerInfo, TransferError,
    TransferEvent, TrustedPeer,
};
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
/// Event channel emitted when Direct Share / `--send-to` initiates a targeted send.
pub const EVENT_TARGETED_SEND: &str = "beamdrop://targeted-send";
/// Event channel emitted when the OS opens a `beamdrop://pair?...` deep link.
pub const EVENT_PAIR_URI: &str = "beamdrop://pair-uri";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TargetedSendRequest {
    pub target_node_id: String,
    pub paths: Vec<String>,
}

/// Shared application state managed by Tauri.
#[derive(Clone)]
pub struct AppState {
    pub node: Arc<BeamDropNode>,
    pub history: Arc<RwLock<Vec<TransferRecordDto>>>,
    pub active_starts: Arc<RwLock<HashMap<Uuid, Instant>>>,
    pub pending_send_paths: Arc<Mutex<Vec<String>>>,
    pub pending_targeted_sends: Arc<Mutex<Vec<TargetedSendRequest>>>,
    pub pending_pairing_uris: Arc<Mutex<Vec<String>>>,
}

impl AppState {
    pub fn new(node: Arc<BeamDropNode>, initial_send_paths: Vec<String>) -> Self {
        Self {
            node,
            history: Arc::new(RwLock::new(Vec::new())),
            active_starts: Arc::new(RwLock::new(HashMap::new())),
            pending_send_paths: Arc::new(Mutex::new(initial_send_paths)),
            pending_targeted_sends: Arc::new(Mutex::new(Vec::new())),
            pending_pairing_uris: Arc::new(Mutex::new(Vec::new())),
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

    pub fn queue_targeted_send(&self, request: TargetedSendRequest) {
        if request.target_node_id.trim().is_empty() || request.paths.is_empty() {
            return;
        }
        if let Ok(mut guard) = self.pending_targeted_sends.lock() {
            guard.push(request);
        }
    }

    pub fn queue_pairing_uri(&self, uri: String) {
        let trimmed = uri.trim().to_string();
        if trimmed.is_empty() {
            return;
        }
        if let Ok(mut guard) = self.pending_pairing_uris.lock() {
            if !guard.iter().any(|existing| existing == &trimmed) {
                guard.push(trimmed);
            }
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
    pub allow_wan: bool,
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
    pub allow_wan: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeasurePathsDto {
    pub resolved_paths: Vec<String>,
    pub total_bytes: u64,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ParsedPairingUriDto {
    pub node_id: String,
    pub addr: Option<String>,
    pub pin: String,
}

#[cfg_attr(not(desktop), allow(dead_code))]
#[derive(Debug, Clone, Default)]
pub struct ParsedCliArgs {
    pub send_paths: Vec<String>,
    pub targeted_send: Option<TargetedSendRequest>,
    pub pairing_uris: Vec<String>,
    pub launched_minimized: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliArgMode {
    None,
    SendPaths,
    AwaitTargetNodeId,
    TargetedPaths,
}

/// Parses `--send <path>...`, `--send-to <node_id> <path>...`, `--minimized`, `beamdrop://pair?...`, or bare paths from args.
#[cfg_attr(not(desktop), allow(dead_code))]
pub fn parse_cli_args<I, S>(args: I) -> ParsedCliArgs
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut parsed = ParsedCliArgs::default();
    let mut mode = CliArgMode::None;
    let mut target_node_id: Option<String> = None;
    let mut targeted_paths: Vec<String> = Vec::new();

    for raw in args.into_iter().skip(1) {
        let arg = raw.as_ref();
        if arg == "--minimized" {
            parsed.launched_minimized = true;
            mode = CliArgMode::None;
            continue;
        }
        if arg.trim().to_ascii_lowercase().starts_with("beamdrop://") {
            parsed.pairing_uris.push(arg.trim().to_string());
            mode = CliArgMode::None;
            continue;
        }
        if let Some(inline_target) = arg.strip_prefix("--send-to=") {
            let trimmed = inline_target.trim();
            if !trimmed.is_empty() {
                target_node_id = Some(trimmed.to_string());
                mode = CliArgMode::TargetedPaths;
            } else {
                mode = CliArgMode::AwaitTargetNodeId;
            }
            continue;
        }
        if arg == "--send-to" {
            mode = CliArgMode::AwaitTargetNodeId;
            continue;
        }
        if let Some(inline) = arg.strip_prefix("--send=") {
            if !inline.is_empty() {
                parsed.send_paths.push(inline.to_string());
            }
            mode = CliArgMode::SendPaths;
            continue;
        }
        if arg == "--send" || arg == "-s" {
            mode = CliArgMode::SendPaths;
            continue;
        }
        if arg.starts_with('-') {
            mode = CliArgMode::None;
            continue;
        }

        match mode {
            CliArgMode::AwaitTargetNodeId => {
                let trimmed = arg.trim();
                if !trimmed.is_empty() {
                    target_node_id = Some(trimmed.to_string());
                    mode = CliArgMode::TargetedPaths;
                }
            }
            CliArgMode::TargetedPaths => {
                if !arg.is_empty() {
                    targeted_paths.push(arg.to_string());
                }
            }
            CliArgMode::SendPaths => {
                if !arg.is_empty() {
                    parsed.send_paths.push(arg.to_string());
                }
            }
            CliArgMode::None => {
                if Path::new(arg).exists() {
                    parsed.send_paths.push(arg.to_string());
                }
            }
        }
    }

    if let Some(target) = target_node_id {
        if !targeted_paths.is_empty() {
            parsed.targeted_send = Some(TargetedSendRequest {
                target_node_id: target,
                paths: targeted_paths,
            });
        }
    }

    parsed
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
            allow_wan: t.allow_wan,
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
            allow_wan: false,
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
            allow_wan: t.allow_wan,
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

async fn emit_outgoing_failure(
    app: &AppHandle,
    history: &RwLock<Vec<TransferRecordDto>>,
    peer_node_id: Option<String>,
    peer_name: String,
    file_name: String,
    reason: String,
) {
    let record = TransferRecordDto {
        transfer_id: Uuid::new_v4().to_string(),
        direction: "outgoing".to_string(),
        status: "failed".to_string(),
        peer_node_id,
        peer_name,
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
    upsert_history(history, record.clone()).await;
    let _ = app.emit(
        EVENT_TRANSFER,
        TransferEventDto {
            kind: "failed".to_string(),
            record,
        },
    );
    send_desktop_notification(
        app,
        "BeamDrop transfer failed",
        &format!("Could not send {file_name}: {reason}"),
    );
}

async fn resolve_target_peer(
    node: &BeamDropNode,
    target: &str,
) -> Result<(NodeId, String), String> {
    let trimmed = target.trim();
    match NodeId::from_str(trimmed) {
        Ok(id) => {
            let known_label = node
                .discovery()
                .known_peers()
                .await
                .into_iter()
                .find(|p| p.node_id == id)
                .map(|p| p.display_name);
            let label = match known_label {
                Some(name) => name,
                None => node
                    .trust_store()
                    .get_peer(&id)
                    .await
                    .map(|t| t.friendly_alias)
                    .unwrap_or_else(|| trimmed.to_string()),
            };
            Ok((id, label))
        }
        Err(_) => {
            let peer = node
                .resolve_peer(trimmed, Duration::from_secs(2))
                .await
                .map_err(|e| e.to_string())?;
            Ok((peer.node_id, peer.display_name))
        }
    }
}

/// Refreshes OS-level trust targets (tray menu, Windows SendTo, Android Direct Share shortcuts).
pub async fn sync_platform_trust_targets(
    #[cfg_attr(not(desktop), allow(unused_variables))] app: &AppHandle,
    #[cfg_attr(not(target_os = "windows"), allow(unused_variables))] node: &BeamDropNode,
) {
    #[cfg(desktop)]
    crate::tray::refresh_tray_menu(app).await;

    #[cfg(target_os = "windows")]
    {
        let trusted = node.trust_store().list_peers().await;
        let _ = tokio::task::spawn_blocking(move || {
            crate::windows_sendto::sync_sendto_shortcuts(&trusted);
        })
        .await;
    }

    #[cfg(target_os = "android")]
    crate::android::sync_direct_share_shortcuts();
}

/// Immediately dispatches a Direct Share or `--send-to` transfer and notifies the frontend drawer.
pub fn resolve_and_dispatch_targeted_send(
    app: AppHandle,
    state: AppState,
    request: TargetedSendRequest,
) {
    if request.target_node_id.trim().is_empty() || request.paths.is_empty() {
        return;
    }

    state.queue_targeted_send(request.clone());
    let _ = app.emit(EVENT_TARGETED_SEND, &request);

    tauri::async_runtime::spawn(async move {
        let fallback_name = request
            .paths
            .first()
            .and_then(|p| Path::new(p).file_name().and_then(|n| n.to_str()))
            .unwrap_or("Direct Share item")
            .to_string();

        let (peer_node_id, peer_label) =
            match resolve_target_peer(&state.node, &request.target_node_id).await {
                Ok(resolved) => resolved,
                Err(reason) => {
                    emit_outgoing_failure(
                        &app,
                        &state.history,
                        None,
                        request.target_node_id.clone(),
                        fallback_name,
                        reason,
                    )
                    .await;
                    return;
                }
            };

        let mut validated = Vec::with_capacity(request.paths.len());
        let mut missing = Vec::new();
        for raw in &request.paths {
            let p = PathBuf::from(raw);
            if p.exists() {
                validated.push(p);
            } else {
                missing.push(raw.clone());
            }
        }

        if validated.is_empty() {
            emit_outgoing_failure(
                &app,
                &state.history,
                Some(peer_node_id.to_string()),
                peer_label,
                fallback_name,
                format!("Path does not exist: {}", missing.join(", ")),
            )
            .await;
            return;
        }

        dispatch_send_paths(&app, &state, peer_node_id, peer_label, validated);
    });
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
                if matches!(
                    err.downcast_ref::<TransferError>(),
                    Some(TransferError::Paused(_) | TransferError::Cancelled(_))
                ) {
                    return;
                }
                emit_outgoing_failure(
                    &app_handle,
                    &history,
                    Some(peer_node_id.to_string()),
                    label,
                    file_name,
                    err.to_string(),
                )
                .await;
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
                    let is_paired = matches!(event, PeerEvent::Paired(_));
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

                    if is_paired {
                        let sync_app = app_for_peers.clone();
                        let sync_node = Arc::clone(&node_for_peers);
                        tauri::async_runtime::spawn(async move {
                            sync_platform_trust_targets(&sync_app, &sync_node).await;
                        });
                    } else {
                        #[cfg(desktop)]
                        {
                            let tray_app = app_for_peers.clone();
                            tauri::async_runtime::spawn(async move {
                                crate::tray::refresh_tray_menu(&tray_app).await;
                            });
                        }
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
        TransferEvent::Started {
            transfer_id,
            peer_node_id,
            peer_name,
            file_name,
            files,
            total_bytes,
            bytes_skipped_resumed,
        } => {
            active_starts.write().await.insert(transfer_id, Instant::now());
            let id_str = transfer_id.to_string();
            let existing = get_history_entry(history, &id_str).await;
            let direction = existing
                .as_ref()
                .map(|r| r.direction.clone())
                .unwrap_or_else(|| "outgoing".to_string());
            let status = if direction == "incoming" {
                "receiving"
            } else {
                "sending"
            };
            let record = TransferRecordDto {
                transfer_id: id_str,
                direction,
                status: status.to_string(),
                peer_node_id: Some(peer_node_id.to_string()),
                peer_name,
                file_name: Some(file_name),
                files,
                bytes_transferred: 0,
                bytes_skipped_resumed,
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
                    kind: "started".to_string(),
                    record,
                },
            );
        }
        TransferEvent::Progress(p) => {
            let started = {
                let mut starts = active_starts.write().await;
                *starts.entry(p.transfer_id).or_insert_with(Instant::now)
            };
            let id_str = p.transfer_id.to_string();
            let existing = get_history_entry(history, &id_str).await;
            if matches!(
                existing.as_ref().map(|r| r.status.as_str()),
                Some("paused" | "cancelled" | "completed" | "failed")
            ) {
                return;
            }
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
        TransferEvent::Paused { transfer_id, reason } => {
            emit_terminal_control_record(
                app,
                history,
                active_starts,
                transfer_id,
                "paused",
                None,
                reason,
                now_ms,
            )
            .await;
        }
        TransferEvent::Cancelled { transfer_id, reason } => {
            emit_terminal_control_record(
                app,
                history,
                active_starts,
                transfer_id,
                "cancelled",
                Some(false),
                reason,
                now_ms,
            )
            .await;
        }
        TransferEvent::Interrupted { transfer_id, reason } => {
            emit_terminal_control_record(
                app,
                history,
                active_starts,
                transfer_id,
                "interrupted",
                Some(false),
                Some(reason),
                now_ms,
            )
            .await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn emit_terminal_control_record(
    app: &AppHandle,
    history: &RwLock<Vec<TransferRecordDto>>,
    active_starts: &RwLock<HashMap<Uuid, Instant>>,
    transfer_id: Uuid,
    status: &str,
    verified: Option<bool>,
    reason: Option<String>,
    now_ms: u64,
) {
    active_starts.write().await.remove(&transfer_id);
    let id_str = transfer_id.to_string();
    let existing = get_history_entry(history, &id_str).await;
    let record = TransferRecordDto {
        transfer_id: id_str,
        direction: existing
            .as_ref()
            .map(|r| r.direction.clone())
            .unwrap_or_else(|| "incoming".to_string()),
        status: status.to_string(),
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
        verified,
        output_dir: None,
        reason,
        updated_at_unix_ms: now_ms,
    };
    upsert_history(history, record.clone()).await;
    let _ = app.emit(
        EVENT_TRANSFER,
        TransferEventDto {
            kind: status.to_string(),
            record,
        },
    );
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

    let sync_app = app.clone();
    let sync_node = Arc::clone(&state.node);
    tauri::async_runtime::spawn(async move {
        sync_platform_trust_targets(&sync_app, &sync_node).await;
    });

    Ok(TrustedPeerDto {
        node_id: paired.node_id.to_string(),
        friendly_alias: paired.friendly_alias,
        os_type: paired.os_type.to_string(),
        paired_at_unix: paired.paired_at_unix,
        auto_accept: paired.auto_accept,
        allow_wan: paired.allow_wan,
    })
}

#[tauri::command]
pub async fn set_peer_wan_enabled(
    state: State<'_, AppState>,
    node_id: String,
    enabled: bool,
) -> Result<bool, String> {
    let parsed = NodeId::from_str(node_id.trim())
        .map_err(|e| format!("Invalid NodeId '{node_id}': {e}"))?;
    state
        .node
        .set_peer_wan_enabled(parsed, enabled)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn is_on_metered_cellular() -> Result<bool, String> {
    #[cfg(target_os = "android")]
    {
        tokio::task::spawn_blocking(crate::android::is_on_metered_cellular)
            .await
            .map_err(|e| format!("Failed to inspect Android connectivity state: {e}"))
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok(false)
    }
}

#[tauri::command]
pub async fn measure_paths_bytes(paths: Vec<String>) -> Result<MeasurePathsDto, String> {
    let cleaned: Vec<String> = paths
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if cleaned.is_empty() {
        return Err("No file or folder paths provided".to_string());
    }

    let validated = resolve_paths_for_platform(cleaned).await?;
    let for_stat = validated.clone();
    let total_bytes = tokio::task::spawn_blocking(move || compute_paths_total_bytes(&for_stat))
        .await
        .map_err(|e| format!("Failed to compute selection size: {e}"))?;

    let resolved_paths = validated
        .into_iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    Ok(MeasurePathsDto {
        resolved_paths,
        total_bytes,
    })
}

fn compute_paths_total_bytes(paths: &[PathBuf]) -> u64 {
    paths.iter().map(|p| compute_entry_bytes(p)).sum()
}

fn compute_entry_bytes(path: &Path) -> u64 {
    let Ok(meta) = std::fs::metadata(path) else {
        return 0;
    };
    if meta.is_file() {
        return meta.len();
    }
    if meta.is_dir() {
        let Ok(entries) = std::fs::read_dir(path) else {
            return 0;
        };
        return entries
            .flatten()
            .map(|entry| compute_entry_bytes(&entry.path()))
            .sum();
    }
    0
}

#[tauri::command]
pub async fn remove_trusted_peer(
    app: AppHandle,
    state: State<'_, AppState>,
    node_id: String,
) -> Result<bool, String> {
    let parsed = NodeId::from_str(node_id.trim())
        .map_err(|e| format!("Invalid NodeId '{node_id}': {e}"))?;
    let removed = state
        .node
        .remove_trusted_peer(&parsed)
        .await
        .map_err(|e| e.to_string())?;

    let sync_app = app.clone();
    let sync_node = Arc::clone(&state.node);
    tauri::async_runtime::spawn(async move {
        sync_platform_trust_targets(&sync_app, &sync_node).await;
    });

    Ok(removed.is_some())
}

#[tauri::command]
pub async fn send_paths(
    app: AppHandle,
    state: State<'_, AppState>,
    target_node_id: String,
    paths: Vec<String>,
) -> Result<SendDispatchDto, String> {
    let cleaned: Vec<String> = paths
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if cleaned.is_empty() {
        return Err("No file or folder paths provided".to_string());
    }

    let (peer_node_id, peer_label) = resolve_target_peer(&state.node, &target_node_id).await?;
    let validated = resolve_paths_for_platform(cleaned).await?;

    let queued = dispatch_send_paths(&app, &state, peer_node_id, peer_label, validated);
    Ok(SendDispatchDto {
        queued,
        target_node_id: peer_node_id.to_string(),
    })
}

async fn resolve_paths_for_platform(paths: Vec<String>) -> Result<Vec<PathBuf>, String> {
    #[cfg(target_os = "android")]
    let resolved_strings = {
        let expected_len = paths.len();
        let resolved = tokio::task::spawn_blocking(move || crate::android::resolve_content_uris(&paths))
            .await
            .map_err(|e| format!("Failed to resolve Android file URIs: {e}"))??;
        if resolved.is_empty() || resolved.len() != expected_len {
            return Err("Could not read one or more selected files from Android storage".to_string());
        }
        resolved
    };

    #[cfg(not(target_os = "android"))]
    let resolved_strings = paths;

    let mut validated = Vec::with_capacity(resolved_strings.len());
    for raw in resolved_strings {
        let p = PathBuf::from(&raw);
        if !p.exists() {
            return Err(format!("Path does not exist: {}", p.display()));
        }
        validated.push(p);
    }
    Ok(validated)
}

#[tauri::command]
pub async fn pause_transfer(
    state: State<'_, AppState>,
    transfer_id: String,
) -> Result<bool, String> {
    let parsed_id = Uuid::from_str(transfer_id.trim())
        .map_err(|e| format!("Invalid transfer UUID '{transfer_id}': {e}"))?;
    Ok(state.node.pause_transfer(parsed_id).await)
}

#[tauri::command]
pub async fn resume_transfer(
    state: State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let parsed_id = Uuid::from_str(transfer_id.trim())
        .map_err(|e| format!("Invalid transfer UUID '{transfer_id}': {e}"))?;
    state
        .node
        .resume_transfer(parsed_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn cancel_transfer(
    state: State<'_, AppState>,
    transfer_id: String,
) -> Result<bool, String> {
    let parsed_id = Uuid::from_str(transfer_id.trim())
        .map_err(|e| format!("Invalid transfer UUID '{transfer_id}': {e}"))?;
    Ok(state.node.cancel_transfer(parsed_id).await)
}

#[tauri::command]
pub async fn refresh_peers(state: State<'_, AppState>) -> Result<Vec<PeerEntryDto>, String> {
    state.node.refresh_peers().await;
    Ok(collect_peer_entries(&state.node).await)
}

#[tauri::command]
pub async fn parse_pairing_uri(uri: String) -> Result<ParsedPairingUriDto, String> {
    let parsed = core_parse_pairing_uri(&uri).map_err(|e| e.to_string())?;
    Ok(ParsedPairingUriDto {
        node_id: parsed.node_id.to_string(),
        addr: parsed.addr.map(|a| a.to_string()),
        pin: parsed.pin,
    })
}

#[tauri::command]
pub async fn take_pending_pairing_uri(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let mut guard = state
        .pending_pairing_uris
        .lock()
        .map_err(|_| "Failed to lock pending pairing URIs".to_string())?;
    Ok(std::mem::take(&mut *guard))
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
pub async fn take_pending_targeted_send(
    state: State<'_, AppState>,
) -> Result<Vec<TargetedSendRequest>, String> {
    let mut guard = state
        .pending_targeted_sends
        .lock()
        .map_err(|_| "Failed to lock pending targeted sends".to_string())?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cli_args_extracts_send_to_target_and_paths() {
        let parsed = parse_cli_args([
            "beamdrop-app",
            "--send-to",
            "node123456",
            "/tmp/photo.jpg",
            "/tmp/doc.pdf",
        ]);
        assert!(!parsed.launched_minimized);
        assert!(parsed.send_paths.is_empty());
        assert_eq!(
            parsed.targeted_send,
            Some(TargetedSendRequest {
                target_node_id: "node123456".to_string(),
                paths: vec!["/tmp/photo.jpg".to_string(), "/tmp/doc.pdf".to_string()],
            })
        );
    }

    #[test]
    fn parse_cli_args_extracts_inline_send_to_send_and_minimized() {
        let parsed = parse_cli_args([
            "beamdrop-app",
            "--minimized",
            "--send",
            "/tmp/broadcast.zip",
            "--send-to=peerABC",
            "/tmp/direct.png",
        ]);
        assert!(parsed.launched_minimized);
        assert_eq!(parsed.send_paths, vec!["/tmp/broadcast.zip".to_string()]);
        assert_eq!(
            parsed.targeted_send,
            Some(TargetedSendRequest {
                target_node_id: "peerABC".to_string(),
                paths: vec!["/tmp/direct.png".to_string()],
            })
        );
    }

    #[test]
    fn parse_cli_args_extracts_beamdrop_pairing_uri() {
        let uri = "beamdrop://pair?node=abc123&addr=192.168.1.10:4433&pin=123456";
        let parsed = parse_cli_args(["beamdrop-app", uri]);
        assert!(parsed.send_paths.is_empty());
        assert_eq!(parsed.pairing_uris, vec![uri.to_string()]);
    }
}


