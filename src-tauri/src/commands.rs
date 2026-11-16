use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use beamdrop_core::{
    parse_pairing_uri as core_parse_pairing_uri, BeamDropNode, PeerEvent, PeerInfo,
    TransferDirection, TransferError, TransferEvent, TrustedPeer,
};
use iroh::NodeId;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
#[cfg(desktop)]
use tauri::{LogicalPosition, Manager, WebviewUrl, WebviewWindowBuilder};
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
    pub node: Arc<RwLock<Option<Arc<BeamDropNode>>>>,
    pub startup_error: Arc<RwLock<Option<String>>>,
    pub node_ready: Arc<tokio::sync::Notify>,
    pub history: Arc<RwLock<Vec<TransferRecordDto>>>,
    pub active_starts: Arc<RwLock<HashMap<Uuid, Instant>>>,
    pub pending_send_paths: Arc<Mutex<Vec<String>>>,
    pub pending_targeted_sends: Arc<Mutex<Vec<TargetedSendRequest>>>,
    pub pending_pairing_uris: Arc<Mutex<Vec<String>>>,
}

impl AppState {
    pub fn new(initial_send_paths: Vec<String>) -> Self {
        Self {
            node: Arc::new(RwLock::new(None)),
            startup_error: Arc::new(RwLock::new(None)),
            node_ready: Arc::new(tokio::sync::Notify::new()),
            history: Arc::new(RwLock::new(Vec::new())),
            active_starts: Arc::new(RwLock::new(HashMap::new())),
            pending_send_paths: Arc::new(Mutex::new(initial_send_paths)),
            pending_targeted_sends: Arc::new(Mutex::new(Vec::new())),
            pending_pairing_uris: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn set_node(&self, node: Arc<BeamDropNode>) {
        *self.node.write().await = Some(node);
        self.node_ready.notify_waiters();
    }

    pub async fn set_startup_error(&self, err: String) {
        *self.startup_error.write().await = Some(err);
        self.node_ready.notify_waiters();
    }

    pub async fn require_node(&self) -> Result<Arc<BeamDropNode>, String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let notified = self.node_ready.notified();
            if let Some(node) = self.node.read().await.as_ref().cloned() {
                return Ok(node);
            }
            if let Some(err) = self.startup_error.read().await.as_ref().cloned() {
                return Err(err);
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err("ZapDrop engine is still starting up; please try again".to_string());
            }
            if tokio::time::timeout(remaining, notified).await.is_err() {
                if let Some(node) = self.node.read().await.as_ref().cloned() {
                    return Ok(node);
                }
                if let Some(err) = self.startup_error.read().await.as_ref().cloned() {
                    return Err(err);
                }
                return Err("Timed out waiting for ZapDrop engine to start".to_string());
            }
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
    pub auto_accept_wan: bool,
    pub paired_at_unix: Option<u64>,
    pub last_seen_unix_ms: Option<u64>,
    pub is_lan: bool,
    pub transport: String,
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
    pub auto_accept_wan: bool,
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
    /// Transport the offer arrived on: `Some(true)` = Internet (WAN), `Some(false)` = local LAN.
    #[serde(default)]
    pub is_wan: Option<bool>,
    /// Live path mode for active Over-Internet transfers (`Some(true)` = Direct P2P, `Some(false)` = Relayed).
    #[serde(default)]
    pub is_direct: Option<bool>,
    /// Unix epoch timestamp (ms) when a `pending_approval` or `awaiting_approval` countdown expires.
    #[serde(default)]
    pub approval_expires_at_unix_ms: Option<u64>,
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

/// Extracts POSIX paths from a `beamdrop://send?path=...` deep link URL.
#[cfg_attr(not(desktop), allow(dead_code))]
pub fn parse_send_uri(uri: &str) -> Option<Vec<String>> {
    let url = tauri::Url::parse(uri.trim()).ok()?;
    if !url.scheme().eq_ignore_ascii_case("beamdrop") {
        return None;
    }
    let host_matches = url
        .host_str()
        .is_some_and(|h| h.eq_ignore_ascii_case("send"));
    let path_matches = url.path().trim_matches('/').eq_ignore_ascii_case("send");
    if !host_matches && !path_matches {
        return None;
    }
    let paths: Vec<String> = url
        .query_pairs()
        .filter(|(k, _)| k == "path")
        .map(|(_, v)| v.into_owned())
        .filter(|v| !v.is_empty())
        .collect();
    Some(paths)
}

/// Parses `--send <path>...`, `--send-to <node_id> <path>...`, `--minimized`, `beamdrop://pair?...`, `beamdrop://send?...`, or bare paths from args.
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
            if let Some(send_paths) = parse_send_uri(arg) {
                parsed.send_paths.extend(send_paths);
            } else {
                parsed.pairing_uris.push(arg.trim().to_string());
            }
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

#[cfg(desktop)]
const INCOMING_BANNER_WINDOW_LABEL: &str = "incoming-banner";
#[cfg(desktop)]
const INCOMING_BANNER_WIDTH: f64 = 360.0;
#[cfg(desktop)]
const INCOMING_BANNER_HEIGHT: f64 = 104.0;

#[cfg(desktop)]
fn is_main_window_foreground(app: &AppHandle) -> bool {
    app.get_webview_window("main")
        .map(|w| {
            w.is_visible().unwrap_or(false)
                && w.is_focused().unwrap_or(false)
                && !w.is_minimized().unwrap_or(false)
        })
        .unwrap_or(false)
}

#[cfg(desktop)]
fn top_right_banner_position(app: &AppHandle) -> Option<(f64, f64)> {
    let monitor = app
        .get_webview_window("main")
        .and_then(|w| w.current_monitor().ok().flatten())
        .or_else(|| app.primary_monitor().ok().flatten())?;
    let scale = monitor.scale_factor().max(1.0);
    let area = monitor.work_area();
    let work_pos = area.position.to_logical::<f64>(scale);
    let work_size = area.size.to_logical::<f64>(scale);
    let margin = 16.0;
    let x = (work_pos.x + work_size.width - INCOMING_BANNER_WIDTH - margin).max(work_pos.x + margin);
    let y = work_pos.y + 12.0;
    Some((x, y))
}

#[cfg(desktop)]
pub fn show_desktop_incoming_banner(
    app: &AppHandle,
    fallback_title: Option<&str>,
    fallback_body: Option<&str>,
) {
    let app_handle = app.clone();
    let title_owned = fallback_title.map(str::to_string);
    let body_owned = fallback_body.map(str::to_string);
    let _ = app.run_on_main_thread(move || {
        if let Some(existing) = app_handle.get_webview_window(INCOMING_BANNER_WINDOW_LABEL) {
            if let Some((x, y)) = top_right_banner_position(&app_handle) {
                let _ = existing.set_position(LogicalPosition::new(x, y));
            }
            let _ = existing.show();
            return;
        }

        let mut builder = WebviewWindowBuilder::new(
            &app_handle,
            INCOMING_BANNER_WINDOW_LABEL,
            WebviewUrl::App("index.html".into()),
        )
        .title("ZapDrop Incoming Transfer")
        .inner_size(INCOMING_BANNER_WIDTH, INCOMING_BANNER_HEIGHT)
        .decorations(false)
        .transparent(true)
        .shadow(true)
        .always_on_top(true)
        .visible_on_all_workspaces(true)
        .resizable(false)
        .maximizable(false)
        .minimizable(false)
        .closable(false)
        .skip_taskbar(true)
        .focused(false)
        .focusable(false)
        .accept_first_mouse(true);

        if let Some((x, y)) = top_right_banner_position(&app_handle) {
            builder = builder.position(x, y);
        }

        match builder.build() {
            Ok(win) => {
                let _ = win.show();
            }
            Err(_) => {
                if let (Some(t), Some(b)) = (title_owned, body_owned) {
                    send_desktop_notification(&app_handle, &t, &b);
                }
            }
        }
    });
}

#[cfg(desktop)]
pub fn hide_desktop_incoming_banner(app: &AppHandle) {
    let app_handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(win) = app_handle.get_webview_window(INCOMING_BANNER_WINDOW_LABEL) {
            let _ = win.hide();
            let _ = win.destroy();
        }
    });
}

#[cfg(desktop)]
pub fn sync_desktop_incoming_banner(app: &AppHandle) {
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = app_handle.state::<AppState>();
        let has_pending = state
            .history
            .read()
            .await
            .iter()
            .any(|r| r.direction == "incoming" && r.status == "pending_approval");
        if !has_pending || is_main_window_foreground(&app_handle) {
            hide_desktop_incoming_banner(&app_handle);
        } else {
            show_desktop_incoming_banner(&app_handle, None, None);
        }
    });
}

fn format_bytes_short(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut val = bytes as f64;
    let mut idx = 0usize;
    while val >= 1024.0 && idx + 1 < UNITS.len() {
        val /= 1024.0;
        idx += 1;
    }
    format!("{val:.1} {}", UNITS[idx])
}

fn format_incoming_notification_text(
    is_wan: bool,
    sender_name: &str,
    file_name: &str,
    files: usize,
    total_bytes: u64,
) -> (String, String) {
    let trimmed_sender = sender_name.trim();
    let title = if trimmed_sender.is_empty() {
        "Nearby Device".to_string()
    } else {
        trimmed_sender.to_string()
    };
    let item_summary = if files <= 1 {
        let trimmed_file = file_name.trim();
        if trimmed_file.is_empty() {
            "1 file".to_string()
        } else {
            trimmed_file.to_string()
        }
    } else {
        format!("{files} files")
    };
    let size_text = format_bytes_short(total_bytes);
    let route_label = if is_wan {
        "Over Internet"
    } else {
        "Same Wi-Fi"
    };
    let body = format!("Sent {item_summary} ({size_text}) • {route_label}");
    (title, body)
}

fn send_incoming_transfer_notification(
    app: &AppHandle,
    transfer_id: &str,
    is_wan: bool,
    sender_name: &str,
    file_name: &str,
    files: usize,
    total_bytes: u64,
) {
    let (title, body) =
        format_incoming_notification_text(is_wan, sender_name, file_name, files, total_bytes);

    #[cfg(target_os = "android")]
    {
        if crate::android::show_incoming_transfer_notification(transfer_id, &title, &body).is_ok()
        {
            return;
        }
        send_desktop_notification(app, &title, &body);
        return;
    }

    #[cfg(desktop)]
    {
        let _ = transfer_id;
        if !is_main_window_foreground(app) {
            show_desktop_incoming_banner(app, Some(&title), Some(&body));
        }
        return;
    }

    #[cfg(all(not(target_os = "android"), not(desktop)))]
    {
        let _ = transfer_id;
        send_desktop_notification(app, &title, &body);
    }
}

fn dismiss_incoming_transfer_notification(app: &AppHandle) {
    #[cfg(target_os = "android")]
    {
        let _ = app;
        crate::android::dismiss_incoming_transfer_notification();
    }
    #[cfg(desktop)]
    hide_desktop_incoming_banner(app);
    #[cfg(all(not(target_os = "android"), not(desktop)))]
    let _ = app;
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
    let is_lan = peer.is_some_and(|p| {
        p.is_lan
            && p.addr
                .is_some_and(|a| !beamdrop_core::discovery::is_iroh_mapped_ip(&a.ip()))
    });
    match (peer, trust) {
        (Some(p), Some(t)) => PeerEntryDto {
            node_id: p.node_id.to_string(),
            display_name: p.display_name.clone(),
            os_type: p.os_type.to_string(),
            addr: if is_lan { p.addr.map(|a| a.to_string()) } else { None },
            port: if is_lan { Some(p.port) } else { None },
            online: if is_lan { p.online } else { false },
            paired: true,
            auto_accept: t.auto_accept,
            allow_wan: t.allow_wan,
            auto_accept_wan: t.auto_accept_wan,
            paired_at_unix: Some(t.paired_at_unix),
            last_seen_unix_ms: Some(p.last_seen_unix_ms),
            is_lan,
            transport: if is_lan && p.online {
                "LAN".to_string()
            } else if t.allow_wan {
                "WAN".to_string()
            } else if is_lan {
                "LAN".to_string()
            } else {
                "Offline".to_string()
            },
        },
        (Some(p), None) => PeerEntryDto {
            node_id: p.node_id.to_string(),
            display_name: p.display_name.clone(),
            os_type: p.os_type.to_string(),
            addr: if is_lan { p.addr.map(|a| a.to_string()) } else { None },
            port: if is_lan { Some(p.port) } else { None },
            online: if is_lan { p.online } else { false },
            paired: false,
            auto_accept: false,
            allow_wan: false,
            auto_accept_wan: false,
            paired_at_unix: None,
            last_seen_unix_ms: Some(p.last_seen_unix_ms),
            is_lan,
            transport: if is_lan { "LAN".to_string() } else { "WAN".to_string() },
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
            auto_accept_wan: t.auto_accept_wan,
            paired_at_unix: Some(t.paired_at_unix),
            last_seen_unix_ms: None,
            is_lan: false,
            transport: if t.allow_wan {
                "WAN".to_string()
            } else {
                "Offline".to_string()
            },
        },
        (None, None) => unreachable!("at least one source exists"),
    }
}

async fn upsert_history(history: &RwLock<Vec<TransferRecordDto>>, mut record: TransferRecordDto) {
    let mut guard = history.write().await;
    if let Some(pos) = guard
        .iter()
        .position(|existing| existing.transfer_id == record.transfer_id)
    {
        if record.is_wan.is_none() {
            record.is_wan = guard[pos].is_wan;
        }
        if record.file_name.is_none() {
            record.file_name = guard[pos].file_name.clone();
        }
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

async fn emit_outgoing_failure_with_id(
    app: &AppHandle,
    history: &RwLock<Vec<TransferRecordDto>>,
    transfer_id: Uuid,
    peer_node_id: Option<String>,
    peer_name: String,
    file_name: String,
    reason: String,
) {
    let existing = get_history_entry(history, &transfer_id.to_string()).await;
    let record = TransferRecordDto {
        transfer_id: transfer_id.to_string(),
        direction: "outgoing".to_string(),
        status: "failed".to_string(),
        peer_node_id,
        peer_name,
        file_name: Some(file_name.clone()),
        files: existing.as_ref().map(|r| r.files.max(1)).unwrap_or(1),
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
        reason: Some(reason.clone()),
        updated_at_unix_ms: now_unix_ms(),
        is_wan: existing.as_ref().and_then(|r| r.is_wan),
        is_direct: None,
        approval_expires_at_unix_ms: None,
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
        "ZapDrop transfer failed",
        &format!("Could not send {file_name}: {reason}"),
    );
}

async fn emit_outgoing_failure(
    app: &AppHandle,
    history: &RwLock<Vec<TransferRecordDto>>,
    peer_node_id: Option<String>,
    peer_name: String,
    file_name: String,
    reason: String,
) {
    emit_outgoing_failure_with_id(
        app,
        history,
        Uuid::new_v4(),
        peer_node_id,
        peer_name,
        file_name,
        reason,
    )
    .await;
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

        let node = match state.require_node().await {
            Ok(n) => n,
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

        let (peer_node_id, peer_label) =
            match resolve_target_peer(&node, &request.target_node_id).await {
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

        dispatch_send_paths(&app, &state, &node, peer_node_id, peer_label, validated);
    });
}

/// Spawns outgoing transfer tasks for `paths` to `peer_node_id`, reused by IPC commands and tray picker.
pub fn dispatch_send_paths(
    app: &AppHandle,
    state: &AppState,
    node: &Arc<BeamDropNode>,
    peer_node_id: NodeId,
    peer_label: String,
    paths: Vec<PathBuf>,
) -> usize {
    let count = paths.len();
    for path in paths {
        let app_handle = app.clone();
        let node = Arc::clone(node);
        let history = Arc::clone(&state.history);
        let label = peer_label.clone();

        tauri::async_runtime::spawn(async move {
            let transfer_id = Uuid::new_v4();
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(ToString::to_string)
                .unwrap_or_else(|| path.display().to_string());

            if let Err(err) = node
                .send_path_for_id(transfer_id, peer_node_id, &path, None)
                .await
            {
                if matches!(
                    err.downcast_ref::<TransferError>(),
                    Some(TransferError::Paused(_) | TransferError::Cancelled(_))
                ) {
                    return;
                }
                let already_recorded = get_history_entry(&history, &transfer_id.to_string())
                    .await
                    .is_some_and(|r| matches!(r.status.as_str(), "failed" | "cancelled" | "paused"));
                if !already_recorded {
                    emit_outgoing_failure_with_id(
                        &app_handle,
                        &history,
                        transfer_id,
                        Some(peer_node_id.to_string()),
                        label,
                        file_name,
                        err.to_string(),
                    )
                    .await;
                }
            }
        });
    }
    count
}

/// Starts background listeners piping `PeerEvent` and `TransferEvent` to the frontend, tray, and OS notifications.
pub fn spawn_event_forwarder(app: AppHandle, state: AppState, node: Arc<BeamDropNode>) {
    #[cfg(desktop)]
    if let Some(main_win) = app.get_webview_window("main") {
        let app_for_focus = app.clone();
        main_win.on_window_event(move |event| match event {
            tauri::WindowEvent::Focused(true) => {
                hide_desktop_incoming_banner(&app_for_focus);
            }
            tauri::WindowEvent::Focused(false) => {
                sync_desktop_incoming_banner(&app_for_focus);
            }
            _ => {}
        });
    }

    let mut peer_rx = node.subscribe_peers();
    let app_for_peers = app.clone();
    let node_for_peers = Arc::clone(&node);

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

    let mut transfer_rx = node.subscribe_transfers();
    let app_for_transfers = app;
    let node_for_transfers = node;
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
                is_wan: None,
                is_direct: None,
                approval_expires_at_unix_ms: None,
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
            let id_str = transfer_id.to_string();
            let existing = get_history_entry(history, &id_str).await;
            let record = TransferRecordDto {
                transfer_id: id_str,
                direction: "incoming".to_string(),
                status: "receiving".to_string(),
                peer_node_id: Some(sender_node_id.to_string()),
                peer_name: sender_name,
                file_name: existing.as_ref().and_then(|r| r.file_name.clone()),
                files,
                bytes_transferred: existing.as_ref().map(|r| r.bytes_transferred).unwrap_or(0),
                bytes_skipped_resumed: existing
                    .as_ref()
                    .map(|r| r.bytes_skipped_resumed)
                    .unwrap_or(0),
                total_bytes,
                speed_mbps: 0.0,
                streams_active: 0,
                verified: None,
                output_dir: None,
                reason: None,
                updated_at_unix_ms: now_ms,
                is_wan: existing.as_ref().and_then(|r| r.is_wan),
                is_direct: None,
                approval_expires_at_unix_ms: None,
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
            file_name,
            files,
            total_bytes,
            is_wan,
            expires_at_unix_ms,
        } => {
            let record = TransferRecordDto {
                transfer_id: transfer_id.to_string(),
                direction: "incoming".to_string(),
                status: "pending_approval".to_string(),
                peer_node_id: Some(sender_node_id.to_string()),
                peer_name: sender_name.clone(),
                file_name: Some(file_name.clone()),
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
                is_wan: Some(is_wan),
                is_direct: None,
                approval_expires_at_unix_ms: Some(expires_at_unix_ms),
            };
            upsert_history(history, record.clone()).await;
            let _ = app.emit(
                EVENT_TRANSFER,
                TransferEventDto {
                    kind: "pending_approval".to_string(),
                    record,
                },
            );
            send_incoming_transfer_notification(
                app,
                &transfer_id.to_string(),
                is_wan,
                &sender_name,
                &file_name,
                files,
                total_bytes,
            );
        }
        TransferEvent::AwaitingApproval {
            transfer_id,
            peer_node_id,
            peer_name,
            file_name,
            files,
            total_bytes,
            is_wan,
            expires_at_unix_ms,
        } => {
            let id_str = transfer_id.to_string();
            let existing = get_history_entry(history, &id_str).await;
            let bytes_transferred = existing.as_ref().map(|r| r.bytes_transferred).unwrap_or(0);
            let bytes_skipped_resumed = existing
                .as_ref()
                .map(|r| r.bytes_skipped_resumed)
                .unwrap_or(0);
            let record = TransferRecordDto {
                transfer_id: id_str,
                direction: "outgoing".to_string(),
                status: "awaiting_approval".to_string(),
                peer_node_id: Some(peer_node_id.to_string()),
                peer_name,
                file_name: Some(file_name),
                files,
                bytes_transferred,
                bytes_skipped_resumed,
                total_bytes,
                speed_mbps: 0.0,
                streams_active: 0,
                verified: None,
                output_dir: None,
                reason: None,
                updated_at_unix_ms: now_ms,
                is_wan: Some(is_wan),
                is_direct: None,
                approval_expires_at_unix_ms: Some(expires_at_unix_ms),
            };
            upsert_history(history, record.clone()).await;
            let _ = app.emit(
                EVENT_TRANSFER,
                TransferEventDto {
                    kind: "awaiting_approval".to_string(),
                    record,
                },
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
            } else if bytes_skipped_resumed == 0 {
                "connecting"
            } else {
                "sending"
            };
            let prev_transferred = existing.as_ref().map(|r| r.bytes_transferred).unwrap_or(0);
            let prev_skipped = existing
                .as_ref()
                .map(|r| r.bytes_skipped_resumed)
                .unwrap_or(0);
            let prev_is_wan = existing.as_ref().and_then(|r| r.is_wan);
            let record = TransferRecordDto {
                transfer_id: id_str,
                direction,
                status: status.to_string(),
                peer_node_id: Some(peer_node_id.to_string()),
                peer_name,
                file_name: Some(file_name),
                files,
                bytes_transferred: prev_transferred,
                bytes_skipped_resumed: prev_skipped.max(bytes_skipped_resumed),
                total_bytes,
                speed_mbps: 0.0,
                streams_active: 0,
                verified: None,
                output_dir: None,
                reason: None,
                updated_at_unix_ms: now_ms,
                is_wan: prev_is_wan,
                is_direct: None,
                approval_expires_at_unix_ms: None,
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
            let is_wan = Some(p.is_wan);
            let is_direct = if p.is_wan { p.is_direct } else { None };

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
                is_wan,
                is_direct,
                approval_expires_at_unix_ms: None,
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
            if direction == "incoming" {
                dismiss_incoming_transfer_notification(app);
            }
            let peer_node_id = existing.as_ref().and_then(|r| r.peer_node_id.clone());
            let peer_name = existing
                .as_ref()
                .map(|r| r.peer_name.clone())
                .unwrap_or_else(|| "Peer".to_string());
            let file_name = existing.as_ref().and_then(|r| r.file_name.clone());
            let is_wan = existing.as_ref().and_then(|r| r.is_wan);
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
                is_wan,
                is_direct: None,
                approval_expires_at_unix_ms: None,
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
            send_desktop_notification(app, "ZapDrop transfer complete", &notif_body);
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
        TransferEvent::Failed {
            transfer_id,
            direction,
            peer_node_id,
            peer_name,
            file_name,
            files,
            total_bytes,
            is_wan,
            reason,
        } => {
            active_starts.write().await.remove(&transfer_id);
            let id_str = transfer_id.to_string();
            let existing = get_history_entry(history, &id_str).await;
            let direction_str = match direction {
                TransferDirection::Incoming => {
                    dismiss_incoming_transfer_notification(app);
                    "incoming".to_string()
                }
                TransferDirection::Outgoing => "outgoing".to_string(),
            };
            let record = TransferRecordDto {
                transfer_id: id_str,
                direction: direction_str,
                status: "failed".to_string(),
                peer_node_id: Some(peer_node_id.to_string()),
                peer_name,
                file_name: Some(file_name.clone()),
                files,
                bytes_transferred: existing.as_ref().map(|r| r.bytes_transferred).unwrap_or(0),
                bytes_skipped_resumed: existing
                    .as_ref()
                    .map(|r| r.bytes_skipped_resumed)
                    .unwrap_or(0),
                total_bytes,
                speed_mbps: 0.0,
                streams_active: 0,
                verified: Some(false),
                output_dir: None,
                reason: Some(reason.clone()),
                updated_at_unix_ms: now_ms,
                is_wan: is_wan.or_else(|| existing.as_ref().and_then(|r| r.is_wan)),
                is_direct: None,
                approval_expires_at_unix_ms: None,
            };
            upsert_history(history, record.clone()).await;
            let _ = app.emit(
                EVENT_TRANSFER,
                TransferEventDto {
                    kind: "failed".to_string(),
                    record,
                },
            );
            if matches!(direction, TransferDirection::Outgoing) {
                send_desktop_notification(
                    app,
                    "ZapDrop transfer failed",
                    &format!("Could not send {file_name}: {reason}"),
                );
            }
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
    let Some(existing) = get_history_entry(history, &id_str).await else {
        // Ignore orphan control events that have no pre-existing transfer record so
        // pre-offer validation failures never create bogus `"Peer" • 0 item(s)` rows.
        return;
    };
    if existing.direction == "incoming" {
        dismiss_incoming_transfer_notification(app);
    }
    let record = TransferRecordDto {
        transfer_id: id_str,
        direction: existing.direction,
        status: status.to_string(),
        peer_node_id: existing.peer_node_id,
        peer_name: existing.peer_name,
        file_name: existing.file_name,
        files: existing.files,
        bytes_transferred: existing.bytes_transferred,
        bytes_skipped_resumed: existing.bytes_skipped_resumed,
        total_bytes: existing.total_bytes,
        speed_mbps: 0.0,
        streams_active: 0,
        verified,
        output_dir: existing.output_dir,
        reason,
        updated_at_unix_ms: now_ms,
        is_wan: existing.is_wan,
        is_direct: None,
        approval_expires_at_unix_ms: None,
    };
    upsert_history(history, record.clone()).await;
    #[cfg(desktop)]
    sync_desktop_incoming_banner(app);
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
    let node = state.require_node().await?;
    let id = node.identity();
    #[cfg(target_os = "android")]
    let download_dir = crate::android::public_download_dir()
        .unwrap_or_else(|| node.download_dir().to_path_buf())
        .display()
        .to_string();
    #[cfg(not(target_os = "android"))]
    let download_dir = node.download_dir().display().to_string();

    Ok(SelfInfoDto {
        node_id: id.node_id.to_string(),
        device_id: id.device_id.to_string(),
        hostname: id.hostname.clone(),
        os_type: id.os_type.to_string(),
        lan_ip: beamdrop_core::detect_lan_ip().to_string(),
        listen_port: node.listen_port(),
        download_dir,
    })
}

#[tauri::command]
pub async fn list_peers(state: State<'_, AppState>) -> Result<Vec<PeerEntryDto>, String> {
    let node = state.require_node().await?;
    Ok(collect_peer_entries(&node).await)
}

#[tauri::command]
pub async fn start_pairing(
    state: State<'_, AppState>,
    force_new: Option<bool>,
) -> Result<PairingSessionDto, String> {
    let node = state.require_node().await?;
    let session = node
        .get_or_start_pairing_session(force_new.unwrap_or(false))
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
pub async fn regenerate_pairing(state: State<'_, AppState>) -> Result<PairingSessionDto, String> {
    let node = state.require_node().await?;
    let session = node
        .get_or_start_pairing_session(true)
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
pub async fn cancel_pairing(state: State<'_, AppState>) -> Result<(), String> {
    let node = state.require_node().await?;
    node.cancel_pairing_session().await;
    Ok(())
}

#[tauri::command]
pub async fn pair_with_peer(
    app: AppHandle,
    state: State<'_, AppState>,
    target: String,
    pin: String,
) -> Result<TrustedPeerDto, String> {
    let node = state.require_node().await?;
    let paired = node
        .pair_with_peer(target.trim(), pin.trim())
        .await
        .map_err(|e| e.to_string())?;

    let known = node.discovery().known_peers().await;
    let matched_known = known.iter().find(|p| p.node_id == paired.node_id);
    let _ = app.emit(
        EVENT_PEER,
        PeerEventDto {
            kind: "paired".to_string(),
            peer: peer_entry_from_parts(matched_known, Some(&paired)),
        },
    );

    let sync_app = app.clone();
    let sync_node = Arc::clone(&node);
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
        auto_accept_wan: paired.auto_accept_wan,
    })
}

#[tauri::command]
pub async fn set_peer_wan_enabled(
    state: State<'_, AppState>,
    node_id: String,
    enabled: bool,
) -> Result<bool, String> {
    let node = state.require_node().await?;
    let parsed = NodeId::from_str(node_id.trim())
        .map_err(|e| format!("Invalid NodeId '{node_id}': {e}"))?;
    node.set_peer_wan_enabled(parsed, enabled)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn set_peer_auto_accept(
    state: State<'_, AppState>,
    node_id: String,
    lan_auto: bool,
    wan_auto: bool,
) -> Result<bool, String> {
    let node = state.require_node().await?;
    let parsed = NodeId::from_str(node_id.trim())
        .map_err(|e| format!("Invalid NodeId '{node_id}': {e}"))?;
    node.set_peer_auto_accept(parsed, lan_auto, wan_auto)
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
    let node = state.require_node().await?;
    let parsed = NodeId::from_str(node_id.trim())
        .map_err(|e| format!("Invalid NodeId '{node_id}': {e}"))?;
    let removed = node
        .remove_trusted_peer(&parsed)
        .await
        .map_err(|e| e.to_string())?;

    let sync_app = app.clone();
    let sync_node = Arc::clone(&node);
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
    let node = state.require_node().await?;
    let cleaned: Vec<String> = paths
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if cleaned.is_empty() {
        return Err("No file or folder paths provided".to_string());
    }

    let (peer_node_id, peer_label) = resolve_target_peer(&node, &target_node_id).await?;
    let validated = resolve_paths_for_platform(cleaned).await?;

    let queued = dispatch_send_paths(&app, &state, &node, peer_node_id, peer_label, validated);
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
    let node = state.require_node().await?;
    let parsed_id = Uuid::from_str(transfer_id.trim())
        .map_err(|e| format!("Invalid transfer UUID '{transfer_id}': {e}"))?;
    Ok(node.pause_transfer(parsed_id).await)
}

#[tauri::command]
pub async fn resume_transfer(
    app: AppHandle,
    state: State<'_, AppState>,
    transfer_id: String,
) -> Result<(), String> {
    let node = state.require_node().await?;
    let parsed_id = Uuid::from_str(transfer_id.trim())
        .map_err(|e| format!("Invalid transfer UUID '{transfer_id}': {e}"))?;
    node.resume_transfer(parsed_id)
        .await
        .map_err(|e| e.to_string())?;

    state
        .active_starts
        .write()
        .await
        .insert(parsed_id, Instant::now());
    let updated_record = {
        let mut guard = state.history.write().await;
        if let Some(entry) = guard
            .iter_mut()
            .find(|r| r.transfer_id == parsed_id.to_string())
        {
            entry.status = if entry.direction == "incoming" {
                "receiving".to_string()
            } else {
                "connecting".to_string()
            };
            entry.reason = None;
            entry.approval_expires_at_unix_ms = None;
            entry.updated_at_unix_ms = now_unix_ms();
            Some(entry.clone())
        } else {
            None
        }
    };
    if let Some(record) = updated_record {
        let _ = app.emit(
            EVENT_TRANSFER,
            TransferEventDto {
                kind: "started".to_string(),
                record,
            },
        );
    }
    Ok(())
}

#[tauri::command]
pub async fn cancel_transfer(
    state: State<'_, AppState>,
    transfer_id: String,
) -> Result<bool, String> {
    let node = state.require_node().await?;
    let parsed_id = Uuid::from_str(transfer_id.trim())
        .map_err(|e| format!("Invalid transfer UUID '{transfer_id}': {e}"))?;
    Ok(node.cancel_transfer(parsed_id).await)
}

#[tauri::command]
pub async fn refresh_peers(state: State<'_, AppState>) -> Result<Vec<PeerEntryDto>, String> {
    let node = state.require_node().await?;
    node.refresh_peers().await;
    Ok(collect_peer_entries(&node).await)
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

/// Shared incoming-offer approval/decline handler called by both UI commands and Android notification actions.
pub async fn process_offer_response(
    app: &AppHandle,
    state: &AppState,
    transfer_id: &str,
    accept: bool,
) -> Result<(), String> {
    let node = state.require_node().await?;
    let parsed_id = Uuid::from_str(transfer_id.trim())
        .map_err(|e| format!("Invalid transfer UUID '{transfer_id}': {e}"))?;

    dismiss_incoming_transfer_notification(app);
    node.respond_to_offer(parsed_id, accept)
        .await
        .map_err(|e| e.to_string())?;

    let updated = {
        let mut guard = state.history.write().await;
        if let Some(entry) = guard
            .iter_mut()
            .find(|r| r.transfer_id == parsed_id.to_string())
        {
            entry.status = if accept {
                "receiving".to_string()
            } else {
                "rejected".to_string()
            };
            entry.approval_expires_at_unix_ms = None;
            entry.updated_at_unix_ms = now_unix_ms();
            Some(entry.clone())
        } else {
            None
        }
    };
    if let Some(record) = updated {
        let kind = if accept { "accepted" } else { "rejected" };
        let _ = app.emit(
            EVENT_TRANSFER,
            TransferEventDto {
                kind: kind.to_string(),
                record,
            },
        );
    }
    #[cfg(desktop)]
    sync_desktop_incoming_banner(app);

    Ok(())
}

#[tauri::command]
pub async fn respond_to_offer(
    app: AppHandle,
    state: State<'_, AppState>,
    transfer_id: String,
    accept: bool,
) -> Result<(), String> {
    process_offer_response(&app, state.inner(), &transfer_id, accept).await
}

#[tauri::command]
pub fn open_main_window(app: AppHandle) {
    #[cfg(desktop)]
    {
        crate::tray::show_main_window(&app);
        hide_desktop_incoming_banner(&app);
    }
    #[cfg(not(desktop))]
    let _ = app;
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
        let node = state.require_node().await?;
        let dir = node.download_dir();
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

    #[test]
    fn parse_cli_args_extracts_beamdrop_send_uri() {
        let uri = "beamdrop://send?path=%2FUsers%2Falex%2FMy%20File%2B1%262.pdf&path=%2FUsers%2Falex%2FFolder";
        let parsed = parse_cli_args(["beamdrop-app", uri]);
        assert!(parsed.pairing_uris.is_empty());
        assert_eq!(
            parsed.send_paths,
            vec![
                "/Users/alex/My File+1&2.pdf".to_string(),
                "/Users/alex/Folder".to_string(),
            ]
        );
    }

    #[test]
    fn format_incoming_notification_text_formats_messenger_banner() {
        let (title, body) = format_incoming_notification_text(
            false,
            "MacBook Pro",
            "report.pdf",
            1,
            2 * 1024 * 1024,
        );
        assert_eq!(title, "MacBook Pro");
        assert_eq!(body, "Sent report.pdf (2.0 MiB) • Same Wi-Fi");

        let (title_wan, body_wan) = format_incoming_notification_text(
            true,
            "   ",
            "",
            4,
            512,
        );
        assert_eq!(title_wan, "Nearby Device");
        assert_eq!(body_wan, "Sent 4 files (512 B) • Over Internet");
    }
}


