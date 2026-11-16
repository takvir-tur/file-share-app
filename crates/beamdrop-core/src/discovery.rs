use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh::endpoint::{Connection, ConnectionType};
use iroh::{Endpoint, NodeAddr, NodeId, RelayMode};
use mdns_sd::{IfKind, ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};
use uuid::Uuid;

use crate::identity::{DeviceIdentity, IdentityError, OsType};
use crate::protocol::{
    read_frame, write_frame, HelloPayload, Message, PairConfirmPayload, PingPayload, PongPayload,
    ProtocolError, RejectPayload, TransferControlPayload, BEAMDROP_ALPN, PROTOCOL_VERSION,
};
use crate::transfer::TransferEngine;
use crate::trust::TrustStore;

/// mDNS service type advertised and browsed by BeamDrop nodes.
pub const MDNS_SERVICE_TYPE: &str = "_beamdrop._udp.local.";

/// Default filename for the disk-cached peer table.
pub const KNOWN_PEERS_FILENAME: &str = "known_peers.json";

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("Identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("mDNS daemon error: {0}")]
    Mdns(#[from] mdns_sd::Error),
    #[error("I/O error accessing known_peers.json: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Iroh transport error: {0}")]
    Iroh(#[from] anyhow::Error),
    #[error("Peer {0} is not found in known peers table")]
    UnknownPeer(NodeId),
}

/// Information about a discovered or cached LAN peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Cryptographic `NodeId` (Ed25519 public key) of the peer.
    pub node_id: NodeId,
    /// Human-readable display name (hostname) of the peer.
    pub display_name: String,
    /// Operating system type (`Windows`, `macOS`, `Android`).
    pub os_type: OsType,
    /// Last known real LAN `SocketAddr` (`IP:port`) for direct QUIC dialing (`None` for WAN-only peers).
    #[serde(default)]
    pub addr: Option<SocketAddr>,
    /// Local listening UDP/QUIC port advertised by the peer.
    #[serde(default)]
    pub port: u16,
    /// Whether this peer is reachable on the local LAN (false for pure WAN/relay peers).
    #[serde(default)]
    pub is_lan: bool,
    /// Whether the peer is currently active on the local network.
    #[serde(default)]
    pub online: bool,
    /// Unix timestamp in milliseconds when the peer was last seen.
    pub last_seen_unix_ms: u64,
}

impl PeerInfo {
    /// Constructs an `iroh::NodeAddr` targeting this peer's last known local `SocketAddr`.
    pub fn to_node_addr(&self) -> NodeAddr {
        let addrs: Vec<SocketAddr> = self
            .addr
            .into_iter()
            .filter(|a| !is_iroh_mapped_ip(&a.ip()) && is_local_lan_ip(&a.ip()))
            .collect();
        NodeAddr::from_parts(self.node_id, None, addrs)
    }
}

/// Events emitted over the `tokio::sync::broadcast` channel by the `DiscoveryEngine`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerEvent {
    /// A peer was discovered or updated on the local network.
    Discovered(PeerInfo),
    /// A previously discovered peer left the network or its mDNS record expired.
    Lost(PeerInfo),
    /// A peer completed a one-time pairing handshake and was added to `trusted_peers.json`.
    Paired(PeerInfo),
}

/// On-disk format for `known_peers.json`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct PersistedPeerCache {
    peers: Vec<PeerInfo>,
}

/// In-memory + disk-cached peer table (`known_peers.json`) storing each peer's
/// last known local `SocketAddr` and `NodeId` for sub-50ms direct dialing.
#[derive(Debug)]
pub struct PeerTable {
    path: PathBuf,
    peers: HashMap<NodeId, PeerInfo>,
    extra_addrs: HashMap<NodeId, Vec<SocketAddr>>,
    fullname_to_node: HashMap<String, NodeId>,
    /// Unix ms timestamp when a live local `_beamdrop._udp.local.` mDNS resolution was observed.
    mdns_seen_ms: HashMap<NodeId, u64>,
}

impl PeerTable {
    /// Returns the default path to `BeamDrop/known_peers.json` in the OS config directory.
    pub fn default_path() -> Result<PathBuf, DiscoveryError> {
        Ok(DeviceIdentity::config_dir()?.join(KNOWN_PEERS_FILENAME))
    }

    /// Loads the peer table from `known_peers.json` (or initializes an empty table if absent).
    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, DiscoveryError> {
        let path = path.as_ref().to_path_buf();
        let mut peers = HashMap::new();

        if path.exists() {
            let raw = fs::read_to_string(&path)?;
            if !raw.trim().is_empty() {
                let cache: PersistedPeerCache = serde_json::from_str(&raw)?;
                for mut peer in cache.peers {
                    let valid_lan_addr = peer
                        .addr
                        .filter(|a| !is_iroh_mapped_ip(&a.ip()) && is_local_lan_ip(&a.ip()));
                    let Some(clean_addr) = valid_lan_addr else {
                        continue;
                    };
                    peer.addr = Some(clean_addr);
                    peer.is_lan = true;
                    peer.online = false;
                    peers.insert(peer.node_id, peer);
                }
            }
        } else {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let empty = PersistedPeerCache::default();
            fs::write(&path, serde_json::to_string_pretty(&empty)?)?;
        }

        Ok(Self {
            path,
            peers,
            extra_addrs: HashMap::new(),
            fullname_to_node: HashMap::new(),
            mdns_seen_ms: HashMap::new(),
        })
    }

    /// Persists the current peer table to `known_peers.json`.
    pub fn save(&self) -> Result<(), DiscoveryError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut list: Vec<PeerInfo> = self.peers.values().cloned().collect();
        list.sort_by_key(|p| p.node_id.to_string());
        let cache = PersistedPeerCache { peers: list };
        let json = serde_json::to_string_pretty(&cache)?;
        fs::write(&self.path, json)?;
        Ok(())
    }

    /// Inserts or updates a peer in the in-memory table and flushes to `known_peers.json`.
    /// Returns `(saved_peer, should_notify)` where `should_notify` is true if the peer
    /// transitioned from offline/unknown to online or changed its listening `SocketAddr`.
    pub fn upsert(
        &mut self,
        mut peer: PeerInfo,
        mdns_fullname: Option<&str>,
    ) -> Result<(PeerInfo, bool), DiscoveryError> {
        let valid_lan_addr = peer
            .addr
            .filter(|a| !is_iroh_mapped_ip(&a.ip()) && is_local_lan_ip(&a.ip()));
        if valid_lan_addr.is_none() {
            self.mdns_seen_ms.remove(&peer.node_id);
            peer.addr = None;
            peer.is_lan = false;
            peer.online = false;
            return Ok((peer, false));
        }
        peer.addr = valid_lan_addr;
        peer.is_lan = true;
        if let Some(fullname) = mdns_fullname {
            self.fullname_to_node
                .insert(fullname.to_ascii_lowercase(), peer.node_id);
            self.mdns_seen_ms.insert(peer.node_id, now_unix_ms());
        }
        let should_notify = match self.peers.get(&peer.node_id) {
            Some(prev) => {
                if prev.port != peer.port {
                    self.extra_addrs
                        .entry(peer.node_id)
                        .and_modify(|list| list.retain(|a| a.port() == peer.port));
                }
                !prev.online || prev.addr != peer.addr || prev.is_lan != peer.is_lan
            }
            None => true,
        };
        self.peers.insert(peer.node_id, peer.clone());
        self.save()?;
        Ok((peer, should_notify))
    }

    /// Marks a peer as lost by its mDNS service fullname, preserving its last known
    /// `SocketAddr` and `NodeId` on disk for fast direct reconnection.
    pub fn mark_lost_by_fullname(&mut self, fullname: &str) -> Option<PeerInfo> {
        let key = fullname.to_ascii_lowercase();
        let node_id = self.fullname_to_node.remove(&key)?;
        self.mark_lost(&node_id)
    }

    /// Marks a peer as offline by its `NodeId` while keeping its cached address in `known_peers.json`.
    pub fn mark_lost(&mut self, node_id: &NodeId) -> Option<PeerInfo> {
        self.mdns_seen_ms.remove(node_id);
        let peer = self.peers.get_mut(node_id)?;
        peer.online = false;
        let snapshot = peer.clone();
        let _ = self.save();
        Some(snapshot)
    }

    /// Looks up a peer by `NodeId`.
    pub fn get(&self, node_id: &NodeId) -> Option<&PeerInfo> {
        self.peers.get(node_id)
    }

    /// Returns all currently online peers.
    pub fn online_peers(&self) -> Vec<PeerInfo> {
        let mut list: Vec<PeerInfo> = self.peers.values().filter(|p| p.online).cloned().collect();
        list.sort_by(|a, b| a.display_name.cmp(&b.display_name));
        list
    }

    /// Returns all known peers (both online and cached offline peers).
    pub fn all_peers(&self) -> Vec<PeerInfo> {
        let mut list: Vec<PeerInfo> = self.peers.values().cloned().collect();
        list.sort_by(|a, b| a.display_name.cmp(&b.display_name));
        list
    }

    /// Records sorted alternate socket addresses (IPv4-first) for `node_id`.
    pub fn set_extra_addrs(&mut self, node_id: NodeId, addrs: Vec<SocketAddr>) {
        if addrs.is_empty() {
            self.extra_addrs.remove(&node_id);
        } else {
            self.extra_addrs.insert(node_id, sort_socket_addrs(&addrs));
        }
    }

    /// Returns all known local `SocketAddr` candidates for `node_id`, sorted IPv4-first.
    pub fn node_addrs_for(&self, node_id: &NodeId) -> Vec<SocketAddr> {
        let mut addrs = Vec::new();
        if let Some(peer) = self.peers.get(node_id) {
            if let Some(addr) = peer.addr {
                if !is_iroh_mapped_ip(&addr.ip()) && is_local_lan_ip(&addr.ip()) {
                    addrs.push(addr);
                }
            }
        }
        if let Some(extra) = self.extra_addrs.get(node_id) {
            for addr in extra {
                if !is_iroh_mapped_ip(&addr.ip())
                    && is_local_lan_ip(&addr.ip())
                    && !addrs.contains(addr)
                {
                    addrs.push(*addr);
                }
            }
        }
        sort_socket_addrs(&addrs)
    }

    /// Returns `iroh::NodeAddr` entries for all cached peers so the local `Endpoint`
    /// can dial them directly in <50ms without waiting for mDNS or relay resolution.
    pub fn cached_node_addrs(&self) -> Vec<NodeAddr> {
        self.peers
            .iter()
            .filter_map(|(id, peer)| {
                let addrs = self.node_addrs_for(id);
                if addrs.is_empty() && !peer.is_lan {
                    None
                } else {
                    Some(NodeAddr::from_parts(*id, None, addrs))
                }
            })
            .collect()
    }

    /// Returns `true` when `node_id` currently has a live, non-expired local mDNS (`_beamdrop._udp.local.`)
    /// entry in `PeerTable` (never matching synthetic `iroh` mapped addresses, stale cached records, or WAN-only peers).
    pub fn has_live_lan_peer(&self, node_id: &NodeId, max_age_ms: u64) -> bool {
        let Some(&seen_ms) = self.mdns_seen_ms.get(node_id) else {
            return false;
        };
        let Some(peer) = self.peers.get(node_id) else {
            return false;
        };
        if !peer.online || !peer.is_lan {
            return false;
        }
        let Some(addr) = peer.addr else {
            return false;
        };
        if is_iroh_mapped_ip(&addr.ip()) || !is_local_lan_ip(&addr.ip()) {
            return false;
        }
        now_unix_ms().saturating_sub(seen_ms) <= max_age_ms
    }

    /// Removes `node_id` from the cached table only when it is not currently online on the LAN.
    pub fn remove_offline_peer(&mut self, node_id: &NodeId) {
        if self.peers.get(node_id).is_some_and(|p| !p.online) {
            self.peers.remove(node_id);
            self.extra_addrs.remove(node_id);
            self.mdns_seen_ms.remove(node_id);
            let _ = self.save();
        }
    }

    /// Removes `node_id` completely from the cached table and persists the change.
    pub fn remove_peer(&mut self, node_id: &NodeId) {
        self.peers.remove(node_id);
        self.extra_addrs.remove(node_id);
        self.mdns_seen_ms.remove(node_id);
        let _ = self.save();
    }

    /// Path to the backing `known_peers.json` file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Request from a remote peer to resume a paused transfer: `(transfer_id, requester_node_id, reply_tx)`.
pub type ResumeRequest = (Uuid, NodeId, oneshot::Sender<Result<(), String>>);

/// Channels used to forward out-of-band transfer & pairing-WAN control requests to `BeamDropNode`.
#[derive(Clone)]
pub struct ControlChannels {
    pub resume_tx: mpsc::UnboundedSender<ResumeRequest>,
    pub cancel_tx: mpsc::UnboundedSender<(Uuid, Option<String>)>,
    pub wan_recheck_tx: mpsc::UnboundedSender<()>,
}

/// Zero-config LAN discovery engine and fast-dial peer manager.
pub struct DiscoveryEngine {
    identity: DeviceIdentity,
    endpoint: Arc<StdRwLock<Option<Endpoint>>>,
    listen_port: Arc<AtomicU16>,
    mdns: Option<ServiceDaemon>,
    service_fullname: StdMutex<String>,
    peer_table: Arc<RwLock<PeerTable>>,
    event_tx: broadcast::Sender<PeerEvent>,
    transfer_engine: Option<Arc<TransferEngine>>,
    trust_store: Option<Arc<TrustStore>>,
    control_channels: Option<ControlChannels>,
    wan_enabled: Arc<AtomicBool>,
    pairing_wan_expires_at: Arc<AtomicU64>,
    reconfigure_lock: Mutex<()>,
    accept_task: Arc<StdMutex<Option<JoinHandle<()>>>>,
    accept_shutdown_tx: StdMutex<watch::Sender<bool>>,
    online_init_task: Arc<StdMutex<Option<JoinHandle<()>>>>,
    probe_reset_tx: watch::Sender<u64>,
    tasks: Vec<JoinHandle<()>>,
}

fn build_mdns_service_info(
    identity: &DeviceIdentity,
    listen_port: u16,
) -> Result<ServiceInfo, DiscoveryError> {
    let node_id_str = identity.node_id.to_string();
    let short_id = &node_id_str[..10.min(node_id_str.len())];
    let instance_name = format!("bd-{short_id}");
    let host_name = format!("beamdrop-{short_id}.local.");
    let port_str = listen_port.to_string();

    let properties = [
        ("node_id", node_id_str.as_str()),
        ("display_name", identity.hostname.as_str()),
        ("os", identity.os_type.as_str()),
        ("port", port_str.as_str()),
    ];

    let mut service_info = ServiceInfo::new(
        MDNS_SERVICE_TYPE,
        &instance_name,
        &host_name,
        (),
        listen_port,
        &properties[..],
    )?
    .enable_addr_auto();
    service_info.set_requires_probe(false);
    Ok(service_info)
}

impl DiscoveryEngine {
    /// Classifies an active QUIC connection as LAN (`true`) or WAN (`false`), checking:
    /// 1) `endpoint.conn_type`/`remote_info(*remote_node_id)` reports an active or direct LAN `SocketAddr`, OR
    /// 2) `PeerTable` currently holds a live non-expired local mDNS/LAN entry for `*remote_node_id`.
    pub async fn is_connection_lan(&self, conn: &Connection, remote_node_id: &NodeId) -> bool {
        let ep_guard = self.endpoint.read().expect("endpoint rwlock").clone();
        is_connection_lan_with_table(
            ep_guard.as_ref(),
            Some(conn),
            Some(&self.peer_table),
            *remote_node_id,
        )
        .await
    }

    /// Starts the discovery engine:
    /// 1. Loads `known_peers.json` and pre-populates the Iroh `Endpoint` with known `NodeAddr`s.
    /// 2. Advertises `_beamdrop._udp.local.` via mDNS with `NodeId`, display name, OS type, and port.
    /// 3. Browses `_beamdrop._udp.local.` on the LAN and emits `PeerEvent::Discovered` / `PeerEvent::Lost`.
    /// 4. Proactively probes cached peers in `known_peers.json` over direct QUIC for <50ms discovery.
    pub async fn start(
        identity: DeviceIdentity,
        endpoint: Endpoint,
        known_peers_path: Option<PathBuf>,
    ) -> Result<Self, DiscoveryError> {
        Self::start_with_transfer(identity, endpoint, known_peers_path, None).await
    }

    /// Starts the discovery engine with an optional `TransferEngine` to handle incoming `Offer`s.
    pub async fn start_with_transfer(
        identity: DeviceIdentity,
        endpoint: Endpoint,
        known_peers_path: Option<PathBuf>,
        transfer_engine: Option<Arc<TransferEngine>>,
    ) -> Result<Self, DiscoveryError> {
        Self::start_with_services(identity, endpoint, known_peers_path, transfer_engine, None)
            .await
    }

    /// Starts the discovery engine with optional `TransferEngine` and `TrustStore` services.
    pub async fn start_with_services(
        identity: DeviceIdentity,
        endpoint: Endpoint,
        known_peers_path: Option<PathBuf>,
        transfer_engine: Option<Arc<TransferEngine>>,
        trust_store: Option<Arc<TrustStore>>,
    ) -> Result<Self, DiscoveryError> {
        Self::start_with_handlers(
            identity,
            endpoint,
            known_peers_path,
            transfer_engine,
            trust_store,
            None,
        )
        .await
    }

    /// Starts the discovery engine with optional `TransferEngine`, `TrustStore`, and out-of-band control channels.
    pub async fn start_with_handlers(
        identity: DeviceIdentity,
        endpoint: Endpoint,
        known_peers_path: Option<PathBuf>,
        transfer_engine: Option<Arc<TransferEngine>>,
        trust_store: Option<Arc<TrustStore>>,
        control_channels: Option<ControlChannels>,
    ) -> Result<Self, DiscoveryError> {
        let table_path = match known_peers_path {
            Some(p) => p,
            None => PeerTable::default_path()?,
        };
        let mut initial_table = PeerTable::load_or_create(&table_path)?;

        // Remove self if accidentally present in known_peers.json
        initial_table.peers.remove(&identity.node_id);

        // Pre-seed the Iroh Endpoint with all cached peer SocketAddrs for <50ms direct dialing
        for node_addr in initial_table.cached_node_addrs() {
            let _ = endpoint.add_node_addr(node_addr);
        }

        let listen_port_val = endpoint.bound_sockets().0.port();
        let listen_port = Arc::new(AtomicU16::new(listen_port_val));
        let shared_endpoint = Arc::new(StdRwLock::new(Some(endpoint.clone())));
        if let Some(ref tr) = transfer_engine {
            tr.attach_endpoint(Arc::clone(&shared_endpoint));
        }
        let wan_initial = match &trust_store {
            Some(store) => store.any_wan_enabled().await,
            None => false,
        };
        let wan_enabled = Arc::new(AtomicBool::new(wan_initial));
        let pairing_wan_expires_at = Arc::new(AtomicU64::new(0));

        let online_init_task = Arc::new(StdMutex::new(if wan_initial {
            let online_ep = endpoint.clone();
            Some(tokio::spawn(async move {
                let _ = tokio::time::timeout(
                    Duration::from_secs(3),
                    online_ep.home_relay().initialized(),
                )
                .await;
            }))
        } else {
            None
        }));

        let peer_table = Arc::new(RwLock::new(initial_table));
        let (event_tx, _) = broadcast::channel(128);

        let service_info = build_mdns_service_info(&identity, listen_port_val).ok();
        let service_fullname = StdMutex::new(
            service_info
                .as_ref()
                .map(|info| info.get_fullname().to_string())
                .unwrap_or_default(),
        );
        let mut mdns: Option<ServiceDaemon> = None;
        let mut browse_rx: Option<mdns_sd::Receiver<ServiceEvent>> = None;
        match ServiceDaemon::new() {
            Ok(daemon) => {
                // Enable IPv4 loopback alongside LAN interfaces so multi-instance testing on one host works.
                if let Err(err) = daemon.enable_interface(vec![IfKind::IPv4, IfKind::LoopbackV4]) {
                    warn!(%err, "mDNS enable_interface failed (continuing without LAN multicast)");
                }
                if let Err(err) = daemon.set_multicast_loop_v4(true) {
                    warn!(%err, "mDNS set_multicast_loop_v4 failed");
                }
                if let Some(info) = service_info {
                    if let Err(err) = daemon.register(info) {
                        warn!(%err, "mDNS service registration failed (continuing without LAN multicast)");
                    }
                }
                match daemon.browse(MDNS_SERVICE_TYPE) {
                    Ok(rx) => browse_rx = Some(rx),
                    Err(err) => {
                        warn!(%err, "mDNS browse failed (continuing without LAN multicast)");
                    }
                }
                mdns = Some(daemon);
            }
            Err(err) => {
                warn!(%err, "Failed to start mDNS daemon (continuing without LAN multicast)");
            }
        }

        // Task 1: Listen for incoming QUIC connections (Hello / Ping / Offer / PairRequest / Control)
        let (accept_shutdown_tx, accept_shutdown_rx) = watch::channel(false);
        let accept_handle = {
            let ep = endpoint.clone();
            let shared_ep = Arc::clone(&shared_endpoint);
            let id = identity.clone();
            let table = Arc::clone(&peer_table);
            let tx = event_tx.clone();
            let transfer = transfer_engine.clone();
            let trust = trust_store.clone();
            let ctrl = control_channels.clone();
            let pair_wan = Arc::clone(&pairing_wan_expires_at);
            tokio::spawn(async move {
                accept_loop(
                    ep,
                    shared_ep,
                    id,
                    listen_port_val,
                    table,
                    tx,
                    transfer,
                    trust,
                    ctrl,
                    pair_wan,
                    accept_shutdown_rx,
                )
                .await;
            })
        };
        let accept_task = Arc::new(StdMutex::new(Some(accept_handle)));
        let accept_shutdown_tx = StdMutex::new(accept_shutdown_tx);
        let (probe_reset_tx, probe_reset_rx) = watch::channel(0u64);

        let mut tasks = Vec::new();

        // Task 2: Browse mDNS events and update peer table + broadcast channel
        if let Some(browse_rx) = browse_rx {
            let ep = Arc::clone(&shared_endpoint);
            let local_node_id = identity.node_id;
            let table = Arc::clone(&peer_table);
            let tx = event_tx.clone();
            tasks.push(tokio::spawn(async move {
                mdns_browse_loop(browse_rx, local_node_id, ep, table, tx).await;
            }));
        }

        // Task 3: Fast-path direct dial probe of cached peers + periodic fallback when mDNS drops
        {
            let ep = Arc::clone(&shared_endpoint);
            let id = identity.clone();
            let port_ref = Arc::clone(&listen_port);
            let table = Arc::clone(&peer_table);
            let tx = event_tx.clone();
            tasks.push(tokio::spawn(async move {
                probe_cached_peers_loop(ep, id, port_ref, table, tx, probe_reset_rx).await;
            }));
        }

        Ok(Self {
            identity,
            endpoint: shared_endpoint,
            listen_port,
            mdns,
            service_fullname,
            peer_table,
            event_tx,
            transfer_engine,
            trust_store,
            control_channels,
            wan_enabled,
            pairing_wan_expires_at,
            reconfigure_lock: Mutex::new(()),
            accept_task,
            accept_shutdown_tx,
            online_init_task,
            probe_reset_tx,
            tasks,
        })
    }

    /// Subscribes to `PeerEvent::Discovered` and `PeerEvent::Lost` notifications.
    pub fn subscribe(&self) -> broadcast::Receiver<PeerEvent> {
        self.event_tx.subscribe()
    }

    /// Returns a clone of the currently active `iroh::Endpoint` without waiting.
    pub fn try_endpoint(&self) -> Option<Endpoint> {
        self.endpoint.read().expect("endpoint rwlock").clone()
    }

    /// Async-safe wait for the currently active `iroh::Endpoint` during WAN transitions.
    pub async fn acquire_endpoint(&self) -> Endpoint {
        for _ in 0..300 {
            if let Some(ep) = self.endpoint.read().expect("endpoint rwlock").clone() {
                return ep;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.endpoint
            .read()
            .expect("endpoint rwlock")
            .clone()
            .expect("endpoint should be initialized outside WAN reconfiguration")
    }

    /// Returns `true` when the attached `TransferEngine` has active, paused, or pending transfers.
    pub async fn has_in_flight_transfers(&self) -> bool {
        match &self.transfer_engine {
            Some(tr) => tr.has_in_flight_transfers().await,
            None => false,
        }
    }

    /// Returns a clone of the currently active `iroh::Endpoint` (waiting briefly if a WAN swap is in progress).
    pub fn endpoint(&self) -> Endpoint {
        for _ in 0..80 {
            if let Some(ep) = self.endpoint.read().expect("endpoint rwlock").clone() {
                return ep;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.endpoint
            .read()
            .expect("endpoint rwlock")
            .clone()
            .expect("endpoint should be initialized outside WAN reconfiguration")
    }

    /// Returns the shared `Endpoint` lock handle used across discovery and transfer engines.
    pub fn shared_endpoint(&self) -> Arc<StdRwLock<Option<Endpoint>>> {
        Arc::clone(&self.endpoint)
    }

    /// Returns whether global Pkarr/DNS discovery and Iroh relay transport are currently enabled.
    pub fn is_wan_transport_enabled(&self) -> bool {
        self.wan_enabled.load(Ordering::Acquire)
    }

    /// Updates the temporary pairing WAN window expiration (Unix seconds; `0` clears it).
    pub fn set_pairing_wan_expires_at(&self, expires_at_unix: u64) {
        self.pairing_wan_expires_at
            .store(expires_at_unix, Ordering::Release);
    }

    /// Returns `true` while a temporary 5-minute QR/invite pairing WAN window is active.
    pub fn is_pairing_wan_active(&self) -> bool {
        let exp = self.pairing_wan_expires_at.load(Ordering::Acquire);
        exp > (now_unix_ms() / 1000)
    }

    /// Returns `true` if WAN transport should be active (either a contact has `allow_wan` or a pairing window is active).
    pub async fn desired_wan_state(&self) -> bool {
        let contact_wan = match &self.trust_store {
            Some(store) => store.any_wan_enabled().await,
            None => false,
        };
        contact_wan || self.is_pairing_wan_active()
    }

    /// Reconfigures the underlying `iroh::Endpoint` to enable (`RelayMode::Default` + `discovery_n0`)
    /// or completely disable (`RelayMode::Disabled` + `clear_discovery`) global discovery and relay.
    pub async fn reconfigure_wan_transport(&self, enabled: bool) -> Result<(), DiscoveryError> {
        let _guard = self.reconfigure_lock.lock().await;
        if self.wan_enabled.load(Ordering::Acquire) == enabled {
            return Ok(());
        }

        let known_nodes = self.peer_table.read().await.cached_node_addrs();
        let current_port = self.listen_port.load(Ordering::Relaxed);

        let prev_online = { self.online_init_task.lock().expect("online_init mutex").take() };
        if let Some(handle) = prev_online {
            handle.abort();
            let _ = handle.await;
        }

        if let Ok(tx) = self.accept_shutdown_tx.lock() {
            let _ = tx.send(true);
        }
        let prev_accept = { self.accept_task.lock().expect("accept_task mutex").take() };
        if let Some(handle) = prev_accept {
            handle.abort();
            let _ = handle.await;
        }

        // Remove the shared Endpoint first and cancel any in-flight cached-peer probes so no
        // background task keeps cloning `old_ep` while we tear down the UDP socket.
        let prev_ep = { self.endpoint.write().expect("endpoint rwlock").take() };
        let next_gen = self.probe_reset_tx.borrow().wrapping_add(1);
        let _ = self.probe_reset_tx.send(next_gen);
        tokio::task::yield_now().await;

        if let Some(old_ep) = prev_ep {
            let ep_for_close = old_ep.clone();
            let mut close_handle = tokio::spawn(async move {
                ep_for_close.close().await;
            });
            let closed_cleanly = tokio::select! {
                _ = &mut close_handle => true,
                _ = tokio::time::sleep(Duration::from_secs(18)) => false,
            };
            if !closed_cleanly {
                warn!(
                    port = current_port,
                    "Previous iroh Endpoint close timed out during WAN transport switch; continuing rebind"
                );
            }
            drop(old_ep);
            if closed_cleanly {
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        let mut bound_ep = None;
        for attempt in 0..4 {
            if let Ok(ep) = build_iroh_endpoint_with_wan(
                &self.identity,
                current_port,
                known_nodes.clone(),
                enabled,
            )
            .await
            {
                let got_port = ep.bound_sockets().0.port();
                if current_port == 0 || got_port == current_port || attempt == 3 {
                    bound_ep = Some(ep);
                    break;
                }
                let _ = tokio::time::timeout(Duration::from_millis(500), ep.close()).await;
                drop(ep);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let new_ep = match bound_ep {
            Some(ep) => ep,
            None => {
                build_iroh_endpoint_with_wan(&self.identity, 0, known_nodes, enabled).await?
            }
        };

        let new_port = new_ep.bound_sockets().0.port();
        self.listen_port.store(new_port, Ordering::Relaxed);
        if new_port != current_port {
            warn!(
                old_port = current_port,
                new_port,
                "BeamDrop QUIC port changed during WAN endpoint reconfiguration; refreshing mDNS"
            );
            if let Some(ref mdns) = self.mdns {
                let old_name = { self.service_fullname.lock().expect("fullname mutex").clone() };
                if !old_name.is_empty() {
                    if let Ok(rx) = mdns.unregister(&old_name) {
                        let _ = tokio::time::timeout(Duration::from_millis(150), rx.recv_async()).await;
                    }
                }
                if let Ok(info) = build_mdns_service_info(&self.identity, new_port) {
                    *self.service_fullname.lock().expect("fullname mutex") =
                        info.get_fullname().to_string();
                    if let Err(err) = mdns.register(info) {
                        warn!(%err, "mDNS re-registration after port change failed");
                    }
                }
            }
        }
        *self.endpoint.write().expect("endpoint rwlock") = Some(new_ep.clone());

        let (new_shutdown_tx, accept_shutdown_rx) = watch::channel(false);
        *self
            .accept_shutdown_tx
            .lock()
            .expect("accept_shutdown mutex") = new_shutdown_tx;

        let new_accept = {
            let accept_ep = new_ep.clone();
            let shared_ep = Arc::clone(&self.endpoint);
            let id = self.identity.clone();
            let table = Arc::clone(&self.peer_table);
            let tx = self.event_tx.clone();
            let transfer = self.transfer_engine.clone();
            let trust = self.trust_store.clone();
            let ctrl = self.control_channels.clone();
            let pair_wan = Arc::clone(&self.pairing_wan_expires_at);
            tokio::spawn(async move {
                accept_loop(
                    accept_ep,
                    shared_ep,
                    id,
                    new_port,
                    table,
                    tx,
                    transfer,
                    trust,
                    ctrl,
                    pair_wan,
                    accept_shutdown_rx,
                )
                .await;
            })
        };
        *self.accept_task.lock().expect("accept_task mutex") = Some(new_accept);
        self.wan_enabled.store(enabled, Ordering::Release);
        if enabled {
            let _ = tokio::time::timeout(
                Duration::from_secs(3),
                new_ep.home_relay().initialized(),
            )
            .await;
        }
        Ok(())
    }

    /// Returns the local listening UDP/QUIC port.
    pub fn listen_port(&self) -> u16 {
        self.listen_port.load(Ordering::Relaxed)
    }

    /// Returns a handle to the shared `PeerTable`.
    pub fn peer_table(&self) -> Arc<RwLock<PeerTable>> {
        Arc::clone(&self.peer_table)
    }

    /// Returns a snapshot of all currently online peers.
    pub async fn online_peers(&self) -> Vec<PeerInfo> {
        self.peer_table.read().await.online_peers()
    }

    /// Returns a snapshot of all known peers (online and disk-cached).
    pub async fn known_peers(&self) -> Vec<PeerInfo> {
        self.peer_table.read().await.all_peers()
    }

    /// Triggers an immediate direct QUIC probe across all cached peers (useful when Android
    /// drops mDNS multicast or after app foregrounding).
    pub async fn probe_cached_peers_now(&self) {
        let ep = self.acquire_endpoint().await;
        probe_peers_once(
            &ep,
            &self.identity,
            self.listen_port(),
            &self.peer_table,
            &self.event_tx,
            false,
            Duration::from_millis(1200),
        )
        .await;
    }

    /// Dials a known peer strictly LAN-first: cached local `SocketAddr`s (refreshed by mDNS) are
    /// tried with a fast [`LAN_DIAL_TIMEOUT`]; only if that fails AND `allow_wan == true` on the
    /// contact does it fall back to global Iroh discovery + relay via `NodeAddr::new(node_id)`.
    pub async fn dial_peer(
        &self,
        endpoint: &Endpoint,
        node_id: NodeId,
    ) -> Result<Connection, DiscoveryError> {
        let (conn, _connected_via_lan) = self.dial_peer_with_path(endpoint, node_id).await?;
        Ok(conn)
    }

    /// Dials a known peer strictly LAN-first and returns `(conn, connected_via_lan)`.
    /// When relay fallback is taken (`!connected_via_lan`), any stale online LAN state is cleared.
    pub async fn dial_peer_with_path(
        &self,
        endpoint: &Endpoint,
        node_id: NodeId,
    ) -> Result<(Connection, bool), DiscoveryError> {
        let lan_addrs: Vec<SocketAddr> = {
            let table = self.peer_table.read().await;
            table.node_addrs_for(&node_id)
        };
        let wan_allowed = match &self.trust_store {
            Some(store) => store.wan_secret_if_allowed(&node_id).await.is_some(),
            None => false,
        };

        let (conn, connected_via_lan) =
            connect_lan_first(endpoint, node_id, &lan_addrs, wan_allowed).await?;

        if connected_via_lan {
            let mut table = self.peer_table.write().await;
            if let Some(mut refreshed) = table.get(&node_id).cloned() {
                refreshed.online = true;
                refreshed.last_seen_unix_ms = now_unix_ms();
                if let Ok((saved, should_notify)) = table.upsert(refreshed, None) {
                    if should_notify {
                        let _ = self.event_tx.send(PeerEvent::Discovered(saved));
                    }
                }
            }
        } else {
            let lost_snapshot = {
                let mut table = self.peer_table.write().await;
                let was_online = table.get(&node_id).is_some_and(|p| p.online);
                was_online.then(|| table.mark_lost(&node_id)).flatten()
            };
            if let Some(lost) = lost_snapshot {
                let _ = self.event_tx.send(PeerEvent::Lost(lost));
            }
        }

        Ok((conn, connected_via_lan))
    }

    /// Dials a peer by explicit `NodeId` and `SocketAddr`, exchanging `Hello` frames
    /// and caching the peer in `known_peers.json`.
    pub async fn dial_addr(
        &self,
        endpoint: &Endpoint,
        node_id: NodeId,
        addr: SocketAddr,
    ) -> Result<PeerInfo, DiscoveryError> {
        let node_addr = NodeAddr::from_parts(node_id, None, vec![addr]);
        endpoint
            .add_node_addr(node_addr.clone())
            .map_err(DiscoveryError::Iroh)?;
        let conn = tokio::time::timeout(
            LAN_ONLY_DIAL_TIMEOUT,
            endpoint.connect(node_addr, BEAMDROP_ALPN),
        )
        .await
        .map_err(|_| {
            DiscoveryError::Iroh(anyhow::anyhow!(
                "Explicit LAN dial to {addr} timed out after {LAN_ONLY_DIAL_TIMEOUT:?}"
            ))
        })?
        .map_err(DiscoveryError::Iroh)?;

        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| DiscoveryError::Iroh(anyhow::Error::from(e)))?;

        let hello = Message::Hello(HelloPayload {
            protocol_version: PROTOCOL_VERSION,
            device_id: self.identity.device_id,
            node_id: self.identity.node_id,
            display_name: self.identity.hostname.clone(),
            os_type: self.identity.os_type,
            listen_port: self.listen_port(),
        });
        write_frame(&mut send, &hello).await?;
        let _ = send.finish();

        let reply = read_frame(&mut recv).await?;
        conn.close(0u32.into(), b"hello");
        match reply {
            Message::Hello(remote) => {
                let peer_addr = SocketAddr::new(addr.ip(), remote.listen_port);
                let is_real_lan = !is_iroh_mapped_ip(&peer_addr.ip()) && is_local_lan_ip(&peer_addr.ip());
                let info = PeerInfo {
                    node_id: remote.node_id,
                    display_name: remote.display_name,
                    os_type: remote.os_type,
                    addr: is_real_lan.then_some(peer_addr),
                    port: remote.listen_port,
                    is_lan: is_real_lan,
                    online: is_real_lan,
                    last_seen_unix_ms: now_unix_ms(),
                };
                if is_real_lan {
                    let mut table = self.peer_table.write().await;
                    let (saved, should_notify) = table.upsert(info, None)?;
                    if should_notify {
                        let _ = self.event_tx.send(PeerEvent::Discovered(saved.clone()));
                    }
                    Ok(saved)
                } else {
                    Ok(info)
                }
            }
            other => Err(DiscoveryError::Iroh(anyhow::anyhow!(
                "Unexpected handshake response: {:?}",
                other.message_type()
            ))),
        }
    }

    /// Records a remote peer in `known_peers.json` after pairing (preserving online status when LAN).
    /// When `addr` is `None` (WAN-paired peer), does NOT write any synthetic address into `known_peers.json`
    /// and returns a WAN `PeerInfo` (`is_lan = false`, `addr = None`).
    pub async fn record_paired_peer(
        &self,
        endpoint: &Endpoint,
        node_id: NodeId,
        display_name: String,
        os_type: OsType,
        addr: Option<SocketAddr>,
    ) -> Result<PeerInfo, DiscoveryError> {
        let valid_lan_addr = addr.filter(|a| !is_iroh_mapped_ip(&a.ip()) && is_local_lan_ip(&a.ip()));
        let info = PeerInfo {
            node_id,
            display_name,
            os_type,
            addr: valid_lan_addr,
            port: valid_lan_addr.map(|a| a.port()).unwrap_or(0),
            is_lan: valid_lan_addr.is_some(),
            online: valid_lan_addr.is_some(),
            last_seen_unix_ms: now_unix_ms(),
        };
        if info.is_lan {
            let _ = endpoint.add_node_addr(info.to_node_addr());
            let mut table = self.peer_table.write().await;
            let (saved, _) = table.upsert(info, None)?;
            Ok(saved)
        } else {
            let mut table = self.peer_table.write().await;
            table.remove_offline_peer(&node_id);
            Ok(info)
        }
    }

    /// Gracefully unregisters the mDNS service and stops background tasks.
    pub async fn shutdown(mut self) {
        if let Some(ref mdns) = self.mdns {
            let fullname = { self.service_fullname.lock().expect("fullname mutex").clone() };
            if !fullname.is_empty() {
                if let Ok(rx) = mdns.unregister(&fullname) {
                    let _ = tokio::time::timeout(Duration::from_millis(250), rx.recv_async()).await;
                }
            }
        }
        let prev_online = { self.online_init_task.lock().expect("online_init mutex").take() };
        if let Some(handle) = prev_online {
            handle.abort();
        }
        if let Ok(tx) = self.accept_shutdown_tx.lock() {
            let _ = tx.send(true);
        }
        let prev_accept = { self.accept_task.lock().expect("accept_task mutex").take() };
        if let Some(handle) = prev_accept {
            handle.abort();
        }
        for handle in self.tasks.drain(..) {
            handle.abort();
        }
        if let Some(mdns) = self.mdns.take() {
            let _ = mdns.shutdown();
        }
    }
}

impl Drop for DiscoveryEngine {
    fn drop(&mut self) {
        if let Ok(tx) = self.accept_shutdown_tx.lock() {
            let _ = tx.send(true);
        }
        if let Ok(mut guard) = self.online_init_task.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        if let Ok(mut guard) = self.accept_task.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
        for handle in &self.tasks {
            handle.abort();
        }
    }
}

async fn mdns_browse_loop(
    browse_rx: mdns_sd::Receiver<ServiceEvent>,
    local_node_id: NodeId,
    endpoint: Arc<StdRwLock<Option<Endpoint>>>,
    peer_table: Arc<RwLock<PeerTable>>,
    event_tx: broadcast::Sender<PeerEvent>,
) {
    while let Ok(event) = browse_rx.recv_async().await {
        match event {
            ServiceEvent::ServiceResolved(info) => {
                if let Some((peer, sorted_addrs)) = parse_resolved_service_with_addrs(&info, local_node_id) {
                    trace!(
                        node_id = %peer.node_id,
                        name = %peer.display_name,
                        addr = ?peer.addr,
                        "mDNS resolved BeamDrop peer"
                    );
                    let maybe_ep = { endpoint.read().expect("endpoint rwlock").clone() };
                    if let Some(ep) = maybe_ep {
                        let _ = ep.add_node_addr(NodeAddr::from_parts(
                            peer.node_id,
                            None,
                            sorted_addrs.clone(),
                        ));
                    }
                    let mut table = peer_table.write().await;
                    table.set_extra_addrs(peer.node_id, sorted_addrs);
                    if let Ok((saved, should_notify)) = table.upsert(peer, Some(info.get_fullname()))
                    {
                        if should_notify {
                            let _ = event_tx.send(PeerEvent::Discovered(saved));
                        }
                    }
                }
            }
            ServiceEvent::ServiceRemoved(_service_type, fullname) => {
                let mut table = peer_table.write().await;
                if let Some(lost_peer) = table.mark_lost_by_fullname(&fullname) {
                    debug!(
                        node_id = %lost_peer.node_id,
                        name = %lost_peer.display_name,
                        "mDNS peer removed"
                    );
                    let _ = event_tx.send(PeerEvent::Lost(lost_peer));
                }
            }
            _ => {}
        }
    }
}

#[allow(dead_code)]
fn parse_resolved_service(info: &ServiceInfo, local_node_id: NodeId) -> Option<PeerInfo> {
    parse_resolved_service_with_addrs(info, local_node_id).map(|(peer, _)| peer)
}

fn parse_resolved_service_with_addrs(
    info: &ServiceInfo,
    local_node_id: NodeId,
) -> Option<(PeerInfo, Vec<SocketAddr>)> {
    let node_id_str = info.get_property_val_str("node_id")?;
    let node_id = NodeId::from_str(node_id_str).ok()?;
    if node_id == local_node_id {
        return None;
    }

    let display_name = info
        .get_property_val_str("display_name")
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| info.get_hostname().trim_end_matches('.').to_string());

    let os_type = info
        .get_property_val_str("os")
        .and_then(|s| OsType::from_str(s).ok())
        .unwrap_or(OsType::MacOS);

    let port = info
        .get_property_val_str("port")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or_else(|| info.get_port());

    let sorted_ips = sort_ip_addrs(
        info.get_addresses()
            .iter()
            .copied()
            .filter(|ip| !is_iroh_mapped_ip(ip) && is_lan_ip(*ip)),
    );
    let primary_ip = select_best_ip(
        &info
            .get_addresses()
            .iter()
            .copied()
            .filter(|ip| !is_iroh_mapped_ip(ip) && is_lan_ip(*ip))
            .collect(),
    )?;
    let addr = SocketAddr::new(primary_ip, port);
    let sorted_addrs: Vec<SocketAddr> = sorted_ips
        .into_iter()
        .filter(|ip| !is_link_local_v6(ip) && !is_iroh_mapped_ip(ip))
        .map(|ip| SocketAddr::new(ip, port))
        .collect();

    Some((
        PeerInfo {
            node_id,
            display_name,
            os_type,
            addr: Some(addr),
            port,
            is_lan: true,
            online: true,
            last_seen_unix_ms: now_unix_ms(),
        },
        sorted_addrs,
    ))
}

fn is_link_local_v6(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => v6.is_unicast_link_local(),
        IpAddr::V4(_) => false,
    }
}

fn ip_sort_priority(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(v4) if v4.is_unspecified() => 6,
        IpAddr::V4(v4) if v4.is_private() || v4.is_link_local() => 0,
        IpAddr::V4(v4) if !v4.is_loopback() => 1,
        IpAddr::V4(_) => 2, // loopback v4
        IpAddr::V6(v6) if v6.is_unspecified() => 6,
        IpAddr::V6(v6) if v6.is_unique_local() => 3, // fd00::/8 / fc00::/7 after IPv4
        IpAddr::V6(v6) if !v6.is_unicast_link_local() => 4,
        IpAddr::V6(_) => 5, // fe80::/10 link-local last
    }
}

/// Sorts IP addresses deterministically so IPv4 is always chosen before IPv6 ULA (`fd00::/8`)
/// and link-local (`fe80::/10`).
pub fn sort_ip_addrs<I>(addrs: I) -> Vec<IpAddr>
where
    I: IntoIterator<Item = IpAddr>,
{
    let mut list: Vec<IpAddr> = addrs
        .into_iter()
        .filter(|ip| !ip.is_unspecified())
        .collect();
    list.sort_by(|a, b| ip_sort_priority(a).cmp(&ip_sort_priority(b)).then_with(|| a.cmp(b)));
    list.dedup();
    list
}

/// Sorts socket addresses IPv4-first before IPv6 ULA / link-local addresses.
pub fn sort_socket_addrs(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut list = addrs.to_vec();
    list.sort_by(|a, b| {
        ip_sort_priority(&a.ip())
            .cmp(&ip_sort_priority(&b.ip()))
            .then_with(|| a.cmp(b))
    });
    list.dedup();
    list
}

fn select_best_ip(addrs: &std::collections::HashSet<IpAddr>) -> Option<IpAddr> {
    sort_ip_addrs(addrs.iter().copied())
        .into_iter()
        .find(|ip| !is_link_local_v6(ip))
}

async fn probe_cached_peers_loop(
    endpoint: Arc<StdRwLock<Option<Endpoint>>>,
    identity: DeviceIdentity,
    listen_port: Arc<AtomicU16>,
    peer_table: Arc<RwLock<PeerTable>>,
    event_tx: broadcast::Sender<PeerEvent>,
    mut reset_rx: watch::Receiver<u64>,
) {
    // Immediate fast probe on startup for <50ms cached peer discovery
    let initial_ep = { endpoint.read().expect("endpoint rwlock").clone() };
    if let Some(ep) = initial_ep {
        let port = listen_port.load(Ordering::Relaxed);
        tokio::select! {
            _ = reset_rx.changed() => {}
            _ = probe_peers_once(
                &ep,
                &identity,
                port,
                &peer_table,
                &event_tx,
                false,
                Duration::from_millis(800),
            ) => {}
        }
        drop(ep);
    }

    // Periodic fallback every 5s for offline/stale peers when mDNS multicast is dropped
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = reset_rx.changed() => {}
            _ = ticker.tick() => {
                let current_ep = { endpoint.read().expect("endpoint rwlock").clone() };
                if let Some(ep) = current_ep {
                    let port = listen_port.load(Ordering::Relaxed);
                    tokio::select! {
                        _ = reset_rx.changed() => {}
                        _ = probe_peers_once(
                            &ep,
                            &identity,
                            port,
                            &peer_table,
                            &event_tx,
                            true,
                            Duration::from_millis(1200),
                        ) => {}
                    }
                    drop(ep);
                }
            }
        }
    }
}

async fn probe_peers_once(
    endpoint: &Endpoint,
    identity: &DeviceIdentity,
    listen_port: u16,
    peer_table: &Arc<RwLock<PeerTable>>,
    event_tx: &broadcast::Sender<PeerEvent>,
    only_offline_or_stale: bool,
    timeout: Duration,
) {
    let cached = {
        let table = peer_table.read().await;
        table.all_peers()
    };

    let now_ms = now_unix_ms();
    let mut handles: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    for peer in cached {
        if peer.node_id == identity.node_id {
            continue;
        }
        if only_offline_or_stale
            && peer.online
            && now_ms.saturating_sub(peer.last_seen_unix_ms) < 15_000
        {
            continue;
        }
        let ep = endpoint.clone();
        let id = identity.clone();
        let table = Arc::clone(peer_table);
        let tx = event_tx.clone();
        handles.spawn(async move {
            let probe_fut = async {
                let node_addr = peer.to_node_addr();
                let _ = ep.add_node_addr(node_addr.clone());
                let conn = ep.connect(node_addr, BEAMDROP_ALPN).await?;
                let (mut send, mut recv) = conn.open_bi().await?;
                let hello = Message::Hello(HelloPayload {
                    protocol_version: PROTOCOL_VERSION,
                    device_id: id.device_id,
                    node_id: id.node_id,
                    display_name: id.hostname.clone(),
                    os_type: id.os_type,
                    listen_port,
                });
                write_frame(&mut send, &hello).await?;
                let _ = send.finish();
                let resp = read_frame(&mut recv).await?;
                conn.close(0u32.into(), b"probe");
                anyhow::Ok(resp)
            };

            if let Ok(Ok(Message::Hello(remote))) = tokio::time::timeout(timeout, probe_fut).await {
                let updated_addr = peer.addr.and_then(|prev| {
                    let cand = SocketAddr::new(prev.ip(), remote.listen_port);
                    (!is_iroh_mapped_ip(&cand.ip()) && is_local_lan_ip(&cand.ip())).then_some(cand)
                });
                let Some(real_addr) = updated_addr else {
                    return;
                };
                let updated = PeerInfo {
                    node_id: remote.node_id,
                    display_name: remote.display_name,
                    os_type: remote.os_type,
                    addr: Some(real_addr),
                    port: remote.listen_port,
                    is_lan: true,
                    online: true,
                    last_seen_unix_ms: now_unix_ms(),
                };
                let mut guard = table.write().await;
                if let Ok((saved, should_notify)) = guard.upsert(updated, None) {
                    if should_notify {
                        let _ = tx.send(PeerEvent::Discovered(saved));
                    }
                }
            }
        });
    }

    while handles.join_next().await.is_some() {}
}

async fn wait_accept_shutdown(rx: &mut watch::Receiver<bool>) {
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            break;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    endpoint: Endpoint,
    shared_endpoint: Arc<StdRwLock<Option<Endpoint>>>,
    identity: DeviceIdentity,
    listen_port: u16,
    peer_table: Arc<RwLock<PeerTable>>,
    event_tx: broadcast::Sender<PeerEvent>,
    transfer_engine: Option<Arc<TransferEngine>>,
    trust_store: Option<Arc<TrustStore>>,
    control_channels: Option<ControlChannels>,
    pairing_wan_expires_at: Arc<AtomicU64>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        let incoming = tokio::select! {
            biased;
            _ = wait_accept_shutdown(&mut shutdown_rx) => break,
            accepted = endpoint.accept() => match accepted {
                Some(inc) => inc,
                None => break,
            }
        };
        let remote_addr = incoming.remote_address();
        let remote_ip = remote_addr.ip();
        let id = identity.clone();
        let table = Arc::clone(&peer_table);
        let tx = event_tx.clone();
        let shared_ep = Arc::clone(&shared_endpoint);
        let transfer = transfer_engine.clone();
        let trust_store = trust_store.clone();
        let ctrl_ch = control_channels.clone();
        let pair_wan = Arc::clone(&pairing_wan_expires_at);
        let mut conn_shutdown = shutdown_rx.clone();

        tokio::spawn(async move {
            let connecting = match incoming.accept() {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to accept incoming connection: {e}");
                    return;
                }
            };
            let conn = tokio::select! {
                biased;
                _ = wait_accept_shutdown(&mut conn_shutdown) => return,
                res = connecting => match res {
                    Ok(c) => c,
                    Err(e) => {
                        debug!("Incoming QUIC handshake failed: {e}");
                        return;
                    }
                }
            };

            let mut uni_started = false;

            loop {
                let (mut send, mut recv) = tokio::select! {
                    biased;
                    _ = wait_accept_shutdown(&mut conn_shutdown) => {
                        conn.close(0u32.into(), b"reconfigure");
                        break;
                    }
                    res = conn.accept_bi() => match res {
                        Ok(pair) => pair,
                        Err(_) => break,
                    }
                };
                let frame = match read_frame(&mut recv).await {
                    Ok(f) => f,
                    Err(_) => break,
                };

                match frame {
                    Message::Hello(remote) => {
                        let ep_snapshot = shared_ep.read().expect("endpoint rwlock").clone();
                        let hello_is_lan = is_connection_lan_with_table(
                            ep_snapshot.as_ref(),
                            Some(&conn),
                            Some(&table),
                            remote.node_id,
                        )
                        .await;
                        let resolved_lan_addr = if hello_is_lan {
                            resolve_real_lan_addr(
                                &shared_ep,
                                &table,
                                remote_ip,
                                remote.node_id,
                                remote.listen_port,
                            )
                            .await
                        } else {
                            None
                        };
                        if let Some(peer_addr) = resolved_lan_addr {
                            let info = PeerInfo {
                                node_id: remote.node_id,
                                display_name: remote.display_name,
                                os_type: remote.os_type,
                                addr: Some(peer_addr),
                                port: remote.listen_port,
                                is_lan: true,
                                online: true,
                                last_seen_unix_ms: now_unix_ms(),
                            };
                            let node_addr = info.to_node_addr();
                            if let Some(ep) = ep_snapshot.as_ref() {
                                let _ = ep.add_node_addr(node_addr);
                            }
                            let mut guard = table.write().await;
                            if let Ok((saved, should_notify)) = guard.upsert(info, None) {
                                if should_notify {
                                    let _ = tx.send(PeerEvent::Discovered(saved));
                                }
                            }
                        }

                        let reply = Message::Hello(HelloPayload {
                            protocol_version: PROTOCOL_VERSION,
                            device_id: id.device_id,
                            node_id: id.node_id,
                            display_name: id.hostname.clone(),
                            os_type: id.os_type,
                            listen_port,
                        });
                        let _ = write_frame(&mut send, &reply).await;
                        let _ = send.finish();
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_millis(300)) => {}
                            _ = conn.closed() => {}
                            _ = wait_accept_shutdown(&mut conn_shutdown) => {}
                        }
                        conn.close(0u32.into(), b"hello-done");
                        break;
                    }
                    Message::Ping(ping) => {
                        let pong = Message::Pong(PongPayload {
                            nonce: ping.nonce,
                            timestamp_ms: now_unix_ms(),
                        });
                        let _ = write_frame(&mut send, &pong).await;
                        let _ = send.finish();
                    }
                    Message::Offer(offer) => {
                        if let Some(ref engine) = transfer {
                            if !uni_started {
                                uni_started = true;
                                engine.spawn_connection_uni_reader(conn.clone());
                            }
                            let eng = Arc::clone(engine);
                            let c = conn.clone();
                            tokio::spawn(async move {
                                eng.handle_incoming_offer(c, offer, send, recv).await;
                            });
                        } else {
                            let reject = Message::Reject(RejectPayload {
                                transfer_id: offer.transfer_id,
                                reason: Some("Incoming transfers are disabled on this node".into()),
                            });
                            let _ = write_frame(&mut send, &reject).await;
                            let _ = send.finish();
                        }
                    }
                    Message::PairRequest(req) => {
                        let auth_node_id = match conn.remote_node_id() {
                            Ok(nid) => nid,
                            Err(e) => {
                                let deny = Message::PairConfirm(PairConfirmPayload {
                                    accepted: false,
                                    responder_node_id: id.node_id,
                                    display_name: id.hostname.clone(),
                                    os_type: id.os_type,
                                    reason: Some(format!("Unauthenticated QUIC peer: {e}")),
                                });
                                let _ = write_frame(&mut send, &deny).await;
                                let _ = send.finish();
                                continue;
                            }
                        };

                        if auth_node_id != req.sender_node_id {
                            let deny = Message::PairConfirm(PairConfirmPayload {
                                accepted: false,
                                responder_node_id: id.node_id,
                                display_name: id.hostname.clone(),
                                os_type: id.os_type,
                                reason: Some(
                                    "PairRequest NodeId does not match authenticated QUIC identity"
                                        .into(),
                                ),
                            });
                            let _ = write_frame(&mut send, &deny).await;
                            let _ = send.finish();
                            continue;
                        }

                        let verify_res = match &trust_store {
                            Some(store) => {
                                match store.verify_and_consume_pairing_pin(&req.pin).await {
                                    Ok(_) => Ok(Arc::clone(store)),
                                    Err(reason) => Err(reason),
                                }
                            }
                            None => Err("Pairing is unavailable: trust store not configured".into()),
                        };

                        match verify_res {
                            Ok(store) => {
                                pair_wan.store(0, Ordering::Release);
                                let ep_snapshot = shared_ep.read().expect("endpoint rwlock").clone();
                                let paired_via_lan = is_connection_lan_with_table(
                                    ep_snapshot.as_ref(),
                                    Some(&conn),
                                    Some(&table),
                                    auth_node_id,
                                )
                                .await;
                                if let Err(err) = store
                                    .trust_peer(
                                        auth_node_id,
                                        req.display_name.clone(),
                                        req.os_type,
                                        true,
                                    )
                                    .await
                                {
                                    let deny = Message::PairConfirm(PairConfirmPayload {
                                        accepted: false,
                                        responder_node_id: id.node_id,
                                        display_name: id.hostname.clone(),
                                        os_type: id.os_type,
                                        reason: Some(format!(
                                            "Failed to save trusted peer: {err}"
                                        )),
                                    });
                                    let _ = write_frame(&mut send, &deny).await;
                                    let _ = send.finish();
                                    continue;
                                }
                                if !paired_via_lan {
                                    let _ = store.set_peer_wan_enabled(&auth_node_id, true).await;
                                }

                                let real_lan_addr = if paired_via_lan {
                                    resolve_real_lan_addr(
                                        &shared_ep,
                                        &table,
                                        remote_ip,
                                        auth_node_id,
                                        0,
                                    )
                                    .await
                                } else {
                                    None
                                };

                                let saved_peer = {
                                    let mut guard = table.write().await;
                                    let is_real_lan = paired_via_lan && real_lan_addr.is_some();
                                    let peer_port = if is_real_lan {
                                        guard
                                            .get(&auth_node_id)
                                            .map(|p| p.port)
                                            .filter(|&p| p > 0)
                                            .or_else(|| real_lan_addr.map(|a| a.port()))
                                            .unwrap_or(0)
                                    } else {
                                        0
                                    };
                                    let final_addr = real_lan_addr.filter(|_| is_real_lan).map(|a| {
                                        let port = if peer_port > 0 { peer_port } else { a.port() };
                                        SocketAddr::new(a.ip(), port)
                                    });
                                    let info = PeerInfo {
                                        node_id: auth_node_id,
                                        display_name: req.display_name,
                                        os_type: req.os_type,
                                        addr: final_addr,
                                        port: peer_port,
                                        is_lan: is_real_lan,
                                        online: is_real_lan,
                                        last_seen_unix_ms: now_unix_ms(),
                                    };
                                    if info.is_lan {
                                        let node_addr = info.to_node_addr();
                                        if let Some(ref ep) = ep_snapshot {
                                            let _ = ep.add_node_addr(node_addr);
                                        }
                                        match guard.upsert(info.clone(), None) {
                                            Ok((saved, _)) => saved,
                                            Err(_) => info,
                                        }
                                    } else {
                                        guard.remove_offline_peer(&auth_node_id);
                                        info
                                    }
                                };

                                let confirm = Message::PairConfirm(PairConfirmPayload {
                                    accepted: true,
                                    responder_node_id: id.node_id,
                                    display_name: id.hostname.clone(),
                                    os_type: id.os_type,
                                    reason: None,
                                });
                                let _ = write_frame(&mut send, &confirm).await;
                                let _ = send.finish();

                                let _ = tx.send(PeerEvent::Paired(saved_peer));
                                if let Some(ref ch) = ctrl_ch {
                                    let _ = ch.wan_recheck_tx.send(());
                                }
                            }
                            Err(reason) => {
                                let deny = Message::PairConfirm(PairConfirmPayload {
                                    accepted: false,
                                    responder_node_id: id.node_id,
                                    display_name: id.hostname.clone(),
                                    os_type: id.os_type,
                                    reason: Some(reason),
                                });
                                let _ = write_frame(&mut send, &deny).await;
                                let _ = send.finish();
                            }
                        }
                    }
                    Message::Pause(ctrl) => {
                        if let Some(ref engine) = transfer {
                            let _ = engine.handle_remote_control(Message::Pause(ctrl)).await;
                        }
                        let _ = send.finish();
                    }
                    Message::Cancel(ctrl) => {
                        let handled = if let Some(ref engine) = transfer {
                            engine
                                .handle_remote_control(Message::Cancel(ctrl.clone()))
                                .await
                        } else {
                            false
                        };
                        if !handled {
                            if let Some(ref ch) = ctrl_ch {
                                let _ = ch.cancel_tx.send((ctrl.transfer_id, ctrl.reason));
                            }
                        }
                        let _ = send.finish();
                    }
                    Message::Resume(req) => {
                        let requester = match conn.remote_node_id() {
                            Ok(nid) => nid,
                            Err(e) => {
                                let reject = Message::Reject(RejectPayload {
                                    transfer_id: req.transfer_id,
                                    reason: Some(format!("Unauthenticated QUIC peer: {e}")),
                                });
                                let _ = write_frame(&mut send, &reject).await;
                                let _ = send.finish();
                                continue;
                            }
                        };

                        let outcome = if let Some(ref ch) = ctrl_ch {
                            let (reply_tx, reply_rx) = oneshot::channel();
                            if ch.resume_tx.send((req.transfer_id, requester, reply_tx)).is_ok() {
                                reply_rx
                                    .await
                                    .unwrap_or_else(|_| Err("Node resume handler closed".into()))
                            } else {
                                Err("Node resume handler unavailable".into())
                            }
                        } else {
                            Err("Remote resume is not enabled on this node".into())
                        };

                        match outcome {
                            Ok(()) => {
                                let ack = Message::Resume(TransferControlPayload {
                                    transfer_id: req.transfer_id,
                                    reason: None,
                                });
                                let _ = write_frame(&mut send, &ack).await;
                            }
                            Err(reason) => {
                                let reject = Message::Reject(RejectPayload {
                                    transfer_id: req.transfer_id,
                                    reason: Some(reason),
                                });
                                let _ = write_frame(&mut send, &reject).await;
                            }
                        }
                        let _ = send.finish();
                    }
                    _ => {
                        break;
                    }
                }
            }
        });
    }
}

/// Prefix of `iroh`'s internal synthetic ULA addresses (`fd15:070a:510b::/48`,
/// used for `NodeIdMappedAddr` and `IpMappedAddr`).
const IROH_MAPPED_ADDR_PREFIX: [u8; 6] = [0xfd, 21, 7, 10, 81, 11];

/// Maximum age for treating a cached/mDNS entry in `PeerTable` as a live LAN peer
/// when classifying incoming QUIC connections before `conn_type` finishes settling.
pub const LIVE_LAN_PEER_TTL_MS: u64 = 120_000;

/// Returns `true` if `ip` is an `iroh` synthetic mapped address (`fd15:070a:510b::/48`).
pub fn is_iroh_mapped_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => v6.octets()[..6] == IROH_MAPPED_ADDR_PREFIX,
        IpAddr::V4(_) => false,
    }
}

/// Returns `true` if `ip` is strictly a real local LAN, link-local, or loopback address:
/// physical private IPv4 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`),
/// IPv4 link-local (`169.254.0.0/16`), IPv4/IPv6 loopback (`127.0.0.0/8`, `::1`),
/// IPv6 link-local (`fe80::/10`), or IPv4-mapped IPv6 whose IPv4 address satisfies those ranges.
/// Explicitly excludes `iroh` synthetic mapped `fd15:070a:510b::/48` and non-link-local IPv6 ULAs.
pub fn is_lan_ip(ip: IpAddr) -> bool {
    if is_iroh_mapped_ip(&ip) {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return mapped.is_private() || mapped.is_link_local() || mapped.is_loopback();
            }
            v6.is_loopback() || v6.is_unicast_link_local()
        }
    }
}

/// Reference wrapper around [`is_lan_ip`].
pub fn is_local_lan_ip(ip: &IpAddr) -> bool {
    is_lan_ip(*ip)
}

/// Fast local dial budget for cached LAN / mDNS addresses before falling back to WAN.
pub const LAN_DIAL_TIMEOUT: Duration = Duration::from_millis(1500);
/// Patience for LAN-only dials when no WAN fallback is permitted (slow Wi-Fi handshakes).
const LAN_ONLY_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound for global discovery + relay connection establishment.
const WAN_DIAL_TIMEOUT: Duration = Duration::from_secs(25);

/// Connects to `node_id` using only explicit `lan_addrs` within `budget`, without WAN fallback.
pub async fn dial_lan_addrs_with_timeout(
    endpoint: &Endpoint,
    node_id: NodeId,
    lan_addrs: &[SocketAddr],
    budget: Duration,
) -> Result<(Connection, bool), DiscoveryError> {
    let sorted_addrs = sort_socket_addrs(lan_addrs);
    if sorted_addrs.is_empty() {
        return Err(DiscoveryError::Iroh(anyhow::anyhow!(
            "No cached LAN address for {node_id}"
        )));
    }
    let node_addr = NodeAddr::from_parts(node_id, None, sorted_addrs);
    endpoint
        .add_node_addr(node_addr.clone())
        .map_err(DiscoveryError::Iroh)?;
    let conn = tokio::time::timeout(budget, endpoint.connect(node_addr, BEAMDROP_ALPN))
        .await
        .map_err(|_| {
            DiscoveryError::Iroh(anyhow::anyhow!("LAN dial timed out after {budget:?}"))
        })?
        .map_err(DiscoveryError::Iroh)?;
    let is_lan = is_endpoint_connection_lan(endpoint, node_id);
    Ok((conn, is_lan))
}

/// Connects to `node_id` strictly LAN-first. Cached `lan_addrs` are dialed with
/// [`LAN_DIAL_TIMEOUT`] when a WAN fallback exists (or a longer LAN-only budget otherwise);
/// on failure, and only if `wan_allowed`, dials `NodeAddr::new(node_id)` through Iroh global
/// discovery + relay. Returns the connection and whether its active path is local LAN.
pub async fn connect_lan_first(
    endpoint: &Endpoint,
    node_id: NodeId,
    lan_addrs: &[SocketAddr],
    wan_allowed: bool,
) -> Result<(Connection, bool), DiscoveryError> {
    let mut lan_failure: Option<String> = None;
    let sorted_addrs = sort_socket_addrs(lan_addrs);
    if !sorted_addrs.is_empty() {
        let node_addr = NodeAddr::from_parts(node_id, None, sorted_addrs.clone());
        endpoint
            .add_node_addr(node_addr.clone())
            .map_err(DiscoveryError::Iroh)?;
        let budget = if wan_allowed { LAN_DIAL_TIMEOUT } else { LAN_ONLY_DIAL_TIMEOUT };
        match tokio::time::timeout(budget, endpoint.connect(node_addr, BEAMDROP_ALPN)).await {
            Ok(Ok(conn)) => {
                let is_lan = is_endpoint_connection_lan(endpoint, node_id);
                return Ok((conn, is_lan));
            }
            Ok(Err(err)) => {
                lan_failure = Some(err.to_string());
            }
            Err(_) => {
                lan_failure = Some(format!("LAN dial timed out after {budget:?}"));
            }
        }
    }

    if !wan_allowed {
        let detail = lan_failure.unwrap_or_else(|| "no cached LAN address".to_string());
        return Err(DiscoveryError::Iroh(anyhow::anyhow!(
            "Peer {node_id} is not reachable on local LAN ({detail}) and long-distance transfers are disabled for this contact"
        )));
    }

    tracing::debug!(%node_id, lan_failure = ?lan_failure, "LAN dial failed; falling back to WAN discovery + relay");
    let conn = tokio::time::timeout(
        WAN_DIAL_TIMEOUT,
        endpoint.connect(NodeAddr::new(node_id), BEAMDROP_ALPN),
    )
    .await
    .map_err(|_| {
        DiscoveryError::Iroh(anyhow::anyhow!(
            "Long-distance dial to {node_id} timed out after {WAN_DIAL_TIMEOUT:?}"
        ))
    })?
    .map_err(DiscoveryError::Iroh)?;
    let is_lan = is_endpoint_connection_lan(endpoint, node_id);
    Ok((conn, is_lan))
}

/// Inspects `RemoteInfo` to determine if the active path is a verified direct local LAN address.
/// Never treats unverified candidate `DirectAddrInfo` hints or `ConnectionType::Relay` as LAN.
fn is_remote_info_lan(info: &iroh::endpoint::RemoteInfo) -> bool {
    match &info.conn_type {
        ConnectionType::Direct(addr) | ConnectionType::Mixed(addr, _) => {
            is_local_lan_ip(&addr.ip())
        }
        ConnectionType::Relay(_) => false,
        ConnectionType::None => info.addrs.iter().any(|a| {
            !is_iroh_mapped_ip(&a.addr.ip())
                && is_local_lan_ip(&a.addr.ip())
                && (a.last_payload.is_some() || a.latency.is_some())
        }),
    }
}

/// Inspects the `Endpoint`'s active or verified direct candidate paths for `remote_node_id` and
/// returns `true` when an active direct physical LAN / link-local / loopback UDP path exists.
pub fn is_endpoint_connection_lan(endpoint: &Endpoint, remote_node_id: NodeId) -> bool {
    let conn_type = endpoint
        .conn_type(remote_node_id)
        .ok()
        .and_then(|w| w.get().ok());
    match conn_type {
        Some(ConnectionType::Direct(addr) | ConnectionType::Mixed(addr, _)) => {
            return is_local_lan_ip(&addr.ip());
        }
        Some(ConnectionType::Relay(_)) => return false,
        Some(ConnectionType::None) | None => {}
    }
    endpoint
        .remote_info(remote_node_id)
        .as_ref()
        .is_some_and(is_remote_info_lan)
}

/// Returns whether the live `iroh` path to `remote_node_id` currently uses a confirmed
/// direct UDP socket (`Some(true)` -> `Direct P2P`), relay/mixed (`Some(false)` -> `Relayed`),
/// or is unknown/not established yet (`None`).
pub fn is_endpoint_connection_direct(
    endpoint: &Endpoint,
    remote_node_id: NodeId,
) -> Option<bool> {
    let conn_type = endpoint
        .conn_type(remote_node_id)
        .ok()
        .and_then(|w| w.get().ok())?;
    match conn_type {
        ConnectionType::Direct(_) => Some(true),
        ConnectionType::Relay(_) | ConnectionType::Mixed(_, _) => Some(false),
        ConnectionType::None => None,
    }
}

/// Extracts the best verified direct physical LAN `SocketAddr` known on `endpoint`
/// for `remote_node_id`, never returning `fd15:070a:510b::/48` or unverified WAN hints.
pub fn best_direct_lan_addr_from_endpoint(
    endpoint: &Endpoint,
    remote_node_id: NodeId,
) -> Option<SocketAddr> {
    if let Ok(watcher) = endpoint.conn_type(remote_node_id) {
        if let Ok(ConnectionType::Direct(addr) | ConnectionType::Mixed(addr, _)) = watcher.get() {
            if !is_iroh_mapped_ip(&addr.ip()) && is_local_lan_ip(&addr.ip()) {
                return Some(addr);
            }
        } else if let Ok(ConnectionType::Relay(_)) = watcher.get() {
            return None;
        }
    }
    let info = endpoint.remote_info(remote_node_id)?;
    if matches!(info.conn_type, ConnectionType::Relay(_)) {
        return None;
    }
    let confirmed: Vec<SocketAddr> = info
        .addrs
        .iter()
        .filter(|a| {
            !is_iroh_mapped_ip(&a.addr.ip())
                && is_local_lan_ip(&a.addr.ip())
                && (a.last_payload.is_some() || a.latency.is_some())
        })
        .map(|a| a.addr)
        .collect();
    sort_socket_addrs(&confirmed).into_iter().next()
}

/// Resolves the best genuine LAN `SocketAddr` for an incoming peer, never returning
/// an `iroh` synthetic `fd15:070a:510b::/48` address.
async fn resolve_real_lan_addr(
    shared_ep: &Arc<StdRwLock<Option<Endpoint>>>,
    peer_table: &Arc<RwLock<PeerTable>>,
    fallback_ip: IpAddr,
    node_id: NodeId,
    preferred_port: u16,
) -> Option<SocketAddr> {
    let existing = {
        let guard = peer_table.read().await;
        guard.get(&node_id).and_then(|p| {
            p.addr
                .filter(|a| !is_iroh_mapped_ip(&a.ip()) && is_local_lan_ip(&a.ip()))
                .map(|a| {
                    let port = if preferred_port > 0 {
                        preferred_port
                    } else {
                        a.port()
                    };
                    SocketAddr::new(a.ip(), port)
                })
        })
    };
    if let Some(addr) = existing {
        return Some(addr);
    }

    let ep_opt = shared_ep.read().expect("endpoint rwlock").clone();
    if let Some(ref ep) = ep_opt {
        if let Some(direct) = best_direct_lan_addr_from_endpoint(ep, node_id) {
            let port = if preferred_port > 0 {
                preferred_port
            } else {
                direct.port()
            };
            return Some(SocketAddr::new(direct.ip(), port));
        }
    }

    if !is_iroh_mapped_ip(&fallback_ip) && is_local_lan_ip(&fallback_ip) && preferred_port > 0 {
        return Some(SocketAddr::new(fallback_ip, preferred_port));
    }

    None
}

/// Shared LAN-vs-WAN classifier checked by both `DiscoveryEngine` and `TransferEngine`:
/// returns `true` ONLY when:
/// 1) `endpoint` is not actively routed over `Relay(_)` AND reports a verified direct physical
///    private IPv4 / link-local / loopback path (outside `fd15:070a:510b::/48`), OR
/// 2) `peer_table` currently holds an active, non-expired local mDNS (`_beamdrop._udp.local.`) entry
///    while the active QUIC connection is not routed via `Relay(_)`.
pub async fn is_connection_lan_with_table(
    endpoint: Option<&Endpoint>,
    conn: Option<&Connection>,
    peer_table: Option<&Arc<RwLock<PeerTable>>>,
    remote_node_id: NodeId,
) -> bool {
    let effective_node_id = conn
        .and_then(|c| c.remote_node_id().ok())
        .unwrap_or(remote_node_id);

    if let Some(ep) = endpoint {
        for candidate_id in [effective_node_id, remote_node_id] {
            if let Ok(watcher) = ep.conn_type(candidate_id) {
                if let Ok(conn_type) = watcher.get() {
                    match conn_type {
                        ConnectionType::Relay(_) => return false,
                        ConnectionType::Direct(addr) | ConnectionType::Mixed(addr, _) => {
                            return is_local_lan_ip(&addr.ip());
                        }
                        ConnectionType::None => {}
                    }
                }
            }
            if is_endpoint_connection_lan(ep, candidate_id) {
                return true;
            }
            if candidate_id == remote_node_id && effective_node_id == remote_node_id {
                break;
            }
        }
    }

    if let Some(table) = peer_table {
        let guard = table.read().await;
        if guard.has_live_lan_peer(&effective_node_id, LIVE_LAN_PEER_TTL_MS)
            || (effective_node_id != remote_node_id
                && guard.has_live_lan_peer(&remote_node_id, LIVE_LAN_PEER_TTL_MS))
        {
            return true;
        }
    }

    false
}

/// Builds a configured `iroh::Endpoint` using the persistent `DeviceIdentity` Ed25519 keypair
/// with global discovery and relay disabled (`RelayMode::Disabled`, strictly LAN-only).
pub async fn build_iroh_endpoint(
    identity: &DeviceIdentity,
    bind_port: u16,
    known_nodes: Vec<NodeAddr>,
) -> Result<Endpoint, DiscoveryError> {
    build_iroh_endpoint_with_wan(identity, bind_port, known_nodes, false).await
}

/// Builds a configured `iroh::Endpoint`, enabling global Pkarr/DNS discovery (`discovery_n0`)
/// and Iroh relays (`RelayMode::Default`) strictly when `wan_enabled` is `true`.
/// Returns `(stream_receive_window, receive_window, send_window)` QUIC flow-control windows.
///
/// Same-Wi-Fi (`wan_enabled == false`) preserves the existing low-BDP defaults untouched,
/// while Over-Internet (`wan_enabled == true`) expands windows for high-latency WAN links.
pub const fn transport_window_sizes(wan_enabled: bool) -> (u32, u32, u64) {
    if wan_enabled {
        (16 * 1024 * 1024, 32 * 1024 * 1024, 32 * 1024 * 1024)
    } else {
        (1024 * 1024, 4 * 1024 * 1024, 4 * 1024 * 1024)
    }
}

/// Builds the QUIC `TransportConfig` for LAN-only (`wan_enabled == false`) or WAN-capable endpoints.
pub fn build_transport_config(wan_enabled: bool) -> iroh::endpoint::TransportConfig {
    let (stream_recv, conn_recv, conn_send) = transport_window_sizes(wan_enabled);
    let mut transport_config = iroh::endpoint::TransportConfig::default();
    transport_config.initial_rtt(Duration::from_millis(100));
    transport_config.keep_alive_interval(Some(Duration::from_secs(3)));
    if let Ok(idle) = Duration::from_secs(15).try_into() {
        transport_config.max_idle_timeout(Some(idle));
    }
    transport_config.stream_receive_window(iroh::endpoint::VarInt::from_u32(stream_recv));
    transport_config.receive_window(iroh::endpoint::VarInt::from_u32(conn_recv));
    transport_config.send_window(conn_send);
    transport_config
}

pub async fn build_iroh_endpoint_with_wan(
    identity: &DeviceIdentity,
    bind_port: u16,
    known_nodes: Vec<NodeAddr>,
    wan_enabled: bool,
) -> Result<Endpoint, DiscoveryError> {
    let bind_v4 = std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, bind_port);
    let transport_config = build_transport_config(wan_enabled);

    let mut builder = Endpoint::builder()
        .secret_key(identity.iroh_secret_key())
        .alpns(vec![BEAMDROP_ALPN.to_vec()])
        .bind_addr_v4(bind_v4)
        .known_nodes(known_nodes)
        .transport_config(transport_config)
        .clear_discovery();

    builder = if wan_enabled {
        builder
            .relay_mode(RelayMode::Default)
            .discovery_n0()
    } else {
        builder.relay_mode(RelayMode::Disabled)
    };

    let endpoint = builder.bind().await.map_err(DiscoveryError::Iroh)?;
    Ok(endpoint)
}

/// Sends a `Ping` frame to a peer and measures the round-trip time.
pub async fn ping_peer(conn: &Connection, nonce: u64) -> Result<Duration, DiscoveryError> {
    let start = std::time::Instant::now();
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| DiscoveryError::Iroh(anyhow::Error::from(e)))?;

    let ping = Message::Ping(PingPayload {
        nonce,
        timestamp_ms: now_unix_ms(),
    });
    write_frame(&mut send, &ping).await?;
    let _ = send.finish();

    let resp = read_frame(&mut recv).await?;
    match resp {
        Message::Pong(pong) if pong.nonce == nonce => Ok(start.elapsed()),
        other => Err(DiscoveryError::Iroh(anyhow::anyhow!(
            "Expected matching Pong, received {:?}",
            other.message_type()
        ))),
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::Ipv6Addr;
    use uuid::Uuid;

    #[test]
    fn test_select_best_ip_skips_link_local_v6() {
        let mut addrs = HashSet::new();
        let link_local_v6 = IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap());
        addrs.insert(link_local_v6);
        assert_eq!(select_best_ip(&addrs), None);

        let loopback_v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        addrs.insert(loopback_v4);
        assert_eq!(select_best_ip(&addrs), Some(loopback_v4));

        let lan_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42));
        addrs.insert(lan_v4);
        assert_eq!(select_best_ip(&addrs), Some(lan_v4));
    }

    #[test]
    fn test_non_link_local_ipv6_ula_excluded_from_lan_and_sorted_after_ipv4() {
        let ula_v6: IpAddr = "fd15:2092:c433::1".parse().unwrap();
        let link_v6: IpAddr = "fe80::abcd".parse().unwrap();
        let pub_v6: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        let lan_v4: IpAddr = "192.168.1.25".parse().unwrap();

        assert!(!is_local_lan_ip(&ula_v6));
        assert!(is_local_lan_ip(&link_v6));
        assert!(!is_local_lan_ip(&pub_v6));
        assert!(is_local_lan_ip(&lan_v4));

        let sorted = sort_ip_addrs([link_v6, ula_v6, pub_v6, lan_v4]);
        assert_eq!(sorted, vec![lan_v4, ula_v6, pub_v6, link_v6]);

        let mut set = HashSet::new();
        set.insert(ula_v6);
        set.insert(lan_v4);
        assert_eq!(select_best_ip(&set), Some(lan_v4));
    }

    #[test]
    fn test_peer_table_persistence_and_lost() {
        let dir = std::env::temp_dir().join(format!("beamdrop-peer-test-{}", Uuid::new_v4()));
        let path = dir.join(KNOWN_PEERS_FILENAME);
        let peer_id = DeviceIdentity::generate().node_id;

        let mut table = PeerTable::load_or_create(&path).expect("load_or_create");
        let peer = PeerInfo {
            node_id: peer_id,
            display_name: "TestMac".to_string(),
            os_type: OsType::MacOS,
            addr: Some("192.168.1.10:4433".parse().unwrap()),
            port: 4433,
            is_lan: true,
            online: true,
            last_seen_unix_ms: 1_700_000_000_000,
        };

        let (_, notify1) = table.upsert(peer.clone(), Some("bd-test._beamdrop._udp.local.")).unwrap();
        assert!(notify1);

        let (_, notify2) = table.upsert(peer.clone(), Some("bd-test._beamdrop._udp.local.")).unwrap();
        assert!(!notify2);

        let reloaded = PeerTable::load_or_create(&path).expect("reload");
        let cached = reloaded.get(&peer_id).expect("peer cached on disk");
        assert_eq!(cached.addr, Some("192.168.1.10:4433".parse::<SocketAddr>().unwrap()));
        assert!(cached.is_lan);
        assert!(!cached.online);
        assert_eq!(reloaded.cached_node_addrs().len(), 1);

        let lost = table
            .mark_lost_by_fullname("bd-test._beamdrop._udp.local.")
            .expect("lost peer");
        assert!(!lost.online);
        assert!(table.get(&peer_id).is_some());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_is_lan_ip_excludes_iroh_mapped_ula_and_handles_v4_mapped_v6() {
        // Real LAN / link-local / loopback addresses
        assert!(is_lan_ip("192.168.1.42".parse().unwrap()));
        assert!(is_lan_ip("10.0.0.5".parse().unwrap()));
        assert!(is_lan_ip("172.16.4.8".parse().unwrap()));
        assert!(is_lan_ip("169.254.10.2".parse().unwrap()));
        assert!(is_lan_ip("127.0.0.1".parse().unwrap()));
        assert!(is_lan_ip("::1".parse().unwrap()));
        assert!(is_lan_ip("fe80::1".parse().unwrap()));
        assert!(is_lan_ip("::ffff:192.168.1.50".parse().unwrap()));
        assert!(is_lan_ip("::ffff:127.0.0.1".parse().unwrap()));

        // Public, non-link-local IPv6 ULAs, and iroh synthetic fd15:070a:510b::/48 addresses MUST return false
        assert!(!is_lan_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_lan_ip("::ffff:8.8.8.8".parse().unwrap()));
        assert!(!is_lan_ip("fd15:2092:c433::1".parse().unwrap()));
        assert!(!is_lan_ip("fd15:070a:510b:0000::1".parse().unwrap()));
        assert!(!is_lan_ip("fd15:70a:510b::1234:5678".parse().unwrap()));
        assert!(is_iroh_mapped_ip(&"fd15:70a:510b::1".parse().unwrap()));
        assert!(!is_iroh_mapped_ip(&"fd15:2092:c433::1".parse().unwrap()));
    }

    #[test]
    fn test_peer_table_ignores_and_scrubs_iroh_mapped_addrs_and_tracks_live_lan() {
        let dir = std::env::temp_dir().join(format!("beamdrop-iroh-scrub-{}", Uuid::new_v4()));
        let path = dir.join(KNOWN_PEERS_FILENAME);
        let wan_id = DeviceIdentity::generate().node_id;
        let lan_id = DeviceIdentity::generate().node_id;

        // Simulate an older persisted known_peers.json containing an fd15:070a:510b mapped entry.
        fs::create_dir_all(&dir).unwrap();
        let legacy_json = serde_json::json!({
            "peers": [
                {
                    "node_id": wan_id,
                    "display_name": "RemoteWanPeer",
                    "os_type": "Android",
                    "addr": "[fd15:070a:510b::42]:12345",
                    "port": 12345,
                    "online": true,
                    "last_seen_unix_ms": now_unix_ms()
                }
            ]
        });
        fs::write(&path, serde_json::to_string_pretty(&legacy_json).unwrap()).unwrap();

        let mut table = PeerTable::load_or_create(&path).expect("load scrubbed");
        assert!(table.get(&wan_id).is_none(), "synthetic fd15 entry must be scrubbed on load");

        let bogus_wan = PeerInfo {
            node_id: wan_id,
            display_name: "RemoteWanPeer".into(),
            os_type: OsType::Android,
            addr: Some("[fd15:70a:510b::99]:12345".parse().unwrap()),
            port: 12345,
            is_lan: false,
            online: true,
            last_seen_unix_ms: now_unix_ms(),
        };
        let (_, notified) = table.upsert(bogus_wan, None).unwrap();
        assert!(!notified);
        assert!(table.get(&wan_id).is_none());
        assert!(!table.has_live_lan_peer(&wan_id, LIVE_LAN_PEER_TTL_MS));

        let real_lan = PeerInfo {
            node_id: lan_id,
            display_name: "LocalPhone".into(),
            os_type: OsType::Android,
            addr: Some("192.168.1.88:45123".parse().unwrap()),
            port: 45123,
            is_lan: true,
            online: true,
            last_seen_unix_ms: now_unix_ms(),
        };
        let (saved_probe, _) = table.upsert(real_lan.clone(), None).unwrap();
        assert!(saved_probe.is_lan);
        assert!(
            !table.has_live_lan_peer(&lan_id, LIVE_LAN_PEER_TTL_MS),
            "non-mDNS upsert must not count as active mDNS LAN peer"
        );

        let (saved, notified_lan) = table
            .upsert(real_lan, Some("bd-localphone._beamdrop._udp.local."))
            .unwrap();
        assert!(!notified_lan);
        assert!(saved.is_lan);
        assert!(table.has_live_lan_peer(&lan_id, LIVE_LAN_PEER_TTL_MS));

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_transport_config_wan_windows() {
        assert_eq!(
            transport_window_sizes(false),
            (1024 * 1024, 4 * 1024 * 1024, 4 * 1024 * 1024)
        );
        assert_eq!(
            transport_window_sizes(true),
            (16 * 1024 * 1024, 32 * 1024 * 1024, 32 * 1024 * 1024)
        );

        let _lan_cfg = build_transport_config(false);
        let _wan_cfg = build_transport_config(true);

        let id = DeviceIdentity::generate();
        if let Ok(endpoint) = build_iroh_endpoint_with_wan(&id, 0, Vec::new(), true).await {
            assert!(is_endpoint_connection_direct(&endpoint, id.node_id()).is_none());
            endpoint.close().await;
        }
    }
}

