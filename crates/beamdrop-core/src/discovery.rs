use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iroh::endpoint::{Connection, ConnectionType};
use iroh::{Endpoint, NodeAddr, NodeId, RelayMode};
use mdns_sd::{IfKind, ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, RwLock};
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
    /// Last known local `SocketAddr` (`IP:port`) for direct QUIC dialing.
    pub addr: SocketAddr,
    /// Local listening UDP/QUIC port advertised by the peer.
    pub port: u16,
    /// Whether the peer is currently active on the local network.
    #[serde(default)]
    pub online: bool,
    /// Unix timestamp in milliseconds when the peer was last seen.
    pub last_seen_unix_ms: u64,
}

impl PeerInfo {
    /// Constructs an `iroh::NodeAddr` targeting this peer's last known local `SocketAddr`.
    pub fn to_node_addr(&self) -> NodeAddr {
        NodeAddr::from_parts(self.node_id, None, vec![self.addr])
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
    fullname_to_node: HashMap<String, NodeId>,
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
            fullname_to_node: HashMap::new(),
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
        peer: PeerInfo,
        mdns_fullname: Option<&str>,
    ) -> Result<(PeerInfo, bool), DiscoveryError> {
        if let Some(fullname) = mdns_fullname {
            self.fullname_to_node
                .insert(fullname.to_ascii_lowercase(), peer.node_id);
        }
        let should_notify = match self.peers.get(&peer.node_id) {
            Some(prev) => !prev.online || prev.addr != peer.addr,
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

    /// Returns `iroh::NodeAddr` entries for all cached peers so the local `Endpoint`
    /// can dial them directly in <50ms without waiting for mDNS or relay resolution.
    pub fn cached_node_addrs(&self) -> Vec<NodeAddr> {
        self.peers.values().map(PeerInfo::to_node_addr).collect()
    }

    /// Path to the backing `known_peers.json` file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Request from a remote peer to resume a paused transfer: `(transfer_id, requester_node_id, reply_tx)`.
pub type ResumeRequest = (Uuid, NodeId, oneshot::Sender<Result<(), String>>);

/// Channels used to forward out-of-band transfer control requests to `BeamDropNode`.
#[derive(Clone)]
pub struct ControlChannels {
    pub resume_tx: mpsc::UnboundedSender<ResumeRequest>,
    pub cancel_tx: mpsc::UnboundedSender<(Uuid, Option<String>)>,
}

/// Zero-config LAN discovery engine and fast-dial peer manager.
pub struct DiscoveryEngine {
    identity: DeviceIdentity,
    endpoint: Arc<StdRwLock<Option<Endpoint>>>,
    listen_port: Arc<AtomicU16>,
    mdns: ServiceDaemon,
    service_fullname: StdMutex<String>,
    peer_table: Arc<RwLock<PeerTable>>,
    event_tx: broadcast::Sender<PeerEvent>,
    transfer_engine: Option<Arc<TransferEngine>>,
    trust_store: Option<Arc<TrustStore>>,
    control_channels: Option<ControlChannels>,
    wan_enabled: Arc<AtomicBool>,
    reconfigure_lock: Mutex<()>,
    accept_task: Arc<StdMutex<Option<JoinHandle<()>>>>,
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

        let peer_table = Arc::new(RwLock::new(initial_table));
        let (event_tx, _) = broadcast::channel(128);

        let mdns = ServiceDaemon::new()?;
        // Enable IPv4 loopback alongside LAN interfaces so multi-instance testing on one host works.
        let _ = mdns.enable_interface(vec![IfKind::IPv4, IfKind::LoopbackV4]);
        let _ = mdns.set_multicast_loop_v4(true);

        let service_info = build_mdns_service_info(&identity, listen_port_val)?;
        let service_fullname = StdMutex::new(service_info.get_fullname().to_string());
        mdns.register(service_info)?;

        let browse_rx = mdns.browse(MDNS_SERVICE_TYPE)?;

        // Task 1: Listen for incoming QUIC connections (Hello / Ping / Offer / PairRequest / Control)
        let accept_handle = {
            let ep = endpoint.clone();
            let id = identity.clone();
            let table = Arc::clone(&peer_table);
            let tx = event_tx.clone();
            let transfer = transfer_engine.clone();
            let trust = trust_store.clone();
            let ctrl = control_channels.clone();
            tokio::spawn(async move {
                accept_loop(ep, id, listen_port_val, table, tx, transfer, trust, ctrl).await;
            })
        };
        let accept_task = Arc::new(StdMutex::new(Some(accept_handle)));

        let mut tasks = Vec::new();

        // Task 2: Browse mDNS events and update peer table + broadcast channel
        {
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
                probe_cached_peers_loop(ep, id, port_ref, table, tx).await;
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
            reconfigure_lock: Mutex::new(()),
            accept_task,
            tasks,
        })
    }

    /// Subscribes to `PeerEvent::Discovered` and `PeerEvent::Lost` notifications.
    pub fn subscribe(&self) -> broadcast::Receiver<PeerEvent> {
        self.event_tx.subscribe()
    }

    /// Returns a clone of the currently active `iroh::Endpoint`.
    pub fn endpoint(&self) -> Endpoint {
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

    /// Reconfigures the underlying `iroh::Endpoint` to enable (`RelayMode::Default` + `discovery_n0`)
    /// or completely disable (`RelayMode::Disabled` + `clear_discovery`) global discovery and relay.
    pub async fn reconfigure_wan_transport(&self, enabled: bool) -> Result<(), DiscoveryError> {
        let _guard = self.reconfigure_lock.lock().await;
        if self.wan_enabled.load(Ordering::Acquire) == enabled {
            return Ok(());
        }

        let known_nodes = self.peer_table.read().await.cached_node_addrs();
        let current_port = self.listen_port.load(Ordering::Relaxed);

        let prev_accept = { self.accept_task.lock().expect("accept_task mutex").take() };
        if let Some(handle) = prev_accept {
            handle.abort();
            let _ = handle.await;
        }

        // Remove and drop the old Endpoint completely before binding so the OS frees `current_port`.
        let prev_ep = { self.endpoint.write().expect("endpoint rwlock").take() };
        if let Some(old_ep) = prev_ep {
            old_ep.close().await;
            drop(old_ep);
            tokio::task::yield_now().await;
        }

        let mut bound_ep = None;
        for _ in 0..8 {
            if let Ok(ep) = build_iroh_endpoint_with_wan(
                &self.identity,
                current_port,
                known_nodes.clone(),
                enabled,
            )
            .await
            {
                bound_ep = Some(ep);
                break;
            }
            tokio::time::sleep(Duration::from_millis(35)).await;
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
            let old_name = { self.service_fullname.lock().expect("fullname mutex").clone() };
            if let Ok(rx) = self.mdns.unregister(&old_name) {
                let _ = tokio::time::timeout(Duration::from_millis(150), rx.recv_async()).await;
            }
            if let Ok(info) = build_mdns_service_info(&self.identity, new_port) {
                *self.service_fullname.lock().expect("fullname mutex") =
                    info.get_fullname().to_string();
                let _ = self.mdns.register(info);
            }
        }
        *self.endpoint.write().expect("endpoint rwlock") = Some(new_ep.clone());

        let new_accept = {
            let id = self.identity.clone();
            let table = Arc::clone(&self.peer_table);
            let tx = self.event_tx.clone();
            let transfer = self.transfer_engine.clone();
            let trust = self.trust_store.clone();
            let ctrl = self.control_channels.clone();
            tokio::spawn(async move {
                accept_loop(new_ep, id, new_port, table, tx, transfer, trust, ctrl).await;
            })
        };
        *self.accept_task.lock().expect("accept_task mutex") = Some(new_accept);
        self.wan_enabled.store(enabled, Ordering::Release);
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
        let ep = self.endpoint();
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

    /// Dials a known peer directly using its cached local `SocketAddr` and `NodeId`
    /// (completing in <50ms on LAN without waiting for mDNS or relay discovery), falling
    /// back to global Iroh node/relay resolution ONLY when `allow_wan == true` on the contact.
    pub async fn dial_peer(
        &self,
        endpoint: &Endpoint,
        node_id: NodeId,
    ) -> Result<Connection, DiscoveryError> {
        let maybe_peer = {
            let table = self.peer_table.read().await;
            table.get(&node_id).cloned()
        };
        let wan_allowed = match &self.trust_store {
            Some(store) => store.wan_secret_if_allowed(&node_id).await.is_some(),
            None => false,
        };

        let (conn, connected_via_lan) = if let Some(peer) = maybe_peer {
            let node_addr = peer.to_node_addr();
            endpoint
                .add_node_addr(node_addr.clone())
                .map_err(DiscoveryError::Iroh)?;
            if wan_allowed {
                match tokio::time::timeout(
                    Duration::from_millis(2200),
                    endpoint.connect(node_addr, BEAMDROP_ALPN),
                )
                .await
                {
                    Ok(Ok(conn)) => (conn, true),
                    Ok(Err(_)) | Err(_) => {
                        let wan_conn = endpoint
                            .connect(NodeAddr::new(node_id), BEAMDROP_ALPN)
                            .await
                            .map_err(DiscoveryError::Iroh)?;
                        (wan_conn, is_endpoint_connection_lan(endpoint, node_id))
                    }
                }
            } else {
                let conn = endpoint
                    .connect(node_addr, BEAMDROP_ALPN)
                    .await
                    .map_err(DiscoveryError::Iroh)?;
                (conn, true)
            }
        } else if wan_allowed {
            let wan_conn = endpoint
                .connect(NodeAddr::new(node_id), BEAMDROP_ALPN)
                .await
                .map_err(DiscoveryError::Iroh)?;
            (wan_conn, is_endpoint_connection_lan(endpoint, node_id))
        } else {
            return Err(DiscoveryError::Iroh(anyhow::anyhow!(
                "Peer {node_id} is not reachable on local LAN and long-distance transfers are disabled for this contact"
            )));
        };

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
        }

        Ok(conn)
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
        let conn = endpoint
            .connect(node_addr, BEAMDROP_ALPN)
            .await
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
        match reply {
            Message::Hello(remote) => {
                let peer_addr = SocketAddr::new(addr.ip(), remote.listen_port);
                let info = PeerInfo {
                    node_id: remote.node_id,
                    display_name: remote.display_name,
                    os_type: remote.os_type,
                    addr: peer_addr,
                    port: remote.listen_port,
                    online: true,
                    last_seen_unix_ms: now_unix_ms(),
                };
                let mut table = self.peer_table.write().await;
                let (saved, should_notify) = table.upsert(info, None)?;
                if should_notify {
                    let _ = self.event_tx.send(PeerEvent::Discovered(saved.clone()));
                }
                Ok(saved)
            }
            other => Err(DiscoveryError::Iroh(anyhow::anyhow!(
                "Unexpected handshake response: {:?}",
                other.message_type()
            ))),
        }
    }

    /// Records a remote peer in `known_peers.json` after pairing (preserving online status).
    pub async fn record_paired_peer(
        &self,
        endpoint: &Endpoint,
        node_id: NodeId,
        display_name: String,
        os_type: OsType,
        addr: SocketAddr,
    ) -> Result<PeerInfo, DiscoveryError> {
        let info = PeerInfo {
            node_id,
            display_name,
            os_type,
            addr,
            port: addr.port(),
            online: true,
            last_seen_unix_ms: now_unix_ms(),
        };
        let _ = endpoint.add_node_addr(info.to_node_addr());
        let mut table = self.peer_table.write().await;
        let (saved, _) = table.upsert(info, None)?;
        Ok(saved)
    }

    /// Gracefully unregisters the mDNS service and stops background tasks.
    pub async fn shutdown(mut self) {
        let fullname = { self.service_fullname.lock().expect("fullname mutex").clone() };
        if let Ok(rx) = self.mdns.unregister(&fullname) {
            let _ = tokio::time::timeout(Duration::from_millis(250), rx.recv_async()).await;
        }
        let prev_accept = { self.accept_task.lock().expect("accept_task mutex").take() };
        if let Some(handle) = prev_accept {
            handle.abort();
        }
        for handle in self.tasks.drain(..) {
            handle.abort();
        }
        let _ = self.mdns.shutdown();
    }
}

impl Drop for DiscoveryEngine {
    fn drop(&mut self) {
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
                if let Some(peer) = parse_resolved_service(&info, local_node_id) {
                    trace!(
                        node_id = %peer.node_id,
                        name = %peer.display_name,
                        addr = %peer.addr,
                        "mDNS resolved BeamDrop peer"
                    );
                    let maybe_ep = { endpoint.read().expect("endpoint rwlock").clone() };
                    if let Some(ep) = maybe_ep {
                        let _ = ep.add_node_addr(peer.to_node_addr());
                    }
                    let mut table = peer_table.write().await;
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

fn parse_resolved_service(info: &ServiceInfo, local_node_id: NodeId) -> Option<PeerInfo> {
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

    let ip = select_best_ip(info.get_addresses())?;
    let addr = SocketAddr::new(ip, port);

    Some(PeerInfo {
        node_id,
        display_name,
        os_type,
        addr,
        port,
        online: true,
        last_seen_unix_ms: now_unix_ms(),
    })
}

fn is_link_local_v6(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
        IpAddr::V4(_) => false,
    }
}

fn select_best_ip(addrs: &std::collections::HashSet<IpAddr>) -> Option<IpAddr> {
    // Prefer non-loopback IPv4 LAN addresses first
    for ip in addrs {
        if let IpAddr::V4(v4) = ip {
            if !v4.is_loopback() && !v4.is_unspecified() {
                return Some(*ip);
            }
        }
    }
    // Next allow loopback IPv4 (for local multi-instance testing)
    for ip in addrs {
        if let IpAddr::V4(v4) = ip {
            if !v4.is_unspecified() {
                return Some(*ip);
            }
        }
    }
    // Fallback to routable (non-link-local, non-unspecified) IPv6
    for ip in addrs {
        if let IpAddr::V6(v6) = ip {
            if !v6.is_unspecified() && !is_link_local_v6(ip) {
                return Some(*ip);
            }
        }
    }
    None
}

async fn probe_cached_peers_loop(
    endpoint: Arc<StdRwLock<Option<Endpoint>>>,
    identity: DeviceIdentity,
    listen_port: Arc<AtomicU16>,
    peer_table: Arc<RwLock<PeerTable>>,
    event_tx: broadcast::Sender<PeerEvent>,
) {
    // Immediate fast probe on startup for <50ms cached peer discovery
    let initial_ep = { endpoint.read().expect("endpoint rwlock").clone() };
    if let Some(ep) = initial_ep {
        let port = listen_port.load(Ordering::Relaxed);
        probe_peers_once(
            &ep,
            &identity,
            port,
            &peer_table,
            &event_tx,
            false,
            Duration::from_millis(800),
        )
        .await;
    }

    // Periodic fallback every 5s for offline/stale peers when mDNS multicast is dropped
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let current_ep = { endpoint.read().expect("endpoint rwlock").clone() };
        if let Some(ep) = current_ep {
            let port = listen_port.load(Ordering::Relaxed);
            probe_peers_once(
                &ep,
                &identity,
                port,
                &peer_table,
                &event_tx,
                true,
                Duration::from_millis(1200),
            )
            .await;
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
    let mut handles = Vec::new();

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
        handles.push(tokio::spawn(async move {
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
                anyhow::Ok(resp)
            };

            if let Ok(Ok(Message::Hello(remote))) = tokio::time::timeout(timeout, probe_fut).await {
                let updated = PeerInfo {
                    node_id: remote.node_id,
                    display_name: remote.display_name,
                    os_type: remote.os_type,
                    addr: SocketAddr::new(peer.addr.ip(), remote.listen_port),
                    port: remote.listen_port,
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
        }));
    }

    for h in handles {
        let _ = h.await;
    }
}

async fn accept_loop(
    endpoint: Endpoint,
    identity: DeviceIdentity,
    listen_port: u16,
    peer_table: Arc<RwLock<PeerTable>>,
    event_tx: broadcast::Sender<PeerEvent>,
    transfer_engine: Option<Arc<TransferEngine>>,
    trust_store: Option<Arc<TrustStore>>,
    control_channels: Option<ControlChannels>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let remote_addr = incoming.remote_address();
        let remote_ip = remote_addr.ip();
        let id = identity.clone();
        let table = Arc::clone(&peer_table);
        let tx = event_tx.clone();
        let ep = endpoint.clone();
        let transfer = transfer_engine.clone();
        let trust_store = trust_store.clone();
        let ctrl_ch = control_channels.clone();

        tokio::spawn(async move {
            let connecting = match incoming.accept() {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to accept incoming connection: {e}");
                    return;
                }
            };
            let conn = match connecting.await {
                Ok(c) => c,
                Err(e) => {
                    debug!("Incoming QUIC handshake failed: {e}");
                    return;
                }
            };

            let mut uni_started = false;

            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                let frame = match read_frame(&mut recv).await {
                    Ok(f) => f,
                    Err(_) => break,
                };

                match frame {
                    Message::Hello(remote) => {
                        let peer_addr = SocketAddr::new(remote_ip, remote.listen_port);
                        let info = PeerInfo {
                            node_id: remote.node_id,
                            display_name: remote.display_name,
                            os_type: remote.os_type,
                            addr: peer_addr,
                            port: remote.listen_port,
                            online: true,
                            last_seen_unix_ms: now_unix_ms(),
                        };
                        let _ = ep.add_node_addr(info.to_node_addr());
                        {
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

                                let saved_peer = {
                                    let mut guard = table.write().await;
                                    let peer_port = guard
                                        .get(&auth_node_id)
                                        .map(|p| p.port)
                                        .unwrap_or_else(|| remote_addr.port());
                                    let info = PeerInfo {
                                        node_id: auth_node_id,
                                        display_name: req.display_name,
                                        os_type: req.os_type,
                                        addr: SocketAddr::new(remote_ip, peer_port),
                                        port: peer_port,
                                        online: true,
                                        last_seen_unix_ms: now_unix_ms(),
                                    };
                                    let _ = ep.add_node_addr(info.to_node_addr());
                                    match guard.upsert(info.clone(), None) {
                                        Ok((saved, _)) => saved,
                                        Err(_) => info,
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

/// Returns `true` if `ip` is strictly a local LAN or loopback address
/// (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `169.254.0.0/16`, `127.0.0.0/8`,
/// IPv6 `::1`, link-local `fe80::/10`, unique-local `fc00::/7`, or IPv4-mapped LAN IPv6).
pub fn is_local_lan_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return mapped.is_private() || mapped.is_loopback() || mapped.is_link_local();
            }
            let seg0 = v6.segments()[0];
            v6.is_loopback()
                || (seg0 & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (seg0 & 0xfe00) == 0xfc00 // fc00::/7 unique local
        }
    }
}

/// Inspects the `Endpoint`'s active path for `remote_node_id` and returns `true` only when the
/// connection is verified as a local LAN / loopback direct UDP connection without relay usage.
pub fn is_endpoint_connection_lan(endpoint: &Endpoint, remote_node_id: NodeId) -> bool {
    match endpoint.conn_type(remote_node_id) {
        Ok(watcher) => match watcher.get() {
            Ok(ConnectionType::Direct(addr)) => is_local_lan_ip(&addr.ip()),
            Ok(ConnectionType::Relay(_)) | Ok(ConnectionType::Mixed(_, _)) => false,
            Ok(ConnectionType::None) | Err(_) => {
                if let Some(info) = endpoint.remote_info(remote_node_id) {
                    info.relay_url.is_none()
                        && !info.addrs.is_empty()
                        && info.addrs.iter().all(|a| is_local_lan_ip(&a.addr.ip()))
                } else {
                    false
                }
            }
        },
        Err(_) => false,
    }
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
pub async fn build_iroh_endpoint_with_wan(
    identity: &DeviceIdentity,
    bind_port: u16,
    known_nodes: Vec<NodeAddr>,
    wan_enabled: bool,
) -> Result<Endpoint, DiscoveryError> {
    let bind_v4 = std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, bind_port);
    let mut transport_config = iroh::endpoint::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
    transport_config.stream_receive_window(iroh::endpoint::VarInt::from_u32(1024 * 1024));
    transport_config.receive_window(iroh::endpoint::VarInt::from_u32(4 * 1024 * 1024));
    transport_config.send_window(4 * 1024 * 1024);

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
    fn test_peer_table_persistence_and_lost() {
        let dir = std::env::temp_dir().join(format!("beamdrop-peer-test-{}", Uuid::new_v4()));
        let path = dir.join(KNOWN_PEERS_FILENAME);
        let peer_id = DeviceIdentity::generate().node_id;

        let mut table = PeerTable::load_or_create(&path).expect("load_or_create");
        let peer = PeerInfo {
            node_id: peer_id,
            display_name: "TestMac".to_string(),
            os_type: OsType::MacOS,
            addr: "192.168.1.10:4433".parse().unwrap(),
            port: 4433,
            online: true,
            last_seen_unix_ms: 1_700_000_000_000,
        };

        let (_, notify1) = table.upsert(peer.clone(), Some("bd-test._beamdrop._udp.local.")).unwrap();
        assert!(notify1);

        let (_, notify2) = table.upsert(peer.clone(), Some("bd-test._beamdrop._udp.local.")).unwrap();
        assert!(!notify2);

        let reloaded = PeerTable::load_or_create(&path).expect("reload");
        let cached = reloaded.get(&peer_id).expect("peer cached on disk");
        assert_eq!(cached.addr, "192.168.1.10:4433".parse::<SocketAddr>().unwrap());
        assert!(!cached.online);
        assert_eq!(reloaded.cached_node_addrs().len(), 1);

        let lost = table
            .mark_lost_by_fullname("bd-test._beamdrop._udp.local.")
            .expect("lost peer");
        assert!(!lost.online);
        assert!(table.get(&peer_id).is_some());

        let _ = fs::remove_dir_all(&dir);
    }
}

