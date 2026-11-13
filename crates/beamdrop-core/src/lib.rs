pub mod discovery;
pub mod identity;
pub mod protocol;
pub mod transfer;
pub mod trust;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use iroh::endpoint::Connection;
use iroh::{Endpoint, NodeAddr, NodeId};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{timeout, Instant};
use uuid::Uuid;

pub use discovery::{
    build_iroh_endpoint, build_iroh_endpoint_with_wan, is_endpoint_connection_lan,
    is_local_lan_ip, ping_peer, ControlChannels, DiscoveryEngine, DiscoveryError, PeerEvent,
    PeerInfo, PeerTable, ResumeRequest, KNOWN_PEERS_FILENAME, MDNS_SERVICE_TYPE,
};
pub use identity::{DeviceIdentity, IdentityError, OsType};
pub use protocol::{
    read_frame, transfer_stream_id, write_frame, AcceptPayload, AcceptedFileResume, ChunkRange,
    CompletePayload, FileHashEntry, FileOfferEntry, HelloPayload, Message, MessageType,
    OfferPayload, PairConfirmPayload, PairRequestPayload, PingPayload, PongPayload, ProtocolError,
    RejectPayload, TransferControlPayload, BEAMDROP_ALPN, FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD_LEN,
    PROTOCOL_VERSION,
};
pub use transfer::{
    current_utc_day, default_download_dir, derive_daily_wan_key, hash_file_blake3, part_path_for,
    resume_path_for, ChunkHeader, ResumeMetadata, TransferEngine, TransferError, TransferEvent,
    TransferProgress, TransferSummary, WanCipherContext, CHANNEL_BOUND, CHUNK_SIZE,
    DEFAULT_APPROVAL_TIMEOUT, MAX_PARALLEL_STREAMS, PARALLEL_STRIPE_THRESHOLD,
    UNI_CHUNK_HEADER_LEN, WAN_CHUNK_OVERHEAD,
};
pub use trust::{
    derive_wan_shared_secret, detect_lan_ip, format_pairing_uri, normalize_pin, parse_pairing_uri,
    PairingSession, ParsedPairingUri, TrustError, TrustStore, TrustedPeer, PAIRING_PIN_TTL,
    TRUSTED_PEERS_FILENAME,
};

/// Configuration options for starting a `BeamDropNode`.
#[derive(Debug, Clone, Default)]
pub struct NodeConfig {
    /// Optional custom directory for `identity.json` and `known_peers.json`
    /// (defaults to `<OS Config Dir>/BeamDrop`).
    pub config_dir: Option<PathBuf>,
    /// Optional output directory for received files (defaults to `Downloads/BeamDrop`).
    pub download_dir: Option<PathBuf>,
    /// Optional display name override (defaults to the machine's hostname).
    pub display_name: Option<String>,
    /// Optional local UDP port to bind the Iroh QUIC endpoint to (`0` = OS-assigned).
    pub port: u16,
}

#[derive(Debug, Clone)]
struct PausedOutgoingInfo {
    peer_node_id: NodeId,
    peer_name: Option<String>,
    source_path: PathBuf,
}

/// High-level BeamDrop peer-to-peer node combining identity, Iroh QUIC transport,
/// mDNS + disk-cached discovery, and bounded-memory parallel QUIC transfers.
pub struct BeamDropNode {
    identity: DeviceIdentity,
    discovery: Arc<DiscoveryEngine>,
    transfer: Arc<TransferEngine>,
    trust: Arc<TrustStore>,
    paused_outgoing: Arc<RwLock<HashMap<Uuid, PausedOutgoingInfo>>>,
    active_resume_tasks: Arc<Mutex<JoinSet<()>>>,
    control_task: JoinHandle<()>,
}

impl BeamDropNode {
    /// Initializes and starts a `BeamDropNode` with the provided configuration.
    pub async fn start(config: NodeConfig) -> Result<Self> {
        let (identity_path, peers_path, trust_path) = match &config.config_dir {
            Some(dir) => (
                dir.join("identity.json"),
                dir.join(KNOWN_PEERS_FILENAME),
                dir.join(TRUSTED_PEERS_FILENAME),
            ),
            None => (
                DeviceIdentity::default_path()?,
                PeerTable::default_path()?,
                TrustStore::default_path()?,
            ),
        };

        let mut identity = DeviceIdentity::load_or_create_at(&identity_path)?;
        if let Some(name) = config.display_name {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                identity.hostname = trimmed.to_string();
                identity.save_to(&identity_path)?;
            }
        }

        let trust = Arc::new(TrustStore::load_or_create_with_identity(
            &trust_path,
            &identity,
        )?);
        let initial_wan = trust.any_wan_enabled().await;
        let initial_table = PeerTable::load_or_create(&peers_path)?;
        let endpoint = build_iroh_endpoint_with_wan(
            &identity,
            config.port,
            initial_table.cached_node_addrs(),
            initial_wan,
        )
        .await?;

        let transfer = Arc::new(TransferEngine::with_trust_store(
            config.download_dir,
            Some(Arc::clone(&trust)),
        )?);
        let (resume_tx, mut resume_rx) = mpsc::unbounded_channel::<ResumeRequest>();
        let (cancel_tx, mut cancel_rx) = mpsc::unbounded_channel::<(Uuid, Option<String>)>();
        let discovery = Arc::new(
            DiscoveryEngine::start_with_handlers(
                identity.clone(),
                endpoint,
                Some(peers_path),
                Some(Arc::clone(&transfer)),
                Some(Arc::clone(&trust)),
                Some(ControlChannels {
                    resume_tx,
                    cancel_tx,
                }),
            )
            .await?,
        );

        let paused_outgoing: Arc<RwLock<HashMap<Uuid, PausedOutgoingInfo>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let active_resume_tasks: Arc<Mutex<JoinSet<()>>> = Arc::new(Mutex::new(JoinSet::new()));

        let control_task = {
            let disc = Arc::clone(&discovery);
            let tr = Arc::clone(&transfer);
            let host = identity.hostname.clone();
            let paused = Arc::clone(&paused_outgoing);
            let tasks = Arc::clone(&active_resume_tasks);
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        Some((transfer_id, requester_node_id, reply_tx)) = resume_rx.recv() => {
                            let maybe_info = {
                                let mut guard = paused.write().await;
                                match guard.get(&transfer_id) {
                                    Some(info) if info.peer_node_id == requester_node_id => guard.remove(&transfer_id),
                                    Some(_) => {
                                        let _ = reply_tx.send(Err("Transfer does not belong to requesting peer".to_string()));
                                        continue;
                                    }
                                    None => {
                                        let _ = reply_tx.send(Err(format!("No paused outgoing transfer found for ID {transfer_id}")));
                                        continue;
                                    }
                                }
                            };
                            if let Some(info) = maybe_info {
                                let _ = reply_tx.send(Ok(()));
                                spawn_resumed_outgoing(
                                    Arc::clone(&disc),
                                    Arc::clone(&tr),
                                    host.clone(),
                                    Arc::clone(&paused),
                                    Arc::clone(&tasks),
                                    transfer_id,
                                    info,
                                    None,
                                )
                                .await;
                            }
                        }
                        Some((transfer_id, reason)) = cancel_rx.recv() => {
                            if paused.write().await.remove(&transfer_id).is_some() {
                                tr.emit_cancelled(transfer_id, reason);
                            }
                        }
                        else => break,
                    }
                }
            })
        };

        Ok(Self {
            identity,
            discovery,
            transfer,
            trust,
            paused_outgoing,
            active_resume_tasks,
            control_task,
        })
    }

    /// Returns this node's persistent `DeviceIdentity`.
    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    /// Returns a clone of the currently active `iroh::Endpoint`.
    pub fn endpoint(&self) -> Endpoint {
        self.discovery.endpoint()
    }

    /// Returns the `DiscoveryEngine`.
    pub fn discovery(&self) -> &DiscoveryEngine {
        &self.discovery
    }

    /// Returns the `TransferEngine`.
    pub fn transfer(&self) -> &Arc<TransferEngine> {
        &self.transfer
    }

    /// Returns the persistent `TrustStore`.
    pub fn trust_store(&self) -> &Arc<TrustStore> {
        &self.trust
    }

    /// Starts an active one-time pairing session generating a 6-digit PIN (valid for 5 minutes)
    /// and a compact `beamdrop://pair?...` URI suitable for QR rendering.
    pub async fn start_pairing_session(&self) -> Result<PairingSession> {
        let lan_ip = detect_lan_ip();
        let lan_addr = SocketAddr::new(lan_ip, self.listen_port());
        Ok(self
            .trust
            .start_pairing_session(self.identity.node_id, lan_addr)
            .await)
    }

    /// Initiates a one-time pairing handshake with `target` (a `beamdrop://pair?...` URI,
    /// `<node_id>@<ip:port>`, display name, `NodeId`, or `SocketAddr`) presenting `pin`.
    pub async fn pair_with_peer(&self, target: &str, pin: &str) -> Result<TrustedPeer> {
        let trimmed_target = target.trim();
        let trimmed_pin = pin.trim();

        let (peer_node_id, peer_addr, effective_pin) = if trimmed_target.starts_with("beamdrop://")
        {
            let parsed = parse_pairing_uri(trimmed_target)?;
            let chosen_pin = if trimmed_pin.is_empty() {
                parsed.pin
            } else {
                normalize_pin(trimmed_pin)?
            };
            let resolved_addr = match parsed.addr {
                Some(addr) => addr,
                None => {
                    self.resolve_peer(&parsed.node_id.to_string(), Duration::from_secs(5))
                        .await?
                        .addr
                }
            };
            (parsed.node_id, resolved_addr, chosen_pin)
        } else {
            let chosen_pin = normalize_pin(trimmed_pin)?;
            if let Some((node_part, addr_part)) = trimmed_target.split_once('@') {
                let node_id = NodeId::from_str(node_part.trim())
                    .map_err(|e| anyhow!("Invalid NodeId '{node_part}': {e}"))?;
                let sock = SocketAddr::from_str(addr_part.trim())
                    .map_err(|e| anyhow!("Invalid SocketAddr '{addr_part}': {e}"))?;
                (node_id, sock, chosen_pin)
            } else if let Ok(sock) = SocketAddr::from_str(trimmed_target) {
                let peer = self
                    .resolve_peer_by_addr(sock, Duration::from_secs(5))
                    .await?;
                (peer.node_id, peer.addr, chosen_pin)
            } else {
                let peer = self
                    .resolve_peer(trimmed_target, Duration::from_secs(5))
                    .await?;
                (peer.node_id, peer.addr, chosen_pin)
            }
        };

        let endpoint = self.discovery.endpoint();
        let node_addr = NodeAddr::from_parts(peer_node_id, None, vec![peer_addr]);
        endpoint.add_node_addr(node_addr.clone())?;
        let conn = endpoint.connect(node_addr, BEAMDROP_ALPN).await?;

        let auth_remote = conn.remote_node_id()?;
        if auth_remote != peer_node_id {
            bail!(
                "Remote TLS NodeId ({auth_remote}) did not match expected pairing target ({peer_node_id})"
            );
        }

        let (mut send, mut recv) = conn.open_bi().await?;
        let req = Message::PairRequest(PairRequestPayload {
            sender_node_id: self.identity.node_id,
            display_name: self.identity.hostname.clone(),
            os_type: self.identity.os_type,
            pin: effective_pin,
        });
        write_frame(&mut send, &req).await?;
        let _ = send.finish();

        match read_frame(&mut recv).await? {
            Message::PairConfirm(confirm) => {
                if confirm.responder_node_id != auth_remote {
                    bail!(
                        "PairConfirm responder NodeId ({}) mismatched authenticated peer ({auth_remote})",
                        confirm.responder_node_id
                    );
                }
                if !confirm.accepted {
                    bail!(
                        "Pairing rejected by peer: {}",
                        confirm
                            .reason
                            .unwrap_or_else(|| "invalid or expired PIN".to_string())
                    );
                }

                let trusted = self
                    .trust
                    .trust_peer(
                        confirm.responder_node_id,
                        confirm.display_name.clone(),
                        confirm.os_type,
                        true,
                    )
                    .await?;
                self.discovery
                    .record_paired_peer(
                        &endpoint,
                        confirm.responder_node_id,
                        confirm.display_name,
                        confirm.os_type,
                        peer_addr,
                    )
                    .await?;
                Ok(trusted)
            }
            other => bail!(
                "Unexpected response to PairRequest: {:?}",
                other.message_type()
            ),
        }
    }

    /// Approves or declines a held incoming transfer offer from an untrusted peer.
    pub async fn respond_to_offer(&self, transfer_id: Uuid, accept: bool) -> Result<()> {
        if self.transfer.respond_to_offer(transfer_id, accept).await {
            Ok(())
        } else {
            Err(anyhow!(
                "No pending transfer offer found for ID {transfer_id}"
            ))
        }
    }

    /// Returns the configured download directory for received files.
    pub fn download_dir(&self) -> &Path {
        self.transfer.download_dir()
    }

    /// Returns the local QUIC listening port.
    pub fn listen_port(&self) -> u16 {
        self.discovery.listen_port()
    }

    /// Subscribes to `PeerEvent::Discovered` and `PeerEvent::Lost` broadcast events.
    pub fn subscribe_peers(&self) -> broadcast::Receiver<PeerEvent> {
        self.discovery.subscribe()
    }

    /// Subscribes to `TransferEvent`s (offers received, progress, completion, interruption).
    pub fn subscribe_transfers(&self) -> broadcast::Receiver<TransferEvent> {
        self.transfer.subscribe()
    }

    /// Dials a known peer by `NodeId` and measures QUIC `Ping`/`Pong` latency.
    pub async fn ping(&self, node_id: NodeId) -> Result<Duration> {
        let ep = self.discovery.endpoint();
        let conn = self.discovery.dial_peer(&ep, node_id).await?;
        let rtt = ping_peer(&conn, rand::random()).await?;
        Ok(rtt)
    }

    /// Toggles long-distance WAN transfers for a trusted contact and dynamically enables/disables
    /// global Pkarr discovery and relay transport on the local endpoint.
    pub async fn set_peer_wan_enabled(&self, node_id: NodeId, enabled: bool) -> Result<bool> {
        let updated = self.trust.set_peer_wan_enabled(&node_id, enabled).await?;
        let any_wan = self.trust.any_wan_enabled().await;
        self.discovery.reconfigure_wan_transport(any_wan).await?;
        Ok(updated)
    }

    /// Removes a trusted contact from the trust store and disables WAN relay transport if no
    /// remaining contacts use long-distance transfers.
    pub async fn remove_trusted_peer(&self, node_id: &NodeId) -> Result<Option<TrustedPeer>> {
        let removed = self.trust.remove_peer(node_id).await?;
        if removed.is_some() {
            let any_wan = self.trust.any_wan_enabled().await;
            self.discovery.reconfigure_wan_transport(any_wan).await?;
        }
        Ok(removed)
    }

    /// Resolves a peer by exact `NodeId`, unique `NodeId` prefix, or display name,
    /// checking cached peers immediately and listening for mDNS discovery up to `wait`.
    pub async fn resolve_peer(&self, peer_name_or_id: &str, wait: Duration) -> Result<PeerInfo> {
        let query = peer_name_or_id.trim();
        if query.is_empty() {
            bail!("Peer name or NodeId cannot be empty");
        }

        let mut events = self.subscribe_peers();

        // Check known/cached peers immediately
        if let Some(found) = match_peer_in_list(&self.discovery.known_peers().await, query)? {
            return Ok(found);
        }

        let deadline = Instant::now() + wait;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, events.recv()).await {
                Ok(Ok(PeerEvent::Discovered(peer))) | Ok(Ok(PeerEvent::Paired(peer))) => {
                    if peer_matches_query(&peer, query) {
                        return Ok(peer);
                    }
                }
                Ok(Ok(PeerEvent::Lost(_))) => continue,
                _ => break,
            }
        }

        // Re-check known peers once more at the end of the discovery window
        if let Some(found) = match_peer_in_list(&self.discovery.known_peers().await, query)? {
            return Ok(found);
        }

        Err(anyhow!(
            "No peer matching '{query}' discovered within {:.1}s",
            wait.as_secs_f64()
        ))
    }

    async fn resolve_peer_by_addr(&self, target_addr: SocketAddr, wait: Duration) -> Result<PeerInfo> {
        if let Some(found) = self
            .discovery
            .known_peers()
            .await
            .into_iter()
            .find(|p| p.addr == target_addr)
        {
            return Ok(found);
        }

        let mut events = self.subscribe_peers();
        let deadline = Instant::now() + wait;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, events.recv()).await {
                Ok(Ok(PeerEvent::Discovered(peer))) | Ok(Ok(PeerEvent::Paired(peer))) => {
                    if peer.addr == target_addr {
                        return Ok(peer);
                    }
                }
                Ok(Ok(PeerEvent::Lost(_))) => continue,
                _ => break,
            }
        }

        if let Some(found) = self
            .discovery
            .known_peers()
            .await
            .into_iter()
            .find(|p| p.addr == target_addr)
        {
            return Ok(found);
        }

        Err(anyhow!(
            "No peer at address {target_addr} discovered within {:.1}s (tip: pass a NodeId or beamdrop://pair?... URI)",
            wait.as_secs_f64()
        ))
    }

    /// Triggers a direct QUIC probe across cached peers when mDNS is unavailable or app resumes.
    pub async fn refresh_peers(&self) {
        self.discovery.probe_cached_peers_now().await;
    }

    /// Requests a graceful pause for an active incoming or outgoing transfer, keeping `.resume.json`.
    pub async fn pause_transfer(&self, transfer_id: Uuid) -> bool {
        self.transfer.pause_transfer(transfer_id).await
    }

    /// Cancels an active or paused incoming or outgoing transfer and removes incomplete partial files.
    pub async fn cancel_transfer(&self, transfer_id: Uuid) -> bool {
        let ep = self.discovery.endpoint();
        let paused_sender = self.transfer.paused_incoming_sender(transfer_id).await;
        if self.transfer.cancel_transfer(transfer_id).await {
            if let Some(sender_node_id) = paused_sender {
                send_remote_cancel_best_effort(
                    &self.discovery,
                    &ep,
                    sender_node_id,
                    transfer_id,
                    Some("Cancelled by peer".to_string()),
                )
                .await;
            }
            return true;
        }

        if let Some(info) = self.paused_outgoing.write().await.remove(&transfer_id) {
            self.transfer
                .emit_cancelled(transfer_id, Some("Cancelled by user".to_string()));
            send_remote_cancel_best_effort(
                &self.discovery,
                &ep,
                info.peer_node_id,
                transfer_id,
                Some("Cancelled by peer".to_string()),
            )
            .await;
            return true;
        }

        false
    }

    /// Resumes a paused incoming or outgoing transfer by reusing `transfer_id` and `.resume.json`.
    pub async fn resume_transfer(&self, transfer_id: Uuid) -> Result<()> {
        let ep = self.discovery.endpoint();
        if let Some(sender_node_id) = self.transfer.paused_incoming_sender(transfer_id).await {
            let conn = self
                .discovery
                .dial_peer(&ep, sender_node_id)
                .await?;
            let (mut send, mut recv) = conn.open_bi().await?;
            let req = Message::Resume(TransferControlPayload {
                transfer_id,
                reason: None,
            });
            write_frame(&mut send, &req).await?;
            let _ = send.finish();

            match read_frame(&mut recv).await? {
                Message::Resume(_) => return Ok(()),
                Message::Reject(rej) => {
                    bail!(rej
                        .reason
                        .unwrap_or_else(|| "Resume rejected by sender".to_string()))
                }
                other => {
                    bail!(
                        "Unexpected response to Resume request: {:?}",
                        other.message_type()
                    )
                }
            }
        }

        let info = self
            .paused_outgoing
            .write()
            .await
            .remove(&transfer_id)
            .ok_or_else(|| anyhow!("No paused transfer found for ID {transfer_id}"))?;

        let conn = match self
            .discovery
            .dial_peer(&ep, info.peer_node_id)
            .await
        {
            Ok(c) => c,
            Err(err) => {
                self.paused_outgoing.write().await.insert(transfer_id, info);
                return Err(err.into());
            }
        };

        spawn_resumed_outgoing(
            Arc::clone(&self.discovery),
            Arc::clone(&self.transfer),
            self.identity.hostname.clone(),
            Arc::clone(&self.paused_outgoing),
            Arc::clone(&self.active_resume_tasks),
            transfer_id,
            info,
            Some(conn),
        )
        .await;

        Ok(())
    }

    /// Sends a single file or recursive directory to `peer_node_id` over Iroh QUIC.
    pub async fn send_path(
        &self,
        peer_node_id: NodeId,
        source_path: impl AsRef<Path>,
        progress_tx: Option<mpsc::Sender<TransferProgress>>,
    ) -> Result<TransferSummary> {
        self.send_path_with_wan_override(peer_node_id, source_path, None, progress_tx)
            .await
    }

    /// Sends a single file or recursive directory to `peer_node_id` with optional explicit
    /// override for daily-rotating ChaCha20-Poly1305 WAN encryption (`None` = auto-detect LAN/WAN).
    pub async fn send_path_with_wan_override(
        &self,
        peer_node_id: NodeId,
        source_path: impl AsRef<Path>,
        force_wan_encryption: Option<bool>,
        progress_tx: Option<mpsc::Sender<TransferProgress>>,
    ) -> Result<TransferSummary> {
        let transfer_id = Uuid::new_v4();
        let source_buf = source_path.as_ref().to_path_buf();
        let peer_name = self.resolve_peer_display_name(peer_node_id).await;
        let ep = self.discovery.endpoint();
        let conn = self
            .discovery
            .dial_peer(&ep, peer_node_id)
            .await?;
        run_tracked_send(
            &self.transfer,
            &conn,
            &self.identity.hostname,
            transfer_id,
            peer_node_id,
            peer_name.as_deref(),
            &source_buf,
            progress_tx,
            &self.paused_outgoing,
            force_wan_encryption,
        )
        .await
    }

    async fn resolve_peer_display_name(&self, peer_node_id: NodeId) -> Option<String> {
        if let Some(peer) = self
            .discovery
            .known_peers()
            .await
            .into_iter()
            .find(|p| p.node_id == peer_node_id)
        {
            return Some(peer.display_name);
        }
        self.trust
            .get_peer(&peer_node_id)
            .await
            .map(|p| p.friendly_alias)
    }

    /// Gracefully shuts down the discovery engine and closes the Iroh QUIC endpoint.
    pub async fn shutdown(self) {
        self.control_task.abort();
        let _ = self.control_task.await;
        self.active_resume_tasks.lock().await.shutdown().await;
        let ep = self.discovery.endpoint();
        if let Ok(disc) = Arc::try_unwrap(self.discovery) {
            disc.shutdown().await;
        }
        ep.close().await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_tracked_send(
    transfer: &Arc<TransferEngine>,
    conn: &Connection,
    local_hostname: &str,
    transfer_id: Uuid,
    peer_node_id: NodeId,
    peer_name: Option<&str>,
    source_path: &Path,
    progress_tx: Option<mpsc::Sender<TransferProgress>>,
    paused_outgoing: &Arc<RwLock<HashMap<Uuid, PausedOutgoingInfo>>>,
    force_wan_encryption: Option<bool>,
) -> Result<TransferSummary> {
    let res = transfer
        .send_path_with_wan_override(
            conn,
            local_hostname,
            source_path,
            peer_name,
            Some(transfer_id),
            progress_tx,
            force_wan_encryption,
        )
        .await;

    match res {
        Ok(summary) => {
            paused_outgoing.write().await.remove(&transfer_id);
            Ok(summary)
        }
        Err(err) => {
            match err {
                TransferError::Paused(_) => {
                    paused_outgoing.write().await.insert(
                        transfer_id,
                        PausedOutgoingInfo {
                            peer_node_id,
                            peer_name: peer_name.map(ToOwned::to_owned),
                            source_path: source_path.to_path_buf(),
                        },
                    );
                }
                TransferError::Cancelled(_) => {
                    paused_outgoing.write().await.remove(&transfer_id);
                }
                _ => {}
            }
            Err(err.into())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn spawn_resumed_outgoing(
    discovery: Arc<DiscoveryEngine>,
    transfer: Arc<TransferEngine>,
    local_hostname: String,
    paused_outgoing: Arc<RwLock<HashMap<Uuid, PausedOutgoingInfo>>>,
    active_resume_tasks: Arc<Mutex<JoinSet<()>>>,
    transfer_id: Uuid,
    info: PausedOutgoingInfo,
    pre_dialed: Option<Connection>,
) {
    let mut tasks = active_resume_tasks.lock().await;
    tasks.spawn(async move {
        let ep = discovery.endpoint();
        let conn = match pre_dialed {
            Some(c) => c,
            None => match discovery.dial_peer(&ep, info.peer_node_id).await {
                Ok(c) => c,
                Err(_) => {
                    paused_outgoing.write().await.insert(transfer_id, info);
                    return;
                }
            },
        };

        let _ = run_tracked_send(
            &transfer,
            &conn,
            &local_hostname,
            transfer_id,
            info.peer_node_id,
            info.peer_name.as_deref(),
            &info.source_path,
            None,
            &paused_outgoing,
            None,
        )
        .await;
    });
}

async fn send_remote_cancel_best_effort(
    discovery: &DiscoveryEngine,
    endpoint: &Endpoint,
    peer_node_id: NodeId,
    transfer_id: Uuid,
    reason: Option<String>,
) {
    let _ = timeout(Duration::from_secs(3), async {
        let conn = discovery.dial_peer(endpoint, peer_node_id).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        let frame = Message::Cancel(TransferControlPayload {
            transfer_id,
            reason,
        });
        write_frame(&mut send, &frame).await?;
        let _ = send.finish();
        let _ = recv.read_to_end(0).await;
        anyhow::Ok(())
    })
    .await;
}

fn peer_matches_query(peer: &PeerInfo, query: &str) -> bool {
    if let Ok(exact_id) = NodeId::from_str(query) {
        return peer.node_id == exact_id;
    }
    let q_lower = query.to_ascii_lowercase();
    peer.display_name.to_ascii_lowercase() == q_lower
        || peer.node_id.to_string().to_ascii_lowercase().starts_with(&q_lower)
}

fn match_peer_in_list(peers: &[PeerInfo], query: &str) -> Result<Option<PeerInfo>> {
    if let Ok(exact_id) = NodeId::from_str(query) {
        return Ok(peers.iter().find(|p| p.node_id == exact_id).cloned());
    }

    let q_lower = query.to_ascii_lowercase();
    let matches: Vec<PeerInfo> = peers
        .iter()
        .filter(|p| {
            p.display_name.to_ascii_lowercase() == q_lower
                || p.node_id.to_string().to_ascii_lowercase().starts_with(&q_lower)
        })
        .cloned()
        .collect();

    if matches.len() > 1 {
        // Prefer online peer if only one of the matches is currently online
        let online: Vec<PeerInfo> = matches.iter().filter(|p| p.online).cloned().collect();
        if online.len() == 1 {
            return Ok(Some(online.into_iter().next().unwrap()));
        }
        let ids: Vec<String> = matches
            .iter()
            .map(|p| format!("{} ({})", p.display_name, p.node_id))
            .collect();
        bail!(
            "Ambiguous peer query '{query}', multiple matches found: {}",
            ids.join(", ")
        );
    }

    Ok(matches.into_iter().next())
}
