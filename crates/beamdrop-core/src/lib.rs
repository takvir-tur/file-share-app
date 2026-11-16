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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};
use iroh::endpoint::Connection;
use iroh::{Endpoint, NodeId};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{timeout, Instant};
use uuid::Uuid;

pub use discovery::{
    build_iroh_endpoint, build_iroh_endpoint_with_wan, build_transport_config,
    is_endpoint_connection_direct, is_endpoint_connection_lan, is_local_lan_ip, ping_peer,
    ControlChannels, DiscoveryEngine, DiscoveryError, PeerEvent, PeerInfo, PeerTable,
    ResumeRequest, KNOWN_PEERS_FILENAME, MDNS_SERVICE_TYPE,
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
    preview_source_summary, resume_path_for, ChunkHeader, PreControlHandle, ResumeMetadata,
    TransferDirection, TransferEngine, TransferError, TransferEvent, TransferProgress,
    TransferSummary, WanCipherContext, CHANNEL_BOUND, CHUNK_SIZE, DEFAULT_APPROVAL_TIMEOUT,
    MAX_PARALLEL_STREAMS, PARALLEL_STRIPE_THRESHOLD, UNI_CHUNK_HEADER_LEN, WAN_CHANNEL_BOUND,
    WAN_CHUNK_OVERHEAD, WAN_CHUNK_SIZE,
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
    pairing_wan_timer: Arc<Mutex<Option<JoinHandle<()>>>>,
    control_task: JoinHandle<()>,
}

/// Raises the soft open-file-descriptor limit (`RLIMIT_NOFILE`) on Unix platforms up to
/// `min(10240, rlim_max)` so macOS app bundles do not fail with `os error 24`
/// (`Too many open files`) during multi-peer mDNS/QUIC/transfer I/O.
pub fn raise_open_file_limit() {
    #[cfg(unix)]
    unsafe {
        const TARGET_NOFILE: libc::rlim_t = 10240;
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) == 0 {
            let cap = if rlim.rlim_max == libc::RLIM_INFINITY {
                TARGET_NOFILE
            } else {
                TARGET_NOFILE.min(rlim.rlim_max)
            };
            if rlim.rlim_cur < cap {
                let updated = libc::rlimit {
                    rlim_cur: cap,
                    rlim_max: rlim.rlim_max,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &updated) != 0 {
                    let fallback = 4096 as libc::rlim_t;
                    if rlim.rlim_cur < fallback {
                        let fb = libc::rlimit {
                            rlim_cur: fallback,
                            rlim_max: rlim.rlim_max,
                        };
                        let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &fb);
                    }
                }
            }
        }
    }
}

impl BeamDropNode {
    /// Initializes and starts a `BeamDropNode` with the provided configuration.
    pub async fn start(config: NodeConfig) -> Result<Self> {
        raise_open_file_limit();
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
        let (wan_recheck_tx, mut wan_recheck_rx) = mpsc::unbounded_channel::<()>();
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
                    wan_recheck_tx,
                }),
            )
            .await?,
        );
        transfer.attach_peer_table(discovery.peer_table());

        let paused_outgoing: Arc<RwLock<HashMap<Uuid, PausedOutgoingInfo>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let active_resume_tasks: Arc<Mutex<JoinSet<()>>> = Arc::new(Mutex::new(JoinSet::new()));
        let pairing_wan_timer: Arc<Mutex<Option<JoinHandle<()>>>> = Arc::new(Mutex::new(None));

        let control_task = {
            struct AbortOnDrop(Option<JoinHandle<()>>);
            impl Drop for AbortOnDrop {
                fn drop(&mut self) {
                    if let Some(handle) = self.0.take() {
                        handle.abort();
                    }
                }
            }
            let disc = Arc::clone(&discovery);
            let tr = Arc::clone(&transfer);
            let trust_bg = Arc::clone(&trust);
            let host = identity.hostname.clone();
            let paused = Arc::clone(&paused_outgoing);
            let tasks = Arc::clone(&active_resume_tasks);
            tokio::spawn(async move {
                let mut post_pair_downgrade = AbortOnDrop(None);
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
                                    Arc::clone(&trust_bg),
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
                        Some(()) = wan_recheck_rx.recv() => {
                            if let Some(prev) = post_pair_downgrade.0.take() {
                                prev.abort();
                            }
                            let disc_bg = Arc::clone(&disc);
                            post_pair_downgrade.0 = Some(tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_secs(15)).await;
                                loop {
                                    let keep_wan = disc_bg.desired_wan_state().await;
                                    if keep_wan {
                                        break;
                                    }
                                    if !disc_bg.has_in_flight_transfers().await {
                                        let desired = disc_bg.desired_wan_state().await;
                                        let _ = disc_bg.reconfigure_wan_transport(desired).await;
                                        break;
                                    }
                                    tokio::time::sleep(Duration::from_millis(500)).await;
                                }
                            }));
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
            pairing_wan_timer,
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

    /// Returns the currently active 5-minute pairing session, or creates one if missing or expired.
    pub async fn start_pairing_session(&self) -> Result<PairingSession> {
        self.get_or_start_pairing_session(false).await
    }

    /// Returns the active unexpired pairing session when `force_new == false`, or creates
    /// a fresh 5-minute session (`force_new == true`), keeping temporary WAN transport enabled
    /// for the 5-minute window.
    pub async fn get_or_start_pairing_session(&self, force_new: bool) -> Result<PairingSession> {
        if !force_new {
            if let Some(existing) = self.trust.active_pairing_session().await {
                self.discovery
                    .set_pairing_wan_expires_at(existing.expires_at_unix);
                self.discovery.reconfigure_wan_transport(true).await?;
                return Ok(existing);
            }
        }

        let placeholder_exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_add(PAIRING_PIN_TTL.as_secs());
        self.discovery.set_pairing_wan_expires_at(placeholder_exp);
        self.discovery.reconfigure_wan_transport(true).await?;

        let lan_ip = detect_lan_ip();
        let lan_addr = SocketAddr::new(lan_ip, self.listen_port());
        let (session, created_new) = self
            .trust
            .get_or_start_pairing_session(self.identity.node_id, lan_addr, force_new)
            .await;
        self.discovery
            .set_pairing_wan_expires_at(session.expires_at_unix);

        if created_new {
            let mut timer_guard = self.pairing_wan_timer.lock().await;
            if let Some(prev) = timer_guard.take() {
                prev.abort();
            }
            let disc = Arc::clone(&self.discovery);
            let trust = Arc::clone(&self.trust);
            let expected_pin = session.pin.clone();
            let wait_dur = session
                .expires_at
                .saturating_duration_since(std::time::Instant::now())
                + Duration::from_millis(50);
            *timer_guard = Some(tokio::spawn(async move {
                tokio::time::sleep(wait_dur).await;
                let _ = trust.expire_pairing_session_if_matches(&expected_pin).await;
                if trust.active_pairing_session().await.is_none() {
                    disc.set_pairing_wan_expires_at(0);
                    loop {
                        let keep_wan = disc.desired_wan_state().await;
                        if keep_wan || !disc.has_in_flight_transfers().await {
                            let _ = disc.reconfigure_wan_transport(keep_wan).await;
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }));
        }

        Ok(session)
    }

    /// Cancels any active pairing session and immediately turns off temporary pairing WAN
    /// transport unless at least one trusted contact has `allow_wan` enabled.
    pub async fn cancel_pairing_session(&self) {
        if let Some(prev) = self.pairing_wan_timer.lock().await.take() {
            prev.abort();
        }
        self.trust.cancel_pairing_session().await;
        self.discovery.set_pairing_wan_expires_at(0);
        let keep_wan = self.trust.any_wan_enabled().await;
        let _ = self.discovery.reconfigure_wan_transport(keep_wan).await;
    }

    /// Initiates a one-time pairing handshake with `target` (a `beamdrop://pair?...` URI,
    /// `<node_id>@<ip:port>`, display name, `NodeId`, or `SocketAddr`) presenting `pin`.
    /// Always dials cached/provided LAN addresses first (~1.2s timeout) before falling back
    /// to `NodeAddr::new(node_id)` over global Iroh discovery + relay.
    pub async fn pair_with_peer(&self, target: &str, pin: &str) -> Result<TrustedPeer> {
        let trimmed_target = target.trim();
        let trimmed_pin = pin.trim();

        let (peer_node_id, mut lan_addrs, effective_pin) = if trimmed_target
            .starts_with("beamdrop://")
        {
            let parsed = parse_pairing_uri(trimmed_target)?;
            let chosen_pin = if trimmed_pin.is_empty() {
                parsed.pin
            } else {
                normalize_pin(trimmed_pin)?
            };
            let mut addrs = Vec::new();
            if let Some(addr) = parsed.addr {
                if !discovery::is_iroh_mapped_ip(&addr.ip()) {
                    addrs.push(addr);
                }
            } else if let Ok(peer) = self
                .resolve_peer(
                    &parsed.node_id.to_string(),
                    discovery::LAN_DIAL_TIMEOUT,
                )
                .await
            {
                if let Some(addr) = peer.addr {
                    addrs.push(addr);
                }
            }
            (parsed.node_id, addrs, chosen_pin)
        } else {
            let chosen_pin = normalize_pin(trimmed_pin)?;
            if let Some((node_part, addr_part)) = trimmed_target.split_once('@') {
                let node_id = NodeId::from_str(node_part.trim())
                    .map_err(|e| anyhow!("Invalid NodeId '{node_part}': {e}"))?;
                let sock = SocketAddr::from_str(addr_part.trim())
                    .map_err(|e| anyhow!("Invalid SocketAddr '{addr_part}': {e}"))?;
                (node_id, vec![sock], chosen_pin)
            } else if let Ok(sock) = SocketAddr::from_str(trimmed_target) {
                let peer = self
                    .resolve_peer_by_addr(sock, Duration::from_secs(5))
                    .await?;
                let addrs = peer.addr.into_iter().collect();
                (peer.node_id, addrs, chosen_pin)
            } else if let Ok(node_id) = NodeId::from_str(trimmed_target) {
                let mut addrs = Vec::new();
                if let Ok(peer) = self
                    .resolve_peer(trimmed_target, discovery::LAN_DIAL_TIMEOUT)
                    .await
                {
                    if let Some(addr) = peer.addr {
                        addrs.push(addr);
                    }
                }
                (node_id, addrs, chosen_pin)
            } else {
                let peer = self
                    .resolve_peer(trimmed_target, Duration::from_secs(5))
                    .await?;
                let addrs = peer.addr.into_iter().collect();
                (peer.node_id, addrs, chosen_pin)
            }
        };

        if let Some(known) = self
            .discovery
            .known_peers()
            .await
            .into_iter()
            .find(|p| p.node_id == peer_node_id)
        {
            if let Some(addr) = known.addr {
                if !lan_addrs.contains(&addr) {
                    lan_addrs.push(addr);
                }
            }
        }

        let was_wan = self.discovery.is_wan_transport_enabled();
        let (conn, connected_via_lan, endpoint) = if was_wan {
            let endpoint = self.discovery.acquire_endpoint().await;
            let (c, lan) =
                discovery::connect_lan_first(&endpoint, peer_node_id, &lan_addrs, true).await?;
            (c, lan, endpoint)
        } else if !lan_addrs.is_empty() {
            let endpoint = self.discovery.acquire_endpoint().await;
            match discovery::dial_lan_addrs_with_timeout(
                &endpoint,
                peer_node_id,
                &lan_addrs,
                discovery::LAN_DIAL_TIMEOUT,
            )
            .await
            {
                Ok((c, lan)) => (c, lan, endpoint),
                Err(_) => {
                    drop(endpoint);
                    self.discovery.reconfigure_wan_transport(true).await?;
                    let endpoint = self.discovery.acquire_endpoint().await;
                    match discovery::connect_lan_first(&endpoint, peer_node_id, &lan_addrs, true)
                        .await
                    {
                        Ok((c, lan)) => (c, lan, endpoint),
                        Err(err) => {
                            drop(endpoint);
                            let desired = self.discovery.desired_wan_state().await;
                            let _ = self.discovery.reconfigure_wan_transport(desired).await;
                            return Err(err.into());
                        }
                    }
                }
            }
        } else {
            self.discovery.reconfigure_wan_transport(true).await?;
            let endpoint = self.discovery.acquire_endpoint().await;
            match discovery::connect_lan_first(&endpoint, peer_node_id, &[], true).await {
                Ok((c, lan)) => (c, lan, endpoint),
                Err(err) => {
                    drop(endpoint);
                    let desired = self.discovery.desired_wan_state().await;
                    let _ = self.discovery.reconfigure_wan_transport(desired).await;
                    return Err(err.into());
                }
            }
        };

        let auth_remote = conn.remote_node_id()?;
        if auth_remote != peer_node_id {
            drop(conn);
            drop(endpoint);
            if !was_wan {
                let desired = self.discovery.desired_wan_state().await;
                let _ = self.discovery.reconfigure_wan_transport(desired).await;
            }
            bail!(
                "Remote TLS NodeId ({auth_remote}) did not match expected pairing target ({peer_node_id})"
            );
        }

        let handshake_res: Result<TrustedPeer> = async {
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

                    let mut trusted = self
                        .trust
                        .trust_peer(
                            confirm.responder_node_id,
                            confirm.display_name.clone(),
                            confirm.os_type,
                            true,
                        )
                        .await?;
                    let is_lan_pair = connected_via_lan
                        || self.discovery.is_connection_lan(&conn, &auth_remote).await;
                    if !is_lan_pair {
                        let _ = self
                            .trust
                            .set_peer_wan_enabled(&confirm.responder_node_id, true)
                            .await;
                        trusted.allow_wan = true;
                        let _ = self
                            .discovery
                            .record_paired_peer(
                                &endpoint,
                                confirm.responder_node_id,
                                confirm.display_name,
                                confirm.os_type,
                                None,
                            )
                            .await;
                    } else {
                        let real_lan_addr = lan_addrs
                            .iter()
                            .copied()
                            .find(|a| {
                                !discovery::is_iroh_mapped_ip(&a.ip())
                                    && discovery::is_local_lan_ip(&a.ip())
                            })
                            .or_else(|| {
                                discovery::best_direct_lan_addr_from_endpoint(
                                    &endpoint,
                                    confirm.responder_node_id,
                                )
                            });
                        self.discovery
                            .record_paired_peer(
                                &endpoint,
                                confirm.responder_node_id,
                                confirm.display_name,
                                confirm.os_type,
                                real_lan_addr,
                            )
                            .await?;
                    }
                    Ok(trusted)
                }
                other => bail!(
                    "Unexpected response to PairRequest: {:?}",
                    other.message_type()
                ),
            }
        }
        .await;

        conn.close(0u32.into(), b"paired");
        drop(conn);
        drop(endpoint);
        if handshake_res.is_err() || (connected_via_lan && !was_wan) {
            let desired = self.discovery.desired_wan_state().await;
            let _ = self.discovery.reconfigure_wan_transport(desired).await;
        }
        handshake_res
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
        let ep = self.discovery.acquire_endpoint().await;
        let conn = self.discovery.dial_peer(&ep, node_id).await?;
        let rtt = ping_peer(&conn, rand::random()).await?;
        conn.close(0u32.into(), b"ping");
        Ok(rtt)
    }

    /// Updates per-contact LAN (`auto_accept`) and WAN (`auto_accept_wan`) auto-accept settings.
    pub async fn set_peer_auto_accept(
        &self,
        node_id: NodeId,
        lan_auto: bool,
        wan_auto: bool,
    ) -> Result<bool> {
        Ok(self
            .trust
            .set_peer_auto_accept(&node_id, lan_auto, wan_auto)
            .await?)
    }

    /// Toggles long-distance WAN transfers for a trusted contact and dynamically enables/disables
    /// global Pkarr discovery and relay transport on the local endpoint.
    pub async fn set_peer_wan_enabled(&self, node_id: NodeId, enabled: bool) -> Result<bool> {
        let updated = self.trust.set_peer_wan_enabled(&node_id, enabled).await?;
        let wan_active = self.discovery.desired_wan_state().await;
        self.discovery.reconfigure_wan_transport(wan_active).await?;
        Ok(updated)
    }

    /// Removes a trusted contact from the trust store and disables WAN relay transport if no
    /// remaining contacts use long-distance transfers.
    pub async fn remove_trusted_peer(&self, node_id: &NodeId) -> Result<Option<TrustedPeer>> {
        let removed = self.trust.remove_peer(node_id).await?;
        let table = self.discovery.peer_table();
        table.write().await.remove_offline_peer(node_id);
        if removed.is_some() {
            let wan_active = self.discovery.desired_wan_state().await;
            self.discovery.reconfigure_wan_transport(wan_active).await?;
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
            .find(|p| p.addr == Some(target_addr))
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
                    if peer.addr == Some(target_addr) {
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
            .find(|p| p.addr == Some(target_addr))
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
        let ep = self.discovery.acquire_endpoint().await;
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
        let ep = self.discovery.acquire_endpoint().await;
        if let Some(sender_node_id) = self.transfer.paused_incoming_sender(transfer_id).await {
            let (conn, _) = self
                .discovery
                .dial_peer_with_path(&ep, sender_node_id)
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

        let (conn, connected_via_lan) = match self
            .discovery
            .dial_peer_with_path(&ep, info.peer_node_id)
            .await
        {
            Ok(pair) => pair,
            Err(err) => {
                self.paused_outgoing.write().await.insert(transfer_id, info);
                return Err(err.into());
            }
        };

        spawn_resumed_outgoing(
            Arc::clone(&self.discovery),
            Arc::clone(&self.transfer),
            Arc::clone(&self.trust),
            self.identity.hostname.clone(),
            Arc::clone(&self.paused_outgoing),
            Arc::clone(&self.active_resume_tasks),
            transfer_id,
            info,
            Some((conn, connected_via_lan)),
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

    /// Sends a single file or recursive directory using a pre-allocated `transfer_id` so callers
    /// can correlate `Connecting` -> `AwaitingApproval` -> `Sending` -> terminal events without
    /// duplicate cards on error.
    pub async fn send_path_for_id(
        &self,
        transfer_id: Uuid,
        peer_node_id: NodeId,
        source_path: impl AsRef<Path>,
        progress_tx: Option<mpsc::Sender<TransferProgress>>,
    ) -> Result<TransferSummary> {
        self.send_path_for_id_with_wan_override(
            transfer_id,
            peer_node_id,
            source_path,
            None,
            progress_tx,
        )
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
        self.send_path_for_id_with_wan_override(
            Uuid::new_v4(),
            peer_node_id,
            source_path,
            force_wan_encryption,
            progress_tx,
        )
        .await
    }

    /// Internal helper implementing pre-dial control registration (`PreControlHandle`) and
    /// consistent `transfer_id` lifecycle reporting across dial, approval, transfer, and errors.
    pub async fn send_path_for_id_with_wan_override(
        &self,
        transfer_id: Uuid,
        peer_node_id: NodeId,
        source_path: impl AsRef<Path>,
        force_wan_encryption: Option<bool>,
        progress_tx: Option<mpsc::Sender<TransferProgress>>,
    ) -> Result<TransferSummary> {
        let source_buf = source_path.as_ref().to_path_buf();
        let peer_name = self.resolve_peer_display_name(peer_node_id).await;
        let peer_label = peer_name
            .clone()
            .unwrap_or_else(|| peer_node_id.to_string());

        let (file_name, files_count, total_bytes) =
            match preview_source_summary(&source_buf).await {
                Ok(summary) => summary,
                Err(err) => {
                    let fallback_name = source_buf
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "Transfer".to_string());
                    self.transfer.emit_failed(
                        transfer_id,
                        TransferDirection::Outgoing,
                        peer_node_id,
                        peer_label,
                        fallback_name,
                        1,
                        0,
                        None,
                        err.to_string(),
                    );
                    return Err(err.into());
                }
            };

        let mut pre_ctrl = self.transfer.register_control(transfer_id).await;
        self.transfer.emit_started(
            transfer_id,
            peer_node_id,
            peer_label.clone(),
            file_name.clone(),
            files_count,
            total_bytes,
            0,
        );

        let ep = self.discovery.acquire_endpoint().await;
        let dial_res = tokio::select! {
            res = self.discovery.dial_peer_with_path(&ep, peer_node_id) => Some(res),
            _ = pre_ctrl.wait_control_signal() => None,
        };

        let (conn, connected_via_lan) = match dial_res {
            Some(Ok(pair)) => pair,
            Some(Err(err)) => {
                pre_ctrl.release().await;
                self.transfer.emit_failed(
                    transfer_id,
                    TransferDirection::Outgoing,
                    peer_node_id,
                    peer_label,
                    file_name,
                    files_count,
                    total_bytes,
                    None,
                    err.to_string(),
                );
                return Err(err.into());
            }
            None => {
                let (kind, reason) = pre_ctrl
                    .paused_or_cancelled_action()
                    .unwrap_or(("cancel", Some("Cancelled by user".to_string())));
                pre_ctrl.release().await;
                if kind == "pause" {
                    self.paused_outgoing.write().await.insert(
                        transfer_id,
                        PausedOutgoingInfo {
                            peer_node_id,
                            peer_name: Some(peer_label),
                            source_path: source_buf,
                        },
                    );
                    self.transfer
                        .emit_control_for_pre_control(transfer_id, kind, reason);
                    return Err(TransferError::Paused(transfer_id).into());
                }
                self.transfer
                    .emit_control_for_pre_control(transfer_id, kind, reason);
                return Err(TransferError::Cancelled(transfer_id).into());
            }
        };

        execute_send_with_wifi_recovery(
            &self.discovery,
            &self.transfer,
            &self.trust,
            &self.identity.hostname,
            transfer_id,
            peer_node_id,
            Some(peer_label.as_str()),
            &source_buf,
            progress_tx,
            &self.paused_outgoing,
            force_wan_encryption,
            conn,
            Some(pre_ctrl),
            connected_via_lan,
            false,
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
        if let Some(timer) = self.pairing_wan_timer.lock().await.take() {
            timer.abort();
        }
        self.control_task.abort();
        let _ = self.control_task.await;
        self.active_resume_tasks.lock().await.shutdown().await;
        let ep = self.discovery.try_endpoint();
        if let Ok(disc) = Arc::try_unwrap(self.discovery) {
            disc.shutdown().await;
        }
        if let Some(ep) = ep {
            let _ = tokio::time::timeout(Duration::from_millis(500), ep.close()).await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_send_with_wifi_recovery(
    discovery: &Arc<DiscoveryEngine>,
    transfer: &Arc<TransferEngine>,
    trust: &Arc<TrustStore>,
    local_hostname: &str,
    transfer_id: Uuid,
    peer_node_id: NodeId,
    peer_name: Option<&str>,
    source_path: &Path,
    progress_tx: Option<mpsc::Sender<TransferProgress>>,
    paused_outgoing: &Arc<RwLock<HashMap<Uuid, PausedOutgoingInfo>>>,
    force_wan_encryption: Option<bool>,
    initial_conn: Connection,
    initial_pre_ctrl: Option<PreControlHandle>,
    initial_connected_via_lan: bool,
    initial_emit_started_event: bool,
) -> Result<TransferSummary> {
    let first_attempt = run_tracked_send(
        transfer,
        &initial_conn,
        local_hostname,
        transfer_id,
        peer_node_id,
        peer_name,
        source_path,
        progress_tx.clone(),
        paused_outgoing,
        force_wan_encryption,
        initial_pre_ctrl,
        Some(initial_connected_via_lan),
        initial_emit_started_event,
    )
    .await;

    let Err(first_err) = first_attempt else {
        return first_attempt;
    };

    if !matches!(
        first_err.downcast_ref::<TransferError>(),
        Some(TransferError::DisconnectedMidTransfer { .. })
    ) {
        return Err(first_err);
    }

    let allow_wan_recovery = force_wan_encryption != Some(false)
        && trust.wan_secret_if_allowed(&peer_node_id).await.is_some();

    if allow_wan_recovery {
        let mut retry_ctrl = transfer.register_control(transfer_id).await;
        let aborted_during_grace = tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(2)) => false,
            _ = retry_ctrl.wait_control_signal() => true,
        };
        if aborted_during_grace {
            let (kind, reason) = retry_ctrl
                .paused_or_cancelled_action()
                .unwrap_or(("cancel", Some("Cancelled by user".to_string())));
            retry_ctrl.release().await;
            if kind == "pause" {
                paused_outgoing.write().await.insert(
                    transfer_id,
                    PausedOutgoingInfo {
                        peer_node_id,
                        peer_name: peer_name.map(ToOwned::to_owned),
                        source_path: source_path.to_path_buf(),
                    },
                );
            }
            transfer.emit_control_for_pre_control(transfer_id, kind, reason);
            return if kind == "pause" {
                Err(TransferError::Paused(transfer_id).into())
            } else {
                Err(TransferError::Cancelled(transfer_id).into())
            };
        }

        let ep = discovery.acquire_endpoint().await;
        let retry_dial = tokio::select! {
            res = discovery.dial_peer_with_path(&ep, peer_node_id) => Some(res),
            _ = retry_ctrl.wait_control_signal() => None,
        };

        match retry_dial {
            None => {
                let (kind, reason) = retry_ctrl
                    .paused_or_cancelled_action()
                    .unwrap_or(("cancel", Some("Cancelled by user".to_string())));
                retry_ctrl.release().await;
                if kind == "pause" {
                    paused_outgoing.write().await.insert(
                        transfer_id,
                        PausedOutgoingInfo {
                            peer_node_id,
                            peer_name: peer_name.map(ToOwned::to_owned),
                            source_path: source_path.to_path_buf(),
                        },
                    );
                }
                transfer.emit_control_for_pre_control(transfer_id, kind, reason);
                return if kind == "pause" {
                    Err(TransferError::Paused(transfer_id).into())
                } else {
                    Err(TransferError::Cancelled(transfer_id).into())
                };
            }
            Some(Ok((retry_conn, retry_via_lan))) => {
                let second_attempt = run_tracked_send(
                    transfer,
                    &retry_conn,
                    local_hostname,
                    transfer_id,
                    peer_node_id,
                    peer_name,
                    source_path,
                    progress_tx,
                    paused_outgoing,
                    force_wan_encryption,
                    Some(retry_ctrl),
                    Some(retry_via_lan),
                    false,
                )
                .await;
                match second_attempt {
                    Ok(summary) => return Ok(summary),
                    Err(retry_err)
                        if !matches!(
                            retry_err.downcast_ref::<TransferError>(),
                            Some(TransferError::DisconnectedMidTransfer { .. })
                        ) =>
                    {
                        return Err(retry_err);
                    }
                    Err(_) => {}
                }
            }
            Some(Err(_)) => {
                retry_ctrl.release().await;
            }
        }
    }

    paused_outgoing.write().await.insert(
        transfer_id,
        PausedOutgoingInfo {
            peer_node_id,
            peer_name: peer_name.map(ToOwned::to_owned),
            source_path: source_path.to_path_buf(),
        },
    );
    transfer.emit_paused(
        transfer_id,
        Some("Wi-Fi disconnected — tap Resume when back online".to_string()),
    );
    Err(TransferError::Paused(transfer_id).into())
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
    pre_control: Option<PreControlHandle>,
    connected_via_lan_hint: Option<bool>,
    emit_started_event: bool,
) -> Result<TransferSummary> {
    let res = transfer
        .send_path_with_control_and_wan(
            conn,
            local_hostname,
            source_path,
            peer_name,
            Some(transfer_id),
            progress_tx,
            force_wan_encryption,
            pre_control,
            connected_via_lan_hint,
            emit_started_event,
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
    trust: Arc<TrustStore>,
    local_hostname: String,
    paused_outgoing: Arc<RwLock<HashMap<Uuid, PausedOutgoingInfo>>>,
    active_resume_tasks: Arc<Mutex<JoinSet<()>>>,
    transfer_id: Uuid,
    info: PausedOutgoingInfo,
    pre_dialed: Option<(Connection, bool)>,
) {
    let mut tasks = active_resume_tasks.lock().await;
    tasks.spawn(async move {
        let ep = discovery.acquire_endpoint().await;
        let (conn, connected_via_lan, pre_ctrl, emit_started_event) = match pre_dialed {
            Some((c, via_lan)) => (c, via_lan, None, true),
            None => {
                let peer_label = info
                    .peer_name
                    .clone()
                    .unwrap_or_else(|| info.peer_node_id.to_string());
                let (file_name, files_count, total_bytes) =
                    match preview_source_summary(&info.source_path).await {
                        Ok(summary) => summary,
                        Err(err) => {
                            let fallback = info
                                .source_path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .map(ToString::to_string)
                                .unwrap_or_else(|| "Transfer".to_string());
                            transfer.emit_failed(
                                transfer_id,
                                TransferDirection::Outgoing,
                                info.peer_node_id,
                                peer_label,
                                fallback,
                                1,
                                0,
                                None,
                                err.to_string(),
                            );
                            return;
                        }
                    };
                let mut pre_ctrl = transfer.register_control(transfer_id).await;
                transfer.emit_started(
                    transfer_id,
                    info.peer_node_id,
                    peer_label.clone(),
                    file_name.clone(),
                    files_count,
                    total_bytes,
                    0,
                );
                let dial_res = tokio::select! {
                    res = discovery.dial_peer_with_path(&ep, info.peer_node_id) => Some(res),
                    _ = pre_ctrl.wait_control_signal() => None,
                };
                match dial_res {
                    Some(Ok((c, via_lan))) => (c, via_lan, Some(pre_ctrl), false),
                    Some(Err(err)) => {
                        pre_ctrl.release().await;
                        paused_outgoing.write().await.insert(transfer_id, info);
                        transfer.emit_paused(transfer_id, Some(err.to_string()));
                        return;
                    }
                    None => {
                        let (kind, reason) = pre_ctrl
                            .paused_or_cancelled_action()
                            .unwrap_or(("cancel", Some("Cancelled by user".to_string())));
                        pre_ctrl.release().await;
                        if kind == "pause" {
                            paused_outgoing.write().await.insert(transfer_id, info);
                        }
                        transfer.emit_control_for_pre_control(transfer_id, kind, reason);
                        return;
                    }
                }
            }
        };

        let _ = execute_send_with_wifi_recovery(
            &discovery,
            &transfer,
            &trust,
            &local_hostname,
            transfer_id,
            info.peer_node_id,
            info.peer_name.as_deref(),
            &info.source_path,
            None,
            &paused_outgoing,
            None,
            conn,
            pre_ctrl,
            connected_via_lan,
            emit_started_event,
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
