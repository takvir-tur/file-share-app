use std::fs::{self, OpenOptions};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use beamdrop_core::{
    BeamDropNode, DeviceIdentity, NodeConfig, PeerEvent, PeerInfo, PeerTable, TransferEvent,
    TransferProgress, TrustStore, KNOWN_PEERS_FILENAME, MDNS_SERVICE_TYPE, TRUSTED_PEERS_FILENAME,
};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use iroh::NodeId;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "beamdrop",
    version,
    about = "BeamDrop P2P LAN file sharing & discovery CLI"
)]
struct Cli {
    /// Optional custom configuration directory (defaults to OS config dir `BeamDrop/`)
    #[arg(long, global = true)]
    config_dir: Option<PathBuf>,

    /// Optional display name override for this instance
    #[arg(long, short = 'n', global = true)]
    name: Option<String>,

    /// Optional local UDP port for the Iroh QUIC endpoint (0 = OS-assigned)
    #[arg(long, short = 'p', global = true, default_value_t = 0)]
    port: u16,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the BeamDrop background daemon: advertise via mDNS and accept QUIC connections & transfers
    Daemon {
        /// Output directory for received files (defaults to `Downloads/BeamDrop`)
        #[arg(long, short = 'o')]
        output_dir: Option<PathBuf>,
    },

    /// Discover active and cached BeamDrop peers on the local network
    Peers {
        /// Discovery window in seconds before printing summary and exiting
        #[arg(long, short = 't', default_value_t = 3)]
        timeout_secs: u64,

        /// Keep watching for peer events continuously instead of exiting after timeout
        #[arg(long, short = 'w')]
        watch: bool,

        /// Verify connectivity to discovered peers with a QUIC Ping/Pong handshake
        #[arg(long, default_value_t = true)]
        ping: bool,
    },

    /// Send a file or directory recursively to a peer by display name or NodeId
    Send {
        /// Target peer display name, NodeId, or unique NodeId prefix
        peer: String,

        /// Path to the file or directory to transfer
        path: PathBuf,

        /// Discovery timeout in seconds when locating the peer on the LAN
        #[arg(long, short = 't', default_value_t = 5)]
        timeout_secs: u64,
    },

    /// Pair a device using a 6-digit PIN and pairing URI (responder by default, or `--peer` + `--pin` to initiate)
    Pair {
        /// Target peer NodeId, pairing URI (`beamdrop://pair?...`), display name, or LAN SocketAddr
        #[arg(long)]
        peer: Option<String>,

        /// 6-digit numeric pairing PIN displayed by the target peer
        #[arg(long)]
        pin: Option<String>,

        /// Timeout in seconds when waiting for an incoming pairing request
        #[arg(long, short = 't', default_value_t = 300)]
        timeout_secs: u64,
    },

    /// Manage cryptographically paired trusted devices (`trusted_peers.json`)
    Trust {
        #[command(subcommand)]
        action: TrustCommands,
    },
}

#[derive(Debug, Subcommand)]
enum TrustCommands {
    /// List all paired trusted devices
    List,

    /// Remove a trusted device from `trusted_peers.json`
    Remove {
        /// NodeId (or unique prefix / alias) of the trusted device to remove
        node_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon { output_dir } => {
            run_daemon(cli.config_dir, output_dir, cli.name, cli.port).await
        }
        Commands::Peers {
            timeout_secs,
            watch,
            ping,
        } => {
            run_peers(
                cli.config_dir,
                cli.name,
                cli.port,
                Duration::from_secs(timeout_secs),
                watch,
                ping,
            )
            .await
        }
        Commands::Send {
            peer,
            path,
            timeout_secs,
        } => {
            run_send(
                cli.config_dir,
                cli.name,
                cli.port,
                peer,
                path,
                Duration::from_secs(timeout_secs),
            )
            .await
        }
        Commands::Pair {
            peer,
            pin,
            timeout_secs,
        } => {
            run_pair(
                cli.config_dir,
                cli.name,
                cli.port,
                peer,
                pin,
                Duration::from_secs(timeout_secs),
            )
            .await
        }
        Commands::Trust { action } => match action {
            TrustCommands::List => run_trust_list(cli.config_dir).await,
            TrustCommands::Remove { node_id } => run_trust_remove(cli.config_dir, node_id).await,
        },
    }
}

async fn run_daemon(
    custom_config_dir: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    display_name: Option<String>,
    port: u16,
) -> Result<()> {
    let config_dir = resolve_daemon_config_dir(custom_config_dir)?;
    let node = BeamDropNode::start(NodeConfig {
        config_dir: Some(config_dir.clone()),
        download_dir: output_dir,
        display_name,
        port,
    })
    .await
    .context("Failed to start BeamDrop node")?;

    let id = node.identity();
    println!("=== BeamDrop Daemon Started ===");
    println!("  Device UUID : {}", id.device_id);
    println!("  NodeId      : {}", id.node_id);
    println!("  Hostname    : {}", id.hostname);
    println!("  OS Type     : {}", id.os_type);
    println!("  QUIC Port   : {}", node.listen_port());
    println!("  mDNS Service: {}", MDNS_SERVICE_TYPE);
    println!("  Config Dir  : {}", config_dir.display());
    println!("  Output Dir  : {}", node.download_dir().display());
    println!("Listening for peers and incoming transfers... (Press Ctrl+C to stop)\n");

    let mut peer_events = node.subscribe_peers();
    let mut transfer_events = node.subscribe_transfers();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\nShutting down BeamDrop daemon...");
                break;
            }
            event = peer_events.recv() => {
                match event {
                    Ok(PeerEvent::Discovered(peer)) => {
                        println!(
                            "[DISCOVERED] {} ({}) | NodeId: {} | Addr: {}",
                            peer.display_name,
                            peer.os_type,
                            peer.node_id,
                            peer.addr.map_or_else(|| "WAN".to_string(), |a| a.to_string())
                        );
                    }
                    Ok(PeerEvent::Lost(peer)) => {
                        println!(
                            "[LOST]       {} ({}) | NodeId: {} | Last Addr: {}",
                            peer.display_name,
                            peer.os_type,
                            peer.node_id,
                            peer.addr.map_or_else(|| "WAN".to_string(), |a| a.to_string())
                        );
                    }
                    Ok(PeerEvent::Paired(peer)) => {
                        println!(
                            "[PAIRED]     {} ({}) | NodeId: {} | Auto-accept enabled",
                            peer.display_name,
                            peer.os_type,
                            peer.node_id,
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            t_event = transfer_events.recv() => {
                match t_event {
                    Ok(TransferEvent::OfferReceived { transfer_id, sender_name, files, total_bytes }) => {
                        println!(
                            "[TRANSFER OFFER] {} | From: {} | {} file(s) ({:.2} MB)",
                            transfer_id,
                            sender_name,
                            files,
                            total_bytes as f64 / (1024.0 * 1024.0)
                        );
                    }
                    Ok(TransferEvent::AutoAccepted { transfer_id, sender_node_id, sender_name, files, total_bytes }) => {
                        println!(
                            "[AUTO-ACCEPTED] {} | Trusted peer: {} ({}) | {} file(s) ({:.2} MB)",
                            transfer_id,
                            sender_name,
                            sender_node_id,
                            files,
                            total_bytes as f64 / (1024.0 * 1024.0)
                        );
                    }
                    Ok(TransferEvent::PendingApproval { transfer_id, sender_node_id, sender_name, file_name, files, total_bytes, is_wan, .. }) => {
                        let via = if is_wan { "WAN" } else { "LAN" };
                        println!(
                            "[PENDING APPROVAL] {} | {} | Peer: {} ({}) | {} ({} file(s), {:.2} MB) | Held up to 60s before rejection",
                            transfer_id,
                            via,
                            sender_name,
                            sender_node_id,
                            file_name,
                            files,
                            total_bytes as f64 / (1024.0 * 1024.0)
                        );
                    }
                    Ok(TransferEvent::AwaitingApproval { transfer_id, peer_name, file_name, files, total_bytes, is_wan, .. }) => {
                        let via = if is_wan { "WAN" } else { "LAN" };
                        println!(
                            "[AWAITING APPROVAL] {} | {} | Receiver: {} | {} ({} file(s), {:.2} MB)",
                            transfer_id,
                            via,
                            peer_name,
                            file_name,
                            files,
                            total_bytes as f64 / (1024.0 * 1024.0)
                        );
                    }
                    Ok(TransferEvent::Completed { transfer_id, files, total_bytes, bytes_transferred, bytes_skipped_resumed, verified, output_dir }) => {
                        println!(
                            "[TRANSFER COMPLETE] {} | {} file(s) | Total: {:.2} MB | Wire: {:.2} MB | Resumed: {:.2} MB | Verified: {} | Dir: {}",
                            transfer_id,
                            files,
                            total_bytes as f64 / (1024.0 * 1024.0),
                            bytes_transferred as f64 / (1024.0 * 1024.0),
                            bytes_skipped_resumed as f64 / (1024.0 * 1024.0),
                            verified,
                            output_dir.map(|d| d.display().to_string()).unwrap_or_default()
                        );
                    }
                    Ok(TransferEvent::Started { transfer_id, files, total_bytes, .. }) => {
                        println!(
                            "[TRANSFER STARTED] {} | {} file(s) ({:.2} MB)",
                            transfer_id,
                            files,
                            total_bytes as f64 / (1024.0 * 1024.0)
                        );
                    }
                    Ok(TransferEvent::Paused { transfer_id, reason }) => {
                        println!("[TRANSFER PAUSED] {} | {}", transfer_id, reason.unwrap_or_default());
                    }
                    Ok(TransferEvent::Cancelled { transfer_id, reason }) => {
                        println!("[TRANSFER CANCELLED] {} | {}", transfer_id, reason.unwrap_or_default());
                    }
                    Ok(TransferEvent::Interrupted { transfer_id, reason }) => {
                        println!("[TRANSFER INTERRUPTED] {} | {}", transfer_id, reason);
                    }
                    Ok(TransferEvent::Failed { transfer_id, peer_name, file_name, reason, .. }) => {
                        println!(
                            "[TRANSFER FAILED] {} | Peer: {} | Item: {} | {}",
                            transfer_id, peer_name, file_name, reason
                        );
                    }
                    Ok(TransferEvent::Progress(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    node.shutdown().await;
    let _ = fs::remove_file(config_dir.join("daemon.pid"));
    Ok(())
}

async fn run_peers(
    custom_config_dir: Option<PathBuf>,
    display_name: Option<String>,
    port: u16,
    wait_duration: Duration,
    watch: bool,
    verify_ping: bool,
) -> Result<()> {
    let (base_dir, scanner_dir, scanner_name) =
        prepare_ephemeral_client_dir(custom_config_dir, display_name, "scanner")?;

    let node = BeamDropNode::start(NodeConfig {
        config_dir: Some(scanner_dir.clone()),
        download_dir: None,
        display_name: scanner_name,
        port,
    })
    .await
    .context("Failed to start BeamDrop discovery node")?;

    println!(
        "Scanning LAN ({}) as {} (NodeId: {}, port: {})...",
        MDNS_SERVICE_TYPE,
        node.identity().hostname,
        node.identity().node_id,
        node.listen_port()
    );

    let mut events = node.subscribe_peers();
    let start = Instant::now();

    if watch {
        println!("Watching for peer events... (Press Ctrl+C to exit)");
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                Ok(ev) = events.recv() => {
                    print_peer_event(&node, ev, verify_ping).await;
                }
            }
        }
    } else {
        let deadline = tokio::time::Instant::now() + wait_duration;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, events.recv()).await {
                Ok(Ok(ev)) => {
                    print_peer_event(&node, ev, verify_ping).await;
                }
                _ => break,
            }
        }
    }

    sync_discovered_peers_back(&node, &base_dir, &scanner_dir).await;

    let peers = node.discovery().known_peers().await;
    println!(
        "\n=== Known Peers ({} total, scanned in {:.2?}) ===",
        peers.len(),
        start.elapsed()
    );
    if peers.is_empty() {
        println!("No peers discovered on the local network.");
    } else {
        for peer in &peers {
            let status = if peer.online { "ONLINE" } else { "CACHED" };
            println!(
                "  - [{status}] {} ({}) | NodeId: {} | SocketAddr: {}",
                peer.display_name, peer.os_type, peer.node_id, peer.addr.map_or_else(|| "WAN".to_string(), |a| a.to_string())
            );
        }
    }

    node.shutdown().await;
    if scanner_dir != base_dir {
        let _ = fs::remove_dir_all(&scanner_dir);
    }
    Ok(())
}

async fn run_send(
    custom_config_dir: Option<PathBuf>,
    display_name: Option<String>,
    port: u16,
    peer_query: String,
    path: PathBuf,
    discovery_timeout: Duration,
) -> Result<()> {
    if !path.exists() {
        bail!("Source path does not exist: {}", path.display());
    }

    let (base_dir, sender_dir, sender_name) =
        prepare_persistent_client_dir(custom_config_dir, display_name, "sender")?;

    let node = BeamDropNode::start(NodeConfig {
        config_dir: Some(sender_dir.clone()),
        download_dir: None,
        display_name: sender_name,
        port,
    })
    .await
    .context("Failed to start BeamDrop sender node")?;

    println!("Resolving peer '{}'...", peer_query);
    let peer = node
        .resolve_peer(&peer_query, discovery_timeout)
        .await
        .with_context(|| format!("Could not find peer '{peer_query}'"))?;

    println!(
        "Connected target: {} ({}) | NodeId: {} | Addr: {}",
        peer.display_name, peer.os_type, peer.node_id, peer.addr.map_or_else(|| "WAN".to_string(), |a| a.to_string())
    );

    let (progress_tx, mut progress_rx) = mpsc::channel::<TransferProgress>(64);
    let pb = ProgressBar::new(0);
    let style = ProgressStyle::with_template(
        "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({msg}) eta {eta}",
    )?
    .progress_chars("=>-");
    pb.set_style(style);

    let send_start = Instant::now();
    let pb_clone = pb.clone();
    let ui_task = tokio::spawn(async move {
        let mut initialized = false;
        while let Some(prog) = progress_rx.recv().await {
            if !initialized && prog.total_bytes > 0 {
                pb_clone.set_length(prog.total_bytes);
                initialized = true;
            }
            let elapsed = send_start.elapsed().as_secs_f64().max(0.001);
            let mb_per_sec = (prog.bytes_transferred as f64 / (1024.0 * 1024.0)) / elapsed;
            let completed = prog.bytes_transferred + prog.bytes_skipped_resumed;
            pb_clone.set_position(completed.min(prog.total_bytes));
            pb_clone.set_message(format!(
                "{:.2} MB/s | {} stream(s) | {}",
                mb_per_sec, prog.streams_active, prog.file_name
            ));
        }
    });

    let result = node
        .send_path(peer.node_id, &path, Some(progress_tx))
        .await;

    let _ = ui_task.await;

    match result {
        Ok(summary) => {
            pb.set_length(summary.total_bytes.max(1));
            pb.set_position(summary.total_bytes.max(1));
            let elapsed_secs = summary.elapsed.as_secs_f64().max(0.001);
            let avg_mb_s = (summary.bytes_sent as f64 / (1024.0 * 1024.0)) / elapsed_secs;
            pb.finish_with_message(format!(
                "{:.2} MB/s | {} stream(s) | BLAKE3 verified",
                avg_mb_s, summary.streams_used
            ));
            println!(
                "\nTransfer complete ({}): {} file(s), {:.2} MB total ({:.2} MB sent, {:.2} MB resumed) in {:.2?} ({:.2} MB/s)",
                summary.transfer_id,
                summary.files_count,
                summary.total_bytes as f64 / (1024.0 * 1024.0),
                summary.bytes_sent as f64 / (1024.0 * 1024.0),
                summary.bytes_skipped_resumed as f64 / (1024.0 * 1024.0),
                summary.elapsed,
                avg_mb_s
            );
            sync_discovered_peers_back(&node, &base_dir, &sender_dir).await;
            node.shutdown().await;
            if sender_dir != base_dir {
                let _ = fs::remove_dir_all(&sender_dir);
            }
            Ok(())
        }
        Err(err) => {
            pb.abandon_with_message(format!("Failed: {err}"));
            sync_discovered_peers_back(&node, &base_dir, &sender_dir).await;
            node.shutdown().await;
            if sender_dir != base_dir {
                let _ = fs::remove_dir_all(&sender_dir);
            }
            Err(err)
        }
    }
}

async fn run_pair(
    custom_config_dir: Option<PathBuf>,
    display_name: Option<String>,
    port: u16,
    peer: Option<String>,
    pin: Option<String>,
    wait_duration: Duration,
) -> Result<()> {
    match (peer, pin) {
        (Some(target), maybe_pin) => {
            let trimmed_target = target.trim();
            let effective_pin = match maybe_pin {
                Some(p) => p,
                None if trimmed_target.starts_with("beamdrop://") => String::new(),
                None => bail!("--pin <6_digit_pin> is required when pairing with --peer"),
            };

            let (base_dir, client_dir, client_name) =
                prepare_persistent_client_dir(custom_config_dir, display_name, "pair")?;

            let node = BeamDropNode::start(NodeConfig {
                config_dir: Some(client_dir.clone()),
                download_dir: None,
                display_name: client_name,
                port,
            })
            .await
            .context("Failed to start BeamDrop pairing initiator node")?;

            println!("Initiating pairing handshake with '{trimmed_target}'...");
            let res = node.pair_with_peer(trimmed_target, &effective_pin).await;

            match res {
                Ok(trusted) => {
                    sync_discovered_peers_back(&node, &base_dir, &client_dir).await;
                    sync_trusted_peers_back(&node, &base_dir, &client_dir).await;
                    println!(
                        "Paired cleanly with {} ({}) | NodeId: {} | Auto-accept: {}",
                        trusted.friendly_alias,
                        trusted.os_type,
                        trusted.node_id,
                        trusted.auto_accept
                    );
                    node.shutdown().await;
                    if client_dir != base_dir {
                        let _ = fs::remove_dir_all(&client_dir);
                    }
                    Ok(())
                }
                Err(err) => {
                    sync_discovered_peers_back(&node, &base_dir, &client_dir).await;
                    node.shutdown().await;
                    if client_dir != base_dir {
                        let _ = fs::remove_dir_all(&client_dir);
                    }
                    Err(err)
                }
            }
        }
        (None, Some(_)) => {
            bail!("--peer <node_id_or_addr> is required when passing --pin")
        }
        (None, None) => {
            let config_dir = match custom_config_dir {
                Some(dir) => dir,
                None => DeviceIdentity::config_dir()?,
            };
            if is_daemon_active_in(&config_dir) {
                bail!(
                    "Another beamdrop daemon is active in '{}'; stop it before running responder `beamdrop pair` or pass a distinct `--config-dir`",
                    config_dir.display()
                );
            }
            fs::create_dir_all(&config_dir)?;

            let node = BeamDropNode::start(NodeConfig {
                config_dir: Some(config_dir),
                download_dir: None,
                display_name,
                port,
            })
            .await
            .context("Failed to start BeamDrop pairing responder node")?;

            let session = node.start_pairing_session().await?;
            println!("=== BeamDrop Device Pairing Session Ready ===");
            println!("  Device Name : {}", node.identity().hostname);
            println!("  NodeId      : {}", session.node_id);
            println!("  LAN Addr    : {}", session.addr);
            println!("  6-Digit PIN : {} (valid for 5 minutes)", session.pin);
            println!("  Pairing URI : {}", session.uri);
            println!("\nWaiting for an incoming pairing request... (Press Ctrl+C to cancel)");

            let mut events = node.subscribe_peers();
            let outcome = tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("\nPairing cancelled.");
                    Ok(())
                }
                res = timeout(wait_duration, async {
                    loop {
                        match events.recv().await {
                            Ok(PeerEvent::Paired(peer)) => break Ok(peer),
                            Ok(_) => continue,
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(e) => break Err(anyhow::Error::from(e)),
                        }
                    }
                }) => match res {
                    Ok(Ok(peer)) => {
                        println!(
                            "\n[PAIRED] {} ({}) | NodeId: {} | Saved to trusted_peers.json (auto_accept = true)",
                            peer.display_name, peer.os_type, peer.node_id
                        );
                        Ok(())
                    }
                    Ok(Err(e)) => Err(e),
                    Err(_) => {
                        println!("\nPairing session timed out.");
                        Ok(())
                    }
                }
            };

            node.shutdown().await;
            outcome
        }
    }
}

async fn run_trust_list(custom_config_dir: Option<PathBuf>) -> Result<()> {
    let (store, _) = open_trust_store_offline(custom_config_dir)?;
    let peers = store.list_peers().await;
    println!("=== Trusted Peers ({}) ===", peers.len());
    if peers.is_empty() {
        println!("No trusted devices paired.");
    } else {
        for p in peers {
            println!(
                "  - {} ({}) | NodeId: {} | Auto-Accept: {} | Paired At (unix): {}",
                p.friendly_alias, p.os_type, p.node_id, p.auto_accept, p.paired_at_unix
            );
        }
    }
    Ok(())
}

async fn run_trust_remove(custom_config_dir: Option<PathBuf>, query: String) -> Result<()> {
    let (store, _) = open_trust_store_offline(custom_config_dir)?;
    let trimmed = query.trim();
    if trimmed.is_empty() {
        bail!("NodeId cannot be empty");
    }

    let target_id = if let Ok(exact) = NodeId::from_str(trimmed) {
        exact
    } else {
        let q_lower = trimmed.to_ascii_lowercase();
        let peers = store.list_peers().await;
        let matches: Vec<_> = peers
            .into_iter()
            .filter(|p| {
                p.node_id
                    .to_string()
                    .to_ascii_lowercase()
                    .starts_with(&q_lower)
                    || p.friendly_alias.to_ascii_lowercase() == q_lower
            })
            .collect();
        match matches.len() {
            0 => bail!("No trusted device matching '{trimmed}' found"),
            1 => matches[0].node_id,
            _ => bail!("Multiple trusted devices match '{trimmed}'; specify full NodeId"),
        }
    };

    if let Some(removed) = store.remove_peer(&target_id).await? {
        println!(
            "Removed trusted device {} ({}) | NodeId: {}",
            removed.friendly_alias, removed.os_type, removed.node_id
        );
        Ok(())
    } else {
        bail!("Device {target_id} was not in trusted_peers.json")
    }
}

fn open_trust_store_offline(custom_config_dir: Option<PathBuf>) -> Result<(TrustStore, PathBuf)> {
    let config_dir = match custom_config_dir {
        Some(dir) => dir,
        None => DeviceIdentity::config_dir()?,
    };
    fs::create_dir_all(&config_dir)?;
    let identity_path = config_dir.join("identity.json");
    let local_id = if identity_path.exists() {
        DeviceIdentity::load_or_create_at(&identity_path)?.node_id
    } else {
        DeviceIdentity::generate().node_id
    };
    let trust_path = config_dir.join(TRUSTED_PEERS_FILENAME);
    let store = TrustStore::load_or_create(&trust_path, local_id)?;
    Ok((store, config_dir))
}

fn prepare_persistent_client_dir(
    custom_config_dir: Option<PathBuf>,
    display_name: Option<String>,
    role: &str,
) -> Result<(PathBuf, PathBuf, Option<String>)> {
    let base_dir = match custom_config_dir {
        Some(dir) => dir,
        None => DeviceIdentity::config_dir()?,
    };

    let client_dir = if is_daemon_active_in(&base_dir) {
        let dir = base_dir
            .join(role)
            .join(format!("cli-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        for file in [
            "identity.json",
            KNOWN_PEERS_FILENAME,
            TRUSTED_PEERS_FILENAME,
        ] {
            let src = base_dir.join(file);
            let dst = dir.join(file);
            if src.exists() && !dst.exists() {
                let _ = fs::copy(&src, &dst);
            }
        }
        dir
    } else {
        base_dir.clone()
    };

    Ok((base_dir, client_dir, display_name))
}

async fn sync_trusted_peers_back(node: &BeamDropNode, base_dir: &PathBuf, client_dir: &PathBuf) {
    if client_dir != base_dir {
        let base_trust_path = base_dir.join(TRUSTED_PEERS_FILENAME);
        if let Ok(base_store) = TrustStore::load_or_create(&base_trust_path, node.identity().node_id)
        {
            for peer in node.trust_store().list_peers().await {
                if peer.node_id != node.identity().node_id {
                    let _ = base_store
                        .trust_peer(
                            peer.node_id,
                            peer.friendly_alias,
                            peer.os_type,
                            peer.auto_accept,
                        )
                        .await;
                }
            }
        }
    }
}

fn prepare_ephemeral_client_dir(
    custom_config_dir: Option<PathBuf>,
    display_name: Option<String>,
    role: &str,
) -> Result<(PathBuf, PathBuf, Option<String>)> {
    let base_dir = match custom_config_dir {
        Some(dir) => dir,
        None => DeviceIdentity::config_dir()?,
    };

    let client_dir = if is_daemon_active_in(&base_dir) {
        let dir = base_dir
            .join(role)
            .join(format!("cli-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let shared_peers = base_dir.join(KNOWN_PEERS_FILENAME);
        let client_peers = dir.join(KNOWN_PEERS_FILENAME);
        if shared_peers.exists() && !client_peers.exists() {
            let _ = fs::copy(&shared_peers, &client_peers);
        }
        dir
    } else {
        base_dir.clone()
    };

    let effective_name = display_name.or_else(|| {
        if client_dir != base_dir {
            Some(format!(
                "{}-{role}",
                beamdrop_core::identity::detect_hostname()
            ))
        } else {
            None
        }
    });

    Ok((base_dir, client_dir, effective_name))
}

async fn sync_discovered_peers_back(
    node: &BeamDropNode,
    base_dir: &PathBuf,
    client_dir: &PathBuf,
) {
    if client_dir != base_dir {
        if let Ok(mut main_table) = PeerTable::load_or_create(base_dir.join(KNOWN_PEERS_FILENAME)) {
            for peer in node.discovery().known_peers().await {
                if peer.node_id != node.identity().node_id {
                    let _ = main_table.upsert(peer, None);
                }
            }
        }
    }
}

async fn print_peer_event(node: &BeamDropNode, event: PeerEvent, verify_ping: bool) {
    match event {
        PeerEvent::Discovered(peer) => {
            if verify_ping {
                let dial_start = Instant::now();
                match node.ping(peer.node_id).await {
                    Ok(rtt) => {
                        println!(
                            "[DISCOVERED] {} ({}) | NodeId: {} | Addr: {} | Direct QUIC dial+ping: {:.2?} (RTT: {:.2?})",
                            peer.display_name,
                            peer.os_type,
                            peer.node_id,
                            peer.addr.map_or_else(|| "WAN".to_string(), |a| a.to_string()),
                            dial_start.elapsed(),
                            rtt
                        );
                    }
                    Err(_) => {
                        println!(
                            "[DISCOVERED] {} ({}) | NodeId: {} | Addr: {}",
                            peer.display_name, peer.os_type, peer.node_id, peer.addr.map_or_else(|| "WAN".to_string(), |a| a.to_string())
                        );
                    }
                }
            } else {
                println!(
                    "[DISCOVERED] {} ({}) | NodeId: {} | Addr: {}",
                    peer.display_name, peer.os_type, peer.node_id, peer.addr.map_or_else(|| "WAN".to_string(), |a| a.to_string())
                );
            }
        }
        PeerEvent::Lost(PeerInfo {
            display_name,
            os_type,
            node_id,
            addr,
            ..
        }) => {
            println!(
                "[LOST]       {} ({}) | NodeId: {} | Last Addr: {}",
                display_name,
                os_type,
                node_id,
                addr.map_or_else(|| "WAN".to_string(), |a| a.to_string())
            );
        }
        PeerEvent::Paired(peer) => {
            println!(
                "[PAIRED]     {} ({}) | NodeId: {} | Auto-accept enabled",
                peer.display_name, peer.os_type, peer.node_id
            );
        }
    }
}

/// Resolves the config directory for `beamdrop daemon`. If another daemon is already active
/// in the default `BeamDrop/` directory and no custom `--config-dir` was provided, automatically
/// allocates a per-instance subdirectory so multiple local daemons get distinct identities.
fn resolve_daemon_config_dir(custom: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = custom {
        fs::create_dir_all(&dir)?;
        write_pid_marker(&dir);
        return Ok(dir);
    }

    let default_dir = DeviceIdentity::config_dir()?;
    fs::create_dir_all(&default_dir)?;

    if !is_daemon_active_in(&default_dir) {
        write_pid_marker(&default_dir);
        return Ok(default_dir);
    }

    let instance_dir = default_dir
        .join("instances")
        .join(format!("node-{}", std::process::id()));
    fs::create_dir_all(&instance_dir)?;
    write_pid_marker(&instance_dir);
    Ok(instance_dir)
}

fn write_pid_marker(dir: &PathBuf) {
    let pid_file = dir.join("daemon.pid");
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(pid_file)
    {
        use std::io::Write;
        let _ = write!(f, "{}", std::process::id());
    }
}

fn is_daemon_active_in(dir: &PathBuf) -> bool {
    let pid_file = dir.join("daemon.pid");
    let Ok(raw) = fs::read_to_string(pid_file) else {
        return false;
    };
    let Ok(pid) = raw.trim().parse::<u32>() else {
        return false;
    };
    if pid == std::process::id() {
        return false;
    }
    #[cfg(unix)]
    {
        // kill(pid, 0) checks if a process with `pid` exists
        unsafe { libc_kill(pid as i32, 0) == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(unix)]
extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}
