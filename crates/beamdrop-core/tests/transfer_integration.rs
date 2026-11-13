use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use beamdrop_core::transfer::{
    DEFAULT_APPROVAL_TIMEOUT, MAX_PARALLEL_STREAMS, ResumeMetadata, TransferEvent,
    TransferProgress, hash_file_blake3, part_path_for, resume_path_for,
};
use beamdrop_core::{BeamDropNode, NodeConfig, PeerEvent};
use tokio::sync::mpsc;
use tokio::time::timeout;

static NEXT_DIR_ID: AtomicU64 = AtomicU64::new(1);

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn new(label: &str) -> Self {
        let id = NEXT_DIR_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "beamdrop_it_{}_{}_{}",
            label,
            std::process::id(),
            id
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create integration test temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn create_deterministic_file(path: &Path, size_bytes: u64, seed: u64) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    let file = File::create(path).expect("create deterministic file");
    let mut writer = BufWriter::with_capacity(1024 * 1024, file);

    let mut state = seed | 1;
    let mut buf = vec![0u8; 1024 * 1024];
    let mut remaining = size_bytes;

    while remaining > 0 {
        let to_write = remaining.min(buf.len() as u64) as usize;
        for chunk in buf[..to_write].chunks_exact_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        let rem = to_write % 8;
        if rem > 0 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let bytes = state.to_le_bytes();
            buf[to_write - rem..to_write].copy_from_slice(&bytes[..rem]);
        }
        writer
            .write_all(&buf[..to_write])
            .expect("write deterministic bytes");
        remaining -= to_write as u64;
    }
    writer.flush().expect("flush deterministic file");
}

async fn start_test_node(root: &Path, name: &str) -> BeamDropNode {
    let config_dir = root.join(format!("{name}_cfg"));
    let download_dir = root.join(format!("{name}_dl"));
    BeamDropNode::start(NodeConfig {
        config_dir: Some(config_dir),
        download_dir: Some(download_dir),
        display_name: Some(name.to_string()),
        port: 0,
    })
    .await
    .expect("start BeamDropNode")
}

async fn connect_localhost(sender: &BeamDropNode, receiver: &BeamDropNode) {
    let receiver_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), receiver.listen_port());
    sender
        .discovery()
        .dial_addr(sender.endpoint(), receiver.identity().node_id, receiver_addr)
        .await
        .expect("dial receiver over localhost");
}

async fn pair_nodes_localhost(initiator: &BeamDropNode, responder: &BeamDropNode) {
    let session = responder
        .start_pairing_session()
        .await
        .expect("start pairing session");
    let target = format!(
        "{}@127.0.0.1:{}",
        responder.identity().node_id,
        responder.listen_port()
    );
    initiator
        .pair_with_peer(&target, &session.pin)
        .await
        .expect("pair initiator with responder");
}

#[tokio::test]
async fn test_transfer_250mb_localhost_and_verify_blake3() {
    let tmp = TestTempDir::new("250mb");
    let total_bytes: u64 = 250 * 1024 * 1024;
    let src_file = tmp.path().join("payload_250mb.bin");
    create_deterministic_file(&src_file, total_bytes, 0xCAFE_BABE_1234_5678);

    let src_hash = hash_file_blake3(&src_file)
        .await
        .expect("hash source file");

    let receiver = start_test_node(tmp.path(), "receiver").await;
    let sender = start_test_node(tmp.path(), "sender").await;
    pair_nodes_localhost(&sender, &receiver).await;

    let mut receiver_events = receiver.subscribe_transfers();
    let (progress_tx, mut progress_rx) = mpsc::channel::<TransferProgress>(64);
    let progress_task = tokio::spawn(async move {
        let mut updates = 0usize;
        let mut max_streams = 0usize;
        while let Some(p) = progress_rx.recv().await {
            updates += 1;
            max_streams = max_streams.max(p.streams_active);
        }
        (updates, max_streams)
    });

    let summary = timeout(
        Duration::from_secs(120),
        sender.send_path(receiver.identity().node_id, &src_file, Some(progress_tx)),
    )
    .await
    .expect("250 MB transfer timed out")
    .expect("250 MB transfer failed");

    let (_updates, max_streams) = progress_task.await.expect("progress collector task");
    assert_eq!(summary.files_count, 1);
    assert_eq!(summary.total_bytes, total_bytes);
    assert_eq!(summary.bytes_sent, total_bytes);
    assert_eq!(summary.bytes_skipped_resumed, 0);
    assert_eq!(summary.streams_used, MAX_PARALLEL_STREAMS);
    assert_eq!(max_streams, MAX_PARALLEL_STREAMS);
    assert_eq!(summary.file_hashes.len(), 1);
    assert_eq!(summary.file_hashes[0].blake3, src_hash);

    // Wait for receiver completion event
    let completed = timeout(Duration::from_secs(10), async {
        loop {
            match receiver_events.recv().await {
                Ok(TransferEvent::Completed {
                    transfer_id,
                    verified,
                    total_bytes: ev_total,
                    ..
                }) if transfer_id == summary.transfer_id => {
                    assert!(verified, "receiver should verify BLAKE3");
                    assert_eq!(ev_total, total_bytes);
                    break;
                }
                Ok(_) => continue,
                Err(e) => panic!("receiver event channel failed: {e}"),
            }
        }
    })
    .await;
    completed.expect("timed out waiting for receiver Completed event");

    let dst_file = receiver.download_dir().join("payload_250mb.bin");
    assert!(dst_file.exists(), "received file must exist");
    assert!(
        !part_path_for(&dst_file).exists(),
        ".beamdrop.part should be renamed cleanly"
    );
    assert!(
        !resume_path_for(&dst_file).exists(),
        ".resume.json should be removed on completion"
    );

    let dst_hash = hash_file_blake3(&dst_file)
        .await
        .expect("hash destination file");
    assert_eq!(dst_hash, src_hash, "BLAKE3 mismatch after 250 MB transfer");

    sender.shutdown().await;
    receiver.shutdown().await;
}

#[tokio::test]
async fn test_resume_after_simulated_mid_transfer_disconnect() {
    let tmp = TestTempDir::new("resume");
    let total_bytes: u64 = 128 * 1024 * 1024;
    let src_file = tmp.path().join("resumable_128mb.bin");
    create_deterministic_file(&src_file, total_bytes, 0xDEAD_BEEF_9988_7766);

    let src_hash = hash_file_blake3(&src_file)
        .await
        .expect("hash source file");

    let receiver = start_test_node(tmp.path(), "receiver").await;
    let sender1 = Arc::new(start_test_node(tmp.path(), "sender1").await);
    pair_nodes_localhost(&sender1, &receiver).await;

    let mut receiver_events = receiver.subscribe_transfers();
    let receiver_id = receiver.identity().node_id;

    let transfer_handle = tokio::spawn({
        let sender = Arc::clone(&sender1);
        let src = src_file.clone();
        async move { sender.send_path(receiver_id, &src, None).await }
    });

    // Wait until the receiver confirms at least 8 MiB flushed to disk, then force-close sender1.
    timeout(Duration::from_secs(60), async {
        loop {
            match receiver_events.recv().await {
                Ok(TransferEvent::Progress(p)) if p.bytes_transferred >= 8 * 1024 * 1024 => {
                    assert!(
                        p.bytes_transferred < total_bytes,
                        "transfer completed too quickly before disconnect test could abort"
                    );
                    break;
                }
                Ok(TransferEvent::Completed { .. }) => {
                    panic!("transfer finished unexpectedly before simulated disconnect");
                }
                Ok(_) => continue,
                Err(e) => panic!("receiver event channel error: {e}"),
            }
        }
    })
    .await
    .expect("timed out waiting for partial progress before abort");

    transfer_handle.abort();
    let _ = transfer_handle.await;
    sender1.endpoint().close().await;

    // Wait for receiver to detect disconnect and persist .resume.json
    timeout(Duration::from_secs(20), async {
        loop {
            match receiver_events.recv().await {
                Ok(TransferEvent::Interrupted { .. }) => break,
                Ok(TransferEvent::Completed { .. }) => {
                    panic!("transfer should have been interrupted, not completed");
                }
                Ok(_) => continue,
                Err(e) => panic!("receiver event channel failed waiting for Interrupted: {e}"),
            }
        }
    })
    .await
    .expect("timed out waiting for receiver Interrupted event");

    let dst_file = receiver.download_dir().join("resumable_128mb.bin");
    let dst_part = part_path_for(&dst_file);
    let dst_resume = resume_path_for(&dst_file);
    assert!(dst_part.exists(), ".beamdrop.part must remain after disconnect");
    assert!(dst_resume.exists(), ".resume.json must exist after disconnect");
    assert!(!dst_file.exists(), "final file must not exist before completion");

    let partial_meta = ResumeMetadata::load(&dst_resume).expect("load resume metadata");
    assert!(
        partial_meta.verified_chunk_count() > 0,
        "expected > 0 verified chunks before disconnect"
    );
    assert!(
        partial_meta.verified_chunk_count() < partial_meta.total_chunks,
        "expected partial transfer (< total_chunks), got {}/{}",
        partial_meta.verified_chunk_count(),
        partial_meta.total_chunks
    );

    if let Ok(node) = Arc::try_unwrap(sender1) {
        node.shutdown().await;
    }

    // Reconnect with a fresh sender node and resume strictly from missing chunks
    let sender2 = start_test_node(tmp.path(), "sender2").await;
    pair_nodes_localhost(&sender2, &receiver).await;

    let resumed_summary = timeout(
        Duration::from_secs(120),
        sender2.send_path(receiver_id, &src_file, None),
    )
    .await
    .expect("resumed transfer timed out")
    .expect("resumed transfer failed");

    assert_eq!(resumed_summary.total_bytes, total_bytes);
    assert!(
        resumed_summary.bytes_skipped_resumed > 0,
        "expected resumed bytes skipped > 0"
    );
    assert!(
        resumed_summary.bytes_sent < total_bytes,
        "expected fewer bytes sent on resume than full file size"
    );
    assert_eq!(
        resumed_summary.bytes_sent + resumed_summary.bytes_skipped_resumed,
        total_bytes
    );

    assert!(dst_file.exists(), "final file must exist after resume");
    assert!(!dst_part.exists(), ".beamdrop.part should be removed after resume");
    assert!(!dst_resume.exists(), ".resume.json should be removed after resume");

    let dst_hash = hash_file_blake3(&dst_file)
        .await
        .expect("hash resumed destination file");
    assert_eq!(dst_hash, src_hash, "BLAKE3 mismatch after resumed transfer");

    sender2.shutdown().await;
    receiver.shutdown().await;
}

#[tokio::test]
async fn test_transfer_recursive_directory_preserves_structure() {
    let tmp = TestTempDir::new("dir");
    let src_dir = tmp.path().join("bundle");
    let f1 = src_dir.join("root.bin");
    let f2 = src_dir.join("sub").join("nested.bin");
    let f3 = src_dir.join("sub").join("deep").join("leaf.bin");

    create_deterministic_file(&f1, 4_096, 11);
    create_deterministic_file(&f2, 300_000, 22);
    create_deterministic_file(&f3, 700_013, 33);

    let h1 = hash_file_blake3(&f1).await.expect("hash f1");
    let h2 = hash_file_blake3(&f2).await.expect("hash f2");
    let h3 = hash_file_blake3(&f3).await.expect("hash f3");

    let receiver = start_test_node(tmp.path(), "receiver").await;
    let sender = start_test_node(tmp.path(), "sender").await;
    pair_nodes_localhost(&sender, &receiver).await;

    let summary = timeout(
        Duration::from_secs(60),
        sender.send_path(receiver.identity().node_id, &src_dir, None),
    )
    .await
    .expect("directory transfer timed out")
    .expect("directory transfer failed");

    assert_eq!(summary.files_count, 3);
    assert_eq!(summary.streams_used, 1);

    let out_root = receiver.download_dir().join("bundle");
    let d1 = out_root.join("root.bin");
    let d2 = out_root.join("sub").join("nested.bin");
    let d3 = out_root.join("sub").join("deep").join("leaf.bin");

    assert_eq!(hash_file_blake3(&d1).await.expect("hash d1"), h1);
    assert_eq!(hash_file_blake3(&d2).await.expect("hash d2"), h2);
    assert_eq!(hash_file_blake3(&d3).await.expect("hash d3"), h3);

    sender.shutdown().await;
    receiver.shutdown().await;
}

#[tokio::test]
async fn test_pin_pairing_handshake_valid_and_wrong_pin() {
    let tmp = TestTempDir::new("pair_pin");
    let responder = start_test_node(tmp.path(), "responder").await;
    let initiator = start_test_node(tmp.path(), "initiator").await;

    let mut peer_events = responder.subscribe_peers();
    let session = responder
        .start_pairing_session()
        .await
        .expect("start pairing session");
    assert_eq!(session.pin.len(), 6);
    assert!(session.uri.starts_with("beamdrop://pair?node="));

    let wrong_pin = if session.pin == "000000" {
        "111111"
    } else {
        "000000"
    };
    let target = format!(
        "{}@127.0.0.1:{}",
        responder.identity().node_id,
        responder.listen_port()
    );

    // Wrong PIN must be rejected and leave both TrustStores clean
    let err = initiator
        .pair_with_peer(&target, wrong_pin)
        .await
        .expect_err("wrong PIN must fail pairing");
    assert!(
        err.to_string().contains("Invalid pairing PIN"),
        "unexpected error: {err}"
    );
    assert!(
        responder
            .trust_store()
            .get_peer(&initiator.identity().node_id)
            .await
            .is_none()
    );
    assert!(
        initiator
            .trust_store()
            .get_peer(&responder.identity().node_id)
            .await
            .is_none()
    );

    // Valid PIN must succeed, emit PeerEvent::Paired, and record mutual trust
    let paired = initiator
        .pair_with_peer(&target, &session.pin)
        .await
        .expect("valid PIN must succeed pairing");
    assert_eq!(paired.node_id, responder.identity().node_id);
    assert!(paired.auto_accept);

    timeout(Duration::from_secs(5), async {
        loop {
            match peer_events.recv().await {
                Ok(PeerEvent::Paired(p)) if p.node_id == initiator.identity().node_id => break,
                Ok(_) => continue,
                Err(e) => panic!("peer event channel error: {e}"),
            }
        }
    })
    .await
    .expect("timed out waiting for PeerEvent::Paired on responder");

    assert!(
        responder
            .trust_store()
            .is_auto_accept_trusted(&initiator.identity().node_id)
            .await
    );
    assert!(
        initiator
            .trust_store()
            .is_auto_accept_trusted(&responder.identity().node_id)
            .await
    );
    assert!(
        responder
            .discovery()
            .known_peers()
            .await
            .iter()
            .any(|p| p.node_id == initiator.identity().node_id),
        "known_peers.json should be updated on pairing"
    );

    // PIN is one-time only and cannot be reused after successful handshake
    let reuse_err = initiator
        .pair_with_peer(&target, &session.pin)
        .await
        .expect_err("consumed PIN must not work twice");
    assert!(reuse_err.to_string().contains("No active pairing session"));

    initiator.shutdown().await;
    responder.shutdown().await;
}

#[tokio::test]
async fn test_paired_device_auto_accepts_immediately() {
    let tmp = TestTempDir::new("auto_accept");
    let src_file = tmp.path().join("auto_accepted_1mb.bin");
    create_deterministic_file(&src_file, 1024 * 1024, 0x1234_ABCD);
    let src_hash = hash_file_blake3(&src_file).await.expect("hash source file");

    let receiver = start_test_node(tmp.path(), "receiver").await;
    let sender = start_test_node(tmp.path(), "sender").await;
    pair_nodes_localhost(&sender, &receiver).await;

    let mut transfer_events = receiver.subscribe_transfers();
    let summary = timeout(
        Duration::from_secs(30),
        sender.send_path(receiver.identity().node_id, &src_file, None),
    )
    .await
    .expect("auto-accepted transfer timed out")
    .expect("auto-accepted transfer failed");

    let mut saw_auto_accepted = false;
    let mut saw_completed = false;
    timeout(Duration::from_secs(5), async {
        while !(saw_auto_accepted && saw_completed) {
            match transfer_events.recv().await {
                Ok(TransferEvent::AutoAccepted {
                    transfer_id,
                    sender_node_id,
                    ..
                }) if transfer_id == summary.transfer_id => {
                    assert_eq!(sender_node_id, sender.identity().node_id);
                    saw_auto_accepted = true;
                }
                Ok(TransferEvent::PendingApproval { transfer_id, .. })
                    if transfer_id == summary.transfer_id =>
                {
                    panic!("paired device with auto_accept=true must not trigger PendingApproval");
                }
                Ok(TransferEvent::Completed {
                    transfer_id,
                    verified,
                    ..
                }) if transfer_id == summary.transfer_id => {
                    assert!(verified);
                    saw_completed = true;
                }
                Ok(_) => continue,
                Err(e) => panic!("transfer event channel failed: {e}"),
            }
        }
    })
    .await
    .expect("timed out waiting for AutoAccepted + Completed events");

    let dst_file = receiver.download_dir().join("auto_accepted_1mb.bin");
    assert_eq!(hash_file_blake3(&dst_file).await.unwrap(), src_hash);

    sender.shutdown().await;
    receiver.shutdown().await;
}

#[tokio::test]
async fn test_untrusted_peer_held_pending_and_rejected() {
    assert_eq!(DEFAULT_APPROVAL_TIMEOUT, Duration::from_secs(60));

    let tmp = TestTempDir::new("untrusted");
    let src_file = tmp.path().join("stranger_file.bin");
    create_deterministic_file(&src_file, 256 * 1024, 0xFACE_B00C);
    let src_hash = hash_file_blake3(&src_file).await.expect("hash source file");

    let receiver = Arc::new(start_test_node(tmp.path(), "receiver").await);
    let untrusted_sender = Arc::new(start_test_node(tmp.path(), "stranger").await);
    connect_localhost(&untrusted_sender, &receiver).await;

    let mut receiver_events = receiver.subscribe_transfers();
    let receiver_id = receiver.identity().node_id;

    // 1. Verify offer from untrusted peer is held in PendingApproval and rejected when declined
    let send_handle = tokio::spawn({
        let s = Arc::clone(&untrusted_sender);
        let p = src_file.clone();
        async move { s.send_path(receiver_id, &p, None).await }
    });

    let held_transfer_id = timeout(Duration::from_secs(10), async {
        loop {
            match receiver_events.recv().await {
                Ok(TransferEvent::PendingApproval {
                    transfer_id,
                    sender_node_id,
                    ..
                }) => {
                    assert_eq!(sender_node_id, untrusted_sender.identity().node_id);
                    break transfer_id;
                }
                Ok(TransferEvent::AutoAccepted { .. }) => {
                    panic!("untrusted sender must never be auto-accepted");
                }
                Ok(_) => continue,
                Err(e) => panic!("receiver transfer event error: {e}"),
            }
        }
    })
    .await
    .expect("timed out waiting for PendingApproval");

    assert!(
        receiver
            .transfer()
            .pending_offer_ids()
            .await
            .contains(&held_transfer_id),
        "offer must remain held in pending map until respond_to_offer"
    );

    receiver
        .respond_to_offer(held_transfer_id, false)
        .await
        .expect("decline held offer");

    let send_err = timeout(Duration::from_secs(10), send_handle)
        .await
        .expect("send task did not finish after rejection")
        .expect("send task panicked")
        .expect_err("declined untrusted transfer must fail on sender");
    assert!(
        send_err.to_string().contains("rejected"),
        "expected Rejected error, got: {send_err}"
    );
    let dst_file = receiver.download_dir().join("stranger_file.bin");
    assert!(!dst_file.exists(), "declined file must not exist on disk");

    // 2. Verify unresponded offers auto-reject on approval timeout
    receiver
        .transfer()
        .set_approval_timeout(Duration::from_millis(250))
        .await;

    let timeout_send = timeout(
        Duration::from_secs(10),
        untrusted_sender.send_path(receiver_id, &src_file, None),
    )
    .await
    .expect("timeout rejection test hung")
    .expect_err("unanswered untrusted offer must reject after timeout");
    assert!(
        timeout_send.to_string().contains("rejected")
            || timeout_send.to_string().contains("timed out"),
        "expected timeout rejection error, got: {timeout_send}"
    );
    assert!(!dst_file.exists());

    // 3. Verify explicit manual acceptance via respond_to_offer(id, true) allows transfer
    receiver
        .transfer()
        .set_approval_timeout(Duration::from_secs(10))
        .await;
    let mut receiver_events = receiver.subscribe_transfers();
    let accept_handle = tokio::spawn({
        let s = Arc::clone(&untrusted_sender);
        let p = src_file.clone();
        async move { s.send_path(receiver_id, &p, None).await }
    });

    let pending_id = timeout(Duration::from_secs(10), async {
        loop {
            match receiver_events.recv().await {
                Ok(TransferEvent::PendingApproval { transfer_id, .. }) => break transfer_id,
                Ok(_) => continue,
                Err(e) => panic!("receiver transfer event error: {e}"),
            }
        }
    })
    .await
    .expect("timed out waiting for second PendingApproval");

    receiver
        .respond_to_offer(pending_id, true)
        .await
        .expect("manually approve held offer");

    let accepted_summary = timeout(Duration::from_secs(15), accept_handle)
        .await
        .expect("manually approved transfer timed out")
        .expect("join error")
        .expect("manually approved transfer failed");
    assert_eq!(accepted_summary.transfer_id, pending_id);
    assert_eq!(hash_file_blake3(&dst_file).await.unwrap(), src_hash);

    if let Ok(node) = Arc::try_unwrap(untrusted_sender) {
        node.shutdown().await;
    }
    if let Ok(node) = Arc::try_unwrap(receiver) {
        node.shutdown().await;
    }
}
