use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use beamdrop_core::transfer::{
    DEFAULT_APPROVAL_TIMEOUT, MAX_PARALLEL_STREAMS, ResumeMetadata, TransferError, TransferEvent,
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
    let ep = sender.endpoint();
    sender
        .discovery()
        .dial_addr(&ep, receiver.identity().node_id, receiver_addr)
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

#[tokio::test]
async fn test_bidirectional_pause_and_resume_transfer() {
    let tmp = TestTempDir::new("pause_resume");
    let total_bytes: u64 = 96 * 1024 * 1024;
    let src_file = tmp.path().join("pausable_96mb.bin");
    create_deterministic_file(&src_file, total_bytes, 0x1122_3344_5566_7788);
    let src_hash = hash_file_blake3(&src_file).await.expect("hash source file");

    let receiver = Arc::new(start_test_node(tmp.path(), "receiver").await);
    let sender = Arc::new(start_test_node(tmp.path(), "sender").await);
    pair_nodes_localhost(&sender, &receiver).await;

    let mut receiver_events = receiver.subscribe_transfers();
    let receiver_id = receiver.identity().node_id;

    let send_handle = tokio::spawn({
        let s = Arc::clone(&sender);
        let p = src_file.clone();
        async move { s.send_path(receiver_id, &p, None).await }
    });

    // Wait for receiver progress >= 4 MiB, then pause from the receiver side.
    let transfer_id = timeout(Duration::from_secs(30), async {
        loop {
            match receiver_events.recv().await {
                Ok(TransferEvent::Progress(p)) if p.bytes_transferred >= 4 * 1024 * 1024 => {
                    break p.transfer_id;
                }
                Ok(TransferEvent::Completed { .. }) => {
                    panic!("transfer finished before test could pause")
                }
                Ok(_) => continue,
                Err(e) => panic!("receiver event error: {e}"),
            }
        }
    })
    .await
    .expect("timed out waiting for progress before first pause");

    assert!(
        receiver.pause_transfer(transfer_id).await,
        "receiver pause_transfer should return true"
    );

    let first_err = timeout(Duration::from_secs(15), send_handle)
        .await
        .expect("sender timed out after pause")
        .expect("send task join error")
        .expect_err("send_path should stop with Paused");
    assert!(
        matches!(
            first_err.downcast_ref::<TransferError>(),
            Some(TransferError::Paused(id)) if *id == transfer_id
        ),
        "expected TransferError::Paused, got: {first_err:?}"
    );

    timeout(Duration::from_secs(10), async {
        loop {
            match receiver_events.recv().await {
                Ok(TransferEvent::Paused { transfer_id: pid, .. }) if pid == transfer_id => break,
                Ok(_) => continue,
                Err(e) => panic!("receiver event error: {e}"),
            }
        }
    })
    .await
    .expect("TransferEvent::Paused should be emitted on receiver after pause");

    let dst_file = receiver.download_dir().join("pausable_96mb.bin");
    assert!(
        resume_path_for(&dst_file).exists(),
        ".resume.json should be persisted after pause"
    );
    assert!(part_path_for(&dst_file).exists(), ".beamdrop.part should stay on disk when paused");

    // Resume from the receiver side (receiver sends Message::Resume to sender), then pause from sender!
    receiver
        .resume_transfer(transfer_id)
        .await
        .expect("receiver-initiated resume failed");

    // Wait until a second Progress event shows resumed flow (or completion), pause from sender if still active,
    // or wait for completion if fast enough, ensuring resumed completion succeeds cleanly.
    let paused_by_sender = timeout(Duration::from_secs(15), async {
        loop {
            match receiver_events.recv().await {
                Ok(TransferEvent::Progress(p)) if p.transfer_id == transfer_id && p.bytes_transferred >= 4 * 1024 * 1024 => {
                    break sender.pause_transfer(transfer_id).await;
                }
                Ok(TransferEvent::Completed { transfer_id: cid, .. }) if cid == transfer_id => {
                    break false;
                }
                Ok(_) => continue,
                Err(e) => panic!("receiver event error: {e}"),
            }
        }
    })
    .await
    .unwrap_or(false);

    if paused_by_sender {
        // Wait for TransferEvent::Paused on sender side before resuming from sender
        let mut sender_events = sender.subscribe_transfers();
        let _ = timeout(Duration::from_secs(10), async {
            loop {
                match sender_events.recv().await {
                    Ok(TransferEvent::Paused { transfer_id: pid, .. }) if pid == transfer_id => break,
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }
        })
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        sender
            .resume_transfer(transfer_id)
            .await
            .expect("sender-initiated resume failed");
    }

    let resumed_bytes = timeout(Duration::from_secs(60), async {
        loop {
            if dst_file.exists() {
                if let Ok(hash) = hash_file_blake3(&dst_file).await {
                    if hash == src_hash {
                        // Drain channel gently for Completed event if still in buffer
                        while let Ok(ev) = receiver_events.try_recv() {
                            if let TransferEvent::Completed {
                                transfer_id: cid,
                                bytes_skipped_resumed,
                                verified,
                                ..
                            } = ev
                            {
                                if cid == transfer_id {
                                    assert!(verified);
                                    return bytes_skipped_resumed;
                                }
                            }
                        }
                        return 1;
                    }
                }
            }
            match receiver_events.recv().await {
                Ok(TransferEvent::Completed {
                    transfer_id: cid,
                    bytes_skipped_resumed,
                    verified,
                    ..
                }) if cid == transfer_id => {
                    assert!(verified, "resumed transfer must verify BLAKE3");
                    break bytes_skipped_resumed;
                }
                Ok(_) => continue,
                Err(e) => panic!("receiver event error waiting for completion: {e}"),
            }
        }
    })
    .await
    .expect("timed out waiting for resumed transfer completion");

    assert!(resumed_bytes > 0, "expected bytes_skipped_resumed > 0 after pause/resume");
    assert!(!part_path_for(&dst_file).exists());
    assert!(!resume_path_for(&dst_file).exists());
    assert_eq!(hash_file_blake3(&dst_file).await.unwrap(), src_hash);

    if let Ok(node) = Arc::try_unwrap(sender) {
        node.shutdown().await;
    }
    if let Ok(node) = Arc::try_unwrap(receiver) {
        node.shutdown().await;
    }
}

#[tokio::test]
async fn test_cancel_while_active_and_while_paused_deletes_partials() {
    let tmp = TestTempDir::new("cancel_cleanup");
    let total_bytes: u64 = 96 * 1024 * 1024;
    let src_file = tmp.path().join("cancellable_96mb.bin");
    create_deterministic_file(&src_file, total_bytes, 0xAABB_CCDD_EEFF_0011);

    let receiver = Arc::new(start_test_node(tmp.path(), "receiver").await);
    let sender = Arc::new(start_test_node(tmp.path(), "sender").await);
    pair_nodes_localhost(&sender, &receiver).await;

    let mut receiver_events = receiver.subscribe_transfers();
    let receiver_id = receiver.identity().node_id;

    let send_handle = tokio::spawn({
        let s = Arc::clone(&sender);
        let p = src_file.clone();
        async move { s.send_path(receiver_id, &p, None).await }
    });

    let transfer_id = timeout(Duration::from_secs(30), async {
        loop {
            match receiver_events.recv().await {
                Ok(TransferEvent::Progress(p)) if p.bytes_transferred >= 2 * 1024 * 1024 => {
                    break p.transfer_id;
                }
                Ok(_) => continue,
                Err(e) => panic!("receiver event error: {e}"),
            }
        }
    })
    .await
    .expect("timed out waiting for progress before pause");

    assert!(sender.pause_transfer(transfer_id).await);
    let pause_err = timeout(Duration::from_secs(15), send_handle)
        .await
        .expect("send timed out on pause")
        .expect("join error")
        .expect_err("expected pause error");
    assert!(matches!(
        pause_err.downcast_ref::<TransferError>(),
        Some(TransferError::Paused(_))
    ));

    let dst_file = receiver.download_dir().join("cancellable_96mb.bin");
    timeout(Duration::from_secs(10), async {
        while !part_path_for(&dst_file).exists() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect(".beamdrop.part should exist while paused");

    // Cancel from sender side while transfer is already paused -> should delete receiver's partials!
    let cancel_ok = sender.cancel_transfer(transfer_id).await;
    assert!(cancel_ok);

    let got_cancel = timeout(Duration::from_secs(10), async {
        loop {
            match receiver_events.recv().await {
                Ok(TransferEvent::Cancelled { transfer_id: cid, .. }) if cid == transfer_id => {
                    break true;
                }
                Ok(_) => continue,
                Err(e) => panic!("receiver cancel wait error: {e}"),
            }
        }
    })
    .await;
    assert!(got_cancel.is_ok(), "receiver did not receive remote Cancel for paused transfer");

    assert!(!part_path_for(&dst_file).exists(), ".beamdrop.part must be deleted on Cancel");
    assert!(!resume_path_for(&dst_file).exists(), ".resume.json must be deleted on Cancel");
    assert!(!dst_file.exists(), "cancelled file must not be finalized");

    if let Ok(node) = Arc::try_unwrap(sender) {
        node.shutdown().await;
    }
    if let Ok(node) = Arc::try_unwrap(receiver) {
        node.shutdown().await;
    }
}

#[tokio::test]
async fn test_wan_opt_in_reconfigures_endpoint_and_encrypts_chunks() {
    let tmp = TestTempDir::new("wan_opt_in");
    let total_bytes: u64 = 512 * 1024 + 321;
    let payload_path = tmp.path().join("wan_secret_payload.bin");
    create_deterministic_file(&payload_path, total_bytes, 0xCAFE_BABE_1234_5678);
    let expected_hash = hash_file_blake3(&payload_path).await.unwrap();

    let alice = start_test_node(tmp.path(), "alice").await;
    let bob = start_test_node(tmp.path(), "bob").await;

    // 1. Fresh nodes default to strictly LAN-only (no WAN relay/discovery active)
    assert!(!alice.trust_store().any_wan_enabled().await);
    assert!(!alice.discovery().is_wan_transport_enabled());
    assert!(!bob.discovery().is_wan_transport_enabled());

    pair_nodes_localhost(&alice, &bob).await;

    // 2. Newly paired peer defaults to allow_wan == false with matching X25519 secret
    let alice_bob_entry = alice
        .trust_store()
        .get_peer(&bob.identity().node_id)
        .await
        .expect("Bob in Alice's trust store");
    let bob_alice_entry = bob
        .trust_store()
        .get_peer(&alice.identity().node_id)
        .await
        .expect("Alice in Bob's trust store");
    assert!(!alice_bob_entry.allow_wan);
    assert!(!bob_alice_entry.allow_wan);
    assert_ne!(alice_bob_entry.wan_shared_secret, [0u8; 32]);
    assert_eq!(
        alice_bob_entry.wan_shared_secret,
        bob_alice_entry.wan_shared_secret
    );

    // 3. Attempting a WAN-encrypted transfer when Alice has allow_wan=false fails immediately
    let blocked_err = alice
        .send_path_with_wan_override(bob.identity().node_id, &payload_path, Some(true), None)
        .await
        .expect_err("WAN transfer must be blocked when allow_wan is false");
    assert!(
        blocked_err.to_string().contains("Long-distance")
            || matches!(
                blocked_err.downcast_ref::<TransferError>(),
                Some(TransferError::WanDisallowed(_))
            )
    );

    // 4. Enabling WAN on Alice reconfigures DiscoveryEngine WAN transport, yet Bob (allow_wan=false) still rejects it
    assert!(alice
        .set_peer_wan_enabled(bob.identity().node_id, true)
        .await
        .unwrap());
    assert!(alice.discovery().is_wan_transport_enabled());

    let peer_rejected = alice
        .send_path_with_wan_override(bob.identity().node_id, &payload_path, Some(true), None)
        .await
        .expect_err("Bob must reject WAN transfer while his allow_wan is false");
    assert!(
        peer_rejected.to_string().contains("disabled"),
        "unexpected error: {peer_rejected}"
    );

    // 5. Enabling WAN on Bob completes end-to-end daily-rotating ChaCha20-Poly1305 encrypted transfer
    assert!(bob
        .set_peer_wan_enabled(alice.identity().node_id, true)
        .await
        .unwrap());
    assert!(bob.discovery().is_wan_transport_enabled());

    let mut bob_events = bob.subscribe_transfers();
    let summary = alice
        .send_path_with_wan_override(bob.identity().node_id, &payload_path, Some(true), None)
        .await
        .expect("WAN encrypted transfer succeeds once both peers opt in");
    assert_eq!(summary.files_count, 1);
    assert_eq!(summary.total_bytes, total_bytes);

    timeout(Duration::from_secs(10), async {
        loop {
            match bob_events.recv().await {
                Ok(TransferEvent::Completed {
                    transfer_id,
                    verified,
                    ..
                }) if transfer_id == summary.transfer_id => {
                    assert!(verified, "decrypted WAN file must pass BLAKE3 verification");
                    break;
                }
                Ok(_) => continue,
                Err(e) => panic!("bob event channel error: {e}"),
            }
        }
    })
    .await
    .expect("timed out waiting for WAN transfer completion");

    let received = bob.download_dir().join("wan_secret_payload.bin");
    let got_hash = hash_file_blake3(&received).await.unwrap();
    assert_eq!(got_hash, expected_hash);

    // 6. Disabling WAN on Alice tears down WAN relay transport back to strictly LAN-only mode
    assert!(alice
        .set_peer_wan_enabled(bob.identity().node_id, false)
        .await
        .unwrap());
    assert!(!alice.trust_store().any_wan_enabled().await);
    assert!(!alice.discovery().is_wan_transport_enabled());

    alice.shutdown().await;
    bob.shutdown().await;
}
