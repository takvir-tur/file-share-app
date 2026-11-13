use std::collections::HashMap;
use std::fs;
use std::io::SeekFrom;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
#[cfg(not(target_os = "android"))]
use directories::UserDirs;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::NodeId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex, RwLock};
use tokio::task::{JoinHandle, JoinSet};
use uuid::Uuid;

#[cfg(not(target_os = "android"))]
use crate::identity::DeviceIdentity;
use crate::protocol::{
    read_frame, transfer_stream_id, write_frame, AcceptPayload, AcceptedFileResume, ChunkRange,
    CompletePayload, FileHashEntry, FileOfferEntry, Message, OfferPayload, ProtocolError,
    RejectPayload,
};
use crate::trust::TrustStore;

/// Chunk size used for bounded disk streaming, incremental BLAKE3 hashing, and resume tracking.
pub const CHUNK_SIZE: usize = 128 * 1024; // 128 KiB

/// File/transfer threshold above which parallel QUIC uni-stream striping is enabled.
pub const PARALLEL_STRIPE_THRESHOLD: u64 = 32 * 1024 * 1024; // 32 MiB

/// Maximum number of concurrent unidirectional QUIC data streams per transfer.
pub const MAX_PARALLEL_STREAMS: usize = 6;

/// Bounded channel capacity (`24 * 128 KiB = 3 MiB`) keeping total RAM well under 15 MB.
pub const CHANNEL_BOUND: usize = 24;

/// Fixed big-endian header length preceding every chunk on unidirectional data streams.
/// Layout: `[u64 transfer_id | u32 file_index | u64 byte_offset | u32 chunk_len]`.
pub const UNI_CHUNK_HEADER_LEN: usize = 24;

/// Default timeout before rejecting unapproved incoming offers from untrusted peers.
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("I/O error during transfer: {0}")]
    Io(#[from] std::io::Error),
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Source path does not exist or contains no transferable files: {0}")]
    EmptySource(PathBuf),
    #[error("Unsafe or invalid relative path in offer manifest: {0}")]
    InvalidRelativePath(String),
    #[error("Transfer {0} rejected by peer: {1}")]
    Rejected(Uuid, String),
    #[error("Unexpected control message: {0}")]
    UnexpectedMessage(String),
    #[error("QUIC transport error: {0}")]
    Quic(String),
    #[error("Invalid 24-byte chunk header on stream for transfer {transfer_id}")]
    InvalidChunkHeader { transfer_id: u64 },
    #[error("Transfer {transfer_id} interrupted mid-transfer with {remaining_chunks} chunks remaining")]
    DisconnectedMidTransfer {
        transfer_id: Uuid,
        remaining_chunks: u64,
    },
    #[error("BLAKE3 integrity verification failed for file '{relative_path}'")]
    IntegrityMismatch { relative_path: String },
}

/// 24-byte big-endian chunk header written on unidirectional QUIC streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    pub transfer_id: u64,
    pub file_index: u32,
    pub byte_offset: u64,
    pub chunk_len: u32,
}

impl ChunkHeader {
    /// Serializes the 24-byte big-endian header:
    /// `[u64 transfer_id | u32 file_index | u64 byte_offset | u32 chunk_len]`.
    pub fn encode(&self) -> [u8; UNI_CHUNK_HEADER_LEN] {
        let mut buf = [0u8; UNI_CHUNK_HEADER_LEN];
        buf[0..8].copy_from_slice(&self.transfer_id.to_be_bytes());
        buf[8..12].copy_from_slice(&self.file_index.to_be_bytes());
        buf[12..20].copy_from_slice(&self.byte_offset.to_be_bytes());
        buf[20..24].copy_from_slice(&self.chunk_len.to_be_bytes());
        buf
    }

    /// Parses a 24-byte big-endian chunk header.
    pub fn decode(buf: &[u8; UNI_CHUNK_HEADER_LEN]) -> Self {
        Self {
            transfer_id: u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            file_index: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            byte_offset: u64::from_be_bytes([
                buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
            ]),
            chunk_len: u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]),
        }
    }
}

/// Live progress snapshot emitted during send and receive transfers.
#[derive(Debug, Clone)]
pub struct TransferProgress {
    pub transfer_id: Uuid,
    pub file_name: String,
    pub bytes_transferred: u64,
    pub bytes_skipped_resumed: u64,
    pub total_bytes: u64,
    pub streams_active: usize,
}

/// Summary returned upon successful completion of a transfer.
#[derive(Debug, Clone)]
pub struct TransferSummary {
    pub transfer_id: Uuid,
    pub files_count: usize,
    pub total_bytes: u64,
    pub bytes_sent: u64,
    pub bytes_skipped_resumed: u64,
    pub streams_used: usize,
    pub elapsed: Duration,
    pub file_hashes: Vec<FileHashEntry>,
}

/// Events published by `TransferEngine` over a `tokio::sync::broadcast` channel.
#[derive(Debug, Clone)]
pub enum TransferEvent {
    OfferReceived {
        transfer_id: Uuid,
        sender_name: String,
        files: usize,
        total_bytes: u64,
    },
    AutoAccepted {
        transfer_id: Uuid,
        sender_node_id: NodeId,
        sender_name: String,
        files: usize,
        total_bytes: u64,
    },
    PendingApproval {
        transfer_id: Uuid,
        sender_node_id: NodeId,
        sender_name: String,
        files: usize,
        total_bytes: u64,
    },
    Progress(TransferProgress),
    Completed {
        transfer_id: Uuid,
        files: usize,
        total_bytes: u64,
        bytes_transferred: u64,
        bytes_skipped_resumed: u64,
        verified: bool,
        output_dir: Option<PathBuf>,
    },
    Interrupted {
        transfer_id: Uuid,
        reason: String,
    },
}

/// On-disk resume state stored in `<filename>.resume.json` alongside `<filename>.beamdrop.part`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeMetadata {
    pub relative_path: String,
    pub size_bytes: u64,
    pub chunk_size: u32,
    pub total_chunks: u64,
    pub head_blake3: Option<[u8; 32]>,
    pub bitmap_hex: String,
    #[serde(skip)]
    bitmap: Vec<u8>,
}

impl ResumeMetadata {
    /// Initializes an empty resume bitmap for a file of `size_bytes`.
    pub fn new(relative_path: String, size_bytes: u64, head_blake3: Option<[u8; 32]>) -> Self {
        let total_chunks = chunk_count_for_size(size_bytes);
        let byte_len = (total_chunks as usize).div_ceil(8);
        let bitmap = vec![0u8; byte_len];
        let bitmap_hex = encode_hex(&bitmap);
        Self {
            relative_path,
            size_bytes,
            chunk_size: CHUNK_SIZE as u32,
            total_chunks,
            head_blake3,
            bitmap_hex,
            bitmap,
        }
    }

    /// Loads `ResumeMetadata` from `<file>.resume.json`.
    pub fn load(path: &Path) -> Result<Self, TransferError> {
        let raw = fs::read_to_string(path)?;
        let mut meta: Self = serde_json::from_str(&raw)?;
        let expected_bytes = (meta.total_chunks as usize).div_ceil(8);
        let decoded = decode_hex(&meta.bitmap_hex)
            .ok_or_else(|| TransferError::InvalidRelativePath("corrupt resume bitmap".into()))?;
        if decoded.len() != expected_bytes {
            return Err(TransferError::InvalidRelativePath(
                "resume bitmap length mismatch".into(),
            ));
        }
        meta.bitmap = decoded;
        Ok(meta)
    }

    /// Saves `ResumeMetadata` atomically via a temporary `.tmp` file + rename.
    pub fn save(&mut self, path: &Path) -> Result<(), TransferError> {
        self.bitmap_hex = encode_hex(&self.bitmap);
        let json = serde_json::to_string(self)?;
        let tmp_path = append_suffix(path, ".tmp");
        fs::write(&tmp_path, json)?;
        fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Checks whether this resume metadata matches an incoming `FileOfferEntry`.
    pub fn matches_offer(&self, entry: &FileOfferEntry, part_file_len: u64) -> bool {
        self.relative_path == entry.relative_path
            && self.size_bytes == entry.size_bytes
            && self.chunk_size == CHUNK_SIZE as u32
            && self.total_chunks == chunk_count_for_size(entry.size_bytes)
            && self.head_blake3 == entry.head_blake3
            && part_file_len <= entry.size_bytes
    }

    /// Clears any chunk bits whose byte range exceeds the actual `.beamdrop.part` file size on disk.
    pub fn clamp_to_file_len(&mut self, part_file_len: u64) {
        for idx in 0..self.total_chunks {
            if self.is_chunk_verified(idx) {
                let end_offset = chunk_end_offset(self.size_bytes, idx);
                if end_offset > part_file_len {
                    self.clear_chunk(idx);
                }
            }
        }
    }

    /// Returns true if chunk `chunk_idx` is verified in the bitmap.
    pub fn is_chunk_verified(&self, chunk_idx: u64) -> bool {
        if chunk_idx >= self.total_chunks {
            return false;
        }
        let byte_idx = (chunk_idx / 8) as usize;
        let bit_mask = 1u8 << (chunk_idx % 8);
        (self.bitmap[byte_idx] & bit_mask) != 0
    }

    /// Marks `chunk_idx` as verified. Returns `true` if it transitioned from `0` to `1`.
    pub fn mark_chunk_verified(&mut self, chunk_idx: u64) -> bool {
        if chunk_idx >= self.total_chunks {
            return false;
        }
        let byte_idx = (chunk_idx / 8) as usize;
        let bit_mask = 1u8 << (chunk_idx % 8);
        let was_set = (self.bitmap[byte_idx] & bit_mask) != 0;
        self.bitmap[byte_idx] |= bit_mask;
        !was_set
    }

    fn clear_chunk(&mut self, chunk_idx: u64) {
        if chunk_idx < self.total_chunks {
            let byte_idx = (chunk_idx / 8) as usize;
            let bit_mask = 1u8 << (chunk_idx % 8);
            self.bitmap[byte_idx] &= !bit_mask;
        }
    }

    /// Number of verified chunks recorded in the bitmap.
    pub fn verified_chunk_count(&self) -> u64 {
        let mut count = 0u64;
        for idx in 0..self.total_chunks {
            if self.is_chunk_verified(idx) {
                count += 1;
            }
        }
        count
    }

    /// Number of missing chunks not yet verified.
    pub fn missing_chunk_count(&self) -> u64 {
        self.total_chunks.saturating_sub(self.verified_chunk_count())
    }

    /// Total bytes already verified on disk.
    pub fn verified_bytes(&self) -> u64 {
        let mut bytes = 0u64;
        for idx in 0..self.total_chunks {
            if self.is_chunk_verified(idx) {
                bytes += expected_chunk_len(self.size_bytes, idx) as u64;
            }
        }
        bytes
    }

    /// Returns contiguous `[start, end)` ranges of missing 128 KiB chunk indices.
    pub fn missing_ranges(&self) -> Vec<ChunkRange> {
        let mut ranges = Vec::new();
        let mut current_start: Option<u64> = None;

        for idx in 0..self.total_chunks {
            let missing = !self.is_chunk_verified(idx);
            match (current_start, missing) {
                (None, true) => current_start = Some(idx),
                (Some(start), false) => {
                    ranges.push(ChunkRange { start, end: idx });
                    current_start = None;
                }
                _ => {}
            }
        }
        if let Some(start) = current_start {
            ranges.push(ChunkRange {
                start,
                end: self.total_chunks,
            });
        }
        ranges
    }

    /// Expands missing chunk ranges into individual chunk indices (for diagnostics and tests).
    pub fn missing_chunk_indices(&self) -> Vec<u64> {
        let mut out = Vec::new();
        for range in self.missing_ranges() {
            out.extend(range.start..range.end);
        }
        out
    }
}

/// Returns the default BeamDrop downloads directory (`Downloads/BeamDrop` or `BEAMDROP_DOWNLOAD_DIR`).
pub fn default_download_dir() -> Result<PathBuf, TransferError> {
    if let Ok(custom) = std::env::var("BEAMDROP_DOWNLOAD_DIR") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    #[cfg(target_os = "android")]
    {
        let root = std::env::var("EXTERNAL_STORAGE")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "/storage/emulated/0".to_string());
        return Ok(PathBuf::from(root).join("Download").join("BeamDrop"));
    }
    #[cfg(not(target_os = "android"))]
    {
        if let Some(user_dirs) = UserDirs::new() {
            if let Some(downloads) = user_dirs.download_dir() {
                return Ok(downloads.join("BeamDrop"));
            }
        }
        if let Ok(cfg) = DeviceIdentity::config_dir() {
            return Ok(cfg.join("Downloads"));
        }
        Ok(PathBuf::from("Downloads").join("BeamDrop"))
    }
}

pub fn part_path_for(final_path: &Path) -> PathBuf {
    append_suffix(final_path, ".beamdrop.part")
}

pub fn resume_path_for(final_path: &Path) -> PathBuf {
    append_suffix(final_path, ".resume.json")
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

pub fn chunk_count_for_size(size_bytes: u64) -> u64 {
    if size_bytes == 0 {
        0
    } else {
        size_bytes.div_ceil(CHUNK_SIZE as u64)
    }
}

pub fn expected_chunk_len(size_bytes: u64, chunk_idx: u64) -> usize {
    let start = chunk_idx * CHUNK_SIZE as u64;
    let remaining = size_bytes.saturating_sub(start);
    remaining.min(CHUNK_SIZE as u64) as usize
}

fn chunk_end_offset(size_bytes: u64, chunk_idx: u64) -> u64 {
    (chunk_idx * CHUNK_SIZE as u64) + expected_chunk_len(size_bytes, chunk_idx) as u64
}

/// Computes the BLAKE3 hash of a file on disk incrementally using `128 KiB` chunks.
pub async fn hash_file_blake3(path: impl AsRef<Path>) -> Result<[u8; 32], TransferError> {
    let mut file = tokio::fs::File::open(path.as_ref()).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

#[derive(Debug, Clone)]
struct SourceManifestEntry {
    offer_entry: FileOfferEntry,
    local_path: PathBuf,
}

#[derive(Debug)]
struct OutgoingChunk {
    file_index: u32,
    byte_offset: u64,
    data: Bytes,
}

#[derive(Debug)]
struct IncomingChunk {
    file_index: u32,
    byte_offset: u64,
    data: Vec<u8>,
}

struct ActiveIncomingTransfer {
    conn_stable_id: usize,
    chunk_tx: mpsc::Sender<IncomingChunk>,
    cancel_tx: watch::Sender<bool>,
}

/// Engine managing bounded-memory parallel QUIC transfers, resume bitmaps, and BLAKE3 verification.
pub struct TransferEngine {
    download_dir: PathBuf,
    trust_store: Option<Arc<TrustStore>>,
    pending_approvals: Arc<Mutex<HashMap<Uuid, oneshot::Sender<bool>>>>,
    approval_timeout: RwLock<Duration>,
    active_incoming: Arc<RwLock<HashMap<u64, ActiveIncomingTransfer>>>,
    completed_files: Arc<RwLock<HashMap<Uuid, Vec<PathBuf>>>>,
    event_tx: broadcast::Sender<TransferEvent>,
}

impl TransferEngine {
    /// Creates a new `TransferEngine` writing received files into `download_dir`
    /// (defaults to `Downloads/BeamDrop` when `None`).
    pub fn new(download_dir: Option<PathBuf>) -> Result<Self, TransferError> {
        Self::with_trust_store(download_dir, None)
    }

    /// Creates a new `TransferEngine` backed by `trust_store` for zero-click auto-accept
    /// authorization on incoming transfer offers.
    pub fn with_trust_store(
        download_dir: Option<PathBuf>,
        trust_store: Option<Arc<TrustStore>>,
    ) -> Result<Self, TransferError> {
        let dir = match download_dir {
            Some(d) => d,
            None => default_download_dir()?,
        };
        let (event_tx, _) = broadcast::channel(256);
        Ok(Self {
            download_dir: dir,
            trust_store,
            pending_approvals: Arc::new(Mutex::new(HashMap::new())),
            approval_timeout: RwLock::new(DEFAULT_APPROVAL_TIMEOUT),
            active_incoming: Arc::new(RwLock::new(HashMap::new())),
            completed_files: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
        })
    }

    /// Configures the approval wait timeout for untrusted offers (defaults to 60 seconds).
    pub async fn set_approval_timeout(&self, duration: Duration) {
        *self.approval_timeout.write().await = duration;
    }

    /// Responds to a pending transfer offer held for manual approval, returning `true` if the
    /// offer was still pending and the decision was delivered.
    pub async fn respond_to_offer(&self, transfer_id: Uuid, accept: bool) -> bool {
        let tx = {
            let mut pending = self.pending_approvals.lock().await;
            pending.remove(&transfer_id)
        };
        if let Some(tx) = tx {
            tx.send(accept).is_ok()
        } else {
            false
        }
    }

    /// Returns the IDs of offers currently awaiting approval.
    pub async fn pending_offer_ids(&self) -> Vec<Uuid> {
        self.pending_approvals.lock().await.keys().copied().collect()
    }

    /// Returns the configured download output directory.
    pub fn download_dir(&self) -> &Path {
        &self.download_dir
    }

    /// Takes the finalized output file paths recorded for a verified completed incoming transfer.
    pub async fn take_completed_files(&self, transfer_id: Uuid) -> Vec<PathBuf> {
        self.completed_files
            .write()
            .await
            .remove(&transfer_id)
            .unwrap_or_default()
    }

    /// Subscribes to incoming/outgoing `TransferEvent`s.
    pub fn subscribe(&self) -> broadcast::Receiver<TransferEvent> {
        self.event_tx.subscribe()
    }

    /// Spawns a single `accept_uni` reader loop for an incoming QUIC `Connection`.
    pub fn spawn_connection_uni_reader(self: &Arc<Self>, conn: Connection) {
        let engine = Arc::clone(self);
        let conn_id = conn.stable_id();
        tokio::spawn(async move {
            let active_tasks = Arc::new(tokio::sync::Notify::new());
            let in_flight = Arc::new(AtomicU64::new(0));

            loop {
                match conn.accept_uni().await {
                    Ok(recv) => {
                        let eng = Arc::clone(&engine);
                        let count = Arc::clone(&in_flight);
                        let notify = Arc::clone(&active_tasks);
                        count.fetch_add(1, Ordering::AcqRel);
                        tokio::spawn(async move {
                            eng.read_uni_stream(recv).await;
                            if count.fetch_sub(1, Ordering::AcqRel) == 1 {
                                notify.notify_waiters();
                            }
                        });
                    }
                    Err(_) => break,
                }
            }

            // Wait briefly for in-flight uni stream tasks to push already-read chunks
            while in_flight.load(Ordering::Acquire) > 0 {
                let notified = active_tasks.notified();
                if in_flight.load(Ordering::Acquire) == 0 {
                    break;
                }
                let _ = tokio::time::timeout(Duration::from_millis(500), notified).await;
                break;
            }

            // Notify any remaining active transfers tied to this connection
            let mut active = engine.active_incoming.write().await;
            let to_cancel: Vec<u64> = active
                .iter()
                .filter(|(_, entry)| entry.conn_stable_id == conn_id)
                .map(|(id, _)| *id)
                .collect();
            for id in to_cancel {
                if let Some(entry) = active.remove(&id) {
                    let _ = entry.cancel_tx.send(true);
                }
            }
        });
    }

    async fn read_uni_stream(&self, mut recv: RecvStream) {
        let mut header_buf = [0u8; UNI_CHUNK_HEADER_LEN];
        let mut cached_tid: Option<u64> = None;
        let mut cached_tx: Option<mpsc::Sender<IncomingChunk>> = None;
        let mut cached_cancel: Option<watch::Receiver<bool>> = None;

        loop {
            if let Some(ref cancel_rx) = cached_cancel {
                if *cancel_rx.borrow() {
                    break;
                }
            }

            match recv.read_exact(&mut header_buf).await {
                Ok(()) => {}
                Err(iroh::endpoint::ReadExactError::FinishedEarly(0)) => {
                    // Clean EOF at chunk boundary
                    break;
                }
                Err(_) => break,
            }

            let hdr = ChunkHeader::decode(&header_buf);
            if hdr.chunk_len == 0 || hdr.chunk_len as usize > CHUNK_SIZE {
                break;
            }

            if cached_tid != Some(hdr.transfer_id) {
                let active = self.active_incoming.read().await;
                if let Some(sink) = active.get(&hdr.transfer_id) {
                    cached_tid = Some(hdr.transfer_id);
                    cached_tx = Some(sink.chunk_tx.clone());
                    cached_cancel = Some(sink.cancel_tx.subscribe());
                } else {
                    break;
                }
            }

            let mut data = vec![0u8; hdr.chunk_len as usize];
            if recv.read_exact(&mut data).await.is_err() {
                break;
            }

            if let Some(ref tx) = cached_tx {
                let chunk = IncomingChunk {
                    file_index: hdr.file_index,
                    byte_offset: hdr.byte_offset,
                    data,
                };
                if tx.send(chunk).await.is_err() {
                    break;
                }
            }
        }
    }

    /// Handles an incoming `Message::Offer` on a bidirectional control stream (`accept_bi`).
    pub async fn handle_incoming_offer(
        self: &Arc<Self>,
        conn: Connection,
        offer: OfferPayload,
        mut ctrl_send: SendStream,
        mut ctrl_recv: RecvStream,
    ) {
        let transfer_uuid = offer.transfer_id;
        let stream_tid = transfer_stream_id(transfer_uuid);

        let sender_node_id = match conn.remote_node_id() {
            Ok(id) => id,
            Err(err) => {
                let reason = format!("Unauthenticated QUIC peer: {err}");
                let reject = Message::Reject(RejectPayload {
                    transfer_id: transfer_uuid,
                    reason: Some(reason.clone()),
                });
                let _ = write_frame(&mut ctrl_send, &reject).await;
                let _ = ctrl_send.finish();
                let _ = self.event_tx.send(TransferEvent::Interrupted {
                    transfer_id: transfer_uuid,
                    reason,
                });
                return;
            }
        };

        let _ = self.event_tx.send(TransferEvent::OfferReceived {
            transfer_id: transfer_uuid,
            sender_name: offer.sender_name.clone(),
            files: offer.files.len(),
            total_bytes: offer.total_bytes,
        });

        let auto_accept = match &self.trust_store {
            Some(store) => store.is_auto_accept_trusted(&sender_node_id).await,
            None => false,
        };

        if auto_accept {
            let _ = self.event_tx.send(TransferEvent::AutoAccepted {
                transfer_id: transfer_uuid,
                sender_node_id,
                sender_name: offer.sender_name.clone(),
                files: offer.files.len(),
                total_bytes: offer.total_bytes,
            });
        } else {
            let (tx, rx) = oneshot::channel::<bool>();
            {
                let mut pending = self.pending_approvals.lock().await;
                pending.insert(transfer_uuid, tx);
            }

            let _ = self.event_tx.send(TransferEvent::PendingApproval {
                transfer_id: transfer_uuid,
                sender_node_id,
                sender_name: offer.sender_name.clone(),
                files: offer.files.len(),
                total_bytes: offer.total_bytes,
            });

            let wait_dur = *self.approval_timeout.read().await;
            let decision = tokio::select! {
                res = tokio::time::timeout(wait_dur, rx) => {
                    match res {
                        Ok(Ok(true)) => Ok(()),
                        Ok(Ok(false)) => Err("Transfer rejected by user".to_string()),
                        Ok(Err(_)) => Err("Transfer approval channel closed".to_string()),
                        Err(_) => Err(format!(
                            "Untrusted transfer offer timed out after {}s",
                            wait_dur.as_secs()
                        )),
                    }
                }
                _ = conn.closed() => {
                    Err("Sender disconnected before transfer approval".to_string())
                }
            };

            {
                let mut pending = self.pending_approvals.lock().await;
                pending.remove(&transfer_uuid);
            }

            if let Err(reason) = decision {
                let reject = Message::Reject(RejectPayload {
                    transfer_id: transfer_uuid,
                    reason: Some(reason.clone()),
                });
                let _ = write_frame(&mut ctrl_send, &reject).await;
                let _ = ctrl_send.finish();
                let _ = self.event_tx.send(TransferEvent::Interrupted {
                    transfer_id: transfer_uuid,
                    reason,
                });
                return;
            }
        }

        let prepared = match self.prepare_incoming_files(&offer.files).await {
            Ok(files) => files,
            Err(err) => {
                let reject = Message::Reject(crate::protocol::RejectPayload {
                    transfer_id: transfer_uuid,
                    reason: Some(err.to_string()),
                });
                let _ = write_frame(&mut ctrl_send, &reject).await;
                let _ = ctrl_send.finish();
                let _ = self.event_tx.send(TransferEvent::Interrupted {
                    transfer_id: transfer_uuid,
                    reason: err.to_string(),
                });
                return;
            }
        };

        let mut accepted_file_ids = Vec::with_capacity(prepared.len());
        let mut file_resumes = Vec::with_capacity(prepared.len());
        let mut remaining_chunks = 0u64;
        let mut initial_skipped_bytes = 0u64;

        for state in &prepared {
            accepted_file_ids.push(state.file_id);
            let missing = state.resume.missing_ranges();
            remaining_chunks += state.resume.missing_chunk_count();
            initial_skipped_bytes += state.resume.verified_bytes();
            file_resumes.push(AcceptedFileResume {
                file_id: state.file_id,
                missing_ranges: missing,
            });
        }

        let (chunk_tx, chunk_rx) = mpsc::channel::<IncomingChunk>(CHANNEL_BOUND);
        let (cancel_tx, cancel_rx) = watch::channel(false);

        {
            let mut active = self.active_incoming.write().await;
            active.insert(
                stream_tid,
                ActiveIncomingTransfer {
                    conn_stable_id: conn.stable_id(),
                    chunk_tx: chunk_tx.clone(),
                    cancel_tx: cancel_tx.clone(),
                },
            );
        }

        let writer_handle = tokio::spawn(run_incoming_writer(
            transfer_uuid,
            prepared,
            remaining_chunks,
            offer.total_bytes,
            initial_skipped_bytes,
            chunk_rx,
            cancel_rx,
            self.event_tx.clone(),
        ));

        let accept_msg = Message::Accept(AcceptPayload {
            transfer_id: transfer_uuid,
            accepted_file_ids,
            file_resumes,
        });

        if let Err(err) = write_frame(&mut ctrl_send, &accept_msg).await {
            self.cleanup_active_transfer(stream_tid, &cancel_tx).await;
            drop(chunk_tx);
            let _ = writer_handle.await;
            let _ = self.event_tx.send(TransferEvent::Interrupted {
                transfer_id: transfer_uuid,
                reason: err.to_string(),
            });
            return;
        }

        // Wait for sender's `Message::Complete` frame on the bidirectional control stream.
        let complete_msg = tokio::select! {
            res = read_frame(&mut ctrl_recv) => res,
            _ = conn.closed() => {
                Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "Connection closed before transfer completion",
                )))
            }
        };

        let sender_complete = match complete_msg {
            Ok(Message::Complete(c)) if c.transfer_id == transfer_uuid => c,
            Ok(other) => {
                self.cleanup_active_transfer(stream_tid, &cancel_tx).await;
                drop(chunk_tx);
                let _ = writer_handle.await;
                let _ = self.event_tx.send(TransferEvent::Interrupted {
                    transfer_id: transfer_uuid,
                    reason: format!("Unexpected control frame: {:?}", other.message_type()),
                });
                return;
            }
            Err(err) => {
                // Connection interrupted mid-transfer: allow already-received chunks in chunk_rx
                // to flush into `.beamdrop.part` and save `.resume.json`.
                {
                    let mut active = self.active_incoming.write().await;
                    active.remove(&stream_tid);
                }
                drop(chunk_tx);
                let _ = tokio::time::timeout(Duration::from_secs(2), writer_handle).await;
                let _ = self.event_tx.send(TransferEvent::Interrupted {
                    transfer_id: transfer_uuid,
                    reason: err.to_string(),
                });
                return;
            }
        };

        // Wait for the writer task to finish writing and hashing all chunks.
        let writer_res = tokio::select! {
            res = writer_handle => {
                match res {
                    Ok(inner) => inner,
                    Err(e) => Err(TransferError::Quic(e.to_string())),
                }
            }
            _ = conn.closed() => {
                self.cleanup_active_transfer(stream_tid, &cancel_tx).await;
                Err(TransferError::DisconnectedMidTransfer {
                    transfer_id: transfer_uuid,
                    remaining_chunks: 1,
                })
            }
        };

        // Always remove active sink entry now that writer finished.
        {
            let mut active = self.active_incoming.write().await;
            active.remove(&stream_tid);
        }
        drop(chunk_tx);

        match writer_res {
            Ok(computed_files) => {
                let mut verified = true;
                for file_result in &computed_files {
                    let expected = sender_complete
                        .file_hashes
                        .iter()
                        .find(|h| h.file_id == file_result.file_id)
                        .map(|h| h.blake3)
                        .or(file_result.offer_expected_blake3);

                    if expected != Some(file_result.computed_blake3) {
                        verified = false;
                        break;
                    }
                }

                if verified {
                    for file_result in &computed_files {
                        if let Err(err) =
                            tokio::fs::rename(&file_result.part_path, &file_result.final_path).await
                        {
                            verified = false;
                            let _ = self.event_tx.send(TransferEvent::Interrupted {
                                transfer_id: transfer_uuid,
                                reason: format!("Failed atomic rename: {err}"),
                            });
                            break;
                        }
                        let _ = tokio::fs::remove_file(&file_result.resume_path).await;
                    }
                }

                let file_hashes: Vec<FileHashEntry> = computed_files
                    .iter()
                    .map(|f| FileHashEntry {
                        file_id: f.file_id,
                        blake3: f.computed_blake3,
                    })
                    .collect();

                let ack = Message::Complete(CompletePayload {
                    transfer_id: transfer_uuid,
                    total_bytes_transferred: sender_complete.total_bytes_transferred,
                    verified,
                    file_hashes,
                });
                let _ = write_frame(&mut ctrl_send, &ack).await;
                let _ = ctrl_send.finish();

                if verified {
                    let paths: Vec<PathBuf> = computed_files
                        .iter()
                        .map(|f| f.final_path.clone())
                        .collect();
                    let mut completed_map = self.completed_files.write().await;
                    if completed_map.len() >= 64 {
                        completed_map.clear();
                    }
                    completed_map.insert(transfer_uuid, paths);
                }

                let _ = self.event_tx.send(TransferEvent::Completed {
                    transfer_id: transfer_uuid,
                    files: computed_files.len(),
                    total_bytes: offer.total_bytes,
                    bytes_transferred: sender_complete.total_bytes_transferred,
                    bytes_skipped_resumed: initial_skipped_bytes,
                    verified,
                    output_dir: Some(self.download_dir.clone()),
                });
            }
            Err(err) => {
                let _ = self.event_tx.send(TransferEvent::Interrupted {
                    transfer_id: transfer_uuid,
                    reason: err.to_string(),
                });
            }
        }
    }

    async fn cleanup_active_transfer(&self, stream_tid: u64, cancel_tx: &watch::Sender<bool>) {
        let _ = cancel_tx.send(true);
        let mut active = self.active_incoming.write().await;
        active.remove(&stream_tid);
    }

    async fn prepare_incoming_files(
        &self,
        entries: &[FileOfferEntry],
    ) -> Result<Vec<FileReceiveState>, TransferError> {
        tokio::fs::create_dir_all(&self.download_dir).await?;
        let mut states = Vec::with_capacity(entries.len());

        for entry in entries {
            let rel = sanitize_relative_path(&entry.relative_path)?;
            let final_path = self.download_dir.join(&rel);
            if let Some(parent) = final_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let part_path = part_path_for(&final_path);
            let resume_path = resume_path_for(&final_path);

            let (mut resume, file) = if part_path.exists() && resume_path.exists() {
                let meta_len = tokio::fs::metadata(&part_path).await?.len();
                match ResumeMetadata::load(&resume_path) {
                    Ok(mut loaded) if loaded.matches_offer(entry, meta_len) => {
                        loaded.clamp_to_file_len(meta_len);
                        let f = tokio::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(&part_path)
                            .await?;
                        if meta_len != entry.size_bytes {
                            f.set_len(entry.size_bytes).await?;
                        }
                        loaded.save(&resume_path)?;
                        (loaded, f)
                    }
                    _ => {
                        let mut fresh = ResumeMetadata::new(
                            entry.relative_path.clone(),
                            entry.size_bytes,
                            entry.head_blake3,
                        );
                        let f = create_part_file(&part_path, entry.size_bytes).await?;
                        fresh.save(&resume_path)?;
                        (fresh, f)
                    }
                }
            } else {
                let mut fresh = ResumeMetadata::new(
                    entry.relative_path.clone(),
                    entry.size_bytes,
                    entry.head_blake3,
                );
                let f = create_part_file(&part_path, entry.size_bytes).await?;
                fresh.save(&resume_path)?;
                (fresh, f)
            };

            // Initialize resume file on disk cleanly if zero-byte
            if entry.size_bytes == 0 {
                resume.save(&resume_path)?;
            }

            states.push(FileReceiveState {
                file_id: entry.file_id,
                relative_path: entry.relative_path.clone(),
                size_bytes: entry.size_bytes,
                offer_expected_blake3: entry.sha256_or_blake3,
                final_path,
                part_path,
                resume_path,
                resume,
                file,
                hasher: blake3::Hasher::new(),
                next_hash_chunk: 0,
            });
        }

        Ok(states)
    }

    /// Sends a single file or recursive directory over an `iroh::endpoint::Connection`.
    pub async fn send_path(
        &self,
        conn: &Connection,
        sender_name: &str,
        source_path: &Path,
        progress_tx: Option<mpsc::Sender<TransferProgress>>,
    ) -> Result<TransferSummary, TransferError> {
        let start = Instant::now();
        let manifest = collect_transfer_manifest(source_path).await?;
        let transfer_uuid = Uuid::new_v4();
        let stream_tid = transfer_stream_id(transfer_uuid);
        let total_bytes: u64 = manifest.iter().map(|m| m.offer_entry.size_bytes).sum();

        let offer = OfferPayload {
            transfer_id: transfer_uuid,
            sender_name: sender_name.to_string(),
            files: manifest.iter().map(|m| m.offer_entry.clone()).collect(),
            total_bytes,
        };

        let (mut ctrl_send, mut ctrl_recv) = conn
            .open_bi()
            .await
            .map_err(|e| TransferError::Quic(e.to_string()))?;

        write_frame(&mut ctrl_send, &Message::Offer(offer)).await?;

        let accept = match read_frame(&mut ctrl_recv).await? {
            Message::Accept(a) => a,
            Message::Reject(r) => {
                return Err(TransferError::Rejected(
                    transfer_uuid,
                    r.reason.unwrap_or_else(|| "No reason given".to_string()),
                ));
            }
            other => {
                return Err(TransferError::UnexpectedMessage(format!(
                    "{:?}",
                    other.message_type()
                )));
            }
        };

        let mut missing_by_file: HashMap<u32, Vec<ChunkRange>> = HashMap::new();
        for fr in &accept.file_resumes {
            missing_by_file.insert(fr.file_id, fr.missing_ranges.clone());
        }

        let mut total_missing_chunks = 0u64;
        let mut total_missing_bytes = 0u64;
        for item in &manifest {
            let entry = &item.offer_entry;
            let ranges = missing_by_file
                .get(&entry.file_id)
                .cloned()
                .unwrap_or_else(|| {
                    let count = chunk_count_for_size(entry.size_bytes);
                    if count == 0 {
                        vec![]
                    } else {
                        vec![ChunkRange {
                            start: 0,
                            end: count,
                        }]
                    }
                });
            for r in &ranges {
                total_missing_chunks += r.end.saturating_sub(r.start);
                for idx in r.start..r.end {
                    total_missing_bytes += expected_chunk_len(entry.size_bytes, idx) as u64;
                }
            }
        }
        let bytes_skipped_resumed = total_bytes.saturating_sub(total_missing_bytes);

        let use_parallel = manifest
            .iter()
            .any(|m| m.offer_entry.size_bytes > PARALLEL_STRIPE_THRESHOLD)
            || total_missing_bytes > PARALLEL_STRIPE_THRESHOLD;

        let num_streams = if total_missing_chunks == 0 {
            0
        } else if use_parallel {
            MAX_PARALLEL_STREAMS.min(total_missing_chunks as usize)
        } else {
            1
        };

        let (chunk_tx, chunk_rx) = mpsc::channel::<OutgoingChunk>(CHANNEL_BOUND);
        let shared_rx = Arc::new(Mutex::new(chunk_rx));
        let bytes_sent_counter = Arc::new(AtomicU64::new(0));
        let current_file_label = Arc::new(RwLock::new(
            manifest
                .first()
                .map(|m| m.offer_entry.relative_path.clone())
                .unwrap_or_default(),
        ));

        // Spawn progress ticker so UI updates smoothly without blocking the QUIC hot path
        let progress_stop = Arc::new(watch::channel(false).0);
        let progress_task = progress_tx.map(|tx| {
            let sent = Arc::clone(&bytes_sent_counter);
            let label = Arc::clone(&current_file_label);
            let mut stop_rx = progress_stop.subscribe();
            let event_tx = self.event_tx.clone();
            AbortOnDrop::new(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_millis(50));
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            let cur = sent.load(Ordering::Relaxed);
                            let name = label.read().await.clone();
                            let snap = TransferProgress {
                                transfer_id: transfer_uuid,
                                file_name: name,
                                bytes_transferred: cur,
                                bytes_skipped_resumed,
                                total_bytes,
                                streams_active: num_streams,
                            };
                            let _ = tx.try_send(snap.clone());
                            let _ = event_tx.send(TransferEvent::Progress(snap));
                        }
                        _ = stop_rx.changed() => break,
                    }
                }
            }))
        });

        // Spawn up to 6 concurrent unidirectional QUIC data streams (JoinSet auto-aborts on drop)
        let mut workers = JoinSet::new();
        for _ in 0..num_streams {
            let rx = Arc::clone(&shared_rx);
            let conn = conn.clone();
            let sent = Arc::clone(&bytes_sent_counter);
            workers.spawn(async move {
                let mut uni: Option<SendStream> = None;
                loop {
                    let chunk = {
                        let mut guard = rx.lock().await;
                        guard.recv().await
                    };
                    let Some(chunk) = chunk else {
                        break;
                    };

                    if uni.is_none() {
                        let stream = conn
                            .open_uni()
                            .await
                            .map_err(|e| TransferError::Quic(e.to_string()))?;
                        uni = Some(stream);
                    }

                    let stream = uni.as_mut().expect("initialized uni stream");
                    let chunk_len = chunk.data.len() as u32;
                    let header = ChunkHeader {
                        transfer_id: stream_tid,
                        file_index: chunk.file_index,
                        byte_offset: chunk.byte_offset,
                        chunk_len,
                    }
                    .encode();

                    // Write 24-byte header immediately followed by raw file bytes
                    stream
                        .write_all_chunks(&mut [
                            Bytes::copy_from_slice(&header),
                            chunk.data,
                        ])
                        .await
                        .map_err(|e| TransferError::Quic(e.to_string()))?;

                    sent.fetch_add(chunk_len as u64, Ordering::Relaxed);
                }

                if let Some(mut stream) = uni {
                    stream
                        .finish()
                        .map_err(|e| TransferError::Quic(e.to_string()))?;
                }
                Ok::<(), TransferError>(())
            });
        }

        // Bounded disk reader: reads 128 KiB chunks sequentially, hashes incrementally via BLAKE3,
        // and forwards only missing chunks to the QUIC stream workers.
        let reader_manifest = manifest.clone();
        let reader_label = Arc::clone(&current_file_label);
        let reader_handle = AbortOnDrop::new(tokio::spawn(async move {
            let mut file_hashes = Vec::with_capacity(reader_manifest.len());
            let mut read_buf = vec![0u8; CHUNK_SIZE];

            for item in reader_manifest {
                let entry = &item.offer_entry;
                if !accept.accepted_file_ids.contains(&entry.file_id) {
                    continue;
                }
                {
                    let mut label = reader_label.write().await;
                    *label = entry.relative_path.clone();
                }

                let ranges = missing_by_file
                    .get(&entry.file_id)
                    .cloned()
                    .unwrap_or_else(|| {
                        let count = chunk_count_for_size(entry.size_bytes);
                        if count == 0 {
                            vec![]
                        } else {
                            vec![ChunkRange {
                                start: 0,
                                end: count,
                            }]
                        }
                    });

                let mut file = tokio::fs::File::open(&item.local_path).await?;
                let mut hasher = blake3::Hasher::new();
                let total_chunks = chunk_count_for_size(entry.size_bytes);
                let mut range_idx = 0usize;

                for chunk_idx in 0..total_chunks {
                    let expected_len = expected_chunk_len(entry.size_bytes, chunk_idx);
                    file.read_exact(&mut read_buf[..expected_len]).await?;

                    // Incremental SIMD-accelerated BLAKE3 update on 128 KiB buffer
                    hasher.update(&read_buf[..expected_len]);

                    while range_idx < ranges.len() && chunk_idx >= ranges[range_idx].end {
                        range_idx += 1;
                    }
                    let is_missing = range_idx < ranges.len()
                        && chunk_idx >= ranges[range_idx].start
                        && chunk_idx < ranges[range_idx].end;

                    if is_missing {
                        let outgoing = OutgoingChunk {
                            file_index: entry.file_id,
                            byte_offset: chunk_idx * CHUNK_SIZE as u64,
                            data: Bytes::copy_from_slice(&read_buf[..expected_len]),
                        };
                        chunk_tx
                            .send(outgoing)
                            .await
                            .map_err(|_| TransferError::Quic("Worker channel closed".into()))?;
                    }
                }

                file_hashes.push(FileHashEntry {
                    file_id: entry.file_id,
                    blake3: *hasher.finalize().as_bytes(),
                });
            }

            drop(chunk_tx);
            Ok::<Vec<FileHashEntry>, TransferError>(file_hashes)
        }));

        let reader_fut = async {
            match reader_handle.join().await {
                Ok(res) => res,
                Err(e) => Err(TransferError::Quic(e.to_string())),
            }
        };
        let workers_fut = async move {
            while let Some(res) = workers.join_next().await {
                match res {
                    Ok(inner) => inner?,
                    Err(e) => return Err(TransferError::Quic(e.to_string())),
                }
            }
            Ok::<(), TransferError>(())
        };

        let (file_hashes, ()) = tokio::try_join!(reader_fut, workers_fut)?;

        let _ = progress_stop.send(true);
        if let Some(pt) = progress_task {
            let _ = pt.join().await;
        }

        let bytes_sent = bytes_sent_counter.load(Ordering::Relaxed);
        let complete = Message::Complete(CompletePayload {
            transfer_id: transfer_uuid,
            total_bytes_transferred: bytes_sent,
            verified: true,
            file_hashes: file_hashes.clone(),
        });
        write_frame(&mut ctrl_send, &complete).await?;
        ctrl_send
            .finish()
            .map_err(|e| TransferError::Quic(e.to_string()))?;

        // Wait for receiver verification & atomic rename confirmation
        match read_frame(&mut ctrl_recv).await? {
            Message::Complete(ack) if ack.transfer_id == transfer_uuid => {
                if !ack.verified {
                    return Err(TransferError::IntegrityMismatch {
                        relative_path: source_path.display().to_string(),
                    });
                }
            }
            other => {
                return Err(TransferError::UnexpectedMessage(format!(
                    "{:?}",
                    other.message_type()
                )));
            }
        }

        let _ = self.event_tx.send(TransferEvent::Completed {
            transfer_id: transfer_uuid,
            files: manifest.len(),
            total_bytes,
            bytes_transferred: bytes_sent,
            bytes_skipped_resumed,
            verified: true,
            output_dir: None,
        });

        Ok(TransferSummary {
            transfer_id: transfer_uuid,
            files_count: manifest.len(),
            total_bytes,
            bytes_sent,
            bytes_skipped_resumed,
            streams_used: num_streams,
            elapsed: start.elapsed(),
            file_hashes,
        })
    }
}

struct FileReceiveState {
    file_id: u32,
    relative_path: String,
    size_bytes: u64,
    offer_expected_blake3: Option<[u8; 32]>,
    final_path: PathBuf,
    part_path: PathBuf,
    resume_path: PathBuf,
    resume: ResumeMetadata,
    file: tokio::fs::File,
    hasher: blake3::Hasher,
    next_hash_chunk: u64,
}

struct CompletedFileInfo {
    file_id: u32,
    offer_expected_blake3: Option<[u8; 32]>,
    final_path: PathBuf,
    part_path: PathBuf,
    resume_path: PathBuf,
    computed_blake3: [u8; 32],
}

async fn run_incoming_writer(
    transfer_id: Uuid,
    mut files: Vec<FileReceiveState>,
    mut remaining_chunks: u64,
    total_bytes: u64,
    initial_skipped_bytes: u64,
    mut chunk_rx: mpsc::Receiver<IncomingChunk>,
    mut cancel_rx: watch::Receiver<bool>,
    event_tx: broadcast::Sender<TransferEvent>,
) -> Result<Vec<CompletedFileInfo>, TransferError> {
    let mut index_map = HashMap::with_capacity(files.len());
    for (idx, f) in files.iter().enumerate() {
        index_map.insert(f.file_id, idx);
    }

    let mut scratch_buf = vec![0u8; CHUNK_SIZE];
    let mut chunks_since_flush = 0u64;
    let mut last_flush = Instant::now();
    let mut received_bytes = 0u64;

    if remaining_chunks > 0 {
        loop {
            let next_chunk = tokio::select! {
                biased;
                chunk = chunk_rx.recv() => chunk,
                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        // Drain anything already buffered in chunk_rx before exiting
                        while let Ok(c) = chunk_rx.try_recv() {
                            if let Some(&idx) = index_map.get(&c.file_index) {
                                let state = &mut files[idx];
                                let _ = write_incoming_chunk(state, c, &mut scratch_buf, &mut remaining_chunks, &mut received_bytes).await?;
                            }
                        }
                        break;
                    }
                    continue;
                }
            };

            let Some(chunk) = next_chunk else {
                break;
            };

            let Some(&vec_idx) = index_map.get(&chunk.file_index) else {
                continue;
            };
            let state = &mut files[vec_idx];
            if write_incoming_chunk(
                state,
                chunk,
                &mut scratch_buf,
                &mut remaining_chunks,
                &mut received_bytes,
            )
            .await?
            {
                chunks_since_flush += 1;
            }

            if chunks_since_flush >= 64 || last_flush.elapsed() >= Duration::from_millis(250) {
                for f in &mut files {
                    f.file.flush().await?;
                    f.resume.save(&f.resume_path)?;
                }
                chunks_since_flush = 0;
                last_flush = Instant::now();

                let _ = event_tx.send(TransferEvent::Progress(TransferProgress {
                    transfer_id,
                    file_name: files[vec_idx].relative_path.clone(),
                    bytes_transferred: received_bytes,
                    bytes_skipped_resumed: initial_skipped_bytes,
                    total_bytes,
                    streams_active: if total_bytes > PARALLEL_STRIPE_THRESHOLD {
                        MAX_PARALLEL_STREAMS
                    } else {
                        1
                    },
                }));
            }

            if remaining_chunks == 0 {
                break;
            }
        }
    }

    // Flush written chunks and persist resume bitmaps cleanly
    for f in &mut files {
        f.file.flush().await?;
        f.resume.save(&f.resume_path)?;
    }

    if remaining_chunks > 0 {
        return Err(TransferError::DisconnectedMidTransfer {
            transfer_id,
            remaining_chunks,
        });
    }

    // Advance BLAKE3 frontier for any resumed prefixes or out-of-order chunks, then finalize
    let mut completed = Vec::with_capacity(files.len());
    for mut f in files {
        advance_hash_frontier(&mut f, &mut scratch_buf).await?;
        f.file.sync_all().await?;
        let computed_blake3 = *f.hasher.finalize().as_bytes();
        completed.push(CompletedFileInfo {
            file_id: f.file_id,
            offer_expected_blake3: f.offer_expected_blake3,
            final_path: f.final_path,
            part_path: f.part_path,
            resume_path: f.resume_path,
            computed_blake3,
        });
    }

    Ok(completed)
}

async fn write_incoming_chunk(
    state: &mut FileReceiveState,
    chunk: IncomingChunk,
    scratch_buf: &mut [u8],
    remaining_chunks: &mut u64,
    received_bytes: &mut u64,
) -> Result<bool, TransferError> {
    if chunk.byte_offset % CHUNK_SIZE as u64 != 0 {
        return Err(TransferError::InvalidChunkHeader {
            transfer_id: state.file_id as u64,
        });
    }
    let chunk_idx = chunk.byte_offset / CHUNK_SIZE as u64;
    if chunk_idx >= state.resume.total_chunks {
        return Err(TransferError::InvalidChunkHeader {
            transfer_id: state.file_id as u64,
        });
    }
    let expected_len = expected_chunk_len(state.size_bytes, chunk_idx);
    if chunk.data.len() != expected_len {
        return Err(TransferError::InvalidChunkHeader {
            transfer_id: state.file_id as u64,
        });
    }

    state.file.seek(SeekFrom::Start(chunk.byte_offset)).await?;
    state.file.write_all(&chunk.data).await?;

    let newly_marked = state.resume.mark_chunk_verified(chunk_idx);
    if newly_marked {
        *remaining_chunks = remaining_chunks.saturating_sub(1);
        *received_bytes += chunk.data.len() as u64;
    }

    // Hash immediately in RAM if this chunk sits right at the sequential BLAKE3 frontier
    if chunk_idx == state.next_hash_chunk {
        state.hasher.update(&chunk.data);
        state.next_hash_chunk += 1;
        advance_hash_frontier(state, scratch_buf).await?;
    }

    Ok(newly_marked)
}

async fn advance_hash_frontier(
    state: &mut FileReceiveState,
    scratch_buf: &mut [u8],
) -> Result<(), TransferError> {
    if state.next_hash_chunk < state.resume.total_chunks
        && state.resume.is_chunk_verified(state.next_hash_chunk)
    {
        state.file.flush().await?;
    }
    while state.next_hash_chunk < state.resume.total_chunks
        && state.resume.is_chunk_verified(state.next_hash_chunk)
    {
        let idx = state.next_hash_chunk;
        let offset = idx * CHUNK_SIZE as u64;
        let len = expected_chunk_len(state.size_bytes, idx);
        state.file.seek(SeekFrom::Start(offset)).await?;
        state.file.read_exact(&mut scratch_buf[..len]).await?;
        state.hasher.update(&scratch_buf[..len]);
        state.next_hash_chunk += 1;
    }
    Ok(())
}

struct AbortOnDrop<T>(Option<JoinHandle<T>>);

impl<T> AbortOnDrop<T> {
    fn new(handle: JoinHandle<T>) -> Self {
        Self(Some(handle))
    }

    async fn join(mut self) -> Result<T, tokio::task::JoinError> {
        let handle = self.0.take().expect("handle already taken");
        handle.await
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

async fn create_part_file(path: &Path, size_bytes: u64) -> Result<tokio::fs::File, TransferError> {
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(path)
        .await?;
    if size_bytes > 0 {
        file.set_len(size_bytes).await?;
    }
    Ok(file)
}

async fn collect_transfer_manifest(source: &Path) -> Result<Vec<SourceManifestEntry>, TransferError> {
    let meta = tokio::fs::metadata(source).await?;
    let mut entries = Vec::new();

    if meta.is_file() {
        let name = source
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| TransferError::EmptySource(source.to_path_buf()))?
            .to_string();
        let head = compute_head_blake3(source).await?;
        entries.push(SourceManifestEntry {
            offer_entry: FileOfferEntry {
                file_id: 0,
                relative_path: name,
                size_bytes: meta.len(),
                sha256_or_blake3: None,
                head_blake3: Some(head),
            },
            local_path: source.to_path_buf(),
        });
        return Ok(entries);
    }

    if !meta.is_dir() {
        return Err(TransferError::EmptySource(source.to_path_buf()));
    }

    let root_name = source
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("beamdrop-folder")
        .to_string();

    let mut stack = vec![(source.to_path_buf(), PathBuf::from(&root_name))];
    let mut files = Vec::new();

    while let Some((disk_dir, rel_dir)) = stack.pop() {
        let mut dir = tokio::fs::read_dir(&disk_dir).await?;
        let mut children = Vec::new();
        while let Some(entry) = dir.next_entry().await? {
            children.push(entry);
        }
        children.sort_by_key(|e| e.file_name());

        for child in children {
            let file_type = child.file_type().await?;
            let child_name = child.file_name();
            let child_name_str = child_name.to_string_lossy().into_owned();
            let next_rel = rel_dir.join(&child_name_str);
            let next_disk = child.path();

            if file_type.is_dir() {
                stack.push((next_disk, next_rel));
            } else if file_type.is_file() {
                let child_meta = child.metadata().await?;
                files.push((next_disk, path_to_slash_string(&next_rel), child_meta.len()));
            }
        }
    }

    files.sort_by(|a, b| a.1.cmp(&b.1));
    if files.is_empty() {
        return Err(TransferError::EmptySource(source.to_path_buf()));
    }

    for (idx, (local_path, relative_path, size_bytes)) in files.into_iter().enumerate() {
        let head = compute_head_blake3(&local_path).await?;
        entries.push(SourceManifestEntry {
            offer_entry: FileOfferEntry {
                file_id: idx as u32,
                relative_path,
                size_bytes,
                sha256_or_blake3: None,
                head_blake3: Some(head),
            },
            local_path,
        });
    }

    Ok(entries)
}

async fn compute_head_blake3(path: &Path) -> Result<[u8; 32], TransferError> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut total_read = 0usize;
    while total_read < CHUNK_SIZE {
        let n = file.read(&mut buf[total_read..]).await?;
        if n == 0 {
            break;
        }
        total_read += n;
    }
    Ok(*blake3::hash(&buf[..total_read]).as_bytes())
}

fn path_to_slash_string(path: &Path) -> String {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub fn sanitize_relative_path(raw: &str) -> Result<PathBuf, TransferError> {
    if raw.is_empty() || raw.contains('\0') {
        return Err(TransferError::InvalidRelativePath(raw.to_string()));
    }
    let mut clean = PathBuf::new();
    for segment in raw.split(['/', '\\']) {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(TransferError::InvalidRelativePath(raw.to_string()));
        }
        // Reject Windows drive letters like C:
        if segment.contains(':') {
            return Err(TransferError::InvalidRelativePath(raw.to_string()));
        }
        clean.push(segment);
    }
    if clean.as_os_str().is_empty() {
        return Err(TransferError::InvalidRelativePath(raw.to_string()));
    }
    Ok(clean)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = from_hex_digit(pair[0])?;
        let lo = from_hex_digit(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn from_hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_header_roundtrip() {
        let hdr = ChunkHeader {
            transfer_id: 0x1122334455667788,
            file_index: 42,
            byte_offset: 128 * 1024 * 999,
            chunk_len: CHUNK_SIZE as u32,
        };
        let encoded = hdr.encode();
        assert_eq!(encoded.len(), UNI_CHUNK_HEADER_LEN);
        let decoded = ChunkHeader::decode(&encoded);
        assert_eq!(hdr, decoded);
    }

    #[test]
    fn test_resume_bitmap_ranges_and_persistence() {
        let dir = std::env::temp_dir().join(format!("beamdrop-resume-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.bin.resume.json");

        let size = (CHUNK_SIZE as u64) * 10 + 500; // 11 chunks
        let mut meta = ResumeMetadata::new("test.bin".to_string(), size, Some([0xaa; 32]));
        assert_eq!(meta.total_chunks, 11);
        assert_eq!(
            meta.missing_ranges(),
            vec![ChunkRange { start: 0, end: 11 }]
        );

        assert!(meta.mark_chunk_verified(0));
        assert!(!meta.mark_chunk_verified(0));
        meta.mark_chunk_verified(1);
        meta.mark_chunk_verified(5);
        meta.mark_chunk_verified(10);
        meta.save(&path).unwrap();

        let reloaded = ResumeMetadata::load(&path).unwrap();
        assert_eq!(reloaded.verified_chunk_count(), 4);
        assert_eq!(
            reloaded.missing_ranges(),
            vec![
                ChunkRange { start: 2, end: 5 },
                ChunkRange { start: 6, end: 10 },
            ]
        );
        assert_eq!(reloaded.missing_chunk_indices(), vec![2, 3, 4, 6, 7, 8, 9]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sanitize_relative_path() {
        assert_eq!(
            sanitize_relative_path("folder/sub/file.txt").unwrap(),
            PathBuf::from("folder").join("sub").join("file.txt")
        );
        assert!(sanitize_relative_path("../secret.txt").is_err());
        assert!(sanitize_relative_path("/etc/passwd").is_err());
        assert!(sanitize_relative_path("C:\\windows\\win.ini").is_err());
        assert!(sanitize_relative_path("").is_err());
    }
}
