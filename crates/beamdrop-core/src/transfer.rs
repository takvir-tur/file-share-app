use std::collections::HashMap;
use std::fs;
use std::io::SeekFrom;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
#[cfg(not(target_os = "android"))]
use directories::UserDirs;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, NodeId};
use rand::RngCore;
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
    RejectPayload, TransferControlPayload,
};
use crate::trust::{OfferApproval, TrustStore};

/// Chunk size used for bounded disk streaming, incremental BLAKE3 hashing, and resume tracking.
pub const CHUNK_SIZE: usize = 128 * 1024; // 128 KiB

/// Maximum payload chunk size for Over-Internet (`!is_lan`) WAN streams (`4 * CHUNK_SIZE`).
pub const WAN_CHUNK_SIZE: usize = 512 * 1024; // 512 KiB

/// Exact number of 128 KiB resume blocks carried by a full `WAN_CHUNK_SIZE` chunk.
pub const WAN_BLOCKS_PER_CHUNK: usize = WAN_CHUNK_SIZE / CHUNK_SIZE;

/// File/transfer threshold above which parallel QUIC uni-stream striping is enabled.
pub const PARALLEL_STRIPE_THRESHOLD: u64 = 32 * 1024 * 1024; // 32 MiB

/// Maximum number of concurrent unidirectional QUIC data streams per transfer.
pub const MAX_PARALLEL_STREAMS: usize = 6;

/// Bounded channel capacity (`24 * 128 KiB = 3 MiB`) keeping total RAM well under 15 MB.
pub const CHANNEL_BOUND: usize = 24;

/// Bounded channel capacity for pipelined WAN chunks (`12 * 512 KiB = 6 MiB`).
pub const WAN_CHANNEL_BOUND: usize = 12;

/// Fixed big-endian header length preceding every chunk on unidirectional data streams.
/// Layout: `[u64 transfer_id | u32 file_index | u64 byte_offset | u32 chunk_len]`.
pub const UNI_CHUNK_HEADER_LEN: usize = 24;

/// Default timeout before rejecting unapproved incoming offers from untrusted peers.
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);

/// 96-bit ChaCha20-Poly1305 nonce length prepended to each encrypted WAN chunk.
pub const WAN_CHUNK_NONCE_LEN: usize = 12;

/// 128-bit Poly1305 authentication tag appended to each encrypted WAN chunk.
pub const WAN_CHUNK_TAG_LEN: usize = 16;

/// Total per-chunk wire overhead (`12B nonce + 16B tag`) added exclusively on WAN transfers.
pub const WAN_CHUNK_OVERHEAD: usize = WAN_CHUNK_NONCE_LEN + WAN_CHUNK_TAG_LEN;

const WAN_DAILY_KEY_CONTEXT: &str = "beamdrop wan daily chacha20poly1305 key v1";

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
    #[error("WAN encryption/decryption error: {0}")]
    WanCrypto(String),
    #[error("Long-distance WAN transfer blocked: {0}")]
    WanDisallowed(String),
    #[error("Transfer {0} paused")]
    Paused(Uuid),
    #[error("Transfer {0} cancelled")]
    Cancelled(Uuid),
}

impl TransferError {
    /// Returns `true` when an active transfer failed due to a recoverable transport/QUIC drop
    /// rather than rejection, cancellation, or payload verification failure.
    pub fn is_recoverable_network_drop(&self) -> bool {
        matches!(
            self,
            Self::Quic(_) | Self::Protocol(_) | Self::DisconnectedMidTransfer { .. }
        )
    }
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
    pub is_wan: bool,
    pub is_direct: Option<bool>,
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

/// Direction of a transfer reported in lifecycle events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferDirection {
    Outgoing,
    Incoming,
}

/// Events published by `TransferEngine` over a `tokio::sync::broadcast` channel.
#[derive(Debug, Clone)]
pub enum TransferEvent {
    Started {
        transfer_id: Uuid,
        peer_node_id: NodeId,
        peer_name: String,
        file_name: String,
        files: usize,
        total_bytes: u64,
        bytes_skipped_resumed: u64,
    },
    AwaitingApproval {
        transfer_id: Uuid,
        peer_node_id: NodeId,
        peer_name: String,
        file_name: String,
        files: usize,
        total_bytes: u64,
        is_wan: bool,
        expires_at_unix_ms: u64,
    },
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
        file_name: String,
        files: usize,
        total_bytes: u64,
        /// `true` when the offer arrived over an Internet (WAN/relay) path rather than local LAN.
        is_wan: bool,
        expires_at_unix_ms: u64,
    },
    Progress(TransferProgress),
    Paused {
        transfer_id: Uuid,
        reason: Option<String>,
    },
    Cancelled {
        transfer_id: Uuid,
        reason: Option<String>,
    },
    Completed {
        transfer_id: Uuid,
        files: usize,
        total_bytes: u64,
        bytes_transferred: u64,
        bytes_skipped_resumed: u64,
        verified: bool,
        output_dir: Option<PathBuf>,
    },
    Failed {
        transfer_id: Uuid,
        direction: TransferDirection,
        peer_node_id: NodeId,
        peer_name: String,
        file_name: String,
        files: usize,
        total_bytes: u64,
        is_wan: Option<bool>,
        reason: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlAction {
    Pause,
    Cancel,
}

#[derive(Debug, Clone)]
pub(crate) struct ControlSignal {
    pub(crate) action: ControlAction,
    pub(crate) reason: Option<String>,
}

async fn recv_control_signal(rx: &mut watch::Receiver<Option<ControlSignal>>) -> ControlSignal {
    loop {
        if let Some(sig) = rx.borrow_and_update().clone() {
            return sig;
        }
        if rx.changed().await.is_err() {
            return ControlSignal {
                action: ControlAction::Cancel,
                reason: Some("Transfer control channel closed".to_string()),
            };
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriterStop {
    Running,
    Pause,
    Cancel,
}

#[derive(Debug, Clone)]
pub struct PartialFilePaths {
    pub part_path: PathBuf,
    pub resume_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct PausedIncomingInfo {
    pub sender_node_id: NodeId,
    pub partial_files: Vec<PartialFilePaths>,
}

/// Returns the current UTC day index (`unix_timestamp / 86400`).
pub fn current_utc_day() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn derive_primary_offer_name(files: &[FileOfferEntry]) -> String {
    if files.is_empty() {
        return "Incoming items".to_string();
    }
    if files.len() == 1 {
        return Path::new(&files[0].relative_path)
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(&files[0].relative_path)
            .to_string();
    }
    let first_root = files[0]
        .relative_path
        .split(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty());
    if let Some(root) = first_root {
        let same_folder = files.iter().all(|f| {
            let rel = f.relative_path.as_str();
            rel.starts_with(&format!("{root}/")) || rel.starts_with(&format!("{root}\\"))
        });
        if same_folder {
            return root.to_string();
        }
    }
    Path::new(&files[0].relative_path)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(&files[0].relative_path)
        .to_string()
}

/// Computes a fast pre-dial summary `(primary_name, files_count, total_bytes)` for `source`
/// so the UI can enter `Connecting` immediately with accurate item metadata.
pub async fn preview_source_summary(source: &Path) -> Result<(String, usize, u64), TransferError> {
    let meta = tokio::fs::metadata(source).await?;
    let fallback_name = source
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("Transfer item")
        .to_string();
    if meta.is_file() {
        return Ok((fallback_name, 1, meta.len()));
    }
    if !meta.is_dir() {
        return Err(TransferError::EmptySource(source.to_path_buf()));
    }
    let source_owned = source.to_path_buf();
    let name_clone = fallback_name.clone();
    let (count, total_bytes) = tokio::task::spawn_blocking(move || -> std::io::Result<(usize, u64)> {
        let mut stack = vec![source_owned];
        let mut files = 0usize;
        let mut bytes = 0u64;
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let md = entry.metadata()?;
                if md.is_dir() {
                    stack.push(entry.path());
                } else if md.is_file() {
                    files += 1;
                    bytes = bytes.saturating_add(md.len());
                }
            }
        }
        Ok((files, bytes))
    })
    .await
    .map_err(|e| TransferError::Quic(e.to_string()))??;
    if count == 0 {
        return Err(TransferError::EmptySource(source.to_path_buf()));
    }
    Ok((name_clone, count, total_bytes))
}

/// Derives a 256-bit daily-rotating key from `wan_shared_secret` and `utc_day`.
pub fn derive_daily_wan_key(wan_shared_secret: &[u8; 32], utc_day: u64) -> [u8; 32] {
    let mut material = [0u8; 40];
    material[..32].copy_from_slice(wan_shared_secret);
    material[32..40].copy_from_slice(&utc_day.to_be_bytes());
    blake3::derive_key(WAN_DAILY_KEY_CONTEXT, &material)
}

fn build_wan_chunk_aad(transfer_id: Uuid, file_index: u32, byte_offset: u64) -> [u8; 28] {
    let mut aad = [0u8; 28];
    aad[..16].copy_from_slice(transfer_id.as_bytes());
    aad[16..20].copy_from_slice(&file_index.to_be_bytes());
    aad[20..28].copy_from_slice(&byte_offset.to_be_bytes());
    aad
}

struct WanCipherState {
    cached_day: u64,
    today_cipher: ChaCha20Poly1305,
    yesterday_cipher: Option<ChaCha20Poly1305>,
}

impl WanCipherState {
    fn for_day(secret: &[u8; 32], utc_day: u64) -> Self {
        let today_key = derive_daily_wan_key(secret, utc_day);
        let today_cipher = ChaCha20Poly1305::new((&today_key).into());
        let yesterday_cipher = utc_day.checked_sub(1).map(|prev| {
            let prev_key = derive_daily_wan_key(secret, prev);
            ChaCha20Poly1305::new((&prev_key).into())
        });
        Self {
            cached_day: utc_day,
            today_cipher,
            yesterday_cipher,
        }
    }
}

/// Automatic daily-rotating ChaCha20-Poly1305 cipher context used strictly for WAN chunks.
/// Accepts keys derived from both `day` and `day - 1` across UTC midnight boundaries.
pub struct WanCipherContext {
    transfer_id: Uuid,
    wan_shared_secret: [u8; 32],
    day_override: Option<u64>,
    state: StdMutex<WanCipherState>,
}

impl WanCipherContext {
    pub fn new(transfer_id: Uuid, wan_shared_secret: [u8; 32]) -> Self {
        let day = current_utc_day();
        Self {
            transfer_id,
            wan_shared_secret,
            day_override: None,
            state: StdMutex::new(WanCipherState::for_day(&wan_shared_secret, day)),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_utc_day(
        transfer_id: Uuid,
        wan_shared_secret: [u8; 32],
        utc_day: u64,
    ) -> Self {
        Self {
            transfer_id,
            wan_shared_secret,
            day_override: Some(utc_day),
            state: StdMutex::new(WanCipherState::for_day(&wan_shared_secret, utc_day)),
        }
    }

    fn effective_day(&self) -> u64 {
        self.day_override.unwrap_or_else(current_utc_day)
    }

    /// Encrypts `plaintext` into `[12-byte random nonce | ChaCha20-Poly1305 ciphertext + 16-byte tag]`.
    pub fn encrypt_chunk(
        &self,
        file_index: u32,
        byte_offset: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, TransferError> {
        let day = self.effective_day();
        let aad = build_wan_chunk_aad(self.transfer_id, file_index, byte_offset);
        let mut nonce_bytes = [0u8; WAN_CHUNK_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let mut guard = self.state.lock().expect("wan cipher mutex");
        if guard.cached_day != day {
            *guard = WanCipherState::for_day(&self.wan_shared_secret, day);
        }

        let ciphertext = guard
            .today_cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| TransferError::WanCrypto("AEAD chunk encryption failed".to_string()))?;

        let mut out = Vec::with_capacity(WAN_CHUNK_NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypts `[12-byte nonce | ciphertext + tag]`, accepting keys for `day` and `day - 1`.
    pub fn decrypt_chunk(
        &self,
        file_index: u32,
        byte_offset: u64,
        encrypted: &[u8],
    ) -> Result<Vec<u8>, TransferError> {
        if encrypted.len() <= WAN_CHUNK_OVERHEAD {
            return Err(TransferError::WanCrypto(format!(
                "Encrypted WAN chunk too short ({} bytes)",
                encrypted.len()
            )));
        }

        let day = self.effective_day();
        let (nonce_bytes, ct) = encrypted.split_at(WAN_CHUNK_NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        let aad = build_wan_chunk_aad(self.transfer_id, file_index, byte_offset);
        let mut guard = self.state.lock().expect("wan cipher mutex");
        if guard.cached_day != day {
            *guard = WanCipherState::for_day(&self.wan_shared_secret, day);
        }

        if let Ok(plaintext) = guard
            .today_cipher
            .decrypt(nonce, Payload { msg: ct, aad: &aad })
        {
            return Ok(plaintext);
        }
        if let Some(ref prev_cipher) = guard.yesterday_cipher {
            if let Ok(plaintext) = prev_cipher.decrypt(nonce, Payload { msg: ct, aad: &aad }) {
                return Ok(plaintext);
            }
        }

        Err(TransferError::WanCrypto(
            "WAN payload authentication failed (wrong contact secret or expired daily key)"
                .to_string(),
        ))
    }
}

struct ActiveIncomingTransfer {
    conn_stable_id: usize,
    chunk_tx: mpsc::Sender<IncomingChunk>,
    stop_tx: watch::Sender<WriterStop>,
    wan_cipher: Option<Arc<WanCipherContext>>,
    max_chunk_payload: usize,
}

struct ControlMapGuard {
    transfer_id: Uuid,
    active_controls: Arc<RwLock<HashMap<Uuid, watch::Sender<Option<ControlSignal>>>>>,
    disarmed: bool,
}

impl ControlMapGuard {
    fn new(
        transfer_id: Uuid,
        active_controls: Arc<RwLock<HashMap<Uuid, watch::Sender<Option<ControlSignal>>>>>,
    ) -> Self {
        Self {
            transfer_id,
            active_controls,
            disarmed: false,
        }
    }

    async fn remove_now(&mut self) {
        if !self.disarmed {
            self.disarmed = true;
            self.active_controls.write().await.remove(&self.transfer_id);
        }
    }
}

/// Active control registration handle created before dialing so Cancel/Pause works even while Connecting.
pub struct PreControlHandle {
    pub(crate) ctrl_rx: watch::Receiver<Option<ControlSignal>>,
    guard: ControlMapGuard,
}

impl PreControlHandle {
    pub fn paused_or_cancelled_action(&self) -> Option<(&'static str, Option<String>)> {
        self.ctrl_rx.borrow().as_ref().map(|sig| {
            let kind = match sig.action {
                ControlAction::Pause => "pause",
                ControlAction::Cancel => "cancel",
            };
            (kind, sig.reason.clone())
        })
    }

    pub async fn wait_control_signal(&mut self) {
        while self.ctrl_rx.borrow().is_none() {
            if self.ctrl_rx.changed().await.is_err() {
                break;
            }
        }
    }

    pub async fn release(mut self) {
        self.guard.remove_now().await;
    }
}

impl Drop for ControlMapGuard {
    fn drop(&mut self) {
        if !self.disarmed {
            if let Ok(mut guard) = self.active_controls.try_write() {
                guard.remove(&self.transfer_id);
            }
        }
    }
}

/// Engine managing bounded-memory parallel QUIC transfers, resume bitmaps, and BLAKE3 verification.
pub struct TransferEngine {
    download_dir: PathBuf,
    trust_store: Option<Arc<TrustStore>>,
    shared_endpoint: StdRwLock<Option<Arc<StdRwLock<Option<Endpoint>>>>>,
    shared_peer_table: StdRwLock<Option<Arc<RwLock<crate::discovery::PeerTable>>>>,
    pending_approvals: Arc<Mutex<HashMap<Uuid, oneshot::Sender<bool>>>>,
    approval_timeout: RwLock<Duration>,
    active_incoming: Arc<RwLock<HashMap<u64, ActiveIncomingTransfer>>>,
    active_controls: Arc<RwLock<HashMap<Uuid, watch::Sender<Option<ControlSignal>>>>>,
    paused_incoming: Arc<RwLock<HashMap<Uuid, PausedIncomingInfo>>>,
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
            shared_endpoint: StdRwLock::new(None),
            shared_peer_table: StdRwLock::new(None),
            pending_approvals: Arc::new(Mutex::new(HashMap::new())),
            approval_timeout: RwLock::new(DEFAULT_APPROVAL_TIMEOUT),
            active_incoming: Arc::new(RwLock::new(HashMap::new())),
            active_controls: Arc::new(RwLock::new(HashMap::new())),
            paused_incoming: Arc::new(RwLock::new(HashMap::new())),
            completed_files: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
        })
    }

    /// Attaches the node's shared `iroh::Endpoint` reference so transfers can distinguish
    /// direct local LAN paths from WAN/relay paths without extra round-trips.
    pub fn attach_endpoint(&self, endpoint: Arc<StdRwLock<Option<Endpoint>>>) {
        *self.shared_endpoint.write().expect("shared_endpoint rwlock") = Some(endpoint);
    }

    /// Attaches `DiscoveryEngine`'s live LAN `PeerTable` so incoming/outgoing transfers
    /// classify active mDNS/LAN peers accurately even before `conn_type` finishes settling.
    pub fn attach_peer_table(&self, peer_table: Arc<RwLock<crate::discovery::PeerTable>>) {
        *self
            .shared_peer_table
            .write()
            .expect("shared_peer_table rwlock") = Some(peer_table);
    }

    async fn is_connection_lan(&self, conn: Option<&Connection>, remote_node_id: NodeId) -> bool {
        let maybe_ep_lock = self
            .shared_endpoint
            .read()
            .expect("shared_endpoint rwlock")
            .clone();
        let table_snapshot = self
            .shared_peer_table
            .read()
            .expect("shared_peer_table rwlock")
            .clone();
        if maybe_ep_lock.is_none() && table_snapshot.is_none() {
            // Standalone unit/integration harnesses without DiscoveryEngine run directly on localhost LAN.
            return true;
        }
        let ep_snapshot = maybe_ep_lock
            .as_ref()
            .and_then(|shared| shared.read().expect("endpoint rwlock").clone());
        crate::discovery::is_connection_lan_with_table(
            ep_snapshot.as_ref(),
            conn,
            table_snapshot.as_ref(),
            remote_node_id,
        )
        .await
    }

    async fn is_connection_direct(&self, remote_node_id: NodeId) -> Option<bool> {
        let maybe_ep_lock = self
            .shared_endpoint
            .read()
            .expect("shared_endpoint rwlock")
            .clone()?;
        let ep_snapshot = maybe_ep_lock.read().expect("endpoint rwlock").clone()?;
        crate::discovery::is_endpoint_connection_direct(&ep_snapshot, remote_node_id)
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

    /// Returns `true` if any transfer is currently active, pending approval, or paused.
    pub async fn has_in_flight_transfers(&self) -> bool {
        !self.active_controls.read().await.is_empty()
            || !self.active_incoming.read().await.is_empty()
            || !self.pending_approvals.lock().await.is_empty()
            || !self.paused_incoming.read().await.is_empty()
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

    /// Requests a clean pause for an active outgoing or incoming transfer, leaving
    /// `.beamdrop.part` and `.resume.json` intact so resuming continues seamlessly.
    pub async fn pause_transfer(&self, transfer_id: Uuid) -> bool {
        let tx = {
            let guard = self.active_controls.read().await;
            guard.get(&transfer_id).cloned()
        };
        if let Some(tx) = tx {
            tx.send_if_modified(|curr| {
                if curr.is_none() {
                    *curr = Some(ControlSignal {
                        action: ControlAction::Pause,
                        reason: Some("Paused by user".to_string()),
                    });
                    true
                } else {
                    false
                }
            });
            return true;
        }
        false
    }

    /// Cancels an active or paused transfer, halting streams and deleting incomplete
    /// `.beamdrop.part` and `.resume.json` files on the receiver.
    pub async fn cancel_transfer(&self, transfer_id: Uuid) -> bool {
        let tx = {
            let guard = self.active_controls.read().await;
            guard.get(&transfer_id).cloned()
        };
        if let Some(tx) = tx {
            tx.send_if_modified(|curr| {
                let replace = !matches!(
                    curr.as_ref().map(|s| s.action),
                    Some(ControlAction::Cancel)
                );
                if replace {
                    *curr = Some(ControlSignal {
                        action: ControlAction::Cancel,
                        reason: Some("Cancelled by user".to_string()),
                    });
                }
                replace
            });
            return true;
        }

        if let Some(paused) = self.paused_incoming.write().await.remove(&transfer_id) {
            remove_partial_files(&paused.partial_files).await;
            let _ = self.event_tx.send(TransferEvent::Cancelled {
                transfer_id,
                reason: Some("Cancelled by user".to_string()),
            });
            return true;
        }

        false
    }

    /// Returns the original sender's `NodeId` for a paused incoming transfer, if known.
    pub async fn paused_incoming_sender(&self, transfer_id: Uuid) -> Option<NodeId> {
        self.paused_incoming
            .read()
            .await
            .get(&transfer_id)
            .map(|info| info.sender_node_id)
    }

    /// Emits an outgoing/incoming control event (`Paused` or `Cancelled`) for a `PreControlHandle`.
    pub fn emit_control_for_pre_control(&self, transfer_id: Uuid, kind: &str, reason: Option<String>) {
        match kind {
            "pause" => self.emit_paused(transfer_id, reason),
            _ => self.emit_cancelled(transfer_id, reason),
        }
    }

    /// Emits a `TransferEvent::Cancelled` notification for a transfer managed at the node level.
    pub fn emit_cancelled(&self, transfer_id: Uuid, reason: Option<String>) {
        let _ = self
            .event_tx
            .send(TransferEvent::Cancelled { transfer_id, reason });
    }

    /// Emits a `TransferEvent::Paused` notification for a transfer managed at the node level.
    pub fn emit_paused(&self, transfer_id: Uuid, reason: Option<String>) {
        let _ = self
            .event_tx
            .send(TransferEvent::Paused { transfer_id, reason });
    }

    /// Emits a `TransferEvent::Started` notification right when an outgoing transfer enters Connecting.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_started(
        &self,
        transfer_id: Uuid,
        peer_node_id: NodeId,
        peer_name: String,
        file_name: String,
        files: usize,
        total_bytes: u64,
        bytes_skipped_resumed: u64,
    ) {
        let _ = self.event_tx.send(TransferEvent::Started {
            transfer_id,
            peer_node_id,
            peer_name,
            file_name,
            files,
            total_bytes,
            bytes_skipped_resumed,
        });
    }

    /// Emits a `TransferEvent::Failed` notification with full item metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn emit_failed(
        &self,
        transfer_id: Uuid,
        direction: TransferDirection,
        peer_node_id: NodeId,
        peer_name: String,
        file_name: String,
        files: usize,
        total_bytes: u64,
        is_wan: Option<bool>,
        reason: String,
    ) {
        let _ = self.event_tx.send(TransferEvent::Failed {
            transfer_id,
            direction,
            peer_node_id,
            peer_name,
            file_name,
            files,
            total_bytes,
            is_wan,
            reason,
        });
    }

    /// Registers a `ControlSignal` channel for `transfer_id` before dialing starts so Cancel/Pause
    /// works immediately in `Connecting` state.
    pub async fn register_control(&self, transfer_id: Uuid) -> PreControlHandle {
        let (ctrl_tx, ctrl_rx) = watch::channel::<Option<ControlSignal>>(None);
        {
            let mut controls = self.active_controls.write().await;
            controls.insert(transfer_id, ctrl_tx);
        }
        PreControlHandle {
            ctrl_rx,
            guard: ControlMapGuard::new(transfer_id, Arc::clone(&self.active_controls)),
        }
    }

    /// Handles an out-of-band `Pause` or `Cancel` control message received after a transfer paused.
    pub async fn handle_remote_control(&self, msg: Message) -> bool {
        match msg {
            Message::Cancel(ctrl) => {
                if let Some(paused) = self.paused_incoming.write().await.remove(&ctrl.transfer_id) {
                    remove_partial_files(&paused.partial_files).await;
                    let _ = self.event_tx.send(TransferEvent::Cancelled {
                        transfer_id: ctrl.transfer_id,
                        reason: ctrl.reason.or_else(|| Some("Cancelled by peer".to_string())),
                    });
                    return true;
                }
                if let Some(tx) = self.active_controls.read().await.get(&ctrl.transfer_id).cloned() {
                    let _ = tx.send(Some(ControlSignal {
                        action: ControlAction::Cancel,
                        reason: ctrl.reason.or_else(|| Some("Cancelled by peer".to_string())),
                    }));
                    return true;
                }
                false
            }
            Message::Pause(ctrl) => {
                if let Some(tx) = self.active_controls.read().await.get(&ctrl.transfer_id).cloned() {
                    let _ = tx.send(Some(ControlSignal {
                        action: ControlAction::Pause,
                        reason: ctrl.reason.or_else(|| Some("Paused by peer".to_string())),
                    }));
                    return true;
                }
                false
            }
            _ => false,
        }
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
                    if *entry.stop_tx.borrow() == WriterStop::Running {
                        let _ = entry.stop_tx.send(WriterStop::Pause);
                    }
                }
            }
        });
    }

    async fn read_uni_stream(&self, mut recv: RecvStream) {
        let mut header_buf = [0u8; UNI_CHUNK_HEADER_LEN];
        let mut cached_tid: Option<u64> = None;
        let mut cached_tx: Option<mpsc::Sender<IncomingChunk>> = None;
        let mut cached_stop_tx: Option<watch::Sender<WriterStop>> = None;
        let mut cached_stop: Option<watch::Receiver<WriterStop>> = None;
        let mut cached_cipher: Option<Arc<WanCipherContext>> = None;
        let mut cached_max_payload: usize = CHUNK_SIZE;

        loop {
            if let Some(ref stop_rx) = cached_stop {
                if *stop_rx.borrow() != WriterStop::Running {
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
            if hdr.chunk_len == 0 || hdr.chunk_len as usize > WAN_CHUNK_SIZE + WAN_CHUNK_OVERHEAD {
                break;
            }

            if cached_tid != Some(hdr.transfer_id) {
                let active = self.active_incoming.read().await;
                if let Some(sink) = active.get(&hdr.transfer_id) {
                    cached_tid = Some(hdr.transfer_id);
                    cached_tx = Some(sink.chunk_tx.clone());
                    cached_stop_tx = Some(sink.stop_tx.clone());
                    cached_stop = Some(sink.stop_tx.subscribe());
                    cached_cipher = sink.wan_cipher.clone();
                    cached_max_payload = sink.max_chunk_payload;
                } else {
                    break;
                }
            }

            let max_wire = if cached_cipher.is_some() {
                cached_max_payload + WAN_CHUNK_OVERHEAD
            } else {
                cached_max_payload
            };
            let min_wire = if cached_cipher.is_some() {
                WAN_CHUNK_OVERHEAD + 1
            } else {
                1
            };
            if (hdr.chunk_len as usize) < min_wire || (hdr.chunk_len as usize) > max_wire {
                if let Some(ref stop_tx) = cached_stop_tx {
                    let _ = stop_tx.send(WriterStop::Cancel);
                }
                break;
            }

            let mut wire_data = vec![0u8; hdr.chunk_len as usize];
            if recv.read_exact(&mut wire_data).await.is_err() {
                break;
            }

            let data = if let Some(ref cipher) = cached_cipher {
                match cipher.decrypt_chunk(hdr.file_index, hdr.byte_offset, &wire_data) {
                    Ok(plaintext) => plaintext,
                    Err(_) => {
                        if let Some(ref stop_tx) = cached_stop_tx {
                            let _ = stop_tx.send(WriterStop::Cancel);
                        }
                        break;
                    }
                }
            } else {
                wire_data
            };

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
        let primary_file_name = derive_primary_offer_name(&offer.files);
        let sender_node_id = match conn.remote_node_id() {
            Ok(id) => id,
            Err(err) => {
                self.paused_incoming.write().await.remove(&transfer_uuid);
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

        let display_sender_name = match &self.trust_store {
            Some(store) => store
                .peer_display_name(&sender_node_id)
                .await
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| offer.sender_name.clone()),
            None => offer.sender_name.clone(),
        };

        let is_lan = self.is_connection_lan(Some(&conn), sender_node_id).await;
        let is_wan_path = !is_lan || offer.wan_encrypted;
        let wan_cipher = if is_wan_path {
            let maybe_secret = match &self.trust_store {
                Some(store) => store.wan_secret_if_allowed(&sender_node_id).await,
                None => None,
            };
            let Some(secret) = maybe_secret else {
                self.paused_incoming.write().await.remove(&transfer_uuid);
                let reason =
                    "Long-distance WAN transfers are disabled for this contact".to_string();
                let reject = Message::Reject(RejectPayload {
                    transfer_id: transfer_uuid,
                    reason: Some(reason.clone()),
                });
                let _ = write_frame(&mut ctrl_send, &reject).await;
                let _ = ctrl_send.finish();
                self.emit_failed(
                    transfer_uuid,
                    TransferDirection::Incoming,
                    sender_node_id,
                    display_sender_name,
                    primary_file_name,
                    offer.files.len(),
                    offer.total_bytes,
                    Some(true),
                    reason,
                );
                return;
            };
            if !is_lan && !offer.wan_encrypted {
                self.paused_incoming.write().await.remove(&transfer_uuid);
                let reason =
                    "Encrypted WAN payload framing is required over non-LAN connections".to_string();
                let reject = Message::Reject(RejectPayload {
                    transfer_id: transfer_uuid,
                    reason: Some(reason.clone()),
                });
                let _ = write_frame(&mut ctrl_send, &reject).await;
                let _ = ctrl_send.finish();
                self.emit_failed(
                    transfer_uuid,
                    TransferDirection::Incoming,
                    sender_node_id,
                    display_sender_name,
                    primary_file_name,
                    offer.files.len(),
                    offer.total_bytes,
                    Some(true),
                    reason,
                );
                return;
            }
            Some(Arc::new(WanCipherContext::new(transfer_uuid, secret)))
        } else {
            None
        };

        let was_previously_approved_pause = self
            .paused_incoming
            .write()
            .await
            .remove(&transfer_uuid)
            .is_some_and(|info| info.sender_node_id == sender_node_id);

        let (ctrl_tx, mut ctrl_rx) = watch::channel::<Option<ControlSignal>>(None);
        {
            let mut controls = self.active_controls.write().await;
            controls.insert(transfer_uuid, ctrl_tx);
        }
        let mut ctrl_guard = ControlMapGuard::new(transfer_uuid, Arc::clone(&self.active_controls));

        let _ = self.event_tx.send(TransferEvent::OfferReceived {
            transfer_id: transfer_uuid,
            sender_name: display_sender_name.clone(),
            files: offer.files.len(),
            total_bytes: offer.total_bytes,
        });

        let is_wan = is_wan_path;
        let auto_accept = was_previously_approved_pause
            || match &self.trust_store {
                Some(store) => matches!(
                    store.offer_approval(&sender_node_id, !is_wan).await,
                    OfferApproval::AutoAccept
                ),
                None => false,
            };

        if auto_accept {
            let _ = self.event_tx.send(TransferEvent::AutoAccepted {
                transfer_id: transfer_uuid,
                sender_node_id,
                sender_name: display_sender_name.clone(),
                files: offer.files.len(),
                total_bytes: offer.total_bytes,
            });
        } else {
            let (tx, rx) = oneshot::channel::<bool>();
            {
                let mut pending = self.pending_approvals.lock().await;
                pending.insert(transfer_uuid, tx);
            }

            let wait_dur = *self.approval_timeout.read().await;
            let expires_at_unix_ms = now_unix_ms().saturating_add(wait_dur.as_millis() as u64);

            let _ = self.event_tx.send(TransferEvent::PendingApproval {
                transfer_id: transfer_uuid,
                sender_node_id,
                sender_name: display_sender_name.clone(),
                file_name: primary_file_name.clone(),
                files: offer.files.len(),
                total_bytes: offer.total_bytes,
                is_wan,
                expires_at_unix_ms,
            });

            enum ApprovalOutcome {
                Approved,
                Rejected(String),
                Control {
                    signal: ControlSignal,
                    initiated_locally: bool,
                },
            }

            let outcome = tokio::select! {
                biased;
                signal = recv_control_signal(&mut ctrl_rx) => {
                    ApprovalOutcome::Control {
                        signal,
                        initiated_locally: true,
                    }
                }
                remote = read_frame(&mut ctrl_recv) => {
                    match remote {
                        Ok(Message::Pause(p)) => ApprovalOutcome::Control {
                            signal: ControlSignal {
                                action: ControlAction::Pause,
                                reason: p.reason.or_else(|| Some("Paused by peer".to_string())),
                            },
                            initiated_locally: false,
                        },
                        Ok(Message::Cancel(c)) => ApprovalOutcome::Control {
                            signal: ControlSignal {
                                action: ControlAction::Cancel,
                                reason: c.reason.or_else(|| Some("Cancelled by peer".to_string())),
                            },
                            initiated_locally: false,
                        },
                        Ok(other) => ApprovalOutcome::Rejected(format!(
                            "Unexpected control frame before acceptance: {:?}",
                            other.message_type()
                        )),
                        Err(_) => ApprovalOutcome::Rejected(
                            "Sender disconnected before transfer approval".to_string(),
                        ),
                    }
                }
                res = tokio::time::timeout(wait_dur, rx) => {
                    match res {
                        Ok(Ok(true)) => ApprovalOutcome::Approved,
                        Ok(Ok(false)) => ApprovalOutcome::Rejected("Transfer rejected by user".to_string()),
                        Ok(Err(_)) => ApprovalOutcome::Rejected("Transfer approval channel closed".to_string()),
                        Err(_) => ApprovalOutcome::Rejected(format!(
                            "Untrusted transfer offer timed out after {}s",
                            wait_dur.as_secs()
                        )),
                    }
                }
                _ = conn.closed() => {
                    ApprovalOutcome::Rejected("Sender disconnected before transfer approval".to_string())
                }
            };

            {
                let mut pending = self.pending_approvals.lock().await;
                pending.remove(&transfer_uuid);
            }

            match outcome {
                ApprovalOutcome::Approved => {}
                ApprovalOutcome::Control {
                    signal,
                    initiated_locally,
                } => {
                    ctrl_guard.remove_now().await;
                    if initiated_locally {
                        send_control_frame(&mut ctrl_send, transfer_uuid, &signal).await;
                    }
                    emit_control_event(&self.event_tx, transfer_uuid, signal);
                    return;
                }
                ApprovalOutcome::Rejected(reason) => {
                    ctrl_guard.remove_now().await;
                    let reject = Message::Reject(RejectPayload {
                        transfer_id: transfer_uuid,
                        reason: Some(reason.clone()),
                    });
                    let _ = write_frame(&mut ctrl_send, &reject).await;
                    let _ = ctrl_send.finish();
                    self.emit_failed(
                        transfer_uuid,
                        TransferDirection::Incoming,
                        sender_node_id,
                        display_sender_name,
                        primary_file_name,
                        offer.files.len(),
                        offer.total_bytes,
                        Some(is_wan),
                        reason,
                    );
                    return;
                }
            }
        }

        let prepared = match self.prepare_incoming_files(&offer.files).await {
            Ok(files) => files,
            Err(err) => {
                ctrl_guard.remove_now().await;
                let reject = Message::Reject(RejectPayload {
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

        let partial_files: Vec<PartialFilePaths> = prepared
            .iter()
            .map(|f| PartialFilePaths {
                part_path: f.part_path.clone(),
                resume_path: f.resume_path.clone(),
            })
            .collect();

        let mut accepted_file_ids = Vec::with_capacity(prepared.len());
        let mut file_resumes = Vec::with_capacity(prepared.len());
        let mut remaining_chunks = 0u64;
        let mut initial_skipped_bytes = 0u64;
        let first_file_name = prepared
            .first()
            .map(|f| f.relative_path.clone())
            .unwrap_or_default();

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

        let max_chunk_payload = if is_wan { WAN_CHUNK_SIZE } else { CHUNK_SIZE };
        let inbound_channel_bound = if is_wan {
            WAN_CHANNEL_BOUND
        } else {
            CHANNEL_BOUND
        };
        let (chunk_tx, chunk_rx) = mpsc::channel::<IncomingChunk>(inbound_channel_bound);
        let (stop_tx, stop_rx) = watch::channel(WriterStop::Running);

        {
            let mut active = self.active_incoming.write().await;
            active.insert(
                stream_tid,
                ActiveIncomingTransfer {
                    conn_stable_id: conn.stable_id(),
                    chunk_tx: chunk_tx.clone(),
                    stop_tx: stop_tx.clone(),
                    wan_cipher,
                    max_chunk_payload,
                },
            );
        }

        let shared_endpoint = self
            .shared_endpoint
            .read()
            .expect("shared_endpoint rwlock")
            .clone();
        let mut writer_handle = tokio::spawn(run_incoming_writer(
            transfer_uuid,
            sender_node_id,
            is_wan,
            max_chunk_payload,
            shared_endpoint,
            prepared,
            remaining_chunks,
            offer.total_bytes,
            initial_skipped_bytes,
            chunk_rx,
            stop_rx,
            self.event_tx.clone(),
        ));

        let accept_msg = Message::Accept(AcceptPayload {
            transfer_id: transfer_uuid,
            accepted_file_ids,
            file_resumes,
        });

        if let Err(err) = write_frame(&mut ctrl_send, &accept_msg).await {
            ctrl_guard.remove_now().await;
            self.cleanup_active_transfer(stream_tid, &stop_tx, WriterStop::Pause)
                .await;
            drop(chunk_tx);
            let _ = writer_handle.await;
            let _ = self.event_tx.send(TransferEvent::Interrupted {
                transfer_id: transfer_uuid,
                reason: err.to_string(),
            });
            return;
        }

        if initial_skipped_bytes > 0 || !first_file_name.is_empty() {
            let initial_is_direct = if is_wan {
                self.is_connection_direct(sender_node_id).await
            } else {
                None
            };
            let _ = self.event_tx.send(TransferEvent::Progress(TransferProgress {
                transfer_id: transfer_uuid,
                file_name: first_file_name,
                bytes_transferred: 0,
                bytes_skipped_resumed: initial_skipped_bytes,
                total_bytes: offer.total_bytes,
                is_wan,
                is_direct: initial_is_direct,
                streams_active: if offer.total_bytes > PARALLEL_STRIPE_THRESHOLD {
                    MAX_PARALLEL_STREAMS
                } else {
                    1
                },
            }));
        }

        enum IncomingWaitResult {
            Complete(CompletePayload),
            Control {
                signal: ControlSignal,
                initiated_locally: bool,
            },
            Unexpected(String),
            Disconnected(String),
        }

        let wait_result = tokio::select! {
            biased;
            signal = recv_control_signal(&mut ctrl_rx) => {
                IncomingWaitResult::Control {
                    signal,
                    initiated_locally: true,
                }
            }
            res = read_frame(&mut ctrl_recv) => {
                match res {
                    Ok(Message::Complete(c)) if c.transfer_id == transfer_uuid => {
                        IncomingWaitResult::Complete(c)
                    }
                    Ok(Message::Pause(p)) => IncomingWaitResult::Control {
                        signal: ControlSignal {
                            action: ControlAction::Pause,
                            reason: p.reason.or_else(|| Some("Paused by sender".to_string())),
                        },
                        initiated_locally: false,
                    },
                    Ok(Message::Cancel(c)) => IncomingWaitResult::Control {
                        signal: ControlSignal {
                            action: ControlAction::Cancel,
                            reason: c.reason.or_else(|| Some("Cancelled by sender".to_string())),
                        },
                        initiated_locally: false,
                    },
                    Ok(other) => IncomingWaitResult::Unexpected(format!(
                        "Unexpected control frame: {:?}",
                        other.message_type()
                    )),
                    Err(err) => IncomingWaitResult::Disconnected(err.to_string()),
                }
            }
            _ = conn.closed() => {
                IncomingWaitResult::Disconnected("Connection closed before transfer completion".to_string())
            }
        };

        let sender_complete = match wait_result {
            IncomingWaitResult::Complete(c) => c,
            IncomingWaitResult::Control {
                signal,
                initiated_locally,
            } => {
                self.finish_incoming_control_stop(
                    transfer_uuid,
                    sender_node_id,
                    stream_tid,
                    &mut ctrl_send,
                    &mut ctrl_guard,
                    &ctrl_rx,
                    &stop_tx,
                    chunk_tx,
                    &mut writer_handle,
                    partial_files,
                    signal,
                    initiated_locally,
                )
                .await;
                return;
            }
            IncomingWaitResult::Unexpected(reason) => {
                ctrl_guard.remove_now().await;
                self.cleanup_active_transfer(stream_tid, &stop_tx, WriterStop::Pause)
                    .await;
                drop(chunk_tx);
                let _ = writer_handle.await;
                let _ = self.event_tx.send(TransferEvent::Interrupted {
                    transfer_id: transfer_uuid,
                    reason,
                });
                return;
            }
            IncomingWaitResult::Disconnected(reason) => {
                ctrl_guard.remove_now().await;
                self.cleanup_active_transfer(stream_tid, &stop_tx, WriterStop::Pause)
                    .await;
                drop(chunk_tx);
                let _ = tokio::time::timeout(Duration::from_secs(2), writer_handle).await;
                self.paused_incoming.write().await.insert(
                    transfer_uuid,
                    PausedIncomingInfo {
                        sender_node_id,
                        partial_files,
                    },
                );
                let display_reason = if !is_wan {
                    "Wi-Fi disconnected — tap Resume when back online".to_string()
                } else {
                    reason
                };
                let _ = self.event_tx.send(TransferEvent::Interrupted {
                    transfer_id: transfer_uuid,
                    reason: display_reason,
                });
                return;
            }
        };

        // Wait for the writer task to finish writing and hashing all chunks, still allowing late
        // pause/cancel from either the local receiver or the sender's control stream.
        tokio::pin!(writer_handle);
        let mut remote_closed = false;
        let writer_res = loop {
            tokio::select! {
                biased;
                signal = recv_control_signal(&mut ctrl_rx) => {
                    self.finish_incoming_control_stop(
                        transfer_uuid,
                        sender_node_id,
                        stream_tid,
                        &mut ctrl_send,
                        &mut ctrl_guard,
                        &ctrl_rx,
                        &stop_tx,
                        chunk_tx,
                        &mut writer_handle,
                        partial_files,
                        signal,
                        true,
                    )
                    .await;
                    return;
                }
                remote = read_frame(&mut ctrl_recv), if !remote_closed => {
                    let remote_signal = match remote {
                        Ok(Message::Pause(p)) => Some(ControlSignal {
                            action: ControlAction::Pause,
                            reason: p.reason.or_else(|| Some("Paused by sender".to_string())),
                        }),
                        Ok(Message::Cancel(c)) => Some(ControlSignal {
                            action: ControlAction::Cancel,
                            reason: c.reason.or_else(|| Some("Cancelled by sender".to_string())),
                        }),
                        Ok(other) => {
                            self.cleanup_active_transfer(stream_tid, &stop_tx, WriterStop::Pause)
                                .await;
                            break Err(TransferError::UnexpectedMessage(format!(
                                "Unexpected control frame: {:?}",
                                other.message_type()
                            )));
                        }
                        Err(ProtocolError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            remote_closed = true;
                            None
                        }
                        Err(err) => {
                            self.cleanup_active_transfer(stream_tid, &stop_tx, WriterStop::Pause)
                                .await;
                            break Err(TransferError::Protocol(err));
                        }
                    };
                    if let Some(signal) = remote_signal {
                        self.finish_incoming_control_stop(
                            transfer_uuid,
                            sender_node_id,
                            stream_tid,
                            &mut ctrl_send,
                            &mut ctrl_guard,
                            &ctrl_rx,
                            &stop_tx,
                            chunk_tx,
                            &mut writer_handle,
                            partial_files,
                            signal,
                            false,
                        )
                        .await;
                        return;
                    }
                }
                res = &mut writer_handle => {
                    break match res {
                        Ok(inner) => inner,
                        Err(e) => Err(TransferError::Quic(e.to_string())),
                    };
                }
                _ = conn.closed() => {
                    self.cleanup_active_transfer(stream_tid, &stop_tx, WriterStop::Pause)
                        .await;
                    break Err(TransferError::DisconnectedMidTransfer {
                        transfer_id: transfer_uuid,
                        remaining_chunks: 1,
                    });
                }
            }
        };

        if writer_res.is_err() {
            drop(chunk_tx);
            let _ = tokio::time::timeout(Duration::from_secs(2), writer_handle).await;
            ctrl_guard.remove_now().await;
            let mut active = self.active_incoming.write().await;
            active.remove(&stream_tid);
        } else {
            // Always remove active sink and control entries now that writer finished.
            ctrl_guard.remove_now().await;
            {
                let mut active = self.active_incoming.write().await;
                active.remove(&stream_tid);
            }
            drop(chunk_tx);
        }

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
            Err(TransferError::Paused(_)) => {
                self.paused_incoming.write().await.insert(
                    transfer_uuid,
                    PausedIncomingInfo {
                        sender_node_id,
                        partial_files,
                    },
                );
                emit_control_event(
                    &self.event_tx,
                    transfer_uuid,
                    ControlSignal {
                        action: ControlAction::Pause,
                        reason: Some("Paused".to_string()),
                    },
                );
            }
            Err(TransferError::Cancelled(_)) => {
                remove_partial_files(&partial_files).await;
                emit_control_event(
                    &self.event_tx,
                    transfer_uuid,
                    ControlSignal {
                        action: ControlAction::Cancel,
                        reason: Some("Cancelled".to_string()),
                    },
                );
            }
            Err(err) => {
                let recoverable = err.is_recoverable_network_drop();
                if recoverable {
                    self.paused_incoming.write().await.insert(
                        transfer_uuid,
                        PausedIncomingInfo {
                            sender_node_id,
                            partial_files,
                        },
                    );
                }
                let reason = if recoverable && !is_wan {
                    "Wi-Fi disconnected — tap Resume when back online".to_string()
                } else {
                    err.to_string()
                };
                let _ = self.event_tx.send(TransferEvent::Interrupted {
                    transfer_id: transfer_uuid,
                    reason,
                });
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_incoming_control_stop(
        &self,
        transfer_uuid: Uuid,
        sender_node_id: NodeId,
        stream_tid: u64,
        ctrl_send: &mut SendStream,
        ctrl_guard: &mut ControlMapGuard,
        ctrl_rx: &watch::Receiver<Option<ControlSignal>>,
        stop_tx: &watch::Sender<WriterStop>,
        chunk_tx: mpsc::Sender<IncomingChunk>,
        writer_handle: &mut JoinHandle<Result<Vec<CompletedFileInfo>, TransferError>>,
        partial_files: Vec<PartialFilePaths>,
        signal: ControlSignal,
        initiated_locally: bool,
    ) {
        let stop_mode = match signal.action {
            ControlAction::Pause => WriterStop::Pause,
            ControlAction::Cancel => WriterStop::Cancel,
        };
        if initiated_locally {
            send_control_frame(ctrl_send, transfer_uuid, &signal).await;
        }
        self.cleanup_active_transfer(stream_tid, stop_tx, stop_mode)
            .await;
        drop(chunk_tx);

        // Wait briefly for writer_handle to flush/save (Pause) or drop File handles (Cancel).
        if tokio::time::timeout(Duration::from_secs(2), &mut *writer_handle)
            .await
            .is_err()
        {
            writer_handle.abort();
            let _ = writer_handle.await;
        }

        // Atomically transition from `active_controls` into `paused_incoming` (lock order:
        // `paused_incoming` -> `active_controls`) so an out-of-band `Cancel` cannot miss either map.
        let mut paused_guard = self.paused_incoming.write().await;
        ctrl_guard.remove_now().await;
        let final_signal = ctrl_rx.borrow().clone().unwrap_or(signal);

        match final_signal.action {
            ControlAction::Pause => {
                paused_guard.insert(
                    transfer_uuid,
                    PausedIncomingInfo {
                        sender_node_id,
                        partial_files,
                    },
                );
                drop(paused_guard);
            }
            ControlAction::Cancel => {
                paused_guard.remove(&transfer_uuid);
                drop(paused_guard);
                remove_partial_files(&partial_files).await;
            }
        }

        emit_control_event(&self.event_tx, transfer_uuid, final_signal);
        if !initiated_locally {
            // Confirm receipt + state persistence so sender does not close `Connection` prematurely.
            let _ = ctrl_send.finish();
        }
    }

    async fn cleanup_active_transfer(
        &self,
        stream_tid: u64,
        stop_tx: &watch::Sender<WriterStop>,
        mode: WriterStop,
    ) {
        let _ = stop_tx.send(mode);
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
        self.send_path_with_id(conn, sender_name, source_path, None, None, progress_tx)
            .await
    }

    /// Sends a single file or recursive directory with optional target metadata and explicit
    /// `transfer_id` (used when resuming paused outgoing transfers in-place).
    pub async fn send_path_with_id(
        &self,
        conn: &Connection,
        sender_name: &str,
        source_path: &Path,
        peer_name: Option<&str>,
        transfer_id_override: Option<Uuid>,
        progress_tx: Option<mpsc::Sender<TransferProgress>>,
    ) -> Result<TransferSummary, TransferError> {
        self.send_path_with_wan_override(
            conn,
            sender_name,
            source_path,
            peer_name,
            transfer_id_override,
            progress_tx,
            None,
        )
        .await
    }

    /// Sends a single file or recursive directory with explicit control over whether daily-rotating
    /// ChaCha20-Poly1305 WAN encryption is enforced (`None` = automatic based on LAN vs WAN path).
    #[allow(clippy::too_many_arguments)]
    pub async fn send_path_with_wan_override(
        &self,
        conn: &Connection,
        sender_name: &str,
        source_path: &Path,
        peer_name: Option<&str>,
        transfer_id_override: Option<Uuid>,
        progress_tx: Option<mpsc::Sender<TransferProgress>>,
        force_wan_encryption: Option<bool>,
    ) -> Result<TransferSummary, TransferError> {
        self.send_path_with_control_and_wan(
            conn,
            sender_name,
            source_path,
            peer_name,
            transfer_id_override,
            progress_tx,
            force_wan_encryption,
            None,
            None,
            true,
        )
        .await
    }

    /// Sends a single file or recursive directory reusing a pre-registered `PreControlHandle`
    /// and emitting `AwaitingApproval` and `Failed` lifecycle events on the sender side.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_path_with_control_and_wan(
        &self,
        conn: &Connection,
        sender_name: &str,
        source_path: &Path,
        peer_name: Option<&str>,
        transfer_id_override: Option<Uuid>,
        progress_tx: Option<mpsc::Sender<TransferProgress>>,
        force_wan_encryption: Option<bool>,
        pre_control: Option<PreControlHandle>,
        connected_via_lan_hint: Option<bool>,
        emit_started_event: bool,
    ) -> Result<TransferSummary, TransferError> {
        let start = Instant::now();
        let transfer_uuid = transfer_id_override.unwrap_or_else(Uuid::new_v4);
        let stream_tid = transfer_stream_id(transfer_uuid);
        let peer_node_id = conn
            .remote_node_id()
            .map_err(|e| TransferError::Quic(e.to_string()))?;

        let peer_label = match &self.trust_store {
            Some(store) => store
                .peer_display_name(&peer_node_id)
                .await
                .filter(|s| !s.trim().is_empty()),
            None => None,
        }
        .or_else(|| peer_name.map(ToString::to_string))
        .unwrap_or_else(|| peer_node_id.to_string());

        let (mut ctrl_rx, mut ctrl_guard) = match pre_control {
            Some(handle) => (handle.ctrl_rx, handle.guard),
            None => {
                let (ctrl_tx, ctrl_rx) = watch::channel::<Option<ControlSignal>>(None);
                {
                    let mut controls = self.active_controls.write().await;
                    controls.insert(transfer_uuid, ctrl_tx);
                }
                let guard =
                    ControlMapGuard::new(transfer_uuid, Arc::clone(&self.active_controls));
                (ctrl_rx, guard)
            }
        };

        let manifest = match collect_transfer_manifest(source_path).await {
            Ok(m) => m,
            Err(err) => {
                ctrl_guard.remove_now().await;
                let fallback_name = source_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("Transfer item")
                    .to_string();
                self.emit_failed(
                    transfer_uuid,
                    TransferDirection::Outgoing,
                    peer_node_id,
                    peer_label,
                    fallback_name,
                    1,
                    0,
                    None,
                    err.to_string(),
                );
                return Err(err);
            }
        };
        let total_bytes: u64 = manifest.iter().map(|m| m.offer_entry.size_bytes).sum();
        let primary_name = source_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(ToString::to_string)
            .unwrap_or_else(|| {
                manifest
                    .first()
                    .map(|m| m.offer_entry.relative_path.clone())
                    .unwrap_or_default()
            });

        if emit_started_event {
            self.emit_started(
                transfer_uuid,
                peer_node_id,
                peer_label.clone(),
                primary_name.clone(),
                manifest.len(),
                total_bytes,
                0,
            );
        }

        let initial_signal = ctrl_rx.borrow().clone();
        if let Some(signal) = initial_signal {
            ctrl_guard.remove_now().await;
            emit_control_event(&self.event_tx, transfer_uuid, signal.clone());
            return Err(control_error(transfer_uuid, signal.action));
        }

        let mut is_lan = self.is_connection_lan(Some(conn), peer_node_id).await;
        if connected_via_lan_hint == Some(false) {
            let endpoint_direct = self
                .shared_endpoint
                .read()
                .expect("shared_endpoint rwlock")
                .as_ref()
                .and_then(|shared| shared.read().expect("endpoint rwlock").clone())
                .is_some_and(|ep| crate::discovery::is_endpoint_connection_lan(&ep, peer_node_id));
            if !endpoint_direct {
                is_lan = false;
            }
        }
        let encrypt_wan = force_wan_encryption.unwrap_or(!is_lan);
        let wan_cipher = if encrypt_wan {
            let secret = match &self.trust_store {
                Some(store) => store.wan_secret_if_allowed(&peer_node_id).await,
                None => None,
            };
            let Some(secret) = secret else {
                ctrl_guard.remove_now().await;
                let msg = "Long-distance transfers are disabled for this contact".to_string();
                self.emit_failed(
                    transfer_uuid,
                    TransferDirection::Outgoing,
                    peer_node_id,
                    peer_label,
                    primary_name,
                    manifest.len(),
                    total_bytes,
                    Some(true),
                    msg.clone(),
                );
                return Err(TransferError::WanDisallowed(msg));
            };
            Some(Arc::new(WanCipherContext::new(transfer_uuid, secret)))
        } else {
            None
        };

        let is_wan_transfer = !is_lan || wan_cipher.is_some();

        let offer = OfferPayload {
            transfer_id: transfer_uuid,
            sender_name: sender_name.to_string(),
            files: manifest.iter().map(|m| m.offer_entry.clone()).collect(),
            total_bytes,
            wan_encrypted: wan_cipher.is_some(),
        };

        let (mut ctrl_send, mut ctrl_recv) = match conn.open_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                ctrl_guard.remove_now().await;
                let msg = e.to_string();
                self.emit_failed(
                    transfer_uuid,
                    TransferDirection::Outgoing,
                    peer_node_id,
                    peer_label,
                    primary_name,
                    manifest.len(),
                    total_bytes,
                    Some(is_wan_transfer),
                    msg.clone(),
                );
                return Err(TransferError::Quic(msg));
            }
        };

        if let Err(err) = write_frame(&mut ctrl_send, &Message::Offer(offer)).await {
            ctrl_guard.remove_now().await;
            let err = TransferError::Protocol(err);
            self.emit_failed(
                transfer_uuid,
                TransferDirection::Outgoing,
                peer_node_id,
                peer_label,
                primary_name,
                manifest.len(),
                total_bytes,
                Some(is_wan_transfer),
                err.to_string(),
            );
            return Err(err);
        }

        let approval_wait = *self.approval_timeout.read().await;
        let expires_at_unix_ms = now_unix_ms().saturating_add(approval_wait.as_millis() as u64);
        let _ = self.event_tx.send(TransferEvent::AwaitingApproval {
            transfer_id: transfer_uuid,
            peer_node_id,
            peer_name: peer_label.clone(),
            file_name: primary_name.clone(),
            files: manifest.len(),
            total_bytes,
            is_wan: is_wan_transfer,
            expires_at_unix_ms,
        });

        let accept = tokio::select! {
            biased;
            signal = recv_control_signal(&mut ctrl_rx) => {
                ctrl_guard.remove_now().await;
                send_control_frame(&mut ctrl_send, transfer_uuid, &signal).await;
                emit_control_event(&self.event_tx, transfer_uuid, signal.clone());
                return Err(control_error(transfer_uuid, signal.action));
            }
            frame_res = tokio::time::timeout(approval_wait, read_frame(&mut ctrl_recv)) => {
                match frame_res {
                    Ok(Ok(Message::Accept(a))) => a,
                    Ok(Ok(Message::Reject(r))) => {
                        ctrl_guard.remove_now().await;
                        let raw_reason = r.reason.unwrap_or_else(|| "No reason given".to_string());
                        let ui_reason = if raw_reason.to_ascii_lowercase().contains("timed out") {
                            format!("{peer_label} did not receive the transfer (timed out)")
                        } else if raw_reason == "Transfer rejected by user" {
                            format!("{peer_label} declined the transfer")
                        } else {
                            raw_reason.clone()
                        };
                        self.emit_failed(
                            transfer_uuid,
                            TransferDirection::Outgoing,
                            peer_node_id,
                            peer_label.clone(),
                            primary_name.clone(),
                            manifest.len(),
                            total_bytes,
                            Some(is_wan_transfer),
                            ui_reason,
                        );
                        return Err(TransferError::Rejected(transfer_uuid, raw_reason));
                    }
                    Ok(Ok(Message::Pause(p))) => {
                        ctrl_guard.remove_now().await;
                        let signal = ControlSignal {
                            action: ControlAction::Pause,
                            reason: p.reason.or_else(|| Some("Paused by receiver".to_string())),
                        };
                        emit_control_event(&self.event_tx, transfer_uuid, signal);
                        return Err(TransferError::Paused(transfer_uuid));
                    }
                    Ok(Ok(Message::Cancel(c))) => {
                        ctrl_guard.remove_now().await;
                        let signal = ControlSignal {
                            action: ControlAction::Cancel,
                            reason: c.reason.or_else(|| Some("Cancelled by receiver".to_string())),
                        };
                        emit_control_event(&self.event_tx, transfer_uuid, signal);
                        return Err(TransferError::Cancelled(transfer_uuid));
                    }
                    Ok(Ok(other)) => {
                        ctrl_guard.remove_now().await;
                        let err = TransferError::UnexpectedMessage(format!(
                            "{:?}",
                            other.message_type()
                        ));
                        self.emit_failed(
                            transfer_uuid,
                            TransferDirection::Outgoing,
                            peer_node_id,
                            peer_label,
                            primary_name,
                            manifest.len(),
                            total_bytes,
                            Some(is_wan_transfer),
                            err.to_string(),
                        );
                        return Err(err);
                    }
                    Ok(Err(err)) => {
                        ctrl_guard.remove_now().await;
                        let err = TransferError::Protocol(err);
                        self.emit_failed(
                            transfer_uuid,
                            TransferDirection::Outgoing,
                            peer_node_id,
                            peer_label,
                            primary_name,
                            manifest.len(),
                            total_bytes,
                            Some(is_wan_transfer),
                            err.to_string(),
                        );
                        return Err(err);
                    }
                    Err(_) => {
                        ctrl_guard.remove_now().await;
                        send_control_frame(
                            &mut ctrl_send,
                            transfer_uuid,
                            &ControlSignal {
                                action: ControlAction::Cancel,
                                reason: Some("Timed out awaiting approval".to_string()),
                            },
                        )
                        .await;
                        let timeout_reason =
                            format!("{peer_label} did not receive the transfer (timed out)");
                        self.emit_failed(
                            transfer_uuid,
                            TransferDirection::Outgoing,
                            peer_node_id,
                            peer_label,
                            primary_name,
                            manifest.len(),
                            total_bytes,
                            Some(is_wan_transfer),
                            timeout_reason.clone(),
                        );
                        return Err(TransferError::Rejected(transfer_uuid, timeout_reason));
                    }
                }
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

        let first_file_label = manifest
            .first()
            .map(|m| m.offer_entry.relative_path.clone())
            .unwrap_or_default();

        if bytes_skipped_resumed > 0 {
            let initial_is_direct = if is_wan_transfer {
                self.is_connection_direct(peer_node_id).await
            } else {
                None
            };
            let _ = self.event_tx.send(TransferEvent::Progress(TransferProgress {
                transfer_id: transfer_uuid,
                file_name: first_file_label.clone(),
                bytes_transferred: 0,
                bytes_skipped_resumed,
                total_bytes,
                streams_active: num_streams,
                is_wan: is_wan_transfer,
                is_direct: initial_is_direct,
            }));
        }

        let outbound_channel_bound = if is_wan_transfer {
            WAN_CHANNEL_BOUND
        } else {
            CHANNEL_BOUND
        };
        let (chunk_tx, chunk_rx) = mpsc::channel::<OutgoingChunk>(outbound_channel_bound);
        let shared_rx = Arc::new(Mutex::new(chunk_rx));
        let bytes_sent_counter = Arc::new(AtomicU64::new(0));
        let current_file_label = Arc::new(RwLock::new(first_file_label));

        // Spawn progress ticker so UI updates smoothly without blocking the QUIC hot path
        let progress_stop = Arc::new(watch::channel(false).0);
        let progress_task = {
            let sent = Arc::clone(&bytes_sent_counter);
            let label = Arc::clone(&current_file_label);
            let mut stop_rx = progress_stop.subscribe();
            let event_tx = self.event_tx.clone();
            let opt_tx = progress_tx;
            let tick_ep = if is_wan_transfer {
                self.shared_endpoint
                    .read()
                    .expect("shared_endpoint rwlock")
                    .clone()
            } else {
                None
            };
            AbortOnDrop::new(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_millis(50));
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            let cur = sent.load(Ordering::Relaxed);
                            let name = label.read().await.clone();
                            let is_direct = if is_wan_transfer {
                                tick_ep
                                    .as_ref()
                                    .and_then(|shared| shared.read().expect("endpoint rwlock").clone())
                                    .and_then(|ep| {
                                        crate::discovery::is_endpoint_connection_direct(
                                            &ep,
                                            peer_node_id,
                                        )
                                    })
                            } else {
                                None
                            };
                            let snap = TransferProgress {
                                transfer_id: transfer_uuid,
                                file_name: name,
                                bytes_transferred: cur,
                                bytes_skipped_resumed,
                                total_bytes,
                                streams_active: num_streams,
                                is_wan: is_wan_transfer,
                                is_direct,
                            };
                            if let Some(ref tx) = opt_tx {
                                let _ = tx.try_send(snap.clone());
                            }
                            let _ = event_tx.send(TransferEvent::Progress(snap));
                        }
                        _ = stop_rx.changed() => break,
                    }
                }
            }))
        };

        // Spawn up to 6 concurrent unidirectional QUIC data streams (JoinSet auto-aborts on drop)
        let mut workers = JoinSet::new();
        for _ in 0..num_streams {
            let rx = Arc::clone(&shared_rx);
            let conn = conn.clone();
            let sent = Arc::clone(&bytes_sent_counter);
            let worker_cipher = wan_cipher.clone();
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
                    let plaintext_len = chunk.data.len() as u64;
                    let wire_data = match worker_cipher {
                        Some(ref cipher) => {
                            let encrypted = cipher.encrypt_chunk(
                                chunk.file_index,
                                chunk.byte_offset,
                                &chunk.data,
                            )?;
                            Bytes::from(encrypted)
                        }
                        None => chunk.data,
                    };
                    let chunk_len = wire_data.len() as u32;
                    let header = ChunkHeader {
                        transfer_id: stream_tid,
                        file_index: chunk.file_index,
                        byte_offset: chunk.byte_offset,
                        chunk_len,
                    }
                    .encode();

                    // Write 24-byte header immediately followed by payload bytes
                    stream
                        .write_all_chunks(&mut [
                            Bytes::copy_from_slice(&header),
                            wire_data,
                        ])
                        .await
                        .map_err(|e| TransferError::Quic(e.to_string()))?;

                    sent.fetch_add(plaintext_len, Ordering::Relaxed);
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
                // On Same Wi-Fi (`!is_wan_transfer`) every 128 KiB block is forwarded as-is;
                // on Over-Internet (`is_wan_transfer`) contiguous missing blocks coalesce up to 512 KiB.
                let mut pending_offset: Option<u64> = None;
                let mut pending_buf = Vec::with_capacity(if is_wan_transfer { WAN_CHUNK_SIZE } else { 0 });

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

                    if !is_wan_transfer {
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
                    } else if is_missing {
                        if pending_offset.is_none() {
                            pending_offset = Some(chunk_idx * CHUNK_SIZE as u64);
                        }
                        pending_buf.extend_from_slice(&read_buf[..expected_len]);
                        if pending_buf.len() >= WAN_CHUNK_SIZE {
                            let offset = pending_offset.take().unwrap_or(chunk_idx * CHUNK_SIZE as u64);
                            let outgoing = OutgoingChunk {
                                file_index: entry.file_id,
                                byte_offset: offset,
                                data: Bytes::copy_from_slice(&pending_buf),
                            };
                            pending_buf.clear();
                            chunk_tx
                                .send(outgoing)
                                .await
                                .map_err(|_| TransferError::Quic("Worker channel closed".into()))?;
                        }
                    } else if let Some(offset) = pending_offset.take() {
                        if !pending_buf.is_empty() {
                            let outgoing = OutgoingChunk {
                                file_index: entry.file_id,
                                byte_offset: offset,
                                data: Bytes::copy_from_slice(&pending_buf),
                            };
                            pending_buf.clear();
                            chunk_tx
                                .send(outgoing)
                                .await
                                .map_err(|_| TransferError::Quic("Worker channel closed".into()))?;
                        }
                    }
                }

                if let Some(offset) = pending_offset.take() {
                    if !pending_buf.is_empty() {
                        let outgoing = OutgoingChunk {
                            file_index: entry.file_id,
                            byte_offset: offset,
                            data: Bytes::copy_from_slice(&pending_buf),
                        };
                        pending_buf.clear();
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

        enum OutgoingStageOutcome {
            Completed(Result<Vec<FileHashEntry>, TransferError>),
            Control {
                signal: ControlSignal,
                initiated_locally: bool,
            },
        }

        let workers_fut = async {
            while let Some(res) = workers.join_next().await {
                match res {
                    Ok(inner) => inner?,
                    Err(e) => return Err(TransferError::Quic(e.to_string())),
                }
            }
            Ok::<(), TransferError>(())
        };
        let mut reader_opt = Some(reader_handle);
        let reader_fut = async {
            let handle = reader_opt.take().expect("reader_handle present");
            match handle.join().await {
                Ok(res) => res,
                Err(e) => Err(TransferError::Quic(e.to_string())),
            }
        };

        let stage_outcome = tokio::select! {
            biased;
            signal = recv_control_signal(&mut ctrl_rx) => {
                OutgoingStageOutcome::Control {
                    signal,
                    initiated_locally: true,
                }
            }
            res = async { tokio::try_join!(reader_fut, workers_fut).map(|(hashes, ())| hashes) } => {
                OutgoingStageOutcome::Completed(res)
            }
            remote = read_frame(&mut ctrl_recv) => {
                match remote {
                    Ok(Message::Pause(p)) => OutgoingStageOutcome::Control {
                        signal: ControlSignal {
                            action: ControlAction::Pause,
                            reason: p.reason.or_else(|| Some("Paused by receiver".to_string())),
                        },
                        initiated_locally: false,
                    },
                    Ok(Message::Cancel(c)) => OutgoingStageOutcome::Control {
                        signal: ControlSignal {
                            action: ControlAction::Cancel,
                            reason: c.reason.or_else(|| Some("Cancelled by receiver".to_string())),
                        },
                        initiated_locally: false,
                    },
                    Ok(other) => OutgoingStageOutcome::Completed(Err(TransferError::UnexpectedMessage(
                        format!("{:?}", other.message_type()),
                    ))),
                    Err(err) => OutgoingStageOutcome::Completed(Err(TransferError::Protocol(err))),
                }
            }
        };

        let file_hashes = match stage_outcome {
            OutgoingStageOutcome::Completed(Ok(hashes)) => hashes,
            OutgoingStageOutcome::Completed(Err(err)) => {
                drop(reader_opt);
                workers.shutdown().await;
                let _ = progress_stop.send(true);
                let _ = progress_task.join().await;

                // Check if local control fired or receiver sent Pause/Cancel just ahead of QUIC reset.
                let maybe_signal = ctrl_rx.borrow().clone();
                if let Some(signal) = maybe_signal {
                    ctrl_guard.remove_now().await;
                    send_control_frame(&mut ctrl_send, transfer_uuid, &signal).await;
                    emit_control_event(&self.event_tx, transfer_uuid, signal.clone());
                    return Err(control_error(transfer_uuid, signal.action));
                }
                if let Ok(Ok(remote_msg)) =
                    tokio::time::timeout(Duration::from_millis(150), read_frame(&mut ctrl_recv)).await
                {
                    match remote_msg {
                        Message::Pause(p) => {
                            ctrl_guard.remove_now().await;
                            let _ = ctrl_send.finish();
                            let signal = ControlSignal {
                                action: ControlAction::Pause,
                                reason: p.reason.or_else(|| Some("Paused by receiver".to_string())),
                            };
                            emit_control_event(&self.event_tx, transfer_uuid, signal);
                            return Err(TransferError::Paused(transfer_uuid));
                        }
                        Message::Cancel(c) => {
                            ctrl_guard.remove_now().await;
                            let _ = ctrl_send.finish();
                            let signal = ControlSignal {
                                action: ControlAction::Cancel,
                                reason: c.reason.or_else(|| Some("Cancelled by receiver".to_string())),
                            };
                            emit_control_event(&self.event_tx, transfer_uuid, signal);
                            return Err(TransferError::Cancelled(transfer_uuid));
                        }
                        _ => {}
                    }
                }
                ctrl_guard.remove_now().await;
                if !is_wan_transfer && err.is_recoverable_network_drop() {
                    return Err(TransferError::DisconnectedMidTransfer {
                        transfer_id: transfer_uuid,
                        remaining_chunks: 1,
                    });
                }
                self.emit_failed(
                    transfer_uuid,
                    TransferDirection::Outgoing,
                    peer_node_id,
                    peer_label,
                    primary_name,
                    manifest.len(),
                    total_bytes,
                    Some(is_wan_transfer),
                    err.to_string(),
                );
                return Err(err);
            }
            OutgoingStageOutcome::Control {
                signal,
                initiated_locally,
            } => {
                drop(reader_opt);
                workers.shutdown().await;
                let _ = progress_stop.send(true);
                let _ = progress_task.join().await;
                ctrl_guard.remove_now().await;
                if initiated_locally {
                    send_control_frame(&mut ctrl_send, transfer_uuid, &signal).await;
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), ctrl_recv.read_to_end(0))
                            .await;
                } else {
                    let _ = ctrl_send.finish();
                }
                emit_control_event(&self.event_tx, transfer_uuid, signal.clone());
                return Err(control_error(transfer_uuid, signal.action));
            }
        };

        let _ = progress_stop.send(true);
        let _ = progress_task.join().await;

        let bytes_sent = bytes_sent_counter.load(Ordering::Relaxed);
        let complete = Message::Complete(CompletePayload {
            transfer_id: transfer_uuid,
            total_bytes_transferred: bytes_sent,
            verified: true,
            file_hashes: file_hashes.clone(),
        });
        if let Err(err) = write_frame(&mut ctrl_send, &complete).await {
            ctrl_guard.remove_now().await;
            let err = TransferError::Protocol(err);
            if !is_wan_transfer {
                return Err(TransferError::DisconnectedMidTransfer {
                    transfer_id: transfer_uuid,
                    remaining_chunks: 1,
                });
            }
            self.emit_failed(
                transfer_uuid,
                TransferDirection::Outgoing,
                peer_node_id,
                peer_label,
                primary_name,
                manifest.len(),
                total_bytes,
                Some(is_wan_transfer),
                err.to_string(),
            );
            return Err(err);
        }

        // Keep `ctrl_send` open until after the ack/control handshake so late
        // pause/cancel triggered while the receiver flushes disk buffers still
        // reaches the receiver over the control stream.
        let ack_msg = tokio::select! {
            biased;
            signal = recv_control_signal(&mut ctrl_rx) => {
                send_control_frame(&mut ctrl_send, transfer_uuid, &signal).await;
                let _ = ctrl_send.finish();
                match tokio::time::timeout(Duration::from_secs(5), read_frame(&mut ctrl_recv)).await {
                    Ok(Ok(Message::Complete(ack))) if ack.transfer_id == transfer_uuid => {
                        Message::Complete(ack)
                    }
                    _ => {
                        ctrl_guard.remove_now().await;
                        emit_control_event(&self.event_tx, transfer_uuid, signal.clone());
                        return Err(control_error(transfer_uuid, signal.action));
                    }
                }
            }
            res = read_frame(&mut ctrl_recv) => {
                let _ = ctrl_send.finish();
                match res {
                    Ok(m) => m,
                    Err(err) => {
                        ctrl_guard.remove_now().await;
                        let err = TransferError::Protocol(err);
                        if !is_wan_transfer {
                            return Err(TransferError::DisconnectedMidTransfer {
                                transfer_id: transfer_uuid,
                                remaining_chunks: 1,
                            });
                        }
                        self.emit_failed(
                            transfer_uuid,
                            TransferDirection::Outgoing,
                            peer_node_id,
                            peer_label,
                            primary_name,
                            manifest.len(),
                            total_bytes,
                            Some(is_wan_transfer),
                            err.to_string(),
                        );
                        return Err(err);
                    }
                }
            }
        };
        ctrl_guard.remove_now().await;

        match ack_msg {
            Message::Complete(ack) if ack.transfer_id == transfer_uuid => {
                if !ack.verified {
                    let err = TransferError::IntegrityMismatch {
                        relative_path: source_path.display().to_string(),
                    };
                    self.emit_failed(
                        transfer_uuid,
                        TransferDirection::Outgoing,
                        peer_node_id,
                        peer_label,
                        primary_name,
                        manifest.len(),
                        total_bytes,
                        Some(is_wan_transfer),
                        err.to_string(),
                    );
                    return Err(err);
                }
            }
            Message::Pause(p) => {
                let signal = ControlSignal {
                    action: ControlAction::Pause,
                    reason: p.reason.or_else(|| Some("Paused by receiver".to_string())),
                };
                emit_control_event(&self.event_tx, transfer_uuid, signal);
                return Err(TransferError::Paused(transfer_uuid));
            }
            Message::Cancel(c) => {
                let signal = ControlSignal {
                    action: ControlAction::Cancel,
                    reason: c.reason.or_else(|| Some("Cancelled by receiver".to_string())),
                };
                emit_control_event(&self.event_tx, transfer_uuid, signal);
                return Err(TransferError::Cancelled(transfer_uuid));
            }
            other => {
                let err = TransferError::UnexpectedMessage(format!(
                    "{:?}",
                    other.message_type()
                ));
                self.emit_failed(
                    transfer_uuid,
                    TransferDirection::Outgoing,
                    peer_node_id,
                    peer_label,
                    primary_name,
                    manifest.len(),
                    total_bytes,
                    Some(is_wan_transfer),
                    err.to_string(),
                );
                return Err(err);
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

async fn send_control_frame(ctrl_send: &mut SendStream, transfer_id: Uuid, signal: &ControlSignal) {
    let payload = TransferControlPayload {
        transfer_id,
        reason: signal.reason.clone(),
    };
    let msg = match signal.action {
        ControlAction::Pause => Message::Pause(payload),
        ControlAction::Cancel => Message::Cancel(payload),
    };
    let _ = write_frame(ctrl_send, &msg).await;
    let _ = ctrl_send.finish();
}

fn emit_control_event(
    event_tx: &broadcast::Sender<TransferEvent>,
    transfer_id: Uuid,
    signal: ControlSignal,
) {
    let ev = match signal.action {
        ControlAction::Pause => TransferEvent::Paused {
            transfer_id,
            reason: signal.reason,
        },
        ControlAction::Cancel => TransferEvent::Cancelled {
            transfer_id,
            reason: signal.reason,
        },
    };
    let _ = event_tx.send(ev);
}

fn control_error(transfer_id: Uuid, action: ControlAction) -> TransferError {
    match action {
        ControlAction::Pause => TransferError::Paused(transfer_id),
        ControlAction::Cancel => TransferError::Cancelled(transfer_id),
    }
}

async fn remove_partial_files(files: &[PartialFilePaths]) {
    for entry in files {
        let _ = tokio::fs::remove_file(&entry.part_path).await;
        let _ = tokio::fs::remove_file(&entry.resume_path).await;
        let tmp = append_suffix(&entry.resume_path, ".tmp");
        let _ = tokio::fs::remove_file(&tmp).await;
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

#[allow(clippy::too_many_arguments)]
async fn run_incoming_writer(
    transfer_id: Uuid,
    sender_node_id: NodeId,
    is_wan: bool,
    max_chunk_payload: usize,
    shared_endpoint: Option<Arc<StdRwLock<Option<Endpoint>>>>,
    mut files: Vec<FileReceiveState>,
    mut remaining_chunks: u64,
    total_bytes: u64,
    initial_skipped_bytes: u64,
    mut chunk_rx: mpsc::Receiver<IncomingChunk>,
    mut stop_rx: watch::Receiver<WriterStop>,
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
            let stop_state = *stop_rx.borrow();
            if stop_state == WriterStop::Cancel {
                return Err(TransferError::Cancelled(transfer_id));
            }
            if stop_state == WriterStop::Pause {
                break;
            }

            let next_chunk = tokio::select! {
                biased;
                _ = stop_rx.changed() => {
                    let current_stop = *stop_rx.borrow();
                    match current_stop {
                        WriterStop::Cancel => return Err(TransferError::Cancelled(transfer_id)),
                        WriterStop::Pause => {
                            while let Ok(c) = chunk_rx.try_recv() {
                                if let Some(&idx) = index_map.get(&c.file_index) {
                                    let state = &mut files[idx];
                                    let _ = write_incoming_chunk(state, c, max_chunk_payload, &mut scratch_buf, &mut remaining_chunks, &mut received_bytes).await?;
                                }
                            }
                            break;
                        }
                        WriterStop::Running => continue,
                    }
                }
                chunk = chunk_rx.recv() => chunk,
            };

            let Some(chunk) = next_chunk else {
                break;
            };

            let Some(&vec_idx) = index_map.get(&chunk.file_index) else {
                continue;
            };
            let state = &mut files[vec_idx];
            chunks_since_flush += write_incoming_chunk(
                state,
                chunk,
                max_chunk_payload,
                &mut scratch_buf,
                &mut remaining_chunks,
                &mut received_bytes,
            )
            .await?;

            if chunks_since_flush >= 64 || last_flush.elapsed() >= Duration::from_millis(250) {
                if !is_wan {
                    for f in &mut files {
                        f.file.flush().await?;
                        f.resume.save(&f.resume_path)?;
                    }
                }
                chunks_since_flush = 0;
                last_flush = Instant::now();

                let live_is_direct = if is_wan {
                    shared_endpoint
                        .as_ref()
                        .and_then(|shared| shared.read().expect("endpoint rwlock").clone())
                        .and_then(|ep| {
                            crate::discovery::is_endpoint_connection_direct(&ep, sender_node_id)
                        })
                } else {
                    None
                };

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
                    is_wan,
                    is_direct: live_is_direct,
                }));
            }

            if remaining_chunks == 0 {
                break;
            }
        }
    }

    if *stop_rx.borrow() == WriterStop::Cancel {
        return Err(TransferError::Cancelled(transfer_id));
    }

    // Flush written chunks and persist resume bitmaps cleanly
    for f in &mut files {
        f.file.flush().await?;
        f.resume.save(&f.resume_path)?;
    }

    if *stop_rx.borrow() == WriterStop::Pause && remaining_chunks > 0 {
        return Err(TransferError::Paused(transfer_id));
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
    max_chunk_payload: usize,
    scratch_buf: &mut [u8],
    remaining_chunks: &mut u64,
    received_bytes: &mut u64,
) -> Result<u64, TransferError> {
    if chunk.byte_offset % CHUNK_SIZE as u64 != 0
        || chunk.data.is_empty()
        || chunk.data.len() > max_chunk_payload
    {
        return Err(TransferError::InvalidChunkHeader {
            transfer_id: state.file_id as u64,
        });
    }
    let first_idx = chunk.byte_offset / CHUNK_SIZE as u64;
    let data_len = chunk.data.len() as u64;
    let Some(end_offset) = chunk.byte_offset.checked_add(data_len) else {
        return Err(TransferError::InvalidChunkHeader {
            transfer_id: state.file_id as u64,
        });
    };
    if end_offset > state.size_bytes {
        return Err(TransferError::InvalidChunkHeader {
            transfer_id: state.file_id as u64,
        });
    }
    if chunk.data.len() % CHUNK_SIZE != 0 && end_offset != state.size_bytes {
        return Err(TransferError::InvalidChunkHeader {
            transfer_id: state.file_id as u64,
        });
    }
    let block_count = (chunk.data.len() + CHUNK_SIZE - 1) as u64 / CHUNK_SIZE as u64;
    if first_idx + block_count > state.resume.total_chunks
        || (max_chunk_payload == CHUNK_SIZE && block_count != 1)
    {
        return Err(TransferError::InvalidChunkHeader {
            transfer_id: state.file_id as u64,
        });
    }

    state.file.seek(SeekFrom::Start(chunk.byte_offset)).await?;
    state.file.write_all(&chunk.data).await?;

    let mut newly_marked_blocks = 0u64;
    let mut newly_received_bytes = 0u64;
    for blk_off in 0..block_count {
        let blk_idx = first_idx + blk_off;
        if state.resume.mark_chunk_verified(blk_idx) {
            *remaining_chunks = remaining_chunks.saturating_sub(1);
            newly_marked_blocks += 1;
            newly_received_bytes += expected_chunk_len(state.size_bytes, blk_idx) as u64;
        }
    }
    *received_bytes += newly_received_bytes;

    // Hash immediately in RAM if this chunk sits right at the sequential BLAKE3 frontier
    if first_idx == state.next_hash_chunk {
        state.hasher.update(&chunk.data);
        state.next_hash_chunk += block_count;
        advance_hash_frontier(state, scratch_buf).await?;
    } else if first_idx < state.next_hash_chunk && first_idx + block_count > state.next_hash_chunk {
        advance_hash_frontier(state, scratch_buf).await?;
    }

    Ok(newly_marked_blocks)
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

    #[test]
    fn test_wan_daily_key_rotation_midnight_boundary_and_aad() {
        let tid = Uuid::new_v4();
        let secret = [0x42u8; 32];
        let day = 20_500u64;
        let payload = b"secret-wan-chunk-payload";

        let sender = WanCipherContext::new_for_utc_day(tid, secret, day);
        let ciphertext = sender.encrypt_chunk(1, 262_144, payload).expect("encrypt");
        assert_eq!(ciphertext.len(), payload.len() + WAN_CHUNK_OVERHEAD);

        // Same day succeeds
        let receiver_same_day = WanCipherContext::new_for_utc_day(tid, secret, day);
        assert_eq!(
            receiver_same_day
                .decrypt_chunk(1, 262_144, &ciphertext)
                .unwrap(),
            payload
        );

        // Next UTC day (day + 1) gracefully accepts `day` via its `day - 1` window
        let receiver_next_day = WanCipherContext::new_for_utc_day(tid, secret, day + 1);
        assert_eq!(
            receiver_next_day
                .decrypt_chunk(1, 262_144, &ciphertext)
                .unwrap(),
            payload
        );

        // Two days later is rejected cleanly
        let receiver_expired = WanCipherContext::new_for_utc_day(tid, secret, day + 2);
        assert!(receiver_expired
            .decrypt_chunk(1, 262_144, &ciphertext)
            .is_err());

        // Mismatched AAD metadata (file_index or byte_offset or transfer_id) fails authentication
        assert!(receiver_same_day
            .decrypt_chunk(2, 262_144, &ciphertext)
            .is_err());
        assert!(receiver_same_day
            .decrypt_chunk(1, 131_072, &ciphertext)
            .is_err());
        let wrong_tid = WanCipherContext::new_for_utc_day(Uuid::new_v4(), secret, day);
        assert!(wrong_tid.decrypt_chunk(1, 262_144, &ciphertext).is_err());

        // Different shared secret fails authentication
        let wrong_secret = WanCipherContext::new_for_utc_day(tid, [0x99u8; 32], day);
        assert!(wrong_secret.decrypt_chunk(1, 262_144, &ciphertext).is_err());
    }

    #[test]
    fn test_is_local_lan_ip_classification() {
        use crate::discovery::is_local_lan_ip;
        use std::net::IpAddr;

        for lan in [
            "192.168.1.42",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.254",
            "169.254.1.2",
            "127.0.0.1",
            "::1",
            "fe80::1",
            "::ffff:192.168.1.5",
        ] {
            let ip: IpAddr = lan.parse().unwrap();
            assert!(is_local_lan_ip(&ip), "expected {lan} to be classified as LAN");
        }

        for wan in [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "100.64.0.1",
            "2001:4860:4860::8888",
            "fd12:3456::1",
            "fd15:070a:510b::1",
        ] {
            let ip: IpAddr = wan.parse().unwrap();
            assert!(!is_local_lan_ip(&ip), "expected {wan} to be classified as WAN");
        }
    }

    #[tokio::test]
    async fn test_wan_512kib_chunk_write_and_cross_granularity_resume() {
        let dir = std::env::temp_dir().join(format!("beamdrop-wan-chunk-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        let size_bytes = (CHUNK_SIZE as u64) * 5 + 12_345; // 5 * 128 KiB + tail
        let payload: Vec<u8> = (0..size_bytes as usize)
            .map(|i| ((i.wrapping_mul(31)) ^ (i >> 8)) as u8)
            .collect();
        let expected_hash = *blake3::hash(&payload).as_bytes();

        let final_path = dir.join("wan_test.bin");
        let part_path = part_path_for(&final_path);
        let resume_path = resume_path_for(&final_path);
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&part_path)
            .await
            .unwrap();
        file.set_len(size_bytes).await.unwrap();

        let resume = ResumeMetadata::new("wan_test.bin".into(), size_bytes, Some(expected_hash));
        let mut state = FileReceiveState {
            file_id: 0,
            relative_path: "wan_test.bin".into(),
            size_bytes,
            offer_expected_blake3: Some(expected_hash),
            final_path,
            part_path: part_path.clone(),
            resume_path,
            resume,
            file,
            hasher: blake3::Hasher::new(),
            next_hash_chunk: 0,
        };
        let mut scratch = vec![0u8; CHUNK_SIZE];
        let mut remaining = state.resume.total_chunks;
        let mut received = 0u64;

        // First chunk sent on LAN (128 KiB = block 0)
        let marked_lan = write_incoming_chunk(
            &mut state,
            IncomingChunk {
                file_index: 0,
                byte_offset: 0,
                data: payload[..CHUNK_SIZE].to_vec(),
            },
            CHUNK_SIZE,
            &mut scratch,
            &mut remaining,
            &mut received,
        )
        .await
        .unwrap();
        assert_eq!(marked_lan, 1);

        // Oversized chunk must still be rejected on strict LAN path
        let rejected_lan = write_incoming_chunk(
            &mut state,
            IncomingChunk {
                file_index: 0,
                byte_offset: CHUNK_SIZE as u64,
                data: payload[CHUNK_SIZE..CHUNK_SIZE + WAN_CHUNK_SIZE].to_vec(),
            },
            CHUNK_SIZE,
            &mut scratch,
            &mut remaining,
            &mut received,
        )
        .await;
        assert!(rejected_lan.is_err());

        // Resume remaining 5 blocks via two WAN chunks (512 KiB = 4 blocks, then final tail block)
        let first_wan_end = CHUNK_SIZE + WAN_CHUNK_SIZE;
        let marked_wan_1 = write_incoming_chunk(
            &mut state,
            IncomingChunk {
                file_index: 0,
                byte_offset: CHUNK_SIZE as u64,
                data: payload[CHUNK_SIZE..first_wan_end].to_vec(),
            },
            WAN_CHUNK_SIZE,
            &mut scratch,
            &mut remaining,
            &mut received,
        )
        .await
        .unwrap();
        assert_eq!(marked_wan_1, 4);

        let marked_wan_2 = write_incoming_chunk(
            &mut state,
            IncomingChunk {
                file_index: 0,
                byte_offset: first_wan_end as u64,
                data: payload[first_wan_end..].to_vec(),
            },
            WAN_CHUNK_SIZE,
            &mut scratch,
            &mut remaining,
            &mut received,
        )
        .await
        .unwrap();
        assert_eq!(marked_wan_2, 1);
        assert_eq!(remaining, 0);
        assert_eq!(received, size_bytes);
        advance_hash_frontier(&mut state, &mut scratch)
            .await
            .unwrap();
        assert_eq!(*state.hasher.finalize().as_bytes(), expected_hash);

        assert!(TransferError::Quic("reset".into()).is_recoverable_network_drop());
        assert!(
            !TransferError::Rejected(Uuid::new_v4(), "no".into()).is_recoverable_network_drop()
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
