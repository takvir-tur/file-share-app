use iroh::NodeId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use crate::identity::OsType;

/// ALPN protocol identifier negotiated over Iroh QUIC connections.
pub const BEAMDROP_ALPN: &[u8] = b"beamdrop/1";

/// Current wire protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Frame header length: `1 byte msg_type + 4 bytes u32 payload_len`.
pub const FRAME_HEADER_LEN: usize = 5;

/// Maximum allowed frame payload size (16 MiB) to guard against malformed allocations.
pub const MAX_FRAME_PAYLOAD_LEN: u32 = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("I/O error during frame transport: {0}")]
    Io(#[from] std::io::Error),
    #[error("Bincode serialization error: {0}")]
    Bincode(#[from] bincode::Error),
    #[error("Unknown message type tag: 0x{0:02x}")]
    UnknownMessageType(u8),
    #[error("Frame payload length {0} exceeds maximum allowed ({MAX_FRAME_PAYLOAD_LEN} bytes)")]
    FrameTooLarge(u32),
    #[error("Incomplete frame buffer: expected at least {expected} bytes, got {actual}")]
    IncompleteFrame { expected: usize, actual: usize },
}

/// Discriminant tag for the 1-byte `msg_type` header in length-prefixed frames.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageType {
    Hello = 0x01,
    Offer = 0x02,
    Accept = 0x03,
    Reject = 0x04,
    Ping = 0x05,
    Pong = 0x06,
    Complete = 0x07,
    PairRequest = 0x08,
    PairConfirm = 0x09,
}

impl TryFrom<u8> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Hello),
            0x02 => Ok(Self::Offer),
            0x03 => Ok(Self::Accept),
            0x04 => Ok(Self::Reject),
            0x05 => Ok(Self::Ping),
            0x06 => Ok(Self::Pong),
            0x07 => Ok(Self::Complete),
            0x08 => Ok(Self::PairRequest),
            0x09 => Ok(Self::PairConfirm),
            other => Err(ProtocolError::UnknownMessageType(other)),
        }
    }
}

/// Handshake payload exchanged when establishing a peer session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloPayload {
    pub protocol_version: u16,
    pub device_id: Uuid,
    pub node_id: NodeId,
    pub display_name: String,
    pub os_type: OsType,
    pub listen_port: u16,
}

/// Metadata for a single file included in a transfer offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOfferEntry {
    pub file_id: u32,
    pub relative_path: String,
    pub size_bytes: u64,
    pub sha256_or_blake3: Option<[u8; 32]>,
    /// BLAKE3 hash of the first 128 KiB chunk (used to safely match `.beamdrop.part` on resume).
    pub head_blake3: Option<[u8; 32]>,
}

/// Transfer offer sent from sender to receiver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferPayload {
    pub transfer_id: Uuid,
    pub sender_name: String,
    pub files: Vec<FileOfferEntry>,
    pub total_bytes: u64,
}

/// Contiguous range `[start, end)` of 128 KiB chunk indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRange {
    pub start: u64,
    pub end: u64,
}

/// Per-file resume instructions sent inside `AcceptPayload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedFileResume {
    pub file_id: u32,
    /// Missing 128 KiB chunk ranges `[start, end)` needed by the receiver.
    pub missing_ranges: Vec<ChunkRange>,
}

/// Receiver acceptance of a transfer offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptPayload {
    pub transfer_id: Uuid,
    pub accepted_file_ids: Vec<u32>,
    pub file_resumes: Vec<AcceptedFileResume>,
}

/// Receiver rejection of a transfer offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectPayload {
    pub transfer_id: Uuid,
    pub reason: Option<String>,
}

/// Liveness and latency probe request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingPayload {
    pub nonce: u64,
    pub timestamp_ms: u64,
}

/// Liveness and latency probe response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PongPayload {
    pub nonce: u64,
    pub timestamp_ms: u64,
}

/// Full-file BLAKE3 digest reported upon completion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHashEntry {
    pub file_id: u32,
    pub blake3: [u8; 32],
}

/// Transfer completion notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletePayload {
    pub transfer_id: Uuid,
    pub total_bytes_transferred: u64,
    pub verified: bool,
    pub file_hashes: Vec<FileHashEntry>,
}

/// One-time pairing request carrying sender identity and 6-digit PIN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRequestPayload {
    pub sender_node_id: NodeId,
    pub display_name: String,
    pub os_type: OsType,
    pub pin: String,
}

/// Pairing handshake response indicating whether the PIN was accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairConfirmPayload {
    pub accepted: bool,
    pub responder_node_id: NodeId,
    pub display_name: String,
    pub os_type: OsType,
    pub reason: Option<String>,
}

/// Derives the deterministic 64-bit `transfer_id` used in 24-byte unidirectional chunk headers
/// from a 128-bit transfer `Uuid`.
pub fn transfer_stream_id(transfer_id: Uuid) -> u64 {
    let bytes = transfer_id.as_bytes();
    let hi = u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let lo = u64::from_be_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    let id = hi ^ lo;
    if id == 0 { 1 } else { id }
}

/// Wire protocol message framed as `[u8 msg_type | u32 payload_len | bincode payload]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    Hello(HelloPayload),
    Offer(OfferPayload),
    Accept(AcceptPayload),
    Reject(RejectPayload),
    Ping(PingPayload),
    Pong(PongPayload),
    Complete(CompletePayload),
    PairRequest(PairRequestPayload),
    PairConfirm(PairConfirmPayload),
}

impl Message {
    /// Returns the 1-byte `MessageType` discriminant for this message.
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::Hello(_) => MessageType::Hello,
            Self::Offer(_) => MessageType::Offer,
            Self::Accept(_) => MessageType::Accept,
            Self::Reject(_) => MessageType::Reject,
            Self::Ping(_) => MessageType::Ping,
            Self::Pong(_) => MessageType::Pong,
            Self::Complete(_) => MessageType::Complete,
            Self::PairRequest(_) => MessageType::PairRequest,
            Self::PairConfirm(_) => MessageType::PairConfirm,
        }
    }

    /// Serializes only the inner payload using `bincode`.
    pub fn encode_payload(&self) -> Result<Vec<u8>, ProtocolError> {
        let payload = match self {
            Self::Hello(p) => bincode::serialize(p)?,
            Self::Offer(p) => bincode::serialize(p)?,
            Self::Accept(p) => bincode::serialize(p)?,
            Self::Reject(p) => bincode::serialize(p)?,
            Self::Ping(p) => bincode::serialize(p)?,
            Self::Pong(p) => bincode::serialize(p)?,
            Self::Complete(p) => bincode::serialize(p)?,
            Self::PairRequest(p) => bincode::serialize(p)?,
            Self::PairConfirm(p) => bincode::serialize(p)?,
        };
        Ok(payload)
    }

    /// Deserializes a `Message` from its `MessageType` tag and `bincode` payload slice.
    pub fn decode_payload(msg_type: MessageType, payload: &[u8]) -> Result<Self, ProtocolError> {
        let msg = match msg_type {
            MessageType::Hello => Self::Hello(bincode::deserialize(payload)?),
            MessageType::Offer => Self::Offer(bincode::deserialize(payload)?),
            MessageType::Accept => Self::Accept(bincode::deserialize(payload)?),
            MessageType::Reject => Self::Reject(bincode::deserialize(payload)?),
            MessageType::Ping => Self::Ping(bincode::deserialize(payload)?),
            MessageType::Pong => Self::Pong(bincode::deserialize(payload)?),
            MessageType::Complete => Self::Complete(bincode::deserialize(payload)?),
            MessageType::PairRequest => Self::PairRequest(bincode::deserialize(payload)?),
            MessageType::PairConfirm => Self::PairConfirm(bincode::deserialize(payload)?),
        };
        Ok(msg)
    }

    /// Encodes the message into a length-prefixed binary frame:
    /// `[u8 msg_type | u32 payload_len (big-endian) | bincode payload]`.
    pub fn encode_frame(&self) -> Result<Vec<u8>, ProtocolError> {
        let payload = self.encode_payload()?;
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| ProtocolError::FrameTooLarge(u32::MAX))?;
        if payload_len > MAX_FRAME_PAYLOAD_LEN {
            return Err(ProtocolError::FrameTooLarge(payload_len));
        }

        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
        frame.push(self.message_type() as u8);
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    /// Decodes a length-prefixed binary frame from a byte slice:
    /// `[u8 msg_type | u32 payload_len (big-endian) | bincode payload]`.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, ProtocolError> {
        if frame.len() < FRAME_HEADER_LEN {
            return Err(ProtocolError::IncompleteFrame {
                expected: FRAME_HEADER_LEN,
                actual: frame.len(),
            });
        }

        let msg_type = MessageType::try_from(frame[0])?;
        let payload_len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
        if payload_len > MAX_FRAME_PAYLOAD_LEN {
            return Err(ProtocolError::FrameTooLarge(payload_len));
        }

        let expected_total = FRAME_HEADER_LEN + payload_len as usize;
        if frame.len() < expected_total {
            return Err(ProtocolError::IncompleteFrame {
                expected: expected_total,
                actual: frame.len(),
            });
        }

        let payload = &frame[FRAME_HEADER_LEN..expected_total];
        Self::decode_payload(msg_type, payload)
    }
}

/// Writes a length-prefixed binary frame (`[u8 msg_type | u32 payload_len | bincode payload]`)
/// to an async writer (such as an `iroh::endpoint::SendStream`).
pub async fn write_frame<W>(writer: &mut W, msg: &Message) -> Result<(), ProtocolError>
where
    W: AsyncWrite + Unpin,
{
    let frame = msg.encode_frame()?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads a length-prefixed binary frame (`[u8 msg_type | u32 payload_len | bincode payload]`)
/// from an async reader (such as an `iroh::endpoint::RecvStream`).
pub async fn read_frame<R>(reader: &mut R) -> Result<Message, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await?;

    let msg_type = MessageType::try_from(header[0])?;
    let payload_len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    if payload_len > MAX_FRAME_PAYLOAD_LEN {
        return Err(ProtocolError::FrameTooLarge(payload_len));
    }

    let mut payload = vec![0u8; payload_len as usize];
    reader.read_exact(&mut payload).await?;

    Message::decode_payload(msg_type, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;

    #[test]
    fn test_frame_roundtrip_all_variants() {
        let id = DeviceIdentity::generate();
        let transfer_id = Uuid::new_v4();

        let messages = vec![
            Message::Hello(HelloPayload {
                protocol_version: PROTOCOL_VERSION,
                device_id: id.device_id,
                node_id: id.node_id,
                display_name: id.hostname.clone(),
                os_type: id.os_type,
                listen_port: 4433,
            }),
            Message::Offer(OfferPayload {
                transfer_id,
                sender_name: "MacBook-Pro".to_string(),
                files: vec![FileOfferEntry {
                    file_id: 0,
                    relative_path: "photo.png".to_string(),
                    size_bytes: 1024 * 512,
                    sha256_or_blake3: Some([0xab; 32]),
                    head_blake3: Some([0xcd; 32]),
                }],
                total_bytes: 1024 * 512,
            }),
            Message::Accept(AcceptPayload {
                transfer_id,
                accepted_file_ids: vec![0],
                file_resumes: vec![AcceptedFileResume {
                    file_id: 0,
                    missing_ranges: vec![ChunkRange { start: 0, end: 4 }],
                }],
            }),
            Message::Reject(RejectPayload {
                transfer_id,
                reason: Some("Disk full".to_string()),
            }),
            Message::Ping(PingPayload {
                nonce: 42,
                timestamp_ms: 1_700_000_000_000,
            }),
            Message::Pong(PongPayload {
                nonce: 42,
                timestamp_ms: 1_700_000_000_005,
            }),
            Message::Complete(CompletePayload {
                transfer_id,
                total_bytes_transferred: 1024 * 512,
                verified: true,
                file_hashes: vec![FileHashEntry {
                    file_id: 0,
                    blake3: [0xab; 32],
                }],
            }),
            Message::PairRequest(PairRequestPayload {
                sender_node_id: id.node_id,
                display_name: "Pixel-9".to_string(),
                os_type: OsType::Android,
                pin: "123456".to_string(),
            }),
            Message::PairConfirm(PairConfirmPayload {
                accepted: true,
                responder_node_id: id.node_id,
                display_name: id.hostname.clone(),
                os_type: id.os_type,
                reason: None,
            }),
        ];

        for msg in messages {
            let encoded = msg.encode_frame().expect("encode_frame should succeed");
            assert_eq!(encoded[0], msg.message_type() as u8);
            let len = u32::from_be_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]);
            assert_eq!(encoded.len(), FRAME_HEADER_LEN + len as usize);

            let decoded = Message::decode_frame(&encoded).expect("decode_frame should succeed");
            assert_eq!(msg, decoded);
        }
    }
}

