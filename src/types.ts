export interface SelfInfo {
  nodeId: string;
  deviceId: string;
  hostname: string;
  osType: string;
  lanIp: string;
  listenPort: number;
  downloadDir: string;
}

export interface PeerEntry {
  nodeId: string;
  displayName: string;
  osType: string;
  addr: string | null;
  port: number | null;
  online: boolean;
  paired: boolean;
  autoAccept: boolean;
  allowWan: boolean;
  autoAcceptWan: boolean;
  pairedAtUnix: number | null;
  lastSeenUnixMs: number | null;
  isLan: boolean;
  transport: string;
}

export interface PairingSession {
  nodeId: string;
  addr: string;
  pin: string;
  uri: string;
  expiresAtUnix: number;
}

export interface TrustedPeer {
  nodeId: string;
  friendlyAlias: string;
  osType: string;
  pairedAtUnix: number;
  autoAccept: boolean;
  allowWan: boolean;
  autoAcceptWan: boolean;
}

export interface MeasurePathsResult {
  resolvedPaths: string[];
  totalBytes: number;
}

export type TransferStatus =
  | "connecting"
  | "awaiting_approval"
  | "pending_approval"
  | "offer_received"
  | "sending"
  | "receiving"
  | "paused"
  | "completed"
  | "failed"
  | "interrupted"
  | "cancelled"
  | "rejected"
  | (string & {});

export interface TransferRecord {
  transferId: string;
  direction: string;
  status: TransferStatus;
  peerNodeId: string | null;
  peerName: string;
  fileName: string | null;
  files: number;
  bytesTransferred: number;
  bytesSkippedResumed: number;
  totalBytes: number;
  speedMbps: number;
  streamsActive: number;
  verified: boolean | null;
  outputDir: string | null;
  reason: string | null;
  updatedAtUnixMs: number;
  isWan?: boolean | null;
  isDirect?: boolean | null;
  approvalExpiresAtUnixMs?: number | null;
}

export interface PeerEventPayload {
  kind: string;
  peer: PeerEntry;
}

export interface TransferEventPayload {
  kind: string;
  record: TransferRecord;
}

export interface FirewallStatus {
  supported: boolean;
  configured: boolean;
  ruleName: string;
  details: string;
}

export interface SendDispatchResult {
  queued: number;
  targetNodeId: string;
}

export interface TargetedSendRequest {
  targetNodeId: string;
  paths: string[];
}

export interface ParsedPairingUri {
  nodeId: string;
  addr: string | null;
  pin: string;
}

