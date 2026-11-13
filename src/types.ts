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
  pairedAtUnix: number | null;
  lastSeenUnixMs: number | null;
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
}

export interface TransferRecord {
  transferId: string;
  direction: string;
  status: string;
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

