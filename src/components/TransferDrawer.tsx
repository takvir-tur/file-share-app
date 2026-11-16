import { useEffect, useState } from "react";
import {
  ChevronIcon,
  CloseIcon,
  FolderIcon,
  GlobeIcon,
  PauseIcon,
  PlayIcon,
  WifiIcon,
} from "../icons";
import { TransferRecord } from "../types";
import { formatBytes, formatEta } from "../utils/format";

interface TransferDrawerProps {
  history: TransferRecord[];
  expanded: boolean;
  onToggleExpanded: () => void;
  onShowInFolder: (record: TransferRecord) => void;
  onPause: (transferId: string) => void;
  onResume: (transferId: string) => void;
  onCancel: (transferId: string) => void;
}

const APPROVAL_WINDOW_MS = 60_000;

function formatStatusLabel(status: string): string {
  switch (status) {
    case "awaiting_approval":
      return "Waiting for Receiver";
    case "pending_approval":
      return "Needs Confirmation";
    case "offer_received":
      return "Offer Received";
    case "connecting":
      return "Connecting";
    case "sending":
      return "Sending";
    case "receiving":
      return "Receiving";
    case "paused":
      return "Paused";
    case "completed":
      return "Completed";
    case "failed":
      return "Failed";
    case "interrupted":
      return "Interrupted";
    case "cancelled":
      return "Cancelled";
    case "rejected":
      return "Declined";
    default:
      return status.replace(/_/g, " ");
  }
}

export function TransferDrawer({
  history,
  expanded,
  onToggleExpanded,
  onShowInFolder,
  onPause,
  onResume,
  onCancel,
}: TransferDrawerProps) {
  const hasWaitingTimer = history.some(
    (i) => i.status === "awaiting_approval" || i.status === "pending_approval"
  );
  const [nowMs, setNowMs] = useState(() => Date.now());

  useEffect(() => {
    if (!hasWaitingTimer) return;
    setNowMs(Date.now());
    const timer = window.setInterval(() => {
      setNowMs(Date.now());
    }, 250);
    return () => window.clearInterval(timer);
  }, [hasWaitingTimer]);

  const activeCount = history.filter((i) =>
    [
      "connecting",
      "awaiting_approval",
      "sending",
      "receiving",
      "paused",
      "pending_approval",
      "offer_received",
    ].includes(i.status)
  ).length;
  const live = history.find((i) =>
    ["sending", "receiving", "awaiting_approval", "connecting"].includes(i.status)
  );

  return (
    <aside className="card drawer" aria-label="Transfers">
      <button type="button" className="d-btn sb" aria-expanded={expanded} onClick={onToggleExpanded}>
        <div className="row min0">
          <strong>Transfers</strong>
          <span className={`badge ${activeCount ? "b-ac" : ""}`}>
            {activeCount ? `${activeCount} active` : `${history.length} recent`}
          </span>
          {live && (
            <span className="mu xs">
              {live.fileName ?? `${live.files} item(s)`} ·{" "}
              {live.status === "connecting"
                ? "Connecting..."
                : live.status === "awaiting_approval"
                  ? `Waiting for ${live.peerName}...`
                  : `${live.speedMbps.toFixed(1)} MB/s`}
            </span>
          )}
        </div>
        <span className="row mu xs g4">
          <span>{expanded ? "Hide" : "Show"}</span>
          <ChevronIcon size={16} className={expanded ? "flip" : ""} />
        </span>
      </button>

      {expanded && (
        <div className="d-body">
          {history.length === 0 ? (
            <p className="mu m0">
              No transfers yet. Drop files onto a device or click Send Files.
            </p>
          ) : (
            <ul className="list">
              {history.map((item) => {
                const isConnecting = item.status === "connecting";
                const isAwaitingApproval = item.status === "awaiting_approval";
                const isStreaming = item.status === "sending" || item.status === "receiving";
                const isPaused = item.status === "paused";
                const isPendingApproval =
                  item.status === "pending_approval" || item.status === "offer_received";
                const isErrorTerminal =
                  item.status === "failed" ||
                  item.status === "interrupted" ||
                  item.status === "rejected";
                const movedBytes =
                  item.totalBytes > 0
                    ? Math.min(item.totalBytes, item.bytesSkippedResumed + item.bytesTransferred)
                    : item.bytesSkippedResumed + item.bytesTransferred;
                const pct =
                  item.totalBytes > 0
                    ? Math.min(100, Math.round((movedBytes / item.totalBytes) * 100))
                    : item.status === "completed"
                      ? 100
                      : 0;
                const expiresAt =
                  item.approvalExpiresAtUnixMs ?? item.updatedAtUnixMs + APPROVAL_WINDOW_MS;
                const waitRemainingMs = Math.max(
                  0,
                  Math.min(APPROVAL_WINDOW_MS, expiresAt - nowMs)
                );
                const waitSecondsLeft = Math.ceil(waitRemainingMs / 1000);
                const canResume =
                  isPaused ||
                  (item.status === "interrupted" &&
                    Boolean(item.reason?.includes("tap Resume")));
                const badgeCls =
                  item.status === "completed"
                    ? "b-ok"
                    : isPendingApproval || isPaused || isAwaitingApproval
                      ? "b-wn"
                      : ["failed", "interrupted", "cancelled", "rejected"].includes(item.status)
                        ? "b-dn"
                        : "b-ac";

                return (
                  <li key={item.transferId} className="item sb">
                    <div className="t-main">
                      <div className="row">
                        <strong className="t-ttl">{item.fileName ?? `${item.files} item(s)`}</strong>
                        <span className="badge">{item.direction === "incoming" ? "Receiving" : "Sending"}</span>
                        {item.isWan != null && (
                          <span className={`badge ${item.isWan ? "b-ac" : "b-ok"}`}>
                            {item.isWan ? <GlobeIcon size={11} /> : <WifiIcon size={11} />}
                            <span>{item.isWan ? "Over Internet" : "Same Wi-Fi"}</span>
                          </span>
                        )}
                        {item.isWan && isStreaming && item.isDirect != null && (
                          <span className={`badge ${item.isDirect ? "b-ok" : "b-wn"}`}>
                            {item.isDirect ? "Direct P2P" : "Relayed"}
                          </span>
                        )}
                        <span className={`badge ${badgeCls}`}>{formatStatusLabel(item.status)}</span>
                      </div>
                      <div className="row mu g10 xs">
                        <span>{item.peerName}</span>
                        <span>
                          {item.files} item(s) · {formatBytes(movedBytes)} / {formatBytes(item.totalBytes)}
                        </span>
                        {item.speedMbps > 0 && isStreaming && (
                          <span>{item.speedMbps.toFixed(1)} MB/s</span>
                        )}
                        {isStreaming && (
                          <span>ETA {formatEta(item.totalBytes, movedBytes, item.speedMbps)}</span>
                        )}
                        {item.verified && item.status === "completed" && (
                          <span className="ok fw6">Verified</span>
                        )}
                      </div>
                      {isConnecting && (
                        <div className="stack g4">
                          <div className="mu xs">Connecting to {item.peerName}...</div>
                          <div className="prg">
                            <progress className="bd-prog" aria-label={`Connecting to ${item.peerName}`} />
                          </div>
                        </div>
                      )}
                      {isAwaitingApproval && (
                        <div className="stack g4">
                          <div className="sb xs">
                            <span className="mu">Waiting for {item.peerName} to accept...</span>
                            <strong className={waitSecondsLeft <= 10 ? "err-txt" : "mu"}>
                              {waitSecondsLeft}s
                            </strong>
                          </div>
                          <div className="prg">
                            <progress
                              className="bd-prog bd-prog-warn"
                              max={APPROVAL_WINDOW_MS}
                              value={waitRemainingMs}
                              aria-label={`Waiting for ${item.peerName}: ${waitSecondsLeft} seconds remaining`}
                            />
                          </div>
                        </div>
                      )}
                      {item.reason && (
                        <div className={isErrorTerminal ? "err xs" : "mu xs"}>{item.reason}</div>
                      )}
                      {(isStreaming || canResume || item.status === "completed") && (
                        <div className="prg">
                          <progress
                            className="bd-prog"
                            max={100}
                            value={pct}
                            aria-label={`Progress ${pct}%`}
                          />
                          <span className="xs fw6">{pct}%</span>
                        </div>
                      )}
                    </div>
                    <div className="row g4">
                      {isStreaming && (
                        <>
                          <button
                            type="button"
                            className="btn bs sm"
                            onClick={() => onPause(item.transferId)}
                          >
                            <PauseIcon size={13} />
                            <span>Pause</span>
                          </button>
                          <button
                            type="button"
                            className="btn bdn sm"
                            onClick={() => onCancel(item.transferId)}
                          >
                            <CloseIcon size={13} />
                            <span>Cancel</span>
                          </button>
                        </>
                      )}
                      {canResume && (
                        <>
                          <button
                            type="button"
                            className="btn bp sm"
                            onClick={() => onResume(item.transferId)}
                          >
                            <PlayIcon size={13} />
                            <span>Resume</span>
                          </button>
                          <button
                            type="button"
                            className="btn bdn sm"
                            onClick={() => onCancel(item.transferId)}
                          >
                            <CloseIcon size={13} />
                            <span>Cancel</span>
                          </button>
                        </>
                      )}
                      {(isConnecting || isAwaitingApproval || isPendingApproval) && (
                        <button
                          type="button"
                          className="btn bdn sm"
                          onClick={() => onCancel(item.transferId)}
                        >
                          <CloseIcon size={13} />
                          <span>Cancel</span>
                        </button>
                      )}
                      {item.status === "completed" && (
                        <button
                          type="button"
                          className="btn bs sm"
                          onClick={() => onShowInFolder(item)}
                        >
                          <FolderIcon size={14} />
                          <span>Show in Folder</span>
                        </button>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </aside>
  );
}
