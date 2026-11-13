import { ChevronIcon, CloseIcon, FolderIcon, PauseIcon, PlayIcon } from "../icons";
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

export function TransferDrawer({
  history,
  expanded,
  onToggleExpanded,
  onShowInFolder,
  onPause,
  onResume,
  onCancel,
}: TransferDrawerProps) {
  const activeCount = history.filter((i) =>
    ["sending", "receiving", "paused", "pending_approval", "offer_received"].includes(i.status)
  ).length;
  const live = history.find((i) => i.status === "sending" || i.status === "receiving");

  return (
    <aside className="card drawer">
      <button type="button" className="d-btn sb" aria-expanded={expanded} onClick={onToggleExpanded}>
        <div className="row min0">
          <strong>Transfers</strong>
          <span className={`badge ${activeCount ? "b-ac" : ""}`}>
            {activeCount ? `${activeCount} active` : `${history.length} recent`}
          </span>
          {live && (
            <span className="mu xs">
              {live.fileName ?? `${live.files} item(s)`} • {live.speedMbps.toFixed(1)} MB/s
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
              No transfers yet. Click a radar node or drop files to begin.
            </p>
          ) : (
            <ul className="list">
              {history.map((item) => {
                const isStreaming = item.status === "sending" || item.status === "receiving";
                const isPaused = item.status === "paused";
                const isPending =
                  item.status === "pending_approval" || item.status === "offer_received";
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
                const badgeCls =
                  item.status === "completed"
                    ? "b-ok"
                    : item.status === "pending_approval" || item.status === "paused"
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
                        <span className={`badge ${badgeCls}`}>{item.status.replace("_", " ")}</span>
                        {item.streamsActive > 0 && isStreaming && (
                          <span className="badge b-ac">{item.streamsActive} QUIC</span>
                        )}
                      </div>
                      <div className="row mu g10 xs">
                        <span>{item.peerName}</span>
                        <span>{formatBytes(movedBytes)} / {formatBytes(item.totalBytes)}</span>
                        {item.speedMbps > 0 && isStreaming && (
                          <span>{item.speedMbps.toFixed(1)} MB/s</span>
                        )}
                        {isStreaming && (
                          <span>ETA {formatEta(item.totalBytes, movedBytes, item.speedMbps)}</span>
                        )}
                        {item.verified && item.status === "completed" && (
                          <span className="ok fw6">BLAKE3 verified</span>
                        )}
                      </div>
                      {item.reason && <div className="mu xs">{item.reason}</div>}
                      {(isStreaming || isPaused || item.status === "completed") && (
                        <div className="prg">
                          <progress max={100} value={pct} aria-label={`Progress ${pct}%`} />
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
                      {isPaused && (
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
                      {isPending && (
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
