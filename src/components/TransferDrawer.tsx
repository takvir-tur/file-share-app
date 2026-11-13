import { ChevronIcon, FolderIcon } from "../icons";
import { TransferRecord } from "../types";
import { formatBytes, formatEta } from "../utils/format";

interface TransferDrawerProps {
  history: TransferRecord[];
  expanded: boolean;
  onToggleExpanded: () => void;
  onShowInFolder: (record: TransferRecord) => void;
}

export function TransferDrawer({
  history,
  expanded,
  onToggleExpanded,
  onShowInFolder,
}: TransferDrawerProps) {
  const activeCount = history.filter((i) => ["sending", "receiving", "pending_approval", "offer_received"].includes(i.status)).length;
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
                const active = item.status === "sending" || item.status === "receiving";
                const pct =
                  item.totalBytes > 0
                    ? Math.min(100, Math.round((item.bytesTransferred / item.totalBytes) * 100))
                    : item.status === "completed"
                      ? 100
                      : 0;
                const badgeCls =
                  item.status === "completed"
                    ? "b-ok"
                    : item.status === "pending_approval"
                      ? "b-wn"
                      : item.status === "failed" || item.status === "interrupted"
                        ? "b-dn"
                        : "b-ac";

                return (
                  <li key={item.transferId} className="item sb">
                    <div className="t-main">
                      <div className="row">
                        <strong className="t-ttl">{item.fileName ?? `${item.files} item(s)`}</strong>
                        <span className="badge">{item.direction === "incoming" ? "Receiving" : "Sending"}</span>
                        <span className={`badge ${badgeCls}`}>{item.status.replace("_", " ")}</span>
                        {item.streamsActive > 0 && (
                          <span className="badge b-ac">{item.streamsActive} QUIC</span>
                        )}
                      </div>
                      <div className="row mu g10 xs">
                        <span>{item.peerName}</span>
                        <span>{formatBytes(item.bytesTransferred)} / {formatBytes(item.totalBytes)}</span>
                        {item.speedMbps > 0 && <span>{item.speedMbps.toFixed(1)} MB/s</span>}
                        {active && <span>ETA {formatEta(item.totalBytes, item.bytesTransferred, item.speedMbps)}</span>}
                        {item.verified && item.status === "completed" && (
                          <span className="ok fw6">BLAKE3 verified</span>
                        )}
                      </div>
                      {item.reason && <div className="mu xs">{item.reason}</div>}
                      {(active || item.status === "completed") && (
                        <div className="prg">
                          <progress max={100} value={pct} aria-label={`Progress ${pct}%`} />
                          <span className="xs fw6">{pct}%</span>
                        </div>
                      )}
                    </div>
                    {item.status === "completed" && (
                      <button type="button" className="btn bs sm" onClick={() => onShowInFolder(item)}>
                        <FolderIcon size={14} />
                        <span>Show in Folder</span>
                      </button>
                    )}
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
