import { useId } from "react";
import { WarningIcon } from "../icons";
import { PeerEntry } from "../types";
import { formatBytes, useModalDialog } from "../utils/format";

export interface PendingCellularSend {
  peer: PeerEntry;
  paths: string[];
  totalBytes: number;
  fromQueue: boolean;
}

interface CellularConfirmModalProps {
  pending: PendingCellularSend | null;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

function formatMbText(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 MB";
  const mb = bytes / (1024 * 1024);
  if (mb >= 0.1) return `${mb.toFixed(1)} MB`;
  return formatBytes(bytes);
}

export function CellularConfirmModal({
  pending,
  busy,
  onCancel,
  onConfirm,
}: CellularConfirmModalProps) {
  const titleId = useId();
  const dialogRef = useModalDialog(Boolean(pending), onCancel, true);

  return (
    <dialog ref={dialogRef} className="dlg dlg-sm" aria-labelledby={titleId}>
      {pending && (
        <div className="m-card">
          <header className="m-hd">
            <div className="stack g8">
              <span className="badge b-wn" style={{ inlineSize: "fit-content" }}>
                <WarningIcon size={14} />
                <span>Mobile Data Safeguard</span>
              </span>
              <h2 id={titleId}>Send Over Cellular Data?</h2>
            </div>
          </header>

          <p className="m0">
            You are on mobile data — sending <strong>{formatMbText(pending.totalBytes)}</strong> over long distance will use cellular data.
          </p>

          <div className="panel-box stack g8">
            <div className="sb">
              <span className="mu">Recipient</span>
              <strong>{pending.peer.displayName}</strong>
            </div>
            <div className="sb">
              <span className="mu">Selection</span>
              <strong>{pending.paths.length} item(s) · {formatBytes(pending.totalBytes)}</strong>
            </div>
            <div className="sb">
              <span className="mu">Encryption</span>
              <span>Daily ChaCha20-Poly1305</span>
            </div>
          </div>

          <div className="row end">
            <button type="button" className="btn bs" autoFocus disabled={busy} onClick={onCancel}>
              Cancel
            </button>
            <button type="button" className="btn bp" disabled={busy} onClick={onConfirm}>
              Send via Internet
            </button>
          </div>
        </div>
      )}
    </dialog>
  );
}
