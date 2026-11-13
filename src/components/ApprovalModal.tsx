import { useId } from "react";
import { WarningIcon } from "../icons";
import { TransferRecord } from "../types";
import { formatBytes, shortNodeId, useModalDialog } from "../utils/format";

interface ApprovalModalProps {
  offer: TransferRecord | null;
  busy: boolean;
  onRespond: (transferId: string, accept: boolean) => Promise<void>;
}

export function ApprovalModal({ offer, busy, onRespond }: ApprovalModalProps) {
  const titleId = useId();
  const dialogRef = useModalDialog(
    Boolean(offer),
    () => {
      if (offer) void onRespond(offer.transferId, false);
    },
    false
  );

  return (
    <dialog ref={dialogRef} className="dlg dlg-sm" aria-labelledby={titleId}>
      {offer && (
        <div className="m-card">
          <header className="m-hd">
            <div className="stack" style={{ gap: 6 }}>
              <span className="badge b-wn" style={{ inlineSize: "fit-content" }}>
                <WarningIcon size={14} />
                <span>Guest Transfer Request</span>
              </span>
              <h2 id={titleId}>{offer.peerName} wants to send files</h2>
            </div>
          </header>

          <div className="panel-box stack" style={{ gap: 6 }}>
            <div className="sb"><span className="mu">Items</span><strong>{offer.files} item(s)</strong></div>
            <div className="sb"><span className="mu">Total Size</span><strong>{formatBytes(offer.totalBytes)}</strong></div>
            {offer.peerNodeId && <div className="sb"><span className="mu">Sender</span><code className="mono">{shortNodeId(offer.peerNodeId)}</code></div>}
          </div>

          <p className="mu m0">
            Untrusted guest device. Accept to save into your BeamDrop Downloads folder.
          </p>

          <div className="row end">
            <button type="button" className="btn bs" autoFocus disabled={busy} onClick={() => void onRespond(offer.transferId, false)}>
              Decline
            </button>
            <button type="button" className="btn bp" disabled={busy} onClick={() => void onRespond(offer.transferId, true)}>
              Accept
            </button>
          </div>
        </div>
      )}
    </dialog>
  );
}
