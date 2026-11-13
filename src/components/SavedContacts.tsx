import { useState } from "react";
import { ChevronIcon, FolderIcon, GlobeIcon, OsIcon, SendIcon, ShieldIcon } from "../icons";
import { PeerEntry } from "../types";
import { shortNodeId } from "../utils/format";

interface SavedContactsProps {
  peers: PeerEntry[];
  busy: boolean;
  queuedSendCount: number;
  isAndroid: boolean;
  onToggleWan: (peer: PeerEntry, enabled: boolean) => Promise<void>;
  onSendFiles: (peer: PeerEntry) => void;
  onSendFolder: (peer: PeerEntry) => void;
}

export function SavedContacts({
  peers,
  busy,
  queuedSendCount,
  isAndroid,
  onToggleWan,
  onSendFiles,
  onSendFolder,
}: SavedContactsProps) {
  const [expanded, setExpanded] = useState(true);
  const contacts = peers.filter((p) => p.paired);

  return (
    <section className="card sc-card stack g8" aria-label="Saved Contacts">
      <div className="sb">
        <div className="min0">
          <div className="row g4">
            <ShieldIcon size={15} className="ok" />
            <h2 className="m0" style={{ fontSize: "0.94rem" }}>Saved Contacts ({contacts.length})</h2>
          </div>
          <p className="mu xs m0 mt4">
            Auto-accepted on LAN. Toggle Long-Distance to send securely over the internet when away.
          </p>
        </div>
        <button
          type="button"
          className="ibtn"
          aria-expanded={expanded}
          aria-label={expanded ? "Collapse Saved Contacts" : "Expand Saved Contacts"}
          onClick={() => setExpanded((v) => !v)}
        >
          <ChevronIcon
            size={16}
            style={{ transform: expanded ? "rotate(180deg)" : "none", transition: "transform 0.15s ease" }}
          />
        </button>
      </div>

      {expanded && (
        contacts.length === 0 ? (
          <div className="item mu xs">
            No saved contacts yet. Pair a device via QR code or PIN to enable zero-click transfers and optional Long-Distance sharing.
          </div>
        ) : (
          <div className="stack g8">
            {contacts.map((peer) => {
              const wanReady = !peer.online && peer.allowWan;
              return (
                <div key={peer.nodeId} className="item sb">
                  <div className="row g8 min0">
                    <OsIcon osType={peer.osType} size={18} />
                    <div className="min0">
                      <div className="row g4">
                        <strong className="n-nm">{peer.displayName}</strong>
                        {peer.online ? (
                          <span className="badge b-ok">Online · LAN</span>
                        ) : peer.allowWan ? (
                          <span className="badge b-ac">
                            <GlobeIcon size={11} />
                            <span>Offline · Long-Distance Ready</span>
                          </span>
                        ) : (
                          <span className="badge">Offline · LAN Only</span>
                        )}
                      </div>
                      <div className="mono mu xs">{shortNodeId(peer.nodeId)}</div>
                    </div>
                  </div>

                  <div className="row g8">
                    <button
                      type="button"
                      role="switch"
                      aria-checked={peer.allowWan}
                      aria-label={`Allow Long-Distance transfers for ${peer.displayName}`}
                      title="Enable encrypted Long-Distance transfers (daily-rotating ChaCha20-Poly1305) when offline on LAN"
                      className={`sw ${peer.allowWan ? "on" : ""}`}
                      disabled={busy}
                      onClick={() => void onToggleWan(peer, !peer.allowWan)}
                    >
                      <span className="sw-trk" aria-hidden="true" />
                      <span>Long-Distance</span>
                    </button>

                    {(peer.online || wanReady) && (
                      <div className="row g4">
                        <button
                          type="button"
                          className={`btn sm ${wanReady ? "bp" : "bs"}`}
                          disabled={busy}
                          onClick={() => onSendFiles(peer)}
                        >
                          {wanReady ? <GlobeIcon size={14} /> : <SendIcon size={14} />}
                          <span>
                            {wanReady
                              ? queuedSendCount
                                ? `Send via Internet (${queuedSendCount})`
                                : "Send via Internet"
                              : queuedSendCount
                                ? `Send LAN (${queuedSendCount})`
                                : "Send LAN"}
                          </span>
                        </button>
                        {!isAndroid && queuedSendCount === 0 && (
                          <button
                            type="button"
                            className="btn bs sm"
                            disabled={busy}
                            title={`Send Folder${wanReady ? " via Internet" : " via LAN"}`}
                            onClick={() => onSendFolder(peer)}
                          >
                            <FolderIcon size={14} />
                            <span>Folder</span>
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )
      )}
    </section>
  );
}
