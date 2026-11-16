import {
  ChevronIcon,
  FolderIcon,
  GlobeIcon,
  OsIcon,
  QrIcon,
  SendIcon,
  WifiIcon,
} from "../icons";
import { PeerEntry } from "../types";
import { isPeerSendable } from "../utils/dropHitTest";
import { shortNodeId } from "../utils/format";

const SUPPORTS_NATIVE_SWITCH =
  typeof HTMLInputElement !== "undefined" && "switch" in HTMLInputElement.prototype;

interface DeviceGridProps {
  peers: PeerEntry[];
  busy: boolean;
  hoveredDropPeerId: string | null;
  queuedSendCount: number;
  isAndroid: boolean;
  onSendFiles: (peer: PeerEntry) => void;
  onSendFolder: (peer: PeerEntry) => void;
  onOpenPair: (targetNodeId?: string) => void;
  onToggleWan: (peer: PeerEntry, enabled: boolean) => Promise<void>;
  onToggleAutoAccept: (peer: PeerEntry, lanAuto: boolean, wanAuto: boolean) => Promise<void>;
  onRemoveTrusted: (peer: PeerEntry) => void;
}

interface SwitchRowProps {
  label: string;
  hint: string;
  checked: boolean;
  disabled: boolean;
  onChange: (checked: boolean) => void;
}

function SwitchRow({ label, hint, checked, disabled, onChange }: SwitchRowProps) {
  return (
    <label className={`sw-row ${disabled ? "is-dis" : ""}`} title={hint}>
      <span className="sw-txt">{label}</span>
      <input
        type="checkbox"
        {...({ switch: "" } as Record<string, unknown>)}
        role={SUPPORTS_NATIVE_SWITCH ? undefined : "switch"}
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.currentTarget.checked)}
      />
    </label>
  );
}

function sortDevices(peers: PeerEntry[]): PeerEntry[] {
  const rank = (peer: PeerEntry) => {
    if (peer.isLan && peer.online) return 0;
    if (peer.paired && peer.allowWan) return 1;
    if (peer.addr) return 2;
    return 3;
  };

  return [...peers].sort((a, b) => {
    const diff = rank(a) - rank(b);
    if (diff !== 0) return diff;
    return a.displayName.localeCompare(b.displayName);
  });
}

export function DeviceGrid({
  peers,
  busy,
  hoveredDropPeerId,
  queuedSendCount,
  isAndroid,
  onSendFiles,
  onSendFolder,
  onOpenPair,
  onToggleWan,
  onToggleAutoAccept,
  onRemoveTrusted,
}: DeviceGridProps) {
  const sorted = sortDevices(peers);
  const readyCount = sorted.filter(isPeerSendable).length;

  return (
    <section className="stack" aria-label="Devices">
      <div className="sb">
        <div className="row g8">
          <h2 className="sec-title">Devices</h2>
          <span className={`badge ${readyCount ? "b-ok" : ""}`}>
            {readyCount ? `${readyCount} ready` : `${sorted.length} saved`}
          </span>
        </div>
        <span className="mu xs">
          {queuedSendCount
            ? `Choose a device to send ${queuedSendCount} item(s)`
            : "Drop files onto a device or click Send Files"}
        </span>
      </div>

      {sorted.length === 0 ? (
        <article className="card dev-empty">
          <h3>No devices found yet</h3>
          <p className="mu m0">
            Open ZapDrop on another device on the same Wi-Fi, or pair devices to share over the internet.
          </p>
          <footer>
            <button type="button" className="btn bp sm" onClick={() => onOpenPair()}>
              <QrIcon size={15} />
              <span>Pair Device</span>
            </button>
          </footer>
        </article>
      ) : (
        <div className="dev-grid">
          {sorted.map((peer) => {
            const sameWifi = peer.isLan && peer.online;
            const overInternet = !sameWifi && peer.paired && peer.allowWan;
            const canSend = isPeerSendable(peer);
            const isDrop = hoveredDropPeerId === peer.nodeId;

            return (
              <article
                key={peer.nodeId}
                className={`card dev-card ${isDrop ? "drop" : ""} ${!canSend ? "is-off" : ""}`}
                data-drop-peer={canSend ? peer.nodeId : undefined}
              >
                <header className="dev-hd">
                  <div className="dev-who">
                    <span className="dev-av" aria-hidden="true">
                      <OsIcon osType={peer.osType} size={19} />
                    </span>
                    <div className="min0">
                      <h3 className="dev-name">{peer.displayName}</h3>
                      <p className="dev-meta mono">
                        Device ID: {shortNodeId(peer.nodeId)}
                        {sameWifi && peer.addr ? ` · ${peer.addr}` : ""}
                      </p>
                    </div>
                  </div>
                  {sameWifi ? (
                    <span className="badge b-ok">
                      <WifiIcon size={12} />
                      <span>Same Wi-Fi</span>
                    </span>
                  ) : overInternet ? (
                    <span className="badge b-ac">
                      <GlobeIcon size={12} />
                      <span>Over Internet</span>
                    </span>
                  ) : (
                    <span className="badge">Offline</span>
                  )}
                </header>

                <footer className="dev-act">
                  {canSend ? (
                    <>
                      <button
                        type="button"
                        className="btn bp sm"
                        disabled={busy}
                        onClick={() => onSendFiles(peer)}
                      >
                        <SendIcon size={14} />
                        <span>{queuedSendCount ? `Send (${queuedSendCount})` : "Send Files"}</span>
                      </button>
                      {!isAndroid && queuedSendCount === 0 && (
                        <button
                          type="button"
                          className="btn bs sm"
                          disabled={busy}
                          onClick={() => onSendFolder(peer)}
                        >
                          <FolderIcon size={14} />
                          <span>Send Folder</span>
                        </button>
                      )}
                      {!peer.paired && (
                        <button
                          type="button"
                          className="btn bg sm"
                          disabled={busy}
                          onClick={() => onOpenPair(peer.nodeId)}
                        >
                          <QrIcon size={14} />
                          <span>Pair</span>
                        </button>
                      )}
                    </>
                  ) : (
                    <p className="mu xs m0">
                      Turn on Internet Sharing below to send while away.
                    </p>
                  )}
                </footer>

                {peer.paired && (
                  <details className="dev-cfg">
                    <summary className="dev-cfg-sum">
                      <span>Sharing Settings</span>
                      <ChevronIcon size={14} className="dev-cfg-ico" />
                    </summary>
                    <div className="dev-cfg-body">
                      <SwitchRow
                        label="Auto-receive on Wi-Fi"
                        hint="Automatically save incoming files sent over the same Wi-Fi"
                        checked={peer.autoAccept}
                        disabled={busy}
                        onChange={(next) =>
                          void onToggleAutoAccept(peer, next, peer.autoAcceptWan)
                        }
                      />
                      <SwitchRow
                        label="Internet Sharing"
                        hint="Allow encrypted transfers over the internet when away from home Wi-Fi"
                        checked={peer.allowWan}
                        disabled={busy}
                        onChange={(next) => void onToggleWan(peer, next)}
                      />
                      <SwitchRow
                        label="Auto-receive over Internet"
                        hint="Automatically save encrypted transfers received over the internet"
                        checked={peer.autoAcceptWan}
                        disabled={busy || !peer.allowWan}
                        onChange={(next) => void onToggleAutoAccept(peer, peer.autoAccept, next)}
                      />
                      <div className="dev-cfg-rm">
                        <button
                          type="button"
                          className="btn btn-danger-ghost sm"
                          disabled={busy}
                          onClick={() => onRemoveTrusted(peer)}
                        >
                          Remove Device
                        </button>
                      </div>
                    </div>
                  </details>
                )}
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}
