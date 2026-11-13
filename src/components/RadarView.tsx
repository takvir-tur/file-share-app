import { useState } from "react";
import { FolderIcon, OsIcon, SendIcon, ShieldIcon } from "../icons";
import { PeerEntry, SelfInfo } from "../types";

interface RadarViewProps {
  selfInfo: SelfInfo | null;
  peers: PeerEntry[];
  selectedPeerId: string | null;
  hoveredDropPeerId: string | null;
  isDraggingOnRadar: boolean;
  queuedSendCount: number;
  busy: boolean;
  onSelectPeer: (nodeId: string) => void;
  onPeerClick: (peer: PeerEntry) => void;
  onPickFolder: (peer: PeerEntry) => void;
}

function layoutPeers(peers: PeerEntry[]) {
  const inner = peers.filter((p) => p.online && p.addr !== null);
  const outer = peers.filter((p) => !(p.online && p.addr !== null));
  const place = (group: PeerEntry[], radius: number, offset: number) =>
    group.map((peer, i) => {
      const a = -Math.PI / 2 + offset + (i * 2 * Math.PI) / group.length;
      return { peer, x: 50 + radius * Math.cos(a), y: 50 + radius * Math.sin(a) };
    });
  return [
    ...place(inner, 31, 0),
    ...place(outer, 42, inner.length ? Math.PI / Math.max(outer.length, 2) : 0),
  ];
}

export function RadarView({
  selfInfo,
  peers,
  selectedPeerId,
  hoveredDropPeerId,
  isDraggingOnRadar,
  queuedSendCount,
  busy,
  onSelectPeer,
  onPeerClick,
  onPickFolder,
}: RadarViewProps) {
  const [paused, setPaused] = useState(false);
  const placed = layoutPeers(peers);
  const active =
    peers.find((p) => p.nodeId === hoveredDropPeerId) ??
    peers.find((p) => p.nodeId === selectedPeerId) ??
    null;

  return (
    <section className="card r-card" aria-label="Device discovery radar">
      <div className="sb">
        <div className="stack g2">
          <strong className="fw6">
            {peers.length
              ? `${peers.filter((p) => p.online).length} online • ${peers.length} known`
              : "Scanning local network (_beamdrop._udp.local.)"}
          </strong>
          <span className="mu xs">
            {queuedSendCount
              ? `Click a device to send ${queuedSendCount} queued item(s)`
              : "Click a device or drop files/folders onto a node"}
          </span>
        </div>

        <button type="button" className="btn bg sm" onClick={() => setPaused((v) => !v)}>
          {paused ? "Resume Sweep" : "Pause Sweep"}
        </button>
      </div>

      <div
        className={`r-stage ${paused ? "paused" : ""} ${isDraggingOnRadar && active ? "drop-on" : ""}`}
        data-radar-drop-surface="true"
      >
        {[1, 2, 3].map((r) => <div key={r} className={`ring r${r}`} aria-hidden="true" />)}
        <div className="sweep" aria-hidden="true" />

        <div className="hub" title={selfInfo?.nodeId}>
          <div className="hub-av">
            <OsIcon osType={selfInfo?.osType ?? "macOS"} size={24} />
          </div>
          <span className="hub-nm">{selfInfo?.hostname ?? "This Device"}</span>
          <span className="mu xs">You</span>
        </div>

        {placed.map(({ peer, x, y }) => {
          const sel = selectedPeerId === peer.nodeId;
          const drop = hoveredDropPeerId === peer.nodeId;
          const lan = Boolean(peer.addr);
          return (
            <div key={peer.nodeId} className="r-anc" style={{ left: `${x}%`, top: `${y}%` }}>
              <button
                type="button"
                className={`r-node ${peer.online ? "" : "off"} ${sel ? "sel" : ""} ${drop ? "drop" : ""}`}
                data-peer-node-id={peer.nodeId}
                disabled={busy}
                onClick={() => {
                  onSelectPeer(peer.nodeId);
                  onPeerClick(peer);
                }}
                onFocus={() => onSelectPeer(peer.nodeId)}
                aria-label={`${peer.displayName}, ${peer.osType}, ${peer.online ? "online" : "offline"}, ${lan ? "Direct LAN" : "Relay"}${peer.paired ? ", Trusted" : ""}`}
              >
                <span className="n-av">
                  <OsIcon osType={peer.osType} size={20} />
                  <span className={`dot ${peer.online ? "on" : ""}`} aria-hidden="true" />
                  {peer.paired && (
                    <span className="sh-pin" title="Trusted device">
                      <ShieldIcon size={11} />
                    </span>
                  )}
                </span>
                <span className="n-nm">{peer.displayName}</span>
                <span className="row g4">
                  <span className={`t-mini ${lan ? "b-ac" : "b-wn"}`}>{lan ? "LAN" : "Relay"}</span>
                  {peer.paired && <span className="t-mini b-ok">Trusted</span>}
                </span>
              </button>
            </div>
          );
        })}

        {peers.length === 0 && (
          <div className="r-empty" aria-live="polite">
            Waiting for nearby macOS, Windows, or Android BeamDrop peers...
          </div>
        )}
      </div>

      {peers.length > 0 && (
        <div className="strip stack g8">
          <div className="row">
            {peers.map((peer) => (
              <button
                key={peer.nodeId}
                type="button"
                className={`chip ${selectedPeerId === peer.nodeId ? "sel" : ""}`}
                onClick={() => onSelectPeer(peer.nodeId)}
              >
                <span className={`dot ${peer.online ? "on" : ""}`} aria-hidden="true" />
                <OsIcon osType={peer.osType} size={14} />
                <span>{peer.displayName}</span>
                {peer.paired && <ShieldIcon size={12} className="ok" />}
              </button>
            ))}
          </div>

          {active && (
            <div className="sb">
              <span className="mu">
                Drop target: <strong>{active.displayName}</strong>
                {active.addr ? ` (${active.addr})` : " (Relay)"}
              </span>
              <div className="row">
                <button type="button" className="btn bp sm" disabled={busy} onClick={() => onPeerClick(active)}>
                  <SendIcon size={14} />
                  <span>{queuedSendCount ? `Send (${queuedSendCount})` : "Send Files"}</span>
                </button>
                <button type="button" className="btn bs sm" disabled={busy || queuedSendCount > 0} onClick={() => onPickFolder(active)}>
                  <FolderIcon size={14} />
                  <span>Send Folder</span>
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
