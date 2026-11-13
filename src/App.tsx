import { useCallback, useEffect, useRef, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { ApprovalModal } from "./components/ApprovalModal";
import { PairDeviceModal } from "./components/PairDeviceModal";
import { RadarView } from "./components/RadarView";
import { TransferDrawer } from "./components/TransferDrawer";
import { FolderIcon, OsIcon, QrIcon, RadarIcon, SendIcon, WarningIcon } from "./icons";
import {
  FirewallStatus,
  PairingSession,
  PeerEntry,
  PeerEventPayload,
  SelfInfo,
  SendDispatchResult,
  TransferEventPayload,
  TransferRecord,
  TrustedPeer,
} from "./types";

function hitTestDropTarget(
  xPhys: number,
  yPhys: number,
  selectedPeerId: string | null,
  peers: PeerEntry[]
) {
  const dpr = window.devicePixelRatio || 1;
  const els = document.elementsFromPoint(xPhys / dpr, yPhys / dpr);

  for (const el of els) {
    if (el instanceof HTMLElement) {
      const id = el.closest<HTMLElement>("[data-peer-node-id]")?.dataset.peerNodeId;
      if (id) return { hoveredPeerId: id, onRadarSurface: true };
    }
  }
  const onRadar = els.some((el) => el instanceof HTMLElement && el.closest("[data-radar-drop-surface='true']"));
  if (onRadar && selectedPeerId && peers.some((p) => p.nodeId === selectedPeerId)) {
    return { hoveredPeerId: selectedPeerId, onRadarSurface: true };
  }
  return { hoveredPeerId: null, onRadarSurface: onRadar };
}

export default function App() {
  const inTauri = isTauri();
  const [selfInfo, setSelfInfo] = useState<SelfInfo | null>(null);
  const [peers, setPeers] = useState<PeerEntry[]>([]);
  const [selectedPeerId, setSelectedPeerId] = useState<string | null>(null);
  const [hoveredDropPeerId, setHoveredDropPeerId] = useState<string | null>(null);
  const [isDraggingOnRadar, setIsDraggingOnRadar] = useState(false);

  const [history, setHistory] = useState<TransferRecord[]>([]);
  const [drawerExpanded, setDrawerExpanded] = useState(false);

  const [pairModalOpen, setPairModalOpen] = useState(false);
  const [pairingSession, setPairingSession] = useState<PairingSession | null>(null);
  const [pairError, setPairError] = useState<string | null>(null);

  const [queuedSendPaths, setQueuedSendPaths] = useState<string[]>([]);
  const [firewall, setFirewall] = useState<FirewallStatus | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const peersRef = useRef<PeerEntry[]>([]);
  const selectedRef = useRef<string | null>(null);
  peersRef.current = peers;
  selectedRef.current = selectedPeerId;

  const pickDefault = (list: PeerEntry[], curr: string | null) =>
    curr && list.some((p) => p.nodeId === curr)
      ? curr
      : (list.find((p) => p.online) ?? list[0])?.nodeId ?? null;

  const queuePaths = (paths: string[]) =>
    setQueuedSendPaths((p) => Array.from(new Set([...p, ...paths])));

  const openDownloads = () =>
    void invoke("open_downloads_folder").catch((e: unknown) => setToast(String(e)));

  const syncPeers = useCallback((list: PeerEntry[]) => {
    setPeers(list);
    setSelectedPeerId((curr) => pickDefault(list, curr));
  }, []);

  const refreshState = useCallback(async () => {
    if (!inTauri) return;
    const [info, peerList, transferHistory, pendingPaths, fwStatus] = await Promise.all([
      invoke<SelfInfo>("get_self_info"),
      invoke<PeerEntry[]>("list_peers"),
      invoke<TransferRecord[]>("get_transfer_history"),
      invoke<string[]>("take_pending_send_paths"),
      invoke<FirewallStatus>("check_windows_firewall"),
    ]);
    setSelfInfo(info);
    syncPeers(peerList);
    setHistory(transferHistory);
    setFirewall(fwStatus);
    if (pendingPaths.length) queuePaths(pendingPaths);
  }, [inTauri, syncPeers]);

  const runAction = useCallback(
    async (task: () => Promise<void>, onError: (msg: string) => void = setToast) => {
      setBusy(true);
      try {
        await task();
      } catch (err) {
        onError(String(err));
      } finally {
        setBusy(false);
      }
    },
    []
  );

  const dispatchPathsToPeer = useCallback(
    async (peer: PeerEntry, paths: string[], fromQueue = false) => {
      if (!inTauri || !paths.length) return;
      await runAction(async () => {
        const res = await invoke<SendDispatchResult>("send_paths", { targetNodeId: peer.nodeId, paths });
        if (fromQueue) setQueuedSendPaths([]);
        setDrawerExpanded(true);
        setToast(`Sending ${res.queued} item(s) to ${peer.displayName}`);
      }, (err) => setToast(`Send failed: ${err}`));
    },
    [inTauri, runAction]
  );

  const dispatchRef = useRef(dispatchPathsToPeer);
  dispatchRef.current = dispatchPathsToPeer;

  useEffect(() => {
    if (!inTauri) return;
    void refreshState().catch((err: unknown) => setToast(`Daemon error: ${String(err)}`));

    const subs = [
      listen<PeerEventPayload>("beamdrop://peer-event", () => {
        void invoke<PeerEntry[]>("list_peers").then(syncPeers);
      }),
      listen<TransferEventPayload>("beamdrop://transfer-event", ({ payload }) => {
        setHistory((prev) => [payload.record, ...prev.filter((i) => i.transferId !== payload.record.transferId)].slice(0, 100));
        if (["auto_accepted", "progress", "offer_received"].includes(payload.kind)) setDrawerExpanded(true);
      }),
      listen<string[]>("beamdrop://send-paths", ({ payload }) => {
        if (payload.length) {
          queuePaths(payload);
          setToast(`Ready to send ${payload.length} queued item(s). Click a device.`);
        }
      }),
      getCurrentWebview().onDragDropEvent(({ payload }) => {
        if (payload.type === "leave") {
          setHoveredDropPeerId(null);
          setIsDraggingOnRadar(false);
          return;
        }
        const hit = hitTestDropTarget(payload.position.x, payload.position.y, selectedRef.current, peersRef.current);
        if (payload.type === "enter" || payload.type === "over") {
          setHoveredDropPeerId(hit.hoveredPeerId);
          setIsDraggingOnRadar(hit.onRadarSurface);
        } else if (payload.type === "drop") {
          setHoveredDropPeerId(null);
          setIsDraggingOnRadar(false);
          const target = peersRef.current.find((p) => p.nodeId === hit.hoveredPeerId);
          if (target && payload.paths.length) {
            setSelectedPeerId(target.nodeId);
            void dispatchRef.current(target, payload.paths, false);
          } else if (payload.paths.length) {
            queuePaths(payload.paths);
            setToast("Drop missed device — queued. Click a node to send.");
          }
        }
      }),
    ];
    return () => { subs.forEach((p) => void p.then((u) => u())); };
  }, [inTauri, refreshState, syncPeers]);

  const refreshPairing = useCallback(() => {
    if (!inTauri) return;
    void runAction(async () => {
      setPairingSession(await invoke<PairingSession>("start_pairing"));
      setPairError(null);
    }, setPairError);
  }, [inTauri, runAction]);

  const handlePeerClick = async (peer: PeerEntry, directory = false) => {
    if (!inTauri) return;
    if (!directory && queuedSendPaths.length) {
      await dispatchPathsToPeer(peer, queuedSendPaths, true);
      return;
    }
    const picked = await openFileDialog({
      multiple: true,
      directory,
      title: `Send ${directory ? "Folder" : "File"}(s) to ${peer.displayName}`,
    });
    if (picked) await dispatchPathsToPeer(peer, Array.isArray(picked) ? picked : [picked], false);
  };

  const pendingOffer = history.find((item) => item.status === "pending_approval") ?? null;

  return (
    <div className="app">
      <header className="card hdr sb">
        <div className="idbox">
          <div className="brand" aria-hidden="true"><RadarIcon size={20} /></div>
          <div className="idtxt">
            <div className="row">
              <h1>{selfInfo?.hostname ?? "BeamDrop"}</h1>
              <span className="badge b-ac">
                <OsIcon osType={selfInfo?.osType ?? "macOS"} size={13} />
                <span>{selfInfo?.osType ?? "Desktop"}</span>
              </span>
              {selfInfo && <span className="badge mono mu">{selfInfo.lanIp}:{selfInfo.listenPort}</span>}
            </div>
            <p className="subline">{toast ?? "Zero-copy QUIC + mDNS LAN sharing"}</p>
          </div>
        </div>

        <div className="row">
          <button
            type="button"
            className="btn bp"
            onClick={() => { setPairError(null); setPairModalOpen(true); refreshPairing(); }}
          >
            <QrIcon size={16} />
            <span>Pair Device</span>
          </button>
          <button
            type="button"
            className="btn bs"
            disabled={!inTauri}
            onClick={openDownloads}
          >
            <FolderIcon size={16} />
            <span>Open Downloads</span>
          </button>
        </div>
      </header>

      {firewall?.supported && !firewall.configured && (
        <div className="banner al-wn sb" role="alert">
          <div className="al-in">
            <WarningIcon size={18} />
            <div>
              <strong>Windows Defender Firewall is blocking LAN discovery</strong>
              <div className="mu xs">{firewall.details}</div>
            </div>
          </div>
          <button
            type="button"
            className="btn bp sm"
            disabled={busy}
            onClick={() =>
              void runAction(async () => {
                const s = await invoke<FirewallStatus>("fix_windows_firewall");
                setFirewall(s);
                setToast(s.details);
              })
            }
          >
            Fix Firewall
          </button>
        </div>
      )}

      {queuedSendPaths.length > 0 && (
        <div className="banner al-ac sb" role="status">
          <div className="al-in">
            <SendIcon size={17} />
            <div>
              <strong>Ready to Send ({queuedSendPaths.length} {queuedSendPaths.length === 1 ? "item" : "items"})</strong>
              <div className="mu mono">Click any device on the radar to start sending immediately.</div>
            </div>
          </div>
          <button type="button" className="btn bs sm" onClick={() => setQueuedSendPaths([])}>Clear</button>
        </div>
      )}

      <main className="main">
        <RadarView
          selfInfo={selfInfo}
          peers={peers}
          selectedPeerId={selectedPeerId}
          hoveredDropPeerId={hoveredDropPeerId}
          isDraggingOnRadar={isDraggingOnRadar}
          queuedSendCount={queuedSendPaths.length}
          busy={busy}
          onSelectPeer={setSelectedPeerId}
          onPeerClick={(peer) => void handlePeerClick(peer, false)}
          onPickFolder={(peer) => void handlePeerClick(peer, true)}
        />
      </main>

      <TransferDrawer
        history={history}
        expanded={drawerExpanded}
        onToggleExpanded={() => setDrawerExpanded((v) => !v)}
        onShowInFolder={openDownloads}
      />

      <PairDeviceModal
        open={pairModalOpen}
        session={pairingSession}
        peers={peers}
        busy={busy}
        errorMessage={pairError}
        onClose={() => setPairModalOpen(false)}
        onRefreshSession={refreshPairing}
        onPairSubmit={(target, pin) =>
          runAction(async () => {
            setPairError(null);
            const paired = await invoke<TrustedPeer>("pair_with_peer", { target, pin });
            syncPeers(await invoke<PeerEntry[]>("list_peers"));
            setToast(`Paired with ${paired.friendlyAlias}`);
          }, setPairError)
        }
        onRemoveTrusted={(nodeId) =>
          runAction(async () => {
            await invoke<boolean>("remove_trusted_peer", { nodeId });
            syncPeers(await invoke<PeerEntry[]>("list_peers"));
            setToast("Removed trusted device");
          }, setPairError)
        }
      />

      <ApprovalModal
        offer={pendingOffer}
        busy={busy}
        onRespond={(transferId, accept) =>
          runAction(async () => {
            await invoke("respond_to_offer", { transferId, accept });
            setHistory(await invoke<TransferRecord[]>("get_transfer_history"));
            if (accept) setDrawerExpanded(true);
          })
        }
      />
    </div>
  );
}
