import { useCallback, useEffect, useRef, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { ApprovalModal } from "./components/ApprovalModal";
import { CellularConfirmModal, PendingCellularSend } from "./components/CellularConfirmModal";
import { PairDeviceModal } from "./components/PairDeviceModal";
import { RadarView } from "./components/RadarView";
import { SavedContacts } from "./components/SavedContacts";
import { TransferDrawer } from "./components/TransferDrawer";
import {
  CloseIcon,
  FolderIcon,
  OsIcon,
  QrIcon,
  RadarIcon,
  RefreshIcon,
  SendIcon,
  WarningIcon,
} from "./icons";
import {
  FirewallStatus,
  MeasurePathsResult,
  PairingSession,
  ParsedPairingUri,
  PeerEntry,
  PeerEventPayload,
  SelfInfo,
  SendDispatchResult,
  TargetedSendRequest,
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
  const [pendingCellularSend, setPendingCellularSend] = useState<PendingCellularSend | null>(null);
  const [firewall, setFirewall] = useState<FirewallStatus | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const lanPeers = peers.filter((p) => p.online);
  const isAndroid = Boolean(selfInfo?.osType.toLowerCase().includes("android"));

  const peersRef = useRef<PeerEntry[]>([]);
  const lanPeersRef = useRef<PeerEntry[]>([]);
  const selectedRef = useRef<string | null>(null);
  const inFlightPairingRef = useRef<Set<string>>(new Set());
  peersRef.current = peers;
  lanPeersRef.current = lanPeers;
  selectedRef.current = selectedPeerId;

  const showError = useCallback((msg: string) => {
    setErrorBanner(msg);
    setToast(msg);
  }, []);

  const pickDefault = (list: PeerEntry[], curr: string | null) => {
    const online = list.filter((p) => p.online);
    return curr && online.some((p) => p.nodeId === curr)
      ? curr
      : online[0]?.nodeId ?? null;
  };

  const queuePaths = (paths: string[]) =>
    setQueuedSendPaths((p) => Array.from(new Set([...p, ...paths])));

  const openDownloads = () =>
    void invoke("open_downloads_folder").catch((e: unknown) => showError(String(e)));

  const syncPeers = useCallback((list: PeerEntry[]) => {
    setPeers(list);
    setSelectedPeerId((curr) => pickDefault(list, curr));
  }, []);

  const applyTargetedSend = useCallback((req: TargetedSendRequest, peerList?: PeerEntry[]) => {
    if (!req.paths.length) return;
    const pool = peerList ?? peersRef.current;
    const matched = pool.find((p) => p.nodeId === req.targetNodeId);
    setSelectedPeerId(req.targetNodeId);
    setDrawerExpanded(true);
    setErrorBanner(null);
    setToast(`Sending ${req.paths.length} item(s) to ${matched?.displayName ?? req.targetNodeId.slice(0, 10)}`);
  }, []);

  const handleIncomingPairingUri = useCallback(
    async (rawUri: string) => {
      const trimmed = rawUri.trim();
      if (!inTauri || !trimmed || inFlightPairingRef.current.has(trimmed)) return;
      inFlightPairingRef.current.add(trimmed);
      setBusy(true);
      try {
        const parsed = await invoke<ParsedPairingUri>("parse_pairing_uri", { uri: trimmed });
        const paired = await invoke<TrustedPeer>("pair_with_peer", {
          target: trimmed,
          pin: parsed.pin,
        });
        syncPeers(await invoke<PeerEntry[]>("list_peers"));
        setSelectedPeerId(paired.nodeId);
        setPairModalOpen(false);
        setPairError(null);
        setErrorBanner(null);
        setToast(`Paired with ${paired.friendlyAlias}`);
      } catch (err) {
        showError(`QR pairing failed: ${String(err)}`);
      } finally {
        inFlightPairingRef.current.delete(trimmed);
        setBusy(false);
      }
    },
    [inTauri, showError, syncPeers]
  );

  const drainPendingIntents = useCallback(
    async (peerList?: PeerEntry[]) => {
      if (!inTauri) return;
      const [pendingPaths, pendingTargeted, pendingPairingUris] = await Promise.all([
        invoke<string[]>("take_pending_send_paths"),
        invoke<TargetedSendRequest[]>("take_pending_targeted_send"),
        invoke<string[]>("take_pending_pairing_uri"),
      ]);
      if (pendingPaths.length) queuePaths(pendingPaths);
      if (pendingTargeted.length) {
        pendingTargeted.forEach((req) => applyTargetedSend(req, peerList));
      }
      for (const uri of pendingPairingUris) {
        void handleIncomingPairingUri(uri);
      }
    },
    [applyTargetedSend, handleIncomingPairingUri, inTauri]
  );

  const refreshState = useCallback(async () => {
    if (!inTauri) return;
    const [info, peerList, transferHistory, fwStatus] = await Promise.all([
      invoke<SelfInfo>("get_self_info"),
      invoke<PeerEntry[]>("list_peers"),
      invoke<TransferRecord[]>("get_transfer_history"),
      invoke<FirewallStatus>("check_windows_firewall"),
    ]);
    setSelfInfo(info);
    syncPeers(peerList);
    setHistory(transferHistory);
    setFirewall(fwStatus);
    await drainPendingIntents(peerList);
  }, [drainPendingIntents, inTauri, syncPeers]);

  const resyncOnForeground = useCallback(async () => {
    if (!inTauri) return;
    try {
      const [updatedPeers, transferHistory] = await Promise.all([
        invoke<PeerEntry[]>("refresh_peers"),
        invoke<TransferRecord[]>("get_transfer_history"),
      ]);
      syncPeers(updatedPeers);
      setHistory(transferHistory);
      await drainPendingIntents(updatedPeers);
    } catch (err) {
      showError(`Refresh failed: ${String(err)}`);
    }
  }, [drainPendingIntents, inTauri, showError, syncPeers]);

  const runAction = useCallback(
    async (task: () => Promise<void>, onError: (msg: string) => void = showError) => {
      setBusy(true);
      try {
        await task();
      } catch (err) {
        onError(String(err));
      } finally {
        setBusy(false);
      }
    },
    [showError]
  );

  const performSend = useCallback(
    async (peer: PeerEntry, paths: string[], fromQueue: boolean) => {
      const res = await invoke<SendDispatchResult>("send_paths", {
        targetNodeId: peer.nodeId,
        paths,
      });
      if (fromQueue) setQueuedSendPaths([]);
      setErrorBanner(null);
      setDrawerExpanded(true);
      setToast(
        `Sending ${res.queued} item(s) to ${peer.displayName}${peer.online ? "" : " via Long-Distance"}`
      );
    },
    []
  );

  const dispatchPathsToPeer = useCallback(
    async (peer: PeerEntry, paths: string[], fromQueue = false) => {
      if (!inTauri || !paths.length) return;
      if (!peer.online) {
        if (!peer.allowWan) {
          showError(
            `${peer.displayName} is offline on LAN. Enable Long-Distance in Saved Contacts to send over the internet.`
          );
          return;
        }
        await runAction(async () => {
          const [metered, measured] = await Promise.all([
            invoke<boolean>("is_on_metered_cellular"),
            invoke<MeasurePathsResult>("measure_paths_bytes", { paths }),
          ]);
          const resolved = measured.resolvedPaths.length ? measured.resolvedPaths : paths;
          if (metered) {
            setPendingCellularSend({
              peer,
              paths: resolved,
              totalBytes: measured.totalBytes,
              fromQueue,
            });
            return;
          }
          await performSend(peer, resolved, fromQueue);
        }, (err) => showError(`Send failed: ${err}`));
        return;
      }
      await runAction(
        () => performSend(peer, paths, fromQueue),
        (err) => showError(`Send failed: ${err}`)
      );
    },
    [inTauri, performSend, runAction, showError]
  );

  const dispatchRef = useRef(dispatchPathsToPeer);
  dispatchRef.current = dispatchPathsToPeer;

  useEffect(() => {
    if (!inTauri) return;
    void refreshState().catch((err: unknown) => showError(`Daemon error: ${String(err)}`));

    const onVisibility = () => {
      if (!document.hidden) void resyncOnForeground();
    };
    const onFocus = () => void resyncOnForeground();
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("focus", onFocus);

    const subs = [
      listen<PeerEventPayload>("beamdrop://peer-event", () => {
        void invoke<PeerEntry[]>("list_peers").then(syncPeers);
      }),
      listen<TransferEventPayload>("beamdrop://transfer-event", ({ payload }) => {
        setHistory((prev) =>
          [payload.record, ...prev.filter((i) => i.transferId !== payload.record.transferId)].slice(
            0,
            100
          )
        );
        if (
          ["auto_accepted", "progress", "offer_received", "started", "paused"].includes(
            payload.kind
          )
        ) {
          setDrawerExpanded(true);
        }
        if (payload.record.status === "failed" || payload.record.status === "interrupted") {
          showError(
            `${payload.record.fileName ?? "Transfer"}: ${payload.record.reason ?? payload.record.status}`
          );
        } else if (payload.record.status === "completed") {
          setErrorBanner(null);
        }
      }),
      listen<string[]>("beamdrop://send-paths", ({ payload }) => {
        if (payload.length) {
          queuePaths(payload);
          setToast(`Ready to send ${payload.length} queued item(s). Click a device.`);
        }
      }),
      listen<TargetedSendRequest>("beamdrop://targeted-send", ({ payload }) => {
        applyTargetedSend(payload);
      }),
      listen<string>("beamdrop://pair-uri", ({ payload }) => {
        void handleIncomingPairingUri(payload);
      }),
      getCurrentWebview().onDragDropEvent(({ payload }) => {
        if (payload.type === "leave") {
          setHoveredDropPeerId(null);
          setIsDraggingOnRadar(false);
          return;
        }
        const hit = hitTestDropTarget(
          payload.position.x,
          payload.position.y,
          selectedRef.current,
          lanPeersRef.current
        );
        if (payload.type === "enter" || payload.type === "over") {
          setHoveredDropPeerId(hit.hoveredPeerId);
          setIsDraggingOnRadar(hit.onRadarSurface);
        } else if (payload.type === "drop") {
          setHoveredDropPeerId(null);
          setIsDraggingOnRadar(false);
          const target = lanPeersRef.current.find((p) => p.nodeId === hit.hoveredPeerId);
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
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("focus", onFocus);
      subs.forEach((p) => void p.then((u) => u()));
    };
  }, [
    applyTargetedSend,
    handleIncomingPairingUri,
    inTauri,
    refreshState,
    resyncOnForeground,
    showError,
    syncPeers,
  ]);

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
    try {
      const picked = await openFileDialog({
        multiple: true,
        directory,
        title: `Send ${directory ? "Folder" : "File"}(s) to ${peer.displayName}`,
      });
      if (picked) {
        await dispatchPathsToPeer(peer, Array.isArray(picked) ? picked : [picked], false);
      }
    } catch (err) {
      const msg = String(err);
      if (!/cancel/i.test(msg)) {
        showError(`File picker failed: ${msg}`);
      }
    }
  };

  const invokeTransferControl = (
    cmd: "pause_transfer" | "resume_transfer" | "cancel_transfer",
    transferId: string,
    label: string
  ) => {
    void invoke(cmd, { transferId }).catch((err: unknown) =>
      showError(`${label} failed: ${String(err)}`)
    );
  };

  const handleToggleWan = (peer: PeerEntry, enabled: boolean) =>
    runAction(async () => {
      await invoke<boolean>("set_peer_wan_enabled", {
        nodeId: peer.nodeId,
        enabled,
      });
      syncPeers(await invoke<PeerEntry[]>("list_peers"));
      setToast(
        enabled
          ? `Long-Distance enabled for ${peer.displayName}`
          : `Long-Distance disabled for ${peer.displayName}`
      );
    });

  const confirmCellularSend = () => {
    if (!pendingCellularSend) return;
    const req = pendingCellularSend;
    setPendingCellularSend(null);
    void runAction(
      () => performSend(req.peer, req.paths, req.fromQueue),
      (err) => showError(`Send failed: ${err}`)
    );
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
            className="btn bs"
            disabled={!inTauri}
            title="Probe cached devices on LAN"
            onClick={() => void resyncOnForeground()}
          >
            <RefreshIcon size={15} />
            <span>Scan</span>
          </button>
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

      {errorBanner && (
        <div className="banner al-dn sb" role="alert">
          <div className="al-in">
            <WarningIcon size={18} />
            <div className="min0">
              <strong>Action Needed</strong>
              <div className="xs">{errorBanner}</div>
            </div>
          </div>
          <button
            type="button"
            className="ibtn"
            aria-label="Dismiss error"
            onClick={() => setErrorBanner(null)}
          >
            <CloseIcon size={15} />
          </button>
        </div>
      )}

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
              <div className="mu mono">Click a radar device or Saved Contact below to start sending immediately.</div>
            </div>
          </div>
          <button type="button" className="btn bs sm" onClick={() => setQueuedSendPaths([])}>Clear</button>
        </div>
      )}

      <main className="main stack">
        <RadarView
          selfInfo={selfInfo}
          peers={lanPeers}
          selectedPeerId={selectedPeerId}
          hoveredDropPeerId={hoveredDropPeerId}
          isDraggingOnRadar={isDraggingOnRadar}
          queuedSendCount={queuedSendPaths.length}
          busy={busy}
          onSelectPeer={setSelectedPeerId}
          onPeerClick={(peer) => void handlePeerClick(peer, false)}
          onPickFolder={(peer) => void handlePeerClick(peer, true)}
        />
        <SavedContacts
          peers={peers}
          busy={busy}
          queuedSendCount={queuedSendPaths.length}
          isAndroid={isAndroid}
          onToggleWan={handleToggleWan}
          onSendFiles={(peer) => void handlePeerClick(peer, false)}
          onSendFolder={(peer) => void handlePeerClick(peer, true)}
        />
      </main>

      <TransferDrawer
        history={history}
        expanded={drawerExpanded}
        onToggleExpanded={() => setDrawerExpanded((v) => !v)}
        onShowInFolder={openDownloads}
        onPause={(id) => invokeTransferControl("pause_transfer", id, "Pause")}
        onResume={(id) => invokeTransferControl("resume_transfer", id, "Resume")}
        onCancel={(id) => invokeTransferControl("cancel_transfer", id, "Cancel")}
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
            setSelectedPeerId(paired.nodeId);
            setErrorBanner(null);
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

      <CellularConfirmModal
        pending={pendingCellularSend}
        busy={busy}
        onCancel={() => setPendingCellularSend(null)}
        onConfirm={confirmCellularSend}
      />
    </div>
  );
}
