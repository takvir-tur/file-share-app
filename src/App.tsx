import { useCallback, useEffect, useRef, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import zapdropLogo from "./assets/zapdrop-icon.png";
import { CellularConfirmModal, PendingCellularSend } from "./components/CellularConfirmModal";
import { DeviceGrid } from "./components/DeviceGrid";
import { IncomingTransferBanner } from "./components/IncomingTransferBanner";
import { PairDeviceModal } from "./components/PairDeviceModal";
import { TransferDrawer } from "./components/TransferDrawer";
import { CloseIcon, FolderIcon, OsIcon, QrIcon, SendIcon, WarningIcon } from "./icons";
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
import { hitTestDropTarget, isPeerSendable } from "./utils/dropHitTest";

export default function App() {
  const inTauri = isTauri();
  const [selfInfo, setSelfInfo] = useState<SelfInfo | null>(null);
  const [peers, setPeers] = useState<PeerEntry[]>([]);
  const [hoveredDropPeerId, setHoveredDropPeerId] = useState<string | null>(null);

  const [history, setHistory] = useState<TransferRecord[]>([]);
  const [drawerExpanded, setDrawerExpanded] = useState(false);

  const [pairModalOpen, setPairModalOpen] = useState(false);
  const [pairInitialTarget, setPairInitialTarget] = useState<string | null>(null);
  const [pairingSession, setPairingSession] = useState<PairingSession | null>(null);
  const [pairError, setPairError] = useState<string | null>(null);

  const [queuedSendPaths, setQueuedSendPaths] = useState<string[]>([]);
  const [pendingCellularSend, setPendingCellularSend] = useState<PendingCellularSend | null>(null);
  const [firewall, setFirewall] = useState<FirewallStatus | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const visiblePeers = peers.filter((p) => p.paired || p.online);
  const sendablePeers = visiblePeers.filter(isPeerSendable);
  const isAndroid = Boolean(selfInfo?.osType.toLowerCase().includes("android"));

  const peersRef = useRef<PeerEntry[]>([]);
  const sendablePeersRef = useRef<PeerEntry[]>([]);
  const inFlightPairingRef = useRef<Set<string>>(new Set());
  peersRef.current = peers;
  sendablePeersRef.current = sendablePeers;

  const showError = useCallback((msg: string) => {
    setErrorBanner(msg);
    setToast(msg);
  }, []);

  const queuePaths = (paths: string[]) =>
    setQueuedSendPaths((p) => Array.from(new Set([...p, ...paths])));

  const openDownloads = () =>
    void invoke("open_downloads_folder").catch((e: unknown) => showError(String(e)));

  const syncPeers = useCallback((list: PeerEntry[]) => {
    setPeers(list);
  }, []);

  const applyTargetedSend = useCallback((req: TargetedSendRequest, peerList?: PeerEntry[]) => {
    if (!req.paths.length) return;
    const pool = peerList ?? peersRef.current;
    const matched = pool.find((p) => p.nodeId === req.targetNodeId);
    setDrawerExpanded(true);
    setErrorBanner(null);
    setToast(
      `Sending ${req.paths.length} item(s) to ${matched?.displayName ?? req.targetNodeId.slice(0, 10)}`
    );
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
        setPairModalOpen(false);
        setPairError(null);
        setErrorBanner(null);
        setToast(`Paired with ${paired.friendlyAlias}`);
      } catch (err) {
        showError(`Pairing failed: ${String(err)}`);
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

  const performSend = useCallback(async (peer: PeerEntry, paths: string[], fromQueue: boolean) => {
    const res = await invoke<SendDispatchResult>("send_paths", {
      targetNodeId: peer.nodeId,
      paths,
    });
    if (fromQueue) setQueuedSendPaths([]);
    setErrorBanner(null);
    setDrawerExpanded(true);
    setToast(`Sending ${res.queued} item(s) to ${peer.displayName}`);
  }, []);

  const dispatchPathsToPeer = useCallback(
    async (peer: PeerEntry, paths: string[], fromQueue = false) => {
      if (!inTauri || !paths.length) return;
      if (!peer.online && !peer.addr) {
        if (!peer.allowWan) {
          showError(
            `${peer.displayName} is offline. Enable Internet Sharing in Sharing Settings to send over the internet.`
          );
          return;
        }
        await runAction(
          async () => {
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
          },
          (err) => showError(`Send failed: ${err}`)
        );
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
    void refreshState().catch((err: unknown) => showError(`Startup error: ${String(err)}`));

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
          [
            "auto_accepted",
            "awaiting_approval",
            "progress",
            "offer_received",
            "started",
            "paused",
            "failed",
          ].includes(payload.kind)
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
          setToast(`Ready to send ${payload.length} item(s) — choose a device.`);
        }
        void invoke<string[]>("take_pending_send_paths").then((drained) => {
          if (drained.length) queuePaths(drained);
        });
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
          return;
        }
        const hitPeerId = hitTestDropTarget(
          payload.position.x,
          payload.position.y,
          sendablePeersRef.current
        );
        if (payload.type === "enter" || payload.type === "over") {
          setHoveredDropPeerId(hitPeerId);
        } else if (payload.type === "drop") {
          setHoveredDropPeerId(null);
          const target = sendablePeersRef.current.find((p) => p.nodeId === hitPeerId);
          if (target && payload.paths.length) {
            void dispatchRef.current(target, payload.paths, false);
          } else if (payload.paths.length) {
            queuePaths(payload.paths);
            setToast("Files ready — choose a device below to send.");
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

  const ensurePairing = useCallback(() => {
    if (!inTauri) return;
    void runAction(async () => {
      setPairingSession(await invoke<PairingSession>("start_pairing", { forceNew: false }));
      setPairError(null);
    }, setPairError);
  }, [inTauri, runAction]);

  const regeneratePairing = useCallback(() => {
    if (!inTauri) return;
    void runAction(async () => {
      setPairingSession(await invoke<PairingSession>("regenerate_pairing"));
      setPairError(null);
    }, setPairError);
  }, [inTauri, runAction]);

  const openPairModal = useCallback(
    (targetNodeId?: string) => {
      setPairError(null);
      setPairInitialTarget(targetNodeId ?? null);
      setPairModalOpen(true);
      ensurePairing();
    },
    [ensurePairing]
  );

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
          ? `Internet Sharing enabled for ${peer.displayName}`
          : `Internet Sharing disabled for ${peer.displayName}`
      );
    });

  const handleToggleAutoAccept = (peer: PeerEntry, lanAuto: boolean, wanAuto: boolean) =>
    runAction(async () => {
      await invoke<boolean>("set_peer_auto_accept", {
        nodeId: peer.nodeId,
        lanAuto,
        wanAuto,
      });
      syncPeers(await invoke<PeerEntry[]>("list_peers"));
      setToast(`Updated sharing settings for ${peer.displayName}`);
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

  const handleRemoveTrusted = (
    nodeId: string,
    label?: string,
    onErr: (msg: string) => void = (err) => showError(`Remove failed: ${err}`)
  ) =>
    runAction(async () => {
      await invoke<boolean>("remove_trusted_peer", { nodeId });
      syncPeers(await invoke<PeerEntry[]>("list_peers"));
      setToast(label ? `Removed ${label}` : "Removed device");
    }, onErr);

  const pendingOffer = history.find((item) => item.status === "pending_approval") ?? null;

  return (
    <div className="app">
      <IncomingTransferBanner
        offer={pairModalOpen || pendingCellularSend ? null : pendingOffer}
        busy={busy}
        variant="inline"
        onRespond={(transferId, accept) =>
          runAction(async () => {
            await invoke("respond_to_offer", { transferId, accept });
            setHistory(await invoke<TransferRecord[]>("get_transfer_history"));
            if (accept) setDrawerExpanded(true);
          })
        }
      />

      <header className="card hdr">
        <div className="idbox">
          <img src={zapdropLogo} alt="" width={34} height={34} className="brand-ico" />
          <div className="idtxt">
            <div className="row g8">
              <h1>ZapDrop</h1>
              {selfInfo && (
                <span className="badge">
                  <OsIcon osType={selfInfo.osType} size={13} />
                  <span>{selfInfo.hostname}</span>
                </span>
              )}
              {selfInfo && (
                <span className="mono mu xs">
                  {selfInfo.lanIp}:{selfInfo.listenPort}
                </span>
              )}
            </div>
            {toast && (
              <p className="subline" role="status">
                {toast}
              </p>
            )}
          </div>
        </div>

        <div className="hdr-act">
          <button type="button" className="btn bp" onClick={() => openPairModal()}>
            <QrIcon size={16} />
            <span>Pair Device</span>
          </button>
          <button type="button" className="btn bs" disabled={!inTauri} onClick={openDownloads}>
            <FolderIcon size={16} />
            <span>Downloads</span>
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
            <div className="min0">
              <strong>Windows Firewall is blocking local discovery</strong>
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
            Allow ZapDrop
          </button>
        </div>
      )}

      {queuedSendPaths.length > 0 && (
        <div className="banner al-ac sb" role="status">
          <div className="al-in">
            <SendIcon size={17} />
            <div className="min0">
              <strong>
                Ready to Send ({queuedSendPaths.length} {queuedSendPaths.length === 1 ? "item" : "items"})
              </strong>
              <div className="mu xs">Click a device below to send now.</div>
            </div>
          </div>
          <button type="button" className="btn bs sm" onClick={() => setQueuedSendPaths([])}>
            Clear
          </button>
        </div>
      )}

      <main className="main">
        <DeviceGrid
          peers={visiblePeers}
          busy={busy}
          hoveredDropPeerId={hoveredDropPeerId}
          queuedSendCount={queuedSendPaths.length}
          isAndroid={isAndroid}
          onSendFiles={(peer) => void handlePeerClick(peer, false)}
          onSendFolder={(peer) => void handlePeerClick(peer, true)}
          onOpenPair={openPairModal}
          onToggleWan={handleToggleWan}
          onToggleAutoAccept={handleToggleAutoAccept}
          onRemoveTrusted={(peer) => {
            void handleRemoveTrusted(peer.nodeId, peer.displayName);
          }}
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
        initialTarget={pairInitialTarget}
        busy={busy}
        errorMessage={pairError}
        onClose={() => {
          setPairModalOpen(false);
        }}
        onEnsureSession={ensurePairing}
        onRegenerateSession={regeneratePairing}
        onPairSubmit={(target, pin) =>
          runAction(async () => {
            setPairError(null);
            const paired = await invoke<TrustedPeer>("pair_with_peer", { target, pin });
            syncPeers(await invoke<PeerEntry[]>("list_peers"));
            setErrorBanner(null);
            setToast(`Paired with ${paired.friendlyAlias}`);
          }, setPairError)
        }
        onRemoveTrusted={(nodeId) => handleRemoveTrusted(nodeId, undefined, setPairError)}
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
