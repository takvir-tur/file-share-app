import { FormEvent, KeyboardEvent, useEffect, useId, useRef, useState } from "react";
import { CheckIcon, CloseIcon, CopyIcon, OsIcon, ShieldIcon } from "../icons";
import { QrSvg } from "../qr";
import { PairingSession, PeerEntry } from "../types";
import { copyTextWithFallback, shortNodeId, useModalDialog } from "../utils/format";

interface PairDeviceModalProps {
  open: boolean;
  session: PairingSession | null;
  peers: PeerEntry[];
  initialTarget: string | null;
  busy: boolean;
  errorMessage: string | null;
  onClose: () => void;
  onEnsureSession: () => void;
  onRegenerateSession: () => void;
  onPairSubmit: (target: string, pin: string) => Promise<void>;
  onRemoveTrusted: (nodeId: string) => Promise<void>;
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [state, setState] = useState<"idle" | "ok" | "fail">("idle");
  const timer = useRef<number | null>(null);
  useEffect(() => () => { if (timer.current !== null) clearTimeout(timer.current); }, []);

  const copy = async () => {
    if (timer.current !== null) clearTimeout(timer.current);
    const ok = await copyTextWithFallback(value);
    setState(ok ? "ok" : "fail");
    timer.current = window.setTimeout(() => setState("idle"), 2000);
  };

  return (
    <span className="cp-wrap">
      <button
        type="button"
        className="btn bs sm"
        onClick={() => void copy()}
        aria-label={label}
        data-copied={state === "ok" ? "" : undefined}
        data-failed={state === "fail" ? "" : undefined}
      >
        {state === "ok" ? <CheckIcon size={14} /> : <CopyIcon size={14} />}
        <span>{state === "ok" ? "Copied" : "Copy"}</span>
      </button>
      <span className="cp-tip" role="status">
        {state === "ok" ? "Copied" : state === "fail" ? "Copy failed" : ""}
      </span>
    </span>
  );
}

export function PairDeviceModal({
  open,
  session,
  peers,
  initialTarget,
  busy,
  errorMessage,
  onClose,
  onEnsureSession,
  onRegenerateSession,
  onPairSubmit,
  onRemoveTrusted,
}: PairDeviceModalProps) {
  const dialogRef = useModalDialog(open, onClose, true);
  const titleId = useId();
  const showId = useId();
  const enterId = useId();
  const showRef = useRef<HTMLButtonElement | null>(null);
  const enterRef = useRef<HTMLButtonElement | null>(null);

  const [tab, setTab] = useState<"show" | "enter">("show");
  const [target, setTarget] = useState("");
  const [pin, setPin] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [nowSec, setNowSec] = useState(() => Math.floor(Date.now() / 1000));

  useEffect(() => {
    if (open) {
      setErr(null);
      if (initialTarget) {
        setTarget(initialTarget);
        setTab("enter");
      } else {
        setTab("show");
      }
      onEnsureSession();
    }
  }, [initialTarget, open, onEnsureSession]);

  useEffect(() => {
    if (!open || !session) return;
    setNowSec(Math.floor(Date.now() / 1000));
    const timer = window.setInterval(() => {
      setNowSec(Math.floor(Date.now() / 1000));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [open, session?.expiresAtUnix]);

  const remainingSecs = session ? Math.max(0, session.expiresAtUnix - nowSec) : 0;
  const countdownText = `${Math.floor(remainingSecs / 60)}:${String(remainingSecs % 60).padStart(2, "0")}`;

  const onTabKey = (e: KeyboardEvent<HTMLDivElement>) => {
    if (["ArrowRight", "ArrowLeft", "Home", "End"].includes(e.key)) {
      e.preventDefault();
      const next = e.key === "Home" ? "show" : e.key === "End" ? "enter" : tab === "show" ? "enter" : "show";
      setTab(next);
      (next === "show" ? showRef.current : enterRef.current)?.focus();
    }
  };

  const onTargetChange = (val: string) => {
    setTarget(val);
    const m = /[?&]pin=(\d{6})\b/.exec(val);
    if (m) setPin(m[1]);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const t = target.trim();
    const p = pin.trim();
    if (!t) return setErr("Enter an address, Device ID, or pairing link.");
    if (!t.startsWith("beamdrop://") && !/^\d{6}$/.test(p)) {
      return setErr("Enter the 6-digit PIN.");
    }
    setErr(null);
    await onPairSubmit(t, p);
    setPin("");
  };

  const trusted = peers.filter((p) => p.paired);
  const online = peers.filter((p) => p.online);
  const tabList: ["show" | "enter", string, typeof showRef, string][] = [
    ["show", showId, showRef, "Show My Code"],
    ["enter", enterId, enterRef, `Enter Code (${trusted.length} saved)`],
  ];

  return (
    <dialog ref={dialogRef} className="dlg" aria-labelledby={titleId} {...({ closedby: "any" } as Record<string, unknown>)}>
      <div className="m-card">
        <header className="m-hd">
          <h2 id={titleId}>Pair Device</h2>
          <form method="dialog">
            <button type="submit" className="ibtn" aria-label="Close">
              <CloseIcon size={18} />
            </button>
          </form>
        </header>

        <div role="tablist" aria-label="Pairing options" className="tabs" onKeyDown={onTabKey}>
          {tabList.map(([key, id, ref, label]) => (
            <button
              key={key}
              ref={ref}
              type="button"
              role="tab"
              id={id}
              aria-selected={tab === key}
              tabIndex={tab === key ? 0 : -1}
              className="tab"
              onClick={() => setTab(key)}
            >
              {label}
            </button>
          ))}
        </div>

        <div role="tabpanel" aria-labelledby={showId} tabIndex={0} hidden={tab !== "show"}>
          {tab === "show" && (
            <div className="stack">
              {session ? (
                <>
                  <div className="qr-box"><QrSvg value={session.uri} /></div>
                  <div className="panel-box sb">
                    <div>
                      <div className="lbl">6-Digit One-Time PIN</div>
                      <div className="pin-num">{session.pin}</div>
                    </div>
                    <CopyButton value={session.pin} label="Copy PIN" />
                  </div>
                  <div className="panel-box sb">
                    <code className="mono uri">{session.uri}</code>
                    <CopyButton value={session.uri} label="Copy pairing link" />
                  </div>
                  <div className="sb">
                    <span className="mu">Same Wi-Fi: {session.addr}</span>
                    <button type="button" className="btn bs sm" onClick={onRegenerateSession} disabled={busy}>
                      New Code
                    </button>
                  </div>
                  <div className="mu xs">
                    {remainingSecs > 0
                      ? `Internet pairing active · Expires in ${countdownText}`
                      : "Code expired — click New Code"}
                  </div>
                </>
              ) : (
                <div className="mu">Creating pairing code...</div>
              )}
            </div>
          )}
        </div>

        <div role="tabpanel" aria-labelledby={enterId} hidden={tab !== "enter"}>
          {tab === "enter" && (
            <div className="stack">
              {online.length > 0 && (
                <div>
                  <div className="lbl">Nearby Online</div>
                  <div className="row mt4">
                    {online.map((peer) => (
                      <button
                        key={peer.nodeId}
                        type="button"
                        className={`chip ${target === peer.nodeId ? "sel" : ""}`}
                        onClick={() => setTarget(peer.nodeId)}
                      >
                        <OsIcon osType={peer.osType} size={14} />
                        <span>{peer.displayName}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <form onSubmit={(e) => void submit(e)} className="stack">
                <label className="fld">
                  <span className="lbl">Address, Device ID, or Pairing Link</span>
                  <input
                    type="text"
                    placeholder="192.168.1.42:51820 or beamdrop://pair?..."
                    value={target}
                    onChange={(e) => onTargetChange(e.target.value)}
                    autoComplete="off"
                  />
                </label>
                <label className="fld">
                  <span className="lbl">6-Digit PIN</span>
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    placeholder="123456"
                    value={pin}
                    onChange={(e) => setPin(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    className="pin-in"
                  />
                </label>
                {(err || errorMessage) && <p className="err" role="alert">{err ?? errorMessage}</p>}
                <button type="submit" className="btn bp" disabled={busy}>
                  {busy ? "Pairing..." : "Pair Device"}
                </button>
              </form>

              <div className="sep-top stack">
                <h3 className="m0 xs fw6">Saved Devices ({trusted.length})</h3>
                {trusted.length === 0 ? (
                  <p className="mu m0">No saved devices yet.</p>
                ) : (
                  <ul className="list">
                    {trusted.map((peer) => (
                      <li key={peer.nodeId} className="item sb">
                        <div className="row g8 min0">
                          <OsIcon osType={peer.osType} size={16} />
                          <div className="min0">
                            <div className="row xs fw6">
                              <span>{peer.displayName}</span>
                              <ShieldIcon size={13} className="ok" />
                            </div>
                            <div className="mono mu">{shortNodeId(peer.nodeId)}</div>
                          </div>
                        </div>
                        <button
                          type="button"
                          className="btn btn-danger-ghost sm"
                          disabled={busy}
                          onClick={() => void onRemoveTrusted(peer.nodeId)}
                        >
                          Remove
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </dialog>
  );
}
