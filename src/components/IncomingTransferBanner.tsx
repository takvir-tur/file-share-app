import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import zapdropLogo from "../assets/zapdrop-icon.png";
import { TransferEventPayload, TransferRecord } from "../types";
import { formatBytes } from "../utils/format";

declare module "react" {
  interface HTMLAttributes<T> {
    popover?: "" | "auto" | "manual";
  }
}

type AriaNotifyDocument = Document & {
  ariaNotify?: (message: string) => void;
};

const OFFER_WINDOW_MS = 60_000;

function supportsNativePopover(): boolean {
  return (
    typeof HTMLElement !== "undefined" &&
    Object.prototype.hasOwnProperty.call(HTMLElement.prototype, "popover")
  );
}

function summarizeOffer(offer: TransferRecord) {
  const senderName = offer.peerName?.trim() || "Nearby Device";
  const fileCount = Math.max(offer.files || 1, 1);
  const itemText =
    fileCount <= 1
      ? offer.fileName?.trim() || "1 file"
      : `${fileCount} files`;
  const sizeText = formatBytes(offer.totalBytes);
  const routeLabel = offer.isWan ? "Over Internet" : "Same Wi-Fi";
  return { senderName, itemText, sizeText, routeLabel };
}

export interface IncomingTransferBannerProps {
  offer: TransferRecord | null;
  busy?: boolean;
  variant?: "inline" | "popup";
  onRespond: (transferId: string, accept: boolean) => void | Promise<void>;
  onOpenApp?: () => void;
}

export function IncomingTransferBanner({
  offer,
  busy = false,
  variant = "inline",
  onRespond,
  onOpenApp,
}: IncomingTransferBannerProps) {
  const bannerRef = useRef<HTMLElement | null>(null);
  const lastAnnouncedIdRef = useRef<string | null>(null);
  const lastTimerIdRef = useRef<string | null>(null);
  const interactionHoldRef = useRef(false);
  const totalWindowRef = useRef(OFFER_WINDOW_MS);

  const [announcement, setAnnouncement] = useState("");
  const [fallbackOpen, setFallbackOpen] = useState(false);
  const [progressFraction, setProgressFraction] = useState(1);

  const isInline = variant === "inline";
  const hasPopoverApi = isInline && supportsNativePopover();

  useEffect(() => {
    const el = bannerRef.current as
      | (HTMLElement & { showPopover?: () => void; hidePopover?: () => void })
      | null;

    if (!isInline) {
      setFallbackOpen(false);
      return;
    }

    if (!offer) {
      setFallbackOpen(false);
      if (hasPopoverApi && el && typeof el.hidePopover === "function") {
        try {
          if (el.matches(":popover-open")) el.hidePopover();
        } catch {
          // Safe no-op if already closed.
        }
      }
      return;
    }

    if (hasPopoverApi && el && typeof el.showPopover === "function") {
      try {
        if (!el.matches(":popover-open")) el.showPopover();
      } catch {
        setFallbackOpen(true);
      }
    } else {
      setFallbackOpen(true);
    }

    return () => {
      if (hasPopoverApi && el && typeof el.hidePopover === "function") {
        try {
          if (el.matches(":popover-open")) el.hidePopover();
        } catch {
          // Element may already be detached.
        }
      }
    };
  }, [hasPopoverApi, isInline, offer?.transferId]);

  useEffect(() => {
    if (!offer) {
      lastAnnouncedIdRef.current = null;
      lastTimerIdRef.current = null;
      setAnnouncement("");
      setProgressFraction(1);
      return;
    }

    const { senderName, itemText, sizeText, routeLabel } = summarizeOffer(offer);
    if (lastAnnouncedIdRef.current !== offer.transferId) {
      lastAnnouncedIdRef.current = offer.transferId;
      const spoken = `${senderName} sent ${itemText} (${sizeText}), ${routeLabel}. Actions available`;
      setAnnouncement(spoken);
      const doc = document as AriaNotifyDocument;
      if (typeof doc.ariaNotify === "function") {
        try {
          doc.ariaNotify(spoken);
        } catch {
          // Live region fallback remains populated.
        }
      }
    }

    const expiresAt = offer.approvalExpiresAtUnixMs;
    if (!expiresAt) {
      setProgressFraction(1);
      return;
    }

    if (lastTimerIdRef.current !== offer.transferId) {
      lastTimerIdRef.current = offer.transferId;
      totalWindowRef.current = Math.max(
        1_000,
        Math.min(OFFER_WINDOW_MS, expiresAt - Date.now())
      );
    }

    const updateFraction = () => {
      if (interactionHoldRef.current) return;
      const remaining = Math.max(0, expiresAt - Date.now());
      setProgressFraction(
        Math.max(0, Math.min(1, remaining / totalWindowRef.current))
      );
    };

    updateFraction();
    const timer = window.setInterval(updateFraction, 250);
    return () => window.clearInterval(timer);
  }, [offer?.transferId, offer?.approvalExpiresAtUnixMs]);

  const cardNode = offer
    ? (() => {
        const { senderName, itemText, sizeText, routeLabel } =
          summarizeOffer(offer);
        const infoInner = (
          <>
            <img
              src={zapdropLogo}
              alt=""
              className="ib-logo"
              width={36}
              height={36}
              draggable={false}
            />
            <div className="ib-meta">
              <div className="ib-top">
                <span className="ib-sender" title={senderName}>
                  {senderName}
                </span>
                <span
                  className={
                    offer.isWan ? "ib-pill ib-pill--wan" : "ib-pill ib-pill--lan"
                  }
                >
                  {routeLabel}
                </span>
              </div>
              <div
                className="ib-summary"
                title={`Sent ${itemText} (${sizeText})`}
              >
                Sent {itemText} ({sizeText})
              </div>
            </div>
          </>
        );

        const cardClasses = isInline
          ? `ib-card ib-card--inline${fallbackOpen ? " is-open" : ""}`
          : "ib-card ib-card--popup";

        return (
          <article
            ref={bannerRef}
            {...(isInline ? { popover: "manual" as const } : {})}
            aria-label={`Incoming transfer from ${senderName}`}
            className={cardClasses}
            onMouseEnter={() => {
              interactionHoldRef.current = true;
            }}
            onMouseLeave={() => {
              interactionHoldRef.current = false;
            }}
            onFocusCapture={() => {
              interactionHoldRef.current = true;
            }}
            onBlurCapture={(e) => {
              if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
                interactionHoldRef.current = false;
              }
            }}
          >
            <div className="ib-row">
              {onOpenApp ? (
                <button
                  type="button"
                  className="ib-open-btn"
                  onClick={onOpenApp}
                  title="Open ZapDrop"
                >
                  {infoInner}
                </button>
              ) : (
                <div className="ib-info">{infoInner}</div>
              )}

              <div className="ib-actions">
                <button
                  type="button"
                  className="ib-btn ib-btn--accept"
                  disabled={busy}
                  aria-label={`Accept transfer from ${senderName}`}
                  onClick={() => void onRespond(offer.transferId, true)}
                >
                  Accept
                </button>
                <button
                  type="button"
                  className="ib-btn ib-btn--decline"
                  disabled={busy}
                  aria-label={`Decline transfer from ${senderName}`}
                  onClick={() => void onRespond(offer.transferId, false)}
                >
                  Decline
                </button>
              </div>
            </div>

            <div className="ib-timer" aria-hidden="true">
              <div
                className="ib-timer-fill"
                style={{ transform: `scaleX(${progressFraction})` }}
              />
            </div>
          </article>
        );
      })()
    : null;

  return (
    <div
      role="region"
      aria-label="Incoming transfer notifications"
      className={isInline ? "incoming-banner-region" : "incoming-popup-shell"}
    >
      <p className="visually-hidden">Screen reader announcements</p>
      <div className="visually-hidden" aria-live="assertive">
        {announcement}
      </div>
      {cardNode}
    </div>
  );
}

export function IncomingBannerPopup() {
  const [offers, setOffers] = useState<TransferRecord[]>([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    document.documentElement.dataset.window = "incoming-banner";
    let disposed = false;

    const loadInitial = async () => {
      try {
        const list = await invoke<TransferRecord[]>("get_transfer_history");
        if (disposed) return;
        setOffers(
          list.filter(
            (r) => r.direction === "incoming" && r.status === "pending_approval"
          )
        );
      } catch {
        // Window will close cleanly once main state settles.
      }
    };

    void loadInitial();

    const unlistenPromise = listen<TransferEventPayload>(
      "beamdrop://transfer-event",
      (event) => {
        if (disposed) return;
        const rec = event.payload.record;
        if (rec.direction !== "incoming") return;
        setOffers((prev) => {
          const rest = prev.filter((item) => item.transferId !== rec.transferId);
          if (rec.status === "pending_approval") {
            return [rec, ...rest];
          }
          return rest;
        });
      }
    );

    return () => {
      disposed = true;
      delete document.documentElement.dataset.window;
      void unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  const currentOffer = offers[0] ?? null;

  return (
    <IncomingTransferBanner
      offer={currentOffer}
      busy={busy}
      variant="popup"
      onOpenApp={() => {
        void invoke("open_main_window");
      }}
      onRespond={async (transferId, accept) => {
        setBusy(true);
        try {
          await invoke("respond_to_offer", { transferId, accept });
          setOffers((prev) =>
            prev.filter((item) => item.transferId !== transferId)
          );
        } finally {
          setBusy(false);
        }
      }}
    />
  );
}
