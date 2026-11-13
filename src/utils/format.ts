import { useEffect, useRef } from "react";

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const idx = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, idx);
  return `${value.toFixed(idx === 0 ? 0 : 1)} ${units[idx]}`;
}

export function shortNodeId(nodeId: string): string {
  if (nodeId.length <= 14) return nodeId;
  return `${nodeId.slice(0, 7)}...${nodeId.slice(-5)}`;
}

export function formatEta(
  totalBytes: number,
  transferredBytes: number,
  speedMbps: number
): string {
  if (totalBytes <= 0 || transferredBytes >= totalBytes) return "0s";
  if (speedMbps <= 0.01) return "--";
  const remainingBytes = totalBytes - transferredBytes;
  const bytesPerSec = speedMbps * 1024 * 1024;
  const secs = Math.max(1, Math.round(remainingBytes / bytesPerSec));
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  const remSecs = secs % 60;
  if (mins < 60) return `${mins}m ${remSecs}s`;
  const hrs = Math.floor(mins / 60);
  return `${hrs}h ${mins % 60}m`;
}

export async function copyTextWithFallback(text: string): Promise<boolean> {
  if (!text) return false;
  try {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fall back to synchronous textarea copy below when clipboard API rejects.
  }

  try {
    const field = document.createElement("textarea");
    field.value = text;
    field.setAttribute("readonly", "");
    field.style.cssText = "position:fixed;inset-block-start:0;opacity:0;pointer-events:none";
    document.body.append(field);
    field.select();
    const ok = document.execCommand("copy");
    field.remove();
    return ok;
  } catch {
    return false;
  }
}

export function useModalDialog(
  open: boolean,
  onClose: () => void,
  enableLightDismiss: boolean
) {
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const closingFromPropRef = useRef(false);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    if (open && !dialog.open) {
      closingFromPropRef.current = false;
      dialog.showModal();
    } else if (!open && dialog.open) {
      closingFromPropRef.current = true;
      dialog.close();
    }
  }, [open]);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;

    const handleClose = () => {
      dialog.returnValue = "";
      const fromProp = closingFromPropRef.current;
      closingFromPropRef.current = false;
      if (!fromProp) {
        onCloseRef.current();
      }
    };
    dialog.addEventListener("close", handleClose);

    if (!enableLightDismiss || "closedBy" in HTMLDialogElement.prototype) {
      return () => {
        dialog.removeEventListener("close", handleClose);
      };
    }

    // Fallback for engines without native <dialog closedby="any"> (e.g. WebKit/WKWebView).
    const isOutside = (e: PointerEvent) => {
      const rect = dialog.getBoundingClientRect();
      return (
        e.clientX < rect.left ||
        e.clientX > rect.right ||
        e.clientY < rect.top ||
        e.clientY > rect.bottom
      );
    };

    let pressedOutside = false;
    const handlePointerDown = (e: PointerEvent) => {
      pressedOutside = dialog.open && isOutside(e);
    };
    const handlePointerUp = (e: PointerEvent) => {
      if (pressedOutside && dialog.open && isOutside(e)) {
        dialog.close();
      }
      pressedOutside = false;
    };

    dialog.addEventListener("pointerdown", handlePointerDown);
    dialog.addEventListener("pointerup", handlePointerUp);

    return () => {
      dialog.removeEventListener("close", handleClose);
      dialog.removeEventListener("pointerdown", handlePointerDown);
      dialog.removeEventListener("pointerup", handlePointerUp);
    };
  }, [enableLightDismiss]);

  return dialogRef;
}
