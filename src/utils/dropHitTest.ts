import { PeerEntry } from "../types";

export function isPeerSendable(peer: PeerEntry): boolean {
  return (peer.isLan && peer.online) || Boolean(peer.addr) || (peer.paired && peer.allowWan);
}

export function hitTestDropTarget(
  xPhys: number,
  yPhys: number,
  sendablePeers: PeerEntry[]
): string | null {
  const dpr = window.devicePixelRatio || 1;
  const els = document.elementsFromPoint(xPhys / dpr, yPhys / dpr);

  for (const el of els) {
    if (el instanceof HTMLElement) {
      const id = el.closest<HTMLElement>("[data-drop-peer]")?.dataset.dropPeer;
      if (id && sendablePeers.some((p) => p.nodeId === id)) {
        return id;
      }
    }
  }
  return null;
}
