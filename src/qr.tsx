import { useMemo } from "react";

// [version, ecFormatBits (M=0, L=1), ecPerBlock, g1Blocks, g1Data, g2Blocks, g2Data]
type Spec = [number, number, number, number, number, number, number];
const SPECS: Spec[] = [
  [1, 0, 10, 1, 16, 0, 0],
  [2, 0, 16, 1, 28, 0, 0],
  [3, 0, 26, 1, 44, 0, 0],
  [4, 0, 18, 2, 32, 0, 0],
  [5, 0, 24, 2, 43, 0, 0],
  [6, 0, 16, 4, 27, 0, 0],
  [7, 0, 18, 4, 31, 0, 0],
  [8, 0, 22, 2, 38, 2, 39],
  [9, 0, 22, 3, 36, 2, 37],
  [10, 0, 26, 4, 43, 1, 44],
  [11, 0, 30, 1, 50, 4, 51],
  [11, 1, 20, 4, 81, 0, 0],
  [12, 1, 24, 2, 92, 2, 93],
];

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) {
  GF_EXP[i] = GF_EXP[i + 255] = x;
  GF_LOG[x] = i;
  x = (x << 1) ^ (x & 128 ? 0x11d : 0);
}

const gfMul = (a: number, b: number) => (a && b ? GF_EXP[GF_LOG[a] + GF_LOG[b]] : 0);

function rsRemainder(data: Uint8Array, ecLen: number): Uint8Array {
  let gen = new Uint8Array([1]);
  for (let i = 0; i < ecLen; i++) {
    const next = new Uint8Array(gen.length + 1);
    for (let j = 0; j < gen.length; j++) {
      next[j] ^= gen[j];
      next[j + 1] ^= gfMul(gen[j], GF_EXP[i]);
    }
    gen = next;
  }
  const buf = new Uint8Array(data.length + ecLen);
  buf.set(data);
  for (let i = 0; i < data.length; i++) {
    const coef = buf[i];
    if (coef) for (let j = 0; j < gen.length; j++) buf[i + j] ^= gfMul(gen[j], coef);
  }
  return buf.subarray(data.length);
}

function encodeCodewords(payload: Uint8Array, spec: Spec): number[] {
  const [ver, , ecLen, g1B, g1D, g2B, g2D] = spec;
  const totalData = g1B * g1D + g2B * g2D;
  const bits: number[] = [];
  const push = (val: number, len: number) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
  };
  push(4, 4);
  push(payload.length, ver <= 9 ? 8 : 16);
  for (const b of payload) push(b, 8);
  for (let i = 0; i < 4 && bits.length < totalData * 8; i++) bits.push(0);
  while (bits.length & 7) bits.push(0);

  const data = new Uint8Array(totalData);
  for (let i = 0; i < bits.length / 8; i++) {
    let b = 0;
    for (let k = 0; k < 8; k++) b = (b << 1) | bits[i * 8 + k];
    data[i] = b;
  }
  for (let i = bits.length / 8, t = 0; i < totalData; i++, t ^= 1) data[i] = t ? 0x11 : 0xec;

  const blocks: Uint8Array[] = [];
  const ecs: Uint8Array[] = [];
  let off = 0;
  for (const [cnt, len] of [[g1B, g1D], [g2B, g2D]]) {
    for (let i = 0; i < cnt; i++) {
      const blk = data.subarray(off, (off += len));
      blocks.push(blk);
      ecs.push(rsRemainder(blk, ecLen));
    }
  }
  const out: number[] = [];
  for (let i = 0, m = Math.max(g1D, g2D); i < m; i++) {
    for (const blk of blocks) if (i < blk.length) out.push(blk[i]);
  }
  for (let i = 0; i < ecLen; i++) for (const ec of ecs) out.push(ec[i]);
  return out;
}

function drawFnPatterns(version: number) {
  const n = 17 + 4 * version;
  const grid = () => Array.from({ length: n }, () => Array<boolean>(n).fill(false));
  const mod = grid(), fn = grid();
  const setFn = (r: number, c: number, d: boolean) => ((mod[r][c] = d), (fn[r][c] = true));

  for (const [r0, c0] of [[0, 0], [0, n - 7], [n - 7, 0]]) {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const r = r0 + dr, c = c0 + dc;
        if (r >= 0 && r < n && c >= 0 && c < n) {
          const d = Math.max(Math.abs(dr - 3), Math.abs(dc - 3));
          setFn(r, c, d !== 2 && d !== 4);
        }
      }
    }
  }

  if (version >= 2) {
    const coords = version <= 6 ? [6, n - 7] : [6, (n - 13) / 2 + 6, n - 7];
    for (const rc of coords) {
      for (const cc of coords) {
        if ((rc < 9 && (cc < 9 || cc >= n - 8)) || (rc >= n - 8 && cc < 9)) continue;
        for (let dr = -2; dr <= 2; dr++) {
          for (let dc = -2; dc <= 2; dc++) setFn(rc + dr, cc + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
        }
      }
    }
  }

  for (let i = 8; i < n - 8; i++) {
    setFn(6, i, !(i & 1));
    setFn(i, 6, !(i & 1));
  }
  for (let i = 0; i <= 8; i++) {
    if (!fn[8][i]) setFn(8, i, false);
    if (!fn[i][8]) setFn(i, 8, false);
  }
  for (let i = n - 8; i < n; i++) {
    setFn(8, i, false);
    if (i > n - 8) setFn(i, 8, false);
  }
  setFn(n - 8, 8, true);

  if (version >= 7) {
    let rem = version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) !== 0;
      const a = n - 11 + (i % 3), b = (i / 3) | 0;
      setFn(a, b, dark);
      setFn(b, a, dark);
    }
  }
  return { mod, fn };
}

function drawFormat(mod: boolean[][], ecBits: number, mask: number) {
  const n = mod.length;
  const data = (ecBits << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;
  for (let i = 0; i < 15; i++) {
    const d = ((bits >>> i) & 1) !== 0;
    mod[i < 6 ? i : i < 8 ? i + 1 : n - 15 + i][8] = d;
    mod[8][i < 8 ? n - i - 1 : i < 9 ? 15 - i : 14 - i] = d;
  }
}

const MASK_FN: ((r: number, c: number) => boolean)[] = [
  (r, c) => ((r + c) & 1) === 0,
  (r) => (r & 1) === 0,
  (_, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (((r >> 1) + ((c / 3) | 0)) & 1) === 0,
  (r, c) => ((r * c) & 1) + ((r * c) % 3) === 0,
  (r, c) => ((((r * c) & 1) + ((r * c) % 3)) & 1) === 0,
  (r, c) => ((((r + c) & 1) + ((r * c) % 3)) & 1) === 0,
];

function penalty(m: boolean[][]): number {
  const n = m.length;
  let score = 0, dark = 0;
  const scanLine = (get: (i: number) => boolean) => {
    let prev = get(0), run = 1;
    for (let i = 1; i < n; i++) {
      const cur = get(i);
      run = cur === prev ? run + 1 : ((prev = cur), 1);
      if (run === 5) score += 3;
      else if (run > 5) score++;
    }
    for (let i = 0; i <= n - 7; i++) {
      if (get(i) && !get(i + 1) && get(i + 2) && get(i + 3) && get(i + 4) && !get(i + 5) && get(i + 6)) {
        const l = i >= 4 && !get(i - 1) && !get(i - 2) && !get(i - 3) && !get(i - 4);
        const r = i + 10 < n && !get(i + 7) && !get(i + 8) && !get(i + 9) && !get(i + 10);
        if (l || r) score += 40;
      }
    }
  };
  for (let i = 0; i < n; i++) {
    scanLine((c) => m[i][c]);
    scanLine((r) => m[r][i]);
    for (let c = 0; c < n; c++) {
      if (m[i][c]) dark++;
      if (i < n - 1 && c < n - 1 && m[i][c] === m[i][c + 1] && m[i][c] === m[i + 1][c] && m[i][c] === m[i + 1][c + 1]) {
        score += 3;
      }
    }
  }
  return score + Math.floor(Math.abs(dark * 20 - n * n * 10) / (n * n)) * 10;
}

export function encodeQrMatrix(text: string): boolean[][] {
  const bytes = new TextEncoder().encode(text);
  const spec =
    SPECS.find(([ver, , , g1B, g1D, g2B, g2D]) => 4 + (ver <= 9 ? 8 : 16) + bytes.length * 8 <= (g1B * g1D + g2B * g2D) * 8) ??
    SPECS[SPECS.length - 1];
  const codewords = encodeCodewords(bytes, spec);
  const { mod: base, fn } = drawFnPatterns(spec[0]);
  const n = base.length;

  for (let right = n - 1, bi = 0; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < n; vert++) {
      for (let j = 0; j < 2; j++) {
        const col = right - j;
        const row = ((right + 1) & 2) === 0 ? n - 1 - vert : vert;
        if (!fn[row][col] && bi < codewords.length * 8) {
          base[row][col] = ((codewords[bi >>> 3] >>> (7 - (bi & 7))) & 1) !== 0;
          bi++;
        }
      }
    }
  }

  let bestScore = Infinity;
  let best = base;
  for (let mask = 0; mask < 8; mask++) {
    const mFn = MASK_FN[mask];
    const cand = base.map((row, r) => row.map((v, c) => (fn[r][c] ? v : v !== mFn(r, c))));
    drawFormat(cand, spec[1], mask);
    const s = penalty(cand);
    if (s < bestScore) {
      bestScore = s;
      best = cand;
    }
  }
  return best;
}

export function QrSvg({ value, size = 188, quietZone = 3 }: { value: string; size?: number; quietZone?: number }) {
  const { vb, d } = useMemo(() => {
    const mat = encodeQrMatrix(value);
    const n = mat.length;
    const cmds: string[] = [];
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) if (mat[r][c]) cmds.push(`M${c + quietZone},${r + quietZone}h1v1h-1z`);
    }
    return { vb: n + quietZone * 2, d: cmds.join("") };
  }, [value, quietZone]);

  return (
    <svg width={size} height={size} viewBox={`0 0 ${vb} ${vb}`} shapeRendering="crispEdges" role="img" aria-label="Pairing QR code" className="qr-svg">
      <rect width={vb} height={vb} fill="#fff" rx="2" />
      <path d={d} fill="#111827" />
    </svg>
  );
}
