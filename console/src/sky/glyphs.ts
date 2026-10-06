/**
 * One small drawing per check, made from what was computed: the hash glyph is
 * the 256 bits of the BLAKE2b-256 the browser just computed, the tree is the
 * real Merkle tree shape of the milestone's cone with this block's path lit,
 * the milestone glyph carries one dot per coordinator signature in the bundle.
 */

import type { StepStatus } from "@/verify/ladder";

export interface GlyphData {
  hash: Uint8Array | null;
  leafCount: number;
  leafIndex: number;
  signatures: number;
}

const RGB = {
  fog400: "110,143,138",
  aurora: "125,240,200",
  nova: "255,90,110",
  void: "5,16,15",
};

const rgba = (c: string, a: number) => `rgba(${c},${Math.max(0, Math.min(1, a)).toFixed(3)})`;

export function bit(h: Uint8Array, k: number): number {
  return (h[k >> 3]! >> (7 - (k & 7))) & 1;
}

interface TreeNode {
  x: number;
  y: number;
  lo: number;
  hi: number;
  kids: TreeNode[];
}

/** RFC 6962 split: the largest power of two below n. */
function split(n: number) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function tree(lo: number, hi: number, depth: number, maxDepth: number, x0: number, w: number, top: number, h: number): TreeNode {
  const n = hi - lo;
  const y = top + (depth / Math.max(1, maxDepth)) * h;
  if (n <= 1) return { x: x0 + w / 2, y: top + h, lo, hi, kids: [] };
  const k = split(n);
  const left = tree(lo, lo + k, depth + 1, maxDepth, x0, (w * k) / n, top, h);
  const right = tree(lo + k, hi, depth + 1, maxDepth, x0 + (w * k) / n, (w * (n - k)) / n, top, h);
  return { x: (left.x + right.x) / 2, y, lo, hi, kids: [left, right] };
}

function treeDepth(n: number): number {
  return n <= 1 ? 0 : 1 + Math.max(treeDepth(split(n)), treeDepth(n - split(n)));
}

export function drawGlyph(
  cx: CanvasRenderingContext2D,
  k: number,
  x: number,
  y: number,
  status: StepStatus,
  alpha: number,
  data: GlyphData,
  scale = 1,
): void {
  const col = status === "pass" ? RGB.aurora : status === "fail" ? RGB.nova : RGB.fog400;
  const a = (status === "waiting" || status === "running" ? 0.45 : status === "unknown" ? 0.6 : 1) * alpha;
  const s = scale;
  cx.save();
  cx.fillStyle = rgba(RGB.void, alpha);
  cx.beginPath();
  cx.arc(x, y, 22 * s, 0, Math.PI * 2);
  cx.fill();
  cx.strokeStyle = rgba(col, a);
  cx.fillStyle = rgba(col, a);
  cx.lineWidth = 1.2;
  cx.lineCap = "round";
  cx.lineJoin = "round";

  if (status === "unknown") {
    cx.setLineDash([2, 3]);
    cx.beginPath();
    cx.arc(x, y, 8 * s, 0, Math.PI * 2);
    cx.stroke();
    cx.restore();
    return;
  }
  if (status === "fail") {
    // a ring broken in three places, crossed out
    const r = 11 * s;
    cx.lineWidth = 1.5;
    for (const [from, to] of [
      [-1.2, 0.2],
      [0.6, 2.4],
      [2.8, 4.6],
    ] as const) {
      cx.beginPath();
      cx.arc(x, y, r, from, to);
      cx.stroke();
    }
    const q = r * 0.45;
    cx.beginPath();
    cx.moveTo(x - q, y - q);
    cx.lineTo(x + q, y + q);
    cx.moveTo(x + q, y - q);
    cx.lineTo(x - q, y + q);
    cx.stroke();
    cx.restore();
    return;
  }

  if (k === 0) {
    // the computed hash, one square per set bit, 16 x 16
    const cell = 2.6 * s;
    const o = 8 * cell;
    if (data.hash) {
      for (let b = 0; b < 256; b++) {
        if (!bit(data.hash, b)) continue;
        cx.fillRect(x - o + (b % 16) * cell, y - o + Math.floor(b / 16) * cell, cell - 0.6, cell - 0.6);
      }
    }
  } else if (k === 1) {
    // the cone's Merkle tree, this block's path to the root lit
    const n = Math.max(1, data.leafCount);
    const root = tree(0, n, 0, treeDepth(n), x - 15 * s, 30 * s, y - 11 * s, 22 * s);
    const walk = (node: TreeNode) => {
      for (const kid of node.kids) {
        const on = data.leafIndex >= kid.lo && data.leafIndex < kid.hi;
        cx.strokeStyle = rgba(col, on ? a : a * 0.35);
        cx.lineWidth = on ? 1.5 : 1;
        cx.beginPath();
        cx.moveTo(node.x, node.y);
        cx.lineTo(kid.x, kid.y);
        cx.stroke();
        walk(kid);
      }
      if (!node.kids.length) {
        const on = data.leafIndex === node.lo;
        cx.fillStyle = rgba(col, on ? a : a * 0.45);
        cx.beginPath();
        cx.arc(node.x, node.y, on ? 2.4 : 1.6, 0, Math.PI * 2);
        cx.fill();
      }
    };
    walk(root);
    cx.fillStyle = rgba(col, a);
    cx.beginPath();
    cx.arc(root.x, root.y, 2.4, 0, Math.PI * 2);
    cx.fill();
  } else if (k === 2) {
    // the milestone, with one dot per coordinator signature
    const q = 9 * s;
    cx.beginPath();
    cx.moveTo(x, y - q);
    cx.lineTo(x + 2, y - 2);
    cx.lineTo(x + q, y);
    cx.lineTo(x + 2, y + 2);
    cx.lineTo(x, y + q);
    cx.lineTo(x - 2, y + 2);
    cx.lineTo(x - q, y);
    cx.lineTo(x - 2, y - 2);
    cx.closePath();
    cx.fill();
    const n = Math.max(1, data.signatures);
    for (let i = 0; i < n; i++) {
      const t = n === 1 ? 0.5 : i / (n - 1);
      const ang = Math.PI * (0.2 + 0.6 * t); // spread on an arc below the star
      cx.beginPath();
      cx.arc(x + Math.cos(ang) * 16 * s, y + Math.sin(ang) * 13 * s, 2.2, 0, Math.PI * 2);
      cx.fill();
    }
  } else if (k === 3) {
    // the sender's key
    cx.beginPath();
    cx.arc(x - 4 * s, y, 6 * s, 0, Math.PI * 2);
    cx.stroke();
    cx.beginPath();
    cx.moveTo(x + 2 * s, y);
    cx.lineTo(x + 13 * s, y);
    cx.moveTo(x + 9 * s, y);
    cx.lineTo(x + 9 * s, y + 4 * s);
    cx.moveTo(x + 13 * s, y);
    cx.lineTo(x + 13 * s, y + 4 * s);
    cx.stroke();
  } else {
    // the public anchor: a star above the horizon
    cx.beginPath();
    cx.moveTo(x - 16 * s, y + 7 * s);
    cx.lineTo(x + 16 * s, y + 7 * s);
    cx.stroke();
    const z = 6 * s;
    const cy = y - 3 * s;
    cx.beginPath();
    cx.moveTo(x, cy - z);
    cx.lineTo(x + 1.6, cy - 1.6);
    cx.lineTo(x + z, cy);
    cx.lineTo(x + 1.6, cy + 1.6);
    cx.lineTo(x, cy + z);
    cx.lineTo(x - 1.6, cy + 1.6);
    cx.lineTo(x - z, cy);
    cx.lineTo(x - 1.6, cy - 1.6);
    cx.closePath();
    cx.fill();
  }
  cx.restore();
}
