/**
 * The one sky engine behind the landing page. It draws the same model and the
 * same interaction state (hover, your trace, the lantern under the cursor) at
 * every depth of the descent: the hero framing, the whole network, milestone
 * 374, one star, its raw bytes and the five checks climbing back up.
 *
 * Everything is a function of the scroll progress `p` plus the interaction
 * state; this file holds no verdicts. Check statuses are passed in from the
 * ladder state the library filled.
 */

import type { StepStatus } from "@/verify/ladder";
import { shortHex } from "@/verify/sample";

import { clamp, io, mixCam, sm, type Cam } from "./camera";
import { drawGlyph, type GlyphData } from "./glyphs";
import { mulberry32, type SkyModel } from "./model";

export interface Box {
  x0: number;
  y0: number;
  x1: number;
  y1: number;
}

export interface StageLayout {
  w: number;
  h: number;
  mobile: boolean;
  /** Where the hero places the sky, in stage px. */
  heroSky: { cx: number; cy: number; width: number };
  /** Hero text boxes; stars behind them are dimmed. */
  clear: Box[];
  /** First mark of the hero ladder, where the plumb line lands. */
  ladderAnchor: { x: number; y: number } | null;
  contentLeft: number;
}

export interface Trace {
  star: number;
  path: number[];
  start: number;
  /** The trust message being traced, if it is one. */
  which: "sample" | "forged" | null;
}

export interface Subject {
  star: number;
  bytes: Uint8Array;
  glyph: GlyphData;
  statuses: StepStatus[];
}

export interface FrameInput {
  p: number;
  /** Seconds, for the twinkle. */
  t: number;
  now: number;
  still: boolean;
  pointer: { x: number; y: number; on: boolean };
  hover: number;
  trace: Trace | null;
  subject: Subject;
  /** Stars whose verdict the library has computed: star index -> failed. */
  verdicts: Map<number, boolean>;
  /** Labels for the milestone view, by star. */
  label: (star: number) => string;
}

export interface FrameOutput {
  /** Hops of the trace drawn so far. */
  traceHops: number;
  /** 0..1 of the plumb line from the milestone into the hero ladder. */
  plumb: number;
}

/** Where the five checks light as you scroll. */
export const THRESHOLDS = [0.665, 0.725, 0.785, 0.845, 0.905] as const;
export const HOP_MS = 170;
const PLUMB_MS = 520;

const C = {
  fog50: "238,246,243",
  fog200: "183,205,200",
  fog400: "110,143,138",
  ember: "242,163,94",
  aurora: "125,240,200",
  nova: "255,90,110",
};
const rgba = (c: string, a: number) => `rgba(${c},${clamp(a).toFixed(3)})`;

function sprite(rgb: string): HTMLCanvasElement {
  const c = document.createElement("canvas");
  const s = 64;
  c.width = c.height = s;
  const g = c.getContext("2d")!;
  const gr = g.createRadialGradient(s / 2, s / 2, 0, s / 2, s / 2, s / 2);
  gr.addColorStop(0, `rgba(${rgb},1)`);
  gr.addColorStop(0.09, `rgba(${rgb},.95)`);
  gr.addColorStop(0.17, `rgba(${rgb},.3)`);
  gr.addColorStop(0.42, `rgba(${rgb},.05)`);
  gr.addColorStop(1, `rgba(${rgb},0)`);
  g.fillStyle = gr;
  g.fillRect(0, 0, s, s);
  return c;
}

export class Scene {
  readonly model: SkyModel;
  /** Screen positions and visibility of every star in the last frame. */
  readonly px: Float32Array;
  readonly py: Float32Array;
  readonly vis: Float32Array;
  private sprites: Record<"fog" | "ember" | "nova", HTMLCanvasElement> | null = null;
  private layout: StageLayout | null = null;
  private cams: { hero: Cam; net: Cam; B: Cam; C: Cam } | null = null;
  private subjectStar = -1;
  private par = { x: 0, y: 0 };
  private jitter: Float32Array;
  private clearMask: Float32Array;

  constructor(model: SkyModel) {
    this.model = model;
    const n = model.stars.length;
    this.px = new Float32Array(n);
    this.py = new Float32Array(n);
    this.vis = new Float32Array(n);
    this.clearMask = new Float32Array(n).fill(1);
    const r = mulberry32(0x435be807);
    this.jitter = new Float32Array(1024 * 3);
    for (let k = 0; k < 1024; k++) {
      const ang = r() * Math.PI * 2;
      const rr = Math.sqrt(r());
      this.jitter[3 * k] = Math.cos(ang) * rr;
      this.jitter[3 * k + 1] = Math.sin(ang) * rr;
      this.jitter[3 * k + 2] = r();
    }
  }

  get stageLayout() {
    return this.layout;
  }

  /** Recompute the cameras for a new stage size, hero placement or descent subject. */
  setLayout(layout: StageLayout, subjectStar: number): void {
    this.layout = layout;
    this.subjectStar = subjectStar;
    const { w, h, mobile, heroSky } = layout;
    const stars = this.model.stars;
    const hero: Cam = { tx: 0, ty: 0, s: heroSky.width / (mobile ? 2.0 : 2.08), ax: heroSky.cx, ay: heroSky.cy };
    const net: Cam = mobile
      ? { tx: 0, ty: 0, s: (w * 0.98) / 1.8, ax: w * 0.5, ay: h * 0.36 }
      : { tx: 0, ty: 0, s: Math.min((w * 0.6) / 1.8, (h * 0.75) / 0.8), ax: layout.contentLeft + (w - 2 * layout.contentLeft) * 0.62, ay: h * 0.5 };
    // milestone 374's window: its cone, both milestone stars and the forged twin
    const win = stars.slice(0, this.model.realCount).filter((s) => s.window === 374);
    const xs = win.map((s) => s.wx);
    const ys = win.map((s) => s.wy);
    const x0 = Math.min(...xs);
    const x1 = Math.max(...xs);
    const y0 = Math.min(...ys);
    const y1 = Math.max(...ys);
    const bw = Math.max(x1 - x0, (y1 - y0) * 1.2) + 0.06;
    const anchorX = mobile ? w * 0.5 : layout.contentLeft + (w - 2 * layout.contentLeft) * 0.66;
    const anchorY = mobile ? h * 0.34 : h * 0.5;
    const B: Cam = { tx: (x0 + x1) / 2, ty: (y0 + y1) / 2, s: (mobile ? w * 0.42 : Math.min(w * 0.3, 420)) / bw, ax: anchorX, ay: anchorY };
    const sub = stars[subjectStar]!;
    const Cc: Cam = { tx: sub.wx, ty: sub.wy, s: B.s * (mobile ? 20 : 26), ax: anchorX, ay: anchorY };
    this.cams = { hero, net, B, C: Cc };
    // stars that sit behind the hero text are dimmed so the claim stays legible
    for (let i = 0; i < stars.length; i++) this.clearMask[i] = 1;
  }

  camAt(p: number): Cam {
    const c = this.cams!;
    if (p <= 0.04) return c.hero;
    if (p < 0.14) return mixCam(c.hero, c.net, io((p - 0.04) / 0.1));
    if (p < 0.3) return mixCam(c.net, c.B, io((p - 0.14) / 0.16));
    if (p < 0.36) return c.B;
    if (p < 0.47) return mixCam(c.B, c.C, io((p - 0.36) / 0.11));
    return c.C;
  }

  /** Opacities of the layers at progress p. */
  static factors(p: number) {
    return {
      hero: 1 - sm((p - 0.03) / 0.06),
      focus: sm((p - 0.16) / 0.1) * (1 - sm((p - 0.38) / 0.06)),
      into: sm((p - 0.37) / 0.09),
      sky: 1 - sm((p - 0.45) / 0.05),
      morph: clamp((p - 0.47) / 0.065),
      hex: sm((p - 0.54) / 0.02) * (1 - sm((p - 0.588) / 0.02)),
      shrink: io((p - 0.6) / 0.06),
      ascent: sm((p - 0.62) / 0.04),
    };
  }

  /** Geometry of the five checks (and the byte grids) for the current layout. */
  column() {
    const L = this.layout!;
    const { w, h, mobile } = L;
    const x = mobile ? 36 : Math.min(L.contentLeft + 560, w * 0.55);
    const ys = [0, 1, 2, 3, 4].map((k) => (mobile ? h * (0.5 - k * 0.083) : h * (0.74 - k * 0.125)));
    const cols = mobile ? 16 : 32;
    const n = this.model.stars[this.subjectStar]?.raw?.length ?? 448;
    const rows = Math.ceil(n / cols);
    const cell = mobile ? Math.min(16, Math.floor((w - 40) / 16)) : 17;
    const c = this.cams!.C;
    const big = { cols, cell, x: c.ax - (cols * cell) / 2, y: c.ay - (rows * cell) / 2 };
    const sc = mobile ? 3 : 5;
    const small = { cols, cell: sc, x: x - (cols * sc) / 2, y: ys[0]! + (mobile ? 30 : 50) };
    return { x, ys, big, small };
  }

  /** Nearest real, visible star within r px of (x, y), or -1. */
  hit(x: number, y: number, r: number): number {
    let best = -1;
    let bd = r * r;
    for (let i = 0; i < this.model.realCount; i++) {
      if (this.vis[i]! < 0.25) continue;
      const dx = this.px[i]! - x;
      const dy = this.py[i]! - y;
      const d = dx * dx + dy * dy;
      if (d < bd) {
        bd = d;
        best = i;
      }
    }
    return best;
  }

  draw(cx: CanvasRenderingContext2D, f: FrameInput): FrameOutput {
    const L = this.layout;
    const out: FrameOutput = { traceHops: 0, plumb: 0 };
    if (!L || !this.cams) return out;
    if (!this.sprites) this.sprites = { fog: sprite(C.fog50), ember: sprite(C.ember), nova: sprite(C.nova) };
    const SP = this.sprites;
    const { w, h } = L;
    const p = f.p;
    const F = Scene.factors(p);
    const cam = this.camAt(p);
    const stars = this.model.stars;
    const N = stars.length;
    cx.clearRect(0, 0, w, h);

    // ---- parallax and the lantern under your cursor
    if (!f.still) {
      let tx = 0;
      let ty = 0;
      if (f.pointer.on) {
        tx = -(f.pointer.x - w / 2) * 0.012;
        ty = -(f.pointer.y - h / 2) * 0.01;
      } else {
        tx = Math.sin(f.t * 0.07) * 5;
        ty = Math.cos(f.t * 0.05) * 3;
      }
      this.par.x += (tx - this.par.x) * 0.05;
      this.par.y += (ty - this.par.y) * 0.05;
    }
    const parK = 1 - F.focus;
    const lanternR = L.mobile ? 110 : 170;
    const lantern = f.pointer.on && F.sky > 0.05;
    const zoom = Math.max(1, Math.sqrt(cam.s / this.cams.hero.s) * 0.55);

    for (let i = 0; i < N; i++) {
      const s = stars[i]!;
      let x = cam.ax + (s.wx - cam.tx) * cam.s + this.par.x * s.z * parK;
      let y = cam.ay + (s.wy - cam.ty) * cam.s + this.par.y * s.z * parK;
      if (lantern && !f.still) {
        const dx = f.pointer.x - x;
        const dy = f.pointer.y - y;
        const d2 = dx * dx + dy * dy;
        if (d2 < lanternR * lanternR) {
          const d = Math.sqrt(d2) || 1;
          const pull = Math.pow(1 - d / lanternR, 2) * 7 * s.z;
          x += (dx / d) * pull;
          y += (dy / d) * pull;
        }
      }
      this.px[i] = x;
      this.py[i] = y;
    }

    // ---- hero text keeps clear of stars (fades out as the hero does)
    const clearK = F.hero;
    if (clearK > 0.01 && L.clear.length) {
      for (let i = 0; i < N; i++) {
        let m = 1;
        for (const b of L.clear) {
          const dx = Math.max(b.x0 - this.px[i]!, 0, this.px[i]! - b.x1);
          const dy = Math.max(b.y0 - this.py[i]!, 0, this.py[i]! - b.y1);
          m = Math.min(m, 0.12 + 0.88 * Math.min(1, Math.hypot(dx, dy) / 40));
        }
        this.clearMask[i] = 1 - (1 - m) * clearK;
      }
    } else this.clearMask.fill(1);

    // ---- the trace: approvals from the star you picked to its milestone
    const lit = new Set<number>();
    let traceHead: [number, number] | null = null;
    const traceA = F.sky * (1 - F.into);
    if (f.trace && traceA > 0.02) {
      const tr = f.trace;
      const hops = tr.path.length - 1;
      const prog = f.still ? hops + 10 : (f.now - tr.start) / HOP_MS;
      out.traceHops = Math.min(hops, prog);
      lit.add(tr.path[0]!);
      cx.save();
      cx.lineCap = "round";
      cx.lineJoin = "round";
      cx.strokeStyle = rgba(C.ember, 0.9 * traceA);
      cx.lineWidth = 1.3;
      cx.beginPath();
      cx.moveTo(this.px[tr.path[0]!]!, this.py[tr.path[0]!]!);
      for (let k = 0; k < hops; k++) {
        const a = tr.path[k]!;
        const b = tr.path[k + 1]!;
        const u = clamp(prog - k);
        if (u <= 0) break;
        cx.lineTo(this.px[a]! + (this.px[b]! - this.px[a]!) * u, this.py[a]! + (this.py[b]! - this.py[a]!) * u);
        if (u >= 1) lit.add(b);
      }
      cx.stroke();
      cx.restore();
      if (prog < hops) {
        const k = Math.floor(prog);
        const u = prog - k;
        const a = tr.path[k]!;
        const b = tr.path[k + 1]!;
        traceHead = [this.px[a]! + (this.px[b]! - this.px[a]!) * u, this.py[a]! + (this.py[b]! - this.py[a]!) * u];
      }
      // from the milestone, a plumb line down into the hero ladder (trust messages only)
      if (tr.which && prog >= hops) {
        const u = f.still ? 1 : clamp(((prog - hops) * HOP_MS) / PLUMB_MS);
        out.plumb = u;
        const an = L.ladderAnchor;
        if (an && F.hero > 0.02) {
          const m = tr.path[hops]!;
          const sx = this.px[m]!;
          const sy = this.py[m]! + 10;
          const ex = an.x;
          const ey = an.y - 6;
          const c1x = sx;
          const c1y = sy + (ey - sy) * 0.55;
          const c2x = ex;
          const c2y = ey - (ey - sy) * 0.45;
          cx.save();
          cx.strokeStyle = rgba(C.ember, 0.55 * F.hero);
          cx.lineWidth = 1;
          cx.setLineDash([2, 5]);
          cx.beginPath();
          const steps = 48;
          const upto = Math.round(steps * u);
          for (let k = 0; k <= upto; k++) {
            const v = k / steps;
            const iv = 1 - v;
            const x = iv * iv * iv * sx + 3 * iv * iv * v * c1x + 3 * iv * v * v * c2x + v * v * v * ex;
            const y = iv * iv * iv * sy + 3 * iv * iv * v * c1y + 3 * iv * v * v * c2y + v * v * v * ey;
            if (k === 0) cx.moveTo(x, y);
            else cx.lineTo(x, y);
          }
          cx.stroke();
          cx.restore();
        }
      }
    }

    if (F.sky > 0.01) {
      // ---- edges: only the real approvals, whisper-faint, legible in your light and in focus
      cx.lineWidth = 1;
      const window374 = (i: number) => stars[i]!.window === 374;
      cx.strokeStyle = rgba(C.fog200, (0.085 - 0.05 * F.focus) * F.sky * (1 - F.into));
      cx.beginPath();
      for (const [a, b] of this.model.edges) {
        cx.moveTo(this.px[a]!, this.py[a]!);
        cx.lineTo(this.px[b]!, this.py[b]!);
      }
      cx.stroke();
      if (F.focus > 0.01) {
        cx.strokeStyle = rgba(C.fog200, 0.42 * F.focus * F.sky * (1 - F.into));
        cx.beginPath();
        for (const [a, b] of this.model.edges) {
          if (!window374(a)) continue;
          cx.moveTo(this.px[a]!, this.py[a]!);
          cx.lineTo(this.px[b]!, this.py[b]!);
        }
        cx.stroke();
      }
      if (lantern) {
        for (const [a, b] of this.model.edges) {
          const da = Math.hypot(this.px[a]! - f.pointer.x, this.py[a]! - f.pointer.y);
          const db = Math.hypot(this.px[b]! - f.pointer.x, this.py[b]! - f.pointer.y);
          const al = Math.max(0, 1 - Math.max(da, db) / (lanternR * 1.35));
          if (al <= 0) continue;
          cx.strokeStyle = rgba(C.fog200, al * 0.5 * F.sky);
          cx.beginPath();
          cx.moveTo(this.px[a]!, this.py[a]!);
          cx.lineTo(this.px[b]!, this.py[b]!);
          cx.stroke();
        }
      }

      // ---- stars
      for (let i = 0; i < N; i++) {
        const s = stars[i]!;
        const x = this.px[i]!;
        const y = this.py[i]!;
        if (x < -40 || x > w + 40 || y < -40 || y > h + 40) {
          this.vis[i] = 0;
          continue;
        }
        let a: number;
        let sz: number;
        let spr = SP.fog;
        const tw = f.still ? 0.6 : 0.5 + 0.5 * Math.sin(f.t * (0.6 + s.tw * 1.2) + s.tw * 40);
        if (!s.real) {
          if (s.dust) {
            a = (0.1 + 0.3 * s.z) * (0.7 + 0.3 * tw);
            sz = 2 + 2.2 * s.z;
          } else {
            a = (0.18 + 0.46 * s.z) * (0.7 + 0.3 * tw) * (1 - sm((Math.abs(s.wx) - 1.0) / 0.3));
            sz = 3 + 5.5 * s.z;
          }
          a *= 1 - 0.85 * F.focus;
        } else {
          a = s.kind === "milestone" ? 0.95 : 0.74 + 0.26 * s.z;
          sz = (6 + Math.sqrt(s.approvers.length) * 3.4) * zoom;
          if (s.kind === "milestone") sz = 12 * zoom;
          if (s.role) {
            a = 1;
            sz = 13 * zoom;
          }
          if (f.verdicts.get(i) === true) spr = SP.nova;
          if (F.focus > 0 && s.window !== 374) a *= 1 - 0.7 * F.focus;
        }
        if (i === this.subjectStar) sz *= 1 + F.into * 1.6;
        else a *= 1 - F.into;
        a *= F.sky * this.clearMask[i]!;
        if (lantern) {
          const dm = Math.hypot(x - f.pointer.x, y - f.pointer.y);
          if (dm < lanternR) {
            const b = 1 - dm / lanternR;
            a = Math.min(1, a + (s.real ? 0.45 : 0.4 * s.z) * b * F.sky);
            sz *= 1 + 0.35 * b;
          }
        }
        if (lit.has(i) && !(i === this.subjectStar && F.into > 0.3)) {
          spr = f.verdicts.get(i) === true ? SP.nova : SP.ember;
          a = Math.max(a, traceA);
          sz *= 1.25;
        }
        if (i === f.hover) {
          a = Math.max(a, F.sky);
          sz *= 1.3;
        }
        this.vis[i] = a;
        if (a <= 0.01) continue;
        cx.globalAlpha = clamp(a);
        cx.drawImage(spr, x - sz, y - sz, sz * 2, sz * 2);
        if (s.kind === "milestone") {
          const arm = (s.msIndex === 374 ? 9 : 7) * zoom;
          cx.globalAlpha = clamp(0.6 * a);
          cx.strokeStyle = "#EEF6F3"; // milestones are never painted as failed: only the forged block is
          cx.lineWidth = 0.8;
          cx.beginPath();
          cx.moveTo(x - arm, y);
          cx.lineTo(x + arm, y);
          cx.moveTo(x, y - arm);
          cx.lineTo(x, y + arm);
          cx.stroke();
        }
      }
      cx.globalAlpha = 1;
      if (traceHead) cx.drawImage(SP.ember, traceHead[0] - 12, traceHead[1] - 12, 24, 24);

      // ---- rings and labels
      if (f.trace) {
        const tr = f.trace;
        const a = tr.path[0]!;
        cx.strokeStyle = rgba(f.verdicts.get(a) ? C.nova : C.ember, 0.85 * F.sky * (1 - F.focus));
        cx.lineWidth = 1;
        cx.beginPath();
        cx.arc(this.px[a]!, this.py[a]!, 8, 0, Math.PI * 2);
        cx.stroke();
        if (f.hover < 0 && F.focus < 0.2 && F.hero > 0.5) this.traceLabels(cx, tr, f, F.hero);
      }
      if (f.hover >= 0) {
        cx.strokeStyle = rgba(C.fog50, 0.55 * F.sky);
        cx.lineWidth = 1;
        cx.beginPath();
        cx.arc(this.px[f.hover]!, this.py[f.hover]!, 8, 0, Math.PI * 2);
        cx.stroke();
      }
      const la = F.focus * F.sky * (1 - F.into);
      if (la > 0.02) this.windowLabels(cx, f, la);
    } else this.vis.fill(0);

    // ---- the subject star opens into its bytes
    const sx = this.px[this.subjectStar] ?? w / 2;
    const sy = this.py[this.subjectStar] ?? h / 2;
    if (F.into > 0 && F.morph < 1) {
      const disc = (L.mobile ? w * 0.42 : h * 0.36) * F.into + 2;
      const gr = cx.createRadialGradient(sx, sy, 0, sx, sy, disc);
      gr.addColorStop(0, rgba(C.fog50, 0.16 * (1 - F.morph)));
      gr.addColorStop(0.7, rgba(C.fog50, 0.05 * (1 - F.morph)));
      gr.addColorStop(1, rgba(C.fog50, 0));
      cx.fillStyle = gr;
      cx.beginPath();
      cx.arc(sx, sy, disc, 0, Math.PI * 2);
      cx.fill();
      cx.strokeStyle = rgba(C.fog50, 0.3 * F.into * Math.max(0, 1 - F.morph * 2.5));
      cx.lineWidth = 1;
      cx.beginPath();
      cx.arc(sx, sy, disc, 0, Math.PI * 2);
      cx.stroke();
    }
    if (F.morph > 0) this.drawBytes(cx, f, F, sx, sy);
    if (F.ascent > 0) this.drawColumn(cx, f, F.ascent, p);
    return out;
  }

  private traceLabels(cx: CanvasRenderingContext2D, tr: Trace, f: FrameInput, alpha: number) {
    const a = tr.path[0]!;
    const m = tr.path[tr.path.length - 1]!;
    const s = this.model.stars[a]!;
    cx.save();
    cx.textBaseline = "middle";
    cx.font = "400 11px 'Spline Sans Mono', ui-monospace, monospace";
    cx.fillStyle = rgba(C.fog50, 0.82 * alpha);
    cx.textAlign = "right";
    if (s.id) cx.fillText(shortHex(s.id), this.px[a]! - 14, this.py[a]!);
    if (m !== a) {
      cx.font = "400 12px 'Schibsted Grotesk', system-ui, sans-serif";
      cx.fillStyle = rgba(C.fog200, 0.85 * alpha);
      const text = f.label(m);
      const fits = this.px[m]! + 16 + cx.measureText(text).width < (this.layout?.w ?? 0) - 8;
      cx.textAlign = fits ? "left" : "center";
      if (fits) cx.fillText(text, this.px[m]! + 16, this.py[m]! - 1);
      else cx.fillText(text, this.px[m]!, this.py[m]! - 20);
    }
    cx.restore();
  }

  private windowLabels(cx: CanvasRenderingContext2D, f: FrameInput, la: number) {
    const stars = this.model.stars;
    const order: number[] = [];
    for (let i = 0; i < this.model.realCount; i++) if (stars[i]!.window === 374) order.push(i);
    order.sort((a, b) => this.py[a]! - this.py[b]!);
    const placed: Box[] = [];
    cx.save();
    cx.textBaseline = "middle";
    cx.textAlign = "left";
    for (const i of order) {
      const s = stars[i]!;
      const isMs = s.kind === "milestone";
      const text = f.label(i);
      cx.font = isMs ? "400 13px 'Schibsted Grotesk', system-ui, sans-serif" : "400 11px 'Spline Sans Mono', ui-monospace, monospace";
      const tw = cx.measureText(text).width;
      const right = this.px[i]! + 15 + tw < this.layout!.w - 10;
      const lx = right ? this.px[i]! + 15 : this.px[i]! - 15 - tw;
      let ly = this.py[i]!;
      for (const dy of [0, 15, -15, 30, -30]) {
        const yy = this.py[i]! + dy;
        if (!placed.some((b) => lx < b.x1 && lx + tw > b.x0 && yy - 8 < b.y1 && yy + 8 > b.y0)) {
          ly = yy;
          break;
        }
      }
      placed.push({ x0: lx, y0: ly - 8, x1: lx + tw, y1: ly + 8 });
      const failed = f.verdicts.get(i) === true;
      const strong = i === this.subjectStar;
      cx.fillStyle = rgba(failed ? C.nova : strong ? C.fog50 : C.fog200, la * (strong ? 1 : 0.78));
      cx.fillText(text, lx, ly);
    }
    const sub = this.subjectStar;
    cx.strokeStyle = rgba(C.ember, 0.85 * la);
    cx.lineWidth = 1;
    cx.beginPath();
    cx.arc(this.px[sub]!, this.py[sub]!, 10, 0, Math.PI * 2);
    cx.stroke();
    cx.restore();
  }

  private drawBytes(cx: CanvasRenderingContext2D, f: FrameInput, F: ReturnType<typeof Scene.factors>, sx: number, sy: number) {
    const L = this.layout!;
    const { big, small } = this.column();
    const B = f.subject.bytes;
    const discR = L.mobile ? L.w * 0.4 : L.h * 0.34;
    cx.save();
    cx.textAlign = "center";
    cx.textBaseline = "middle";
    cx.font = `400 ${L.mobile ? 9 : 10.5}px 'Spline Sans Mono', ui-monospace, monospace`;
    for (let i = 0; i < B.length; i++) {
      const c = i % big.cols;
      const r = Math.floor(i / big.cols);
      const j = (i % 1024) * 3;
      const gx = big.x + c * big.cell + big.cell / 2;
      const gy = big.y + r * big.cell + big.cell / 2;
      const tx = small.x + c * small.cell + small.cell / 2;
      const ty = small.y + r * small.cell + small.cell / 2;
      const u = io(clamp(F.morph * 1.5 - this.jitter[j + 2]! * 0.5));
      const x0 = sx + this.jitter[j]! * discR;
      const y0 = sy + this.jitter[j + 1]! * discR;
      let x = x0 + (gx - x0) * u;
      let y = y0 + (gy - y0) * u;
      x += (tx - x) * F.shrink;
      y += (ty - y) * F.shrink;
      const v = B[i]!;
      const dotA = (0.35 + 0.65 * (v / 255)) * (1 - F.hex) * (1 - F.shrink * 0.35);
      const rad = (0.8 + Math.sqrt(v / 255) * (big.cell * 0.28)) * (1 - F.shrink) + (0.5 + Math.sqrt(v / 255) * 1.3) * F.shrink;
      if (dotA > 0.01) {
        cx.fillStyle = rgba(C.fog50, dotA);
        cx.beginPath();
        cx.arc(x, y, rad, 0, Math.PI * 2);
        cx.fill();
      }
      if (F.hex > 0.01) {
        cx.fillStyle = rgba(C.fog200, F.hex * (0.45 + 0.55 * (v / 255)));
        cx.fillText((v < 16 ? "0" : "") + v.toString(16), x, y);
      }
    }
    cx.restore();
  }

  private drawColumn(cx: CanvasRenderingContext2D, f: FrameInput, alpha: number, p: number) {
    const { x, ys, small } = this.column();
    const st = f.subject.statuses;
    let lit = 0;
    for (let k = 0; k < 5; k++) if (p >= THRESHOLDS[k]!) lit = k + 1;
    const base = small.y - 8;
    const grow = clamp((p - 0.63) / (THRESHOLDS[4] - 0.63)) * 5;
    // the thread climbs while checks pass; it stops under the first one that did not
    let stop = 5;
    for (let k = 0; k < 5; k++)
      if (st[k] !== "pass") {
        stop = k;
        break;
      }
    cx.save();
    cx.lineWidth = 1;
    cx.strokeStyle = rgba(C.fog400, 0.35 * alpha);
    cx.beginPath();
    cx.moveTo(x, base);
    cx.lineTo(x, ys[4]!);
    cx.stroke();
    const reach = Math.min(grow, stop);
    const fl = Math.floor(reach);
    let yTop: number;
    if (reach <= 0) yTop = base;
    else if (fl >= 4) yTop = ys[4]!;
    else yTop = ys[fl]! - (ys[fl]! - ys[fl + 1]!) * (reach - fl);
    if (grow > 0 && stop > 0) {
      cx.strokeStyle = rgba(C.aurora, 0.9 * alpha);
      cx.lineWidth = 1.4;
      cx.beginPath();
      cx.moveTo(x, base);
      cx.lineTo(x, Math.max(ys[4]!, yTop));
      cx.stroke();
    }
    cx.restore();
    const scale = this.layout!.mobile ? 0.72 : 1;
    for (let k = 0; k < 5; k++) drawGlyph(cx, k, x, ys[k]!, k < lit ? st[k]! : "waiting", alpha, f.subject.glyph, scale);
  }
}
