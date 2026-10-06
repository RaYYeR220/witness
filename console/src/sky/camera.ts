/** A 2D camera: world point (tx, ty) sits at screen point (ax, ay), `s` screen px per world unit. */
export interface Cam {
  tx: number;
  ty: number;
  s: number;
  ax: number;
  ay: number;
}

export const clamp = (x: number, a = 0, b = 1) => (x < a ? a : x > b ? b : x);
/** smoothstep */
export const sm = (u: number) => {
  const x = clamp(u);
  return x * x * (3 - 2 * x);
};
/** cubic in-out */
export const io = (u: number) => {
  const x = clamp(u);
  return x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2;
};

/**
 * From camera `a` to camera `b` at `e` in 0..1: the scale grows geometrically
 * while `b`'s target glides in a straight line across the screen to its final
 * spot, so a zoom of 30x reads as one steady dive instead of a lurch at the end.
 */
export function mixCam(a: Cam, b: Cam, e: number): Cam {
  if (e <= 0) return a;
  if (e >= 1) return b;
  const sx = a.ax + (b.tx - a.tx) * a.s;
  const sy = a.ay + (b.ty - a.ty) * a.s;
  return {
    tx: b.tx,
    ty: b.ty,
    s: a.s * Math.pow(b.s / a.s, e),
    ax: sx + (b.ax - sx) * e,
    ay: sy + (b.ay - sy) * e,
  };
}

export function toScreenX(c: Cam, wx: number) {
  return c.ax + (wx - c.tx) * c.s;
}
export function toScreenY(c: Cam, wy: number) {
  return c.ay + (wy - c.ty) * c.s;
}
