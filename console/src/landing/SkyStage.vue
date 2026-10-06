<script setup lang="ts">
/**
 * Hero and descent in one stage. The hero frames the sky next to the claim;
 * scrolling flies the same camera into the network, milestone 374, one star,
 * its raw bytes, and back up the five checks. One engine, one state: what you
 * hover or trace in the hero is what the descent shows.
 */
import { blake2b256 } from "@witness/verify";
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from "vue";

import StepList from "@/components/StepList.vue";
import { clamp } from "@/sky/camera";
import { buildSky, milestoneFacts, pathToMilestone, type SkyModel } from "@/sky/model";
import { Scene, THRESHOLDS, type Box, type FrameInput, type Subject, type Trace } from "@/sky/scene";
import { useVerificationStore } from "@/stores/verification";
import { stepNote, stepValue, type StepStatus } from "@/verify/ladder";
import { shortHex, type Which } from "@/verify/sample";

import { bundleFacts, glosses } from "./facts";

const props = defineProps<{ still: boolean }>();
const emit = defineEmits<{ verify: [] }>();

const store = useVerificationStore();
const facts = { sample: bundleFacts("sample"), forged: bundleFacts("forged") };
const gloss = { sample: glosses(facts.sample), forged: glosses(facts.forged) };

const section = ref<HTMLElement | null>(null);
const stage = ref<HTMLElement | null>(null);
const canvas = ref<HTMLCanvasElement | null>(null);
const annot = ref<HTMLElement | null>(null);
const skySlot = ref<HTMLElement | null>(null);
const grid = ref<HTMLElement | null>(null);
const h1El = ref<HTMLElement | null>(null);
const subEl = ref<HTMLElement | null>(null);
const actEl = ref<HTMLElement | null>(null);
const hintEl = ref<HTMLElement | null>(null);
const ladder = ref<InstanceType<typeof StepList> | null>(null);
const stillCanvas = ref<HTMLCanvasElement | null>(null);
const stillStage = ref<HTMLElement | null>(null);

const mq = typeof matchMedia === "function" ? matchMedia("(max-width: 760px)") : null;
const mobile = ref(mq?.matches ?? false);
let model: SkyModel = buildSky({ mobile: mobile.value });
let scene = new Scene(model);
const realCount = model.realCount;

// ---------------------------------------------------------------- reactive view state
const p = ref(0);
const hoverNote = reactive({ show: false, id: "", text: "", left: false });
const plainNote = ref("");
const plainSubject = ref<{ id: string; kind: string } | null>(null);
const column = ref<{ x: number; ys: number[] } | null>(null);

const factors = computed(() => Scene.factors(p.value));
const subject = computed<Which>(() => store.subject);
const sf = computed(() => facts[subject.value]);
const subjectLadder = computed(() => store.results[subject.value]);

function msLabel(index: number, which: Which | "shared") {
  return which === "forged" ? `milestone ${index}, twin bundle` : `milestone ${index}`;
}

const captions = computed(() => {
  const f = sf.value;
  const r = subjectLadder.value;
  const failed = r.failedAt;
  const failedStep = failed ? r.steps[failed - 1] : null;
  return [
    {
      from: 0.09,
      to: 0.17,
      h: "A private IOTA Tangle",
      p: `The bright stars are the sample: ${realCount} blocks and milestones, 370 to ${f.msIndex}, with their real approvals. The faint ones are scenery.`,
    },
    {
      from: 0.17,
      to: 0.355,
      h: `Milestone ${f.msIndex}`,
      p: `${f.signatures} coordinators signed it. It confirmed ${f.leafCount} blocks and committed to ${f.leafCount === 2 ? "both" : "all of them"} in one Merkle root.`,
    },
    {
      from: 0.355,
      to: 0.475,
      h: "One block, one trust score",
      p: `${f.scoreText ?? "?"} for ${f.entity ?? "an aeriOS entity"}, in an envelope that names ${f.issuer ?? "its issuer"} as the signer.`,
    },
    {
      from: 0.475,
      to: 0.605,
      h: `${f.bytes} bytes`,
      p: `Everything the proof rests on: ${f.parents} parents, the tagged payload with the signed envelope, a nonce.`,
    },
    {
      from: 0.605,
      to: 0.955,
      h: "Five checks, back up to a public anchor",
      p: "Each one runs in your browser. None of them asks the dashboard.",
    },
    {
      from: 0.955,
      to: 1.01,
      h: r.overall === "VALID" ? "Verified." : r.overall === "INVALID" ? (subject.value === "forged" ? "Forged." : "Broken.") : "Checking.",
      p:
        r.overall === "VALID"
          ? `All five checks passed in your browser, ${Math.max(1, Math.round(r.computeMs ?? 0))} ms.`
          : failedStep
            ? `Check ${failed}, ${failedStep.title.toLowerCase()}, failed in your browser: ${stepNote(failedStep.detail)}.`
            : "",
      end: true,
      bad: r.overall === "INVALID",
    },
  ];
});

const trail = computed(() => [
  { label: "Tangle", at: 0.12, from: 0 },
  { label: `Milestone ${sf.value.msIndex}`, at: 0.27, from: 0.2 },
  { label: "Block", mono: shortHex(sf.value.id), at: 0.42, from: 0.37 },
  { label: "Bytes", at: 0.55, from: 0.5 },
  { label: "Five checks", at: 0.93, from: 0.63 },
]);
const depth = computed(() => {
  let here = 0;
  trail.value.forEach((t, k) => {
    if (p.value >= t.from) here = k;
  });
  return here;
});

const ascentRows = computed(() =>
  subjectLadder.value.steps.map((s, k) => {
    const shown = props.still || p.value >= THRESHOLDS[k]!;
    const status: StepStatus = shown ? s.status : "waiting";
    return {
      key: s.name,
      n: s.n,
      title: s.title,
      status,
      value: shown ? stepValue(s) : "",
      gloss: status === "fail" || status === "unknown" ? stepNote(s.detail) : gloss[subject.value][k],
    };
  }),
);

// ---------------------------------------------------------------- hero ladder copy
const heroFacts = computed(() => (store.heroSubject ? facts[store.heroSubject] : null));
const heroVerdict = computed(() => {
  const h = store.hero;
  if (!store.heroSubject) return plainNote.value ? { bad: false, b: "", t: plainNote.value } : null;
  if (h.overall === "VALID") return { bad: false, b: "Verified.", t: `All five checks passed in your browser, ${Math.max(1, Math.round(h.computeMs ?? 0))} ms.` };
  if (h.overall === "INVALID") {
    const st = h.failedAt ? h.steps[h.failedAt - 1] : null;
    if (store.heroSubject === "forged" && h.failedAt === 4)
      return { bad: true, b: "Forged.", t: `It is on the ledger, but the sender signature does not check out against ${facts.forged.kid}.` };
    return { bad: true, b: `Broken at check ${h.failedAt}.`, t: stepNote(st?.detail ?? "") };
  }
  if (h.overall === "PARTIAL") return { bad: false, b: "Partly checked.", t: "Some checks could not be evaluated." };
  if (h.running) return { bad: false, b: "", t: "Checking in your browser…" };
  return null;
});

// ---------------------------------------------------------------- interaction state
const pointer = { x: -1e4, y: -1e4, on: false };
let hover = -1;
let keyStar = -1;
let trace: Trace | null = null;
let plumbFired = false;
let raf = 0;
const t0 = performance.now();
let onScreen = true;
let dpr = 1;
let sectionTop = 0;

const subjectStar = () => (subject.value === "forged" ? model.forged : model.sample);

function verdicts(): Map<number, boolean> {
  const m = new Map<number, boolean>();
  for (const w of ["sample", "forged"] as const) {
    const r = store.results[w];
    if (r.overall) m.set(w === "forged" ? model.forged : model.sample, r.overall === "INVALID");
  }
  return m;
}

function subjectInput(): Subject {
  const star = model.stars[subjectStar()]!;
  const bytes = star.raw ?? new Uint8Array(0);
  const f = sf.value;
  return {
    star: star.i,
    bytes,
    glyph: { hash: bytes.length ? blake2b256(bytes) : null, leafCount: f.leafCount, leafIndex: f.leafIndex, signatures: f.signatures },
    statuses: subjectLadder.value.steps.map((s) => s.status),
  };
}
let subjectCache: Subject | null = null;
watch(
  () => [subject.value, subjectLadder.value.overall],
  () => {
    subjectCache = null;
  },
);

function label(i: number): string {
  const s = model.stars[i]!;
  if (s.kind === "milestone") return msLabel(s.msIndex ?? 0, s.role ?? "shared");
  if (s.role === "forged") return `${shortHex(s.id!)} forged twin`;
  return s.id ? shortHex(s.id) : "";
}

/** The catalogue note for a real star. Decorative stars have none. */
function describe(i: number): { id: string; text: string } | null {
  const s = model.stars[i];
  if (!s || !s.real || !s.id) return null;
  const conf = s.confirmedBy !== null ? model.stars[s.confirmedBy]! : null;
  if (s.role === "sample" || s.role === "forged") {
    const f = facts[s.role];
    const r = store.results[s.role];
    const verdict =
      r.overall === "VALID"
        ? "All five checks pass."
        : r.overall === "INVALID"
          ? `${s.role === "forged" ? "The forged twin: check" : "Check"} ${r.failedAt} fails.`
          : "Checking…";
    return { id: shortHex(s.id), text: `trust.score ${f.scoreText} for ${f.entity}. ${verdict}` };
  }
  if (s.kind === "milestone") {
    const m = milestoneFacts(model, i);
    if (!m) return { id: shortHex(s.id), text: `Milestone ${s.msIndex}.` };
    const twin = m.universe === "forged" ? " of the forged-twin bundle" : "";
    return {
      id: shortHex(m.id),
      text: `Milestone ${m.index}${twin}. Confirms ${m.cone.length} blocks; ${m.sigValid} of ${m.sigTotal} coordinator signatures check out.`,
    };
  }
  const where = conf ? `confirmed by milestone ${conf.msIndex}` : "not confirmed yet";
  if (!s.raw) return { id: shortHex(s.id), text: `Block ${where}. Its bytes are not part of the sample.` };
  return { id: shortHex(s.id), text: `${s.tag ?? "Untagged"} block, ${where}. No signed envelope, so no sender to check.` };
}

function setHover(i: number) {
  if (i === hover) return;
  hover = i;
  const d = i >= 0 ? describe(i) : null;
  if (!d) {
    hover = -1;
    hoverNote.show = false;
  } else {
    hoverNote.id = d.id;
    hoverNote.text = d.text;
    hoverNote.show = true;
  }
  if (canvas.value) canvas.value.style.cursor = hover >= 0 ? "pointer" : "default";
  kick();
}

function placeAnnot() {
  const el = annot.value;
  if (!el || hover < 0) return;
  const x = scene.px[hover]!;
  const y = scene.py[hover]!;
  const w = scene.stageLayout?.w ?? 1000;
  const left = x > w - 320;
  hoverNote.left = left;
  el.style.transform = left ? `translate(${x - 8}px, ${y - 11}px) translateX(-100%)` : `translate(${x + 8}px, ${y - 11}px)`;
}

function startTrace(i: number) {
  const s = model.stars[i];
  if (!s || !s.real) return;
  const path = pathToMilestone(model, i) ?? [i];
  const which = s.role ?? null;
  trace = { star: i, path, start: performance.now(), which };
  plumbFired = false;
  if (which) {
    plainNote.value = "";
    plainSubject.value = null;
    // the subject changes once the ladder starts, so the descent follows what you picked
  } else {
    store.clearHero();
    const conf = s.confirmedBy !== null ? model.stars[s.confirmedBy]! : null;
    plainSubject.value = { id: shortHex(s.kind === "milestone" ? (milestoneFacts(model, i)?.id ?? s.id!) : s.id!), kind: s.kind === "milestone" ? label(i) : (s.tag ?? "block") };
    if (s.kind === "milestone" && !conf) {
      const m = milestoneFacts(model, i);
      plainNote.value = `A milestone. It confirms ${m?.cone.length ?? 0} blocks; nothing later in the sample confirms it yet.`;
    } else if (s.kind === "milestone") {
      plainNote.value = `The block carrying ${label(i)}. Its approvals reach milestone ${conf!.msIndex} in ${path.length - 1} hop${path.length === 2 ? "" : "s"}.`;
    } else {
      plainNote.value = `No signed trust message in this block, so there is nothing to sign-check. Its approvals reach milestone ${conf?.msIndex} in ${path.length - 1} hop${path.length === 2 ? "" : "s"}.`;
    }
  }
  kick();
}

function traceForged() {
  setHover(-1);
  if (p.value > 0.05) {
    scrollToP(0);
  }
  startTrace(model.forged);
}

// ---------------------------------------------------------------- layout and frames
function rel(el: Element, base: DOMRect): Box {
  const r = el.getBoundingClientRect();
  return { x0: r.left - base.left - 4, y0: r.top - base.top - 2, x1: r.right - base.left + 4, y1: r.bottom - base.top + 2 };
}

function ladderAnchor(base: DOMRect) {
  const el = ladder.value?.firstMark;
  if (!el) return null;
  const r = el.getBoundingClientRect();
  if (!r.width) return null;
  return { x: r.left - base.left + r.width / 2, y: r.top - base.top + 2 };
}

function measure() {
  const st = stage.value;
  const cv = canvas.value;
  const slot = skySlot.value;
  if (!st || !cv || !slot) return;
  const isMobile = mq?.matches ?? false;
  if (isMobile !== mobile.value) {
    mobile.value = isMobile;
    model = buildSky({ mobile: isMobile });
    scene = new Scene(model); // real stars keep their indices, so a trace in progress survives
  }
  const base = st.getBoundingClientRect();
  shortStage.value = base.height < 800;
  dpr = Math.min(window.devicePixelRatio || 1, 2);
  cv.width = Math.round(base.width * dpr);
  cv.height = Math.round(base.height * dpr);
  const s = slot.getBoundingClientRect();
  const g = grid.value?.getBoundingClientRect();
  scene.setLayout(
    {
      w: base.width,
      h: base.height,
      mobile: isMobile,
      heroSky: { cx: s.left - base.left + s.width / 2, cy: s.top - base.top + s.height / 2, width: s.width },
      clear: [h1El.value, subEl.value, actEl.value, hintEl.value].filter((el): el is HTMLElement => !!el).map((el) => rel(el, base)),
      ladderAnchor: ladderAnchor(base),
      contentLeft: g ? g.left - base.left : 48,
    },
    subjectStar(),
  );
  column.value = scene.column();
  const sec = section.value;
  if (sec) sectionTop = sec.getBoundingClientRect().top + window.scrollY;
  kick();
}

function progress(): number {
  if (props.still) return 0;
  const sec = section.value;
  if (!sec) return 0;
  const span = sec.offsetHeight - window.innerHeight;
  return span > 0 ? clamp((window.scrollY - sectionTop) / span) : 0;
}

function frameInput(now: number): FrameInput {
  subjectCache ??= subjectInput();
  return {
    p: p.value,
    t: (now - t0) / 1000,
    now,
    still: props.still,
    pointer,
    hover,
    trace,
    subject: subjectCache,
    verdicts: verdicts(),
    label,
  };
}

function frame(now: number) {
  raf = 0;
  const cv = canvas.value;
  const st = stage.value;
  if (!cv || !st) return;
  const cx = cv.getContext("2d");
  if (!cx) return;
  const L = scene.stageLayout;
  if (L && trace?.which && factors.value.hero > 0.02) L.ladderAnchor = ladderAnchor(st.getBoundingClientRect());
  cx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const out = scene.draw(cx, frameInput(now));
  if (trace?.which && !plumbFired && out.plumb >= 1) {
    plumbFired = true;
    void store.verifyInHero(trace.which, props.still ? 0 : 190);
  }
  placeAnnot();
  const animating = trace !== null && (!plumbFired || out.traceHops < trace.path.length - 1);
  if (!props.still && onScreen && !document.hidden && (p.value < 0.46 || animating)) raf = requestAnimationFrame(frame);
  else if (props.still && animating) raf = requestAnimationFrame(frame);
}

function kick() {
  if (!raf && typeof requestAnimationFrame === "function") raf = requestAnimationFrame(frame);
}

function onScroll() {
  const np = progress();
  if (np !== p.value) {
    p.value = np;
    if (np > 0.4 && hover >= 0) setHover(-1);
  }
  kick();
}

function scrollToP(target: number) {
  const sec = section.value;
  if (!sec) return;
  const span = sec.offsetHeight - window.innerHeight;
  window.scrollTo({ top: sectionTop + target * span, behavior: props.still ? "auto" : "smooth" });
}

// ---------------------------------------------------------------- pointer and keyboard
function local(e: PointerEvent | MouseEvent) {
  const r = stage.value!.getBoundingClientRect();
  return { x: e.clientX - r.left, y: e.clientY - r.top };
}
function interactive() {
  return factors.value.sky > 0.6 && p.value < 0.4;
}
function onMove(e: PointerEvent) {
  const q = local(e);
  pointer.x = q.x;
  pointer.y = q.y;
  pointer.on = true;
  setHover(interactive() ? scene.hit(q.x, q.y, e.pointerType === "touch" ? 26 : 16) : -1);
  kick();
}
function onLeave() {
  pointer.on = false;
  setHover(-1);
  kick();
}
function onClick(e: MouseEvent) {
  if (!interactive()) return;
  const q = local(e);
  const i = scene.hit(q.x, q.y, 24);
  if (i >= 0) {
    setHover(i);
    startTrace(i);
  }
}
/** Arrow keys walk the real stars in time order; Enter traces the one in focus. */
function onKey(e: KeyboardEvent) {
  const n = model.realCount;
  if (e.key === "ArrowRight" || e.key === "ArrowDown" || e.key === "ArrowLeft" || e.key === "ArrowUp") {
    e.preventDefault();
    const order = [...Array(n).keys()].sort((a, b) => model.stars[a]!.wx - model.stars[b]!.wx);
    const at = order.indexOf(keyStar);
    const step = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : -1;
    keyStar = order[(at + step + n) % n]!;
    setHover(keyStar);
  } else if ((e.key === "Enter" || e.key === " ") && keyStar >= 0) {
    e.preventDefault();
    startTrace(keyStar);
  } else if (e.key === "Escape") setHover(-1);
}
function onFocus() {
  if (keyStar < 0) keyStar = model.sample;
  setHover(keyStar);
}

// ---------------------------------------------------------------- the reduced-motion still frame
function drawStill() {
  const cv = stillCanvas.value;
  const box = stillStage.value;
  const st = stage.value;
  if (!cv || !box || !st) return;
  const r = box.getBoundingClientRect();
  const s2 = new Scene(model);
  const g = grid.value?.getBoundingClientRect();
  const base = st.getBoundingClientRect();
  s2.setLayout(
    {
      w: r.width,
      h: r.height,
      mobile: mobile.value,
      heroSky: { cx: r.width / 2, cy: r.height / 2, width: r.width / 2 },
      clear: [],
      ladderAnchor: null,
      contentLeft: g ? g.left - base.left : 48,
    },
    subjectStar(),
  );
  stillColumn.value = s2.column();
  cv.width = Math.round(r.width * dpr);
  cv.height = Math.round(r.height * dpr);
  const cx = cv.getContext("2d");
  if (!cx) return;
  cx.setTransform(dpr, 0, 0, dpr, 0, 0);
  s2.draw(cx, { ...frameInput(performance.now()), p: 0.97, trace: null, hover: -1, pointer: { x: 0, y: 0, on: false } });
}
const stillColumn = ref<{ x: number; ys: number[] } | null>(null);

// ---------------------------------------------------------------- lifecycle
let ro: ResizeObserver | null = null;
let io: IntersectionObserver | null = null;
let resizeTimer = 0;
function onResize() {
  window.clearTimeout(resizeTimer);
  resizeTimer = window.setTimeout(() => {
    measure();
    onScroll();
    if (props.still) drawStill();
  }, 80);
}
function onVisibility() {
  if (!document.hidden) kick();
}

watch(subject, () => {
  if (scene.stageLayout) scene.setLayout(scene.stageLayout, subjectStar());
  column.value = scene.column();
  subjectCache = null;
  if (props.still) void nextTick(drawStill);
  kick();
});
watch(
  () => [store.results.sample.overall, store.results.forged.overall],
  () => {
    subjectCache = null;
    if (props.still) void nextTick(drawStill);
    kick();
  },
);

onMounted(async () => {
  void store.computeAll();
  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("resize", onResize);
  document.addEventListener("visibilitychange", onVisibility);
  if (typeof ResizeObserver === "function" && stage.value) {
    ro = new ResizeObserver(onResize);
    ro.observe(stage.value);
  }
  if (typeof IntersectionObserver === "function" && section.value) {
    io = new IntersectionObserver((entries) => {
      onScreen = entries.some((x) => x.isIntersecting);
      if (onScreen) kick();
    });
    io.observe(section.value);
  }
  await (document.fonts?.ready ?? Promise.resolve());
  measure();
  onScroll();
  await store.computeAll();
  if (props.still) {
    startTrace(model.sample);
    await nextTick();
    drawStill();
  } else {
    window.setTimeout(() => {
      if (!trace) startTrace(model.sample);
    }, 650);
  }
  // read-only hooks for end-to-end tests: where a real star is on screen right now
  Object.assign(window, {
    __witnessReady: true,
    __witnessSky: {
      star: (role: "sample" | "forged" | "ms374") => {
        const i = role === "ms374" ? model.msOf.sample : role === "forged" ? model.forged : model.sample;
        return { x: scene.px[i], y: scene.py[i] };
      },
    },
  });
});

onBeforeUnmount(() => {
  window.removeEventListener("scroll", onScroll);
  window.removeEventListener("resize", onResize);
  document.removeEventListener("visibilitychange", onVisibility);
  ro?.disconnect();
  io?.disconnect();
  if (raf) cancelAnimationFrame(raf);
});

defineExpose({ scrollToP });

const heroStyle = computed(() => {
  const a = factors.value.hero;
  return {
    opacity: a,
    visibility: a < 0.02 ? ("hidden" as const) : ("visible" as const),
    transform: `translateY(${-50 * (1 - a)}px)`,
  };
});
/** On small or short screens the depth trail waits until the hero has gone, so it never sits on the claim. */
const shortStage = ref(false);
const trailStyle = computed(() => {
  const a = mobile.value || shortStage.value ? 1 - factors.value.hero : 1;
  return { opacity: a, visibility: a < 0.02 ? ("hidden" as const) : ("visible" as const) };
});
const skyLabel = `A sample IOTA Tangle drawn as stars: ${realCount} real blocks from the test vectors with their approvals, milestones as four-point stars, in a field of decorative stars that carry no data. Arrow keys move between the real blocks, Enter traces one to its milestone and runs the five checks.`;
</script>

<template>
  <section ref="section" class="descent" :class="{ still }" aria-label="The sample, from the Tangle down to one trust score and back up through its proof">
    <div ref="stage" class="stage">
      <canvas
        ref="canvas"
        class="sky"
        tabindex="0"
        role="img"
        :aria-label="skyLabel"
        @pointermove="onMove"
        @pointerleave="onLeave"
        @click="onClick"
        @keydown="onKey"
        @focus="onFocus"
        @blur="setHover(-1)"
      ></canvas>

      <div ref="annot" class="annot" :class="{ show: hoverNote.show, left: hoverNote.left }" aria-live="polite">
        <span class="a1">{{ hoverNote.id }}</span>
        <span class="a2">{{ hoverNote.text }}</span>
      </div>

      <div class="hero" :style="heroStyle">
        <div ref="grid" class="hero-grid">
          <div class="hero-copy">
            <h1 ref="h1El">Don&rsquo;t trust the dashboard.<br />Verify the Tangle.</h1>
            <p ref="subEl" class="sub">
              Witness proves each aeriOS trust score against a private IOTA Tangle. Five checks, computed in your browser.
            </p>
            <div ref="actEl" class="act">
              <button class="btn btn--solid" type="button" @click="emit('verify')">Verify a trust score</button>
              <button class="text-action" type="button" @click="traceForged">Look at the forged twin</button>
            </div>
            <p ref="hintEl" class="hint">
              The bright stars are {{ realCount }} real blocks and milestones from the test vectors. Point at one to read it, click it to trace it to its milestone.
            </p>
          </div>

          <div class="hero-side">
            <div ref="skySlot" class="sky-slot" aria-hidden="true"></div>
            <div class="hero-ladder" :class="{ dim: !store.heroSubject }" role="group" aria-label="The five checks for the traced block">
              <p class="subject">
                <span class="pin" aria-hidden="true"></span>
                <template v-if="heroFacts">
                  <span class="mono">{{ shortHex(heroFacts.id) }}</span>
                  <span>trust.score {{ heroFacts.scoreText }}</span>
                </template>
                <template v-else-if="plainSubject">
                  <span class="mono">{{ plainSubject.id }}</span>
                  <span>{{ plainSubject.kind }}</span>
                </template>
                <span v-else>Pick a star</span>
              </p>
              <StepList ref="ladder" :steps="store.hero.steps" :glosses="gloss[store.heroSubject ?? 'sample']" :compact="mobile" />
              <p class="verdict" aria-live="polite">
                <template v-if="heroVerdict">
                  <b v-if="heroVerdict.b" :class="{ bad: heroVerdict.bad }">{{ heroVerdict.b }}</b>
                  {{ heroVerdict.t }}
                </template>
              </p>
            </div>
          </div>
        </div>
      </div>

      <template v-if="!still">
        <div class="caps">
          <div
            v-for="c in captions"
            :key="c.from"
            class="cap"
            :class="{ on: p >= c.from && p < c.to }"
            :aria-hidden="!(p >= c.from && p < c.to)"
          >
            <h2 :class="{ bad: c.bad }">{{ c.h }}</h2>
            <p>
              {{ c.p }}
              <a v-if="c.end" href="#flip" @click.prevent="emit('verify')">{{ c.bad ? "Now break the real one." : "Now break it." }}</a>
            </p>
          </div>
        </div>

        <ol v-if="column" class="ascent" aria-label="The five checks for this block">
          <li
            v-for="(r, k) in ascentRows"
            :key="r.key"
            :data-s="r.status"
            :class="{ seen: p >= 0.63 }"
            :style="{ left: `${column.x + (mobile ? 26 : 44)}px`, top: `${column.ys[k]}px` }"
          >
            <div class="nm"><i>{{ r.n }}</i>{{ r.title }}</div>
            <div class="vl">{{ r.value }}</div>
            <div class="gl">{{ r.gloss }}</div>
          </li>
        </ol>

        <nav class="trail" aria-label="Depth" :style="trailStyle">
          <button
            v-for="(t, k) in trail"
            :key="t.label"
            type="button"
            :class="{ here: k === depth, past: k < depth }"
            @click="scrollToP(t.at)"
          >
            {{ t.label }} <span v-if="t.mono" class="mono">{{ t.mono }}</span>
          </button>
        </nav>
      </template>
    </div>

    <div v-if="still" ref="stillStage" class="stage still-frame">
      <canvas ref="stillCanvas" class="sky" role="img" aria-label="The five checks for the sample block, climbing from its raw bytes up to the public anchor."></canvas>
      <div class="caps">
        <div class="cap on">
          <h2>Five checks, back up to a public anchor</h2>
          <p>
            Each one runs in your browser. None of them asks the dashboard.
            <a href="#flip" @click.prevent="emit('verify')">Now break it.</a>
          </p>
        </div>
      </div>
      <ol v-if="stillColumn" class="ascent" aria-label="The five checks for this block">
        <li
          v-for="(r, k) in ascentRows"
          :key="r.key"
          :data-s="r.status"
          class="seen"
          :style="{ left: `${stillColumn.x + (mobile ? 26 : 44)}px`, top: `${stillColumn.ys[k]}px` }"
        >
          <div class="nm"><i>{{ r.n }}</i>{{ r.title }}</div>
          <div class="vl">{{ r.value }}</div>
          <div class="gl">{{ r.gloss }}</div>
        </li>
      </ol>
    </div>
  </section>
</template>

<style scoped>
.descent {
  position: relative;
  height: 640vh;
}
.descent.still {
  height: auto;
}
.stage {
  position: sticky;
  top: 0;
  height: 100vh;
  height: 100svh;
  min-height: 600px;
  overflow: hidden;
}
.still .stage {
  position: relative;
}
.still-frame {
  border-top: 1px solid var(--hair);
}
.sky {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  display: block;
  touch-action: pan-y;
}
.sky:focus-visible {
  outline: none;
}

/* the catalogue note next to a star: two lines, no box */
.annot {
  position: absolute;
  z-index: 4;
  left: 0;
  top: 0;
  max-width: 300px;
  padding-left: 28px;
  pointer-events: none;
  opacity: 0;
  transition: opacity var(--t-quick);
}
.annot::before {
  content: "";
  position: absolute;
  left: 4px;
  top: 10px;
  width: 18px;
  height: 1px;
  background: rgba(var(--rgb-fog-50), 0.45);
}
.annot.left {
  padding: 0 28px 0 0;
  text-align: right;
}
.annot.left::before {
  left: auto;
  right: 4px;
}
.annot.show {
  opacity: 1;
}
.a1 {
  display: block;
  font: 400 12px/20px var(--mono);
  color: var(--fog-50);
  text-shadow: 0 0 8px var(--void), 0 0 3px var(--void);
}
.a2 {
  display: block;
  font: 400 13px/18px var(--sans);
  color: var(--fog-200);
  text-shadow: 0 0 8px var(--void), 0 0 3px var(--void);
}

/* hero: the claim and the sky side by side, gathered around the centre */
.hero {
  position: absolute;
  inset: 0;
  z-index: 3;
  display: flex;
  padding: 92px var(--gut) 72px;
  pointer-events: none;
  will-change: opacity, transform;
}
.hero-grid {
  width: 100%;
  max-width: var(--content);
  margin: 0 auto;
  display: grid;
  grid-template-columns: minmax(0, 480px) minmax(0, 1fr);
  column-gap: 48px;
  align-items: center;
}
.hero-copy {
  pointer-events: none;
}
h1 {
  margin: 0;
  font: 400 var(--fs-h1) / 0.95 var(--serif);
  letter-spacing: -0.018em;
  color: var(--fog-50);
  text-wrap: balance;
}
.sub {
  margin: 26px 0 0;
  max-width: 38ch;
  font-size: var(--fs-lead);
  line-height: 27px;
  color: var(--fog-200);
}
.act {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 14px 26px;
  margin-top: 30px;
}
.act > * {
  pointer-events: auto;
}
.hint {
  margin: 22px 0 0;
  max-width: 44ch;
  font-size: var(--fs-small);
  line-height: 19px;
  color: var(--fog-400);
}
.hero-side {
  display: flex;
  flex-direction: column;
  min-width: 0;
}
.sky-slot {
  height: clamp(300px, 50vh, 470px);
}
.hero-ladder {
  width: min(100%, 392px);
  margin: 4px 0 0 8%;
  pointer-events: auto;
  font-size: 14px;
  transition: opacity var(--t-step);
}
.hero-ladder.dim :deep(.steps) {
  opacity: 0.4;
}
.subject {
  position: relative;
  display: flex;
  gap: 12px;
  align-items: baseline;
  min-height: 19px;
  margin: 0 0 8px;
  padding-left: 22px;
  font-size: var(--fs-small);
  color: var(--fog-400);
}
.subject .mono {
  color: var(--fog-50);
}
.pin {
  position: absolute;
  left: 3px;
  top: 7px;
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: var(--ember);
}
.verdict {
  margin: 12px 0 0 22px;
  min-height: 38px;
  font-size: var(--fs-small);
  line-height: 19px;
  color: var(--fog-400);
}
.verdict b {
  font-weight: 500;
  color: var(--fog-50);
}
.verdict b.bad {
  color: var(--fail);
}

/* the descent: one caption at a time, at the left edge of the content */
.caps {
  position: absolute;
  z-index: 3;
  left: max(var(--gut), calc((100% - var(--content)) / 2));
  top: 50%;
  width: min(380px, calc(100% - 2 * var(--gut)));
}
.cap {
  position: absolute;
  left: 0;
  top: 0;
  transform: translateY(-50%);
  opacity: 0;
  transition: opacity 180ms;
  pointer-events: none;
}
.cap.on {
  opacity: 1;
  pointer-events: auto;
}
.cap h2 {
  margin: 0;
  font: 400 44px/46px var(--serif);
  letter-spacing: -0.01em;
  color: var(--fog-50);
}
.cap h2.bad {
  color: var(--fail);
}
.cap p {
  margin: 14px 0 0;
  max-width: 34ch;
  font-size: 16px;
  line-height: 25px;
  color: var(--fog-200);
  overflow-wrap: anywhere;
}
.cap a {
  color: var(--fog-50);
  text-decoration-color: var(--ember);
  text-underline-offset: 4px;
}

.ascent {
  list-style: none;
  margin: 0;
  padding: 0;
  position: absolute;
  z-index: 3;
  left: 0;
  top: 0;
  width: 0;
  height: 0;
}
.ascent li {
  position: absolute;
  width: 400px;
  transform: translateY(-50%);
  opacity: 0;
  transition: opacity 300ms;
}
.ascent li.seen {
  opacity: 1;
}
.ascent .nm {
  display: flex;
  gap: 12px;
  align-items: baseline;
  font-size: 17px;
  line-height: 24px;
  color: var(--fog-400);
  transition: color 300ms;
}
.ascent .nm i {
  font-style: normal;
  font-variant-numeric: tabular-nums;
}
.ascent .vl {
  min-height: 18px;
  font: 400 12px/18px var(--mono);
  color: var(--fog-400);
}
.ascent .gl {
  margin-top: 2px;
  max-width: 46ch;
  font-size: 13.5px;
  line-height: 19px;
  color: var(--fog-400);
  overflow-wrap: anywhere;
}
.ascent li[data-s="pass"] .nm {
  color: var(--fog-50);
}
.ascent li[data-s="pass"] .vl {
  color: var(--fog-200);
}
.ascent li[data-s="fail"] .nm,
.ascent li[data-s="fail"] .vl {
  color: var(--fail);
}
.ascent li[data-s="fail"] .gl {
  color: var(--fog-200);
}
.ascent li[data-s="waiting"] .gl {
  opacity: 0.6;
}

.trail {
  position: absolute;
  z-index: 4;
  left: max(calc(var(--gut) - 10px), calc((100% - var(--content)) / 2 - 10px));
  bottom: 26px;
  display: flex;
  gap: 6px;
  align-items: center;
  transition: opacity 200ms;
}
.trail button {
  position: relative;
  border: 0;
  background: none;
  padding: 6px 10px 8px;
  border-radius: 4px;
  font-size: var(--fs-small);
  color: rgba(var(--rgb-fog-400), 0.75);
  cursor: pointer;
  transition: color 300ms;
}
.trail button::after {
  content: "";
  position: absolute;
  left: 10px;
  right: 10px;
  bottom: 2px;
  height: 1px;
  background: var(--ember);
  transform: scaleX(0);
  transform-origin: left;
  transition: transform 350ms var(--ease-out);
}
.trail button.past {
  color: var(--fog-200);
}
.trail button.here {
  color: var(--fog-50);
}
.trail button.here::after {
  transform: scaleX(1);
}
.trail button:hover {
  color: var(--fog-50);
}
.trail button + button::before {
  content: "";
  position: absolute;
  left: -4px;
  top: 50%;
  width: 3px;
  height: 3px;
  border-radius: 50%;
  background: var(--fog-400);
  opacity: 0.6;
}
.trail .mono {
  font-size: 11.5px;
}

@media (max-width: 1100px) and (min-width: 761px) {
  .hero-grid {
    grid-template-columns: minmax(0, 420px) minmax(0, 1fr);
    column-gap: 32px;
  }
  h1 {
    font-size: 68px;
  }
}

@media (max-width: 760px) {
  .hero {
    padding: 64px var(--gut) 28px;
  }
  .hero-grid {
    grid-template-columns: minmax(0, 1fr);
    align-content: start;
  }
  .hero-side {
    order: -1;
  }
  .sky-slot {
    height: clamp(220px, 34svh, 300px);
  }
  .hero-ladder {
    width: 100%;
    margin: 0;
  }
  .subject {
    display: none;
  }
  .verdict {
    margin: 8px 0 0;
    min-height: 17px;
    font-size: 12.5px;
    line-height: 17px;
  }
  .hero-copy {
    margin-top: 18px;
  }
  h1 {
    line-height: 0.96;
  }
  .sub {
    margin-top: 16px;
    font-size: 16px;
    line-height: 25px;
  }
  .act {
    margin-top: 22px;
  }
  .hint {
    margin-top: 14px;
  }
  .caps {
    top: auto;
    bottom: 92px;
    left: var(--gut);
    right: var(--gut);
    width: auto;
  }
  .cap {
    top: auto;
    bottom: 0;
    transform: none;
  }
  .cap h2 {
    font-size: 32px;
    line-height: 34px;
  }
  .cap p {
    font-size: 15px;
    line-height: 22px;
  }
  .ascent li {
    width: calc(100vw - 96px);
  }
  .ascent .nm {
    font-size: 15px;
  }
  .ascent .gl {
    display: none;
  }
  .trail {
    left: 10px;
    right: 10px;
    bottom: 14px;
    flex-wrap: wrap;
    gap: 0;
  }
  .trail button {
    font-size: 12px;
    padding: 5px 7px 7px;
  }
  .trail .mono {
    display: none;
  }
}
</style>
