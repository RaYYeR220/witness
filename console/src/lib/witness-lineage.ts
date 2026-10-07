/**
 * WitnessLineage as a library, for pages outside the Witness console (the
 * aeriOS Management Portal): `vite build --mode lib` → dist-lib/.
 *
 * In a Vue 3 app:
 *
 *   import { WitnessLineage } from "witness-lineage.js";
 *   import "witness-lineage.css";
 *   <WitnessLineage api-base="https://witness.example/api" ie-id="MyDomain:fa163e5e25ef" />
 *
 * In any page (Vue 3 loaded as the global `Vue`, then the UMD script):
 *
 *   WitnessLineage.mountWitnessLineage("#trust", {
 *     apiBase: "https://witness.example/api",
 *     ieId: "MyDomain:fa163e5e25ef",
 *     verifyBase: "https://witness.example",   // optional: scores link to its Verify screen
 *   });
 *
 * The API must allow the embedding origin (CORS). The widget only reads
 * (GET /ie/{id}/lineage, /alerts, /incidents) and never runs a check itself:
 * its links lead to a Witness console, where the browser verifies.
 */

import "./tokens.css";

import { createApp, h } from "vue";

import WitnessLineage from "@/components/WitnessLineage.vue";

export { WitnessLineage };

export interface MountOptions {
  /** Base URL of the witness-api. */
  apiBase: string;
  /** The Infrastructure Element, `<Domain>:<12 hex>`. */
  ieId: string;
  /** A Witness console; each score then links to `{verifyBase}/m/{blockId}`. Only http(s). */
  verifyBase?: string;
}

/** `{verifyBase}/m/{blockId}` builder, or undefined when `verifyBase` is not an http(s) URL. */
export function verifyLinks(verifyBase: string | undefined, here = globalThis.location?.href ?? "http://localhost/"): ((blockId: string) => string) | undefined {
  if (!verifyBase) return undefined;
  let base: URL;
  try {
    base = new URL(verifyBase, here);
  } catch {
    return undefined;
  }
  if (base.protocol !== "https:" && base.protocol !== "http:") return undefined;
  const root = base.href.replace(/\/+$/, "");
  return (blockId: string) => `${root}/m/${encodeURIComponent(blockId)}`;
}

/** Mounts the widget into `el`; returns a function that unmounts it. */
export function mountWitnessLineage(el: Element | string, options: MountOptions): () => void {
  const verifyHref = verifyLinks(options.verifyBase);
  const app = createApp({ render: () => h(WitnessLineage, { apiBase: options.apiBase, ieId: options.ieId, verifyHref }) });
  app.mount(el);
  return () => app.unmount();
}

export default WitnessLineage;
