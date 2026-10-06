/// <reference types="vite/client" />

declare module "*.vue" {
  import type { DefineComponent } from "vue";
  const component: DefineComponent<object, object, unknown>;
  export default component;
}

interface ImportMetaEnv {
  readonly VITE_MODE?: "live" | "replay";
  readonly VITE_API_URL?: string;
  readonly VITE_REPLAY_ROOT?: string;
  /** Trusted DID resolver (the anchor service's /resolve), default /anchor. */
  readonly VITE_RESOLVER_URL?: string;
}
