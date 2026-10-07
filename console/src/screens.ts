/** The console screens and their one-line descriptions. */

export interface Screen {
  path: string;
  name: string;
  title: string;
  blurb: string;
  /** Listed in the console's top bar (screens with a parameter are reached from other screens). */
  tab: boolean;
  /** Where the tab links to, when the path has a parameter. */
  link?: string;
}

export const SCREENS: Screen[] = [
  {
    path: "/live",
    name: "live",
    title: "Live",
    tab: true,
    blurb: "Trust messages as they reach the Tangle, each with the verdict the indexer recorded and a way to check it yourself.",
  },
  { path: "/search", name: "search", title: "Search", tab: true, blurb: "Find a block, a milestone, a DID or an aeriOS entity by any id you have." },
  { path: "/m/:blockId", name: "verify", title: "Verify", tab: false, blurb: "One trust message, its raw bytes and the five checks, run in your browser." },
  {
    path: "/ie/:id?",
    name: "lineage",
    title: "Lineage",
    tab: true,
    link: "/ie",
    blurb: "The trust score history of one aeriOS entity as written to the ledger, next to what Orion reports now.",
  },
  {
    path: "/integrity",
    name: "integrity",
    title: "Integrity",
    tab: true,
    blurb: "Alerts the rules raised, the incidents they were grouped into, and how well detection held up under attack.",
  },
  {
    path: "/identity",
    name: "identity",
    title: "Identity",
    tab: true,
    blurb: "The did:iota identities that sign trust messages, their keys and the writer policy that says who may write what.",
  },
  {
    path: "/anchors",
    name: "anchors",
    title: "Anchors",
    tab: true,
    blurb: "Checkpoints of milestone ranges recorded on IOTA Rebased, and a re-check of each one from your browser.",
  },
  {
    path: "/posture",
    name: "posture",
    title: "Posture",
    tab: true,
    blurb: "The last security scan of the node this explorer watches: what it found and how to fix it.",
  },
  {
    path: "/reports",
    name: "reports",
    title: "Reports",
    tab: true,
    blurb: "Signed audit reports, whether the ledger vouches for each one, and its hash recomputed in your browser.",
  },
];

export const CONSOLE_TABS = SCREENS.filter((s) => s.tab);
