/** The console screens and their one-line descriptions. */

export interface Screen {
  path: string;
  name: string;
  title: string;
  blurb: string;
  /** Listed in the console's top bar (screens with a parameter are reached from other screens). */
  tab: boolean;
}

/** Console screens. Each one is a placeholder until its task lands. */
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
    path: "/ie/:id",
    name: "lineage",
    title: "Lineage",
    tab: false,
    blurb: "The trust score history of one aeriOS entity as written to the ledger, next to what Orion reports now.",
  },
  {
    path: "/integrity",
    name: "integrity",
    title: "Integrity",
    tab: true,
    blurb: "Forgeries, replays and unauthorized writers the pipeline caught, and the check each one failed.",
  },
  {
    path: "/identity",
    name: "identity",
    title: "Identity",
    tab: true,
    blurb: "The did:iota identities that sign trust messages, their keys and when keys were revoked.",
  },
  {
    path: "/anchors",
    name: "anchors",
    title: "Anchors",
    tab: true,
    blurb: "Checkpoints of milestone ranges recorded on IOTA Rebased, and the proof that each one matches.",
  },
  {
    path: "/posture",
    name: "posture",
    title: "Posture",
    tab: true,
    blurb: "How much of the domain's traffic is signed, attested, legacy or rejected, over time.",
  },
  {
    path: "/reports",
    name: "reports",
    title: "Reports",
    tab: true,
    blurb: "Exportable evidence: a period, its checkpoints and every verdict, ready for an auditor.",
  },
  {
    path: "/flows",
    name: "flows",
    title: "Flows",
    tab: true,
    blurb: "Which components write which tags, and how messages move between aeriOS domains.",
  },
  {
    path: "/incidents",
    name: "incidents",
    title: "Incidents",
    tab: true,
    blurb: "Alerts grouped into incidents, with the blocks that triggered them.",
  },
];

export const CONSOLE_TABS = SCREENS.filter((s) => s.tab);
