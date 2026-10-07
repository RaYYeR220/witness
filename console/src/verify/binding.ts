/**
 * Binds a proof bundle to the block it was asked for.
 *
 * The ladder proves things about the block inside the bundle. A valid proof
 * of some other block says nothing about the one in the address bar, so before
 * any verdict is shown the bundle's block must be the requested one: its raw
 * bytes must hash (BLAKE2b-256, as step 1 recomputes it) to the requested id,
 * and the id it claims must be that id too.
 */

import { blake2b256, fromHex, isDict, parseJson, toHex } from "@witness/verify";

export type Binding =
  /** The bundle is about the requested block. */
  | { kind: "bound" }
  /** The bundle is about another block: `servedId` is what its bytes hash to (or claim, when they do not decode). */
  | { kind: "other"; servedId: string; claimedId: string | null }
  /** The bundle cannot be read far enough to tell; the ladder fails it on its own. */
  | { kind: "unreadable" };

const HEX32 = /^0x[0-9a-fA-F]{64}$/;

export function bindBundle(text: string, requested: string): Binding {
  const want = requested.toLowerCase();
  let bundle: unknown;
  try {
    bundle = parseJson(text);
  } catch {
    return { kind: "unreadable" };
  }
  const block = isDict(bundle) ? bundle.block : undefined;
  if (!isDict(block)) return { kind: "unreadable" };
  const claimed = typeof block.id === "string" && HEX32.test(block.id) ? block.id.toLowerCase() : null;
  let hashed: string | null = null;
  if (typeof block.raw === "string") {
    try {
      hashed = toHex(blake2b256(fromHex(block.raw)));
    } catch {
      hashed = null;
    }
  }
  // The bytes decide; a wrong claimed id on the right bytes is step 1's failure to report.
  if (hashed !== null) return hashed === want ? { kind: "bound" } : { kind: "other", servedId: hashed, claimedId: claimed };
  if (claimed !== null) return claimed === want ? { kind: "bound" } : { kind: "other", servedId: claimed, claimedId: claimed };
  return { kind: "unreadable" };
}
