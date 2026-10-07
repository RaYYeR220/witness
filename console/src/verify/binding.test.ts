import { describe, expect, it } from "vitest";

import { bundleCase } from "@/test/vectors";

import { bindBundle } from "./binding";

const text = (name: string) => JSON.stringify(bundleCase(name).bundle);
const idOf = (name: string): string => bundleCase(name).bundle.block.id;

describe("bindBundle", () => {
  it("binds a bundle to the block it is about, ignoring case", () => {
    expect(bindBundle(text("valid_anchored"), idOf("valid_anchored"))).toEqual({ kind: "bound" });
    expect(bindBundle(text("valid_anchored"), idOf("valid_anchored").toUpperCase().replace("0X", "0x"))).toEqual({ kind: "bound" });
  });

  it("names the block a swapped bundle is really about", () => {
    const b = bindBundle(text("valid_anchored"), idOf("envelope_forged"));
    expect(b).toEqual({ kind: "other", servedId: idOf("valid_anchored"), claimedId: idOf("valid_anchored") });
  });

  it("goes by the bytes: a bundle claiming the requested id over another block's bytes is foreign", () => {
    const b = structuredClone(bundleCase("valid_anchored").bundle);
    b.block.id = idOf("envelope_forged");
    expect(bindBundle(JSON.stringify(b), idOf("envelope_forged"))).toMatchObject({ kind: "other", servedId: idOf("valid_anchored") });
  });

  it("treats bytes that do not hash to the requested id as another block", () => {
    // raw_byte_flipped: the claimed id is the sample's, one byte of the raw block differs
    const flipped = bundleCase("raw_byte_flipped").bundle;
    expect(bindBundle(JSON.stringify(flipped), flipped.block.id)).toMatchObject({ kind: "other", claimedId: flipped.block.id });
  });

  it("leaves the right bytes under a wrong claimed id to step 1, and unreadable text to the ladder", () => {
    const b = structuredClone(bundleCase("valid_anchored").bundle);
    b.block.id = idOf("envelope_forged");
    expect(bindBundle(JSON.stringify(b), idOf("valid_anchored"))).toEqual({ kind: "bound" });
    expect(bindBundle("{not json", idOf("valid_anchored"))).toEqual({ kind: "unreadable" });
  });
});
