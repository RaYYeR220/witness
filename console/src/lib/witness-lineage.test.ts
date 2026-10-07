import { describe, expect, it } from "vitest";

import { verifyLinks } from "./witness-lineage";

describe("WitnessLineage library", () => {
  it("links scores to a console's Verify screen over http(s) only", () => {
    expect(verifyLinks("https://witness.example/")!("0xab")).toBe("https://witness.example/m/0xab");
    expect(verifyLinks("/console", "https://portal.example/app")!("0xab")).toBe("https://portal.example/console/m/0xab");
    expect(verifyLinks("javascript:alert(1)")).toBeUndefined();
    expect(verifyLinks("data:text/html,x")).toBeUndefined();
    expect(verifyLinks(undefined)).toBeUndefined();
  });
});
