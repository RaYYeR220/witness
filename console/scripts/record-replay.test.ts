import { describe, expect, it } from "vitest";

import { REPORT_CSP, withCsp } from "./record-replay.mjs";

describe("record-replay", () => {
  it("puts the API's report CSP into a recorded report page, first thing in <head>", () => {
    const page = '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>r</title></head><body>x</body></html>';
    const out = withCsp(page);
    expect(out).toContain(`<head><meta http-equiv="Content-Security-Policy" content="${REPORT_CSP}"><meta charset="utf-8">`);
    expect(REPORT_CSP).toContain("default-src 'none'");
    expect(withCsp("<p>no head</p>").startsWith("<!doctype html><head><meta http-equiv")).toBe(true);
  });
});
