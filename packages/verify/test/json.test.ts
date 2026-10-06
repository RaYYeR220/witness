import { describe, expect, it } from "vitest";

import {
  canonHash,
  CanonicalizationError,
  jcs,
  JCS_MAX_DEPTH,
  JsonNumber,
  JsonParseError,
  parseJson,
  PY_JSON_MAX_DEPTH,
  pyRepr,
  RecursionError,
  textTooDeep,
} from "../src/index.js";
import { toHex } from "../src/bytes.js";
import { raw } from "./vectors.js";

describe("parseJson keeps Python's number model", () => {
  it("integral float literals stay floats", () => {
    for (const lit of ["7.0", "1e3", "1E2", "-0.0", "1.5e1"]) {
      const v = parseJson(lit);
      expect(v).toBeInstanceOf(JsonNumber);
      expect((v as JsonNumber).kind).toBe("float");
    }
    expect(parseJson("1e400")).toEqual(new JsonNumber("float", Infinity, "1e400"));
    expect(parseJson("0.745")).toBe(0.745);
  });

  it("integers past 2^53 - 1 are kept apart; safe ones are plain numbers", () => {
    expect(parseJson("9007199254740991")).toBe(2 ** 53 - 1);
    expect(parseJson("-9007199254740991")).toBe(-(2 ** 53 - 1));
    const big = parseJson("9007199254740993");
    expect(big).toBeInstanceOf(JsonNumber);
    expect((big as JsonNumber).kind).toBe("int");
    expect((big as JsonNumber).literal).toBe("9007199254740993");
    expect(() => parseJson("1".repeat(4301))).toThrow(SyntaxError);
  });

  it("agrees with JSON.parse on every shared vector file", () => {
    for (const text of Object.values(raw)) {
      const ours = JSON.parse(JSON.stringify(parseJson(text)));
      expect(ours).toEqual(JSON.parse(text));
    }
  });

  it("objects: __proto__ is a plain key, duplicates keep the first position and last value", () => {
    const o = parseJson('{"__proto__": {"x": 1}, "a": 1, "b": 2, "a": 3}') as Record<string, unknown>;
    expect(Object.getPrototypeOf(o)).toBe(Object.prototype);
    expect(Object.keys(o)).toEqual(["__proto__", "a", "b"]);
    expect(o.a).toBe(3);
    expect((o as any).x).toBeUndefined();
  });

  it("strings and escapes", () => {
    expect(parseJson('"a\\u00e9\\ud83d\\ude00\\n\\/"')).toBe("aé😀\n/");
    expect(parseJson('"\\ud800"')).toBe("\ud800");
  });

  it.each([
    "", " ", "\ufeff{}", "{} x", "[1,]", "{\"a\":1,}", "01", "1.", ".5", "+1", "-", "NaN", "Infinity", "-Infinity",
    "'x'", '"\t"', '"\\x"', '"\\u12"', "tru", "[1 2]", '{"a" 1}', "{1:2}",
  ])("rejects %j", (text) => {
    expect(() => parseJson(text)).toThrow(SyntaxError);
  });

  it("nesting past the cap is a RecursionError, never a parse error, so callers can fail closed", () => {
    const nest = (n: number) => "[".repeat(n) + "]".repeat(n);
    expect(() => parseJson(nest(PY_JSON_MAX_DEPTH))).not.toThrow();
    for (const n of [PY_JSON_MAX_DEPTH + 1, 12000, 200000]) {
      expect(() => parseJson(nest(n))).toThrow(RecursionError);
      expect(() => parseJson(nest(n))).not.toThrow(JsonParseError);
    }
    expect(() => parseJson(nest(20), { maxDepth: 19 })).toThrow(RecursionError);
  });

  it("shares its cap with the reference and judges nesting by brackets alone", () => {
    expect(PY_JSON_MAX_DEPTH).toBe(2500); // witness_core.nesting.MAX_JSON_DEPTH
    const cap = PY_JSON_MAX_DEPTH;
    const nest = (n: number) => "[".repeat(n) + "]".repeat(n);
    // Broken text past the cap is still a RecursionError, wherever the syntax breaks.
    for (const text of ["[".repeat(cap + 1), `${"[".repeat(cap + 1)}x`, `{"a":1 ${"[".repeat(cap + 1)}`, `﻿${nest(cap + 1)}`]) {
      expect(textTooDeep(text)).toBe(true);
      expect(() => parseJson(text)).toThrow(RecursionError);
    }
    // Brackets inside strings do not count, nor after an escaped quote.
    expect(textTooDeep(`["${"[".repeat(2 * cap)}"]`)).toBe(false);
    expect(textTooDeep(`"\\\"${"{".repeat(2 * cap)}"`)).toBe(false);
    expect(textTooDeep(`["${"[".repeat(2 * cap)}`)).toBe(false); // an open string runs to the end
    expect(parseJson(`["${"[".repeat(2 * cap)}"]`)).toEqual(["[".repeat(2 * cap)]);
    const mixed = `${'{"a":'.repeat(cap - 1)}[1]${"}".repeat(cap - 1)}`;
    expect(textTooDeep(mixed)).toBe(false);
    expect(() => parseJson(`[${mixed}]`)).toThrow(RecursionError);
  });

  it("accepts NaN/Infinity only on request", () => {
    expect((parseJson("[NaN, -Infinity]", { constants: true }) as JsonNumber[]).map((n) => n.value)).toEqual([
      NaN,
      -Infinity,
    ]);
  });
});

describe("jcs (RFC 8785 with the rfc8785 package's domain rules)", () => {
  it("sorts keys by UTF-16 code units and serializes numbers the ECMAScript way", () => {
    expect(jcs({ b: 1, a: [true, null, "x"], "€": 0, "\u00e9": 1, "\ud83d\ude00": 2 })).toBe(
      '{"a":[true,null,"x"],"b":1,"é":1,"€":0,"😀":2}',
    );
    expect(jcs(parseJson("[0.1, 1e21, 1e-7, -0, 1.2345678901234568e20, 5e-324, 4.5]"))).toBe(
      "[0.1,1e+21,1e-7,0,123456789012345680000,5e-324,4.5]",
    );
    expect(jcs("\u0000\u001f\"\\\b\f\n\r\t\u007f")).toBe('"\\u0000\\u001f\\"\\\\\\b\\f\\n\\r\\t\u007f"');
  });

  it("float literals from parseJson serialize like Python floats", () => {
    expect(jcs(parseJson('{"seq": 7.0, "big": 1e300, "z": -0.0}'))).toBe('{"big":1e+300,"seq":7,"z":0}');
  });

  it("keys that look like JavaScript internals are ordinary keys", () => {
    const v = parseJson('{"toJSON": "x", "__proto__": 1, "constructor": 2}');
    expect(jcs(v)).toBe('{"__proto__":1,"constructor":2,"toJSON":"x"}');
  });

  it.each([
    ["NaN", NaN, "nan is not representable in JCS"],
    ["Infinity", Infinity, "inf is not representable in JCS"],
    ["2^53", 2 ** 53, "9007199254740992 exceeds safe integer domain for JSON floats"],
    ["-(2^53)", -(2 ** 53), "-9007199254740992 exceeds safe integer domain for JSON floats"],
    ["big int literal", parseJson("18446744073709551616"), "18446744073709551616 exceeds safe integer domain for JSON floats"],
    ["lone surrogate", "\udc00", "input contains non-UTF-8 codepoints"],
    ["lone surrogate key", { "\ud800": 1 }, "input contains non-UTF-8 codepoints"],
    ["undefined", { a: undefined }, "unsupported type: undefined"],
    ["bytes", new Uint8Array(1), "unsupported type: object"],
  ])("rejects %s", (_name, value, message) => {
    expect(() => jcs(value)).toThrow(CanonicalizationError);
    expect(() => jcs(value)).toThrow(message);
  });

  it("stops below the reference serializer's recursion limit with a RecursionError", () => {
    const nested = (n: number) => {
      let v: unknown[] = [];
      for (let i = 1; i < n; i++) v = [v];
      return v;
    };
    expect(jcs(nested(JCS_MAX_DEPTH + 1))).toHaveLength(2 * (JCS_MAX_DEPTH + 1));
    expect(() => jcs(nested(JCS_MAX_DEPTH + 2))).toThrow(RecursionError);
    expect(() => jcs(nested(JCS_MAX_DEPTH + 2))).not.toThrow(CanonicalizationError);
  });

  it("2^53 - 1 is still in range", () => {
    expect(jcs([2 ** 53 - 1, -(2 ** 53 - 1)])).toBe("[9007199254740991,-9007199254740991]");
  });

  it("canonHash is BLAKE2b-256 of the canonical bytes", () => {
    expect(toHex(canonHash({ b: 1, a: 2 }))).toBe(toHex(canonHash({ a: 2, b: 1 })));
  });
});

describe("pyRepr", () => {
  it.each([
    [null, "None"],
    [true, "True"],
    ["private_tangle1", "'private_tangle1'"],
    ["it's", '"it\'s"'],
    ["a'b\"c", "'a\\'b\"c'"],
    ["tab\there\n", "'tab\\there\\n'"],
    ["\u0001\u00a0é", "'\\x01\\xa0é'"],
    [5, "5"],
    [1.5, "1.5"],
    [parseJson("7.0"), "7.0"],
    [parseJson("1e16"), "1e+16"],
    [1e-5, "1e-05"],
    [0.0001, "0.0001"],
    [[1, "x", null], "[1, 'x', None]"],
    [{ a: [true] }, "{'a': [True]}"],
  ])("%j", (value, expected) => {
    expect(pyRepr(value)).toBe(expected);
  });
});
