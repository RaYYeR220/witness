/**
 * JSON with the value model of Python's `json.loads`, which the reference
 * verifier is written against.
 *
 * `JSON.parse` folds `7.0` into `7` and rounds integers past 2^53, so a
 * verifier built on it would accept an envelope whose `seq` is the float `7.0`
 * (Python: MALFORMED) and sign over a rounded integer (Python: not
 * canonicalizable). `parseJson` keeps those literals apart as `JsonNumber`;
 * every other value comes out exactly as `JSON.parse` would build it.
 */

/** Largest integer the envelope/bundle schemas accept (2^53 - 1). */
export const MAX_UINT = Number.MAX_SAFE_INTEGER;

/** Python refuses to convert integer literals longer than this (int_max_str_digits). */
const MAX_INT_DIGITS = 4300;

/**
 * Container nesting cap for `parseJson`. CPython's own `json.loads` limit
 * depends on the platform (about 3000 on Windows, 10000 on Linux), so this is a
 * fixed cap at the lower figure. Deeper input throws `RecursionError`, never a
 * parse error, and the bundle verifier fails closed on it.
 */
export const PY_JSON_MAX_DEPTH = 2997;

/** Nesting beyond what the verifier will recurse through (Python's RecursionError). */
export class RecursionError extends RangeError {
  override name = "RecursionError";
}

/**
 * A number literal Python would not read as a plain JSON-safe int:
 * `kind: "float"` for integral or non-finite float literals (`7.0`, `1e3`,
 * `1e400`), `kind: "int"` for integers beyond ±(2^53 - 1). Never a uint.
 */
export class JsonNumber {
  constructor(
    readonly kind: "float" | "int",
    readonly value: number,
    readonly literal: string,
  ) {}

  valueOf(): number {
    return this.value;
  }

  toJSON(): number {
    return this.value;
  }
}

export type Json = null | boolean | number | string | JsonNumber | Json[] | { [key: string]: Json };
export type JsonObject = { [key: string]: Json };

export class JsonParseError extends SyntaxError {
  override name = "JsonParseError";
}

export interface ParseOptions {
  /** Accept `NaN`, `Infinity`, `-Infinity` like Python's default `json.loads`. */
  constants?: boolean;
  /** Maximum container nesting; deeper input throws `RecursionError`. Default `PY_JSON_MAX_DEPTH`. */
  maxDepth?: number;
}

const NUMBER = /-?(?:0|[1-9]\d*)(\.\d+)?([eE][-+]?\d+)?/y;

/** Parse JSON text with Python `json.loads` semantics (see module doc). */
export function parseJson(text: string, options: ParseOptions = {}): Json {
  const p = new Parser(text, options.constants === true, options.maxDepth ?? PY_JSON_MAX_DEPTH);
  p.ws();
  const value = p.value();
  p.ws();
  if (p.pos !== text.length) p.fail("extra data");
  return value;
}

class Parser {
  pos = 0;
  private depth = 0;

  constructor(
    private readonly text: string,
    private readonly constants: boolean,
    private readonly maxDepth: number,
  ) {}

  private enter(): void {
    if (++this.depth > this.maxDepth) throw new RecursionError("maximum JSON nesting depth exceeded");
  }

  fail(what: string): never {
    throw new JsonParseError(`${what} at offset ${this.pos}`);
  }

  ws(): void {
    const t = this.text;
    while (this.pos < t.length) {
      const c = t.charCodeAt(this.pos);
      if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) break;
      this.pos++;
    }
  }

  private literal(word: string, value: Json): Json {
    if (!this.text.startsWith(word, this.pos)) this.fail("invalid literal");
    this.pos += word.length;
    return value;
  }

  value(): Json {
    const c = this.text[this.pos];
    switch (c) {
      case "{":
      case "[": {
        this.enter();
        const v = c === "{" ? this.object() : this.array();
        this.depth--;
        return v;
      }
      case '"':
        return this.string();
      case "t":
        return this.literal("true", true);
      case "f":
        return this.literal("false", false);
      case "n":
        return this.literal("null", null);
      case "N":
        if (this.constants) return this.literal("NaN", new JsonNumber("float", NaN, "NaN"));
        break;
      case "I":
        if (this.constants) return this.literal("Infinity", new JsonNumber("float", Infinity, "Infinity"));
        break;
      case "-":
        if (this.constants && this.text.startsWith("-Infinity", this.pos)) {
          return this.literal("-Infinity", new JsonNumber("float", -Infinity, "-Infinity"));
        }
        return this.number();
      default:
        if (c !== undefined && c >= "0" && c <= "9") return this.number();
    }
    return this.fail("expecting value");
  }

  private number(): Json {
    NUMBER.lastIndex = this.pos;
    const m = NUMBER.exec(this.text);
    if (m === null) return this.fail("expecting value");
    const lit = m[0];
    this.pos += lit.length;
    if (m[1] === undefined && m[2] === undefined) {
      if (lit.replace("-", "").length > MAX_INT_DIGITS) this.fail("integer literal too long");
      const n = Number(lit);
      return Number.isSafeInteger(n) ? n : new JsonNumber("int", n, lit);
    }
    const f = Number(lit);
    return Number.isInteger(f) || !Number.isFinite(f) ? new JsonNumber("float", f, lit) : f;
  }

  private string(): string {
    const t = this.text;
    this.pos++; // opening quote
    let out = "";
    let start = this.pos;
    for (;;) {
      if (this.pos >= t.length) this.fail("unterminated string");
      const c = t.charCodeAt(this.pos);
      if (c === 0x22) {
        out += t.slice(start, this.pos);
        this.pos++;
        return out;
      }
      if (c < 0x20) this.fail("invalid control character in string");
      if (c !== 0x5c) {
        this.pos++;
        continue;
      }
      out += t.slice(start, this.pos);
      const e = t[this.pos + 1];
      this.pos += 2;
      switch (e) {
        case '"':
        case "\\":
        case "/":
          out += e;
          break;
        case "b":
          out += "\b";
          break;
        case "f":
          out += "\f";
          break;
        case "n":
          out += "\n";
          break;
        case "r":
          out += "\r";
          break;
        case "t":
          out += "\t";
          break;
        case "u": {
          const hex = t.slice(this.pos, this.pos + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail("invalid \\u escape");
          out += String.fromCharCode(parseInt(hex, 16));
          this.pos += 4;
          break;
        }
        default:
          this.pos -= 2;
          this.fail("invalid escape");
      }
      start = this.pos;
    }
  }

  private array(): Json[] {
    this.pos++;
    const out: Json[] = [];
    this.ws();
    if (this.text[this.pos] === "]") {
      this.pos++;
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.value());
      this.ws();
      const c = this.text[this.pos++];
      if (c === "]") return out;
      if (c !== ",") {
        this.pos--;
        this.fail("expecting ',' or ']'");
      }
    }
  }

  private object(): JsonObject {
    this.pos++;
    const out: JsonObject = {};
    this.ws();
    if (this.text[this.pos] === "}") {
      this.pos++;
      return out;
    }
    for (;;) {
      this.ws();
      if (this.text[this.pos] !== '"') this.fail("expecting property name");
      const key = this.string();
      this.ws();
      if (this.text[this.pos] !== ":") this.fail("expecting ':'");
      this.pos++;
      this.ws();
      // defineProperty keeps "__proto__" an ordinary key, as JSON.parse does;
      // a repeated key keeps its first position and takes the last value, as in Python.
      Object.defineProperty(out, key, { value: this.value(), enumerable: true, writable: true, configurable: true });
      this.ws();
      const c = this.text[this.pos++];
      if (c === "}") return out;
      if (c !== ",") {
        this.pos--;
        this.fail("expecting ',' or '}'");
      }
    }
  }
}

// ---------------------------------------------------------------- Python value semantics

/**
 * `isinstance(v, dict)` for values that came out of JSON: a plain object from
 * any realm (its prototype is an `Object.prototype` or null), never a class
 * instance such as `JsonNumber` or `Uint8Array`.
 */
export function isDict(v: unknown): v is JsonObject {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === null || Object.getPrototypeOf(proto) === null;
}

/** `key in d` (own keys only, so `constructor` and friends never leak in). */
export function has(d: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(d, key);
}

/** `d.get(key)`: undefined when absent. */
export function get(d: object, key: string): unknown {
  return has(d, key) ? (d as Record<string, unknown>)[key] : undefined;
}

/** Python's `x is None` for a value read with `get`. */
export function isNone(v: unknown): v is null | undefined {
  return v === null || v === undefined;
}

/** A JSON integer in [0, 2^53 - 1] (bools and float literals excluded). */
export function isUint(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= MAX_UINT;
}

/** Python truthiness of a JSON value. */
export function pyTruthy(v: unknown): boolean {
  if (isNone(v) || v === false || v === "" || v === 0) return false;
  if (v instanceof JsonNumber) return v.value !== 0; // NaN is truthy in Python too
  if (Array.isArray(v)) return v.length > 0;
  if (isDict(v)) return Object.keys(v).length > 0;
  return true;
}

// ---------------------------------------------------------------- repr

const NON_PRINTABLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]/u;

function reprStr(s: string): string {
  const quote = s.includes("'") && !s.includes('"') ? '"' : "'";
  let out = quote;
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (ch === "\\" || ch === quote) out += "\\" + ch;
    else if (ch === "\t") out += "\\t";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch !== " " && NON_PRINTABLE.test(ch)) {
      if (cp < 0x100) out += "\\x" + cp.toString(16).padStart(2, "0");
      else if (cp < 0x10000) out += "\\u" + cp.toString(16).padStart(4, "0");
      else out += "\\U" + cp.toString(16).padStart(8, "0");
    } else out += ch;
  }
  return out + quote;
}

function reprFloat(f: number): string {
  if (Number.isNaN(f)) return "nan";
  if (!Number.isFinite(f)) return f > 0 ? "inf" : "-inf";
  const sign = f < 0 || Object.is(f, -0) ? "-" : "";
  if (f === 0) return sign + "0.0";
  const [mant, expStr] = Math.abs(f).toExponential().split("e") as [string, string];
  const exp = Number(expStr);
  const digits = mant.replace(".", "");
  if (exp >= -4 && exp < 16) {
    if (exp < 0) return `${sign}0.${"0".repeat(-exp - 1)}${digits}`;
    const int = digits.slice(0, exp + 1).padEnd(exp + 1, "0");
    return `${sign}${int}.${digits.slice(exp + 1) || "0"}`;
  }
  const m = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
  return `${sign}${m}e${exp < 0 ? "-" : "+"}${String(Math.abs(exp)).padStart(2, "0")}`;
}

/** Python `repr()` of a JSON value, used verbatim in ladder details. */
export function pyRepr(v: unknown): string {
  if (isNone(v)) return "None";
  if (v === true) return "True";
  if (v === false) return "False";
  if (typeof v === "string") return reprStr(v);
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : reprFloat(v);
  if (v instanceof JsonNumber) return v.kind === "int" ? v.literal : reprFloat(v.value);
  if (Array.isArray(v)) return `[${v.map(pyRepr).join(", ")}]`;
  if (isDict(v)) return `{${Object.entries(v).map(([k, x]) => `${reprStr(k)}: ${pyRepr(x)}`).join(", ")}}`;
  return String(v);
}
