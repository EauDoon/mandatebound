import { Buffer } from "node:buffer";
import type { JsonValue, ValidationErrorCode } from "./domain.js";

export interface StrictJsonLimits {
  readonly maxBytes: number;
  readonly maxDepth: number;
  readonly maxArrayLength: number;
  readonly maxObjectKeys: number;
  readonly maxStringBytes: number;
  readonly maxNodes: number;
}

export const DEFAULT_STRICT_JSON_LIMITS: StrictJsonLimits = Object.freeze({
  maxBytes: 1_048_576,
  maxDepth: 32,
  maxArrayLength: 10_000,
  maxObjectKeys: 10_000,
  maxStringBytes: 262_144,
  maxNodes: 100_000,
});

const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

export class StrictJsonError extends Error {
  public readonly code: ValidationErrorCode;
  public readonly offset: number;

  public constructor(code: ValidationErrorCode, offset: number, message: string) {
    super(`${message} (offset ${offset})`);
    this.name = "StrictJsonError";
    this.code = code;
    this.offset = offset;
  }
}

function resolveLimits(overrides: Partial<StrictJsonLimits> | undefined): StrictJsonLimits {
  const limits = { ...DEFAULT_STRICT_JSON_LIMITS, ...overrides };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new TypeError(`Invalid strict JSON limit: ${name}`);
    }
  }
  return limits;
}

class Parser {
  readonly #text: string;
  readonly #limits: StrictJsonLimits;
  #index = 0;
  #nodes = 0;

  public constructor(text: string, limits: StrictJsonLimits) {
    this.#text = text;
    this.#limits = limits;
  }

  public parse(): JsonValue {
    if (this.#text.length > 0 && this.#text.charCodeAt(0) === 0xfeff) {
      this.#fail("ALB_JSON_INVALID", "A JSON byte-order mark is not accepted");
    }
    this.#skipWhitespace();
    const value = this.#parseValue(0);
    this.#skipWhitespace();
    if (this.#index !== this.#text.length) {
      this.#fail("ALB_JSON_INVALID", "Unexpected trailing JSON content");
    }
    return value;
  }

  #parseValue(depth: number): JsonValue {
    if (depth > this.#limits.maxDepth) {
      this.#fail("ALB_JSON_LIMIT", "Maximum JSON nesting depth exceeded");
    }
    this.#nodes += 1;
    if (this.#nodes > this.#limits.maxNodes) {
      this.#fail("ALB_JSON_LIMIT", "Maximum JSON node count exceeded");
    }

    const char = this.#text[this.#index];
    switch (char) {
      case "{":
        return this.#parseObject(depth);
      case "[":
        return this.#parseArray(depth);
      case "\"":
        return this.#parseString();
      case "t":
        this.#expectLiteral("true");
        return true;
      case "f":
        this.#expectLiteral("false");
        return false;
      case "n":
        this.#expectLiteral("null");
        return null;
      default:
        if (char === "-" || (char !== undefined && char >= "0" && char <= "9")) {
          return this.#parseNumber();
        }
        this.#fail("ALB_JSON_INVALID", "Expected a JSON value");
    }
  }

  #parseObject(depth: number): JsonValue {
    this.#index += 1;
    this.#skipWhitespace();
    const object: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
    const keys = new Set<string>();
    if (this.#consume("}")) {
      return object;
    }

    while (true) {
      if (this.#text[this.#index] !== "\"") {
        this.#fail("ALB_JSON_INVALID", "Expected an object key");
      }
      const keyOffset = this.#index;
      const key = this.#parseString();
      if (UNSAFE_KEYS.has(key)) {
        throw new StrictJsonError("ALB_JSON_UNSAFE_KEY", keyOffset, "Unsafe object key rejected");
      }
      if (keys.has(key)) {
        throw new StrictJsonError("ALB_JSON_DUPLICATE_KEY", keyOffset, "Duplicate object key rejected");
      }
      keys.add(key);
      if (keys.size > this.#limits.maxObjectKeys) {
        this.#fail("ALB_JSON_LIMIT", "Maximum object key count exceeded");
      }
      this.#skipWhitespace();
      if (!this.#consume(":")) {
        this.#fail("ALB_JSON_INVALID", "Expected a colon after an object key");
      }
      this.#skipWhitespace();
      object[key] = this.#parseValue(depth + 1);
      this.#skipWhitespace();
      if (this.#consume("}")) {
        return object;
      }
      if (!this.#consume(",")) {
        this.#fail("ALB_JSON_INVALID", "Expected a comma or object terminator");
      }
      this.#skipWhitespace();
    }
  }

  #parseArray(depth: number): JsonValue {
    this.#index += 1;
    this.#skipWhitespace();
    const array: JsonValue[] = [];
    if (this.#consume("]")) {
      return array;
    }
    while (true) {
      if (array.length >= this.#limits.maxArrayLength) {
        this.#fail("ALB_JSON_LIMIT", "Maximum array length exceeded");
      }
      array.push(this.#parseValue(depth + 1));
      this.#skipWhitespace();
      if (this.#consume("]")) {
        return array;
      }
      if (!this.#consume(",")) {
        this.#fail("ALB_JSON_INVALID", "Expected a comma or array terminator");
      }
      this.#skipWhitespace();
    }
  }

  #parseString(): string {
    this.#index += 1;
    let output = "";
    while (this.#index < this.#text.length) {
      const code = this.#text.charCodeAt(this.#index);
      if (code === 0x22) {
        this.#index += 1;
        if (Buffer.byteLength(output, "utf8") > this.#limits.maxStringBytes) {
          this.#fail("ALB_JSON_LIMIT", "Maximum JSON string length exceeded");
        }
        return output;
      }
      if (code === 0x5c) {
        this.#index += 1;
        output += this.#parseEscape();
        continue;
      }
      if (code < 0x20) {
        this.#fail("ALB_JSON_INVALID", "Unescaped control character in JSON string");
      }
      if (code >= 0xd800 && code <= 0xdbff) {
        const low = this.#text.charCodeAt(this.#index + 1);
        if (!(low >= 0xdc00 && low <= 0xdfff)) {
          this.#fail("ALB_JSON_UNPAIRED_SURROGATE", "Unpaired Unicode surrogate rejected");
        }
        output += this.#text.slice(this.#index, this.#index + 2);
        this.#index += 2;
        continue;
      }
      if (code >= 0xdc00 && code <= 0xdfff) {
        this.#fail("ALB_JSON_UNPAIRED_SURROGATE", "Unpaired Unicode surrogate rejected");
      }
      output += this.#text[this.#index] as string;
      this.#index += 1;
    }
    this.#fail("ALB_JSON_INVALID", "Unterminated JSON string");
  }

  #parseEscape(): string {
    const escaped = this.#text[this.#index];
    this.#index += 1;
    switch (escaped) {
      case "\"": return "\"";
      case "\\": return "\\";
      case "/": return "/";
      case "b": return "\b";
      case "f": return "\f";
      case "n": return "\n";
      case "r": return "\r";
      case "t": return "\t";
      case "u": {
        const high = this.#readHexCodeUnit();
        if (high >= 0xd800 && high <= 0xdbff) {
          if (this.#text.slice(this.#index, this.#index + 2) !== "\\u") {
            this.#fail("ALB_JSON_UNPAIRED_SURROGATE", "Unpaired Unicode surrogate rejected");
          }
          this.#index += 2;
          const low = this.#readHexCodeUnit();
          if (!(low >= 0xdc00 && low <= 0xdfff)) {
            this.#fail("ALB_JSON_UNPAIRED_SURROGATE", "Unpaired Unicode surrogate rejected");
          }
          return String.fromCodePoint(0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00));
        }
        if (high >= 0xdc00 && high <= 0xdfff) {
          this.#fail("ALB_JSON_UNPAIRED_SURROGATE", "Unpaired Unicode surrogate rejected");
        }
        return String.fromCharCode(high);
      }
      default:
        this.#fail("ALB_JSON_INVALID", "Invalid JSON escape sequence");
    }
  }

  #readHexCodeUnit(): number {
    const value = this.#text.slice(this.#index, this.#index + 4);
    if (!/^[0-9A-Fa-f]{4}$/.test(value)) {
      this.#fail("ALB_JSON_INVALID", "Invalid Unicode escape sequence");
    }
    this.#index += 4;
    return Number.parseInt(value, 16);
  }

  #parseNumber(): number {
    const rest = this.#text.slice(this.#index);
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(rest);
    if (match === null) {
      this.#fail("ALB_JSON_INVALID", "Invalid JSON number");
    }
    const token = match[0];
    this.#index += token.length;
    if (token.includes(".") || token.includes("e") || token.includes("E")) {
      this.#fail("ALB_JSON_UNSAFE_NUMBER", "Only safe integers are accepted by this protocol");
    }
    const value = Number(token);
    if (!Number.isSafeInteger(value)) {
      this.#fail("ALB_JSON_UNSAFE_NUMBER", "JSON integer exceeds the safe range");
    }
    return Object.is(value, -0) ? 0 : value;
  }

  #expectLiteral(literal: string): void {
    if (this.#text.slice(this.#index, this.#index + literal.length) !== literal) {
      this.#fail("ALB_JSON_INVALID", "Invalid JSON literal");
    }
    this.#index += literal.length;
  }

  #skipWhitespace(): void {
    while (this.#index < this.#text.length) {
      const code = this.#text.charCodeAt(this.#index);
      if (code !== 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) {
        return;
      }
      this.#index += 1;
    }
  }

  #consume(expected: string): boolean {
    if (this.#text[this.#index] !== expected) {
      return false;
    }
    this.#index += 1;
    return true;
  }

  #fail(code: ValidationErrorCode, message: string): never {
    throw new StrictJsonError(code, this.#index, message);
  }
}

/** Parse JSON without the duplicate-key and prototype ambiguities of JSON.parse. */
export function parseStrictJson(
  text: string,
  overrides?: Partial<StrictJsonLimits>,
): JsonValue {
  if (typeof text !== "string") {
    throw new TypeError("Strict JSON input must be a string");
  }
  const limits = resolveLimits(overrides);
  if (Buffer.byteLength(text, "utf8") > limits.maxBytes) {
    throw new StrictJsonError("ALB_JSON_LIMIT", 0, "Maximum JSON byte length exceeded");
  }
  return new Parser(text, limits).parse();
}

export function parseStrictJsonObject(
  text: string,
  overrides?: Partial<StrictJsonLimits>,
): Record<string, JsonValue> {
  const parsed = parseStrictJson(text, overrides);
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new StrictJsonError("ALB_JSON_INVALID", 0, "Expected a top-level JSON object");
  }
  return parsed;
}
