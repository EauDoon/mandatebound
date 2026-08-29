import { Buffer } from "node:buffer";
import { createHash, timingSafeEqual } from "node:crypto";
import { types } from "node:util";
import type { Sha256Digest, ValidationErrorCode } from "./domain.js";

export interface CanonicalLimits {
  readonly maxDepth: number;
  readonly maxNodes: number;
  readonly maxBytes: number;
}

const DEFAULT_LIMITS: CanonicalLimits = Object.freeze({
  maxDepth: 32,
  maxNodes: 100_000,
  maxBytes: 1_048_576,
});

const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;

export class CanonicalizationError extends Error {
  public readonly code: ValidationErrorCode = "ALB_CANONICAL_UNSUPPORTED";

  public constructor(message: string) {
    super(message);
    this.name = "CanonicalizationError";
  }
}

function ensureUnicodeScalarString(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const low = value.charCodeAt(index + 1);
      if (!(low >= 0xdc00 && low <= 0xdfff)) {
        throw new CanonicalizationError("Unpaired Unicode surrogate is not canonicalizable");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new CanonicalizationError("Unpaired Unicode surrogate is not canonicalizable");
    }
  }
}

interface Counter {
  nodes: number;
}

function serialize(value: unknown, depth: number, limits: CanonicalLimits, counter: Counter): string {
  if (depth > limits.maxDepth) {
    throw new CanonicalizationError("Maximum canonical JSON depth exceeded");
  }
  counter.nodes += 1;
  if (counter.nodes > limits.maxNodes) {
    throw new CanonicalizationError("Maximum canonical JSON node count exceeded");
  }

  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "string") {
    ensureUnicodeScalarString(value);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new CanonicalizationError("Only safe integers are supported by canonical protocol JSON");
    }
    return Object.is(value, -0) ? "0" : JSON.stringify(value);
  }
  if (types.isProxy(value)) {
    throw new CanonicalizationError("Proxy values are not canonicalizable");
  }
  if (Array.isArray(value)) {
    if (value.length > limits.maxNodes - counter.nodes) {
      throw new CanonicalizationError("Maximum canonical JSON node count exceeded");
    }
    if (
      Object.getPrototypeOf(value) !== Array.prototype ||
      Reflect.ownKeys(value).length !== value.length + 1
    ) {
      throw new CanonicalizationError("Only plain dense JSON arrays are canonicalizable");
    }
    const parts: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
        throw new CanonicalizationError("Sparse and accessor-backed arrays are not canonicalizable");
      }
      parts.push(serialize(descriptor.value, depth + 1, limits, counter));
    }
    return `[${parts.join(",")}]`;
  }
  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value) as unknown;
    if (prototype !== Object.prototype && prototype !== null) {
      throw new CanonicalizationError("Only plain JSON objects are canonicalizable");
    }
    if (Object.getOwnPropertySymbols(value).length !== 0) {
      throw new CanonicalizationError("Symbol keys are not canonicalizable");
    }
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort(); // RFC 8785: UTF-16 code-unit ordering.
    if (Object.getOwnPropertyNames(record).length !== keys.length) {
      throw new CanonicalizationError("Non-enumerable properties are not canonicalizable");
    }
    const parts: string[] = [];
    for (const key of keys) {
      ensureUnicodeScalarString(key);
      if (UNSAFE_KEYS.has(key)) {
        throw new CanonicalizationError("Unsafe object key is not canonicalizable");
      }
      const descriptor = Object.getOwnPropertyDescriptor(record, key);
      if (descriptor === undefined || !descriptor.enumerable || descriptor.get !== undefined || descriptor.set !== undefined) {
        throw new CanonicalizationError("Accessor and non-enumerable properties are not canonicalizable");
      }
      parts.push(`${JSON.stringify(key)}:${serialize(record[key], depth + 1, limits, counter)}`);
    }
    return `{${parts.join(",")}}`;
  }
  throw new CanonicalizationError("Unsupported value in canonical protocol JSON");
}

function resolveLimits(overrides?: Partial<CanonicalLimits>): CanonicalLimits {
  const limits = { ...DEFAULT_LIMITS, ...overrides };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new TypeError(`Invalid canonicalization limit: ${name}`);
    }
  }
  return limits;
}

/** RFC 8785-compatible canonical JSON for the protocol's safe-integer I-JSON subset. */
export function canonicalize(value: unknown, overrides?: Partial<CanonicalLimits>): string {
  const limits = resolveLimits(overrides);
  const result = serialize(value, 0, limits, { nodes: 0 });
  if (Buffer.byteLength(result, "utf8") > limits.maxBytes) {
    throw new CanonicalizationError("Maximum canonical JSON byte length exceeded");
  }
  return result;
}

export function canonicalBytes(value: unknown, overrides?: Partial<CanonicalLimits>): Uint8Array {
  return Buffer.from(canonicalize(value, overrides), "utf8");
}

export function assertCanonicalizable(value: unknown, overrides?: Partial<CanonicalLimits>): void {
  canonicalize(value, overrides);
}

export function sha256Bytes(bytes: Uint8Array): Sha256Digest {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

/** Strings are hashed as UTF-8 bytes; all other non-byte inputs are canonicalized. */
export function sha256Digest(value: unknown): Sha256Digest {
  if (typeof value === "string") {
    return sha256Bytes(Buffer.from(value, "utf8"));
  }
  if (value instanceof Uint8Array) {
    return sha256Bytes(value);
  }
  return sha256Bytes(canonicalBytes(value));
}

export function contentId(value: unknown): Sha256Digest {
  return sha256Digest(value);
}

export function isSha256Digest(value: unknown): value is Sha256Digest {
  return typeof value === "string" && SHA256_PATTERN.test(value);
}

export function digestBytes(digest: Sha256Digest): Uint8Array {
  if (!isSha256Digest(digest)) {
    throw new TypeError("Invalid SHA-256 content identifier");
  }
  return Buffer.from(digest.slice("sha256:".length), "hex");
}

export function equalDigest(left: Sha256Digest, right: Sha256Digest): boolean {
  if (!isSha256Digest(left) || !isSha256Digest(right)) return false;
  return timingSafeEqual(digestBytes(left), digestBytes(right));
}
