import { Buffer } from "node:buffer";
import { createHash, timingSafeEqual } from "node:crypto";
import { TextDecoder } from "node:util";
import { canonicalize } from "../canonical.js";
import type { JsonObject, Sha256Digest } from "../domain.js";
import type { EcPublicJwk, InteropIssue, InteropVerification, JoseEcAlgorithm } from "./types.js";
import { UcpAp2ParseError } from "./parse-error.js";

/**
 * Low-level helpers shared across UCP/AP2 evidence modules: byte-decoding
 * guards, RFC 3339 parsing, JSON shape guards, the bounded InteropIssue /
 * InteropVerification builders, the JOSE algorithm allowlist helper, and the
 * canonical fingerprint and identity helpers used by JWS verification.
 */

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const RFC3339_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const RFC3339_PARTS_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](\d{2}):(\d{2}))$/;

export const STATE_CHANGING_METHODS: ReadonlySet<string> = new Set([
  "POST",
  "PUT",
  "DELETE",
  "PATCH",
]);

export const JOSE_ALGORITHMS: Readonly<Record<JoseEcAlgorithm, {
  readonly curve: EcPublicJwk["crv"];
  readonly hash: "sha256" | "sha384" | "sha512";
  readonly signatureLength: number;
  readonly coordinateLength: number;
}>> = Object.freeze({
  ES256: Object.freeze({ curve: "P-256", hash: "sha256", signatureLength: 64, coordinateLength: 32 }),
  ES384: Object.freeze({ curve: "P-384", hash: "sha384", signatureLength: 96, coordinateLength: 48 }),
  ES512: Object.freeze({ curve: "P-521", hash: "sha512", signatureLength: 132, coordinateLength: 66 }),
});

export function upstreamIssue(code: string, path: string, message: string): InteropIssue {
  return Object.freeze({ code, path, message, impact: "upstream_validity" });
}

export function eligibilityIssue(code: string, path: string, message: string): InteropIssue {
  return Object.freeze({ code, path, message, impact: "evidence_eligibility" });
}

export function finish<T>(value: T | null, issues: readonly InteropIssue[]): InteropVerification<T> {
  const upstreamValid = !issues.some((entry) => entry.impact === "upstream_validity");
  const evidenceEligible =
    upstreamValid && !issues.some((entry) => entry.impact === "evidence_eligibility");
  return Object.freeze({
    upstreamValid,
    evidenceEligible,
    value: upstreamValid ? value : null,
    issues: Object.freeze([...issues]),
  });
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function hasOwn(value: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

export function strictUtf8(bytes: Uint8Array): string {
  try {
    return UTF8_DECODER.decode(bytes);
  } catch {
    throw new UcpAp2ParseError("Input is not valid UTF-8");
  }
}

export function decodeBase64Url(value: string, path = "base64url"): Uint8Array {
  if (
    value.length === 0 ||
    !BASE64URL_PATTERN.test(value) ||
    value.length % 4 === 1 ||
    value.includes("=")
  ) {
    throw new UcpAp2ParseError(`Invalid unpadded base64url at ${path}`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) {
    throw new UcpAp2ParseError(`Non-canonical base64url at ${path}`);
  }
  return decoded;
}

export function decodeBase64(value: string, path = "base64"): Uint8Array {
  if (value.length === 0 || value.length % 4 !== 0 || !BASE64_PATTERN.test(value)) {
    throw new UcpAp2ParseError(`Invalid base64 at ${path}`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) {
    throw new UcpAp2ParseError(`Non-canonical base64 at ${path}`);
  }
  return decoded;
}

export function parseEpoch(value: string | number, path: string): number {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new UcpAp2ParseError(`Invalid epoch seconds at ${path}`);
    }
    return value;
  }
  return Math.floor(parseTimestampMillis(value, path) / 1_000);
}

export function parseTimestampMillis(value: string, path: string): number {
  const match = RFC3339_PATTERN.test(value) ? RFC3339_PARTS_PATTERN.exec(value) : null;
  if (match === null) {
    throw new UcpAp2ParseError(`Invalid RFC 3339 timestamp at ${path}`);
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = match[7] === undefined ? 0 : Number(match[7]);
  const offsetMinute = match[8] === undefined ? 0 : Number(match[8]);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > (daysInMonth[month - 1] ?? 0) ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59
  ) {
    throw new UcpAp2ParseError(`Invalid RFC 3339 timestamp at ${path}`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new UcpAp2ParseError(`Invalid RFC 3339 timestamp at ${path}`);
  }
  return parsed;
}

export function parseHttpsUrl(value: string, path: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new UcpAp2ParseError(`Invalid URL at ${path}`);
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== ""
  ) {
    throw new UcpAp2ParseError(`URL at ${path} must be a credential-free HTTPS URL`);
  }
  return parsed;
}

export function requireJsonObject(value: unknown, path: string): JsonObject {
  if (!isObject(value)) {
    throw new UcpAp2ParseError(`Expected JSON object at ${path}`);
  }
  return value as JsonObject;
}

export function requireString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new UcpAp2ParseError(`Expected non-empty string at ${path}`);
  }
  return value;
}

export function requireSafeInteger(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new UcpAp2ParseError(`Expected safe integer at ${path}`);
  }
  return value;
}

export function digestEquals(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && timingSafeEqual(left, right);
}

export function base64UrlSha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("base64url");
}

export function validateAllowedAlgorithms(
  allowed: readonly JoseEcAlgorithm[] | undefined,
  defaults: readonly JoseEcAlgorithm[],
): ReadonlySet<JoseEcAlgorithm> {
  const resolved = allowed ?? defaults;
  if (resolved.length === 0) {
    throw new UcpAp2ParseError("Algorithm allowlist must not be empty");
  }
  const result = new Set<JoseEcAlgorithm>();
  for (const algorithm of resolved) {
    if (!hasOwn(JOSE_ALGORITHMS, algorithm)) {
      throw new UcpAp2ParseError("Algorithm allowlist contains an unsupported value");
    }
    result.add(algorithm);
  }
  return result;
}

export function publicJwkIdentity(jwk: EcPublicJwk): string {
  return canonicalize({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
}
