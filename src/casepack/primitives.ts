import { Buffer } from "node:buffer";
import {
  canonicalBytes,
  isSha256Digest,
  sha256Bytes,
} from "../canonical.js";
import type {
  AsciiIdentifier,
  Rfc3339Timestamp,
  Sha256Digest,
  ValidationIssue,
} from "../domain.js";
import { CASEPACK_STATUSES, type CasePackStatus } from "./types.js";

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
export const SEMVER_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+$/;
export const MEDIA_TYPE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]+$/;
export const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
export const JSON_POINTER_PATTERN = /^(?:|\/(?:[^~/]|~0|~1)*)$/;
const CASEPACK_CANONICAL_LIMITS = Object.freeze({
  maxDepth: 48,
  maxNodes: 250_000,
  maxBytes: 16_777_216,
});
export const MAX_PROTOCOL_EVIDENCE = 1_024;
export const MAX_CHECKPOINTS = 1_024;
export const MAX_RAW_EVIDENCE_BYTES = 16_777_216;
export const MAX_TOTAL_RAW_EVIDENCE_BYTES = 67_108_864;
export const MAX_ISSUES = 128;
export const CHECKPOINT_DOMAIN = Buffer.from("MANDATEBOUND-SOURCE-CHECKPOINT-V1\0", "ascii");

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

export function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort(compareAscii);
  const wanted = [...expected].sort(compareAscii);
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

export function expectedKeys(required: readonly string[], value: Record<string, unknown>, optional: readonly string[]): string[] {
  return [...required, ...optional.filter((key) => Object.hasOwn(value, key))];
}

export function addIssue(
  issues: ValidationIssue[],
  path: string,
  code: string,
  message: string,
): void {
  if (issues.length < MAX_ISSUES) issues.push({ path, code, message });
}

export function isIdentifier(value: unknown): value is AsciiIdentifier {
  return typeof value === "string" && IDENTIFIER_PATTERN.test(value);
}

export function isTimestamp(value: unknown): value is Rfc3339Timestamp {
  if (typeof value !== "string" || value.length !== 24 || value[19] !== "." || value[23] !== "Z") {
    return false;
  }
  const parsed = new Date(value);
  return !Number.isNaN(parsed.valueOf()) && parsed.toISOString() === value;
}

export function timestampMillis(value: Rfc3339Timestamp): number {
  return new Date(value).valueOf();
}

export function isMediaType(value: unknown): value is string {
  return typeof value === "string" && value.length <= 160 && MEDIA_TYPE_PATTERN.test(value);
}

export function isBoundedInteger(value: unknown, minimum: number, maximum: number): value is number {
  return Number.isSafeInteger(value) && (value as number) >= minimum && (value as number) <= maximum;
}

export function isStatus(value: unknown): value is CasePackStatus {
  return typeof value === "string" && CASEPACK_STATUSES.includes(value as CasePackStatus);
}

export function digestCanonical(value: unknown): Sha256Digest {
  return sha256Bytes(canonicalBytes(value, CASEPACK_CANONICAL_LIMITS));
}

export function envelopeMaterial(value: unknown): unknown {
  return value;
}

export function mappingMaterial(value: unknown): unknown {
  return value;
}

export function externalTrustMaterial(value: unknown): unknown {
  return value;
}

export function delegationMaterial(value: unknown): unknown {
  return value;
}

export function coverageMaterial(value: unknown): unknown {
  return value;
}

export function checkpointMaterial(value: unknown): unknown {
  return value;
}

export function casePackMaterial(value: unknown): unknown {
  return value;
}

export function withoutProperty<T extends object, K extends PropertyKey>(
  value: T,
  property: K,
): Omit<T, K> {
  const result: Record<PropertyKey, unknown> = {};
  for (const key of Reflect.ownKeys(value)) {
    if (key !== property) result[key] = (value as Record<PropertyKey, unknown>)[key];
  }
  return result as Omit<T, K>;
}

export { isSha256Digest };
