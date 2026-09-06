import {
  canonicalize,
  equalDigest,
  isSha256Digest,
  sha256Bytes,
  sha256Digest,
} from "./canonical.js";
import type { Sha256Digest } from "./domain.js";

export const EXTERNAL_REVIEW_FORMAT = "MandateBoundExternalEvidenceReview/v1";
export const EXTERNAL_REVIEW_SOURCE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
export const EXTERNAL_REVIEW_MAX_EVIDENCE_BYTES = 1_048_576;
const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;
const MEDIA_TYPE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]+$/;

export type ExternalReviewVerdict = "recorded" | "conflicting" | "unsupported";

export interface ExternalReviewSource {
  readonly sourceId: string;
  readonly eventClass: string;
}

export interface ExternalReviewEvidence {
  readonly mediaType: string;
  readonly bytesBase64: string;
  readonly digest: Sha256Digest;
  readonly byteLength: number;
}

export interface ExternalReviewAnchors {
  readonly expectedDigest: Sha256Digest;
}

export interface ExternalReviewUpstream {
  readonly verifier: string;
  readonly valid: boolean;
  readonly actionId: string;
  readonly outcome: string;
  readonly trustedKeyIds: readonly string[];
}

export interface ExternalReviewInput {
  readonly source: ExternalReviewSource;
  readonly evidence: ExternalReviewEvidence;
  readonly anchors: ExternalReviewAnchors;
  readonly upstream: ExternalReviewUpstream;
}

export interface ExternalReviewReceipt {
  readonly receiptId: string;
  readonly outcome: string;
  readonly recourseStatus: string;
  readonly eventChainHead: string;
  readonly actionDigest: string;
}

export interface ExternalEvidenceReview {
  readonly format: typeof EXTERNAL_REVIEW_FORMAT;
  readonly reviewId: string;
  readonly source: ExternalReviewSource;
  readonly actionId: string;
  readonly evidenceDigest: Sha256Digest;
  readonly receipt: ExternalReviewReceipt;
  readonly upstream: ExternalReviewUpstream;
  readonly verdict: ExternalReviewVerdict;
  readonly legalEffect: "not-determined";
  readonly reviewDigest: Sha256Digest;
}

export class ReviewInputError extends Error {
  readonly code = "REVIEW_INPUT_INVALID";
  constructor(message: string) {
    super(message);
    this.name = "ReviewInputError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function requireRecord(value: unknown, field: string): Record<string, unknown> {
  if (!isRecord(value)) throw new ReviewInputError(`${field} must be an object.`);
  return value;
}

function requireExactKeys(record: Record<string, unknown>, keys: readonly string[], field: string): void {
  const actual = Object.keys(record);
  if (actual.length !== keys.length || !keys.every((key) => Object.hasOwn(record, key))) {
    throw new ReviewInputError(`${field} must contain exactly: ${keys.join(", ")}.`);
  }
}

function requireIdentifier(value: unknown, field: string): string {
  if (typeof value !== "string" || !EXTERNAL_REVIEW_SOURCE_ID_PATTERN.test(value)) {
    throw new ReviewInputError(`${field} must be an ASCII identifier.`);
  }
  return value;
}

function requireDigest(value: unknown, field: string): Sha256Digest {
  if (!isSha256Digest(value)) throw new ReviewInputError(`${field} must be a sha256 digest.`);
  return value;
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ReviewInputError(`${field} must be a non-empty string.`);
  }
  return value;
}

function decodeEvidenceBytes(value: unknown): Uint8Array {
  if (typeof value !== "string" || value.length === 0 || value.length > EXTERNAL_REVIEW_MAX_EVIDENCE_BYTES * 2) {
    throw new ReviewInputError("evidence.bytesBase64 is invalid.");
  }
  if (!BASE64_PATTERN.test(value) || value.length % 4 !== 0) {
    throw new ReviewInputError("evidence.bytesBase64 is invalid.");
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) {
    throw new ReviewInputError("evidence.bytesBase64 is invalid.");
  }
  if (bytes.length === 0 || bytes.length > EXTERNAL_REVIEW_MAX_EVIDENCE_BYTES) {
    throw new ReviewInputError("evidence.bytesBase64 is invalid.");
  }
  return bytes;
}

function parseInput(value: unknown): { parsed: ExternalReviewInput; bytes: Uint8Array } {
  const record = requireRecord(value, "Review input");
  requireExactKeys(record, ["source", "evidence", "anchors", "upstream"], "Review input");
  const sourceRecord = requireRecord(record["source"], "source");
  requireExactKeys(sourceRecord, ["sourceId", "eventClass"], "source");
  const evidenceRecord = requireRecord(record["evidence"], "evidence");
  requireExactKeys(evidenceRecord, ["mediaType", "bytesBase64", "digest", "byteLength"], "evidence");
  const anchorsRecord = requireRecord(record["anchors"], "anchors");
  requireExactKeys(anchorsRecord, ["expectedDigest"], "anchors");
  const upstreamRecord = requireRecord(record["upstream"], "upstream");
  requireExactKeys(
    upstreamRecord,
    ["verifier", "valid", "actionId", "outcome", "trustedKeyIds"],
    "upstream",
  );
  const mediaType = requireString(evidenceRecord["mediaType"], "evidence.mediaType");
  if (!MEDIA_TYPE_PATTERN.test(mediaType)) {
    throw new ReviewInputError("evidence.mediaType is invalid.");
  }
  if (typeof evidenceRecord["byteLength"] !== "number" || !Number.isInteger(evidenceRecord["byteLength"])) {
    throw new ReviewInputError("evidence.byteLength must be an integer.");
  }
  if (typeof upstreamRecord["valid"] !== "boolean") {
    throw new ReviewInputError("upstream.valid must be a boolean.");
  }
  if (!Array.isArray(upstreamRecord["trustedKeyIds"]) || upstreamRecord["trustedKeyIds"].some((key) => typeof key !== "string")) {
    throw new ReviewInputError("upstream.trustedKeyIds must be an array of strings.");
  }
  const bytes = decodeEvidenceBytes(evidenceRecord["bytesBase64"]);
  return {
    parsed: {
      source: {
        sourceId: requireIdentifier(sourceRecord["sourceId"], "source.sourceId"),
        eventClass: requireIdentifier(sourceRecord["eventClass"], "source.eventClass"),
      },
      evidence: {
        mediaType,
        bytesBase64: evidenceRecord["bytesBase64"] as string,
        digest: requireDigest(evidenceRecord["digest"], "evidence.digest"),
        byteLength: evidenceRecord["byteLength"] as number,
      },
      anchors: { expectedDigest: requireDigest(anchorsRecord["expectedDigest"], "anchors.expectedDigest") },
      upstream: {
        verifier: requireIdentifier(upstreamRecord["verifier"], "upstream.verifier"),
        valid: upstreamRecord["valid"] as boolean,
        actionId: requireString(upstreamRecord["actionId"], "upstream.actionId"),
        outcome: requireString(upstreamRecord["outcome"], "upstream.outcome"),
        trustedKeyIds: [...(upstreamRecord["trustedKeyIds"] as string[])],
      },
    },
    bytes,
  };
}

interface ExtractedReceipt {
  readonly receipt: ExternalReviewReceipt;
  readonly actionId: string;
  readonly bound: boolean;
}

function extractReceipt(bytes: Uint8Array): ExtractedReceipt | null {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  let bundle: unknown;
  try {
    bundle = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(bundle)) return null;
  const action = bundle["action"];
  const receipt = bundle["settlement_receipt"];
  if (!isRecord(action) || !isRecord(receipt)) return null;
  const fields: Record<string, unknown> = {
    actionId: action["action_id"],
    receiptActionId: receipt["action_id"],
    receiptId: receipt["receipt_id"],
    outcome: receipt["outcome"],
    recourseStatus: receipt["recourse_final_status"],
    eventChainHead: receipt["event_chain_head"],
    actionDigest: receipt["action_digest"],
  };
  if (
    Object.values(fields).some((field) => typeof field !== "string" || (field as string).length === 0)
  ) {
    return null;
  }
  return {
    receipt: {
      receiptId: fields["receiptId"] as string,
      outcome: fields["outcome"] as string,
      recourseStatus: fields["recourseStatus"] as string,
      eventChainHead: fields["eventChainHead"] as string,
      actionDigest: fields["actionDigest"] as string,
    },
    actionId: fields["actionId"] as string,
    bound: fields["receiptActionId"] === fields["actionId"],
  };
}

export function reviewExternalEvidence(input: unknown): ExternalEvidenceReview {
  const { parsed, bytes } = parseInput(input);
  if (parsed.evidence.mediaType !== "application/json") {
    return buildReview(parsed, sha256Bytes(bytes), "unsupported", null);
  }
  if (bytes.length !== parsed.evidence.byteLength) {
    return buildReview(parsed, sha256Bytes(bytes), "conflicting", null);
  }
  const computed = sha256Bytes(bytes);
  if (!equalDigest(computed, parsed.evidence.digest) || !equalDigest(computed, parsed.anchors.expectedDigest)) {
    return buildReview(parsed, computed, "conflicting", null);
  }
  const extracted = extractReceipt(bytes);
  if (extracted === null) {
    return buildReview(parsed, computed, "unsupported", null);
  }
  if (!extracted.bound || extracted.actionId !== parsed.upstream.actionId || extracted.receipt.outcome !== parsed.upstream.outcome) {
    return buildReview(parsed, computed, "conflicting", extracted.receipt);
  }
  return buildReview(parsed, computed, "recorded", extracted.receipt);
}

function buildReview(
  parsed: ExternalReviewInput,
  computed: Sha256Digest,
  verdict: ExternalReviewVerdict,
  receipt: ExternalReviewReceipt | null,
): ExternalEvidenceReview {
  const actionId = parsed.upstream.actionId;
  const reviewId = `review-${sha256Digest(`${parsed.source.sourceId}:${parsed.source.eventClass}:${computed}:${actionId}`).slice("sha256:".length, "sha256:".length + 16)}`;
  const settled: ExternalReviewReceipt = receipt === null
    ? { receiptId: "", outcome: "", recourseStatus: "", eventChainHead: "", actionDigest: "" }
    : { ...receipt };
  const body = {
    format: EXTERNAL_REVIEW_FORMAT,
    reviewId,
    source: { ...parsed.source },
    actionId,
    evidenceDigest: computed,
    receipt: settled,
    upstream: {
      ...parsed.upstream,
      trustedKeyIds: [...parsed.upstream.trustedKeyIds],
    },
    verdict,
    legalEffect: "not-determined",
  } as const;
  return { ...body, reviewDigest: sha256Digest(canonicalize(body)) };
}
