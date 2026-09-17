import { createHash } from "node:crypto";
import { sha256Bytes } from "../canonical.js";
import type {
  InteropIssue,
  InteropVerification,
  ParsedContentDigest,
  RawBodyDigestVerification,
} from "./types.js";
import { UcpAp2ParseError } from "./parse-error.js";
import { decodeBase64, digestEquals, finish, upstreamIssue } from "./primitives.js";

/**
 * RFC 9530 sha-256 Content-Digest parsing and raw-body digest verification.
 * The adapter accepts exactly one sha-256 byte sequence per header value.
 */

/** Parse the UCP-required RFC 9530 sha-256 Content-Digest profile. */
export function parseContentDigest(value: string): ParsedContentDigest {
  if (typeof value !== "string") {
    throw new UcpAp2ParseError("Content-Digest must be a string");
  }
  const match = /^\s*sha-256=:([A-Za-z0-9+/]*={0,2}):\s*$/.exec(value);
  if (match === null || match[1] === undefined) {
    throw new UcpAp2ParseError("Content-Digest must contain exactly one sha-256 byte sequence");
  }
  const digest = decodeBase64(match[1], "Content-Digest.sha-256");
  if (digest.byteLength !== 32) {
    throw new UcpAp2ParseError("Content-Digest sha-256 value must be 32 bytes");
  }
  return Object.freeze({ algorithm: "sha-256", digest, exact: value });
}

export function verifyRawBodyContentDigest(
  rawBody: Uint8Array,
  contentDigest: string,
): InteropVerification<RawBodyDigestVerification> {
  const issues: InteropIssue[] = [];
  try {
    const parsed = parseContentDigest(contentDigest);
    const actual = createHash("sha256").update(rawBody).digest();
    if (!digestEquals(actual, parsed.digest)) {
      issues.push(upstreamIssue(
        "UCP_CONTENT_DIGEST_MISMATCH",
        "content-digest",
        "Content-Digest does not match the exact raw body bytes",
      ));
    }
  } catch (error) {
    issues.push(upstreamIssue(
      "UCP_CONTENT_DIGEST_INVALID",
      "content-digest",
      error instanceof Error ? error.message : "Invalid Content-Digest",
    ));
  }
  return finish(
    Object.freeze({ contentDigest, rawBodyDigest: sha256Bytes(rawBody) }),
    issues,
  );
}
