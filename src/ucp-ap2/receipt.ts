import { Buffer } from "node:buffer";
import type { JsonObject } from "../domain.js";
import type {
  Ap2ReceiptKind,
  Ap2ReceiptStatus,
  InteropIssue,
  InteropVerification,
  JoseEcAlgorithm,
  ParsedJwt,
  VerifyAp2ReceiptOptions,
  VerifiedAp2Receipt,
} from "./types.js";
import { AP2_RECEIPT_KINDS, UCP_AP2_EVIDENCE_PROFILE } from "./profile.js";
import { UcpAp2ParseError } from "./parse-error.js";
import {
  base64UrlSha256,
  decodeBase64Url,
  eligibilityIssue,
  finish,
  parseEpoch,
  requireSafeInteger,
  requireString,
  upstreamIssue,
  validateAllowedAlgorithms,
} from "./primitives.js";
import {
  checkKeySnapshot,
  verifyParsedJwtSignature,
} from "./jwk.js";
import { parseJwtCompact } from "./jwt-parse.js";
import { parseAp2MandateChainSegments } from "./mandate-chain.js";

/**
 * AP2 Receipt verification plus the Receipt reference helpers used by the
 * dispute resolver to bind a Receipt JWT back to its terminal closed Mandate.
 */

function validateReceiptClaims(
  claims: JsonObject,
  kind: Ap2ReceiptKind,
  asOf: number,
  issues: InteropIssue[],
): {
  readonly issuer: string;
  readonly issuedAt: number;
  readonly status: Ap2ReceiptStatus;
  readonly reference: string;
} | null {
  let issuer = "";
  let issuedAt = 0;
  let status: Ap2ReceiptStatus = "Error";
  let reference = "";
  try {
    issuer = requireString(claims.iss, "receipt.claims.iss");
    issuedAt = requireSafeInteger(claims.iat, "receipt.claims.iat");
    if (issuedAt < 0) throw new UcpAp2ParseError("Receipt iat must not be negative");
    if (issuedAt > asOf + 60) {
      throw new UcpAp2ParseError("Receipt issuance time is in the future");
    }
    if (claims.status !== "Success" && claims.status !== "Error") {
      throw new UcpAp2ParseError("Receipt status is not Success or Error");
    }
    status = claims.status;
    reference = requireString(claims.reference, "receipt.claims.reference");
    if (decodeBase64Url(reference, "receipt.claims.reference").byteLength !== 32) {
      throw new UcpAp2ParseError("Receipt reference is not a SHA-256 digest");
    }

    if (status === "Error") {
      requireString(claims.error, "receipt.claims.error");
      requireString(claims.error_description, "receipt.claims.error_description");
      if (
        claims.order_id !== undefined ||
        claims.psp_confirmation_id !== undefined ||
        claims.network_confirmation_id !== undefined
      ) {
        throw new UcpAp2ParseError("Error Receipt contains a success-only claim");
      }
    } else {
      if (claims.error !== undefined || claims.error_description !== undefined) {
        throw new UcpAp2ParseError("Success Receipt contains an error claim");
      }
      if (kind === "checkout_receipt") {
        requireString(claims.order_id, "receipt.claims.order_id");
      }
      if (kind === "payment_receipt") {
        requireString(claims.psp_confirmation_id, "receipt.claims.psp_confirmation_id");
        requireString(claims.network_confirmation_id, "receipt.claims.network_confirmation_id");
      }
    }
    if (kind === "payment_receipt") {
      requireString(claims.payment_id, "receipt.claims.payment_id");
    }
  } catch (error) {
    issues.push(upstreamIssue(
      "AP2_RECEIPT_CLAIMS_INVALID",
      "receipt.claims",
      error instanceof Error ? error.message : "Receipt claims are invalid",
    ));
    return null;
  }
  return { issuer, issuedAt, status, reference };
}

/**
 * Compute the AP2 v0.2.0 SDK-compatible Receipt reference over the exact ASCII
 * bytes of the terminal compact JWS, before the first disclosure separator.
 * This deliberately supports one named reference profile instead of trying
 * multiple ambiguous hash representations until one passes.
 */
export function computeAp2MandateReference(token: string): string {
  if (token.includes("~~") || token.endsWith("~")) {
    const segments = parseAp2MandateChainSegments(token);
    const terminal = segments[segments.length - 1];
    if (terminal === undefined) throw new UcpAp2ParseError("AP2 Mandate chain is empty");
    return base64UrlSha256(terminal.issuerJwt.exactCompact);
  }
  // Compatibility for the pre-v1.2 additive adapter's non-AP2 trailing
  // key-binding form. Its only signed Mandate JWS is also its terminal JWS.
  return base64UrlSha256(parseJwtCompact(token, "token.issuerJwt").exactCompact);
}

/** Compute the AP2 sd_hash of the exact open root Mandate presentation. */
export function computeAp2OpenMandateHash(token: string): string {
  const segments = parseAp2MandateChainSegments(token);
  const root = segments[0];
  if (root === undefined) throw new UcpAp2ParseError("AP2 Mandate chain is empty");
  return base64UrlSha256(root.canonical);
}

export function verifyAp2Receipt(
  options: VerifyAp2ReceiptOptions,
): InteropVerification<VerifiedAp2Receipt> {
  const issues: InteropIssue[] = [];
  let parsed: ParsedJwt;
  let allowed: ReadonlySet<JoseEcAlgorithm>;
  let asOf: number;
  try {
    if (
      typeof options.token !== "string" ||
      options.token.length === 0 ||
      Buffer.byteLength(options.token, "utf8") > 1_048_576
    ) {
      throw new UcpAp2ParseError("AP2 Receipt JWT is empty or exceeds the byte limit");
    }
    if (!AP2_RECEIPT_KINDS.includes(options.kind)) {
      throw new UcpAp2ParseError("AP2 Receipt kind is unsupported");
    }
    parsed = parseJwtCompact(options.token, "receipt");
    allowed = validateAllowedAlgorithms(options.allowedAlgorithms, ["ES256"]);
    asOf = parseEpoch(options.asOf, "asOf");
  } catch (error) {
    issues.push(upstreamIssue(
      "AP2_RECEIPT_INVALID",
      "receipt",
      error instanceof Error ? error.message : "Invalid AP2 Receipt JWT",
    ));
    return finish<VerifiedAp2Receipt>(null, issues);
  }

  if (!checkKeySnapshot(
    options.issuerKeySnapshot,
    options.expectedIssuerKeySourceDigest,
    options.asOf,
    issues,
    "receiptIssuerKeySnapshot",
  )) {
    return finish<VerifiedAp2Receipt>(null, issues);
  }

  let issuerHeader: { readonly algorithm: JoseEcAlgorithm; readonly kid: string | null } | null = null;
  try {
    issuerHeader = verifyParsedJwtSignature(
      parsed,
      options.issuerKeySnapshot.jwk,
      allowed,
      options.issuerKeySnapshot.kid,
      "issuer",
    );
  } catch (error) {
    issues.push(upstreamIssue(
      "AP2_RECEIPT_SIGNATURE_INVALID",
      "receipt",
      error instanceof Error ? error.message : "Receipt signature is invalid",
    ));
  }

  const validated = validateReceiptClaims(parsed.claims, options.kind, asOf, issues);
  if (validated === null) return finish<VerifiedAp2Receipt>(null, issues);
  if (validated.issuer !== options.expectedIssuer) {
    issues.push(upstreamIssue(
      "AP2_RECEIPT_ISSUER_MISMATCH",
      "receipt.claims.iss",
      "Receipt issuer does not match the expected verifier",
    ));
  }
  if (options.expectedMandateToken === undefined) {
    issues.push(eligibilityIssue(
      "AP2_RECEIPT_REFERENCE_UNANCHORED",
      "receipt.claims.reference",
      "Receipt reference was not checked against an exact closed Mandate presentation",
    ));
  } else {
    try {
      if (validated.reference !== computeAp2MandateReference(options.expectedMandateToken)) {
        issues.push(upstreamIssue(
          "AP2_RECEIPT_REFERENCE_MISMATCH",
          "receipt.claims.reference",
          "Receipt reference does not match the exact closed Mandate presentation",
        ));
      }
    } catch (error) {
      issues.push(upstreamIssue(
        "AP2_RECEIPT_MANDATE_INVALID",
        "expectedMandateToken",
        error instanceof Error ? error.message : "Expected Mandate is invalid",
      ));
    }
  }

  const result: VerifiedAp2Receipt = Object.freeze({
    profileId: UCP_AP2_EVIDENCE_PROFILE.id,
    ap2Version: UCP_AP2_EVIDENCE_PROFILE.ap2Version,
    exactToken: options.token,
    kind: options.kind,
    issuer: validated.issuer,
    issuedAt: validated.issuedAt,
    status: validated.status,
    reference: validated.reference,
    claims: parsed.claims,
    issuerKid: issuerHeader?.kid ?? options.issuerKeySnapshot.kid,
    issuerAlgorithm: issuerHeader?.algorithm ?? "ES256",
    authorizesNativeRole: false,
  });
  return finish(result, issues);
}
