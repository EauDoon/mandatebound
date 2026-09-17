import { Buffer } from "node:buffer";
import { canonicalize } from "../canonical.js";
import type { JsonObject, JsonValue } from "../domain.js";
import type {
  Ap2MandateVct,
  EcPublicJwk,
  InteropIssue,
  InteropVerification,
  ParsedJwt,
  ParsedSdJwtDisclosure,
  VerifyAp2MandateOptions,
  VerifiedAp2MandateChain,
} from "./types.js";
import { AP2_V020_MANDATE_CHAIN_PROFILE, UCP_AP2_EVIDENCE_PROFILE } from "./profile.js";
import { UcpAp2ParseError } from "./parse-error.js";
import {
  base64UrlSha256,
  finish,
  hasOwn,
  isObject,
  parseEpoch,
  publicJwkIdentity,
  requireJsonObject,
  requireSafeInteger,
  requireString,
  upstreamIssue,
  validateAllowedAlgorithms,
} from "./primitives.js";
import { checkKeySnapshot } from "./jwk.js";
import { parseCompactAp2Token } from "./jwt-parse.js";
import {
  AP2_INHERITANCE_EXCLUSIONS,
  AP2_INTERMEDIATE_TYPES,
  AP2_ROOT_TYPES,
  AP2_TERMINAL_TYPES,
  verifyConstraints,
  verifyExpiryClaims,
} from "./mandate-verify.js";
import { verifyParsedJwtSignature } from "./jwk.js";

/**
 * AP2 v0.2.0 delegate SD-JWT chain verification. Accepts directly signed
 * closed Mandates and canonical Delegate SD-JWT chains, never a trailing
 * plain KB-JWT.
 *
 * The `parseAp2MandateChainSegments` helper is also used by the Receipt
 * reference helper in ./receipt.ts.
 */

interface ParsedAp2MandateChainSegment {
  readonly canonical: string;
  readonly issuerJwt: ParsedJwt;
  readonly disclosures: readonly ParsedSdJwtDisclosure[];
  readonly claims: JsonObject;
}

export function parseAp2MandateChainSegments(token: string): readonly ParsedAp2MandateChainSegment[] {
  if (
    typeof token !== "string" ||
    token.length === 0 ||
    Buffer.byteLength(token, "utf8") > 1_048_576
  ) {
    throw new UcpAp2ParseError("AP2 Mandate chain is empty or exceeds the byte limit");
  }
  const rawSegments = token.split("~~");
  if (rawSegments.some((segment) => segment.length === 0)) {
    throw new UcpAp2ParseError("AP2 Mandate chain contains an empty segment");
  }
  if (!token.endsWith("~")) {
    throw new UcpAp2ParseError("AP2 Mandate chain must end with an SD-JWT separator");
  }
  return Object.freeze(rawSegments.map((raw, index) => {
    const isLast = index === rawSegments.length - 1;
    if ((!isLast && raw.endsWith("~")) || (isLast && !raw.endsWith("~"))) {
      throw new UcpAp2ParseError("AP2 Mandate chain uses a non-canonical separator");
    }
    const canonical = isLast ? raw : `${raw}~`;
    const parsed = parseCompactAp2Token(canonical);
    if (parsed.keyBindingJwt !== null) {
      throw new UcpAp2ParseError("AP2 v0.2.0 does not accept a trailing plain KB-JWT");
    }
    const algorithm = parsed.issuerJwt.claims._sd_alg;
    if (algorithm !== undefined && algorithm !== "sha-256") {
      throw new UcpAp2ParseError("AP2 Mandate chain supports only sha-256 SD-JWTs");
    }
    return Object.freeze({
      canonical,
      issuerJwt: parsed.issuerJwt,
      disclosures: parsed.disclosures,
      claims: parsed.issuerJwt.claims,
    });
  }));
}

function resolveAp2SegmentClaims(segment: ParsedAp2MandateChainSegment): JsonObject {
  const byDigest = new Map<string, ParsedSdJwtDisclosure>();
  const byExact = new Map<string, ParsedSdJwtDisclosure>();
  for (const disclosure of segment.disclosures) {
    if (byDigest.has(disclosure.digest) || byExact.has(disclosure.exact)) {
      throw new UcpAp2ParseError("AP2 SD-JWT contains duplicate disclosures");
    }
    byDigest.set(disclosure.digest, disclosure);
    byExact.set(disclosure.exact, disclosure);
  }
  const used = new Set<string>();

  const resolveDisclosure = (
    disclosure: ParsedSdJwtDisclosure,
    expectedLength: 2 | 3,
  ): JsonValue => {
    if (used.has(disclosure.digest)) {
      throw new UcpAp2ParseError("AP2 SD-JWT disclosure is referenced more than once");
    }
    if (!Array.isArray(disclosure.decoded) || disclosure.decoded.length !== expectedLength) {
      throw new UcpAp2ParseError("AP2 SD-JWT disclosure has the wrong contextual shape");
    }
    used.add(disclosure.digest);
    return disclosure.decoded[expectedLength === 2 ? 1 : 2] as JsonValue;
  };

  const walk = (value: JsonValue, inDelegatePayload = false): JsonValue | undefined => {
    if (Array.isArray(value)) {
      const result: JsonValue[] = [];
      for (const item of value) {
        if (
          isObject(item) &&
          Object.keys(item).length === 1 &&
          typeof item["..."] === "string"
        ) {
          const disclosure = byDigest.get(item["..."]);
          if (disclosure === undefined) continue;
          const resolved = walk(resolveDisclosure(disclosure, 2));
          if (resolved !== undefined) result.push(resolved);
          continue;
        }
        if (inDelegatePayload && typeof item === "string") {
          const disclosure = byDigest.get(item) ?? byExact.get(item);
          if (disclosure !== undefined) {
            if (
              !Array.isArray(disclosure.decoded) ||
              (disclosure.decoded.length !== 2 && disclosure.decoded.length !== 3)
            ) {
              throw new UcpAp2ParseError("AP2 delegate disclosure is malformed");
            }
            const expectedLength = disclosure.decoded.length;
            const resolved = walk(resolveDisclosure(disclosure, expectedLength));
            if (resolved !== undefined) result.push(resolved);
            continue;
          }
        }
        const resolved = walk(item, false);
        if (resolved !== undefined) result.push(resolved);
      }
      return result;
    }
    if (!isObject(value)) return value;
    if (hasOwn(value, "...")) {
      throw new UcpAp2ParseError("AP2 SD-JWT contains an invalid disclosure placeholder");
    }
    const result: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
    for (const [name, child] of Object.entries(value)) {
      if (name === "_sd") continue;
      const resolved = walk(child as JsonValue, name === "delegate_payload");
      if (resolved !== undefined) result[name] = resolved;
    }
    const digests = value["_sd"];
    if (digests !== undefined) {
      if (!Array.isArray(digests) || digests.some((entry) => typeof entry !== "string")) {
        throw new UcpAp2ParseError("AP2 SD-JWT _sd must contain digest strings");
      }
      if (new Set(digests).size !== digests.length) {
        throw new UcpAp2ParseError("AP2 SD-JWT _sd contains duplicate digests");
      }
      for (const digest of digests as string[]) {
        const disclosure = byDigest.get(digest);
        if (disclosure === undefined) continue;
        if (
          !Array.isArray(disclosure.decoded) ||
          disclosure.decoded.length !== 3 ||
          typeof disclosure.decoded[1] !== "string"
        ) {
          throw new UcpAp2ParseError("AP2 object-property disclosure is malformed");
        }
        const name = disclosure.decoded[1];
        if (hasOwn(result, name) || name === "__proto__" || name === "constructor") {
          throw new UcpAp2ParseError("AP2 disclosure conflicts with an existing claim");
        }
        const resolved = walk(resolveDisclosure(disclosure, 3), name === "delegate_payload");
        if (resolved !== undefined) result[name] = resolved;
      }
    }
    return result;
  };

  const resolved = walk(segment.claims);
  if (!isObject(resolved)) {
    throw new UcpAp2ParseError("AP2 SD-JWT payload did not resolve to an object");
  }
  if (used.size !== segment.disclosures.length) {
    throw new UcpAp2ParseError("AP2 SD-JWT contains an unbound disclosure");
  }
  return resolved as JsonObject;
}

function effectiveDelegatePayload(claims: JsonObject): JsonObject {
  if (
    !Array.isArray(claims.delegate_payload) ||
    claims.delegate_payload.length !== 1 ||
    !isObject(claims.delegate_payload[0])
  ) {
    throw new UcpAp2ParseError("AP2 Mandate segment must disclose exactly one delegate payload");
  }
  return claims.delegate_payload[0] as JsonObject;
}

function cnfJwkFromPayload(payload: JsonObject): EcPublicJwk | null {
  if (payload.cnf === undefined) return null;
  const cnf = requireJsonObject(payload.cnf, "delegate_payload.cnf");
  return requireJsonObject(cnf.jwk, "delegate_payload.cnf.jwk") as unknown as EcPublicJwk;
}

function verifyAp2ChainTimeClaims(
  claims: JsonObject,
  asOf: number,
  path: string,
  requireIssuedAt: boolean,
): void {
  if (requireIssuedAt && claims.iat === undefined) {
    throw new UcpAp2ParseError(`Missing iat at ${path}`);
  }
  if (claims.iat !== undefined) {
    const issuedAt = requireSafeInteger(claims.iat, `${path}.iat`);
    if (issuedAt < 0 || issuedAt > asOf + 60) {
      throw new UcpAp2ParseError(`Invalid iat at ${path}`);
    }
  }
  if (claims.nbf !== undefined) {
    const notBefore = requireSafeInteger(claims.nbf, `${path}.nbf`);
    if (notBefore < 0 || asOf < notBefore) {
      throw new UcpAp2ParseError(`Invalid nbf at ${path}`);
    }
  }
  if (claims.exp !== undefined) {
    const expires = requireSafeInteger(claims.exp, `${path}.exp`);
    if (expires < 0 || asOf >= expires) {
      throw new UcpAp2ParseError(`Invalid exp at ${path}`);
    }
  }
}

function verifyAp2OpenInheritance(
  openPayloads: readonly JsonObject[],
  closed: JsonObject,
  options: VerifyAp2MandateOptions,
  issues: InteropIssue[],
): void {
  const expectedOpenVct: Ap2MandateVct = options.expectedVct === "mandate.checkout.1"
    ? "mandate.checkout.open.1"
    : "mandate.payment.open.1";
  for (let index = 0; index < openPayloads.length; index += 1) {
    const open = openPayloads[index] as JsonObject;
    if (open.vct !== expectedOpenVct) {
      issues.push(upstreamIssue(
        "AP2_DELEGATION_VCT_MISMATCH",
        `token.chain[${String(index)}].delegate_payload.vct`,
        "Open Mandate type does not lead to the expected closed Mandate type",
      ));
    }
    verifyConstraints(open, options, issues, closed, true);
    for (const [name, value] of Object.entries(open)) {
      if (AP2_INHERITANCE_EXCLUSIONS.has(name)) continue;
      if (!hasOwn(closed, name) || canonicalize(closed[name] as JsonValue) !== canonicalize(value)) {
        issues.push(upstreamIssue(
          "AP2_DELEGATED_CLAIM_MISMATCH",
          `token.chain[${String(index)}].delegate_payload.${name}`,
          "A claim fixed by an open Mandate changed in the closed Mandate",
        ));
      }
    }
  }
}

function verifyAp2ClosedMandateClaims(
  claims: JsonObject,
  options: VerifyAp2MandateOptions,
  issues: InteropIssue[],
): string | undefined {
  if (claims.iss !== undefined && claims.iss !== options.expectedIssuer) {
    issues.push(upstreamIssue(
      "AP2_ISSUER_MISMATCH",
      "token.closedMandate.iss",
      "Closed Mandate issuer does not match the caller-owned expected issuer",
    ));
  }
  if (claims.vct !== options.expectedVct) {
    issues.push(upstreamIssue(
      "AP2_VCT_MISMATCH",
      "token.closedMandate.vct",
      "Closed Mandate vct does not exactly match the expected versioned type",
    ));
  }
  if (options.expectedVct === "mandate.checkout.1") {
    if (typeof claims.checkout_jwt !== "string" || typeof claims.checkout_hash !== "string") {
      issues.push(upstreamIssue(
        "AP2_CHECKOUT_BINDING_MISSING",
        "token.closedMandate",
        "Closed Checkout Mandate is missing checkout_jwt or checkout_hash",
      ));
      return undefined;
    }
    const checkoutHash = base64UrlSha256(claims.checkout_jwt);
    if (claims.checkout_hash !== checkoutHash) {
      issues.push(upstreamIssue(
        "AP2_CHECKOUT_HASH_MISMATCH",
        "token.closedMandate.checkout_hash",
        "checkout_hash does not match the exact checkout_jwt field value",
      ));
    }
    if (
      options.expectedCheckoutJwt !== undefined &&
      claims.checkout_jwt !== options.expectedCheckoutJwt
    ) {
      issues.push(upstreamIssue(
        "AP2_CHECKOUT_JWT_MISMATCH",
        "token.closedMandate.checkout_jwt",
        "Mandate is bound to a different Checkout JWT",
      ));
    }
    if (
      options.expectedCheckoutHash !== undefined &&
      claims.checkout_hash !== options.expectedCheckoutHash
    ) {
      issues.push(upstreamIssue(
        "AP2_EXPECTED_CHECKOUT_HASH_MISMATCH",
        "token.closedMandate.checkout_hash",
        "Mandate checkout hash does not match the caller-owned expected value",
      ));
    }
    return checkoutHash;
  }
  if (options.expectedVct !== "mandate.payment.1") {
    issues.push(upstreamIssue(
      "AP2_CLOSED_MANDATE_TYPE_UNSUPPORTED",
      "expectedVct",
      "The strict dispute profile accepts only closed Checkout or Payment Mandates",
    ));
    return undefined;
  }
  if (
    typeof claims.transaction_id !== "string" ||
    !isObject(claims.payee) ||
    typeof claims.payee.id !== "string" ||
    claims.payee.id.length === 0 ||
    typeof claims.payee.name !== "string" ||
    claims.payee.name.length === 0 ||
    !isObject(claims.payment_amount) ||
    !Number.isSafeInteger(claims.payment_amount.amount) ||
    typeof claims.payment_amount.currency !== "string" ||
    claims.payment_amount.currency.length === 0 ||
    !isObject(claims.payment_instrument) ||
    typeof claims.payment_instrument.id !== "string" ||
    claims.payment_instrument.id.length === 0 ||
    typeof claims.payment_instrument.type !== "string" ||
    claims.payment_instrument.type.length === 0
  ) {
    issues.push(upstreamIssue(
      "AP2_PAYMENT_MANDATE_SCHEMA_INVALID",
      "token.closedMandate",
      "Closed Payment Mandate is missing a required AP2 v0.2.0 field",
    ));
  }
  if (
    options.expectedCheckoutHash !== undefined &&
    claims.transaction_id !== options.expectedCheckoutHash
  ) {
    issues.push(upstreamIssue(
      "AP2_PAYMENT_CHECKOUT_BINDING_MISMATCH",
      "token.closedMandate.transaction_id",
      "Payment Mandate transaction_id is not the expected checkout hash",
    ));
  }
  return typeof claims.transaction_id === "string" ? claims.transaction_id : undefined;
}

/**
 * Verify an AP2 v0.2.0 directly signed closed Mandate or Delegate SD-JWT
 * chain. This strict profile is used by the dispute resolver and deliberately
 * does not accept the legacy trailing plain KB-JWT adapter shape.
 */
export function verifyAp2MandateChain(
  options: VerifyAp2MandateOptions,
): InteropVerification<VerifiedAp2MandateChain> {
  const issues: InteropIssue[] = [];
  if (!checkKeySnapshot(
    options.issuerKeySnapshot,
    options.expectedIssuerKeySourceDigest,
    options.asOf,
    issues,
    "issuerKeySnapshot",
  )) return finish<VerifiedAp2MandateChain>(null, issues);
  try {
    requireString(options.expectedIssuer, "expectedIssuer");
    const segments = parseAp2MandateChainSegments(options.token);
    const allowed = validateAllowedAlgorithms(options.allowedAlgorithms, ["ES256"]);
    const asOf = parseEpoch(options.asOf, "asOf");
    const root = segments[0] as ParsedAp2MandateChainSegment;
    const rootTyp = root.issuerJwt.protectedHeader.typ;
    if (
      rootTyp !== undefined &&
      (typeof rootTyp !== "string" || !AP2_ROOT_TYPES.has(rootTyp))
    ) {
      throw new UcpAp2ParseError("Root SD-JWT typ is not supported by the AP2 profile");
    }
    const rootHeader = verifyParsedJwtSignature(
      root.issuerJwt,
      options.issuerKeySnapshot.jwk,
      allowed,
      options.issuerKeySnapshot.kid,
      "issuer",
    );
    const rootClaims = resolveAp2SegmentClaims(root);
    if (rootClaims.iss !== undefined && rootClaims.iss !== options.expectedIssuer) {
      issues.push(upstreamIssue(
        "AP2_ISSUER_MISMATCH",
        "token.chain[0].claims.iss",
        "Root Mandate issuer does not match the caller-owned expected issuer",
      ));
    }
    const payloads: JsonObject[] = [effectiveDelegatePayload(rootClaims)];
    verifyAp2ChainTimeClaims(payloads[0] as JsonObject, asOf, "token.chain[0].delegate_payload", false);

    let previous = root;
    let previousPayload = payloads[0] as JsonObject;
    if (segments.length > 1) {
      requireString(options.expectedAudience, "expectedAudience");
      requireString(options.expectedNonce, "expectedNonce");
      verifyExpiryClaims(previousPayload, asOf, issues, "token.chain[0].delegate_payload");
      const initialCnf = cnfJwkFromPayload(previousPayload);
      if (initialCnf === null) {
        throw new UcpAp2ParseError("Open root Mandate is missing cnf.jwk");
      }
      if (
        options.expectedAgentJwk !== undefined &&
        publicJwkIdentity(initialCnf) !== publicJwkIdentity(options.expectedAgentJwk)
      ) {
        throw new UcpAp2ParseError("Root cnf key does not match the expected agent key");
      }
      for (let index = 1; index < segments.length; index += 1) {
        const current = segments[index] as ParsedAp2MandateChainSegment;
        const isLast = index === segments.length - 1;
        const typ = current.issuerJwt.protectedHeader.typ;
        if (
          typeof typ !== "string" ||
          (isLast ? !AP2_TERMINAL_TYPES.has(typ) : !AP2_INTERMEDIATE_TYPES.has(typ))
        ) {
          throw new UcpAp2ParseError("Delegate SD-JWT hop has the wrong terminal shape");
        }
        const signingJwk = cnfJwkFromPayload(previousPayload);
        if (signingJwk === null) {
          throw new UcpAp2ParseError("Previous Delegate SD-JWT hop is missing cnf.jwk");
        }
        verifyParsedJwtSignature(
          current.issuerJwt,
          signingJwk,
          allowed,
          signingJwk.kid ?? null,
          "key-binding",
        );
        const claims = resolveAp2SegmentClaims(current);
        const hasSdHash = hasOwn(claims, "sd_hash");
        const hasIssuerHash = hasOwn(claims, "issuer_jwt_hash");
        if (hasSdHash === hasIssuerHash) {
          throw new UcpAp2ParseError("Delegate hop must contain exactly one binding hash");
        }
        const expectedBinding = hasSdHash
          ? base64UrlSha256(previous.canonical)
          : base64UrlSha256(previous.issuerJwt.exactCompact);
        if (claims[hasSdHash ? "sd_hash" : "issuer_jwt_hash"] !== expectedBinding) {
          throw new UcpAp2ParseError("Delegate hop binding hash does not match the previous hop");
        }
        verifyAp2ChainTimeClaims(claims, asOf, `token.chain[${String(index)}].claims`, true);
        const aud = requireString(claims.aud, `token.chain[${String(index)}].claims.aud`);
        const nonce = requireString(claims.nonce, `token.chain[${String(index)}].claims.nonce`);
        if (isLast && (aud !== options.expectedAudience || nonce !== options.expectedNonce)) {
          throw new UcpAp2ParseError("Terminal Delegate SD-JWT audience or nonce does not match");
        }
        const payload = effectiveDelegatePayload(claims);
        verifyAp2ChainTimeClaims(
          payload,
          asOf,
          `token.chain[${String(index)}].delegate_payload`,
          false,
        );
        verifyExpiryClaims(
          payload,
          asOf,
          issues,
          `token.chain[${String(index)}].delegate_payload`,
        );
        const nextCnf = cnfJwkFromPayload(payload);
        if ((isLast && nextCnf !== null) || (!isLast && nextCnf === null)) {
          throw new UcpAp2ParseError("Delegate hop cnf does not match its protected typ");
        }
        payloads.push(payload);
        previous = current;
        previousPayload = payload;
      }
    } else {
      if (options.requireKeyBinding === true) {
        throw new UcpAp2ParseError("Caller requires a delegated, key-bound Mandate chain");
      }
      verifyExpiryClaims(previousPayload, asOf, issues, "token.chain[0].delegate_payload");
      if (cnfJwkFromPayload(previousPayload) !== null) {
        throw new UcpAp2ParseError("Directly signed closed Mandate must not remain open via cnf");
      }
    }

    const closed = payloads[payloads.length - 1] as JsonObject;
    if (segments.length > 1) {
      verifyAp2OpenInheritance(payloads.slice(0, -1), closed, options, issues);
    }
    const checkoutHash = verifyAp2ClosedMandateClaims(closed, options, issues);
    const result: VerifiedAp2MandateChain = Object.freeze({
      profileId: UCP_AP2_EVIDENCE_PROFILE.id,
      chainProfileId: AP2_V020_MANDATE_CHAIN_PROFILE.id,
      ap2Version: UCP_AP2_EVIDENCE_PROFILE.ap2Version,
      exactToken: options.token,
      vct: options.expectedVct,
      issuer: options.expectedIssuer,
      claims: closed,
      issuerKid: rootHeader.kid ?? options.issuerKeySnapshot.kid,
      issuerAlgorithm: rootHeader.algorithm,
      keyBound: segments.length > 1,
      presentationMode: segments.length > 1 ? "human_not_present" : "human_present",
      chainDepth: segments.length,
      terminalCompactJws: previous.issuerJwt.exactCompact,
      authorizesNativeRole: false,
      ...(checkoutHash === undefined ? {} : { checkoutHash }),
    });
    return finish(result, issues);
  } catch {
    issues.push(upstreamIssue(
      "AP2_MANDATE_CHAIN_INVALID",
      "token",
      "AP2 v0.2.0 Mandate chain failed strict bounded verification",
    ));
    return finish<VerifiedAp2MandateChain>(null, issues);
  }
}
