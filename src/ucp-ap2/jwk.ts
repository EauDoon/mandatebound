import { Buffer } from "node:buffer";
import {
  createPublicKey,
  verify as verifySignature,
  type JsonWebKeyInput,
  type KeyObject,
} from "node:crypto";
import { isSha256Digest } from "../canonical.js";
import type { JsonObject, Sha256Digest } from "../domain.js";
import type { EcPublicJwk, InteropIssue, JoseEcAlgorithm, ParsedJwt, PinnedEcKeySnapshot } from "./types.js";
import { UcpAp2ParseError } from "./parse-error.js";
import {
  decodeBase64Url,
  eligibilityIssue,
  hasOwn,
  isObject,
  JOSE_ALGORITHMS,
  parseEpoch,
  parseTimestampMillis,
  requireJsonObject,
  requireString,
  upstreamIssue,
  validateAllowedAlgorithms,
} from "./primitives.js";

/**
 * JWK validation, ECDSA verification, key-snapshot window checks, JOSE
 * protected-header validation, and parsed-JWT signature verification. These
 * helpers are shared across the merchant authorization, mandate verification,
 * checkout-jwt, receipt, and request-evidence code paths.
 */

export function parseJoseAlgorithm(value: unknown, path: string): JoseEcAlgorithm {
  if (value !== "ES256" && value !== "ES384" && value !== "ES512") {
    throw new UcpAp2ParseError(`Unsupported JOSE algorithm at ${path}`);
  }
  return value;
}

export function validateJoseProtectedHeader(
  header: JsonObject,
  allowed: ReadonlySet<JoseEcAlgorithm>,
  mode: "merchant" | "issuer" | "key-binding",
): { readonly algorithm: JoseEcAlgorithm; readonly kid: string | null } {
  const algorithm = parseJoseAlgorithm(header.alg, "protected.alg");
  if (!allowed.has(algorithm)) {
    throw new UcpAp2ParseError("Protected JOSE algorithm is not allowlisted");
  }
  if (
    hasOwn(header, "crit") ||
    hasOwn(header, "jku") ||
    hasOwn(header, "jwk") ||
    hasOwn(header, "x5u") ||
    hasOwn(header, "x5c") ||
    header.b64 === false
  ) {
    throw new UcpAp2ParseError("Unsupported or attacker-controlled JOSE header parameter");
  }
  const allowedNames = mode === "merchant"
    ? new Set(["alg", "kid"])
    : new Set(["alg", "kid", "typ", "cty"]);
  for (const name of Object.keys(header)) {
    if (!allowedNames.has(name)) {
      throw new UcpAp2ParseError("Unexpected protected JOSE header parameter");
    }
  }
  if (header.typ !== undefined) requireString(header.typ, "protected.typ");
  if (header.cty !== undefined) requireString(header.cty, "protected.cty");
  const kid = header.kid === undefined ? null : requireString(header.kid, "protected.kid");
  if (mode !== "key-binding" && kid === null) {
    throw new UcpAp2ParseError("Protected JOSE header is missing kid");
  }
  return { algorithm, kid };
}

export function validateEcJwk(
  input: unknown,
  algorithm: JoseEcAlgorithm,
  expectedKid?: string,
): { readonly jwk: EcPublicJwk; readonly key: KeyObject } {
  const jwk = requireJsonObject(input, "jwk") as unknown as EcPublicJwk & Record<string, unknown>;
  const parameters = JOSE_ALGORITHMS[algorithm];
  const allowedNames = new Set(["kty", "crv", "x", "y", "kid", "alg", "use", "key_ops"]);
  if (Object.keys(jwk).some((name) => !allowedNames.has(name))) {
    throw new UcpAp2ParseError("JWK contains an unsupported member");
  }
  if (jwk.kty !== "EC" || jwk.crv !== parameters.curve) {
    throw new UcpAp2ParseError("JOSE algorithm and EC key curve do not match");
  }
  if (hasOwn(jwk, "d") || hasOwn(jwk, "k")) {
    throw new UcpAp2ParseError("Private or symmetric key material is not accepted");
  }
  if (jwk.alg !== undefined && jwk.alg !== algorithm) {
    throw new UcpAp2ParseError("JWK alg does not match the protected algorithm");
  }
  if (jwk.use !== undefined && jwk.use !== "sig") {
    throw new UcpAp2ParseError("JWK use is not signature verification");
  }
  if (jwk.kid !== undefined && (typeof jwk.kid !== "string" || jwk.kid.length === 0)) {
    throw new UcpAp2ParseError("JWK kid must be a non-empty string");
  }
  if (jwk.key_ops !== undefined) {
    if (
      !Array.isArray(jwk.key_ops) ||
      jwk.key_ops.length !== 1 ||
      jwk.key_ops[0] !== "verify"
    ) {
      throw new UcpAp2ParseError("JWK key_ops must be the verification operation");
    }
  }
  if (expectedKid !== undefined && jwk.kid !== undefined && jwk.kid !== expectedKid) {
    throw new UcpAp2ParseError("JWK kid does not match the pinned key identifier");
  }
  const x = decodeBase64Url(requireString(jwk.x, "jwk.x"), "jwk.x");
  const y = decodeBase64Url(requireString(jwk.y, "jwk.y"), "jwk.y");
  if (x.byteLength !== parameters.coordinateLength || y.byteLength !== parameters.coordinateLength) {
    throw new UcpAp2ParseError("EC coordinate length does not match the selected curve");
  }
  try {
    const key = createPublicKey({
      key: jwk,
      format: "jwk",
    } as unknown as JsonWebKeyInput);
    if (key.asymmetricKeyType !== "ec") {
      throw new UcpAp2ParseError("JWK did not resolve to an EC public key");
    }
    return { jwk, key };
  } catch (error) {
    if (error instanceof UcpAp2ParseError) throw error;
    throw new UcpAp2ParseError("Invalid EC public key");
  }
}

export function verifyRawEcdsa(
  algorithm: JoseEcAlgorithm,
  data: Uint8Array,
  signature: Uint8Array,
  jwk: EcPublicJwk,
  expectedKid?: string,
): boolean {
  const parameters = JOSE_ALGORITHMS[algorithm];
  if (signature.byteLength !== parameters.signatureLength) {
    throw new UcpAp2ParseError(
      `ECDSA signature must use ${String(parameters.signatureLength)}-byte fixed-width raw r||s encoding`,
    );
  }
  const { key } = validateEcJwk(jwk, algorithm, expectedKid);
  try {
    return verifySignature(
      parameters.hash,
      data,
      { key, dsaEncoding: "ieee-p1363" },
      signature,
    );
  } catch {
    return false;
  }
}

export function verifyParsedJwtSignature(
  jwt: ParsedJwt,
  key: EcPublicJwk,
  allowed: ReadonlySet<JoseEcAlgorithm>,
  expectedKid: string | null,
  mode: "issuer" | "key-binding",
): { readonly algorithm: JoseEcAlgorithm; readonly kid: string | null } {
  const header = validateJoseProtectedHeader(jwt.protectedHeader, allowed, mode);
  if (expectedKid !== null && header.kid !== expectedKid) {
    throw new UcpAp2ParseError("Protected kid does not match the pinned key");
  }
  const signature = decodeBase64Url(jwt.signatureSegment, "token.signature");
  const signingInput = Buffer.from(
    `${jwt.protectedSegment}.${jwt.payloadSegment}`,
    "ascii",
  );
  if (!verifyRawEcdsa(header.algorithm, signingInput, signature, key, expectedKid ?? undefined)) {
    throw new UcpAp2ParseError("JWT signature verification failed");
  }
  return header;
}

export function checkKeySnapshot(
  snapshotValue: unknown,
  expectedDigest: Sha256Digest,
  asOf: string | number,
  issues: InteropIssue[],
  path: string,
): boolean {
  if (
    !isObject(snapshotValue) ||
    typeof snapshotValue.kid !== "string" ||
    typeof snapshotValue.capturedAt !== "string" ||
    typeof snapshotValue.validUntil !== "string" ||
    !isObject(snapshotValue.jwk)
  ) {
    issues.push(upstreamIssue(
      "INTEROP_KEY_SNAPSHOT_INVALID",
      path,
      "External key snapshot has an invalid shape",
    ));
    return false;
  }
  const snapshot = snapshotValue as unknown as PinnedEcKeySnapshot;
  if (!isSha256Digest(snapshot.sourceDigest) || snapshot.sourceDigest !== expectedDigest) {
    issues.push(eligibilityIssue(
      "INTEROP_KEY_SOURCE_PIN_MISMATCH",
      `${path}.sourceDigest`,
      "External key snapshot does not match the caller-owned source pin",
    ));
  }
  if (snapshot.kid.length === 0) {
    issues.push(upstreamIssue("INTEROP_KEY_ID_INVALID", `${path}.kid`, "Pinned key ID is empty"));
  }
  try {
    const at = parseEpoch(asOf, "asOf");
    const captured = Math.floor(parseTimestampMillis(snapshot.capturedAt, `${path}.capturedAt`) / 1_000);
    const validUntil = Math.floor(
      parseTimestampMillis(snapshot.validUntil, `${path}.validUntil`) / 1_000,
    );
    if (captured > validUntil) {
      issues.push(upstreamIssue(
        "INTEROP_KEY_SNAPSHOT_WINDOW_INVALID",
        path,
        "Key snapshot capture time is after its validity limit",
      ));
    }
    if (captured > at) {
      issues.push(eligibilityIssue(
        "INTEROP_KEY_SNAPSHOT_FROM_FUTURE",
        path,
        "Pinned key snapshot was captured after the evidence evaluation time",
      ));
    }
    if (at > validUntil) {
      issues.push(eligibilityIssue(
        "INTEROP_KEY_SNAPSHOT_STALE",
        path,
        "Pinned external key snapshot is stale at the evidence evaluation time",
      ));
    }
    if (snapshot.validFrom !== undefined) {
      const validFrom = Math.floor(
        parseTimestampMillis(snapshot.validFrom, `${path}.validFrom`) / 1_000,
      );
      if (at < validFrom) {
        issues.push(eligibilityIssue(
          "INTEROP_KEY_NOT_YET_VALID",
          path,
          "Pinned key is not valid at the evidence evaluation time",
        ));
      }
    }
    if (snapshot.invalidFrom !== undefined) {
      const invalidFrom = Math.floor(
        parseTimestampMillis(snapshot.invalidFrom, `${path}.invalidFrom`) / 1_000,
      );
      if (at >= invalidFrom) {
        issues.push(eligibilityIssue(
          "INTEROP_KEY_INVALIDATED",
          path,
          "Pinned key was invalidated at or before the evidence evaluation time",
        ));
      }
    }
  } catch (error) {
    issues.push(upstreamIssue(
      "INTEROP_KEY_SNAPSHOT_TIME_INVALID",
      path,
      error instanceof Error ? error.message : "Invalid key snapshot time",
    ));
  }
  return true;
}
