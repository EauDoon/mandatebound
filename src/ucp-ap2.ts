import { Buffer } from "node:buffer";
import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify as verifySignature,
  type JsonWebKeyInput,
  type KeyObject,
} from "node:crypto";
import { TextDecoder } from "node:util";
import { canonicalBytes, canonicalize, isSha256Digest, sha256Bytes } from "./canonical.js";
import type { JsonObject, JsonValue, Sha256Digest } from "./domain.js";
import { parseStrictJson, parseStrictJsonObject } from "./strict-json.js";

/**
 * This module is an additive evidence adapter. It deliberately does not extend
 * or reinterpret MandateBound's v1 wire schemas.
 */
export const UCP_AP2_EVIDENCE_PROFILE = Object.freeze({
  id: "ucp-2026-04-08-rest+ap2-mandates-0.2.0",
  ucpVersion: "2026-04-08",
  ucpTransport: "rest",
  ucpService: "dev.ucp.shopping",
  checkoutCapability: "dev.ucp.shopping.checkout",
  ap2Extension: "dev.ucp.shopping.ap2_mandate",
  ap2Version: "0.2.0",
} as const);

export const AP2_MANDATE_VCTS = Object.freeze([
  "mandate.checkout.1",
  "mandate.checkout.open.1",
  "mandate.payment.1",
  "mandate.payment.open.1",
] as const);

export type Ap2MandateVct = (typeof AP2_MANDATE_VCTS)[number];
export type JoseEcAlgorithm = "ES256" | "ES384" | "ES512";
export type UcpHttpAlgorithm = "ES256" | "ES384";
export type EvidenceCoverageState =
  | "satisfied"
  | "missing"
  | "conflicting"
  | "unsupported"
  | "unknown"
  | "not_applicable";

export interface EvidenceCoverageItem {
  readonly requirement: string;
  readonly state: EvidenceCoverageState;
  readonly sourceRefs: readonly string[];
  readonly note?: string;
}

export type InteropIssueImpact = "upstream_validity" | "evidence_eligibility";

export interface InteropIssue {
  readonly code: string;
  readonly path: string;
  /** Bounded diagnostic. It never contains request bodies, tokens, or secrets. */
  readonly message: string;
  readonly impact: InteropIssueImpact;
}

export interface InteropVerification<T> {
  /**
   * True only when the imported object satisfies the upstream protocol checks
   * performed by this adapter. This does not grant a MandateBound actor role.
   */
  readonly upstreamValid: boolean;
  /**
   * True only when upstream validation passed and the evidence is pinned,
   * fresh, and suitable for durable downstream use.
   */
  readonly evidenceEligible: boolean;
  readonly value: T | null;
  readonly issues: readonly InteropIssue[];
}

export interface EcPublicJwk {
  readonly kty: "EC";
  readonly crv: "P-256" | "P-384" | "P-521";
  readonly x: string;
  readonly y: string;
  readonly kid?: string;
  readonly alg?: JoseEcAlgorithm;
  readonly use?: "sig";
  readonly key_ops?: readonly string[];
}

export interface PinnedEcKeySnapshot {
  readonly kid: string;
  readonly jwk: EcPublicJwk;
  /** Digest of the externally captured profile, JWKS, or trust document. */
  readonly sourceDigest: Sha256Digest;
  readonly capturedAt: string;
  readonly validUntil: string;
  readonly validFrom?: string;
  readonly invalidFrom?: string;
}

export interface UcpProfileSnapshot {
  /** Exact fetched profile bytes; the adapter performs no network access. */
  readonly profileBytes: Uint8Array;
  readonly profileDigest: Sha256Digest;
  readonly profileUrl: string;
  readonly capturedAt: string;
  readonly validUntil: string;
  /** AP2 is pinned out-of-band because it is not a UCP profile field. */
  readonly ap2Version: string;
}

export interface VerifiedUcpProfile {
  readonly profileId: typeof UCP_AP2_EVIDENCE_PROFILE.id;
  readonly profileDigest: Sha256Digest;
  readonly profileUrl: string;
  readonly ucpVersion: typeof UCP_AP2_EVIDENCE_PROFILE.ucpVersion;
  readonly transport: typeof UCP_AP2_EVIDENCE_PROFILE.ucpTransport;
  readonly ap2Version: typeof UCP_AP2_EVIDENCE_PROFILE.ap2Version;
  readonly profile: JsonObject;
  /** External discovery is evidence; it never grants a native v1 actor role. */
  readonly authorizesNativeRole: false;
}

export interface VerifyUcpProfileOptions {
  readonly expectedProfileDigest: Sha256Digest;
  readonly asOf: string;
}

export interface ParsedContentDigest {
  readonly algorithm: "sha-256";
  readonly digest: Uint8Array;
  readonly exact: string;
}

export interface RawBodyDigestVerification {
  readonly contentDigest: string;
  readonly rawBodyDigest: Sha256Digest;
}

export interface DetachedMerchantAuthorization {
  readonly exactCompact: string;
  readonly protectedHeader: JsonObject;
  readonly canonicalPayloadDigest: Sha256Digest;
  readonly kid: string;
  readonly algorithm: JoseEcAlgorithm;
}

export interface VerifyDetachedMerchantAuthorizationOptions {
  readonly keySnapshot: PinnedEcKeySnapshot;
  readonly expectedKeySourceDigest: Sha256Digest;
  readonly asOf: string;
  readonly allowedAlgorithms?: readonly JoseEcAlgorithm[];
}

export interface ParsedJwt {
  readonly exactCompact: string;
  readonly protectedSegment: string;
  readonly payloadSegment: string;
  readonly signatureSegment: string;
  readonly protectedHeader: JsonObject;
  readonly claims: JsonObject;
}

export interface ParsedSdJwtDisclosure {
  readonly exact: string;
  readonly digest: string;
  readonly decoded: JsonValue;
}

export interface ParsedCompactAp2Token {
  readonly exact: string;
  readonly issuerJwt: ParsedJwt;
  readonly disclosures: readonly ParsedSdJwtDisclosure[];
  readonly keyBindingJwt: ParsedJwt | null;
  /** Exact presentation bytes hashed by a Key Binding JWT's sd_hash claim. */
  readonly sdJwtWithoutKeyBinding: string;
}

export interface ExpectedMerchant {
  readonly id: string;
  readonly website?: string;
}

export interface VerifyAp2MandateOptions {
  readonly token: string;
  readonly expectedVct: Ap2MandateVct;
  readonly issuerKeySnapshot: PinnedEcKeySnapshot;
  readonly expectedIssuerKeySourceDigest: Sha256Digest;
  readonly expectedIssuer: string;
  readonly expectedAudience: string;
  readonly expectedNonce: string;
  readonly asOf: string | number;
  readonly allowedAlgorithms?: readonly JoseEcAlgorithm[];
  readonly requireKeyBinding?: boolean;
  readonly expectedAgentJwk?: EcPublicJwk;
  readonly expectedCheckoutJwt?: string;
  readonly expectedCheckoutHash?: string;
  readonly expectedMerchant?: ExpectedMerchant;
}

export interface VerifiedAp2Mandate {
  readonly profileId: typeof UCP_AP2_EVIDENCE_PROFILE.id;
  readonly ap2Version: typeof UCP_AP2_EVIDENCE_PROFILE.ap2Version;
  readonly exactToken: string;
  readonly vct: Ap2MandateVct;
  readonly issuer: string;
  readonly claims: JsonObject;
  readonly issuerKid: string;
  readonly issuerAlgorithm: JoseEcAlgorithm;
  readonly keyBound: boolean;
  readonly checkoutHash?: string;
  /** AP2 evidence does not by itself establish a native MandateBound role. */
  readonly authorizesNativeRole: false;
}

export interface UcpIdempotencyRecord {
  readonly operation: string;
  readonly rawBodyDigest: Sha256Digest;
}

export interface UcpRequestEvidenceInput {
  readonly method: string;
  readonly authority: string;
  readonly path: string;
  /** RFC 9421 @query value, with or without the leading question mark. */
  readonly query?: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly rawBody?: Uint8Array;
  readonly signatureInput: string;
  readonly signature: string;
  readonly keySnapshot: PinnedEcKeySnapshot;
  readonly expectedKeySourceDigest: Sha256Digest;
  readonly asOf: string | number;
  readonly idempotencyLedger?: ReadonlyMap<string, UcpIdempotencyRecord>;
  readonly replayDisposition?: "new" | "cached";
}

export interface ParsedUcpSignatureInput {
  readonly label: string;
  readonly components: readonly string[];
  readonly keyId: string;
  readonly created: number | null;
  readonly expires: number | null;
  readonly serializedParameters: string;
}

export interface VerifiedUcpRequestEvidence {
  readonly profileId: typeof UCP_AP2_EVIDENCE_PROFILE.id;
  readonly operation: string;
  readonly keyId: string;
  readonly algorithm: UcpHttpAlgorithm;
  readonly signedComponents: readonly string[];
  readonly rawBodyDigest: Sha256Digest;
  readonly replayStatus: "new" | "cached" | "unresolved";
  readonly upstreamValid: true;
}

export const TRANSACTION_LIFECYCLE_KINDS = Object.freeze([
  "checkout",
  "order",
  "refund",
  "return",
  "cancel",
  "adjustment",
] as const);

export type TransactionLifecycleKind = (typeof TRANSACTION_LIFECYCLE_KINDS)[number];

export interface TransactionLifecycleEvidence {
  readonly eventId: string;
  readonly kind: TransactionLifecycleKind;
  readonly transactionId: string;
  readonly occurredAt: string;
  readonly sourceDigest: Sha256Digest;
  readonly checkoutId?: string;
  readonly orderId?: string;
  readonly parentEventIds?: readonly string[];
  readonly upstreamValid: boolean;
  readonly evidenceEligible: boolean;
}

export interface TransactionLifecycleCorrelation {
  readonly transactionId: string;
  readonly events: readonly TransactionLifecycleEvidence[];
  readonly duplicateEventIds: readonly string[];
  readonly conflictingEventIds: readonly string[];
  readonly orphanEventIds: readonly string[];
  /**
   * A bounded import can establish correlations, never that every upstream
   * lifecycle event was captured.
   */
  readonly historyCompleteness: "unknown";
  readonly coverage: readonly EvidenceCoverageItem[];
}

export class UcpAp2ParseError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "UcpAp2ParseError";
  }
}

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const RFC3339_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const STATE_CHANGING_METHODS = new Set(["POST", "PUT", "DELETE", "PATCH"]);
const JOSE_ALGORITHMS: Readonly<Record<JoseEcAlgorithm, {
  readonly curve: EcPublicJwk["crv"];
  readonly hash: "sha256" | "sha384" | "sha512";
  readonly signatureLength: number;
  readonly coordinateLength: number;
}>> = Object.freeze({
  ES256: Object.freeze({ curve: "P-256", hash: "sha256", signatureLength: 64, coordinateLength: 32 }),
  ES384: Object.freeze({ curve: "P-384", hash: "sha384", signatureLength: 96, coordinateLength: 48 }),
  ES512: Object.freeze({ curve: "P-521", hash: "sha512", signatureLength: 132, coordinateLength: 66 }),
});

function upstreamIssue(code: string, path: string, message: string): InteropIssue {
  return Object.freeze({ code, path, message, impact: "upstream_validity" });
}

function eligibilityIssue(code: string, path: string, message: string): InteropIssue {
  return Object.freeze({ code, path, message, impact: "evidence_eligibility" });
}

function finish<T>(value: T | null, issues: readonly InteropIssue[]): InteropVerification<T> {
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

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasOwn(value: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function strictUtf8(bytes: Uint8Array): string {
  try {
    return UTF8_DECODER.decode(bytes);
  } catch {
    throw new UcpAp2ParseError("Input is not valid UTF-8");
  }
}

function decodeBase64Url(value: string, path = "base64url"): Uint8Array {
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

function decodeBase64(value: string, path = "base64"): Uint8Array {
  if (value.length === 0 || value.length % 4 !== 0 || !BASE64_PATTERN.test(value)) {
    throw new UcpAp2ParseError(`Invalid base64 at ${path}`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) {
    throw new UcpAp2ParseError(`Non-canonical base64 at ${path}`);
  }
  return decoded;
}

function parseEpoch(value: string | number, path: string): number {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new UcpAp2ParseError(`Invalid epoch seconds at ${path}`);
    }
    return value;
  }
  if (!RFC3339_PATTERN.test(value)) {
    throw new UcpAp2ParseError(`Invalid RFC 3339 timestamp at ${path}`);
  }
  const millis = Date.parse(value);
  if (!Number.isFinite(millis)) {
    throw new UcpAp2ParseError(`Invalid RFC 3339 timestamp at ${path}`);
  }
  return Math.floor(millis / 1_000);
}

function parseTimestampMillis(value: string, path: string): number {
  if (!RFC3339_PATTERN.test(value)) {
    throw new UcpAp2ParseError(`Invalid RFC 3339 timestamp at ${path}`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new UcpAp2ParseError(`Invalid RFC 3339 timestamp at ${path}`);
  }
  return parsed;
}

function parseHttpsUrl(value: string, path: string): URL {
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

function requireJsonObject(value: unknown, path: string): JsonObject {
  if (!isObject(value)) {
    throw new UcpAp2ParseError(`Expected JSON object at ${path}`);
  }
  return value as JsonObject;
}

function requireString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new UcpAp2ParseError(`Expected non-empty string at ${path}`);
  }
  return value;
}

function requireSafeInteger(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new UcpAp2ParseError(`Expected safe integer at ${path}`);
  }
  return value;
}

function digestEquals(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && timingSafeEqual(left, right);
}

function base64UrlSha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("base64url");
}

function validateAllowedAlgorithms(
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

function validateEcJwk(
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

function verifyRawEcdsa(
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

function checkKeySnapshot(
  snapshot: PinnedEcKeySnapshot,
  expectedDigest: Sha256Digest,
  asOf: string | number,
  issues: InteropIssue[],
  path: string,
): void {
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
}

function extractCapabilityEntries(
  capabilities: JsonObject,
  name: string,
  path: string,
): readonly JsonObject[] {
  const value = capabilities[name];
  if (!Array.isArray(value) || value.length === 0) {
    throw new UcpAp2ParseError(`Missing capability at ${path}`);
  }
  return value.map((entry, index) => requireJsonObject(entry, `${path}[${String(index)}]`));
}

function hasVersionEntry(entries: readonly JsonObject[], version: string): boolean {
  return entries.some((entry) => entry.version === version);
}

export function verifyUcpProfileSnapshot(
  snapshot: UcpProfileSnapshot,
  options: VerifyUcpProfileOptions,
): InteropVerification<VerifiedUcpProfile> {
  const issues: InteropIssue[] = [];
  let profile: JsonObject;
  try {
    parseHttpsUrl(snapshot.profileUrl, "profileUrl");
    const capturedAt = parseTimestampMillis(snapshot.capturedAt, "capturedAt");
    const validUntil = parseTimestampMillis(snapshot.validUntil, "validUntil");
    const asOf = parseTimestampMillis(options.asOf, "asOf");
    if (capturedAt > validUntil) {
      issues.push(upstreamIssue(
        "UCP_PROFILE_WINDOW_INVALID",
        "profile",
        "Profile capture time is after its validity limit",
      ));
    }
    if (asOf > validUntil) {
      issues.push(eligibilityIssue(
        "UCP_PROFILE_SNAPSHOT_STALE",
        "profile",
        "Pinned UCP profile snapshot is stale",
      ));
    }
    profile = parseStrictJsonObject(strictUtf8(snapshot.profileBytes));
  } catch (error) {
    issues.push(upstreamIssue(
      "UCP_PROFILE_INVALID",
      "profile",
      error instanceof Error ? error.message : "Invalid UCP profile snapshot",
    ));
    return finish<VerifiedUcpProfile>(null, issues);
  }

  const actualDigest = sha256Bytes(snapshot.profileBytes);
  if (!isSha256Digest(snapshot.profileDigest) || snapshot.profileDigest !== actualDigest) {
    issues.push(upstreamIssue(
      "UCP_PROFILE_DIGEST_MISMATCH",
      "profileDigest",
      "Declared UCP profile digest does not match the exact captured bytes",
    ));
  }
  if (!isSha256Digest(options.expectedProfileDigest) || actualDigest !== options.expectedProfileDigest) {
    issues.push(eligibilityIssue(
      "UCP_PROFILE_PIN_MISMATCH",
      "profileDigest",
      "Captured UCP profile does not match the caller-owned digest pin",
    ));
  }
  if (snapshot.ap2Version !== UCP_AP2_EVIDENCE_PROFILE.ap2Version) {
    issues.push(upstreamIssue(
      "AP2_VERSION_UNSUPPORTED",
      "ap2Version",
      "Only the AP2 v0.2.0 evidence profile is supported",
    ));
  }

  try {
    const ucp = requireJsonObject(profile.ucp, "profile.ucp");
    if (ucp.version !== UCP_AP2_EVIDENCE_PROFILE.ucpVersion) {
      issues.push(upstreamIssue(
        "UCP_VERSION_UNSUPPORTED",
        "profile.ucp.version",
        "UCP profile version is not the pinned 2026-04-08 version",
      ));
    }
    const services = requireJsonObject(ucp.services, "profile.ucp.services");
    const shopping = services[UCP_AP2_EVIDENCE_PROFILE.ucpService];
    if (!Array.isArray(shopping)) {
      throw new UcpAp2ParseError("Missing UCP shopping service");
    }
    const restService = shopping.some((entry) => {
      if (!isObject(entry)) return false;
      return (
        entry.transport === UCP_AP2_EVIDENCE_PROFILE.ucpTransport &&
        entry.version === UCP_AP2_EVIDENCE_PROFILE.ucpVersion
      );
    });
    if (!restService) {
      issues.push(upstreamIssue(
        "UCP_REST_PROFILE_MISSING",
        "profile.ucp.services",
        "Pinned UCP REST shopping service declaration is missing",
      ));
    }

    const capabilities = requireJsonObject(ucp.capabilities, "profile.ucp.capabilities");
    const checkoutEntries = extractCapabilityEntries(
      capabilities,
      UCP_AP2_EVIDENCE_PROFILE.checkoutCapability,
      `profile.ucp.capabilities.${UCP_AP2_EVIDENCE_PROFILE.checkoutCapability}`,
    );
    if (!hasVersionEntry(checkoutEntries, UCP_AP2_EVIDENCE_PROFILE.ucpVersion)) {
      issues.push(upstreamIssue(
        "UCP_CHECKOUT_VERSION_UNSUPPORTED",
        "profile.ucp.capabilities",
        "Checkout capability is not pinned to UCP 2026-04-08",
      ));
    }
    const ap2Entries = extractCapabilityEntries(
      capabilities,
      UCP_AP2_EVIDENCE_PROFILE.ap2Extension,
      `profile.ucp.capabilities.${UCP_AP2_EVIDENCE_PROFILE.ap2Extension}`,
    );
    if (!hasVersionEntry(ap2Entries, UCP_AP2_EVIDENCE_PROFILE.ucpVersion)) {
      issues.push(upstreamIssue(
        "UCP_AP2_EXTENSION_VERSION_UNSUPPORTED",
        "profile.ucp.capabilities",
        "AP2 Mandates extension is not pinned to UCP 2026-04-08",
      ));
    }
  } catch (error) {
    issues.push(upstreamIssue(
      "UCP_PROFILE_SHAPE_INVALID",
      "profile",
      error instanceof Error ? error.message : "Invalid UCP profile structure",
    ));
  }

  const value: VerifiedUcpProfile = Object.freeze({
    profileId: UCP_AP2_EVIDENCE_PROFILE.id,
    profileDigest: actualDigest,
    profileUrl: snapshot.profileUrl,
    ucpVersion: UCP_AP2_EVIDENCE_PROFILE.ucpVersion,
    transport: UCP_AP2_EVIDENCE_PROFILE.ucpTransport,
    ap2Version: UCP_AP2_EVIDENCE_PROFILE.ap2Version,
    profile,
    authorizesNativeRole: false,
  });
  return finish(value, issues);
}

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

function parseJoseAlgorithm(value: unknown, path: string): JoseEcAlgorithm {
  if (value !== "ES256" && value !== "ES384" && value !== "ES512") {
    throw new UcpAp2ParseError(`Unsupported JOSE algorithm at ${path}`);
  }
  return value;
}

function validateJoseProtectedHeader(
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

export function verifyDetachedMerchantAuthorization(
  checkout: unknown,
  detachedJws: string,
  options: VerifyDetachedMerchantAuthorizationOptions,
): InteropVerification<DetachedMerchantAuthorization> {
  const issues: InteropIssue[] = [];
  let protectedHeader: JsonObject;
  let kid = options.keySnapshot.kid;
  let algorithm: JoseEcAlgorithm = "ES256";
  let canonicalPayloadDigest = sha256Bytes(new Uint8Array());
  try {
    if (
      typeof detachedJws !== "string" ||
      detachedJws.length === 0 ||
      Buffer.byteLength(detachedJws, "utf8") > 65_536
    ) {
      throw new UcpAp2ParseError("Detached merchant JWS is empty or exceeds the byte limit");
    }
    const segments = detachedJws.split(".");
    if (
      segments.length !== 3 ||
      segments[0] === undefined ||
      segments[1] !== "" ||
      segments[2] === undefined ||
      segments[0].length === 0 ||
      segments[2].length === 0
    ) {
      throw new UcpAp2ParseError("Merchant authorization must use detached compact JWS form");
    }
    protectedHeader = parseStrictJsonObject(
      strictUtf8(decodeBase64Url(segments[0], "merchantAuthorization.protected")),
    );
    const allowed = validateAllowedAlgorithms(
      options.allowedAlgorithms,
      ["ES256", "ES384", "ES512"],
    );
    const parsedHeader = validateJoseProtectedHeader(protectedHeader, allowed, "merchant");
    algorithm = parsedHeader.algorithm;
    kid = parsedHeader.kid as string;
    if (kid !== options.keySnapshot.kid) {
      issues.push(upstreamIssue(
        "UCP_AP2_MERCHANT_KEY_MISMATCH",
        "merchantAuthorization.protected.kid",
        "Merchant authorization kid does not match the pinned key snapshot",
      ));
    }

    const checkoutObject = requireJsonObject(checkout, "checkout");
    const ap2 = requireJsonObject(checkoutObject.ap2, "checkout.ap2");
    if (ap2.merchant_authorization !== detachedJws) {
      issues.push(upstreamIssue(
        "UCP_AP2_MERCHANT_AUTHORIZATION_UNBOUND",
        "checkout.ap2.merchant_authorization",
        "Detached JWS is not the exact merchant_authorization embedded in the checkout",
      ));
    }
    const payload: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
    for (const [name, value] of Object.entries(checkoutObject)) {
      if (name !== "ap2") payload[name] = value;
    }
    const bytes = canonicalBytes(payload);
    canonicalPayloadDigest = sha256Bytes(bytes);
    const signingInput = Buffer.from(
      `${segments[0]}.${Buffer.from(bytes).toString("base64url")}`,
      "ascii",
    );
    const signature = decodeBase64Url(
      segments[2],
      "merchantAuthorization.signature",
    );
    if (!verifyRawEcdsa(
      algorithm,
      signingInput,
      signature,
      options.keySnapshot.jwk,
      options.keySnapshot.kid,
    )) {
      issues.push(upstreamIssue(
        "UCP_AP2_MERCHANT_SIGNATURE_INVALID",
        "merchantAuthorization.signature",
        "Detached merchant authorization signature verification failed",
      ));
    }
  } catch (error) {
    issues.push(upstreamIssue(
      "UCP_AP2_MERCHANT_AUTHORIZATION_INVALID",
      "merchantAuthorization",
      error instanceof Error ? error.message : "Invalid merchant authorization",
    ));
    return finish<DetachedMerchantAuthorization>(null, issues);
  }

  checkKeySnapshot(
    options.keySnapshot,
    options.expectedKeySourceDigest,
    options.asOf,
    issues,
    "merchantKeySnapshot",
  );
  return finish(Object.freeze({
    exactCompact: detachedJws,
    protectedHeader,
    canonicalPayloadDigest,
    kid,
    algorithm,
  }), issues);
}

function parseJwtCompact(compact: string, path: string): ParsedJwt {
  const parts = compact.split(".");
  if (
    parts.length !== 3 ||
    parts[0] === undefined ||
    parts[1] === undefined ||
    parts[2] === undefined ||
    parts.some((entry) => entry.length === 0)
  ) {
    throw new UcpAp2ParseError(`Expected a three-segment compact JWT at ${path}`);
  }
  const protectedHeader = parseStrictJsonObject(
    strictUtf8(decodeBase64Url(parts[0], `${path}.protected`)),
  );
  const claims = parseStrictJsonObject(
    strictUtf8(decodeBase64Url(parts[1], `${path}.payload`)),
  );
  decodeBase64Url(parts[2], `${path}.signature`);
  return Object.freeze({
    exactCompact: compact,
    protectedSegment: parts[0],
    payloadSegment: parts[1],
    signatureSegment: parts[2],
    protectedHeader,
    claims,
  });
}

export function parseCompactAp2Token(token: string): ParsedCompactAp2Token {
  if (typeof token !== "string" || token.length === 0 || Buffer.byteLength(token) > 1_048_576) {
    throw new UcpAp2ParseError("AP2 compact token is empty or exceeds the byte limit");
  }
  const parts = token.split("~");
  const issuerCompact = parts.shift();
  if (issuerCompact === undefined || issuerCompact.length === 0) {
    throw new UcpAp2ParseError("AP2 compact token is missing its issuer JWT");
  }
  const issuerJwt = parseJwtCompact(issuerCompact, "token.issuerJwt");

  let keyBindingJwt: ParsedJwt | null = null;
  if (parts.length > 0) {
    const final = parts[parts.length - 1];
    if (final !== undefined && final.length > 0 && final.split(".").length === 3) {
      keyBindingJwt = parseJwtCompact(final, "token.keyBindingJwt");
      parts.pop();
    } else if (final === "") {
      parts.pop();
    }
  }
  if (parts.some((entry) => entry.length === 0 || entry.includes("."))) {
    throw new UcpAp2ParseError("AP2 token contains an invalid disclosure segment");
  }

  const algorithm = issuerJwt.claims._sd_alg === undefined
    ? "sha-256"
    : requireString(issuerJwt.claims._sd_alg, "token.issuerJwt.claims._sd_alg");
  if (algorithm !== "sha-256") {
    throw new UcpAp2ParseError("Only sha-256 SD-JWT disclosures are supported");
  }
  const disclosures = parts.map((encoded, index): ParsedSdJwtDisclosure => {
    const decodedBytes = decodeBase64Url(encoded, `token.disclosures[${String(index)}]`);
    const decoded = parseStrictJson(strictUtf8(decodedBytes));
    if (!Array.isArray(decoded) || (decoded.length !== 2 && decoded.length !== 3)) {
      throw new UcpAp2ParseError("SD-JWT disclosure must be a two- or three-element array");
    }
    if (typeof decoded[0] !== "string" || decoded[0].length < 8) {
      throw new UcpAp2ParseError("SD-JWT disclosure salt is missing or too short");
    }
    return Object.freeze({
      exact: encoded,
      digest: base64UrlSha256(encoded),
      decoded,
    });
  });

  const prefixSegments = [issuerCompact, ...parts];
  const sdJwtWithoutKeyBinding = keyBindingJwt === null
    ? token
    : `${prefixSegments.join("~")}~`;
  return Object.freeze({
    exact: token,
    issuerJwt,
    disclosures: Object.freeze(disclosures),
    keyBindingJwt,
    sdJwtWithoutKeyBinding,
  });
}

function materializeTopLevelDisclosures(
  parsed: ParsedCompactAp2Token,
  issues: InteropIssue[],
): JsonObject {
  const claims: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
  for (const [name, value] of Object.entries(parsed.issuerJwt.claims)) {
    claims[name] = value;
  }
  const digestList = claims._sd;
  const accepted = new Set<string>();
  if (digestList !== undefined) {
    if (!Array.isArray(digestList) || digestList.some((entry) => typeof entry !== "string")) {
      issues.push(upstreamIssue(
        "AP2_SD_DIGESTS_INVALID",
        "token.issuerJwt.claims._sd",
        "SD-JWT _sd must be an array of digest strings",
      ));
      return claims;
    }
    for (const entry of digestList) accepted.add(entry as string);
  }

  for (let index = 0; index < parsed.disclosures.length; index += 1) {
    const disclosure = parsed.disclosures[index] as ParsedSdJwtDisclosure;
    if (!accepted.has(disclosure.digest)) {
      issues.push(upstreamIssue(
        "AP2_DISCLOSURE_UNBOUND",
        `token.disclosures[${String(index)}]`,
        "Disclosure digest is not committed by the issuer JWT",
      ));
      continue;
    }
    const decoded = disclosure.decoded;
    if (!Array.isArray(decoded) || decoded.length !== 3 || typeof decoded[1] !== "string") {
      issues.push(upstreamIssue(
        "AP2_DISCLOSURE_SHAPE_UNSUPPORTED",
        `token.disclosures[${String(index)}]`,
        "Only top-level object-property disclosures are supported by this adapter",
      ));
      continue;
    }
    const name = decoded[1];
    if (hasOwn(claims, name)) {
      issues.push(upstreamIssue(
        "AP2_DISCLOSURE_CONFLICT",
        `token.disclosures[${String(index)}]`,
        "Disclosure conflicts with an existing claim",
      ));
      continue;
    }
    claims[name] = decoded[2] as JsonValue;
  }
  return claims;
}

function verifyParsedJwtSignature(
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

function publicJwkIdentity(jwk: EcPublicJwk): string {
  return canonicalize({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
}

function verifyAudience(value: unknown, expected: string): boolean {
  if (typeof value === "string") return value === expected;
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) return false;
  return value.includes(expected);
}

function verifyExpiryClaims(
  claims: JsonObject,
  asOf: number,
  issues: InteropIssue[],
  path: string,
): void {
  if (claims.exp === undefined) {
    issues.push(eligibilityIssue(
      "AP2_EXPIRY_MISSING",
      `${path}.exp`,
      "Mandate has no explicit expiration and is not eligible for durable authority evidence",
    ));
  } else {
    try {
      const exp = requireSafeInteger(claims.exp, `${path}.exp`);
      if (asOf >= exp) {
        issues.push(upstreamIssue("AP2_TOKEN_EXPIRED", `${path}.exp`, "Mandate is expired"));
      }
    } catch (error) {
      issues.push(upstreamIssue(
        "AP2_EXPIRY_INVALID",
        `${path}.exp`,
        error instanceof Error ? error.message : "Invalid expiration claim",
      ));
    }
  }
  if (claims.nbf !== undefined) {
    try {
      if (asOf < requireSafeInteger(claims.nbf, `${path}.nbf`)) {
        issues.push(upstreamIssue("AP2_TOKEN_NOT_YET_VALID", `${path}.nbf`, "Mandate is not yet valid"));
      }
    } catch (error) {
      issues.push(upstreamIssue(
        "AP2_NBF_INVALID",
        `${path}.nbf`,
        error instanceof Error ? error.message : "Invalid nbf claim",
      ));
    }
  }
  if (claims.iat !== undefined) {
    try {
      if (requireSafeInteger(claims.iat, `${path}.iat`) > asOf + 60) {
        issues.push(upstreamIssue(
          "AP2_IAT_IN_FUTURE",
          `${path}.iat`,
          "Mandate issuance time is in the future",
        ));
      }
    } catch (error) {
      issues.push(upstreamIssue(
        "AP2_IAT_INVALID",
        `${path}.iat`,
        error instanceof Error ? error.message : "Invalid iat claim",
      ));
    }
  }
}

function verifyAllowedMerchantConstraint(
  constraint: JsonObject,
  expectedMerchant: ExpectedMerchant | undefined,
): boolean {
  if (expectedMerchant === undefined || !Array.isArray(constraint.allowed)) return false;
  return constraint.allowed.some((candidate) => {
    if (!isObject(candidate) || candidate.id !== expectedMerchant.id) return false;
    return expectedMerchant.website === undefined || candidate.website === expectedMerchant.website;
  });
}

function verifyConstraints(
  claims: JsonObject,
  options: VerifyAp2MandateOptions,
  issues: InteropIssue[],
): void {
  if (claims.constraints === undefined) return;
  if (!Array.isArray(claims.constraints)) {
    issues.push(upstreamIssue(
      "AP2_CONSTRAINTS_INVALID",
      "token.claims.constraints",
      "Mandate constraints must be an array",
    ));
    return;
  }
  for (let index = 0; index < claims.constraints.length; index += 1) {
    const candidate = claims.constraints[index];
    if (!isObject(candidate) || typeof candidate.type !== "string") {
      issues.push(upstreamIssue(
        "AP2_CONSTRAINT_INVALID",
        `token.claims.constraints[${String(index)}]`,
        "Constraint is missing a string type",
      ));
      continue;
    }
    if (candidate.type === "checkout.allowed_merchants") {
      if (!verifyAllowedMerchantConstraint(candidate as JsonObject, options.expectedMerchant)) {
        issues.push(upstreamIssue(
          "AP2_CONSTRAINT_FAILED",
          `token.claims.constraints[${String(index)}]`,
          "Allowed-merchant constraint could not be satisfied",
        ));
      }
      continue;
    }
    issues.push(upstreamIssue(
      "AP2_CONSTRAINT_UNSUPPORTED",
      `token.claims.constraints[${String(index)}]`,
      "Unknown or unsupported constraint types fail closed",
    ));
  }
}

export function verifyAp2Mandate(
  options: VerifyAp2MandateOptions,
): InteropVerification<VerifiedAp2Mandate> {
  const issues: InteropIssue[] = [];
  let parsed: ParsedCompactAp2Token;
  let allowed: ReadonlySet<JoseEcAlgorithm>;
  let asOf: number;
  try {
    parsed = parseCompactAp2Token(options.token);
    allowed = validateAllowedAlgorithms(options.allowedAlgorithms, ["ES256"]);
    asOf = parseEpoch(options.asOf, "asOf");
  } catch (error) {
    issues.push(upstreamIssue(
      "AP2_TOKEN_INVALID",
      "token",
      error instanceof Error ? error.message : "Invalid AP2 token",
    ));
    return finish<VerifiedAp2Mandate>(null, issues);
  }

  checkKeySnapshot(
    options.issuerKeySnapshot,
    options.expectedIssuerKeySourceDigest,
    options.asOf,
    issues,
    "issuerKeySnapshot",
  );

  let issuerHeader: { readonly algorithm: JoseEcAlgorithm; readonly kid: string | null } | null = null;
  try {
    issuerHeader = verifyParsedJwtSignature(
      parsed.issuerJwt,
      options.issuerKeySnapshot.jwk,
      allowed,
      options.issuerKeySnapshot.kid,
      "issuer",
    );
  } catch (error) {
    issues.push(upstreamIssue(
      "AP2_ISSUER_SIGNATURE_INVALID",
      "token.issuerJwt",
      error instanceof Error ? error.message : "Issuer signature is invalid",
    ));
  }

  const claims = materializeTopLevelDisclosures(parsed, issues);
  const vct = claims.vct;
  if (!AP2_MANDATE_VCTS.includes(vct as Ap2MandateVct) || vct !== options.expectedVct) {
    issues.push(upstreamIssue(
      "AP2_VCT_MISMATCH",
      "token.claims.vct",
      "Mandate vct does not exactly match the expected versioned type",
    ));
  }
  if (claims.iss !== options.expectedIssuer) {
    issues.push(upstreamIssue(
      "AP2_ISSUER_MISMATCH",
      "token.claims.iss",
      "Mandate issuer does not match the expected issuer",
    ));
  }
  verifyExpiryClaims(claims, asOf, issues, "token.claims");

  const requireKeyBinding = options.requireKeyBinding ?? true;
  let keyBound = false;
  if (parsed.keyBindingJwt === null) {
    if (requireKeyBinding) {
      issues.push(upstreamIssue(
        "AP2_KEY_BINDING_MISSING",
        "token.keyBindingJwt",
        "A Key Binding JWT is required by this evidence profile",
      ));
    }
  } else {
    try {
      const cnf = requireJsonObject(claims.cnf, "token.claims.cnf");
      const embeddedJwk = requireJsonObject(cnf.jwk, "token.claims.cnf.jwk") as unknown as EcPublicJwk;
      const kbHeader = validateJoseProtectedHeader(
        parsed.keyBindingJwt.protectedHeader,
        allowed,
        "key-binding",
      );
      validateEcJwk(embeddedJwk, kbHeader.algorithm);
      if (
        options.expectedAgentJwk !== undefined &&
        publicJwkIdentity(embeddedJwk) !== publicJwkIdentity(options.expectedAgentJwk)
      ) {
        throw new UcpAp2ParseError("cnf key does not match the expected agent key");
      }
      verifyParsedJwtSignature(
        parsed.keyBindingJwt,
        embeddedJwk,
        allowed,
        null,
        "key-binding",
      );
      const kbClaims = parsed.keyBindingJwt.claims;
      if (!verifyAudience(kbClaims.aud, options.expectedAudience)) {
        throw new UcpAp2ParseError("Key Binding audience does not match");
      }
      if (kbClaims.nonce !== options.expectedNonce) {
        throw new UcpAp2ParseError("Key Binding nonce does not match");
      }
      const expectedSdHash = base64UrlSha256(parsed.sdJwtWithoutKeyBinding);
      if (kbClaims.sd_hash !== expectedSdHash) {
        throw new UcpAp2ParseError("Key Binding sd_hash does not match the exact SD-JWT presentation");
      }
      verifyExpiryClaims(kbClaims, asOf, issues, "token.keyBindingJwt.claims");
      keyBound = true;
    } catch (error) {
      issues.push(upstreamIssue(
        "AP2_KEY_BINDING_INVALID",
        "token.keyBindingJwt",
        error instanceof Error ? error.message : "Invalid AP2 Key Binding JWT",
      ));
    }
  }

  let checkoutHash: string | undefined;
  if (vct === "mandate.checkout.1") {
    if (typeof claims.checkout_jwt !== "string" || typeof claims.checkout_hash !== "string") {
      issues.push(upstreamIssue(
        "AP2_CHECKOUT_BINDING_MISSING",
        "token.claims",
        "Closed Checkout Mandate is missing checkout_jwt or checkout_hash",
      ));
    } else {
      checkoutHash = base64UrlSha256(claims.checkout_jwt);
      if (claims.checkout_hash !== checkoutHash) {
        issues.push(upstreamIssue(
          "AP2_CHECKOUT_HASH_MISMATCH",
          "token.claims.checkout_hash",
          "checkout_hash does not match the exact checkout_jwt field value",
        ));
      }
      if (
        options.expectedCheckoutJwt !== undefined &&
        claims.checkout_jwt !== options.expectedCheckoutJwt
      ) {
        issues.push(upstreamIssue(
          "AP2_CHECKOUT_JWT_MISMATCH",
          "token.claims.checkout_jwt",
          "Mandate is bound to a different Checkout JWT",
        ));
      }
      if (
        options.expectedCheckoutHash !== undefined &&
        claims.checkout_hash !== options.expectedCheckoutHash
      ) {
        issues.push(upstreamIssue(
          "AP2_EXPECTED_CHECKOUT_HASH_MISMATCH",
          "token.claims.checkout_hash",
          "Mandate checkout hash does not match the caller-owned expected value",
        ));
      }
    }
  } else if (vct === "mandate.payment.1" && options.expectedCheckoutHash !== undefined) {
    if (claims.transaction_id !== options.expectedCheckoutHash) {
      issues.push(upstreamIssue(
        "AP2_PAYMENT_CHECKOUT_BINDING_MISMATCH",
        "token.claims.transaction_id",
        "Payment Mandate transaction_id is not the expected checkout hash",
      ));
    } else {
      checkoutHash = options.expectedCheckoutHash;
    }
  }

  verifyConstraints(claims, options, issues);

  const result: VerifiedAp2Mandate = {
    profileId: UCP_AP2_EVIDENCE_PROFILE.id,
    ap2Version: UCP_AP2_EVIDENCE_PROFILE.ap2Version,
    exactToken: options.token,
    vct: AP2_MANDATE_VCTS.includes(vct as Ap2MandateVct)
      ? vct as Ap2MandateVct
      : options.expectedVct,
    issuer: typeof claims.iss === "string" ? claims.iss : options.expectedIssuer,
    claims,
    issuerKid: issuerHeader?.kid ?? options.issuerKeySnapshot.kid,
    issuerAlgorithm: issuerHeader?.algorithm ?? "ES256",
    keyBound,
    authorizesNativeRole: false,
    ...(checkoutHash === undefined ? {} : { checkoutHash }),
  };
  return finish(Object.freeze(result), issues);
}

function parseQuoted(
  input: string,
  start: number,
): { readonly value: string; readonly next: number } {
  if (input[start] !== "\"") throw new UcpAp2ParseError("Expected quoted string");
  let cursor = start + 1;
  let output = "";
  while (cursor < input.length) {
    const character = input[cursor];
    if (character === "\"") return { value: output, next: cursor + 1 };
    if (character === "\\" || character === "\r" || character === "\n" || character === undefined) {
      throw new UcpAp2ParseError("Escapes and line breaks are not accepted in signature parameters");
    }
    output += character;
    cursor += 1;
  }
  throw new UcpAp2ParseError("Unterminated quoted string");
}

/**
 * Parse the single-signature RFC 9421 subset used by UCP. The exact serialized
 * inner-list and parameters are retained for signature-base reconstruction.
 */
export function parseUcpSignatureInput(value: string): ParsedUcpSignatureInput {
  if (typeof value !== "string" || value.length > 16_384) {
    throw new UcpAp2ParseError("Signature-Input is empty or exceeds the byte limit");
  }
  const equals = value.indexOf("=");
  if (equals <= 0) throw new UcpAp2ParseError("Signature-Input is missing a label");
  const label = value.slice(0, equals);
  if (!/^[a-z][a-z0-9_-]*$/.test(label)) {
    throw new UcpAp2ParseError("Signature-Input label is invalid");
  }
  const serializedParameters = value.slice(equals + 1);
  if (!serializedParameters.startsWith("(")) {
    throw new UcpAp2ParseError("Signature-Input must contain an inner list");
  }
  let cursor = 1;
  const components: string[] = [];
  while (cursor < serializedParameters.length) {
    if (serializedParameters[cursor] === ")") {
      cursor += 1;
      break;
    }
    if (components.length > 0) {
      if (serializedParameters[cursor] !== " ") {
        throw new UcpAp2ParseError("Signature components must be separated by one space");
      }
      cursor += 1;
    }
    const parsed = parseQuoted(serializedParameters, cursor);
    if (!/^@?[a-z0-9][a-z0-9_-]*$/.test(parsed.value)) {
      throw new UcpAp2ParseError("Signature component identifier is invalid");
    }
    if (components.includes(parsed.value)) {
      throw new UcpAp2ParseError("Signature component identifiers must be unique");
    }
    components.push(parsed.value);
    cursor = parsed.next;
  }
  if (components.length === 0 || serializedParameters[cursor - 1] !== ")") {
    throw new UcpAp2ParseError("Signature-Input inner list is empty or unterminated");
  }

  const parameters = new Map<string, string | number | true>();
  while (cursor < serializedParameters.length) {
    if (serializedParameters[cursor] !== ";") {
      throw new UcpAp2ParseError("Invalid Signature-Input parameter separator");
    }
    cursor += 1;
    const nameMatch = /^[a-z][a-z0-9_-]*/.exec(serializedParameters.slice(cursor));
    if (nameMatch === null) throw new UcpAp2ParseError("Invalid Signature-Input parameter name");
    const name = nameMatch[0];
    cursor += name.length;
    if (parameters.has(name)) {
      throw new UcpAp2ParseError("Duplicate Signature-Input parameter");
    }
    if (serializedParameters[cursor] !== "=") {
      parameters.set(name, true);
      continue;
    }
    cursor += 1;
    if (serializedParameters[cursor] === "\"") {
      const parsed = parseQuoted(serializedParameters, cursor);
      parameters.set(name, parsed.value);
      cursor = parsed.next;
    } else {
      const integerMatch = /^(?:0|[1-9][0-9]*)/.exec(serializedParameters.slice(cursor));
      if (integerMatch === null) {
        throw new UcpAp2ParseError("Unsupported Signature-Input parameter value");
      }
      const parsed = Number(integerMatch[0]);
      if (!Number.isSafeInteger(parsed)) {
        throw new UcpAp2ParseError("Signature-Input integer parameter is unsafe");
      }
      parameters.set(name, parsed);
      cursor += integerMatch[0].length;
    }
  }
  if (parameters.has("alg")) {
    throw new UcpAp2ParseError("UCP derives the algorithm from the JWK; alg is not accepted here");
  }
  for (const name of parameters.keys()) {
    if (!new Set(["keyid", "created", "expires", "nonce", "tag"]).has(name)) {
      throw new UcpAp2ParseError("Unsupported Signature-Input parameter");
    }
  }
  const keyId = parameters.get("keyid");
  if (typeof keyId !== "string" || keyId.length === 0) {
    throw new UcpAp2ParseError("Signature-Input is missing keyid");
  }
  const created = parameters.get("created");
  const expires = parameters.get("expires");
  if (created !== undefined && typeof created !== "number") {
    throw new UcpAp2ParseError("Signature-Input created must be an integer");
  }
  if (expires !== undefined && typeof expires !== "number") {
    throw new UcpAp2ParseError("Signature-Input expires must be an integer");
  }
  return Object.freeze({
    label,
    components: Object.freeze(components),
    keyId,
    created: created ?? null,
    expires: expires ?? null,
    serializedParameters,
  });
}

function normalizeHeaders(headers: Readonly<Record<string, string>>): ReadonlyMap<string, string> {
  const result = new Map<string, string>();
  for (const [name, value] of Object.entries(headers)) {
    const normalizedName = name.toLowerCase();
    if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(normalizedName)) {
      throw new UcpAp2ParseError("HTTP field name is invalid");
    }
    if (result.has(normalizedName)) {
      throw new UcpAp2ParseError("HTTP fields collide after case normalization");
    }
    if (typeof value !== "string" || /[\r\n]/.test(value)) {
      throw new UcpAp2ParseError("HTTP field value contains an invalid line break");
    }
    result.set(normalizedName, value.trim().replace(/[ \t]+/g, " "));
  }
  return result;
}

function requestComponentValue(
  component: string,
  input: UcpRequestEvidenceInput,
  headers: ReadonlyMap<string, string>,
): string {
  switch (component) {
    case "@method":
      return input.method.toUpperCase();
    case "@authority":
      return input.authority;
    case "@path":
      return input.path;
    case "@query":
      if (input.query === undefined) {
        throw new UcpAp2ParseError("Signed @query has no request query value");
      }
      return input.query.startsWith("?") ? input.query : `?${input.query}`;
    default: {
      if (component.startsWith("@")) {
        throw new UcpAp2ParseError("Unsupported derived HTTP signature component");
      }
      const value = headers.get(component);
      if (value === undefined) {
        throw new UcpAp2ParseError("Signed HTTP field is absent from request metadata");
      }
      return value;
    }
  }
}

export function buildUcpRequestSignatureBase(
  input: UcpRequestEvidenceInput,
  parsed = parseUcpSignatureInput(input.signatureInput),
): Uint8Array {
  const headers = normalizeHeaders(input.headers);
  const lines = parsed.components.map((component) =>
    `"${component}": ${requestComponentValue(component, input, headers)}`);
  lines.push(`"@signature-params": ${parsed.serializedParameters}`);
  return Buffer.from(lines.join("\n"), "utf8");
}

function parseUcpSignatureValue(
  value: string,
  expectedLabel: string,
): Uint8Array {
  const match = /^([a-z][a-z0-9_-]*)=:([A-Za-z0-9+/]*={0,2}):$/.exec(value);
  if (match === null || match[1] !== expectedLabel || match[2] === undefined) {
    throw new UcpAp2ParseError("Signature field label or byte sequence is invalid");
  }
  return decodeBase64(match[2], "Signature");
}

function requiredUcpRequestComponents(
  input: UcpRequestEvidenceInput,
  headers: ReadonlyMap<string, string>,
): readonly string[] {
  const required = ["@method", "@authority", "@path"];
  if (input.query !== undefined && input.query.length > 0) required.push("@query");
  if (headers.has("ucp-agent")) required.push("ucp-agent");
  if (STATE_CHANGING_METHODS.has(input.method.toUpperCase())) required.push("idempotency-key");
  if (input.rawBody !== undefined) required.push("content-digest", "content-type");
  return required;
}

function validateUcpAgentHeader(value: string): void {
  const match = /^profile="([^"\\]+)"$/.exec(value);
  if (match === null || match[1] === undefined) {
    throw new UcpAp2ParseError("UCP-Agent must contain exactly one quoted profile URL");
  }
  parseHttpsUrl(match[1], "ucp-agent.profile");
}

function validIdempotencyKey(value: string): boolean {
  return (
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value) ||
    /^[A-Za-z0-9_-]{22,}$/.test(value)
  );
}

export function verifyUcpRequestEvidence(
  input: UcpRequestEvidenceInput,
): InteropVerification<VerifiedUcpRequestEvidence> {
  const issues: InteropIssue[] = [];
  let parsed: ParsedUcpSignatureInput;
  let headers: ReadonlyMap<string, string>;
  let algorithm: UcpHttpAlgorithm = "ES256";
  let rawBodyDigest: Sha256Digest = sha256Bytes(input.rawBody ?? new Uint8Array());
  let operation = "";
  let replayStatus: "new" | "cached" | "unresolved" = "new";

  try {
    parsed = parseUcpSignatureInput(input.signatureInput);
    headers = normalizeHeaders(input.headers);
    if (!/^[A-Z]+$/.test(input.method.toUpperCase())) {
      throw new UcpAp2ParseError("HTTP method is invalid");
    }
    if (
      input.authority.length === 0 ||
      /[\r\n/]/.test(input.authority) ||
      !input.path.startsWith("/") ||
      /[\r\n]/.test(input.path)
    ) {
      throw new UcpAp2ParseError("HTTP authority or path is invalid");
    }
    operation = `${input.method.toUpperCase()} ${input.path}${
      input.query === undefined || input.query.length === 0
        ? ""
        : input.query.startsWith("?") ? input.query : `?${input.query}`
    }`;

    if (parsed.keyId !== input.keySnapshot.kid) {
      issues.push(upstreamIssue(
        "UCP_SIGNATURE_KEY_MISMATCH",
        "signature-input.keyid",
        "Signature keyid does not match the pinned key snapshot",
      ));
    }
    algorithm = input.keySnapshot.jwk.crv === "P-384" ? "ES384" : "ES256";
    if (input.keySnapshot.jwk.crv === "P-521") {
      issues.push(upstreamIssue(
        "UCP_ALGORITHM_UNSUPPORTED",
        "keySnapshot.jwk.crv",
        "UCP REST permits ES256 and optionally ES384, not ES512",
      ));
    }

    const required = requiredUcpRequestComponents(input, headers);
    for (const component of required) {
      if (!parsed.components.includes(component)) {
        issues.push(upstreamIssue(
          "UCP_SIGNED_COMPONENT_MISSING",
          "signature-input.components",
          `Required signed component ${component} is missing`,
        ));
      }
    }

    const ucpAgent = headers.get("ucp-agent");
    if (ucpAgent !== undefined) validateUcpAgentHeader(ucpAgent);

    if (input.rawBody !== undefined) {
      rawBodyDigest = sha256Bytes(input.rawBody);
      const contentDigest = headers.get("content-digest");
      if (contentDigest === undefined) {
        issues.push(upstreamIssue(
          "UCP_CONTENT_DIGEST_MISSING",
          "headers.content-digest",
          "Content-Digest is required when a request has a body",
        ));
      } else {
        const bodyReport = verifyRawBodyContentDigest(input.rawBody, contentDigest);
        issues.push(...bodyReport.issues);
      }
      if (headers.get("content-type") === undefined) {
        issues.push(upstreamIssue(
          "UCP_CONTENT_TYPE_MISSING",
          "headers.content-type",
          "Content-Type is required when a request has a body",
        ));
      }
    }

    if (STATE_CHANGING_METHODS.has(input.method.toUpperCase())) {
      const idempotencyKey = headers.get("idempotency-key");
      if (idempotencyKey === undefined || !validIdempotencyKey(idempotencyKey)) {
        issues.push(upstreamIssue(
          "UCP_IDEMPOTENCY_KEY_INVALID",
          "headers.idempotency-key",
          "State-changing request lacks a high-entropy idempotency key",
        ));
      } else {
        const previous = input.idempotencyLedger?.get(idempotencyKey);
        if (previous !== undefined) {
          if (previous.operation !== operation || previous.rawBodyDigest !== rawBodyDigest) {
            issues.push(upstreamIssue(
              "UCP_IDEMPOTENCY_CONFLICT",
              "headers.idempotency-key",
              "Idempotency key was previously used for different request bytes or operation",
            ));
          } else if (input.replayDisposition === "cached") {
            replayStatus = "cached";
          } else {
            replayStatus = "unresolved";
            issues.push(eligibilityIssue(
              "UCP_REPLAY_DISPOSITION_UNPROVEN",
              "replayDisposition",
              "Duplicate request is not evidenced as a cached, side-effect-free replay",
            ));
          }
        } else if (input.replayDisposition === "cached") {
          issues.push(upstreamIssue(
            "UCP_REPLAY_RECORD_MISSING",
            "replayDisposition",
            "Cached replay was asserted without a matching prior idempotency record",
          ));
        }
      }
    }

    const asOf = parseEpoch(input.asOf, "asOf");
    if (parsed.created !== null && parsed.created > asOf + 60) {
      issues.push(upstreamIssue(
        "UCP_SIGNATURE_CREATED_IN_FUTURE",
        "signature-input.created",
        "Signature creation time is in the future",
      ));
    }
    if (parsed.expires !== null && asOf >= parsed.expires) {
      issues.push(upstreamIssue(
        "UCP_SIGNATURE_EXPIRED",
        "signature-input.expires",
        "HTTP message signature is expired",
      ));
    }

    const signature = parseUcpSignatureValue(input.signature, parsed.label);
    const signatureBase = buildUcpRequestSignatureBase(input, parsed);
    if (!verifyRawEcdsa(
      algorithm,
      signatureBase,
      signature,
      input.keySnapshot.jwk,
      input.keySnapshot.kid,
    )) {
      issues.push(upstreamIssue(
        "UCP_SIGNATURE_INVALID",
        "signature",
        "RFC 9421 signature verification failed",
      ));
    }
  } catch (error) {
    issues.push(upstreamIssue(
      "UCP_REQUEST_EVIDENCE_INVALID",
      "request",
      error instanceof Error ? error.message : "Invalid UCP request evidence",
    ));
    return finish<VerifiedUcpRequestEvidence>(null, issues);
  }

  checkKeySnapshot(
    input.keySnapshot,
    input.expectedKeySourceDigest,
    input.asOf,
    issues,
    "keySnapshot",
  );

  const value: VerifiedUcpRequestEvidence = Object.freeze({
    profileId: UCP_AP2_EVIDENCE_PROFILE.id,
    operation,
    keyId: parsed.keyId,
    algorithm,
    signedComponents: parsed.components,
    rawBodyDigest,
    replayStatus,
    upstreamValid: true,
  });
  return finish(value, issues);
}

export function correlateTransactionLifecycle(
  input: readonly TransactionLifecycleEvidence[],
): readonly TransactionLifecycleCorrelation[] {
  const groups = new Map<string, TransactionLifecycleEvidence[]>();
  for (const event of input) {
    if (
      event.eventId.length === 0 ||
      event.transactionId.length === 0 ||
      !TRANSACTION_LIFECYCLE_KINDS.includes(event.kind) ||
      !isSha256Digest(event.sourceDigest)
    ) {
      throw new UcpAp2ParseError("Lifecycle evidence contains an invalid identifier, kind, or digest");
    }
    parseTimestampMillis(event.occurredAt, "lifecycle.occurredAt");
    const group = groups.get(event.transactionId) ?? [];
    group.push(event);
    groups.set(event.transactionId, group);
  }

  const correlations: TransactionLifecycleCorrelation[] = [];
  for (const [transactionId, group] of [...groups.entries()].sort(([left], [right]) =>
    left.localeCompare(right))) {
    const sorted = [...group].sort((left, right) =>
      left.occurredAt.localeCompare(right.occurredAt) || left.eventId.localeCompare(right.eventId));
    const byId = new Map<string, TransactionLifecycleEvidence[]>();
    for (const event of sorted) {
      const entries = byId.get(event.eventId) ?? [];
      entries.push(event);
      byId.set(event.eventId, entries);
    }
    const duplicateEventIds: string[] = [];
    const conflictingEventIds: string[] = [];
    for (const [eventId, entries] of byId) {
      if (entries.length > 1) {
        duplicateEventIds.push(eventId);
        if (new Set(entries.map((entry) => entry.sourceDigest)).size > 1) {
          conflictingEventIds.push(eventId);
        }
      }
    }
    const eventIds = new Set(sorted.map((entry) => entry.eventId));
    const orphanEventIds = sorted
      .filter((entry) => (entry.parentEventIds ?? []).some((parent) => !eventIds.has(parent)))
      .map((entry) => entry.eventId);

    const eligible = sorted.filter((entry) => entry.upstreamValid && entry.evidenceEligible);
    const coverage: EvidenceCoverageItem[] = [
      Object.freeze({
        requirement: "checkout_evidence",
        state: eligible.some((entry) => entry.kind === "checkout") ? "satisfied" : "unknown",
        sourceRefs: Object.freeze(
          eligible.filter((entry) => entry.kind === "checkout").map((entry) => entry.eventId),
        ),
      }),
      Object.freeze({
        requirement: "order_evidence",
        state: eligible.some((entry) => entry.kind === "order") ? "satisfied" : "unknown",
        sourceRefs: Object.freeze(
          eligible.filter((entry) => entry.kind === "order").map((entry) => entry.eventId),
        ),
      }),
      Object.freeze({
        requirement: "post_order_adjustments",
        state: eligible.some((entry) =>
          entry.kind === "refund" ||
          entry.kind === "return" ||
          entry.kind === "cancel" ||
          entry.kind === "adjustment")
          ? "satisfied"
          : "unknown",
        sourceRefs: Object.freeze(
          eligible
            .filter((entry) =>
              entry.kind === "refund" ||
              entry.kind === "return" ||
              entry.kind === "cancel" ||
              entry.kind === "adjustment")
            .map((entry) => entry.eventId),
        ),
      }),
      Object.freeze({
        requirement: "complete_upstream_history",
        state: "unknown",
        sourceRefs: Object.freeze([]),
        note: "Bounded imported evidence cannot prove that no upstream events are missing",
      }),
    ];
    correlations.push(Object.freeze({
      transactionId,
      events: Object.freeze(sorted),
      duplicateEventIds: Object.freeze(duplicateEventIds.sort()),
      conflictingEventIds: Object.freeze(conflictingEventIds.sort()),
      orphanEventIds: Object.freeze([...new Set(orphanEventIds)].sort()),
      historyCompleteness: "unknown",
      coverage: Object.freeze(coverage),
    }));
  }
  return Object.freeze(correlations);
}
