import type { JsonObject, JsonValue, Sha256Digest } from "../domain.js";
import type {
  AP2_RECEIPT_KINDS,
  AP2_V020_MANDATE_CHAIN_PROFILE,
  AP2_MANDATE_VCTS,
  UCP_AP2_EVIDENCE_PROFILE,
} from "./profile.js";
import type { TransactionLifecycleKind } from "./transaction-lifecycle.js";

/**
 * Type/interface declarations exported by the UCP/AP2 evidence adapter. These
 * declarations are collected here so downstream modules can import them
 * without pulling in the wire-byte helpers.
 */

export type Ap2MandateVct = (typeof AP2_MANDATE_VCTS)[number];
export type Ap2ReceiptKind = (typeof AP2_RECEIPT_KINDS)[number];
export type Ap2ReceiptStatus = "Success" | "Error";
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
  /** Exact AP2 sd_hash of the associated open Checkout Mandate. */
  readonly expectedOpenCheckoutHash?: string;
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

export interface VerifiedAp2MandateChain extends VerifiedAp2Mandate {
  readonly chainProfileId: typeof AP2_V020_MANDATE_CHAIN_PROFILE.id;
  readonly presentationMode: "human_present" | "human_not_present";
  readonly chainDepth: number;
  /** Exact compact JWS of the terminal closed Mandate, without disclosures. */
  readonly terminalCompactJws: string;
}

export interface VerifyAp2ReceiptOptions {
  /** Exact compact verifier-signed Receipt JWT. */
  readonly token: string;
  readonly kind: Ap2ReceiptKind;
  readonly issuerKeySnapshot: PinnedEcKeySnapshot;
  readonly expectedIssuerKeySourceDigest: Sha256Digest;
  readonly expectedIssuer: string;
  readonly asOf: string | number;
  readonly allowedAlgorithms?: readonly JoseEcAlgorithm[];
  /** Exact closed Mandate presentation to which the Receipt must bind. */
  readonly expectedMandateToken?: string;
}

export interface VerifiedAp2Receipt {
  readonly profileId: typeof UCP_AP2_EVIDENCE_PROFILE.id;
  readonly ap2Version: typeof UCP_AP2_EVIDENCE_PROFILE.ap2Version;
  readonly exactToken: string;
  readonly kind: Ap2ReceiptKind;
  readonly issuer: string;
  readonly issuedAt: number;
  readonly status: Ap2ReceiptStatus;
  readonly reference: string;
  readonly claims: JsonObject;
  readonly issuerKid: string;
  readonly issuerAlgorithm: JoseEcAlgorithm;
  /** AP2 evidence does not by itself establish a native MandateBound role. */
  readonly authorizesNativeRole: false;
}

export interface VerifyAp2CheckoutJwtOptions {
  /** Exact merchant-signed Checkout JWT disclosed by the Checkout Mandate. */
  readonly token: string;
  readonly merchantKeySnapshot: PinnedEcKeySnapshot;
  readonly expectedMerchantKeySourceDigest: Sha256Digest;
  readonly asOf: string | number;
  readonly allowedAlgorithms?: readonly JoseEcAlgorithm[];
  readonly expectedIssuer?: string;
}

export interface VerifiedAp2CheckoutJwt {
  readonly profileId: typeof UCP_AP2_EVIDENCE_PROFILE.id;
  readonly ap2Version: typeof UCP_AP2_EVIDENCE_PROFILE.ap2Version;
  readonly exactToken: string;
  readonly claims: JsonObject;
  readonly issuer: string | null;
  readonly merchantKid: string;
  readonly merchantAlgorithm: JoseEcAlgorithm;
  /** Checkout contents remain evidence and never grant a native actor role. */
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

export type {
  TransactionLifecycleKind,
} from "./transaction-lifecycle.js";

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
