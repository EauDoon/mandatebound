import { Buffer } from "node:buffer";
import { isSha256Digest, sha256Digest } from "./canonical.js";
import type { Sha256Digest } from "./domain.js";
import {
  AP2_V020_MANDATE_CHAIN_PROFILE,
  computeAp2OpenMandateHash,
  verifyAp2CheckoutJwt,
  verifyAp2MandateChain,
  verifyAp2Receipt,
  type Ap2ReceiptStatus,
  type EvidenceCoverageItem,
  type InteropIssue,
  type InteropVerification,
  type VerifiedAp2Mandate,
  type VerifiedAp2Receipt,
  type VerifyAp2MandateOptions,
  type VerifyAp2ReceiptOptions,
  type VerifyAp2CheckoutJwtOptions,
} from "./ucp-ap2.js";
import { LEGAL_EFFECT, RELEASE_VERSION } from "./version.js";

export const AP2_DISPUTE_EVIDENCE_PROFILE = Object.freeze({
  id: "ap2-v0.2.0+b4587ac1d055888a73b4b21750973cffba961793",
  ap2Version: "0.2.0",
  ap2ReleaseCommit: "b4587ac1d055888a73b4b21750973cffba961793",
  mandateProfileId: AP2_V020_MANDATE_CHAIN_PROFILE.id,
  receiptReferenceProfile: "sha256-terminal-compact-jws",
  retrievalTransport: "caller-supplied",
  builtInNetworkAccess: false,
} as const);

export const AP2_DISPUTE_ARTIFACT_KINDS = Object.freeze([
  "checkout_mandate",
  "checkout_receipt",
  "payment_mandate",
  "payment_receipt",
] as const);

export const AP2_DISPUTE_SOURCE_ROLES = Object.freeze([
  "shopping_agent",
  "merchant",
  "credential_provider",
  "network",
  "merchant_payment_processor",
] as const);

export type Ap2DisputeArtifactKind = (typeof AP2_DISPUTE_ARTIFACT_KINDS)[number];
export type Ap2DisputeSourceRole = (typeof AP2_DISPUTE_SOURCE_ROLES)[number];
export type Ap2DisputeResolutionStatus = "evidence_verified" | "unresolved";
export type Ap2DisputeGateState = "passed" | "failed" | "unknown";
export type Ap2DisputeIssueImpact =
  | "missing"
  | "conflicting"
  | "invalid"
  | "unsupported"
  | "retrieval"
  | "eligibility";

export interface Ap2DisputeArtifactInput {
  readonly kind: Ap2DisputeArtifactKind;
  /** Exact compact SD-JWT presentation or compact Receipt JWT. */
  readonly token: string;
}

export interface Ap2DisputeEvidenceSource {
  readonly sourceId: string;
  readonly role: Ap2DisputeSourceRole;
  readonly retrievedAt: string;
  readonly artifacts: readonly Ap2DisputeArtifactInput[];
}

export type Ap2DisputeMandateVerificationPlan = Omit<
  VerifyAp2MandateOptions,
  "token" | "expectedVct" | "expectedCheckoutHash" | "asOf"
>;

export type Ap2DisputeReceiptVerificationPlan = Omit<
  VerifyAp2ReceiptOptions,
  "token" | "kind" | "expectedMandateToken" | "asOf"
>;

export type Ap2DisputeCheckoutJwtVerificationPlan = Omit<
  VerifyAp2CheckoutJwtOptions,
  "token" | "asOf"
>;

export interface Ap2DisputeVerificationPlan {
  /** Caller-owned trust and challenge inputs. Sources cannot supply these pins. */
  readonly checkoutMandate: Ap2DisputeMandateVerificationPlan;
  readonly checkoutJwt: Ap2DisputeCheckoutJwtVerificationPlan;
  readonly checkoutReceipt: Ap2DisputeReceiptVerificationPlan;
  readonly paymentMandate: Ap2DisputeMandateVerificationPlan;
  readonly paymentReceipt: Ap2DisputeReceiptVerificationPlan;
}

export interface AssembleAp2DisputeEvidenceInput {
  /** AP2 Payment Mandate transaction_id and Checkout Mandate checkout_hash. */
  readonly transactionId: string;
  readonly asOf: string;
  readonly verificationPlan: Ap2DisputeVerificationPlan;
  readonly sources: readonly Ap2DisputeEvidenceSource[];
}

export interface Ap2DisputeRetrievalRequest {
  readonly profileId: typeof AP2_DISPUTE_EVIDENCE_PROFILE.id;
  readonly transactionId: string;
  readonly asOf: string;
  readonly signal?: AbortSignal;
}

export interface Ap2DisputeRetrievalResponse {
  readonly retrievedAt: string;
  readonly artifacts: readonly Ap2DisputeArtifactInput[];
}

export interface Ap2DisputeEvidenceRetriever {
  readonly id: string;
  readonly role: Ap2DisputeSourceRole;
  /**
   * The caller owns transport authentication and authorization. Knowledge of a
   * transaction ID is never treated as retrieval authority by this library.
   */
  readonly retrieve: (
    request: Ap2DisputeRetrievalRequest,
  ) => Promise<Ap2DisputeRetrievalResponse | null>;
}

export interface ResolveAp2DisputeEvidenceInput {
  readonly transactionId: string;
  readonly asOf: string;
  readonly verificationPlan: Ap2DisputeVerificationPlan;
  readonly retrievers: readonly Ap2DisputeEvidenceRetriever[];
  readonly signal?: AbortSignal;
}

export interface Ap2DisputeRetrievalAttempt {
  readonly sourceId: string;
  readonly role: Ap2DisputeSourceRole;
  readonly status: "provided" | "empty" | "failed";
  readonly artifactKinds: readonly Ap2DisputeArtifactKind[];
}

export interface Ap2DisputeIssue {
  readonly code: string;
  readonly path: string;
  /** Bounded diagnostic. It never contains tokens, Checkout data, or secrets. */
  readonly message: string;
  readonly impact: Ap2DisputeIssueImpact;
  readonly sourceRefs: readonly string[];
}

export interface Ap2DisputeGateResult {
  readonly gate: string;
  readonly state: Ap2DisputeGateState;
  readonly sourceRefs: readonly string[];
}

export interface Ap2DisputeSelectedArtifact {
  readonly kind: Ap2DisputeArtifactKind;
  readonly digest: Sha256Digest;
  readonly sourceRefs: readonly string[];
  readonly issuer: string;
  readonly issuerKid: string;
  readonly mandateVct?: "mandate.checkout.1" | "mandate.payment.1";
  readonly receiptStatus?: Ap2ReceiptStatus;
  readonly issuedAt?: number;
}

export interface Ap2DisputeEvidenceResolution {
  readonly schemaId: "MandateBoundAp2DisputeEvidenceResolution/v1";
  readonly releaseVersion: typeof RELEASE_VERSION;
  readonly profile: typeof AP2_DISPUTE_EVIDENCE_PROFILE;
  readonly transactionId: string;
  readonly asOf: string;
  readonly status: Ap2DisputeResolutionStatus;
  readonly selectedArtifacts: readonly Ap2DisputeSelectedArtifact[];
  readonly retrievalAttempts: readonly Ap2DisputeRetrievalAttempt[];
  readonly gates: readonly Ap2DisputeGateResult[];
  readonly coverage: readonly EvidenceCoverageItem[];
  readonly issues: readonly Ap2DisputeIssue[];
  /** AP2 retrieval is bounded and cannot prove that no upstream evidence exists. */
  readonly historyCompleteness: "unknown";
  readonly legalEffect: typeof LEGAL_EFFECT;
  readonly disputeOutcome: "not-determined";
  readonly resolutionDigest: Sha256Digest;
}

export type Ap2ReportedRevocationStatus = "not_revoked" | "revoked" | "unknown";

export interface Ap2CheckoutVersionInput {
  readonly versionId: string;
  readonly sourceId: string;
  readonly observedAt: string;
  /** Exact merchant-signed Checkout JWT. Evidence packs are sensitive. */
  readonly checkoutJwt: string;
}

export interface Ap2CheckoutVersionEvidence extends Ap2CheckoutVersionInput {
  readonly checkoutJwtDigest: Sha256Digest;
}

export interface Ap2RevocationEvidenceInput {
  readonly recordId: string;
  readonly mandateKind: "checkout_mandate" | "payment_mandate";
  readonly sourceId: string;
  readonly checkedAt: string;
  readonly reportedStatus: Ap2ReportedRevocationStatus;
  /** Canonical base64 of the exact external revocation snapshot bytes. */
  readonly snapshotBase64: string;
}

export interface Ap2RevocationEvidence extends Ap2RevocationEvidenceInput {
  readonly snapshotDigest: Sha256Digest;
}

export interface PackAp2DisputeEvidenceInput extends AssembleAp2DisputeEvidenceInput {
  readonly createdAt: string;
  readonly checkoutVersions: readonly Ap2CheckoutVersionInput[];
  readonly revocations: readonly Ap2RevocationEvidenceInput[];
}

export interface Ap2DisputeEvidencePack {
  readonly schemaId: "MandateBoundAp2EvidencePack/v1";
  readonly releaseVersion: typeof RELEASE_VERSION;
  readonly profile: typeof AP2_DISPUTE_EVIDENCE_PROFILE;
  readonly transactionId: string;
  readonly asOf: string;
  readonly createdAt: string;
  readonly verificationPlan: Ap2DisputeVerificationPlan;
  readonly sources: readonly Ap2DisputeEvidenceSource[];
  readonly checkoutVersions: readonly Ap2CheckoutVersionEvidence[];
  readonly revocations: readonly Ap2RevocationEvidence[];
  readonly legalEffect: typeof LEGAL_EFFECT;
  readonly packDigest: Sha256Digest;
}

export interface VerifyAp2DisputeEvidencePackOptions {
  /** Independently retained content address for the Pack under review. */
  readonly expectedPackDigest: Sha256Digest;
}

export type Ap2CheckoutVersionBinding = "matched" | "missing" | "conflicting";
export type Ap2RevocationCoverage = "provided" | "missing";
export type Ap2ReportedRevocationState = "not_revoked" | "revoked" | "unknown";

export interface Ap2DisputeEvidencePackVerification {
  readonly schemaId: "MandateBoundAp2EvidencePackVerification/v1";
  readonly releaseVersion: typeof RELEASE_VERSION;
  readonly status: "verified" | "unresolved";
  readonly packDigest: Sha256Digest | null;
  readonly expectedPackDigest: Sha256Digest | null;
  readonly anchorMatched: boolean;
  readonly digestValid: boolean;
  readonly checkoutVersionBinding: Ap2CheckoutVersionBinding;
  readonly revocationCoverage: Ap2RevocationCoverage;
  /** This is a report contained in imported evidence, not an authenticated fact. */
  readonly reportedRevocationState: Ap2ReportedRevocationState;
  readonly resolution: Ap2DisputeEvidenceResolution | null;
  readonly issues: readonly Ap2DisputeIssue[];
  readonly legalEffect: typeof LEGAL_EFFECT;
  readonly reportDigest: Sha256Digest;
}

export interface Ap2EvidenceTimelineEvent {
  readonly occurredAt: string;
  readonly eventType: "checkout_version" | "artifact_retrieval" | "revocation_check" | "resolution";
  readonly label: string;
  readonly state: string;
  readonly digest?: Sha256Digest;
  readonly sourceRefs: readonly string[];
}

interface Candidate {
  readonly kind: Ap2DisputeArtifactKind;
  readonly token: string;
  readonly digest: Sha256Digest;
  readonly sourceId: string;
}

interface SelectedInternal {
  readonly token: string;
  readonly output: Ap2DisputeSelectedArtifact;
  readonly verifiedMandate?: VerifiedAp2Mandate;
}

const SOURCE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const RFC3339_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const RFC3339_PARTS_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](\d{2}):(\d{2}))$/;
const MAX_SOURCES = 16;
const MAX_ARTIFACTS = 64;
const MAX_ARTIFACT_TOKEN_BYTES = 1_048_576;
const MAX_RESOLUTION_ISSUES = 256;
const MAX_CHECKOUT_VERSIONS = 32;
const MAX_REVOCATION_RECORDS = 64;
const MAX_REVOCATION_SNAPSHOT_BYTES = 1_048_576;
const MAX_PACK_CANONICAL_BYTES = 16_777_216;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function compareCodeUnits(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

const ALLOWED_SOURCE_ROLES: Readonly<Record<
  Ap2DisputeArtifactKind,
  ReadonlySet<Ap2DisputeSourceRole>
>> = Object.freeze({
  checkout_mandate: new Set<Ap2DisputeSourceRole>(["shopping_agent", "merchant"]),
  checkout_receipt: new Set<Ap2DisputeSourceRole>(["shopping_agent", "merchant"]),
  payment_mandate: new Set<Ap2DisputeSourceRole>([
    "shopping_agent",
    "credential_provider",
    "network",
    "merchant_payment_processor",
  ]),
  payment_receipt: new Set<Ap2DisputeSourceRole>([
    "shopping_agent",
    "credential_provider",
    "network",
    "merchant_payment_processor",
  ]),
});

function parseTimestamp(value: string, path: string): number {
  const match = RFC3339_PATTERN.test(value) ? RFC3339_PARTS_PATTERN.exec(value) : null;
  if (match === null) throw new TypeError(`Invalid timestamp at ${path}`);
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
    throw new TypeError(`Invalid timestamp at ${path}`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new TypeError(`Invalid timestamp at ${path}`);
  return parsed;
}

function validateTransactionId(value: string): void {
  if (
    typeof value !== "string" ||
    !BASE64URL_PATTERN.test(value) ||
    value.includes("=") ||
    value.length % 4 === 1
  ) {
    throw new TypeError("AP2 transaction ID must be canonical base64url");
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.byteLength !== 32 || bytes.toString("base64url") !== value) {
    throw new TypeError("AP2 transaction ID must encode one SHA-256 digest");
  }
}

function freezeStrings(values: Iterable<string>): readonly string[] {
  return Object.freeze([...new Set(values)].sort());
}

function makeIssue(
  code: string,
  path: string,
  message: string,
  impact: Ap2DisputeIssueImpact,
  sourceRefs: Iterable<string> = [],
): Ap2DisputeIssue {
  return Object.freeze({
    code,
    path,
    message,
    impact,
    sourceRefs: freezeStrings(sourceRefs),
  });
}

function issueImpact(issue: InteropIssue): Ap2DisputeIssueImpact {
  if (issue.code.includes("UNSUPPORTED")) return "unsupported";
  return issue.impact === "evidence_eligibility" ? "eligibility" : "invalid";
}

function importVerificationIssues(
  target: Ap2DisputeIssue[],
  artifactKind: Ap2DisputeArtifactKind,
  sourceRefs: readonly string[],
  report: InteropVerification<unknown>,
): void {
  for (const issue of report.issues) {
    target.push(makeIssue(
      issue.code,
      `artifacts.${artifactKind}.${issue.path}`,
      issue.message,
      issueImpact(issue),
      sourceRefs,
    ));
  }
}

function gate(
  name: string,
  state: Ap2DisputeGateState,
  sourceRefs: Iterable<string>,
): Ap2DisputeGateResult {
  return Object.freeze({ gate: name, state, sourceRefs: freezeStrings(sourceRefs) });
}

function coverage(
  requirement: string,
  state: EvidenceCoverageItem["state"],
  sourceRefs: Iterable<string>,
  note?: string,
): EvidenceCoverageItem {
  return Object.freeze({
    requirement,
    state,
    sourceRefs: freezeStrings(sourceRefs),
    ...(note === undefined ? {} : { note }),
  });
}

function safeMandateVerification(
  kind: "checkout_mandate" | "payment_mandate",
  token: string,
  input: AssembleAp2DisputeEvidenceInput,
  expectedOpenCheckoutHash?: string,
): InteropVerification<VerifiedAp2Mandate> {
  try {
    const plan = kind === "checkout_mandate"
      ? input.verificationPlan.checkoutMandate
      : input.verificationPlan.paymentMandate;
    return verifyAp2MandateChain({
      ...plan,
      token,
      expectedVct: kind === "checkout_mandate" ? "mandate.checkout.1" : "mandate.payment.1",
      expectedCheckoutHash: input.transactionId,
      asOf: input.asOf,
      ...(expectedOpenCheckoutHash === undefined ? {} : { expectedOpenCheckoutHash }),
    });
  } catch {
    return Object.freeze({
      upstreamValid: false,
      evidenceEligible: false,
      value: null,
      issues: Object.freeze([Object.freeze({
        code: "AP2_DISPUTE_VERIFICATION_PLAN_INVALID",
        path: "verificationPlan",
        message: "Caller-owned Mandate verification plan is invalid",
        impact: "upstream_validity" as const,
      })]),
    });
  }
}

function safeReceiptVerification(
  kind: "checkout_receipt" | "payment_receipt",
  token: string,
  expectedMandateToken: string | undefined,
  input: AssembleAp2DisputeEvidenceInput,
): InteropVerification<VerifiedAp2Receipt> {
  try {
    const plan = kind === "checkout_receipt"
      ? input.verificationPlan.checkoutReceipt
      : input.verificationPlan.paymentReceipt;
    return verifyAp2Receipt({
      ...plan,
      token,
      kind,
      asOf: input.asOf,
      ...(expectedMandateToken === undefined ? {} : { expectedMandateToken }),
    });
  } catch {
    return Object.freeze({
      upstreamValid: false,
      evidenceEligible: false,
      value: null,
      issues: Object.freeze([Object.freeze({
        code: "AP2_DISPUTE_VERIFICATION_PLAN_INVALID",
        path: "verificationPlan",
        message: "Caller-owned Receipt verification plan is invalid",
        impact: "upstream_validity" as const,
      })]),
    });
  }
}

function verifyEmbeddedCheckoutJwt(
  checkoutMandate: SelectedInternal | null,
  input: AssembleAp2DisputeEvidenceInput,
  issues: Ap2DisputeIssue[],
): boolean {
  if (checkoutMandate?.verifiedMandate === undefined) return false;
  const token = checkoutMandate.verifiedMandate.claims.checkout_jwt;
  if (typeof token !== "string") return false;
  try {
    const report = verifyAp2CheckoutJwt({
      ...input.verificationPlan.checkoutJwt,
      token,
      asOf: input.asOf,
    });
    for (const issue of report.issues) {
      issues.push(makeIssue(
        issue.code,
        `artifacts.checkout_mandate.checkout_jwt.${issue.path}`,
        issue.message,
        issueImpact(issue),
        checkoutMandate.output.sourceRefs,
      ));
    }
    return report.upstreamValid && report.evidenceEligible && report.value !== null;
  } catch {
    issues.push(makeIssue(
      "AP2_DISPUTE_VERIFICATION_PLAN_INVALID",
      "verificationPlan.checkoutJwt",
      "Caller-owned Checkout JWT verification plan is invalid",
      "invalid",
      checkoutMandate.output.sourceRefs,
    ));
    return false;
  }
}

function uniqueCandidate(
  kind: Ap2DisputeArtifactKind,
  candidates: readonly Candidate[],
  issues: Ap2DisputeIssue[],
): { readonly token: string; readonly digest: Sha256Digest; readonly sourceRefs: readonly string[] } | null {
  const matching = candidates.filter((candidate) => candidate.kind === kind);
  if (matching.length === 0) {
    issues.push(makeIssue(
      "AP2_DISPUTE_ARTIFACT_MISSING",
      `artifacts.${kind}`,
      `Required ${kind} evidence was not provided`,
      "missing",
    ));
    return null;
  }
  const byDigest = new Map<Sha256Digest, Candidate[]>();
  for (const candidate of matching) {
    const group = byDigest.get(candidate.digest) ?? [];
    group.push(candidate);
    byDigest.set(candidate.digest, group);
  }
  if (byDigest.size !== 1) {
    issues.push(makeIssue(
      "AP2_DISPUTE_ARTIFACT_CONFLICT",
      `artifacts.${kind}`,
      `Sources supplied conflicting exact bytes for ${kind}`,
      "conflicting",
      matching.map((candidate) => candidate.sourceId),
    ));
    return null;
  }
  const only = [...byDigest.entries()][0];
  if (only === undefined) throw new TypeError("Unreachable AP2 dispute candidate state");
  const [digest, group] = only;
  const token = group[0]?.token;
  if (token === undefined) throw new TypeError("Unreachable AP2 dispute candidate state");
  return {
    token,
    digest,
    sourceRefs: freezeStrings(group.map((candidate) => candidate.sourceId)),
  };
}

function selectMandate(
  kind: "checkout_mandate" | "payment_mandate",
  candidate: ReturnType<typeof uniqueCandidate>,
  input: AssembleAp2DisputeEvidenceInput,
  issues: Ap2DisputeIssue[],
  expectedOpenCheckoutHash?: string,
): SelectedInternal | null {
  if (candidate === null) return null;
  const report = safeMandateVerification(kind, candidate.token, input, expectedOpenCheckoutHash);
  importVerificationIssues(issues, kind, candidate.sourceRefs, report);
  if (!report.upstreamValid || !report.evidenceEligible || report.value === null) return null;
  return {
    token: candidate.token,
    verifiedMandate: report.value,
    output: Object.freeze({
      kind,
      digest: candidate.digest,
      sourceRefs: candidate.sourceRefs,
      issuer: report.value.issuer,
      issuerKid: report.value.issuerKid,
      mandateVct: kind === "checkout_mandate" ? "mandate.checkout.1" : "mandate.payment.1",
    }),
  };
}

function selectReceipt(
  kind: "checkout_receipt" | "payment_receipt",
  candidate: ReturnType<typeof uniqueCandidate>,
  expectedMandate: SelectedInternal | null,
  input: AssembleAp2DisputeEvidenceInput,
  issues: Ap2DisputeIssue[],
): SelectedInternal | null {
  if (candidate === null) return null;
  const report = safeReceiptVerification(
    kind,
    candidate.token,
    expectedMandate?.token,
    input,
  );
  importVerificationIssues(issues, kind, candidate.sourceRefs, report);
  if (!report.upstreamValid || !report.evidenceEligible || report.value === null) return null;
  return {
    token: candidate.token,
    output: Object.freeze({
      kind,
      digest: candidate.digest,
      sourceRefs: candidate.sourceRefs,
      issuer: report.value.issuer,
      issuerKid: report.value.issuerKid,
      receiptStatus: report.value.status,
      issuedAt: report.value.issuedAt,
    }),
  };
}

function validateAndCollect(
  input: AssembleAp2DisputeEvidenceInput,
  issues: Ap2DisputeIssue[],
): Candidate[] {
  validateTransactionId(input.transactionId);
  const asOf = parseTimestamp(input.asOf, "asOf");
  if (!Array.isArray(input.sources) || input.sources.length > MAX_SOURCES) {
    throw new TypeError("AP2 dispute source count exceeds the limit");
  }
  const sourceIds = new Set<string>();
  const candidates: Candidate[] = [];
  let artifactCount = 0;
  for (let index = 0; index < input.sources.length; index += 1) {
    const source = input.sources[index];
    if (
      source === undefined ||
      typeof source.sourceId !== "string" ||
      !SOURCE_ID_PATTERN.test(source.sourceId) ||
      !AP2_DISPUTE_SOURCE_ROLES.includes(source.role) ||
      sourceIds.has(source.sourceId) ||
      !Array.isArray(source.artifacts)
    ) {
      throw new TypeError(`Invalid AP2 dispute source at index ${String(index)}`);
    }
    sourceIds.add(source.sourceId);
    const retrievedAt = parseTimestamp(source.retrievedAt, `sources[${String(index)}].retrievedAt`);
    const sourceTimeValid = retrievedAt <= asOf + 60_000;
    if (!sourceTimeValid) {
      issues.push(makeIssue(
        "AP2_DISPUTE_RETRIEVAL_TIME_INVALID",
        `sources.${source.sourceId}.retrievedAt`,
        "Evidence source retrieval time is after the evaluation time",
        "invalid",
        [source.sourceId],
      ));
    }
    artifactCount += source.artifacts.length;
    if (artifactCount > MAX_ARTIFACTS) throw new TypeError("AP2 dispute artifact count exceeds the limit");
    for (let artifactIndex = 0; artifactIndex < source.artifacts.length; artifactIndex += 1) {
      const artifact = source.artifacts[artifactIndex];
      if (
        artifact === undefined ||
        !AP2_DISPUTE_ARTIFACT_KINDS.includes(artifact.kind) ||
        typeof artifact.token !== "string" ||
        artifact.token.length === 0 ||
        Buffer.byteLength(artifact.token, "utf8") > MAX_ARTIFACT_TOKEN_BYTES
      ) {
        throw new TypeError("AP2 dispute artifact has an invalid shape");
      }
      const kind = artifact.kind as Ap2DisputeArtifactKind;
      if (!ALLOWED_SOURCE_ROLES[kind].has(source.role)) {
        issues.push(makeIssue(
          "AP2_DISPUTE_SOURCE_ROLE_INVALID",
          `sources.${source.sourceId}.artifacts[${String(artifactIndex)}]`,
          "Source role is not eligible to provide this AP2 dispute artifact kind",
          "invalid",
          [source.sourceId],
        ));
        continue;
      }
      if (!sourceTimeValid) continue;
      candidates.push(Object.freeze({
        kind,
        token: artifact.token,
        digest: sha256Digest(artifact.token),
        sourceId: source.sourceId,
      }));
    }
  }
  return candidates;
}

function materializedAttempts(
  sources: readonly Ap2DisputeEvidenceSource[],
): readonly Ap2DisputeRetrievalAttempt[] {
  return Object.freeze([...sources]
    .sort((left, right) => compareCodeUnits(left.sourceId, right.sourceId))
    .map((source) => Object.freeze({
      sourceId: source.sourceId,
      role: source.role,
      status: source.artifacts.length === 0 ? "empty" as const : "provided" as const,
      artifactKinds: Object.freeze([...new Set(source.artifacts.map((artifact) => artifact.kind))].sort()),
    })));
}

function assemble(
  input: AssembleAp2DisputeEvidenceInput,
  attempts: readonly Ap2DisputeRetrievalAttempt[],
): Ap2DisputeEvidenceResolution {
  const issues: Ap2DisputeIssue[] = [];
  const candidates = validateAndCollect(input, issues);
  for (const attempt of attempts) {
    if (attempt.status !== "provided") {
      issues.push(makeIssue(
        attempt.status === "failed"
          ? "AP2_DISPUTE_RETRIEVAL_FAILED"
          : "AP2_DISPUTE_RETRIEVAL_EMPTY",
        `retrieval.${attempt.sourceId}`,
        attempt.status === "failed"
          ? "Configured evidence retrieval failed without exposing provider details"
          : "Configured evidence source returned no artifacts",
        "retrieval",
        [attempt.sourceId],
      ));
    }
  }

  const checkoutMandateCandidate = uniqueCandidate("checkout_mandate", candidates, issues);
  const paymentMandateCandidate = uniqueCandidate("payment_mandate", candidates, issues);
  const checkoutMandate = selectMandate(
    "checkout_mandate",
    checkoutMandateCandidate,
    input,
    issues,
  );
  let openCheckoutHash: string | undefined;
  if (checkoutMandate !== null) {
    try {
      openCheckoutHash = computeAp2OpenMandateHash(checkoutMandate.token);
    } catch {
      issues.push(makeIssue(
        "AP2_OPEN_CHECKOUT_REFERENCE_INVALID",
        "artifacts.checkout_mandate",
        "Associated open Checkout Mandate reference could not be computed",
        "invalid",
        checkoutMandate.output.sourceRefs,
      ));
    }
  }
  const paymentMandate = selectMandate(
    "payment_mandate",
    paymentMandateCandidate,
    input,
    issues,
    openCheckoutHash,
  );
  const checkoutJwtVerified = verifyEmbeddedCheckoutJwt(checkoutMandate, input, issues);
  const checkoutReceipt = selectReceipt(
    "checkout_receipt",
    uniqueCandidate("checkout_receipt", candidates, issues),
    checkoutMandate,
    input,
    issues,
  );
  const paymentReceipt = selectReceipt(
    "payment_receipt",
    uniqueCandidate("payment_receipt", candidates, issues),
    paymentMandate,
    input,
    issues,
  );

  const selected = [checkoutMandate, checkoutReceipt, paymentMandate, paymentReceipt]
    .filter((entry): entry is SelectedInternal => entry !== null)
    .map((entry) => entry.output)
    .sort((left, right) => compareCodeUnits(left.kind, right.kind));
  const selectedByKind = new Map(selected.map((artifact) => [artifact.kind, artifact]));
  const gates = AP2_DISPUTE_ARTIFACT_KINDS.map((kind) => {
    const artifact = selectedByKind.get(kind);
    return gate(
      `${kind}_verified`,
      artifact === undefined ? "failed" : "passed",
      artifact?.sourceRefs ?? [],
    );
  });
  gates.push(gate(
    "checkout_jwt_signature_verified",
    checkoutJwtVerified ? "passed" : "failed",
    checkoutMandate?.output.sourceRefs ?? [],
  ));
  gates.push(gate(
    "complete_upstream_history",
    "unknown",
    [],
  ));
  const coverageItems = AP2_DISPUTE_ARTIFACT_KINDS.map((kind) => {
    const artifact = selectedByKind.get(kind);
    return coverage(
      kind,
      artifact === undefined ? "missing" : "satisfied",
      artifact?.sourceRefs ?? [],
    );
  });
  coverageItems.push(coverage(
    "checkout_jwt_signature",
    checkoutJwtVerified ? "satisfied" : "missing",
    checkoutMandate?.output.sourceRefs ?? [],
  ));
  coverageItems.push(coverage(
    "complete_upstream_history",
    "unknown",
    [],
    "Bounded retrieval cannot prove that no upstream evidence is missing",
  ));

  const sortedIssues = [...issues].sort((left, right) =>
    compareCodeUnits(left.code, right.code) ||
    compareCodeUnits(left.path, right.path) ||
    compareCodeUnits(left.sourceRefs.join("\u0000"), right.sourceRefs.join("\u0000")));
  const frozenIssues = Object.freeze(sortedIssues.length <= MAX_RESOLUTION_ISSUES
    ? sortedIssues
    : [
        ...sortedIssues.slice(0, MAX_RESOLUTION_ISSUES - 1),
        makeIssue(
          "AP2_DISPUTE_ISSUE_LIMIT_REACHED",
          "issues",
          "Additional bounded diagnostics were omitted after the issue limit",
          "unsupported",
        ),
      ]);
  const status: Ap2DisputeResolutionStatus =
    selected.length === AP2_DISPUTE_ARTIFACT_KINDS.length &&
    checkoutJwtVerified &&
    frozenIssues.length === 0
      ? "evidence_verified"
      : "unresolved";
  const material = Object.freeze({
    schemaId: "MandateBoundAp2DisputeEvidenceResolution/v1" as const,
    releaseVersion: RELEASE_VERSION,
    profile: AP2_DISPUTE_EVIDENCE_PROFILE,
    transactionId: input.transactionId,
    asOf: input.asOf,
    status,
    selectedArtifacts: Object.freeze(selected),
    retrievalAttempts: Object.freeze([...attempts]),
    gates: Object.freeze(gates),
    coverage: Object.freeze(coverageItems),
    issues: frozenIssues,
    historyCompleteness: "unknown" as const,
    legalEffect: LEGAL_EFFECT,
    disputeOutcome: "not-determined" as const,
  });
  return Object.freeze({
    ...material,
    resolutionDigest: sha256Digest(material),
  });
}

/** Assemble and verify caller-supplied AP2 dispute evidence without network access. */
export function assembleAp2DisputeEvidence(
  input: AssembleAp2DisputeEvidenceInput,
): Ap2DisputeEvidenceResolution {
  return assemble(input, materializedAttempts(input.sources));
}

/**
 * Invoke caller-supplied retrieval adapters, then run the same deterministic
 * offline assembler. Retrieval errors are bounded and fail closed.
 */
export async function resolveAp2DisputeEvidence(
  input: ResolveAp2DisputeEvidenceInput,
): Promise<Ap2DisputeEvidenceResolution> {
  validateTransactionId(input.transactionId);
  parseTimestamp(input.asOf, "asOf");
  if (!Array.isArray(input.retrievers) || input.retrievers.length > MAX_SOURCES) {
    throw new TypeError("AP2 dispute retriever count exceeds the limit");
  }
  const ids = new Set<string>();
  const sorted = [...input.retrievers].sort((left, right) => compareCodeUnits(left.id, right.id));
  for (const retriever of sorted) {
    if (
      !SOURCE_ID_PATTERN.test(retriever.id) ||
      ids.has(retriever.id) ||
      !AP2_DISPUTE_SOURCE_ROLES.includes(retriever.role) ||
      typeof retriever.retrieve !== "function"
    ) {
      throw new TypeError("AP2 dispute retriever is invalid or duplicated");
    }
    ids.add(retriever.id);
  }

  const results = await Promise.all(sorted.map(async (retriever): Promise<{
    readonly source: Ap2DisputeEvidenceSource | null;
    readonly attempt: Ap2DisputeRetrievalAttempt;
  }> => {
    try {
      const response = await retriever.retrieve({
        profileId: AP2_DISPUTE_EVIDENCE_PROFILE.id,
        transactionId: input.transactionId,
        asOf: input.asOf,
        ...(input.signal === undefined ? {} : { signal: input.signal }),
      });
      if (response === null) {
        return {
          source: null,
          attempt: Object.freeze({
            sourceId: retriever.id,
            role: retriever.role,
            status: "empty",
            artifactKinds: Object.freeze([]),
          }),
        };
      }
      if (
        typeof response.retrievedAt !== "string" ||
        !Array.isArray(response.artifacts) ||
        response.artifacts.length > MAX_ARTIFACTS
      ) {
        throw new TypeError("AP2 dispute retriever returned an invalid response");
      }
      parseTimestamp(response.retrievedAt, `retrieval.${retriever.id}.retrievedAt`);
      for (const artifact of response.artifacts) {
        if (
          artifact === undefined ||
          !AP2_DISPUTE_ARTIFACT_KINDS.includes(artifact.kind) ||
          typeof artifact.token !== "string" ||
          artifact.token.length === 0 ||
          Buffer.byteLength(artifact.token, "utf8") > MAX_ARTIFACT_TOKEN_BYTES
        ) {
          throw new TypeError("AP2 dispute retriever returned an invalid artifact");
        }
      }
      if (response.artifacts.length === 0) {
        return {
          source: {
            sourceId: retriever.id,
            role: retriever.role,
            retrievedAt: response.retrievedAt,
            artifacts: response.artifacts,
          },
          attempt: Object.freeze({
            sourceId: retriever.id,
            role: retriever.role,
            status: "empty",
            artifactKinds: Object.freeze([]),
          }),
        };
      }
      const artifactKinds: readonly Ap2DisputeArtifactKind[] = Object.freeze(
        [...new Set<Ap2DisputeArtifactKind>(
          response.artifacts.map((artifact: Ap2DisputeArtifactInput) => artifact.kind),
        )].sort(compareCodeUnits),
      );
      return {
        source: {
          sourceId: retriever.id,
          role: retriever.role,
          retrievedAt: response.retrievedAt,
          artifacts: response.artifacts,
        },
        attempt: Object.freeze({
          sourceId: retriever.id,
          role: retriever.role,
          status: "provided",
          artifactKinds,
        }),
      };
    } catch {
      return {
        source: null,
        attempt: Object.freeze({
          sourceId: retriever.id,
          role: retriever.role,
          status: "failed",
          artifactKinds: Object.freeze([]),
        }),
      };
    }
  }));
  return assemble({
    transactionId: input.transactionId,
    asOf: input.asOf,
    verificationPlan: input.verificationPlan,
    sources: results
      .map((entry) => entry.source)
      .filter((source): source is Ap2DisputeEvidenceSource => source !== null),
  }, Object.freeze(results.map((entry) => entry.attempt)));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort(compareCodeUnits);
  const expected = [...keys].sort(compareCodeUnits);
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function hasAllowedKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key));
}

const JOSE_EC_ALGORITHMS = Object.freeze(["ES256", "ES384", "ES512"] as const);

function isJoseAlgorithmArray(value: unknown): boolean {
  return Array.isArray(value) &&
    value.length > 0 &&
    value.length <= JOSE_EC_ALGORITHMS.length &&
    value.every((entry) => JOSE_EC_ALGORITHMS.includes(entry)) &&
    new Set(value).size === value.length;
}

const EC_JWK_PROFILES = Object.freeze({
  "P-256": Object.freeze({ algorithm: "ES256", coordinateLength: 43 }),
  "P-384": Object.freeze({ algorithm: "ES384", coordinateLength: 64 }),
  "P-521": Object.freeze({ algorithm: "ES512", coordinateLength: 88 }),
} as const);

function isPublicEcJwkShape(value: unknown, expectedKid?: string): boolean {
  if (
    !isRecord(value) ||
    !hasAllowedKeys(value, ["kty", "crv", "x", "y"], ["kid", "alg", "use", "key_ops"]) ||
    value.kty !== "EC" ||
    typeof value.crv !== "string" ||
    !Object.hasOwn(EC_JWK_PROFILES, value.crv)
  ) {
    return false;
  }
  const profile = EC_JWK_PROFILES[value.crv as keyof typeof EC_JWK_PROFILES];
  if (
    typeof value.x !== "string" ||
    value.x.length !== profile.coordinateLength ||
    !/^[A-Za-z0-9_-]+$/u.test(value.x) ||
    typeof value.y !== "string" ||
    value.y.length !== profile.coordinateLength ||
    !/^[A-Za-z0-9_-]+$/u.test(value.y) ||
    (value.kid !== undefined && (
      typeof value.kid !== "string" ||
      value.kid.length === 0 ||
      (expectedKid !== undefined && value.kid !== expectedKid)
    )) ||
    (value.alg !== undefined && value.alg !== profile.algorithm) ||
    (value.use !== undefined && value.use !== "sig") ||
    (value.key_ops !== undefined && (
      !Array.isArray(value.key_ops) ||
      value.key_ops.length !== 1 ||
      value.key_ops[0] !== "verify"
    ))
  ) {
    return false;
  }
  return true;
}

function isExpectedMerchantShape(value: unknown): boolean {
  return isRecord(value) &&
    hasAllowedKeys(value, ["id"], ["website"]) &&
    typeof value.id === "string" &&
    value.id.length > 0 &&
    (value.website === undefined || typeof value.website === "string");
}

function isKeySnapshotShape(value: unknown): boolean {
  if (
    !isRecord(value) ||
    !hasAllowedKeys(
      value,
      ["kid", "jwk", "sourceDigest", "capturedAt", "validUntil"],
      ["validFrom", "invalidFrom"],
    ) ||
    typeof value.kid !== "string" ||
    value.kid.length === 0 ||
    !isPublicEcJwkShape(value.jwk, value.kid) ||
    typeof value.sourceDigest !== "string" ||
    !isSha256Digest(value.sourceDigest) ||
    typeof value.capturedAt !== "string" ||
    typeof value.validUntil !== "string" ||
    (value.validFrom !== undefined && typeof value.validFrom !== "string") ||
    (value.invalidFrom !== undefined && typeof value.invalidFrom !== "string")
  ) {
    return false;
  }
  try {
    parseTimestamp(value.capturedAt, "keySnapshot.capturedAt");
    parseTimestamp(value.validUntil, "keySnapshot.validUntil");
    if (value.validFrom !== undefined) parseTimestamp(value.validFrom, "keySnapshot.validFrom");
    if (value.invalidFrom !== undefined) parseTimestamp(value.invalidFrom, "keySnapshot.invalidFrom");
  } catch {
    return false;
  }
  return true;
}

function assertVerificationPlanShape(value: unknown): asserts value is Ap2DisputeVerificationPlan {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "checkoutMandate",
      "checkoutJwt",
      "checkoutReceipt",
      "paymentMandate",
      "paymentReceipt",
    ])
  ) {
    throw new TypeError("AP2 dispute verification plan shape is invalid");
  }
  const mandateRequired = [
    "issuerKeySnapshot",
    "expectedIssuerKeySourceDigest",
    "expectedIssuer",
    "expectedAudience",
    "expectedNonce",
  ];
  const mandateOptional = [
    "allowedAlgorithms",
    "requireKeyBinding",
    "expectedAgentJwk",
    "expectedCheckoutJwt",
    "expectedOpenCheckoutHash",
    "expectedMerchant",
  ];
  for (const name of ["checkoutMandate", "paymentMandate"] as const) {
    const plan = value[name];
    if (
      !isRecord(plan) ||
      !hasAllowedKeys(plan, mandateRequired, mandateOptional) ||
      !isKeySnapshotShape(plan.issuerKeySnapshot) ||
      typeof plan.expectedIssuerKeySourceDigest !== "string" ||
      !isSha256Digest(plan.expectedIssuerKeySourceDigest) ||
      typeof plan.expectedIssuer !== "string" ||
      plan.expectedIssuer.length === 0 ||
      typeof plan.expectedAudience !== "string" ||
      typeof plan.expectedNonce !== "string" ||
      (plan.allowedAlgorithms !== undefined && !isJoseAlgorithmArray(plan.allowedAlgorithms)) ||
      (plan.requireKeyBinding !== undefined && typeof plan.requireKeyBinding !== "boolean") ||
      (plan.expectedAgentJwk !== undefined && !isPublicEcJwkShape(plan.expectedAgentJwk)) ||
      (plan.expectedCheckoutJwt !== undefined && typeof plan.expectedCheckoutJwt !== "string") ||
      (
        plan.expectedOpenCheckoutHash !== undefined &&
        typeof plan.expectedOpenCheckoutHash !== "string"
      ) ||
      (plan.expectedMerchant !== undefined && !isExpectedMerchantShape(plan.expectedMerchant))
    ) {
      throw new TypeError(`AP2 dispute ${name} verification plan shape is invalid`);
    }
  }
  for (const name of ["checkoutReceipt", "paymentReceipt"] as const) {
    const plan = value[name];
    if (
      !isRecord(plan) ||
      !hasAllowedKeys(
        plan,
        ["issuerKeySnapshot", "expectedIssuerKeySourceDigest", "expectedIssuer"],
        ["allowedAlgorithms"],
      ) ||
      !isKeySnapshotShape(plan.issuerKeySnapshot) ||
      typeof plan.expectedIssuerKeySourceDigest !== "string" ||
      !isSha256Digest(plan.expectedIssuerKeySourceDigest) ||
      typeof plan.expectedIssuer !== "string" ||
      plan.expectedIssuer.length === 0 ||
      (plan.allowedAlgorithms !== undefined && !isJoseAlgorithmArray(plan.allowedAlgorithms))
    ) {
      throw new TypeError(`AP2 dispute ${name} verification plan shape is invalid`);
    }
  }
  const checkoutPlan = value.checkoutJwt;
  if (
    !isRecord(checkoutPlan) ||
    !hasAllowedKeys(
      checkoutPlan,
      ["merchantKeySnapshot", "expectedMerchantKeySourceDigest"],
      ["allowedAlgorithms", "expectedIssuer"],
    ) ||
    !isKeySnapshotShape(checkoutPlan.merchantKeySnapshot) ||
    typeof checkoutPlan.expectedMerchantKeySourceDigest !== "string" ||
    !isSha256Digest(checkoutPlan.expectedMerchantKeySourceDigest) ||
    (checkoutPlan.allowedAlgorithms !== undefined && !isJoseAlgorithmArray(checkoutPlan.allowedAlgorithms)) ||
    (checkoutPlan.expectedIssuer !== undefined && typeof checkoutPlan.expectedIssuer !== "string")
  ) {
    throw new TypeError("AP2 dispute Checkout JWT verification plan shape is invalid");
  }
}

function cloneBoundedJson<T>(value: T, path: string): T {
  let serialized: string;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new TypeError(`Invalid JSON-compatible value at ${path}`);
  }
  if (
    typeof serialized !== "string" ||
    Buffer.byteLength(serialized, "utf8") > MAX_PACK_CANONICAL_BYTES
  ) {
    throw new TypeError(`JSON-compatible value at ${path} exceeds the byte limit`);
  }
  return JSON.parse(serialized) as T;
}

function decodeCanonicalBase64(value: string, path: string): Uint8Array {
  if (
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !BASE64_PATTERN.test(value)
  ) {
    throw new TypeError(`Invalid canonical base64 at ${path}`);
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) {
    throw new TypeError(`Invalid canonical base64 at ${path}`);
  }
  return bytes;
}

function packMaterial(pack: Omit<Ap2DisputeEvidencePack, "packDigest">): Omit<Ap2DisputeEvidencePack, "packDigest"> {
  return Object.freeze({
    schemaId: pack.schemaId,
    releaseVersion: pack.releaseVersion,
    profile: pack.profile,
    transactionId: pack.transactionId,
    asOf: pack.asOf,
    createdAt: pack.createdAt,
    verificationPlan: pack.verificationPlan,
    sources: pack.sources,
    checkoutVersions: pack.checkoutVersions,
    revocations: pack.revocations,
    legalEffect: pack.legalEffect,
  });
}

function sourceIdSet(sources: readonly Ap2DisputeEvidenceSource[]): ReadonlySet<string> {
  return new Set(sources.map((source) => source.sourceId));
}

function materializeCheckoutVersions(
  values: readonly Ap2CheckoutVersionInput[],
  sources: ReadonlySet<string>,
  asOf: number,
  allowStoredDigest = false,
): readonly Ap2CheckoutVersionEvidence[] {
  if (!Array.isArray(values) || values.length === 0 || values.length > MAX_CHECKOUT_VERSIONS) {
    throw new TypeError("AP2 Evidence Pack requires a bounded Checkout version history");
  }
  const ids = new Set<string>();
  const materialized = values.map((value, index) => {
    if (
      !isRecord(value) ||
      !hasExactKeys(value, [
        "versionId",
        "sourceId",
        "observedAt",
        "checkoutJwt",
        ...(allowStoredDigest ? ["checkoutJwtDigest"] : []),
      ]) ||
      typeof value.versionId !== "string" ||
      !SOURCE_ID_PATTERN.test(value.versionId) ||
      ids.has(value.versionId) ||
      typeof value.sourceId !== "string" ||
      !sources.has(value.sourceId) ||
      typeof value.observedAt !== "string" ||
      parseTimestamp(value.observedAt, `checkoutVersions[${String(index)}].observedAt`) > asOf + 60_000 ||
      typeof value.checkoutJwt !== "string" ||
      value.checkoutJwt.length === 0 ||
      Buffer.byteLength(value.checkoutJwt, "utf8") > MAX_ARTIFACT_TOKEN_BYTES
    ) {
      throw new TypeError(`Invalid Checkout version evidence at index ${String(index)}`);
    }
    ids.add(value.versionId);
    return Object.freeze({
      versionId: value.versionId,
      sourceId: value.sourceId,
      observedAt: value.observedAt,
      checkoutJwt: value.checkoutJwt,
      checkoutJwtDigest: sha256Digest(value.checkoutJwt),
    });
  });
  return Object.freeze(materialized.sort((left, right) =>
    parseTimestamp(left.observedAt, "checkoutVersions.observedAt") -
      parseTimestamp(right.observedAt, "checkoutVersions.observedAt") ||
    compareCodeUnits(left.versionId, right.versionId)));
}

function materializeRevocations(
  values: readonly Ap2RevocationEvidenceInput[],
  sources: ReadonlySet<string>,
  asOf: number,
  allowStoredDigest = false,
): readonly Ap2RevocationEvidence[] {
  if (!Array.isArray(values) || values.length === 0 || values.length > MAX_REVOCATION_RECORDS) {
    throw new TypeError("AP2 Evidence Pack requires bounded reported revocation evidence");
  }
  const ids = new Set<string>();
  const materialized = values.map((value, index) => {
    if (
      !isRecord(value) ||
      !hasExactKeys(value, [
        "recordId",
        "mandateKind",
        "sourceId",
        "checkedAt",
        "reportedStatus",
        "snapshotBase64",
        ...(allowStoredDigest ? ["snapshotDigest"] : []),
      ]) ||
      typeof value.recordId !== "string" ||
      !SOURCE_ID_PATTERN.test(value.recordId) ||
      ids.has(value.recordId) ||
      (value.mandateKind !== "checkout_mandate" && value.mandateKind !== "payment_mandate") ||
      typeof value.sourceId !== "string" ||
      !sources.has(value.sourceId) ||
      typeof value.checkedAt !== "string" ||
      parseTimestamp(value.checkedAt, `revocations[${String(index)}].checkedAt`) > asOf + 60_000 ||
      (
        value.reportedStatus !== "not_revoked" &&
        value.reportedStatus !== "revoked" &&
        value.reportedStatus !== "unknown"
      ) ||
      typeof value.snapshotBase64 !== "string"
    ) {
      throw new TypeError(`Invalid reported revocation evidence at index ${String(index)}`);
    }
    const bytes = decodeCanonicalBase64(
      value.snapshotBase64,
      `revocations[${String(index)}].snapshotBase64`,
    );
    if (bytes.byteLength > MAX_REVOCATION_SNAPSHOT_BYTES) {
      throw new TypeError(`Reported revocation snapshot exceeds the byte limit at index ${String(index)}`);
    }
    ids.add(value.recordId);
    return Object.freeze({
      recordId: value.recordId,
      mandateKind: value.mandateKind,
      sourceId: value.sourceId,
      checkedAt: value.checkedAt,
      reportedStatus: value.reportedStatus,
      snapshotBase64: value.snapshotBase64,
      snapshotDigest: sha256Digest(bytes),
    });
  });
  return Object.freeze(materialized.sort((left, right) =>
    parseTimestamp(left.checkedAt, "revocations.checkedAt") -
      parseTimestamp(right.checkedAt, "revocations.checkedAt") ||
    compareCodeUnits(left.recordId, right.recordId)));
}

/** Seal exact AP2 evidence bytes and caller-owned verification pins into a sensitive pack. */
export function packAp2DisputeEvidence(
  input: PackAp2DisputeEvidenceInput,
): Ap2DisputeEvidencePack {
  validateTransactionId(input.transactionId);
  const asOf = parseTimestamp(input.asOf, "asOf");
  const createdAt = parseTimestamp(input.createdAt, "createdAt");
  if (createdAt > asOf + 60_000) {
    throw new TypeError("AP2 Evidence Pack creation time is after its evaluation time");
  }

  assertVerificationPlanShape(input.verificationPlan);
  const clonedPlan = cloneBoundedJson(input.verificationPlan, "verificationPlan");
  const clonedSources = cloneBoundedJson(input.sources, "sources");
  // The assembler validates source shape, artifact bounds, and the verification plan
  // without requiring the dispute itself to resolve successfully.
  assembleAp2DisputeEvidence({
    transactionId: input.transactionId,
    asOf: input.asOf,
    verificationPlan: clonedPlan,
    sources: clonedSources,
  });
  const sources = Object.freeze(clonedSources.map((source) => Object.freeze({
    sourceId: source.sourceId,
    role: source.role,
    retrievedAt: source.retrievedAt,
    artifacts: Object.freeze(source.artifacts.map((artifact) => Object.freeze({
      kind: artifact.kind,
      token: artifact.token,
    }))),
  })).sort((left, right) => compareCodeUnits(left.sourceId, right.sourceId)));
  const ids = sourceIdSet(sources);
  const checkoutVersions = materializeCheckoutVersions(input.checkoutVersions, ids, asOf);
  const revocations = materializeRevocations(input.revocations, ids, asOf);
  const material = packMaterial(Object.freeze({
    schemaId: "MandateBoundAp2EvidencePack/v1" as const,
    releaseVersion: RELEASE_VERSION,
    profile: AP2_DISPUTE_EVIDENCE_PROFILE,
    transactionId: input.transactionId,
    asOf: input.asOf,
    createdAt: input.createdAt,
    verificationPlan: clonedPlan,
    sources,
    checkoutVersions,
    revocations,
    legalEffect: LEGAL_EFFECT,
  }));
  cloneBoundedJson(material, "pack");
  return Object.freeze({
    ...material,
    packDigest: sha256Digest(material),
  });
}

function assertPackShape(value: unknown): asserts value is Ap2DisputeEvidencePack {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "schemaId",
      "releaseVersion",
      "profile",
      "transactionId",
      "asOf",
      "createdAt",
      "verificationPlan",
      "sources",
      "checkoutVersions",
      "revocations",
      "legalEffect",
      "packDigest",
    ]) ||
    value.schemaId !== "MandateBoundAp2EvidencePack/v1" ||
    value.releaseVersion !== RELEASE_VERSION ||
    !isRecord(value.profile) ||
    typeof value.transactionId !== "string" ||
    typeof value.asOf !== "string" ||
    typeof value.createdAt !== "string" ||
    !isRecord(value.verificationPlan) ||
    !Array.isArray(value.sources) ||
    !Array.isArray(value.checkoutVersions) ||
    !Array.isArray(value.revocations) ||
    value.legalEffect !== LEGAL_EFFECT ||
    typeof value.packDigest !== "string" ||
    !isSha256Digest(value.packDigest)
  ) {
    throw new TypeError("AP2 Evidence Pack shape is invalid");
  }
  cloneBoundedJson(value, "pack");
  if (sha256Digest(value.profile) !== sha256Digest(AP2_DISPUTE_EVIDENCE_PROFILE)) {
    throw new TypeError("AP2 Evidence Pack profile is invalid");
  }
  assertVerificationPlanShape(value.verificationPlan);
  validateTransactionId(value.transactionId);
  const asOf = parseTimestamp(value.asOf, "pack.asOf");
  if (parseTimestamp(value.createdAt, "pack.createdAt") > asOf + 60_000) {
    throw new TypeError("AP2 Evidence Pack creation time is after its evaluation time");
  }
}

function sortedBoundedPackIssues(issues: readonly Ap2DisputeIssue[]): readonly Ap2DisputeIssue[] {
  const sorted = [...issues].sort((left, right) =>
    compareCodeUnits(left.code, right.code) ||
    compareCodeUnits(left.path, right.path) ||
    compareCodeUnits(left.sourceRefs.join("\u0000"), right.sourceRefs.join("\u0000")));
  if (sorted.length <= MAX_RESOLUTION_ISSUES) return Object.freeze(sorted);
  return Object.freeze([
    ...sorted.slice(0, MAX_RESOLUTION_ISSUES - 1),
    makeIssue(
      "AP2_PACK_ISSUE_LIMIT_REACHED",
      "issues",
      "Additional bounded diagnostics were omitted after the issue limit",
      "unsupported",
    ),
  ]);
}

function readExpectedPackDigest(
  options: unknown,
): Sha256Digest | null {
  if (
    !isRecord(options) ||
    !hasExactKeys(options, ["expectedPackDigest"]) ||
    !isSha256Digest(options.expectedPackDigest)
  ) {
    return null;
  }
  return options.expectedPackDigest;
}

function invalidPackReport(
  issues: readonly Ap2DisputeIssue[],
  expectedPackDigest: Sha256Digest | null,
): Ap2DisputeEvidencePackVerification {
  const material = Object.freeze({
    schemaId: "MandateBoundAp2EvidencePackVerification/v1" as const,
    releaseVersion: RELEASE_VERSION,
    status: "unresolved" as const,
    packDigest: null,
    expectedPackDigest,
    anchorMatched: false,
    digestValid: false,
    checkoutVersionBinding: "missing" as const,
    revocationCoverage: "missing" as const,
    reportedRevocationState: "unknown" as const,
    resolution: null,
    issues: sortedBoundedPackIssues(issues),
    legalEffect: LEGAL_EFFECT,
  });
  return Object.freeze({ ...material, reportDigest: sha256Digest(material) });
}

/** Independently recompute pack, artifact, Checkout-version, and snapshot evidence. */
export function verifyAp2DisputeEvidencePack(
  value: unknown,
  options: VerifyAp2DisputeEvidencePackOptions,
): Ap2DisputeEvidencePackVerification {
  const expectedPackDigest = readExpectedPackDigest(options);
  const anchorIssues = expectedPackDigest === null
    ? [makeIssue(
        "AP2_PACK_TRUST_ANCHOR_MISSING",
        "expectedPackDigest",
        "An independently retained expected Pack digest is required",
        "missing",
      )]
    : [];
  try {
    assertPackShape(value);
  } catch {
    return invalidPackReport([
      ...anchorIssues,
      makeIssue(
        "AP2_PACK_SHAPE_INVALID",
        "pack",
        "AP2 Evidence Pack failed bounded structural validation",
        "invalid",
      ),
    ], expectedPackDigest);
  }
  const pack = value;
  const issues: Ap2DisputeIssue[] = [...anchorIssues];
  const material = packMaterial(pack);
  const recomputedPackDigest = sha256Digest(material);
  const digestValid = recomputedPackDigest === pack.packDigest;
  if (!digestValid) {
    issues.push(makeIssue(
      "AP2_PACK_DIGEST_MISMATCH",
      "packDigest",
      "Pack digest does not match the exact canonical pack material",
      "invalid",
    ));
  }
  const anchorMatched = expectedPackDigest !== null && expectedPackDigest === pack.packDigest;
  if (expectedPackDigest !== null && !anchorMatched) {
    issues.push(makeIssue(
      "AP2_PACK_TRUST_ANCHOR_MISMATCH",
      "expectedPackDigest",
      "Pack digest does not match the independently retained expected digest",
      "invalid",
    ));
  }

  let resolution: Ap2DisputeEvidenceResolution | null = null;
  let verifiedVersions: readonly Ap2CheckoutVersionEvidence[] = Object.freeze([]);
  let verifiedRevocations: readonly Ap2RevocationEvidence[] = Object.freeze([]);
  try {
    resolution = assembleAp2DisputeEvidence({
      transactionId: pack.transactionId,
      asOf: pack.asOf,
      verificationPlan: pack.verificationPlan,
      sources: pack.sources,
    });
    const ids = sourceIdSet(pack.sources);
    verifiedVersions = materializeCheckoutVersions(
      pack.checkoutVersions,
      ids,
      parseTimestamp(pack.asOf, "pack.asOf"),
      true,
    );
    verifiedRevocations = materializeRevocations(
      pack.revocations,
      ids,
      parseTimestamp(pack.asOf, "pack.asOf"),
      true,
    );
  } catch {
    issues.push(makeIssue(
      "AP2_PACK_CONTENT_INVALID",
      "pack",
      "Pack contents failed bounded independent verification",
      "invalid",
    ));
  }

  if (verifiedVersions.length === pack.checkoutVersions.length) {
    const storedById = new Map(pack.checkoutVersions.map((entry, index) => [
      entry.versionId,
      { entry, index },
    ]));
    for (const verified of verifiedVersions) {
      const stored = storedById.get(verified.versionId);
      if (stored === undefined || verified.checkoutJwtDigest !== stored.entry.checkoutJwtDigest) {
        issues.push(makeIssue(
          "AP2_CHECKOUT_VERSION_DIGEST_MISMATCH",
          stored === undefined
            ? "checkoutVersions"
            : `checkoutVersions[${String(stored.index)}].checkoutJwtDigest`,
          "Checkout-version digest does not match its exact Checkout JWT bytes",
          "invalid",
          stored === undefined ? [] : [stored.entry.sourceId],
        ));
      }
    }
  }
  if (verifiedRevocations.length === pack.revocations.length) {
    const storedById = new Map(pack.revocations.map((entry, index) => [
      entry.recordId,
      { entry, index },
    ]));
    for (const verified of verifiedRevocations) {
      const stored = storedById.get(verified.recordId);
      if (stored === undefined || verified.snapshotDigest !== stored.entry.snapshotDigest) {
        issues.push(makeIssue(
          "AP2_REVOCATION_SNAPSHOT_DIGEST_MISMATCH",
          stored === undefined
            ? "revocations"
            : `revocations[${String(stored.index)}].snapshotDigest`,
          "Reported revocation snapshot digest does not match its exact bytes",
          "invalid",
          stored === undefined ? [] : [stored.entry.sourceId],
        ));
      }
    }
  }

  const expectedCheckoutJwt = pack.verificationPlan.checkoutMandate.expectedCheckoutJwt;
  const checkoutVersionBinding: Ap2CheckoutVersionBinding =
    typeof expectedCheckoutJwt !== "string" || expectedCheckoutJwt.length === 0
      ? "missing"
      : verifiedVersions.some((entry) => entry.checkoutJwt === expectedCheckoutJwt)
        ? "matched"
        : verifiedVersions.length === 0 ? "missing" : "conflicting";
  if (checkoutVersionBinding !== "matched") {
    issues.push(makeIssue(
      checkoutVersionBinding === "missing"
        ? "AP2_CHECKOUT_VERSION_MISSING"
        : "AP2_CHECKOUT_VERSION_CONFLICT",
      "checkoutVersions",
      checkoutVersionBinding === "missing"
        ? "No exact Checkout version is pinned by the verification plan"
        : "Checkout version history does not contain the exact Checkout JWT pinned by the Mandate",
      checkoutVersionBinding === "missing" ? "missing" : "conflicting",
    ));
  }

  const revocationKinds = new Set(verifiedRevocations.map((entry) => entry.mandateKind));
  const revocationCoverage: Ap2RevocationCoverage =
    revocationKinds.has("checkout_mandate") && revocationKinds.has("payment_mandate")
      ? "provided"
      : "missing";
  const hasRevoked = verifiedRevocations.some((entry) => entry.reportedStatus === "revoked");
  const hasUnknown = verifiedRevocations.some((entry) => entry.reportedStatus === "unknown");
  const revocationRecordsValid = verifiedRevocations.length === pack.revocations.length;
  const revocationDigestsValid = !issues.some((entry) =>
    entry.code === "AP2_REVOCATION_SNAPSHOT_DIGEST_MISMATCH");
  const reportedRevocationState: Ap2ReportedRevocationState = hasRevoked
    ? "revoked"
    : hasUnknown ||
        revocationCoverage === "missing" ||
        !revocationRecordsValid ||
        !revocationDigestsValid
      ? "unknown"
      : "not_revoked";
  if (revocationCoverage === "missing") {
    issues.push(makeIssue(
      "AP2_REVOCATION_COVERAGE_MISSING",
      "revocations",
      "Reported revocation evidence does not cover both closed Mandates",
      "missing",
    ));
  }
  if (reportedRevocationState !== "not_revoked") {
    issues.push(makeIssue(
      reportedRevocationState === "revoked"
        ? "AP2_REPORTED_REVOCATION_REVOKED"
        : "AP2_REPORTED_REVOCATION_UNKNOWN",
      "revocations",
      reportedRevocationState === "revoked"
        ? "Imported evidence reports at least one Mandate as revoked"
        : "Imported revocation state is incomplete, conflicting, or unknown",
      reportedRevocationState === "revoked" ? "invalid" : "eligibility",
    ));
  }
  if (resolution?.status !== "evidence_verified") {
    issues.push(makeIssue(
      "AP2_PACK_RESOLUTION_UNRESOLVED",
      "resolution",
      "Embedded evidence did not pass every deterministic AP2 resolution gate",
      "eligibility",
    ));
  }

  const frozenIssues = sortedBoundedPackIssues(issues);
  const status =
    digestValid &&
    anchorMatched &&
    resolution?.status === "evidence_verified" &&
    checkoutVersionBinding === "matched" &&
    revocationCoverage === "provided" &&
    reportedRevocationState === "not_revoked" &&
    frozenIssues.length === 0
      ? "verified" as const
      : "unresolved" as const;
  const reportMaterial = Object.freeze({
    schemaId: "MandateBoundAp2EvidencePackVerification/v1" as const,
    releaseVersion: RELEASE_VERSION,
    status,
    packDigest: pack.packDigest,
    expectedPackDigest,
    anchorMatched,
    digestValid,
    checkoutVersionBinding,
    revocationCoverage,
    reportedRevocationState,
    resolution,
    issues: frozenIssues,
    legalEffect: LEGAL_EFFECT,
  });
  return Object.freeze({ ...reportMaterial, reportDigest: sha256Digest(reportMaterial) });
}

function buildAp2EvidenceTimeline(
  pack: Ap2DisputeEvidencePack,
  verification: Ap2DisputeEvidencePackVerification,
): readonly Ap2EvidenceTimelineEvent[] {
  assertPackShape(pack);
  const events: Ap2EvidenceTimelineEvent[] = [];
  for (const version of pack.checkoutVersions) {
    events.push(Object.freeze({
      occurredAt: version.observedAt,
      eventType: "checkout_version" as const,
      label: `Checkout version ${version.versionId}`,
      state: "observed",
      digest: version.checkoutJwtDigest,
      sourceRefs: Object.freeze([version.sourceId]),
    }));
  }
  for (const source of pack.sources) {
    const sourceDigest = sha256Digest({
      sourceId: source.sourceId,
      role: source.role,
      retrievedAt: source.retrievedAt,
      artifacts: source.artifacts.map((artifact) => ({
        kind: artifact.kind,
        digest: sha256Digest(artifact.token),
      })),
    });
    events.push(Object.freeze({
      occurredAt: source.retrievedAt,
      eventType: "artifact_retrieval" as const,
      label: `Evidence retrieval ${source.sourceId}`,
      state: source.artifacts.length === 0 ? "empty" : "provided",
      digest: sourceDigest,
      sourceRefs: Object.freeze([source.sourceId]),
    }));
  }
  for (const revocation of pack.revocations) {
    events.push(Object.freeze({
      occurredAt: revocation.checkedAt,
      eventType: "revocation_check" as const,
      label: `Reported revocation check ${revocation.recordId}`,
      state: revocation.reportedStatus,
      digest: revocation.snapshotDigest,
      sourceRefs: Object.freeze([revocation.sourceId]),
    }));
  }
  events.push(Object.freeze({
    occurredAt: pack.asOf,
    eventType: "resolution" as const,
    label: "Deterministic non-binding resolution",
    state: verification.status,
    ...(verification.resolution === null
      ? {}
      : { digest: verification.resolution.resolutionDigest }),
    sourceRefs: Object.freeze([]),
  }));
  return Object.freeze(events.sort((left, right) =>
    parseTimestamp(left.occurredAt, "timeline.occurredAt") -
      parseTimestamp(right.occurredAt, "timeline.occurredAt") ||
    compareCodeUnits(left.eventType, right.eventType) ||
    compareCodeUnits(left.label, right.label) ||
    compareCodeUnits(left.sourceRefs.join("\u0000"), right.sourceRefs.join("\u0000"))));
}

/** Build a deterministic metadata-only timeline after anchored Pack verification. */
export function createAp2EvidenceTimeline(
  pack: Ap2DisputeEvidencePack,
  options: VerifyAp2DisputeEvidencePackOptions,
): readonly Ap2EvidenceTimelineEvent[] {
  assertPackShape(pack);
  return buildAp2EvidenceTimeline(pack, verifyAp2DisputeEvidencePack(pack, options));
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** Render a self-contained, metadata-only AP2 evidence timeline. */
export function renderAp2EvidenceTimelineHtml(
  pack: Ap2DisputeEvidencePack,
  options: VerifyAp2DisputeEvidencePackOptions,
): string {
  assertPackShape(pack);
  const verification = verifyAp2DisputeEvidencePack(pack, options);
  const timeline = buildAp2EvidenceTimeline(pack, verification);
  const rows = timeline.map((event) => `<tr><td>${escapeHtml(event.occurredAt)}</td><td>${escapeHtml(event.eventType)}</td><td>${escapeHtml(event.label)}</td><td>${escapeHtml(event.state)}</td><td><code>${escapeHtml(event.digest ?? "-")}</code></td><td>${escapeHtml(event.sourceRefs.join(", ") || "-")}</td></tr>`).join("");
  const issueRows = verification.issues.length === 0
    ? "<li>None</li>"
    : verification.issues.map((issue) => `<li><code>${escapeHtml(issue.code)}</code>: ${escapeHtml(issue.message)}</li>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>MandateBound AP2 Evidence Timeline</title><style>body{font:15px/1.45 system-ui,sans-serif;margin:2rem;color:#17202a;background:#fff}h1{margin-bottom:.25rem}.meta{color:#52606d;margin-bottom:1.5rem}.notice{padding:.8rem 1rem;background:#fff7d6;border-left:4px solid #d6a800}table{border-collapse:collapse;width:100%;margin-top:1rem}th,td{border:1px solid #d9e2ec;padding:.55rem;text-align:left;vertical-align:top}th{background:#f5f7fa}code{overflow-wrap:anywhere}.verified{color:#176b35}.unresolved{color:#9b1c1c}@media print{body{margin:.5in}}</style></head><body><h1>AP2 Evidence Timeline</h1><p class="meta">MandateBound ${escapeHtml(pack.releaseVersion)} | transaction <code>${escapeHtml(pack.transactionId)}</code> | <strong class="${escapeHtml(verification.status)}">${escapeHtml(verification.status)}</strong></p><p class="notice">Non-binding technical evidence report. Revocation states are imported reports, not authenticated facts. Raw Mandates, Receipt JWTs, Checkout JWTs, and revocation snapshot bytes are intentionally omitted from this rendering.</p><h2>Timeline</h2><table><thead><tr><th>Time</th><th>Event</th><th>Label</th><th>State</th><th>Digest</th><th>Sources</th></tr></thead><tbody>${rows}</tbody></table><h2>Verification issues</h2><ul>${issueRows}</ul><p>Pack digest: <code>${escapeHtml(pack.packDigest)}</code><br>Report digest: <code>${escapeHtml(verification.reportDigest)}</code><br>Legal effect: ${escapeHtml(verification.legalEffect)}</p></body></html>`;
}
