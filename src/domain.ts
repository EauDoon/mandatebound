/**
 * Normative protocol types for the agent-liability reference engine.
 *
 * These types describe evidence and deterministic allocation outputs. A valid
 * artifact or proof does not establish identity, intent, causation, legal
 * liability, or insurance coverage.
 */

export type JsonPrimitive = null | boolean | string | number;
export type JsonValue = JsonPrimitive | JsonValue[] | { readonly [key: string]: JsonValue };
export type JsonObject = { readonly [key: string]: JsonValue };

export type AsciiIdentifier = string;
export type Rfc3339Timestamp = string;
export type Sha256Digest = `sha256:${string}`;
export type Base64Url = string;
export type KeyId = `urn:agent-liability:jwk:${string}`;

export const ARTIFACT_TYPES = [
  "mandate_envelope",
  "runtime_event",
  "execution_receipt",
  "incident_report",
  "causation_attestation",
  "liability_policy",
  "liability_decision",
  "evidence_bundle",
  "trust_snapshot",
  "appeal_event",
  "rulebook",
] as const;

export type ArtifactType = (typeof ARTIFACT_TYPES)[number];

export const ACTOR_ROLES = [
  "principal",
  "operator",
  "agent",
  "model_vendor",
  "causation_attestor",
  "reviewer",
  "rulebook_publisher",
  "trust_publisher",
  "bundle_assembler",
] as const;

export type ActorRole = (typeof ACTOR_ROLES)[number];

export const PROOF_PURPOSES = [
  "artifact_issuance",
  "mandate_authorization",
  "runtime_observation",
  "execution_attestation",
  "incident_filing",
  "causation_attestation",
  "policy_acceptance",
  "decision_issuance",
  "trust_snapshot_issuance",
  "bundle_assembly",
  "appeal_event",
  "rulebook_issuance",
] as const;

export type ProofPurpose = (typeof PROOF_PURPOSES)[number];

export interface Ed25519PublicJwk {
  readonly kty: "OKP";
  readonly crv: "Ed25519";
  readonly x: Base64Url;
  readonly alg?: "EdDSA";
  readonly use?: "sig";
  readonly key_ops?: readonly ["verify"];
}

export interface ProofHeader {
  readonly alg: "EdDSA";
  readonly kid: KeyId;
  readonly typ: string;
  readonly artifactType: ArtifactType;
  readonly schemaDigest: Sha256Digest;
  readonly purpose: ProofPurpose;
  readonly signedAt: Rfc3339Timestamp;
  readonly canonicalization: "RFC8785";
}

/** Detached compact-JWS components. The payload is the canonical artifact payload. */
export interface DetachedProof {
  readonly protected: Base64Url;
  readonly signature: Base64Url;
}

export interface SignedArtifact<T> {
  readonly format: "agent-liability-signed-artifact/v1";
  readonly artifactType: ArtifactType;
  readonly schemaId: string;
  readonly payload: T;
  readonly payloadDigest: Sha256Digest;
  readonly proofs: readonly DetachedProof[];
}

export interface ActorRef {
  readonly id: AsciiIdentifier;
  readonly role: ActorRole;
}

export interface ArtifactRef {
  readonly artifactType: ArtifactType;
  readonly artifactId: AsciiIdentifier;
  readonly digest: Sha256Digest;
}

export interface Quantity {
  readonly asset: AsciiIdentifier;
  /** Base-10 integer string. Interpretation of scale belongs to the asset profile. */
  readonly minorUnits: string;
}

export interface ActionDescriptor {
  readonly kind: AsciiIdentifier;
  readonly target: AsciiIdentifier;
  readonly parametersDigest: Sha256Digest;
  readonly counterparty?: AsciiIdentifier;
  readonly quantity?: Quantity;
}

export interface ActionScope {
  readonly kind: AsciiIdentifier;
  readonly targets: readonly AsciiIdentifier[];
  readonly counterparties?: readonly AsciiIdentifier[];
  readonly asset?: AsciiIdentifier;
  readonly maxMinorUnits?: string;
}

export interface DelegationScope {
  readonly allowed: boolean;
  readonly maxDepth: number;
  readonly delegates: readonly AsciiIdentifier[];
}

export interface MandateScope {
  readonly actions: readonly ActionScope[];
  readonly maxExecutions: number;
  readonly delegation: DelegationScope;
}

export interface MandateEnvelope {
  readonly schemaVersion: "1.0.0";
  readonly artifactId: AsciiIdentifier;
  readonly revision: number;
  readonly issuedAt: Rfc3339Timestamp;
  readonly validFrom: Rfc3339Timestamp;
  readonly expiresAt: Rfc3339Timestamp;
  readonly nonce: AsciiIdentifier;
  readonly principal: ActorRef;
  readonly operator: ActorRef;
  readonly agent: ActorRef;
  readonly modelVendor?: ActorRef;
  readonly policyRef: ArtifactRef;
  readonly rulebookRef: ArtifactRef;
  readonly scope: MandateScope;
  readonly requiredControls: readonly AsciiIdentifier[];
}

export const RUNTIME_EVENT_TYPES = [
  "request_received",
  "mandate_revoked",
  "mandate_checked",
  "policy_checked",
  "human_approved",
  "model_invoked",
  "tool_called",
  "execution_attempted",
  "execution_completed",
  "execution_failed",
  "rollback_completed",
] as const;

export type RuntimeEventType = (typeof RUNTIME_EVENT_TYPES)[number];

export interface RuntimeEvent {
  readonly schemaVersion: "1.0.0";
  readonly artifactId: AsciiIdentifier;
  readonly executionId: AsciiIdentifier;
  readonly sequence: number;
  readonly eventType: RuntimeEventType;
  readonly actor: ActorRef;
  readonly observedAt: Rfc3339Timestamp;
  /** Required by the mandate_revoked profile; otherwise omitted. */
  readonly effectiveAt?: Rfc3339Timestamp;
  readonly mandateRef?: ArtifactRef;
  readonly actionDigest: Sha256Digest;
  readonly parentEventIds: readonly AsciiIdentifier[];
  readonly contentDigest?: Sha256Digest;
  readonly controlId?: AsciiIdentifier;
  readonly controlResult?: "pass" | "fail" | "not_applicable";
}

export interface ControlResult {
  readonly controlId: AsciiIdentifier;
  readonly result: "pass" | "fail" | "not_applicable";
  readonly eventId: AsciiIdentifier;
}

export interface ExecutionReceipt {
  readonly schemaVersion: "1.0.0";
  readonly artifactId: AsciiIdentifier;
  readonly executionId: AsciiIdentifier;
  readonly mandateRef: ArtifactRef;
  readonly policyRef: ArtifactRef;
  readonly authorizationNonce: AsciiIdentifier;
  readonly idempotencyKey: AsciiIdentifier;
  readonly operator: ActorRef;
  readonly action: ActionDescriptor;
  readonly modelDigest?: Sha256Digest;
  readonly toolManifestDigest: Sha256Digest;
  readonly deploymentDigest: Sha256Digest;
  readonly disposition: "authorized" | "denied" | "executed" | "failed" | "rolled_back";
  readonly executedAt: Rfc3339Timestamp;
  readonly controlResults: readonly ControlResult[];
  readonly eventRootDigest: Sha256Digest;
  readonly actualEffectDigest?: Sha256Digest;
  readonly previousReceiptDigest?: Sha256Digest;
}

export type LiabilityOutcome = "principal" | "operator" | "model_vendor" | "unresolved";

export interface IncidentReport {
  readonly schemaVersion: "1.0.0";
  readonly artifactId: AsciiIdentifier;
  readonly executionReceiptRef: ArtifactRef;
  readonly reporter: ActorRef;
  readonly filedAt: Rfc3339Timestamp;
  readonly discoveredAt: Rfc3339Timestamp;
  readonly allegedBranch: LiabilityOutcome;
  readonly harmCodes: readonly AsciiIdentifier[];
  readonly summaryDigest: Sha256Digest;
  readonly evidenceRefs: readonly ArtifactRef[];
}

export const CAUSATION_METHODS = [
  "counterfactual_replay",
  "controlled_reproduction",
  "signed_provider_admission",
] as const;

export type CausationMethod = (typeof CAUSATION_METHODS)[number];

export interface CounterfactualEvidence {
  readonly baselineDigest: Sha256Digest;
  readonly interventionDigest: Sha256Digest;
  readonly resultDigest: Sha256Digest;
  readonly repetitions: number;
}

export interface CausationAttestation {
  readonly schemaVersion: "1.0.0";
  readonly artifactId: AsciiIdentifier;
  readonly incidentRef: ArtifactRef;
  readonly subject: ActorRef;
  readonly modelDigest: Sha256Digest;
  readonly attestor: ActorRef;
  readonly method: CausationMethod;
  readonly conclusion: "sufficient" | "insufficient" | "conflicting";
  readonly failureCode: AsciiIdentifier;
  readonly causalEventIds: readonly AsciiIdentifier[];
  readonly counterfactual?: CounterfactualEvidence;
  readonly reproductionDigest?: Sha256Digest;
  readonly competingCauseIds: readonly AsciiIdentifier[];
  readonly issuedAt: Rfc3339Timestamp;
}

export interface CausationRequirements {
  readonly requiredForVendorOutcome: true;
  readonly independentAttestorRequired: true;
  readonly allowedMethods: readonly CausationMethod[];
  readonly acceptedAttestorRoles: readonly ["causation_attestor"];
}

export interface AppealPolicy {
  readonly reviewerIds: readonly AsciiIdentifier[];
  readonly maxAppealEvents: number;
}

export interface LiabilityPolicy {
  readonly schemaVersion: "1.0.0";
  readonly artifactId: AsciiIdentifier;
  readonly revision: number;
  readonly issuedAt: Rfc3339Timestamp;
  readonly effectiveFrom: Rfc3339Timestamp;
  readonly effectiveUntil: Rfc3339Timestamp;
  readonly attributionProfile: "mandate-to-liability-v1";
  readonly principalId: AsciiIdentifier;
  readonly operatorId: AsciiIdentifier;
  readonly modelVendorIds: readonly AsciiIdentifier[];
  readonly rulebookRef: ArtifactRef;
  readonly trustSnapshotRef: ArtifactRef;
  readonly causation: CausationRequirements;
  readonly appeal: AppealPolicy;
  readonly legalEffect: "not-determined";
}

export type FactScalar = null | boolean | string | number;

export type RuleCondition =
  | { readonly op: "eq"; readonly fact: AsciiIdentifier; readonly value: FactScalar }
  | { readonly op: "in"; readonly fact: AsciiIdentifier; readonly values: readonly FactScalar[] }
  | { readonly op: "all" | "any"; readonly conditions: readonly RuleCondition[] }
  | { readonly op: "not"; readonly condition: RuleCondition };

export interface PolicyRule {
  readonly id: AsciiIdentifier;
  readonly priority: number;
  readonly when: RuleCondition;
  readonly outcome: LiabilityOutcome;
  readonly reasonCode: AsciiIdentifier;
}

export interface Rulebook {
  readonly schemaVersion: "1.0.0";
  readonly artifactId: AsciiIdentifier;
  readonly revision: number;
  readonly semanticsVersion: "mandate-to-liability-v1";
  readonly issuedAt: Rfc3339Timestamp;
  readonly rules: readonly PolicyRule[];
  readonly defaultOutcome: "unresolved";
}

export interface DecisionTraceEntry {
  readonly stage: AsciiIdentifier;
  readonly result: "pass" | "fail" | "not_applicable" | "matched";
  readonly reasonCode: AsciiIdentifier;
  readonly artifactRefs: readonly ArtifactRef[];
}

export type DecisionDisposition = "allocated" | "indeterminate" | "conflicted" | "invalid";

export interface DecisionCryptographicFact {
  readonly artifactRef: ArtifactRef;
  readonly proofKid?: string;
  readonly schemaDigest?: Sha256Digest;
  readonly purpose: ProofPurpose | "digest_pin";
  readonly signedAt?: Rfc3339Timestamp;
  readonly trustBasis: "caller_digest_pin" | "pinned_root_and_digest";
}

export interface DecisionVerifiedFact {
  readonly name: AsciiIdentifier;
  readonly value: FactScalar;
  readonly sourceRefs: readonly ArtifactRef[];
}

export interface DecisionAttributedAttestation {
  readonly artifactRef: ArtifactRef;
  readonly attributedTo: ActorRef;
  readonly assertion: string;
  readonly accepted: boolean;
}

export interface DecisionPolicyConclusion {
  readonly ruleId?: AsciiIdentifier;
  readonly reasonCode: AsciiIdentifier;
  readonly outcome: LiabilityOutcome;
  readonly disposition: DecisionDisposition;
}

export interface DecisionRejectedEvidence {
  readonly artifactRef?: ArtifactRef;
  readonly reasonCode: AsciiIdentifier;
}

export interface DecisionConditionTrace {
  readonly path: string;
  readonly operator: "eq" | "in" | "all" | "any" | "not";
  readonly matched: boolean;
  readonly fact?: AsciiIdentifier;
  readonly actual?: FactScalar;
  readonly expected?: FactScalar | readonly FactScalar[];
}

export interface DecisionRuleTrace {
  readonly ruleId: AsciiIdentifier;
  readonly priority: number;
  readonly matched: boolean;
  readonly conditions: readonly DecisionConditionTrace[];
}

export interface DecisionPins extends BundlePins {
  readonly bundleRootDigest: Sha256Digest;
  readonly trustRootKid?: string;
}

export interface LiabilityDecision {
  readonly schemaVersion: "1.0.0";
  readonly artifactId: AsciiIdentifier;
  readonly caseId: AsciiIdentifier;
  readonly evaluatedAt: Rfc3339Timestamp;
  readonly evidenceBundleId: AsciiIdentifier;
  readonly evidenceBundleDigest: Sha256Digest;
  readonly policyRef: ArtifactRef;
  readonly rulebookRef: ArtifactRef;
  readonly trustSnapshotRef: ArtifactRef;
  readonly engineVersion: string;
  readonly outcome: LiabilityOutcome;
  readonly disposition: DecisionDisposition;
  readonly policyOutcome: LiabilityOutcome;
  /** Reviewer assertions and event cap copied from the evaluated policy. */
  readonly appealPolicy: AppealPolicy;
  readonly allocation?: ActorRef;
  readonly reasonCodes: readonly AsciiIdentifier[];
  readonly trace: readonly DecisionTraceEntry[];
  readonly missingEvidence: readonly AsciiIdentifier[];
  readonly conflictingEvidence: readonly AsciiIdentifier[];
  readonly cryptographicFacts: readonly DecisionCryptographicFact[];
  readonly verifiedFacts: readonly DecisionVerifiedFact[];
  readonly attributedAttestations: readonly DecisionAttributedAttestation[];
  readonly policyConclusions: readonly DecisionPolicyConclusion[];
  readonly rejectedEvidence: readonly DecisionRejectedEvidence[];
  readonly deterministicTrace: readonly DecisionRuleTrace[];
  readonly pins: DecisionPins;
  readonly externalAuthenticity: "established_by_caller_pins" | "unestablished";
  readonly supersedesDecisionId?: AsciiIdentifier;
  readonly appealId?: AsciiIdentifier;
  readonly legalEffect: "not-determined";
}

export interface BundleEntry {
  readonly path: string;
  readonly mediaType: string;
  readonly schemaId?: string;
  readonly size: number;
  readonly classification: "public" | "internal" | "confidential" | "restricted";
  readonly digest: Sha256Digest;
}

export interface BundlePins {
  readonly asOf: Rfc3339Timestamp;
  readonly policyDigest: Sha256Digest;
  readonly trustSnapshotDigest: Sha256Digest;
  readonly rulebookDigest: Sha256Digest;
  readonly schemaDigests: readonly Sha256Digest[];
  readonly engineVersion: string;
}

/**
 * Caller-owned anchors required before a portable bundle may be allocated.
 *
 * `evaluateBundle` reads nested `pins`, never flattened BundlePins fields.
 * `expectedBundleRootDigest` is an optional second factor for the closed bundle.
 */
export interface EvaluationAnchors {
  readonly pins: BundlePins;
  readonly trustRootJwk?: Ed25519PublicJwk;
  readonly expectedBundleRootDigest?: Sha256Digest;
}

export interface BundleManifest {
  readonly format: "agent-liability-bundle-manifest/v1";
  readonly evidenceCutoff: Rfc3339Timestamp;
  readonly pins: BundlePins;
  readonly entries: readonly BundleEntry[];
  readonly manifestDigest: Sha256Digest;
  readonly merkleRoot: Sha256Digest;
}

export interface BundleObject {
  readonly path: string;
  readonly encoding: "jcs-json";
  readonly content: unknown;
}

export interface EvidenceBundle {
  readonly schemaVersion: "1.0.0";
  readonly artifactId: AsciiIdentifier;
  readonly bundleId: `urn:agent-liability:bundle:${string}`;
  readonly rootDigest: Sha256Digest;
  readonly manifest: BundleManifest;
  readonly objects: readonly BundleObject[];
  readonly proofs: readonly DetachedProof[];
}

export type ValidationErrorCode =
  | "ALB_JSON_INVALID"
  | "ALB_JSON_LIMIT"
  | "ALB_JSON_DUPLICATE_KEY"
  | "ALB_JSON_UNSAFE_KEY"
  | "ALB_JSON_UNSAFE_NUMBER"
  | "ALB_JSON_UNPAIRED_SURROGATE"
  | "ALB_CANONICAL_UNSUPPORTED"
  | "ALB_SCHEMA_UNKNOWN"
  | "ALB_SCHEMA_INVALID"
  | "ALB_DIGEST_MISMATCH"
  | "ALB_PROOF_INVALID"
  | "ALB_PROOF_BINDING"
  | "ALB_TRUST_PIN_MISMATCH"
  | "ALB_TRUST_ROOT_INVALID"
  | "ALB_TRUST_KEY_NOT_FOUND"
  | "ALB_TRUST_ROLE_DENIED"
  | "ALB_TRUST_PURPOSE_DENIED"
  | "ALB_TRUST_SCOPE_DENIED"
  | "ALB_TRUST_KEY_NOT_YET_VALID"
  | "ALB_TRUST_KEY_EXPIRED"
  | "ALB_TRUST_KEY_REVOKED";

export interface ValidationIssue {
  readonly code: ValidationErrorCode | AsciiIdentifier;
  readonly path: string;
  /** Bounded, generic diagnostic. Never contains an input body or secret. */
  readonly message: string;
}

export type ValidationResult<T> =
  | { readonly ok: true; readonly value: T; readonly issues: readonly [] }
  | { readonly ok: false; readonly issues: readonly ValidationIssue[] };

export interface BundleVerificationReport {
  readonly valid: boolean;
  readonly bundleId?: AsciiIdentifier;
  readonly manifestDigest?: Sha256Digest;
  readonly merkleRoot?: Sha256Digest;
  readonly verifiedEntries: number;
  readonly totalEntries: number;
  readonly trustChecked: boolean;
  readonly issues: readonly ValidationIssue[];
}

export interface TrustKey {
  readonly kid: KeyId;
  readonly publicKey: Ed25519PublicJwk;
  readonly roles: readonly ActorRole[];
  readonly purposes: readonly ProofPurpose[];
  readonly validFrom: Rfc3339Timestamp;
  readonly validUntil: Rfc3339Timestamp;
  /** If present, signatures at or after this instant are not trusted. */
  readonly invalidFrom?: Rfc3339Timestamp;
  readonly scopes: readonly AsciiIdentifier[];
}

export interface TrustSnapshot {
  readonly schemaVersion: "1.0.0";
  readonly artifactId: AsciiIdentifier;
  readonly revision: number;
  readonly issuedAt: Rfc3339Timestamp;
  readonly asOf: Rfc3339Timestamp;
  readonly issuer: ActorRef;
  readonly previousSnapshotDigest?: Sha256Digest;
  readonly keys: readonly TrustKey[];
}

export const APPEAL_EVENT_TYPES = [
  "filed",
  "evidence_added",
  "review_started",
  "upheld",
  "reversed",
  "withdrawn",
] as const;

export type AppealEventType = (typeof APPEAL_EVENT_TYPES)[number];

export interface AppealEvent {
  readonly schemaVersion: "1.0.0";
  readonly artifactId: AsciiIdentifier;
  readonly appealId: AsciiIdentifier;
  readonly decisionId: AsciiIdentifier;
  readonly sequence: number;
  readonly previousEventDigest?: Sha256Digest;
  readonly eventType: AppealEventType;
  readonly actor: ActorRef;
  readonly occurredAt: Rfc3339Timestamp;
  readonly reasonCodes: readonly AsciiIdentifier[];
  readonly evidenceBundleDigest?: Sha256Digest;
  readonly supersedingDecisionId?: AsciiIdentifier;
}

export interface EvaluationCase {
  readonly caseId: AsciiIdentifier;
  readonly asOf: Rfc3339Timestamp;
  /** Caller-supplied pins. Never hydrate this field from the evidence bundle. */
  readonly pins: BundlePins;
  /** Optional second factor for authenticating the pinned snapshot publisher. */
  readonly trustRootJwk?: Ed25519PublicJwk;
  readonly mandate?: SignedArtifact<MandateEnvelope>;
  readonly runtimeEvents: readonly SignedArtifact<RuntimeEvent>[];
  readonly priorReceipts: readonly SignedArtifact<ExecutionReceipt>[];
  readonly executionReceipt?: SignedArtifact<ExecutionReceipt>;
  readonly incidentReport?: SignedArtifact<IncidentReport>;
  readonly causationAttestations: readonly SignedArtifact<CausationAttestation>[];
  readonly policy: SignedArtifact<LiabilityPolicy>;
  readonly rulebook: SignedArtifact<Rulebook>;
  readonly trustSnapshot: SignedArtifact<TrustSnapshot>;
  readonly evidenceBundle?: EvidenceBundle;
  readonly priorDecision?: SignedArtifact<LiabilityDecision>;
  readonly appealId?: AsciiIdentifier;
}

export type EvaluationInput = EvaluationCase;
