import {
  createEvidenceBundle,
  evaluationCaseFromBundle,
  verifyEvidenceBundle,
  type BundleReplayAnchors,
} from "./bundle.js";
import { isSha256Digest, sha256Digest } from "./canonical.js";
import { decodeProofHeader, jwkThumbprint, verifySignedArtifactDigest } from "./crypto.js";
import type {
  ActorRef,
  ActorRole,
  ArtifactRef,
  ArtifactType,
  BundlePins,
  CausationAttestation,
  DecisionTraceEntry,
  Ed25519PublicJwk,
  EvaluationCase,
  EvidenceBundle,
  ExecutionReceipt,
  LiabilityDecision,
  LiabilityOutcome,
  MandateEnvelope,
  ProofPurpose,
  Rfc3339Timestamp,
  Rulebook,
  RuntimeEvent,
  Sha256Digest,
  SignedArtifact,
  ValidationIssue,
} from "./domain.js";
import {
  evaluateRulebook,
  validateRulebook,
  type PolicyEvaluation,
  type PolicyFacts,
  type PolicyFactName,
  type PolicyFactValue,
  type RuleEvaluationTrace,
} from "./policy.js";
import {
  verifyPinnedTrustSnapshot,
  verifyProofWithTrust,
  type VerifiedTrustSnapshot,
} from "./trust.js";
import { schemaDigestForArtifactType, validateSignedArtifact } from "./validation.js";
import { ENGINE_VERSION, LEGAL_EFFECT } from "./version.js";

const ASCII_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ASCII_LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const ASCII_DIGITS = "0123456789";
const ASCII_IDENTIFIER_LEAD = ASCII_UPPERCASE + ASCII_LOWERCASE + ASCII_DIGITS;
const ASCII_IDENTIFIER_CHARACTERS = ASCII_IDENTIFIER_LEAD + "._:-";

export type DecisionDisposition = "allocated" | "indeterminate" | "conflicted" | "invalid";

export interface EvaluationAnchors extends BundleReplayAnchors {
  readonly expectedBundleRootDigest?: Sha256Digest;
}

export interface CryptographicFact {
  readonly artifactRef: ArtifactRef;
  readonly proofKid?: string;
  readonly schemaDigest?: Sha256Digest;
  readonly purpose: ProofPurpose | "digest_pin";
  readonly signedAt?: Rfc3339Timestamp;
  readonly trustBasis: "caller_digest_pin" | "pinned_root_and_digest";
}

export interface VerifiedPolicyFact {
  readonly name: PolicyFactName;
  readonly value: PolicyFactValue;
  readonly sourceRefs: readonly ArtifactRef[];
}

export interface AttributedAttestation {
  readonly artifactRef: ArtifactRef;
  readonly attributedTo: ActorRef;
  readonly assertion: string;
  readonly accepted: boolean;
}

export interface PolicyConclusion {
  readonly ruleId?: string;
  readonly reasonCode: string;
  readonly outcome: LiabilityOutcome;
  readonly disposition: DecisionDisposition;
}

export interface RejectedEvidence {
  readonly artifactRef?: ArtifactRef;
  readonly reasonCode: string;
}

export interface EngineDecisionPins extends BundlePins {
  readonly bundleRootDigest: Sha256Digest;
  readonly trustRootKid?: string;
}

/**
 * Strictly richer than the stable protocol LiabilityDecision. Consumers that
 * only know the base interface can ignore the separated evidence categories.
 */
export interface EngineLiabilityDecision extends LiabilityDecision {
  readonly disposition: DecisionDisposition;
  readonly policyOutcome: LiabilityOutcome;
  readonly allocation?: ActorRef;
  readonly cryptographicFacts: readonly CryptographicFact[];
  readonly verifiedFacts: readonly VerifiedPolicyFact[];
  readonly attributedAttestations: readonly AttributedAttestation[];
  readonly policyConclusions: readonly PolicyConclusion[];
  readonly rejectedEvidence: readonly RejectedEvidence[];
  readonly deterministicTrace: readonly RuleEvaluationTrace[];
  readonly pins: EngineDecisionPins;
  readonly externalAuthenticity: "established_by_caller_pins" | "unestablished";
}

export const RESERVED_CONTROL_IDS = Object.freeze({
  mandateValid: "mandate-valid",
  mandateNotRevoked: "mandate-not-revoked",
  scopeCompliant: "scope-compliant",
  replayProtected: "replay-protected",
} as const);

const EMPTY_DIGEST = sha256Digest(new Uint8Array());

interface MutableEvaluation {
  hardInvalid: boolean;
  tampered: boolean;
  readonly missing: Set<string>;
  readonly conflicts: Set<string>;
  readonly rejected: RejectedEvidence[];
  readonly cryptographicFacts: CryptographicFact[];
  readonly attestations: AttributedAttestation[];
  readonly verifiedRefs: ArtifactRef[];
  trust?: VerifiedTrustSnapshot;
}

interface ArtifactExpectation<T> {
  readonly artifactType: ArtifactType;
  readonly purpose: ProofPurpose;
  readonly role: ActorRole;
  readonly actorId?: string;
  readonly label: string;
  readonly artifact: SignedArtifact<T>;
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function uniqueSorted(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort(compareAscii);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function refFor<T extends { readonly artifactId: string }>(artifact: SignedArtifact<T>): ArtifactRef {
  return {
    artifactType: artifact.artifactType,
    artifactId: artifact.payload.artifactId,
    digest: artifact.payloadDigest,
  };
}

function safeRef(artifact: unknown, artifactType: ArtifactType, label: string): ArtifactRef {
  if (isPlainObject(artifact)) {
    const payload = artifact.payload;
    const digest = artifact.payloadDigest;
    const actualType = artifact.artifactType;
    if (
      isPlainObject(payload) &&
      typeof payload.artifactId === "string" &&
      isSha256Digest(digest) &&
      typeof actualType === "string"
    ) {
      return {
        artifactType: actualType as ArtifactType,
        artifactId: payload.artifactId,
        digest,
      };
    }
  }
  return { artifactType, artifactId: `missing-${label}`, digest: EMPTY_DIGEST };
}

function sameRef(reference: ArtifactRef, artifact: SignedArtifact<{ readonly artifactId: string }>): boolean {
  return (
    reference.artifactType === artifact.artifactType &&
    reference.artifactId === artifact.payload.artifactId &&
    reference.digest === artifact.payloadDigest
  );
}

function reject(
  state: MutableEvaluation,
  reasonCode: string,
  artifact?: SignedArtifact<{ readonly artifactId: string }>,
  mode: "invalid" | "tampered" | "conflict" = "invalid",
): void {
  if (mode === "invalid") state.hardInvalid = true;
  if (mode === "tampered") {
    state.hardInvalid = true;
    state.tampered = true;
  }
  if (mode === "conflict") state.conflicts.add(reasonCode);
  const candidate: RejectedEvidence = artifact === undefined
    ? { reasonCode }
    : { artifactRef: refFor(artifact), reasonCode };
  const key = `${candidate.artifactRef?.digest ?? "none"}:${reasonCode}`;
  if (!state.rejected.some((item) => `${item.artifactRef?.digest ?? "none"}:${item.reasonCode}` === key)) {
    state.rejected.push(candidate);
  }
}

function addMissing(state: MutableEvaluation, code: string): void {
  state.missing.add(code);
}

function proofSchemaPinned(pins: BundlePins, schemaDigest: Sha256Digest): boolean {
  return pins.schemaDigests.includes(schemaDigest);
}

function verifyArtifact<T extends { readonly artifactId: string }>(
  state: MutableEvaluation,
  input: EvaluationCase,
  expectation: ArtifactExpectation<T>,
): boolean {
  const { artifact } = expectation;
  if (
    artifact.format !== "agent-liability-signed-artifact/v1" ||
    artifact.artifactType !== expectation.artifactType ||
    typeof artifact.schemaId !== "string" ||
    artifact.schemaId.length === 0
  ) {
    reject(state, `${expectation.label}_shape_invalid`, artifact, "tampered");
    return false;
  }
  const schema = validateSignedArtifact(artifact);
  if (!schema.ok) {
    reject(state, `${expectation.label}_schema_invalid`, artifact, "tampered");
    return false;
  }
  const digest = verifySignedArtifactDigest(artifact);
  if (!digest.ok) {
    reject(state, `${expectation.label}_digest_invalid`, artifact, "tampered");
    return false;
  }
  if (artifact.proofs.length !== 1) {
    reject(state, `${expectation.label}_proof_count_invalid`, artifact, "tampered");
    return false;
  }
  const proof = artifact.proofs[0];
  if (proof === undefined) {
    reject(state, `${expectation.label}_proof_missing`, artifact, "tampered");
    return false;
  }
  const header = decodeProofHeader(proof);
  let expectedSchemaDigest: Sha256Digest;
  try {
    expectedSchemaDigest = schemaDigestForArtifactType(expectation.artifactType);
  } catch {
    reject(state, `${expectation.label}_schema_unknown`, artifact, "tampered");
    return false;
  }
  if (
    !header.ok ||
    header.value.schemaDigest !== expectedSchemaDigest ||
    !proofSchemaPinned(input.pins, expectedSchemaDigest)
  ) {
    reject(state, `${expectation.label}_schema_unpinned`, artifact, "tampered");
    return false;
  }
  if (state.trust === undefined) {
    reject(state, `${expectation.label}_trust_unavailable`, artifact, "invalid");
    return false;
  }
  const trustedKey = state.trust.snapshot.keys.find((candidate) => candidate.kid === header.value.kid);
  if (
    expectation.actorId !== undefined &&
    (trustedKey === undefined ||
      !trustedKey.scopes.includes(expectation.actorId))
  ) {
    reject(state, `${expectation.label}_actor_scope_denied`, artifact, "tampered");
    return false;
  }
  const verified = verifyProofWithTrust(artifact.payload, proof, state.trust, {
    role: expectation.role,
    purpose: expectation.purpose,
    at: input.asOf,
    artifactType: expectation.artifactType,
    schemaDigest: expectedSchemaDigest,
    ...(expectation.actorId === undefined ? {} : { scope: expectation.actorId }),
  });
  if (!verified.ok) {
    reject(state, `${expectation.label}_proof_invalid`, artifact, "tampered");
    return false;
  }
  const reference = refFor(artifact);
  state.verifiedRefs.push(reference);
  state.cryptographicFacts.push({
    artifactRef: reference,
    proofKid: verified.value.kid,
    schemaDigest: verified.value.schemaDigest,
    purpose: verified.value.purpose,
    signedAt: verified.value.signedAt,
    trustBasis: state.trust.publisherAuthenticated
      ? "pinned_root_and_digest"
      : "caller_digest_pin",
  });
  return true;
}

function pinsAreSortedAndUnique(pins: BundlePins): boolean {
  if (pins.schemaDigests.length === 0) return false;
  return pins.schemaDigests.every((digest, index) => {
    const previous = pins.schemaDigests[index - 1];
    return isSha256Digest(digest) && (index === 0 || (previous !== undefined && previous < digest));
  });
}

function checkPins(input: EvaluationCase, state: MutableEvaluation): void {
  if (
    input.pins.asOf !== input.asOf ||
    input.pins.engineVersion !== ENGINE_VERSION ||
    !pinsAreSortedAndUnique(input.pins)
  ) {
    reject(state, "input_pins_invalid");
  }
  try {
    if (
      sha256Digest(input.policy.payload) !== input.pins.policyDigest ||
      input.policy.payloadDigest !== input.pins.policyDigest
    ) {
      reject(state, "policy_pin_mismatch", input.policy, "tampered");
    }
    if (
      sha256Digest(input.rulebook.payload) !== input.pins.rulebookDigest ||
      input.rulebook.payloadDigest !== input.pins.rulebookDigest
    ) {
      reject(state, "rulebook_pin_mismatch", input.rulebook, "tampered");
    }
    if (
      sha256Digest(input.trustSnapshot.payload) !== input.pins.trustSnapshotDigest ||
      input.trustSnapshot.payloadDigest !== input.pins.trustSnapshotDigest
    ) {
      reject(state, "trust_pin_mismatch", input.trustSnapshot, "tampered");
    }
  } catch {
    reject(state, "pinned_artifact_not_canonical", undefined, "tampered");
  }
  if (input.evidenceBundle !== undefined) {
    const report = verifyEvidenceBundle(input.evidenceBundle);
    if (!report.valid) reject(state, "evidence_bundle_invalid", undefined, "tampered");
    try {
      if (sha256Digest(input.evidenceBundle.manifest.pins) !== sha256Digest(input.pins)) {
        reject(state, "bundle_pin_mismatch", undefined, "tampered");
      }
      if (report.valid) {
        const replayInput = evaluationCaseFromBundle(input.evidenceBundle, {
          pins: input.pins,
          ...(input.trustRootJwk === undefined ? {} : { trustRootJwk: input.trustRootJwk }),
        });
        if (sha256Digest(evaluationCaseMaterial(input)) !== sha256Digest(evaluationCaseMaterial(replayInput))) {
          reject(state, "evidence_bundle_case_mismatch", undefined, "tampered");
        }
      }
    } catch {
      reject(state, "bundle_pin_invalid", undefined, "tampered");
    }
  }
}

function verifyTrust(input: EvaluationCase, state: MutableEvaluation): void {
  const schema = validateSignedArtifact(input.trustSnapshot);
  if (!schema.ok) {
    reject(state, "trust_snapshot_schema_invalid", input.trustSnapshot, "tampered");
    return;
  }
  const expectedSchemaDigest = schemaDigestForArtifactType("trust_snapshot");
  const header = input.trustSnapshot.proofs[0] === undefined
    ? undefined
    : decodeProofHeader(input.trustSnapshot.proofs[0]);
  if (
    input.trustSnapshot.proofs.length !== 1 ||
    header === undefined ||
    !header.ok ||
    header.value.schemaDigest !== expectedSchemaDigest ||
    !proofSchemaPinned(input.pins, expectedSchemaDigest) ||
    input.trustSnapshot.payload.asOf !== input.asOf ||
    input.trustSnapshot.payload.issuedAt > input.asOf
  ) {
    reject(state, "trust_snapshot_binding_invalid", input.trustSnapshot, "tampered");
    return;
  }
  const result = verifyPinnedTrustSnapshot(
    input.trustSnapshot,
    input.pins.trustSnapshotDigest,
    input.trustRootJwk,
    input.asOf,
  );
  if (!result.ok) {
    reject(state, "trust_snapshot_unverified", input.trustSnapshot, "invalid");
    return;
  }
  state.trust = result.value;
  const reference = refFor(input.trustSnapshot);
  state.verifiedRefs.push(reference);
  state.cryptographicFacts.push({
    artifactRef: reference,
    purpose: "digest_pin",
    trustBasis: result.value.publisherAuthenticated
      ? "pinned_root_and_digest"
      : "caller_digest_pin",
  });
}

function activeAt(timestamp: string, start: string, end: string): boolean {
  return timestamp >= start && timestamp < end;
}

function canonicalNonNegativeInteger(value: string): bigint | undefined {
  if (value.length === 0 || (value.length > 1 && value.startsWith("0"))) return undefined;
  for (const character of value) {
    if (character < "0" || character > "9") return undefined;
  }
  try {
    return BigInt(value);
  } catch {
    return undefined;
  }
}

function actionInScope(action: ExecutionReceipt["action"], mandate: MandateEnvelope): boolean {
  for (const scope of mandate.scope.actions) {
    if (scope.kind !== action.kind || !scope.targets.includes(action.target)) continue;
    if (
      scope.counterparties !== undefined &&
      (action.counterparty === undefined || !scope.counterparties.includes(action.counterparty))
    ) {
      continue;
    }
    if (scope.asset !== undefined) {
      if (action.quantity === undefined || action.quantity.asset !== scope.asset) continue;
    }
    if (scope.maxMinorUnits !== undefined) {
      if (action.quantity === undefined) continue;
      const actual = canonicalNonNegativeInteger(action.quantity.minorUnits);
      const maximum = canonicalNonNegativeInteger(scope.maxMinorUnits);
      if (actual === undefined || maximum === undefined || actual > maximum) continue;
    }
    return true;
  }
  return false;
}

function runtimeOrder(
  left: SignedArtifact<RuntimeEvent>,
  right: SignedArtifact<RuntimeEvent>,
): number {
  return (
    left.payload.sequence - right.payload.sequence ||
    compareAscii(left.payload.artifactId, right.payload.artifactId) ||
    compareAscii(left.payloadDigest, right.payloadDigest)
  );
}

function signedArtifactOrder<T extends { readonly artifactId: string }>(
  left: SignedArtifact<T>,
  right: SignedArtifact<T>,
): number {
  return compareAscii(left.payload.artifactId, right.payload.artifactId) ||
    compareAscii(left.payloadDigest, right.payloadDigest);
}

/** Known case fields normalized exactly as the evidence-bundle index normalizes them. */
function evaluationCaseMaterial(input: EvaluationCase): unknown {
  return {
    caseId: input.caseId,
    asOf: input.asOf,
    ...(input.mandate === undefined ? {} : { mandate: input.mandate }),
    runtimeEvents: [...input.runtimeEvents].sort(runtimeOrder),
    priorReceipts: [...input.priorReceipts].sort(signedArtifactOrder),
    ...(input.executionReceipt === undefined ? {} : { executionReceipt: input.executionReceipt }),
    ...(input.incidentReport === undefined ? {} : { incidentReport: input.incidentReport }),
    causationAttestations: [...input.causationAttestations].sort(signedArtifactOrder),
    policy: input.policy,
    rulebook: input.rulebook,
    trustSnapshot: input.trustSnapshot,
    ...(input.priorDecision === undefined ? {} : { priorDecision: input.priorDecision }),
    ...(input.appealId === undefined ? {} : { appealId: input.appealId }),
  };
}

/** Public so fixtures and independent implementations can reproduce the root. */
export function computeEventRootDigest(events: readonly SignedArtifact<RuntimeEvent>[]): Sha256Digest {
  const normalized = [...events].sort(runtimeOrder).map((event) => ({
    sequence: event.payload.sequence,
    artifactId: event.payload.artifactId,
    payloadDigest: event.payloadDigest,
  }));
  return sha256Digest({ profile: "agent-liability-event-root/v1", events: normalized });
}

function controlState(
  mandate: MandateEnvelope,
  receipt: ExecutionReceipt,
  runtimeEvents: readonly SignedArtifact<RuntimeEvent>[],
  verifiedEventDigests: ReadonlySet<Sha256Digest>,
  state: MutableEvaluation,
): "compliant" | "noncompliant" | "unknown" {
  const seen = new Set<string>();
  let compliant = true;
  for (const result of receipt.controlResults) {
    if (seen.has(result.controlId)) {
      state.conflicts.add("duplicate_control_result");
      compliant = false;
    }
    seen.add(result.controlId);
    const matchingEvent = runtimeEvents.find(
      (event) =>
        verifiedEventDigests.has(event.payloadDigest) &&
        event.payload.artifactId === result.eventId &&
        event.payload.controlId === result.controlId &&
        event.payload.controlResult === result.result,
    );
    if (matchingEvent === undefined) {
      state.conflicts.add("control_event_mismatch");
      compliant = false;
    }
  }
  for (const required of mandate.requiredControls) {
    const result = receipt.controlResults.find((candidate) => candidate.controlId === required);
    if (result === undefined || result.result !== "pass") compliant = false;
    const controlEvents = runtimeEvents.filter(
      (event) =>
        verifiedEventDigests.has(event.payloadDigest) &&
        event.payload.controlId === required,
    );
    if (controlEvents.some((event) => event.payload.controlResult === undefined)) {
      state.conflicts.add("control_event_incomplete");
      compliant = false;
    }
    const eventResults = new Set(
      controlEvents
        .map((event) => event.payload.controlResult)
        .filter((value): value is NonNullable<RuntimeEvent["controlResult"]> => value !== undefined),
    );
    if (
      eventResults.size > 1 ||
      (result !== undefined && [...eventResults].some((value) => value !== result.result))
    ) {
      state.conflicts.add("control_event_contradiction");
      compliant = false;
    }
  }
  if (mandate.requiredControls.length === 0) return "unknown";
  return compliant ? "compliant" : "noncompliant";
}

function runtimeActorBound(event: RuntimeEvent, mandate: MandateEnvelope): boolean {
  if (event.actor.role === "principal") return event.actor.id === mandate.principal.id;
  if (event.actor.role === "operator") return event.actor.id === mandate.operator.id;
  if (event.actor.role === "agent") return event.actor.id === mandate.agent.id;
  if (event.actor.role === "model_vendor") {
    return mandate.modelVendor !== undefined && event.actor.id === mandate.modelVendor.id;
  }
  return false;
}

function verifyRuntimeGraph(
  events: readonly SignedArtifact<RuntimeEvent>[],
  receipt: ExecutionReceipt,
  state: MutableEvaluation,
): void {
  const ordered = [...events].sort(runtimeOrder);
  const ids = new Set<string>();
  const sequences = new Set<number>();
  const actionDigest = sha256Digest(receipt.action);
  for (const event of ordered) {
    if (ids.has(event.payload.artifactId) || sequences.has(event.payload.sequence)) {
      state.conflicts.add("runtime_event_order_conflict");
    }
    if (event.payload.executionId !== receipt.executionId) {
      state.conflicts.add("runtime_execution_id_conflict");
    }
    if (event.payload.actionDigest !== actionDigest && event.payload.eventType !== "mandate_revoked") {
      state.conflicts.add("runtime_action_digest_conflict");
    }
    if (event.payload.observedAt > receipt.executedAt && event.payload.eventType !== "rollback_completed") {
      state.conflicts.add("runtime_event_after_execution");
    }
    for (const parent of event.payload.parentEventIds) {
      if (!ids.has(parent)) state.conflicts.add("runtime_parent_missing_or_forward");
    }
    ids.add(event.payload.artifactId);
    sequences.add(event.payload.sequence);
  }
  if (!ordered.some((event) => event.payload.eventType === "execution_completed")) {
    addMissing(state, "execution_completed_event");
  }
  if (receipt.eventRootDigest !== computeEventRootDigest(events)) {
    state.conflicts.add("event_root_digest_mismatch");
  }
}

function verifiedPriorReceipts(
  input: EvaluationCase,
  state: MutableEvaluation,
): readonly SignedArtifact<ExecutionReceipt>[] {
  const verified: SignedArtifact<ExecutionReceipt>[] = [];
  for (const artifact of input.priorReceipts) {
    const accepted = verifyArtifact(state, input, {
      artifact,
      artifactType: "execution_receipt",
      purpose: "execution_attestation",
      role: "operator",
      actorId: artifact.payload.operator.id,
      label: "prior_receipt",
    });
    if (artifact.payload.executedAt > input.asOf) {
      reject(state, "prior_receipt_future_dated", artifact, "invalid");
    } else if (accepted) {
      verified.push(artifact);
    }
  }
  return verified;
}

function replayed(
  current: ExecutionReceipt,
  mandate: SignedArtifact<MandateEnvelope>,
  policy: EvaluationCase["policy"],
  priors: readonly SignedArtifact<ExecutionReceipt>[],
  state: MutableEvaluation,
): boolean {
  const relevant = new Map<Sha256Digest, SignedArtifact<ExecutionReceipt>>();
  const executionIds = new Map<string, Sha256Digest>();
  const idempotencyKeys = new Map<string, Sha256Digest>();
  for (const prior of priors) {
    if (!sameRef(prior.payload.mandateRef, mandate)) continue;
    if (
      prior.payload.operator.role !== "operator" ||
      prior.payload.operator.id !== mandate.payload.operator.id ||
      !sameRef(prior.payload.policyRef, policy) ||
      prior.payload.authorizationNonce !== mandate.payload.nonce
    ) {
      state.conflicts.add("prior_receipt_binding_conflict");
      continue;
    }
    if (prior.payload.executedAt > current.executedAt) {
      state.conflicts.add("prior_receipt_after_current_execution");
      continue;
    }
    const executionDigest = executionIds.get(prior.payload.executionId);
    const idempotencyDigest = idempotencyKeys.get(prior.payload.idempotencyKey);
    if (
      (executionDigest !== undefined && executionDigest !== prior.payloadDigest) ||
      (idempotencyDigest !== undefined && idempotencyDigest !== prior.payloadDigest)
    ) {
      state.conflicts.add("prior_receipt_identity_conflict");
      continue;
    }
    executionIds.set(prior.payload.executionId, prior.payloadDigest);
    idempotencyKeys.set(prior.payload.idempotencyKey, prior.payloadDigest);
    relevant.set(prior.payloadDigest, prior);
  }
  for (const prior of relevant.values()) {
    if (
      prior.payload.executionId === current.executionId ||
      prior.payload.idempotencyKey === current.idempotencyKey
    ) {
      return true;
    }
  }
  const completed = [...relevant.values()].filter(
    (prior) => prior.payload.disposition === "executed",
  ).length;
  return completed + 1 > mandate.payload.scope.maxExecutions;
}

function revocationEffective(
  events: readonly SignedArtifact<RuntimeEvent>[],
  mandate: SignedArtifact<MandateEnvelope>,
  executedAt: string,
  verifiedEventDigests: ReadonlySet<Sha256Digest>,
): boolean {
  return events.some(
    (event) =>
      verifiedEventDigests.has(event.payloadDigest) &&
      event.payload.eventType === "mandate_revoked" &&
      event.payload.effectiveAt !== undefined &&
      event.payload.effectiveAt <= executedAt &&
      event.payload.mandateRef !== undefined &&
      sameRef(event.payload.mandateRef, mandate),
  );
}

function causationState(
  input: EvaluationCase,
  state: MutableEvaluation,
  receiptTrusted: boolean,
  verifiedEventDigests: ReadonlySet<Sha256Digest>,
): {
  readonly state: PolicyFacts["causation_state"];
  readonly provenance: PolicyFacts["model_provenance"];
  readonly vendor?: ActorRef;
} {
  if (input.causationAttestations.length === 0) {
    return { state: "missing", provenance: "missing" };
  }
  const accepted: SignedArtifact<CausationAttestation>[] = [];
  for (const artifact of input.causationAttestations) {
    const proofAccepted = verifyArtifact(state, input, {
      artifact,
      artifactType: "causation_attestation",
      purpose: "causation_attestation",
      role: "causation_attestor",
      actorId: artifact.payload.attestor.id,
      label: "causation_attestation",
    });
    let semanticallyAccepted = proofAccepted;
    if (
      input.incidentReport === undefined ||
      !sameRef(artifact.payload.incidentRef, input.incidentReport) ||
      artifact.payload.attestor.id === artifact.payload.subject.id ||
      artifact.payload.attestor.id === input.policy.payload.principalId ||
      artifact.payload.attestor.id === input.policy.payload.operatorId ||
      artifact.payload.attestor.role !== "causation_attestor" ||
      artifact.payload.subject.role !== "model_vendor" ||
      !input.policy.payload.modelVendorIds.includes(artifact.payload.subject.id) ||
      !input.policy.payload.causation.allowedMethods.includes(artifact.payload.method) ||
      artifact.payload.issuedAt > input.asOf
    ) {
      semanticallyAccepted = false;
      state.conflicts.add("causation_attestation_binding_conflict");
    }
    state.attestations.push({
      artifactRef: refFor(artifact),
      attributedTo: artifact.payload.attestor,
      assertion: `causation:${artifact.payload.conclusion}:${artifact.payload.failureCode}`,
      accepted: semanticallyAccepted,
    });
    if (semanticallyAccepted) accepted.push(artifact);
  }
  if (accepted.length === 0) return { state: "missing", provenance: "missing" };
  if (accepted.some((artifact) => artifact.payload.conclusion === "conflicting")) {
    return { state: "conflicting", provenance: "mismatched" };
  }
  const sufficient = accepted.filter((artifact) => artifact.payload.conclusion === "sufficient");
  const insufficient = accepted.filter((artifact) => artifact.payload.conclusion === "insufficient");
  if (sufficient.length > 0 && insufficient.length > 0) {
    return { state: "conflicting", provenance: "mismatched" };
  }
  if (accepted.some((artifact) => artifact.payload.competingCauseIds.length > 0)) {
    return { state: "multi_causal", provenance: "mismatched" };
  }
  if (sufficient.length === 0) return { state: "insufficient", provenance: "missing" };
  const causalClaims = new Set(
    sufficient.map((artifact) =>
      sha256Digest({
        subject: artifact.payload.subject,
        modelDigest: artifact.payload.modelDigest,
        failureCode: artifact.payload.failureCode,
        causalEventIds: [...artifact.payload.causalEventIds].sort(compareAscii),
      }),
    ),
  );
  if (causalClaims.size > 1) {
    return { state: "multi_causal", provenance: "mismatched" };
  }
  const selected = sufficient[0];
  if (selected === undefined || !receiptTrusted || input.executionReceipt === undefined || input.mandate === undefined) {
    return { state: "sufficient", provenance: "missing" };
  }
  const receipt = input.executionReceipt.payload;
  const mandateVendor = input.mandate.payload.modelVendor;
  const modelEvents = input.runtimeEvents.filter(
    (event) =>
      verifiedEventDigests.has(event.payloadDigest) && event.payload.eventType === "model_invoked",
  );
  const matching =
    mandateVendor !== undefined &&
    mandateVendor.id === selected.payload.subject.id &&
    receipt.modelDigest !== undefined &&
    receipt.modelDigest === selected.payload.modelDigest &&
    modelEvents.length > 0 &&
    modelEvents.every((event) => event.payload.contentDigest === receipt.modelDigest) &&
    selected.payload.causalEventIds.every((eventId) =>
      modelEvents.some((event) => event.payload.artifactId === eventId),
    );
  return {
    state: "sufficient",
    provenance: matching ? "matched" : "mismatched",
    ...(matching ? { vendor: selected.payload.subject } : {}),
  };
}

function checkIncidentEvidenceClosure(input: EvaluationCase, state: MutableEvaluation): void {
  if (input.incidentReport === undefined) return;
  const provided: SignedArtifact<{ readonly artifactId: string }>[] = [
    ...input.runtimeEvents,
    ...input.priorReceipts,
    ...input.causationAttestations,
    input.policy,
    input.rulebook,
    input.trustSnapshot,
  ];
  if (input.mandate !== undefined) provided.push(input.mandate);
  if (input.executionReceipt !== undefined) provided.push(input.executionReceipt);
  if (input.priorDecision !== undefined) provided.push(input.priorDecision);
  const verifiedDigests = new Set(state.verifiedRefs.map((reference) => reference.digest));
  for (const reference of input.incidentReport.payload.evidenceRefs) {
    const exact = provided.find(
      (artifact) =>
        artifact.artifactType === reference.artifactType &&
        artifact.payload.artifactId === reference.artifactId &&
        artifact.payloadDigest === reference.digest,
    );
    if (exact === undefined) {
      const conflicting = provided.some(
        (artifact) =>
          artifact.artifactType === reference.artifactType &&
          artifact.payload.artifactId === reference.artifactId,
      );
      if (conflicting) state.conflicts.add("incident_evidence_digest_conflict");
      else addMissing(state, `incident_evidence:${reference.artifactType}:${reference.artifactId}`);
    } else if (!verifiedDigests.has(exact.payloadDigest)) {
      addMissing(state, `incident_evidence_unverified:${reference.artifactType}:${reference.artifactId}`);
    }
  }
}

function allowedOutcome(outcome: LiabilityOutcome, facts: PolicyFacts): boolean {
  if (outcome === "unresolved") return true;
  if (facts.evidence_state !== "sufficient" || facts.policy_state !== "active" || facts.trust_state !== "pinned") {
    return false;
  }
  if (outcome === "operator") {
    return facts.receipt_state === "trusted" && facts.operator_violation !== "none";
  }
  if (
    facts.mandate_state !== "valid" ||
    facts.receipt_state !== "trusted" ||
    facts.execution_state !== "compliant" ||
    facts.operator_controls !== "compliant" ||
    facts.operator_violation !== "none"
  ) {
    return false;
  }
  if (outcome === "principal") return true;
  return facts.model_provenance === "matched" && facts.causation_state === "sufficient";
}

function guardedPolicyEvaluation(
  input: EvaluationCase,
  state: MutableEvaluation,
  facts: PolicyFacts,
): PolicyEvaluation {
  if (state.hardInvalid || state.tampered) {
    return { outcome: "unresolved", reasonCode: "invalid_evidence", trace: [] };
  }
  if (state.conflicts.size > 0 || facts.causation_state === "conflicting" || facts.causation_state === "multi_causal") {
    return { outcome: "unresolved", reasonCode: "conflicting_evidence", trace: [] };
  }
  if (state.missing.size > 0 || facts.evidence_state === "missing") {
    return { outcome: "unresolved", reasonCode: "missing_required_evidence", trace: [] };
  }
  const validation = validateRulebook(input.rulebook.payload);
  if (!validation.valid) {
    return { outcome: "unresolved", reasonCode: "invalid_rulebook", trace: [] };
  }
  const evaluated = evaluateRulebook(input.rulebook.payload as Rulebook, facts);
  if (!allowedOutcome(evaluated.outcome, facts)) {
    return {
      outcome: "unresolved",
      reasonCode: "rulebook_conclusion_denied",
      ...(evaluated.matchedRuleId === undefined ? {} : { matchedRuleId: evaluated.matchedRuleId }),
      trace: evaluated.trace,
    };
  }
  return evaluated;
}

function dispositionFor(evaluation: PolicyEvaluation): DecisionDisposition {
  if (evaluation.outcome !== "unresolved") return "allocated";
  if (evaluation.reasonCode === "invalid_evidence" || evaluation.reasonCode === "invalid_rulebook" || evaluation.reasonCode === "rulebook_conclusion_denied") {
    return "invalid";
  }
  if (evaluation.reasonCode === "conflicting_evidence") return "conflicted";
  return "indeterminate";
}

function allocationFor(
  outcome: LiabilityOutcome,
  input: EvaluationCase,
  vendor?: ActorRef,
): ActorRef | undefined {
  if (outcome === "principal") {
    return input.mandate?.payload.principal ?? { id: input.policy.payload.principalId, role: "principal" };
  }
  if (outcome === "operator") {
    return input.mandate?.payload.operator ?? { id: input.policy.payload.operatorId, role: "operator" };
  }
  if (outcome === "model_vendor") return vendor;
  return undefined;
}

function traceEntry(
  stage: string,
  result: DecisionTraceEntry["result"],
  reasonCode: string,
  refs: readonly ArtifactRef[],
): DecisionTraceEntry {
  return { stage, result, reasonCode, artifactRefs: [...refs].sort((a, b) => compareAscii(a.digest, b.digest)) };
}

function bundleForInput(input: EvaluationCase): EvidenceBundle {
  if (input.evidenceBundle !== undefined) return input.evidenceBundle;
  return createEvidenceBundle(input);
}

function evaluateCaseInternal(
  input: EvaluationCase,
  forcedReason?: "ALB_TRUST_ANCHOR_REQUIRED" | "ALB_BUNDLE_ANCHOR_MISMATCH",
): EngineLiabilityDecision {
  const state: MutableEvaluation = {
    hardInvalid: forcedReason !== undefined,
    tampered: false,
    missing: new Set<string>(),
    conflicts: new Set<string>(),
    rejected: [],
    cryptographicFacts: [],
    attestations: [],
    verifiedRefs: [],
  };
  if (forcedReason !== undefined) reject(state, forcedReason);
  checkPins(input, state);
  verifyTrust(input, state);

  const policyValid = verifyArtifact(state, input, {
    artifact: input.policy,
    artifactType: "liability_policy",
    purpose: "policy_acceptance",
    role: "principal",
    actorId: input.policy.payload.principalId,
    label: "policy",
  });
  const rulebookValid = verifyArtifact(state, input, {
    artifact: input.rulebook,
    artifactType: "rulebook",
    purpose: "rulebook_issuance",
    role: "rulebook_publisher",
    label: "rulebook",
  });
  let priorDecisionTrusted = false;
  if (input.priorDecision !== undefined) {
    priorDecisionTrusted = verifyArtifact(state, input, {
      artifact: input.priorDecision,
      artifactType: "liability_decision",
      purpose: "decision_issuance",
      role: "reviewer",
      label: "prior_decision",
    });
    if (
      input.appealId === undefined ||
      input.priorDecision.payload.caseId !== input.caseId ||
      input.priorDecision.payload.evaluatedAt > input.asOf ||
      input.priorDecision.payload.legalEffect !== LEGAL_EFFECT
    ) {
      priorDecisionTrusted = false;
      state.conflicts.add("prior_decision_appeal_binding_conflict");
    }
  }
  let policyState: PolicyFacts["policy_state"] = "invalid";
  if (policyValid && rulebookValid) {
    policyState = activeAt(
      input.asOf,
      input.policy.payload.effectiveFrom,
      input.policy.payload.effectiveUntil,
    ) ? "active" : "inactive";
    if (
      !sameRef(input.policy.payload.rulebookRef, input.rulebook) ||
      !sameRef(input.policy.payload.trustSnapshotRef, input.trustSnapshot) ||
      input.policy.payload.legalEffect !== LEGAL_EFFECT
    ) {
      policyState = "invalid";
      reject(state, "policy_reference_invalid");
    }
    if (input.policy.payload.issuedAt > input.asOf || input.rulebook.payload.issuedAt > input.asOf) {
      policyState = "invalid";
      reject(state, "policy_or_rulebook_future_dated");
    }
  }

  let mandateTrusted = false;
  if (input.mandate === undefined) {
    addMissing(state, "mandate");
  } else {
    mandateTrusted = verifyArtifact(state, input, {
      artifact: input.mandate,
      artifactType: "mandate_envelope",
      purpose: "mandate_authorization",
      role: "principal",
      actorId: input.mandate.payload.principal.id,
      label: "mandate",
    });
    if (input.mandate.payload.issuedAt > input.asOf) {
      mandateTrusted = false;
      reject(state, "mandate_future_dated", input.mandate, "invalid");
    }
  }

  let receiptTrusted = false;
  if (input.executionReceipt === undefined) {
    addMissing(state, "execution_receipt");
  } else {
    receiptTrusted = verifyArtifact(state, input, {
      artifact: input.executionReceipt,
      artifactType: "execution_receipt",
      purpose: "execution_attestation",
      role: "operator",
      actorId: input.executionReceipt.payload.operator.id,
      label: "execution_receipt",
    });
    if (input.executionReceipt.payload.executedAt > input.asOf) {
      receiptTrusted = false;
      reject(state, "execution_receipt_future_dated", input.executionReceipt, "invalid");
    }
    state.attestations.push({
      artifactRef: refFor(input.executionReceipt),
      attributedTo: input.executionReceipt.payload.operator,
      assertion: `execution:${input.executionReceipt.payload.disposition}`,
      accepted: receiptTrusted,
    });
  }

  let incidentTrusted = false;
  if (input.incidentReport === undefined) {
    addMissing(state, "incident_report");
  } else {
    incidentTrusted = verifyArtifact(state, input, {
      artifact: input.incidentReport,
      artifactType: "incident_report",
      purpose: "incident_filing",
      role: input.incidentReport.payload.reporter.role,
      actorId: input.incidentReport.payload.reporter.id,
      label: "incident_report",
    });
    if (
      input.incidentReport.payload.filedAt > input.asOf ||
      input.incidentReport.payload.discoveredAt > input.asOf
    ) {
      incidentTrusted = false;
      reject(state, "incident_report_future_dated", input.incidentReport, "invalid");
    }
    state.attestations.push({
      artifactRef: refFor(input.incidentReport),
      attributedTo: input.incidentReport.payload.reporter,
      assertion: `incident:${input.incidentReport.payload.allegedBranch}`,
      accepted: incidentTrusted,
    });
  }

  const verifiedEventDigests = new Set<Sha256Digest>();
  for (const event of input.runtimeEvents) {
    const expectedRole: ActorRole = event.payload.eventType === "mandate_revoked"
      ? "principal"
      : event.payload.actor.role;
    let accepted = verifyArtifact(state, input, {
      artifact: event,
      artifactType: "runtime_event",
      purpose: "runtime_observation",
      role: expectedRole,
      actorId: event.payload.actor.id,
      label: "runtime_event",
    });
    if (event.payload.observedAt > input.asOf) {
      accepted = false;
      reject(state, "runtime_event_future_dated", event, "invalid");
    }
    if (input.mandate !== undefined && !runtimeActorBound(event.payload, input.mandate.payload)) {
      accepted = false;
      state.conflicts.add("runtime_actor_binding_conflict");
    }
    if (event.payload.eventType === "mandate_revoked" && input.mandate !== undefined) {
      const semanticallyAccepted =
        accepted &&
        event.payload.actor.role === "principal" &&
        event.payload.actor.id === input.mandate.payload.principal.id &&
        event.payload.effectiveAt !== undefined &&
        event.payload.mandateRef !== undefined &&
        sameRef(event.payload.mandateRef, input.mandate);
      state.attestations.push({
        artifactRef: refFor(event),
        attributedTo: event.payload.actor,
        assertion: "mandate:revoked",
        accepted: semanticallyAccepted,
      });
      if (!semanticallyAccepted) state.conflicts.add("revocation_binding_conflict");
    }
    if (accepted) verifiedEventDigests.add(event.payloadDigest);
  }
  if (input.runtimeEvents.length === 0) addMissing(state, "runtime_events");

  const priors = verifiedPriorReceipts(input, state);
  let mandateState: PolicyFacts["mandate_state"] = input.mandate === undefined
    ? "missing"
    : mandateTrusted ? "valid" : "invalid";
  let receiptState: PolicyFacts["receipt_state"] = input.executionReceipt === undefined
    ? "missing"
    : receiptTrusted ? "trusted" : "untrusted";
  let executionState: PolicyFacts["execution_state"] = input.executionReceipt === undefined
    ? "missing"
    : "noncompliant";
  let controls: PolicyFacts["operator_controls"] = "unknown";
  let violation: PolicyFacts["operator_violation"] = "none";

  if (input.mandate !== undefined && input.executionReceipt !== undefined && receiptTrusted) {
    const mandate = input.mandate;
    const receipt = input.executionReceipt.payload;
    const mandateRefsValid =
      mandateTrusted &&
      sameRef(mandate.payload.policyRef, input.policy) &&
      sameRef(mandate.payload.rulebookRef, input.rulebook) &&
      sameRef(receipt.mandateRef, mandate) &&
      sameRef(receipt.policyRef, input.policy) &&
      receipt.authorizationNonce === mandate.payload.nonce &&
      receipt.operator.id === mandate.payload.operator.id &&
      receipt.operator.role === "operator";
    const authorityBindingsValid =
      mandate.payload.principal.role === "principal" &&
      mandate.payload.principal.id === input.policy.payload.principalId &&
      mandate.payload.operator.role === "operator" &&
      mandate.payload.operator.id === input.policy.payload.operatorId &&
      (mandate.payload.modelVendor === undefined ||
        (mandate.payload.modelVendor.role === "model_vendor" &&
          input.policy.payload.modelVendorIds.includes(mandate.payload.modelVendor.id)));
    if (!authorityBindingsValid) state.conflicts.add("mandate_policy_authority_conflict");
    const intervalValid = mandate.payload.validFrom < mandate.payload.expiresAt;
    const beforeStart = receipt.executedAt < mandate.payload.validFrom;
    const expired = receipt.executedAt >= mandate.payload.expiresAt;
    const revoked = revocationEffective(
      input.runtimeEvents,
      mandate,
      receipt.executedAt,
      verifiedEventDigests,
    );
    const isReplay = replayed(receipt, mandate, input.policy, priors, state);
    const inScope = actionInScope(receipt.action, mandate.payload);
    controls = controlState(
      mandate.payload,
      receipt,
      input.runtimeEvents,
      verifiedEventDigests,
      state,
    );
    if (!mandateRefsValid || !authorityBindingsValid || !intervalValid || beforeStart) {
      mandateState = "invalid";
      violation = "invalid_mandate";
    } else if (expired) {
      mandateState = "expired";
      violation = "expired_mandate";
    } else if (revoked) {
      mandateState = "revoked";
      violation = "revoked_mandate";
    } else if (isReplay) {
      violation = "replayed_execution";
      executionState = "replayed";
    } else if (!inScope) {
      mandateState = "out_of_scope";
      violation = "out_of_scope";
    } else if (controls !== "compliant") {
      violation = "control_failure";
    }
    if (receipt.executedAt > input.asOf) state.conflicts.add("execution_after_as_of");
    if (receipt.disposition === "executed" && receipt.actualEffectDigest === undefined) {
      addMissing(state, "actual_effect_digest");
    }
    verifyRuntimeGraph(input.runtimeEvents, receipt, state);
    if (
      violation === "none" &&
      controls === "compliant" &&
      receipt.disposition === "executed" &&
      receipt.actualEffectDigest !== undefined &&
      state.conflicts.size === 0
    ) {
      executionState = "compliant";
    }
  }

  if (
    incidentTrusted &&
    input.incidentReport !== undefined &&
    (input.executionReceipt === undefined || !sameRef(input.incidentReport.payload.executionReceiptRef, input.executionReceipt))
  ) {
    state.conflicts.add("incident_receipt_reference_conflict");
  }

  const causation = causationState(input, state, receiptTrusted, verifiedEventDigests);
  checkIncidentEvidenceClosure(input, state);
  if (causation.state === "sufficient" && causation.provenance !== "matched") {
    addMissing(state, "matching_model_provenance");
  }
  if (causation.state === "conflicting" || causation.state === "multi_causal") {
    state.conflicts.add("causation_conflict");
  }

  const evidenceState: PolicyFacts["evidence_state"] = state.tampered
    ? "tampered"
    : state.conflicts.size > 0
      ? "contradictory"
      : state.missing.size > 0
        ? "missing"
        : "sufficient";
  const facts: PolicyFacts = {
    input_state: state.hardInvalid ? "invalid" : "valid",
    evidence_state: evidenceState,
    policy_state: policyState,
    trust_state: state.trust === undefined ? "invalid" : "pinned",
    mandate_state: mandateState,
    receipt_state: receiptState,
    execution_state: executionState,
    operator_controls: controls,
    operator_violation: violation,
    model_provenance: causation.provenance,
    causation_state: causation.state,
  };

  let evaluation = guardedPolicyEvaluation(input, state, facts);
  if (forcedReason !== undefined) {
    evaluation = { outcome: "unresolved", reasonCode: forcedReason, trace: [] };
  }
  const disposition = forcedReason === undefined ? dispositionFor(evaluation) : "invalid";
  const allocation = allocationFor(evaluation.outcome, input, causation.vendor);
  const sourceBundle = bundleForInput(input);
  const trustRootKid = input.trustRootJwk === undefined ? undefined : jwkThumbprint(input.trustRootJwk);
  const pins: EngineDecisionPins = {
    ...input.pins,
    bundleRootDigest: sourceBundle.rootDigest,
    ...(trustRootKid === undefined ? {} : { trustRootKid }),
  };
  const verifiedFacts: VerifiedPolicyFact[] = (Object.keys(facts) as PolicyFactName[])
    .sort(compareAscii)
    .map((name) => ({
      name,
      value: facts[name],
      sourceRefs: [...state.verifiedRefs].sort((a, b) => compareAscii(a.digest, b.digest)),
    }));
  const policyConclusion: PolicyConclusion = {
    ...(evaluation.matchedRuleId === undefined ? {} : { ruleId: evaluation.matchedRuleId }),
    reasonCode: evaluation.reasonCode,
    outcome: evaluation.outcome,
    disposition,
  };
  const trace: DecisionTraceEntry[] = [
    traceEntry("pin_validation", state.hardInvalid ? "fail" : "pass", state.hardInvalid ? "pin_or_artifact_invalid" : "pins_verified", []),
    traceEntry("trust_validation", state.trust === undefined ? "fail" : "pass", state.trust === undefined ? "trust_unverified" : "trust_pinned", [safeRef(input.trustSnapshot, "trust_snapshot", "trust")]),
    traceEntry("mandate_evaluation", mandateState === "valid" ? "pass" : "fail", `mandate_${mandateState}`, input.mandate === undefined ? [] : [refFor(input.mandate)]),
    traceEntry("causation_evaluation", causation.state === "sufficient" ? "pass" : "not_applicable", `causation_${causation.state}`, input.causationAttestations.map(refFor)),
    traceEntry("policy_evaluation", evaluation.outcome === "unresolved" ? "fail" : "matched", evaluation.reasonCode, state.verifiedRefs),
  ];
  const reasonCodes = [
    evaluation.reasonCode,
    ...(state.rejected.length > 0 ? ["evidence_rejected"] : []),
    ...(state.missing.size > 0 ? ["evidence_missing"] : []),
    ...(state.conflicts.size > 0 ? ["evidence_conflict"] : []),
  ];
  const appealPolicy = policyValid
    ? {
        reviewerIds: [...input.policy.payload.appeal.reviewerIds],
        maxAppealEvents: input.policy.payload.appeal.maxAppealEvents,
      }
    : { reviewerIds: [], maxAppealEvents: 0 };
  const decisionMaterial = {
    schemaVersion: "1.0.0",
    caseId: input.caseId,
    evaluatedAt: input.asOf,
    evidenceBundleId: sourceBundle.artifactId,
    evidenceBundleDigest: sourceBundle.rootDigest,
    policyRef: safeRef(input.policy, "liability_policy", "policy"),
    rulebookRef: safeRef(input.rulebook, "rulebook", "rulebook"),
    trustSnapshotRef: safeRef(input.trustSnapshot, "trust_snapshot", "trust"),
    engineVersion: ENGINE_VERSION,
    outcome: evaluation.outcome,
    reasonCodes,
    trace,
    missingEvidence: uniqueSorted([...state.missing]),
    conflictingEvidence: uniqueSorted([...state.conflicts]),
    legalEffect: LEGAL_EFFECT,
    disposition,
    policyOutcome: evaluation.outcome,
    appealPolicy,
    ...(allocation === undefined ? {} : { allocation }),
    cryptographicFacts: [...state.cryptographicFacts].sort((a, b) => compareAscii(a.artifactRef.digest, b.artifactRef.digest)),
    verifiedFacts,
    attributedAttestations: [...state.attestations].sort((a, b) => compareAscii(a.artifactRef.digest, b.artifactRef.digest)),
    policyConclusions: [policyConclusion],
    rejectedEvidence: [...state.rejected].sort((a, b) =>
      compareAscii(a.artifactRef?.digest ?? "", b.artifactRef?.digest ?? "") || compareAscii(a.reasonCode, b.reasonCode),
    ),
    deterministicTrace: evaluation.trace,
    pins,
    externalAuthenticity: forcedReason === undefined
      ? "established_by_caller_pins"
      : "unestablished",
    ...(!priorDecisionTrusted || input.priorDecision === undefined
      ? {}
      : { supersedesDecisionId: input.priorDecision.payload.artifactId }),
    ...(input.appealId === undefined ? {} : { appealId: input.appealId }),
  } as const;
  const artifactId = `decision-${sha256Digest(decisionMaterial).slice("sha256:".length)}`;
  return { artifactId, ...decisionMaterial };
}

function safeProtocolIdentifier(value: string): boolean {
  if (value.length === 0 || value.length > 128) return false;
  const first = value[0];
  if (first === undefined || !ASCII_IDENTIFIER_LEAD.includes(first)) {
    return false;
  }
  for (const character of value) if (!ASCII_IDENTIFIER_CHARACTERS.includes(character)) return false;
  return true;
}

function safeProtocolTimestamp(value: string): boolean {
  if (value.length !== 24 || value[23] !== "Z" || value[19] !== ".") return false;
  const parsed = new Date(value);
  return !Number.isNaN(parsed.valueOf()) && parsed.toISOString() === value;
}

function safeInputString(input: unknown, key: "caseId" | "asOf", fallback: string): string {
  try {
    if (isPlainObject(input) && typeof input[key] === "string") {
      const value = input[key];
      if (
        (key === "caseId" && safeProtocolIdentifier(value)) ||
        (key === "asOf" && safeProtocolTimestamp(value))
      ) {
        return value;
      }
    }
  } catch {
    // Hostile accessors are treated as malformed input.
  }
  return fallback;
}

function malformedDecision(input: unknown, reasonCode: string): EngineLiabilityDecision {
  const caseId = safeInputString(input, "caseId", "malformed-case");
  const evaluatedAt = safeInputString(input, "asOf", "1970-01-01T00:00:00.000Z");
  const facts: PolicyFacts = {
    input_state: "invalid",
    evidence_state: "tampered",
    policy_state: "invalid",
    trust_state: "invalid",
    mandate_state: "missing",
    receipt_state: "missing",
    execution_state: "missing",
    operator_controls: "unknown",
    operator_violation: "none",
    model_provenance: "missing",
    causation_state: "missing",
  };
  const pins: EngineDecisionPins = {
    asOf: evaluatedAt,
    policyDigest: EMPTY_DIGEST,
    trustSnapshotDigest: EMPTY_DIGEST,
    rulebookDigest: EMPTY_DIGEST,
    schemaDigests: [EMPTY_DIGEST],
    engineVersion: ENGINE_VERSION,
    bundleRootDigest: EMPTY_DIGEST,
  };
  const conclusion: PolicyConclusion = {
    reasonCode,
    outcome: "unresolved",
    disposition: "invalid",
  };
  const trace = [traceEntry("input_validation", "fail", reasonCode, [])];
  const material = {
    schemaVersion: "1.0.0" as const,
    caseId,
    evaluatedAt,
    evidenceBundleId: "malformed-input",
    evidenceBundleDigest: EMPTY_DIGEST,
    policyRef: { artifactType: "liability_policy" as const, artifactId: "missing-policy", digest: EMPTY_DIGEST },
    rulebookRef: { artifactType: "rulebook" as const, artifactId: "missing-rulebook", digest: EMPTY_DIGEST },
    trustSnapshotRef: { artifactType: "trust_snapshot" as const, artifactId: "missing-trust", digest: EMPTY_DIGEST },
    engineVersion: ENGINE_VERSION,
    outcome: "unresolved" as const,
    reasonCodes: [reasonCode, "evidence_rejected"],
    trace,
    missingEvidence: ["valid_evaluation_case"],
    conflictingEvidence: [],
    legalEffect: LEGAL_EFFECT,
    disposition: "invalid" as const,
    policyOutcome: "unresolved" as const,
    appealPolicy: { reviewerIds: [], maxAppealEvents: 0 },
    cryptographicFacts: [],
    verifiedFacts: (Object.keys(facts) as PolicyFactName[]).sort(compareAscii).map((name) => ({
      name,
      value: facts[name],
      sourceRefs: [],
    })),
    attributedAttestations: [],
    policyConclusions: [conclusion],
    rejectedEvidence: [{ reasonCode }],
    deterministicTrace: [],
    pins,
    externalAuthenticity: "unestablished" as const,
  };
  return {
    artifactId: `decision-${sha256Digest(material).slice("sha256:".length)}`,
    ...material,
  };
}

export function evaluateCase(input: EvaluationCase): EngineLiabilityDecision {
  try {
    return evaluateCaseInternal(input);
  } catch {
    return malformedDecision(input, "ALB_SCHEMA_INVALID");
  }
}

export const evaluateLiability = evaluateCase;
export const evaluate = evaluateCase;

function bundleFailureDecision(bundle: EvidenceBundle, reason: string): EngineLiabilityDecision {
  const pins = bundle.manifest.pins;
  const placeholder = evaluationCaseFromBundle(bundle, { pins });
  return evaluateCaseInternal(placeholder, reason as "ALB_TRUST_ANCHOR_REQUIRED");
}

export function evaluateBundle(
  bundle: EvidenceBundle,
  anchors?: EvaluationAnchors,
): EngineLiabilityDecision {
  try {
    const integrity = verifyEvidenceBundle(bundle);
    if (!integrity.valid) return malformedDecision(bundle, "ALB_BUNDLE_INVALID");
    if (anchors === undefined) {
      return bundleFailureDecision(bundle, "ALB_TRUST_ANCHOR_REQUIRED");
    }
    const anchorsMatch =
      sha256Digest(anchors.pins) === sha256Digest(bundle.manifest.pins) &&
      (anchors.expectedBundleRootDigest === undefined || anchors.expectedBundleRootDigest === bundle.rootDigest);
    const input = evaluationCaseFromBundle(bundle, anchors);
    return evaluateCaseInternal(input, anchorsMatch ? undefined : "ALB_BUNDLE_ANCHOR_MISMATCH");
  } catch {
    return malformedDecision(bundle, "ALB_BUNDLE_INVALID");
  }
}

export function explainDecision(decision: LiabilityDecision): string {
  const extended = decision as Partial<EngineLiabilityDecision>;
  const disposition = extended.disposition ?? (decision.outcome === "unresolved" ? "indeterminate" : "allocated");
  const reason = decision.reasonCodes[0] ?? "unresolved_default";
  const allocation = extended.allocation === undefined
    ? "no party allocated"
    : `${extended.allocation.role} ${extended.allocation.id}`;
  return `Outcome: ${decision.outcome}; disposition: ${disposition}; ${allocation}; reason: ${reason}; legal effect: ${decision.legalEffect}.`;
}

export type { BundleVerificationReport } from "./domain.js";
export { createEvidenceBundle, verifyEvidenceBundle } from "./bundle.js";

// Keep ValidationIssue reachable for consumers that build bounded diagnostics.
export type EngineValidationIssue = ValidationIssue;
