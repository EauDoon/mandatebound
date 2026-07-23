import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { sha256Digest } from "../dist/canonical.js";
import {
  createSignedArtifact,
  exportPublicJwk,
  jwkThumbprint,
} from "../dist/crypto.js";
import {
  computeEventRootDigest,
  createEvidenceBundle,
  evaluateBundle,
  evaluateCase,
} from "../dist/engine.js";
import {
  SCHEMA_IDS,
  schemaDigestForArtifactType,
  validateArtifact,
} from "../dist/validation.js";
import { ENGINE_VERSION } from "../dist/version.js";

const AS_OF = "2026-07-23T00:00:00.000Z";
const BEFORE = "2026-01-01T00:00:00.000Z";
const ONE_MS_BEFORE = "2026-07-22T23:59:59.999Z";
const ONE_MS_AFTER = "2026-07-23T00:00:00.001Z";
const AFTER = "2027-01-01T00:00:00.000Z";

const principal = { id: "principal-boundary", role: "principal" };
const operator = { id: "operator-boundary", role: "operator" };
const agent = { id: "agent-boundary", role: "agent" };
const vendor = { id: "vendor-boundary", role: "model_vendor" };
const attestor = { id: "attestor-boundary", role: "causation_attestor" };
const trustPublisher = { id: "trust-publisher-boundary", role: "trust_publisher" };

function privateKey() {
  return generateKeyPairSync("ed25519").privateKey;
}

function reference(artifact) {
  return {
    artifactType: artifact.artifactType,
    artifactId: artifact.payload.artifactId,
    digest: artifact.payloadDigest,
  };
}

function trustKey(key, roles, purposes, scopes = []) {
  const publicKey = exportPublicJwk(key);
  return {
    kid: jwkThumbprint(publicKey),
    publicKey,
    roles,
    purposes,
    validFrom: "2025-01-01T00:00:00.000Z",
    validUntil: "2030-01-01T00:00:00.000Z",
    scopes,
  };
}

export function buildCase(options = {}) {
  const keys = {
    principal: privateKey(),
    operator: privateKey(),
    attestor: privateKey(),
    rulebook: privateKey(),
    root: privateKey(),
  };
  const sign = (payload, key, artifactType, purpose, signedAt = AS_OF, schemaType = artifactType) =>
    createSignedArtifact(payload, key, {
      artifactType,
      purpose,
      schemaId: SCHEMA_IDS[artifactType],
      schemaDigest: schemaDigestForArtifactType(schemaType),
      signedAt,
    });

  const rulebookPayload = JSON.parse(readFileSync(
    new URL("../rulebooks/v1/mandate-to-liability.v1.json", import.meta.url),
    "utf8",
  ));
  if (options.futureRulebook) rulebookPayload.issuedAt = ONE_MS_AFTER;
  const rulebook = sign(rulebookPayload, keys.rulebook, "rulebook", "rulebook_issuance");

  const trustPayload = {
    schemaVersion: "1.0.0",
    artifactId: "trust-boundary-v1",
    revision: 1,
    issuedAt: options.futureTrust ? ONE_MS_AFTER : BEFORE,
    asOf: options.futureTrust ? ONE_MS_AFTER : AS_OF,
    issuer: trustPublisher,
    keys: [
      trustKey(keys.principal, ["principal"], [
        "mandate_authorization",
        "incident_filing",
        "policy_acceptance",
        "runtime_observation",
      ], [principal.id, "principal-other"]),
      trustKey(
        keys.operator,
        ["operator"],
        ["runtime_observation", "execution_attestation"],
        [operator.id, "operator-other", "operator-cross-case"],
      ),
      trustKey(keys.attestor, ["causation_attestor"], ["causation_attestation"], [attestor.id]),
      trustKey(keys.rulebook, ["rulebook_publisher"], ["rulebook_issuance"]),
    ],
  };
  const trustSnapshot = sign(
    trustPayload,
    keys.root,
    "trust_snapshot",
    "trust_snapshot_issuance",
    options.futureRootProof ? ONE_MS_AFTER : AS_OF,
  );
  const policyPayload = {
    schemaVersion: "1.0.0",
    artifactId: "policy-boundary-v1",
    revision: 1,
    issuedAt: options.futurePolicy ? ONE_MS_AFTER : BEFORE,
    effectiveFrom: BEFORE,
    effectiveUntil: AFTER,
    attributionProfile: "mandate-to-liability-v1",
    principalId: principal.id,
    operatorId: operator.id,
    modelVendorIds: [vendor.id],
    rulebookRef: reference(rulebook),
    trustSnapshotRef: reference(trustSnapshot),
    causation: {
      requiredForVendorOutcome: true,
      independentAttestorRequired: true,
      allowedMethods: ["controlled_reproduction"],
      acceptedAttestorRoles: ["causation_attestor"],
    },
    appeal: { reviewerIds: ["reviewer-boundary"], maxAppealEvents: 8 },
    legalEffect: "not-determined",
  };
  const policy = sign(policyPayload, keys.principal, "liability_policy", "policy_acceptance");

  const mandatePrincipal = options.crossPrincipal
    ? { id: "principal-other", role: "principal" }
    : principal;
  const mandateOperator = options.crossOperator
    ? { id: "operator-other", role: "operator" }
    : operator;
  const mandateVendor = options.unlistedVendor
    ? { id: "vendor-other", role: "model_vendor" }
    : vendor;
  const mandatePayload = {
    schemaVersion: "1.0.0",
    artifactId: "mandate-boundary-1",
    revision: 1,
    issuedAt: BEFORE,
    validFrom: options.validFrom ?? BEFORE,
    expiresAt: options.expiresAt ?? AFTER,
    nonce: "nonce-boundary-1",
    principal: mandatePrincipal,
    operator: mandateOperator,
    agent,
    modelVendor: mandateVendor,
    policyRef: reference(policy),
    rulebookRef: reference(rulebook),
    scope: {
      actions: [{
        kind: "purchase",
        targets: ["merchant.boundary"],
        counterparties: ["supplier.boundary"],
        asset: "USD",
        maxMinorUnits: options.maxMinorUnits ?? "100",
      }],
      maxExecutions: 1,
      delegation: { allowed: false, maxDepth: 0, delegates: [] },
    },
    requiredControls: ["mandate-valid", "policy-valid"],
  };
  const mandate = sign(
    mandatePayload,
    keys.principal,
    "mandate_envelope",
    "mandate_authorization",
    AS_OF,
    options.schemaSubstitution ? "runtime_event" : "mandate_envelope",
  );

  const executedAt = options.executedAt ?? AS_OF;
  const action = {
    kind: "purchase",
    target: options.outOfScope ? "merchant.other" : "merchant.boundary",
    parametersDigest: sha256Digest({ sku: "boundary-item" }),
    counterparty: "supplier.boundary",
    quantity: { asset: "USD", minorUnits: options.amount ?? "100" },
  };
  const actionDigest = sha256Digest(action);
  const eventPayloads = [];
  let sequence = 1;
  if (options.revokedAt !== undefined) {
    eventPayloads.push({
      schemaVersion: "1.0.0",
      artifactId: "event-revocation",
      executionId: "execution-boundary-1",
      sequence: sequence++,
      eventType: "mandate_revoked",
      actor: mandatePrincipal,
      observedAt: executedAt,
      effectiveAt: options.revokedAt,
      mandateRef: reference(mandate),
      actionDigest,
      parentEventIds: [],
    });
  }
  const runtimeOperator = options.crossRuntimeActor
    ? { id: "operator-cross-case", role: "operator" }
    : mandateOperator;
  const mandateEventId = "event-mandate-check";
  const policyEventId = "event-policy-check";
  eventPayloads.push({
    schemaVersion: "1.0.0",
    artifactId: mandateEventId,
    executionId: "execution-boundary-1",
    sequence: sequence++,
    eventType: "mandate_checked",
    actor: runtimeOperator,
    observedAt: executedAt,
    actionDigest,
    parentEventIds: [],
    controlId: "mandate-valid",
    controlResult: options.controlFailure ? "fail" : "pass",
  });
  eventPayloads.push({
    schemaVersion: "1.0.0",
    artifactId: policyEventId,
    executionId: "execution-boundary-1",
    sequence: sequence++,
    eventType: "policy_checked",
    actor: runtimeOperator,
    observedAt: executedAt,
    actionDigest,
    parentEventIds: [mandateEventId],
    controlId: "policy-valid",
    controlResult: "pass",
  });
  if (options.extraControlFailure) {
    eventPayloads.push({
      schemaVersion: "1.0.0",
      artifactId: "event-control-failure-hidden-by-receipt",
      executionId: "execution-boundary-1",
      sequence: sequence++,
      eventType: "policy_checked",
      actor: runtimeOperator,
      observedAt: executedAt,
      actionDigest,
      parentEventIds: [policyEventId],
      controlId: "mandate-valid",
      controlResult: "fail",
    });
  }
  let modelEventId;
  if (options.vendorCausation) {
    modelEventId = "event-model-invoked";
    eventPayloads.push({
      schemaVersion: "1.0.0",
      artifactId: modelEventId,
      executionId: "execution-boundary-1",
      sequence: sequence++,
      eventType: "model_invoked",
      actor: runtimeOperator,
      observedAt: executedAt,
      actionDigest,
      parentEventIds: [policyEventId],
      contentDigest: sha256Digest({ model: "boundary-v1" }),
    });
  }
  const completedParent = modelEventId ?? policyEventId;
  eventPayloads.push({
    schemaVersion: "1.0.0",
    artifactId: "event-execution-completed",
    executionId: "execution-boundary-1",
    sequence: sequence++,
    eventType: "execution_completed",
    actor: runtimeOperator,
    observedAt: executedAt,
    actionDigest,
    parentEventIds: [completedParent],
  });
  const runtimeEvents = eventPayloads.map((payload) => sign(
    payload,
    payload.eventType === "mandate_revoked" ? keys.principal : keys.operator,
    "runtime_event",
    "runtime_observation",
  ));
  const modelDigest = sha256Digest({ model: "boundary-v1" });
  const receiptPayload = {
    schemaVersion: "1.0.0",
    artifactId: "receipt-boundary-1",
    executionId: "execution-boundary-1",
    mandateRef: reference(mandate),
    policyRef: reference(policy),
    authorizationNonce: mandate.payload.nonce,
    idempotencyKey: "idempotency-boundary-1",
    operator: mandateOperator,
    action,
    modelDigest,
    toolManifestDigest: sha256Digest({ tools: ["purchase"] }),
    deploymentDigest: sha256Digest({ deployment: "boundary" }),
    disposition: "executed",
    executedAt,
    controlResults: [
      {
        controlId: "mandate-valid",
        result: options.controlFailure ? "fail" : "pass",
        eventId: mandateEventId,
      },
      { controlId: "policy-valid", result: "pass", eventId: policyEventId },
    ],
    eventRootDigest: computeEventRootDigest(runtimeEvents),
    actualEffectDigest: sha256Digest({ effect: "loss" }),
  };
  const executionReceipt = sign(
    receiptPayload,
    keys.operator,
    "execution_receipt",
    "execution_attestation",
  );
  const priorReceipts = [];
  if (options.crossOperatorPriorReceipt) {
    priorReceipts.push(sign(
      {
        ...receiptPayload,
        artifactId: "receipt-unrelated-operator",
        executionId: "execution-unrelated-operator",
        idempotencyKey: "idempotency-unrelated-operator",
        operator: { id: "operator-other", role: "operator" },
        executedAt: BEFORE,
      },
      keys.operator,
      "execution_receipt",
      "execution_attestation",
    ));
  }
  const evidenceRefs = runtimeEvents.map(reference);
  if (options.incidentMissingRef) {
    evidenceRefs.push({
      artifactType: "runtime_event",
      artifactId: "event-absent",
      digest: `sha256:${"a".repeat(64)}`,
    });
  }
  if (options.incidentDigestConflict) {
    evidenceRefs[0] = { ...evidenceRefs[0], digest: `sha256:${"b".repeat(64)}` };
  }
  const incidentPayload = {
    schemaVersion: "1.0.0",
    artifactId: "incident-boundary-1",
    executionReceiptRef: reference(executionReceipt),
    reporter: principal,
    filedAt: AS_OF,
    discoveredAt: executedAt,
    allegedBranch: options.vendorCausation ? "model_vendor" : "principal",
    harmCodes: ["economic-loss"],
    summaryDigest: sha256Digest({ summary: "boundary" }),
    evidenceRefs,
  };
  const incidentReport = sign(
    incidentPayload,
    keys.principal,
    "incident_report",
    "incident_filing",
  );
  const causationAttestations = [];
  if (options.vendorCausation) {
    const baseAttestation = {
      schemaVersion: "1.0.0",
      artifactId: "causation-boundary-1",
      incidentRef: reference(incidentReport),
      subject: mandateVendor,
      modelDigest,
      attestor,
      method: "controlled_reproduction",
      conclusion: "sufficient",
      failureCode: "model-failure",
      causalEventIds: [modelEventId],
      reproductionDigest: sha256Digest({ reproduction: "boundary" }),
      competingCauseIds: options.competingCause ? ["operator-cause"] : [],
      issuedAt: AS_OF,
    };
    causationAttestations.push(sign(
      baseAttestation,
      keys.attestor,
      "causation_attestation",
      "causation_attestation",
    ));
    if (options.multiCausal) {
      causationAttestations.push(sign(
        { ...baseAttestation, artifactId: "causation-boundary-2", failureCode: "other-failure" },
        keys.attestor,
        "causation_attestation",
        "causation_attestation",
      ));
    }
    if (options.mixedCausationConclusion) {
      causationAttestations.push(sign(
        { ...baseAttestation, artifactId: "causation-boundary-insufficient", conclusion: "insufficient" },
        keys.attestor,
        "causation_attestation",
        "causation_attestation",
      ));
    }
  }
  const schemaDigests = [
    "mandate_envelope",
    "runtime_event",
    "execution_receipt",
    "incident_report",
    "causation_attestation",
    "liability_policy",
    "rulebook",
    "trust_snapshot",
  ].map(schemaDigestForArtifactType).sort();
  return {
    caseId: "case-boundary",
    asOf: AS_OF,
    pins: {
      asOf: AS_OF,
      policyDigest: policy.payloadDigest,
      trustSnapshotDigest: trustSnapshot.payloadDigest,
      rulebookDigest: rulebook.payloadDigest,
      schemaDigests,
      engineVersion: ENGINE_VERSION,
    },
    trustRootJwk: exportPublicJwk(keys.root),
    mandate,
    runtimeEvents,
    priorReceipts,
    executionReceipt,
    incidentReport,
    causationAttestations,
    policy,
    rulebook,
    trustSnapshot,
  };
}

function fact(decision, name) {
  return decision.verifiedFacts.find((candidate) => candidate.name === name)?.value;
}

test("validity intervals are start-inclusive and expiry-exclusive", () => {
  const atStart = evaluateCase(buildCase({ validFrom: AS_OF, expiresAt: ONE_MS_AFTER }));
  assert.equal(atStart.outcome, "principal");

  const atExpiry = evaluateCase(buildCase({ validFrom: BEFORE, expiresAt: AS_OF }));
  assert.equal(atExpiry.outcome, "operator");
  assert.equal(fact(atExpiry, "operator_violation"), "expired_mandate");

  const beforeStart = evaluateCase(buildCase({ validFrom: ONE_MS_AFTER, expiresAt: AFTER }));
  assert.equal(beforeStart.outcome, "operator");
  assert.equal(fact(beforeStart, "operator_violation"), "invalid_mandate");
});

test("minor-unit scope limit is inclusive and uses integer arithmetic", () => {
  assert.equal(evaluateCase(buildCase({ amount: "100", maxMinorUnits: "100" })).outcome, "principal");
  const over = evaluateCase(buildCase({ amount: "101", maxMinorUnits: "100" }));
  assert.equal(over.outcome, "operator");
  assert.equal(fact(over, "operator_violation"), "out_of_scope");
});

test("revocation is effective at its exact instant and not before", () => {
  const exact = evaluateCase(buildCase({ revokedAt: AS_OF }));
  assert.equal(exact.outcome, "operator");
  assert.equal(fact(exact, "operator_violation"), "revoked_mandate");
  assert.equal(evaluateCase(buildCase({ revokedAt: ONE_MS_AFTER })).outcome, "principal");
});

test("trusted failed controls allocate to the operator", () => {
  const decision = evaluateCase(buildCase({ controlFailure: true }));
  assert.equal(decision.outcome, "operator");
  assert.equal(fact(decision, "operator_violation"), "control_failure");
});

test("operator breach takes precedence over otherwise sufficient vendor causation", () => {
  const decision = evaluateCase(buildCase({ outOfScope: true, vendorCausation: true }));
  assert.equal(decision.outcome, "operator");
  assert.equal(fact(decision, "model_provenance"), "matched");
});

test("conflicting and multi-causal attestations remain unresolved", () => {
  for (const options of [
    { vendorCausation: true, competingCause: true },
    { vendorCausation: true, multiCausal: true },
    { vendorCausation: true, mixedCausationConclusion: true },
  ]) {
    const decision = evaluateCase(buildCase(options));
    assert.equal(decision.outcome, "unresolved");
    assert.equal(decision.disposition, "conflicted");
    assert.ok(decision.conflictingEvidence.includes("causation_conflict"));
  }
});

test("a supplied bundle must contain the exact normalized evaluation case", () => {
  const input = buildCase();
  const bundle = createEvidenceBundle(input);
  const rebound = evaluateCase({ ...input, caseId: "case-rebound", evidenceBundle: bundle });
  assert.equal(rebound.outcome, "unresolved");
  assert.equal(rebound.disposition, "invalid");
  assert.ok(rebound.rejectedEvidence.some(
    (item) => item.reasonCode === "evidence_bundle_case_mismatch",
  ));

  const replay = evaluateBundle(bundle, {
    pins: input.pins,
    trustRootJwk: input.trustRootJwk,
    expectedBundleRootDigest: bundle.rootDigest,
  });
  assert.equal(replay.caseId, input.caseId);
  assert.notEqual(rebound.artifactId, replay.artifactId);
});

test("unrelated operator receipts cannot consume mandate usage", () => {
  const decision = evaluateCase(buildCase({ crossOperatorPriorReceipt: true }));
  assert.equal(decision.outcome, "unresolved");
  assert.equal(decision.disposition, "conflicted");
  assert.ok(decision.conflictingEvidence.includes("prior_receipt_binding_conflict"));
  assert.notEqual(fact(decision, "operator_violation"), "replayed_execution");
});

test("all signed required-control results are reconciled", () => {
  const decision = evaluateCase(buildCase({ extraControlFailure: true }));
  assert.equal(decision.outcome, "unresolved");
  assert.equal(decision.disposition, "conflicted");
  assert.equal(fact(decision, "operator_controls"), "noncompliant");
  assert.ok(decision.conflictingEvidence.includes("control_event_contradiction"));
});

test("cross-principal, cross-operator, unlisted-vendor, and runtime actor substitution fail closed", () => {
  for (const options of [
    { crossPrincipal: true },
    { crossOperator: true },
    { unlistedVendor: true },
    { crossRuntimeActor: true },
  ]) {
    const decision = evaluateCase(buildCase(options));
    assert.equal(decision.outcome, "unresolved");
    assert.notEqual(decision.disposition, "allocated");
  }
});

test("incident evidence closure distinguishes absent from contradictory refs", () => {
  const absent = evaluateCase(buildCase({ incidentMissingRef: true }));
  assert.equal(absent.outcome, "unresolved");
  assert.equal(absent.disposition, "indeterminate");
  assert.ok(absent.missingEvidence.some((code) => code.includes("event-absent")));

  const conflict = evaluateCase(buildCase({ incidentDigestConflict: true }));
  assert.equal(conflict.outcome, "unresolved");
  assert.equal(conflict.disposition, "conflicted");
});

test("cross-type pinned schema substitution is invalid even when both digests are pinned", () => {
  const decision = evaluateCase(buildCase({ schemaSubstitution: true }));
  assert.equal(decision.outcome, "unresolved");
  assert.equal(decision.disposition, "invalid");
  assert.ok(decision.rejectedEvidence.some((item) => item.reasonCode === "mandate_schema_unpinned"));
});

test("temporal pins reject future snapshots, root proofs, policies, and rulebooks", () => {
  for (const options of [
    { futureTrust: true },
    { futureRootProof: true },
    { futurePolicy: true },
    { futureRulebook: true },
  ]) {
    const decision = evaluateCase(buildCase(options));
    assert.equal(decision.outcome, "unresolved");
    assert.equal(decision.disposition, "invalid");
    assert.equal(validateArtifact("liability_decision", decision).ok, true);
  }
});

test("digest-pin-only mode remains deterministic while root mode adds publisher authentication", () => {
  const rootedInput = buildCase();
  const rooted = evaluateCase(rootedInput);
  const { trustRootJwk: _root, ...digestOnlyInput } = rootedInput;
  const digestOnly = evaluateCase(digestOnlyInput);
  assert.equal(rooted.outcome, "principal");
  assert.equal(digestOnly.outcome, "principal");
  assert.ok(rooted.cryptographicFacts.every((item) => item.trustBasis === "pinned_root_and_digest"));
  assert.ok(digestOnly.cryptographicFacts.every((item) => item.trustBasis === "caller_digest_pin"));
  assert.notEqual(rooted.artifactId, digestOnly.artifactId);
});
