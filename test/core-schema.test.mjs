import assert from "node:assert/strict";
import test from "node:test";
import {
  SCHEMA_IDS,
  createSchemaRegistry,
  deriveLiabilityDecisionId,
  parseAndValidateArtifact,
  schemaKeyForArtifactType,
  validateArtifact,
  validateSignedArtifact,
} from "../dist/validation.js";

const digest = `sha256:${"0".repeat(64)}`;
const ref = (artifactType, artifactId) => ({ artifactType, artifactId, digest });

function mandate() {
  return {
    schemaVersion: "1.0.0",
    artifactId: "mandate-1",
    revision: 1,
    issuedAt: "2026-01-01T00:00:00.000Z",
    validFrom: "2026-01-01T00:00:00.000Z",
    expiresAt: "2026-01-02T00:00:00.000Z",
    nonce: "nonce-1",
    principal: { id: "principal-1", role: "principal" },
    operator: { id: "operator-1", role: "operator" },
    agent: { id: "agent-1", role: "agent" },
    policyRef: ref("liability_policy", "policy-1"),
    rulebookRef: ref("rulebook", "rules-1"),
    scope: {
      actions: [{ kind: "transfer", targets: ["rail-1"], asset: "USD", maxMinorUnits: "10000" }],
      maxExecutions: 1,
      delegation: { allowed: false, maxDepth: 0, delegates: [] },
    },
    requiredControls: ["mandate-valid", "scope-compliant", "replay-protected"],
  };
}

function decision(overrides = {}) {
  const pins = {
    asOf: "2026-01-01T00:00:00.000Z",
    policyDigest: digest,
    trustSnapshotDigest: digest,
    rulebookDigest: digest,
    schemaDigests: [digest],
    engineVersion: "1.0.0",
    bundleRootDigest: digest,
  };
  const material = {
    schemaVersion: "1.0.0",
    caseId: "case-1",
    evaluatedAt: pins.asOf,
    evidenceBundleId: "bundle-1",
    evidenceBundleDigest: digest,
    policyRef: ref("liability_policy", "policy-1"),
    rulebookRef: ref("rulebook", "rulebook-1"),
    trustSnapshotRef: ref("trust_snapshot", "trust-1"),
    engineVersion: pins.engineVersion,
    outcome: "unresolved",
    disposition: "indeterminate",
    policyOutcome: "unresolved",
    appealPolicy: { reviewerIds: ["reviewer-1"], maxAppealEvents: 10 },
    reasonCodes: ["unresolved-default"],
    trace: [],
    missingEvidence: [],
    conflictingEvidence: [],
    cryptographicFacts: [],
    verifiedFacts: [],
    attributedAttestations: [],
    policyConclusions: [{
      reasonCode: "unresolved-default",
      outcome: "unresolved",
      disposition: "indeterminate",
    }],
    rejectedEvidence: [],
    deterministicTrace: [],
    pins,
    externalAuthenticity: "established_by_caller_pins",
    legalEffect: "not-determined",
    ...overrides,
  };
  return { artifactId: deriveLiabilityDecisionId(material), ...material };
}

test("all normative Draft 2020-12 schemas compile", () => {
  const registry = createSchemaRegistry();
  for (const key of Object.keys(SCHEMA_IDS)) {
    assert.match(registry.schemaDigest(key), /^sha256:[a-f0-9]{64}$/);
  }
});

test("mandate schema accepts a closed valid artifact", () => {
  const result = validateArtifact("mandate_envelope", mandate());
  assert.equal(result.ok, true, JSON.stringify(result.issues));
});

test("schema validation rejects unknown fields and semantic role confusion", () => {
  const extra = { ...mandate(), privatePrompt: "must not be accepted" };
  const extraResult = validateArtifact("mandate_envelope", extra);
  assert.equal(extraResult.ok, false);
  assert(extraResult.issues.some((entry) => entry.code === "ALB_SCHEMA_INVALID"));

  const confused = mandate();
  confused.operator = { id: "operator-1", role: "principal" };
  const roleResult = validateArtifact("mandate_envelope", confused);
  assert.equal(roleResult.ok, false);
  assert(roleResult.issues.some((entry) => entry.path === "/operator/role"));
});

test("parse-and-validate preserves duplicate-key failures without reflecting bodies", () => {
  const result = parseAndValidateArtifact("mandate_envelope", '{"schemaVersion":"1.0.0","schemaVersion":"1.0.0"}');
  assert.equal(result.ok, false);
  assert.equal(result.issues[0].code, "ALB_JSON_DUPLICATE_KEY");
  assert.equal(result.issues[0].message.includes("schemaVersion"), false);
  assert.match(result.issues[0].message, /offset \d+/);
});

test("appeal chain starts at one and links every later event", () => {
  const genesis = {
    schemaVersion: "1.0.0",
    artifactId: "appeal-event-1",
    appealId: "appeal-1",
    decisionId: "decision-1",
    sequence: 1,
    eventType: "filed",
    actor: { id: "principal-1", role: "principal" },
    occurredAt: "2026-01-01T00:00:00.000Z",
    reasonCodes: ["request-review"],
  };
  assert.equal(validateArtifact("appeal_event", genesis).ok, true);
  assert.equal(validateArtifact("appeal_event", { ...genesis, sequence: 0 }).ok, false);
  assert.equal(validateArtifact("appeal_event", { ...genesis, sequence: 2 }).ok, false);
  assert.equal(validateArtifact("appeal_event", {
    ...genesis,
    artifactId: "appeal-event-2",
    sequence: 2,
    previousEventDigest: digest,
  }).ok, true);
});

test("registry APIs fail closed for unsupported values and schema confusion", () => {
  const registry = createSchemaRegistry();
  assert.equal(registry.validate("not_registered", {}).issues[0].code, "ALB_SCHEMA_UNKNOWN");
  assert.throws(() => registry.schemaDigest("not_registered"), TypeError);
  assert.throws(() => schemaKeyForArtifactType("common"), TypeError);
  assert.equal(registry.validate("mandate_envelope", new Date()).issues[0].code, "ALB_CANONICAL_UNSUPPORTED");
  assert.equal(
    parseAndValidateArtifact("mandate_envelope", "{}", { maxBytes: 0 }).issues[0].code,
    "ALB_JSON_INVALID",
  );

  const wrapper = {
    format: "agent-liability-signed-artifact/v1",
    artifactType: "mandate_envelope",
    schemaId: SCHEMA_IDS.mandate_envelope,
    payload: mandate(),
    payloadDigest: digest,
    proofs: [{ protected: "A", signature: "A".repeat(86) }],
  };
  assert.equal(validateSignedArtifact(wrapper).ok, true);
  assert.equal(validateSignedArtifact({ ...wrapper, schemaId: SCHEMA_IDS.rulebook }).ok, false);
  assert.equal(validateSignedArtifact({ ...wrapper, payload: {} }).ok, false);
});

test("v1 evidence bundles are unsigned containers with signed inner artifacts", () => {
  const pins = {
    asOf: "2026-01-01T00:00:00.000Z",
    policyDigest: digest,
    trustSnapshotDigest: digest,
    rulebookDigest: digest,
    schemaDigests: [digest],
    engineVersion: "1.0.0",
  };
  const bundle = {
    schemaVersion: "1.0.0",
    artifactId: "bundle-unsigned-container",
    bundleId: `urn:agent-liability:bundle:${"0".repeat(64)}`,
    rootDigest: digest,
    manifest: {
      format: "agent-liability-bundle-manifest/v1",
      evidenceCutoff: pins.asOf,
      pins,
      entries: [{
        path: "case.json",
        mediaType: "application/json",
        size: 2,
        classification: "internal",
        digest,
      }],
      manifestDigest: digest,
      merkleRoot: digest,
    },
    objects: [{ path: "case.json", encoding: "jcs-json", content: {} }],
    proofs: [],
  };
  assert.equal(validateArtifact("evidence_bundle", bundle).ok, true);
  assert.equal(validateArtifact("evidence_bundle", {
    ...bundle,
    proofs: [{ protected: "A", signature: "A".repeat(86) }],
  }).ok, false);
  const duplicateEntry = bundle.manifest.entries[0];
  const duplicateObject = bundle.objects[0];
  assert.equal(validateArtifact("evidence_bundle", {
    ...bundle,
    manifest: { ...bundle.manifest, entries: [duplicateEntry, duplicateEntry] },
    objects: [duplicateObject, duplicateObject],
  }).ok, false);
  assert.equal(validateArtifact("evidence_bundle", {
    ...bundle,
    objects: [{ ...duplicateObject, path: "other.json" }],
  }).ok, false);
});

test("liability decisions bind allocation, pins, references, and content identity", () => {
  const unresolved = decision();
  assert.equal(validateArtifact("liability_decision", unresolved).ok, true);

  const principal = decision({
    outcome: "principal",
    policyOutcome: "principal",
    disposition: "allocated",
    allocation: { id: "principal-1", role: "principal" },
    policyConclusions: [{
      reasonCode: "principal-authorized",
      outcome: "principal",
      disposition: "allocated",
    }],
  });
  assert.equal(validateArtifact("liability_decision", principal).ok, true);

  assert.equal(validateArtifact("liability_decision", decision({ policyOutcome: "operator" })).ok, false);
  assert.equal(validateArtifact("liability_decision", decision({ disposition: "allocated" })).ok, false);
  assert.equal(validateArtifact("liability_decision", decision({
    allocation: { id: "principal-1", role: "principal" },
  })).ok, false);
  assert.equal(validateArtifact("liability_decision", decision({
    outcome: "principal",
    policyOutcome: "principal",
    disposition: "allocated",
    allocation: { id: "operator-1", role: "operator" },
  })).ok, false);
  assert.equal(validateArtifact("liability_decision", decision({
    outcome: "principal",
    policyOutcome: "principal",
    disposition: "indeterminate",
  })).ok, false);
  assert.equal(validateArtifact("liability_decision", decision({
    evaluatedAt: "2026-01-01T00:00:01.000Z",
  })).ok, false);
  assert.equal(validateArtifact("liability_decision", decision({
    engineVersion: "9.9.9",
  })).ok, false);
  assert.equal(validateArtifact("liability_decision", decision({
    policyRef: { ...ref("liability_policy", "policy-1"), digest: `sha256:${"1".repeat(64)}` },
  })).ok, false);
  assert.equal(validateArtifact("liability_decision", decision({
    policyRef: ref("runtime_event", "policy-1"),
  })).ok, false);
  assert.equal(validateArtifact("liability_decision", decision({
    evidenceBundleDigest: `sha256:${"1".repeat(64)}`,
  })).ok, false);

  const edited = { ...unresolved, reasonCodes: ["silently-edited"] };
  assert.equal(validateArtifact("liability_decision", edited).ok, false);
  assert.equal(validateArtifact("liability_decision", { ...unresolved, artifactId: "decision-forged" }).ok, false);
});

test("semantic validation rejects role, interval, rule, trust, and bundle ambiguities", () => {
  const runtime = {
    schemaVersion: "1.0.0", artifactId: "event-1", executionId: "exec-1", sequence: 0,
    eventType: "mandate_revoked", actor: { id: "operator-1", role: "operator" },
    observedAt: "2026-01-01T00:00:00.000Z", effectiveAt: "2026-01-01T00:00:00.000Z",
    mandateRef: ref("mandate_envelope", "mandate-1"), actionDigest: digest, parentEventIds: [],
  };
  assert.equal(validateArtifact("runtime_event", runtime).ok, false);

  const receipt = {
    schemaVersion: "1.0.0", artifactId: "receipt-1", executionId: "exec-1",
    mandateRef: ref("mandate_envelope", "mandate-1"), policyRef: ref("liability_policy", "policy-1"),
    authorizationNonce: "nonce-1", idempotencyKey: "idem-1",
    operator: { id: "operator-1", role: "principal" },
    action: { kind: "transfer", target: "rail-1", parametersDigest: digest },
    toolManifestDigest: digest, deploymentDigest: digest, disposition: "executed",
    executedAt: "2026-01-01T00:00:00.000Z",
    controlResults: [{ controlId: "scope-compliant", result: "pass", eventId: "event-1" }],
    eventRootDigest: digest,
  };
  assert.equal(validateArtifact("execution_receipt", receipt).ok, false);

  const causation = {
    schemaVersion: "1.0.0", artifactId: "cause-1", incidentRef: ref("incident_report", "incident-1"),
    subject: { id: "same-party", role: "operator" }, modelDigest: digest,
    attestor: { id: "same-party", role: "operator" }, method: "signed_provider_admission",
    conclusion: "sufficient", failureCode: "model-defect", causalEventIds: ["event-1"],
    competingCauseIds: [], issuedAt: "2026-01-01T00:00:00.000Z",
  };
  assert.equal(validateArtifact("causation_attestation", causation).ok, false);

  const policy = {
    schemaVersion: "1.0.0", artifactId: "policy-1", revision: 1,
    issuedAt: "2026-01-02T00:00:00.000Z", effectiveFrom: "2026-01-02T00:00:00.000Z",
    effectiveUntil: "2026-01-01T00:00:00.000Z", attributionProfile: "mandate-to-liability-v1",
    principalId: "principal-1", operatorId: "operator-1", modelVendorIds: ["vendor-1"],
    rulebookRef: ref("rulebook", "rules-1"), trustSnapshotRef: ref("trust_snapshot", "trust-1"),
    causation: { requiredForVendorOutcome: true, independentAttestorRequired: true, allowedMethods: ["controlled_reproduction"], acceptedAttestorRoles: ["causation_attestor"] },
    appeal: { reviewerIds: ["reviewer-1"], maxAppealEvents: 10 }, legalEffect: "not-determined",
  };
  assert.equal(validateArtifact("liability_policy", policy).ok, false);

  const trustKey = {
    kid: `urn:agent-liability:jwk:${"A".repeat(43)}`,
    publicKey: { kty: "OKP", crv: "Ed25519", x: "A".repeat(43) },
    roles: ["operator"], purposes: ["execution_attestation"],
    validFrom: "2025-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z", scopes: [],
  };
  const trust = {
    schemaVersion: "1.0.0", artifactId: "trust-1", revision: 1,
    issuedAt: "2026-01-01T00:00:00.000Z", asOf: "2026-01-01T00:00:00.000Z",
    issuer: { id: "root-1", role: "trust_publisher" }, keys: [trustKey, trustKey],
  };
  assert.equal(validateArtifact("trust_snapshot", trust).ok, false);
  assert.equal(validateArtifact("trust_snapshot", {
    ...trust,
    artifactId: "trust-wildcard-scope",
    keys: [{ ...trustKey, scopes: ["*"] }],
  }).ok, false);

  const rule = { id: "rule-1", priority: 1, when: { op: "eq", fact: "mandate_state", value: "valid" }, outcome: "principal", reasonCode: "authorized" };
  const rulebook = {
    schemaVersion: "1.0.0", artifactId: "rules-1", revision: 1,
    semanticsVersion: "mandate-to-liability-v1", issuedAt: "2026-01-01T00:00:00.000Z",
    rules: [rule, { ...rule, id: "rule-2" }], defaultOutcome: "unresolved",
  };
  assert.equal(validateArtifact("rulebook", rulebook).ok, false);

  const pins = { asOf: "2026-01-01T00:00:00.000Z", policyDigest: digest, trustSnapshotDigest: digest, rulebookDigest: digest, schemaDigests: [digest], engineVersion: "1.0.0" };
  const entry = (path) => ({ path, mediaType: "application/json", size: 2, classification: "public", digest });
  const bundle = {
    schemaVersion: "1.0.0", artifactId: "bundle-1", bundleId: `urn:agent-liability:bundle:${"0".repeat(64)}`,
    rootDigest: digest,
    manifest: { format: "agent-liability-bundle-manifest/v1", evidenceCutoff: pins.asOf, pins, entries: [entry("z.json"), entry("a.json")], manifestDigest: digest, merkleRoot: digest },
    objects: [{ path: "z.json", encoding: "jcs-json", content: {} }, { path: "a.json", encoding: "jcs-json", content: {} }], proofs: [],
  };
  assert.equal(validateArtifact("evidence_bundle", bundle).ok, false);
});
