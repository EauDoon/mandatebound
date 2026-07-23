import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { appealEventDigest } from "./appeals.js";
import { createEvidenceBundle, verifyEvidenceBundle } from "./bundle.js";
import { sha256Digest } from "./canonical.js";
import { createSignedArtifact, exportPublicJwk, jwkThumbprint } from "./crypto.js";
import type {
  ActorRef,
  AppealEvent,
  ArtifactRef,
  ArtifactType,
  BundlePins,
  CausationAttestation,
  EvidenceBundle,
  EvaluationCase,
  ExecutionReceipt,
  IncidentReport,
  LiabilityDecision,
  LiabilityOutcome,
  LiabilityPolicy,
  MandateEnvelope,
  ProofPurpose,
  Rulebook,
  RuntimeEvent,
  SignedArtifact,
  TrustKey,
  TrustSnapshot,
} from "./domain.js";
import { MemoryStore } from "./store.js";
import { SCHEMA_IDS, schemaDigestForArtifactType } from "./validation.js";
import { ENGINE_VERSION } from "./version.js";

export const SIMULATION_SCENARIOS = [
  "principal",
  "operator",
  "model_vendor",
  "unresolved",
  "expiry",
  "replay",
  "tamper",
  "conflict",
  "appeal",
] as const;

export type SimulationScenarioName = (typeof SIMULATION_SCENARIOS)[number];

export interface BuiltScenario {
  readonly name: SimulationScenarioName;
  readonly expected: LiabilityOutcome | "invalid" | "upheld";
  readonly input: EvaluationCase;
  readonly bundle?: EvidenceBundle;
}

export interface SimulationResult {
  readonly scenario: SimulationScenarioName;
  readonly expected: BuiltScenario["expected"];
  readonly observed: LiabilityOutcome | "invalid" | "upheld" | "rejected";
  readonly passed: boolean;
  readonly legalEffect: "not-determined";
  readonly decision?: LiabilityDecision;
  readonly verification?: ReturnType<typeof verifyEvidenceBundle>;
  readonly appeal?: unknown;
}

const AS_OF = "2026-07-23T00:00:00.000Z";
const BEFORE = "2026-07-22T00:00:00.000Z";
const AFTER = "2027-07-23T00:00:00.000Z";

interface ScenarioKeys {
  readonly principal: KeyObject;
  readonly operator: KeyObject;
  readonly modelVendor: KeyObject;
  readonly attestor: KeyObject;
  readonly reviewer: KeyObject;
  readonly rulebookPublisher: KeyObject;
  readonly trustRoot: KeyObject;
}

function key(): KeyObject {
  return generateKeyPairSync("ed25519").privateKey;
}

function keys(): ScenarioKeys {
  return {
    principal: key(),
    operator: key(),
    modelVendor: key(),
    attestor: key(),
    reviewer: key(),
    rulebookPublisher: key(),
    trustRoot: key(),
  };
}

const principal: ActorRef = { id: "principal-synthetic", role: "principal" };
const operator: ActorRef = { id: "operator-synthetic", role: "operator" };
const agent: ActorRef = { id: "agent-synthetic", role: "agent" };
const modelVendor: ActorRef = { id: "model-vendor-synthetic", role: "model_vendor" };
const attestor: ActorRef = { id: "attestor-synthetic", role: "causation_attestor" };
const reviewer: ActorRef = { id: "reviewer-synthetic", role: "reviewer" };
const rulebookPublisher: ActorRef = { id: "rulebook-publisher-synthetic", role: "rulebook_publisher" };
const trustPublisher: ActorRef = { id: "trust-publisher-synthetic", role: "trust_publisher" };

function schemaId(type: ArtifactType): string {
  return SCHEMA_IDS[type];
}

function schemaDigest(type: ArtifactType): `sha256:${string}` {
  return schemaDigestForArtifactType(type);
}

function sign<T>(
  payload: T,
  privateKey: KeyObject,
  artifactType: ArtifactType,
  purpose: ProofPurpose,
): SignedArtifact<T> {
  return createSignedArtifact(payload, privateKey, {
    artifactType,
    purpose,
    schemaId: schemaId(artifactType),
    schemaDigest: schemaDigest(artifactType),
    signedAt: AS_OF,
  });
}

function ref<T extends { readonly artifactId: string }>(
  artifactType: ArtifactType,
  artifact: SignedArtifact<T>,
): ArtifactRef {
  return { artifactType, artifactId: artifact.payload.artifactId, digest: artifact.payloadDigest };
}

function trustKey(
  privateKey: KeyObject,
  roles: TrustKey["roles"],
  purposes: TrustKey["purposes"],
): TrustKey {
  const publicKey = exportPublicJwk(privateKey);
  return {
    kid: jwkThumbprint(publicKey),
    publicKey,
    roles,
    purposes,
    validFrom: "2025-01-01T00:00:00.000Z",
    validUntil: "2030-01-01T00:00:00.000Z",
    scopes: [
      "case-synthetic",
      principal.id,
      operator.id,
      agent.id,
      modelVendor.id,
      attestor.id,
      reviewer.id,
      rulebookPublisher.id,
      trustPublisher.id,
    ],
  };
}

function makeRulebook(): Rulebook {
  return {
    schemaVersion: "1.0.0",
    artifactId: "rulebook-synthetic-v1",
    revision: 1,
    semanticsVersion: "mandate-to-liability-v1",
    issuedAt: "2025-12-31T00:00:00.000Z",
    rules: [
      {
        id: "operator-violation",
        priority: 300,
        when: {
          op: "in",
          fact: "operator_violation",
          values: ["invalid_mandate", "expired_mandate", "revoked_mandate", "replayed_execution", "out_of_scope"],
        },
        outcome: "operator",
        reasonCode: "operator_control_boundary",
      },
      {
        id: "vendor-causation",
        priority: 200,
        when: {
          op: "all",
          conditions: [
            { op: "eq", fact: "mandate_state", value: "valid" },
            { op: "eq", fact: "operator_controls", value: "compliant" },
            { op: "eq", fact: "causation_state", value: "sufficient" },
          ],
        },
        outcome: "model_vendor",
        reasonCode: "vendor_causation_attested",
      },
      {
        id: "principal-inside-mandate",
        priority: 100,
        when: {
          op: "all",
          conditions: [
            { op: "eq", fact: "mandate_state", value: "valid" },
            { op: "eq", fact: "execution_state", value: "compliant" },
            { op: "eq", fact: "operator_controls", value: "compliant" },
            { op: "in", fact: "causation_state", values: ["insufficient", "missing"] },
          ],
        },
        outcome: "principal",
        reasonCode: "inside_mandate_without_vendor_causation",
      },
    ],
    defaultOutcome: "unresolved",
  };
}

function makeTrustSnapshot(scenarioKeys: ScenarioKeys): TrustSnapshot {
  return {
    schemaVersion: "1.0.0",
    artifactId: "trust-snapshot-synthetic-v1",
    revision: 1,
    issuedAt: BEFORE,
    asOf: AS_OF,
    issuer: trustPublisher,
    keys: [
      trustKey(scenarioKeys.principal, ["principal"], ["mandate_authorization", "incident_filing", "policy_acceptance"]),
      trustKey(scenarioKeys.operator, ["operator"], ["runtime_observation", "execution_attestation"]),
      trustKey(scenarioKeys.modelVendor, ["model_vendor"], ["artifact_issuance"]),
      trustKey(scenarioKeys.attestor, ["causation_attestor"], ["causation_attestation"]),
      trustKey(scenarioKeys.reviewer, ["reviewer"], ["decision_issuance", "appeal_event"]),
      trustKey(scenarioKeys.rulebookPublisher, ["rulebook_publisher"], ["rulebook_issuance"]),
    ],
  };
}

function buildCompleteCase(name: SimulationScenarioName): EvaluationCase {
  const scenarioKeys = keys();
  const rulebook = sign(makeRulebook(), scenarioKeys.rulebookPublisher, "rulebook", "rulebook_issuance");
  const trustSnapshot = sign(
    makeTrustSnapshot(scenarioKeys),
    scenarioKeys.trustRoot,
    "trust_snapshot",
    "trust_snapshot_issuance",
  );
  const policyPayload: LiabilityPolicy = {
    schemaVersion: "1.0.0",
    artifactId: "policy-synthetic-v1",
    revision: 1,
    issuedAt: BEFORE,
    effectiveFrom: "2026-01-01T00:00:00.000Z",
    effectiveUntil: AFTER,
    attributionProfile: "mandate-to-liability-v1",
    principalId: principal.id,
    operatorId: operator.id,
    modelVendorIds: [modelVendor.id],
    rulebookRef: ref("rulebook", rulebook),
    trustSnapshotRef: ref("trust_snapshot", trustSnapshot),
    causation: {
      requiredForVendorOutcome: true,
      independentAttestorRequired: true,
      allowedMethods: ["counterfactual_replay", "controlled_reproduction", "signed_provider_admission"],
      acceptedAttestorRoles: ["causation_attestor"],
    },
    appeal: { reviewerIds: [reviewer.id], maxAppealEvents: 32 },
    legalEffect: "not-determined",
  };
  const policy = sign(policyPayload, scenarioKeys.principal, "liability_policy", "policy_acceptance");
  const mandatePayload: MandateEnvelope = {
    schemaVersion: "1.0.0",
    artifactId: "mandate-synthetic-1",
    revision: 1,
    issuedAt: "2025-12-31T00:00:00.000Z",
    validFrom: "2026-01-01T00:00:00.000Z",
    expiresAt: name === "expiry" ? "2026-07-22T23:59:59.000Z" : AFTER,
    nonce: "nonce-synthetic-1",
    principal,
    operator,
    agent,
    modelVendor,
    policyRef: ref("liability_policy", policy),
    rulebookRef: ref("rulebook", rulebook),
    scope: {
      actions: [{
        kind: "purchase",
        targets: ["merchant.synthetic"],
        counterparties: ["supplier.synthetic"],
        asset: "USD",
        maxMinorUnits: "10000",
      }],
      maxExecutions: 1,
      delegation: { allowed: false, maxDepth: 0, delegates: [] },
    },
    requiredControls: ["mandate-valid", "mandate-not-revoked", "scope-compliant", "replay-protected"],
  };
  const mandate = sign(mandatePayload, scenarioKeys.principal, "mandate_envelope", "mandate_authorization");
  const action = {
    kind: "purchase",
    target: name === "operator" ? "outside.synthetic" : "merchant.synthetic",
    parametersDigest: sha256Digest({ sku: "synthetic-item", quantity: 1 }),
    counterparty: "supplier.synthetic",
    quantity: { asset: "USD", minorUnits: "2500" },
  } as const;
  const actionDigest = sha256Digest(action);
  const runtimePayloads: RuntimeEvent[] = [
    {
      schemaVersion: "1.0.0",
      artifactId: "event-synthetic-1",
      executionId: "execution-synthetic-1",
      sequence: 1,
      eventType: "mandate_checked",
      actor: operator,
      observedAt: AS_OF,
      actionDigest,
      parentEventIds: [],
      controlId: "mandate-valid",
      controlResult: "pass",
    },
    {
      schemaVersion: "1.0.0",
      artifactId: "event-synthetic-2",
      executionId: "execution-synthetic-1",
      sequence: 2,
      eventType: "mandate_checked",
      actor: operator,
      observedAt: AS_OF,
      actionDigest,
      parentEventIds: ["event-synthetic-1"],
      controlId: "mandate-not-revoked",
      controlResult: "pass",
    },
    {
      schemaVersion: "1.0.0",
      artifactId: "event-synthetic-3",
      executionId: "execution-synthetic-1",
      sequence: 3,
      eventType: "policy_checked",
      actor: operator,
      observedAt: AS_OF,
      actionDigest,
      parentEventIds: ["event-synthetic-2"],
      controlId: "scope-compliant",
      controlResult: "pass",
    },
    {
      schemaVersion: "1.0.0",
      artifactId: "event-synthetic-4",
      executionId: "execution-synthetic-1",
      sequence: 4,
      eventType: "model_invoked",
      actor: operator,
      observedAt: AS_OF,
      actionDigest,
      parentEventIds: ["event-synthetic-3"],
      contentDigest: sha256Digest({ model: "synthetic-model-v1" }),
    },
    {
      schemaVersion: "1.0.0",
      artifactId: "event-synthetic-5",
      executionId: "execution-synthetic-1",
      sequence: 5,
      eventType: "execution_completed",
      actor: operator,
      observedAt: AS_OF,
      actionDigest,
      parentEventIds: ["event-synthetic-4"],
      controlId: "replay-protected",
      controlResult: "pass",
    },
  ];
  const runtimeEvents = runtimePayloads.map((payload) =>
    sign(payload, scenarioKeys.operator, "runtime_event", "runtime_observation")
  );
  const receiptPayload: ExecutionReceipt = {
    schemaVersion: "1.0.0",
    artifactId: "receipt-synthetic-1",
    executionId: "execution-synthetic-1",
    mandateRef: ref("mandate_envelope", mandate),
    policyRef: ref("liability_policy", policy),
    authorizationNonce: mandate.payload.nonce,
    idempotencyKey: "idempotency-synthetic-1",
    operator,
    action,
    modelDigest: sha256Digest({ model: "synthetic-model-v1" }),
    toolManifestDigest: sha256Digest({ tools: ["synthetic-purchase"] }),
    deploymentDigest: sha256Digest({ deployment: "synthetic" }),
    disposition: "executed",
    executedAt: AS_OF,
    controlResults: [
      { controlId: "mandate-valid", result: "pass", eventId: "event-synthetic-1" },
      { controlId: "mandate-not-revoked", result: "pass", eventId: "event-synthetic-2" },
      { controlId: "scope-compliant", result: "pass", eventId: "event-synthetic-3" },
      { controlId: "replay-protected", result: "pass", eventId: "event-synthetic-5" },
    ],
    eventRootDigest: sha256Digest({
      profile: "agent-liability-event-root/v1",
      events: runtimeEvents.map((event) => ({
        sequence: event.payload.sequence,
        artifactId: event.payload.artifactId,
        payloadDigest: event.payloadDigest,
      })),
    }),
    actualEffectDigest: sha256Digest({ result: "synthetic-loss" }),
  };
  let executionReceipt = sign(
    receiptPayload,
    scenarioKeys.operator,
    "execution_receipt",
    "execution_attestation",
  );
  const incidentPayload: IncidentReport = {
    schemaVersion: "1.0.0",
    artifactId: "incident-synthetic-1",
    executionReceiptRef: ref("execution_receipt", executionReceipt),
    reporter: principal,
    filedAt: AS_OF,
    discoveredAt: AS_OF,
    allegedBranch: name === "operator" || name === "expiry" || name === "replay"
      ? "operator"
      : name === "model_vendor" || name === "conflict" ? "model_vendor" : "principal",
    harmCodes: ["synthetic-economic-loss"],
    summaryDigest: sha256Digest({ summary: "synthetic-only" }),
    evidenceRefs: runtimeEvents.map((event) => ref("runtime_event", event)),
  };
  const incidentReport = sign(incidentPayload, scenarioKeys.principal, "incident_report", "incident_filing");
  const attestations: SignedArtifact<CausationAttestation>[] = [];
  if (name === "model_vendor" || name === "conflict") {
    const sufficient: CausationAttestation = {
      schemaVersion: "1.0.0",
      artifactId: "causation-synthetic-1",
      incidentRef: ref("incident_report", incidentReport),
      subject: modelVendor,
      modelDigest: receiptPayload.modelDigest ?? sha256Digest("missing"),
      attestor,
      method: "controlled_reproduction",
      conclusion: "sufficient",
      failureCode: "synthetic-model-failure",
      causalEventIds: ["event-synthetic-4"],
      reproductionDigest: sha256Digest({ reproduction: "synthetic" }),
      competingCauseIds: [],
      issuedAt: AS_OF,
    };
    attestations.push(sign(sufficient, scenarioKeys.attestor, "causation_attestation", "causation_attestation"));
    if (name === "conflict") {
      attestations.push(sign(
        { ...sufficient, artifactId: "causation-synthetic-2", conclusion: "conflicting", competingCauseIds: ["operator-control"] },
        scenarioKeys.attestor,
        "causation_attestation",
        "causation_attestation",
      ));
    }
  }
  const priorReceipts: SignedArtifact<ExecutionReceipt>[] = [];
  if (name === "replay") {
    priorReceipts.push(sign(
      {
        ...receiptPayload,
        artifactId: "receipt-synthetic-prior",
        executionId: "execution-synthetic-prior",
        executedAt: "2026-07-22T23:00:00.000Z",
      },
      scenarioKeys.operator,
      "execution_receipt",
      "execution_attestation",
    ));
  }

  if (name === "tamper") {
    executionReceipt = {
      ...executionReceipt,
      payload: {
        ...executionReceipt.payload,
        action: { ...executionReceipt.payload.action, target: "tampered.synthetic" },
      },
    };
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
  ].map((type) => schemaDigest(type as ArtifactType)).sort();
  const pins: BundlePins = {
    asOf: AS_OF,
    policyDigest: policy.payloadDigest,
    trustSnapshotDigest: trustSnapshot.payloadDigest,
    rulebookDigest: rulebook.payloadDigest,
    schemaDigests,
    engineVersion: ENGINE_VERSION,
  };
  const base: EvaluationCase = {
    caseId: "case-synthetic",
    asOf: AS_OF,
    pins,
    trustRootJwk: exportPublicJwk(scenarioKeys.trustRoot),
    mandate,
    runtimeEvents,
    executionReceipt,
    priorReceipts,
    incidentReport,
    causationAttestations: attestations,
    policy,
    rulebook,
    trustSnapshot,
  };

  if (name === "unresolved") {
    const {
      mandate: _mandate,
      executionReceipt: _executionReceipt,
      incidentReport: _incidentReport,
      ...unresolved
    } = base;
    return unresolved;
  }
  return base;
}

function expectedFor(name: SimulationScenarioName): BuiltScenario["expected"] {
  switch (name) {
    case "principal": return "principal";
    case "operator": return "operator";
    case "model_vendor": return "model_vendor";
    case "unresolved": return "unresolved";
    case "expiry": return "operator";
    case "replay": return "operator";
    case "tamper": return "invalid";
    case "conflict": return "unresolved";
    case "appeal": return "upheld";
  }
}

export function buildScenario(name: string): BuiltScenario {
  if (!(SIMULATION_SCENARIOS as readonly string[]).includes(name)) {
    throw Object.assign(new TypeError("Unknown synthetic simulation scenario."), { code: "ALB_SCENARIO_UNKNOWN" });
  }
  const scenarioName = name as SimulationScenarioName;
  const input = buildCompleteCase(scenarioName);
  let bundle: EvidenceBundle | undefined;
  if (scenarioName !== "unresolved") {
    try {
      bundle = createEvidenceBundle(input);
      if (scenarioName === "tamper") {
        bundle = { ...bundle, rootDigest: sha256Digest("synthetic-tamper") };
      }
    } catch {
      bundle = undefined;
    }
  }
  return {
    name: scenarioName,
    expected: expectedFor(scenarioName),
    input: bundle === undefined ? input : { ...input, evidenceBundle: bundle },
    ...(bundle === undefined ? {} : { bundle }),
  };
}

async function evaluate(input: EvaluationCase): Promise<LiabilityDecision> {
  const module = await import("./engine.js");
  const candidate = Reflect.get(module, "evaluateCase") ?? Reflect.get(module, "evaluateLiability") ?? Reflect.get(module, "evaluate");
  if (typeof candidate !== "function") throw new TypeError("Evaluation engine is unavailable.");
  return await Reflect.apply(candidate, undefined, [input]) as LiabilityDecision;
}

async function simulateAppeal(built: BuiltScenario): Promise<SimulationResult> {
  const original = await evaluate(built.input);
  const store = new MemoryStore();
  try {
    await store.putDecision(original);
    const filed: AppealEvent = {
      schemaVersion: "1.0.0",
      artifactId: "appeal-event-synthetic-1",
      appealId: "appeal-synthetic-1",
      decisionId: original.artifactId,
      sequence: 1,
      eventType: "filed",
      actor: principal,
      occurredAt: AS_OF,
      reasonCodes: ["synthetic-review-requested"],
    };
    await store.appendAppeal(filed);
    const review: AppealEvent = {
      ...filed,
      artifactId: "appeal-event-synthetic-2",
      sequence: 2,
      previousEventDigest: appealEventDigest(filed),
      eventType: "review_started",
      actor: reviewer,
      reasonCodes: ["synthetic-review-started"],
    };
    await store.appendAppeal(review);
    const upheld: AppealEvent = {
      ...filed,
      artifactId: "appeal-event-synthetic-3",
      sequence: 3,
      previousEventDigest: appealEventDigest(review),
      eventType: "upheld",
      actor: reviewer,
      reasonCodes: ["synthetic-original-decision-upheld"],
    };
    const appeal = await store.appendAppeal(upheld);
    return {
      scenario: "appeal",
      expected: "upheld",
      observed: appeal.status === "upheld" ? "upheld" : "rejected",
      passed: appeal.status === "upheld"
        && appeal.issues.length === 0
        && (await store.getDecision(original.artifactId))?.outcome === original.outcome,
      legalEffect: "not-determined",
      decision: original,
      appeal,
    };
  } finally {
    await store.close();
  }
}

export async function simulateScenario(name: string): Promise<SimulationResult | readonly SimulationResult[]> {
  if (name === "all") {
    const results: SimulationResult[] = [];
    for (const scenario of SIMULATION_SCENARIOS) {
      results.push(await simulateScenario(scenario) as SimulationResult);
    }
    return results;
  }
  const built = buildScenario(name);
  if (built.name === "appeal") return simulateAppeal(built);
  if (built.name === "tamper") {
    const verification = built.bundle === undefined
      ? { valid: false, verifiedEntries: 0, totalEntries: 0, trustChecked: false, issues: [] }
      : verifyEvidenceBundle(built.bundle);
    return {
      scenario: built.name,
      expected: built.expected,
      observed: verification.valid ? "rejected" : "invalid",
      passed: !verification.valid,
      legalEffect: "not-determined",
      verification,
    };
  }
  try {
    const decision = await evaluate(built.input);
    return {
      scenario: built.name,
      expected: built.expected,
      observed: decision.outcome,
      passed: decision.outcome === built.expected,
      legalEffect: "not-determined",
      decision,
      ...(built.bundle === undefined ? {} : { verification: verifyEvidenceBundle(built.bundle) }),
    };
  } catch {
    return {
      scenario: built.name,
      expected: built.expected,
      observed: "rejected",
      passed: built.expected === "invalid",
      legalEffect: "not-determined",
    };
  }
}
