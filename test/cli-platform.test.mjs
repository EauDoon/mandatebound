import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import { CLI_EXIT, runCli } from "../dist/cli.js";
import { sha256Digest } from "../dist/canonical.js";
import { buildScenario } from "../dist/simulator.js";
import { MemoryStore, StoreError } from "../dist/store.js";
import { deriveLiabilityDecisionId } from "../dist/validation.js";

const DIGEST = `sha256:${"a".repeat(64)}`;

function decision(overrides = {}) {
  const { artifactId: _artifactId, ...fields } = overrides;
  const pins = fields.pins ?? {
    asOf: "2026-07-23T00:00:00.000Z",
    policyDigest: DIGEST,
    trustSnapshotDigest: DIGEST,
    rulebookDigest: DIGEST,
    schemaDigests: [DIGEST],
    engineVersion: "1.0.0",
    bundleRootDigest: DIGEST,
  };
  const material = {
    schemaVersion: "1.0.0",
    caseId: "case-cli-1",
    evaluatedAt: pins.asOf,
    evidenceBundleId: "bundle-cli-1",
    evidenceBundleDigest: pins.bundleRootDigest,
    policyRef: { artifactType: "liability_policy", artifactId: "policy-1", digest: pins.policyDigest },
    rulebookRef: { artifactType: "rulebook", artifactId: "rulebook-1", digest: pins.rulebookDigest },
    trustSnapshotRef: { artifactType: "trust_snapshot", artifactId: "trust-1", digest: pins.trustSnapshotDigest },
    engineVersion: pins.engineVersion,
    outcome: "unresolved",
    disposition: "indeterminate",
    policyOutcome: "unresolved",
    appealPolicy: { reviewerIds: ["reviewer-synthetic"], maxAppealEvents: 8 },
    reasonCodes: ["missing_required_evidence"],
    trace: [],
    missingEvidence: ["mandate"],
    conflictingEvidence: [],
    cryptographicFacts: [],
    verifiedFacts: [],
    attributedAttestations: [],
    policyConclusions: [{
      reasonCode: "missing_required_evidence",
      outcome: "unresolved",
      disposition: "indeterminate",
    }],
    rejectedEvidence: [],
    deterministicTrace: [],
    pins,
    externalAuthenticity: "established_by_caller_pins",
    legalEffect: "not-determined",
    ...fields,
  };
  return { artifactId: deriveLiabilityDecisionId(material), ...material };
}

function engine(overrides = {}) {
  return {
    verifyEvidenceBundle: () => ({ valid: true, verifiedEntries: 1, totalEntries: 1, trustChecked: false, issues: [] }),
    evaluateCase: () => decision(),
    explainDecision: () => "Synthetic, nonlegal explanation.",
    ...overrides,
  };
}

function collector() {
  let text = "";
  return {
    stream: new Writable({
      write(chunk, _encoding, callback) {
        text += chunk.toString();
        callback();
      },
    }),
    value: () => text,
  };
}

async function invoke(argv, input, options = {}) {
  const stdout = collector();
  const stderr = collector();
  const code = await runCli(argv, {
    stdin: Readable.from([input]),
    stdout: stdout.stream,
    stderr: stderr.stream,
    engine: options.engine ?? engine(),
    store: options.store,
    signal: options.signal,
    onServer: options.onServer,
  });
  return { code, stdout: stdout.value(), stderr: stderr.value() };
}

test("verify and decide use stable success/invalid exit codes with JSON stdout", async () => {
  const verified = await invoke(["verify", "-"], "{}", {});
  assert.equal(verified.code, CLI_EXIT.SUCCESS);
  assert.equal(JSON.parse(verified.stdout).ok, true);
  assert.equal(verified.stderr, "");

  const invalid = await invoke(["verify", "-"], "{}", {
    engine: engine({
      verifyEvidenceBundle: () => ({ valid: false, verifiedEntries: 0, totalEntries: 1, trustChecked: false, issues: [] }),
    }),
  });
  assert.equal(invalid.code, CLI_EXIT.INVALID);
  assert.equal(JSON.parse(invalid.stdout).ok, false);

  const store = new MemoryStore();
  const decided = await invoke(["decide", "-"], JSON.stringify({ pins: {} }), { store });
  assert.equal(decided.code, CLI_EXIT.SUCCESS);
  assert.equal(JSON.parse(decided.stdout).result.outcome, "unresolved");
  const decidedArtifact = JSON.parse(decided.stdout).result;
  assert.equal((await store.getDecision(decidedArtifact.artifactId)).legalEffect, "not-determined");
  await store.close();
});

test("explain is JSON and explicitly nonlegal", async () => {
  const result = await invoke(["explain", "-"], JSON.stringify(decision()));
  assert.equal(result.code, CLI_EXIT.SUCCESS);
  const output = JSON.parse(result.stdout);
  assert.equal(output.result.legalEffect, "not-determined");
  assert.match(output.result.explanation, /nonlegal/);
});

test("appeal and replay commands preserve append order", async () => {
  const store = new MemoryStore();
  const stored = decision();
  await store.putDecision(stored);
  const filed = {
    schemaVersion: "1.0.0",
    artifactId: "event-cli-1",
    appealId: "appeal-cli-1",
    decisionId: stored.artifactId,
    sequence: 1,
    eventType: "filed",
    actor: { id: "principal-synthetic", role: "principal" },
    occurredAt: "2026-07-23T00:00:00.000Z",
    reasonCodes: ["review_requested"],
  };
  const appealed = await invoke(["appeal", "-"], JSON.stringify(filed), { store });
  assert.equal(appealed.code, CLI_EXIT.SUCCESS);
  assert.equal(JSON.parse(appealed.stdout).result.status, "open");

  const replayed = await invoke(["replay", "-"], JSON.stringify([filed]));
  assert.equal(replayed.code, CLI_EXIT.SUCCESS);
  assert.equal(JSON.parse(replayed.stdout).result.completeness.state, "unproven");
  await store.close();
});

test("usage and input failures are privacy-safe", async () => {
  const usage = await invoke(["unknown"], "");
  assert.equal(usage.code, CLI_EXIT.USAGE);
  assert.equal(JSON.parse(usage.stdout).error.code, "ALB_CLI_USAGE");
  assert.match(usage.stderr, /ALB_CLI_USAGE/);

  const canary = "C:\\private\\owner\\SECRET_CANARY.json";
  const missing = await invoke(["verify", canary], "");
  assert.equal(missing.code, CLI_EXIT.INVALID);
  assert.equal(missing.stdout.includes("SECRET_CANARY"), false);
  assert.equal(missing.stderr.includes("SECRET_CANARY"), false);
});

test("documented --input and --format options work, while ambiguous and unsupported options fail", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mandatebound-cli-"));
  const inputFile = join(directory, "bundle.json");
  try {
    await writeFile(inputFile, "{}", "utf8");
    const verified = await invoke(["verify", "--input", inputFile, "--format", "json"], "");
    assert.equal(verified.code, CLI_EXIT.SUCCESS);

    for (const argv of [
      ["verify", "-", "--input", inputFile],
      ["verify", "--input"],
      ["verify", "--input", inputFile, "--input", inputFile],
      ["verify", "--format", "yaml"],
      ["verify", "--scenario", "principal"],
      ["serve", "--input", inputFile],
      ["serve", "--allow-remote"],
      ["verify", "--unknown"],
    ]) {
      const result = await invoke(argv, "{}");
      assert.equal(result.code, CLI_EXIT.USAGE, argv.join(" "));
      assert.equal(JSON.parse(result.stdout).error.code, "ALB_CLI_USAGE");
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("help and version are stable JSON and use the public brand", async () => {
  const help = await invoke(["--help"], "");
  assert.equal(help.code, CLI_EXIT.SUCCESS);
  assert.equal(JSON.parse(help.stdout).result.name, "MandateBound");
  assert.match(JSON.parse(help.stdout).result.usage, /mandatebound/);

  const version = await invoke(["--version"], "");
  assert.equal(version.code, CLI_EXIT.SUCCESS);
  assert.equal(JSON.parse(version.stdout).result.version, "1.0.0");
  assert.equal(JSON.parse(version.stdout).result.releaseVersion, "1.2.0");
  assert.equal(JSON.parse(version.stdout).result.engineVersion, "1.0.0");
});

test("v1.2 policy and conformance commands are deterministic and fail closed", async () => {
  const rulebook = JSON.parse(await readFile(
    new URL("../rulebooks/v1/mandate-to-liability.v1.json", import.meta.url),
    "utf8",
  ));
  const policy = structuredClone(buildScenario("principal").input.policy.payload);
  policy.rulebookRef = {
    artifactType: "rulebook",
    artifactId: rulebook.artifactId,
    digest: sha256Digest(rulebook),
  };

  const validated = await invoke(
    ["policy", "validate", "-"],
    JSON.stringify({ policy, rulebook }),
  );
  assert.equal(validated.code, CLI_EXIT.SUCCESS);
  assert.equal(JSON.parse(validated.stdout).result.valid, true);

  const tested = await invoke(
    ["policy", "test", "-"],
    JSON.stringify({
      policy,
      rulebook,
      cases: [{
        id: "missing-evidence",
        facts: {
          input_state: "valid",
          evidence_state: "missing",
          policy_state: "active",
          trust_state: "pinned",
          mandate_state: "valid",
          receipt_state: "missing",
          execution_state: "missing",
          operator_controls: "unknown",
          operator_violation: "none",
          model_provenance: "missing",
          causation_state: "missing",
        },
        expected: { outcome: "unresolved" },
      }],
    }),
  );
  assert.equal(tested.code, CLI_EXIT.SUCCESS);
  assert.equal(JSON.parse(tested.stdout).result.passed, true);

  const diffed = await invoke(
    ["policy", "diff", "-"],
    JSON.stringify({ before: rulebook, after: rulebook }),
  );
  assert.equal(diffed.code, CLI_EXIT.SUCCESS);
  assert.equal(JSON.parse(diffed.stdout).result.changed, false);

  const conformance = await invoke(["conformance"], "");
  assert.equal(conformance.code, CLI_EXIT.SUCCESS);
  assert.equal(
    JSON.parse(conformance.stdout).result.claim,
    "bounded-evidence-profile",
  );

  for (const argv of [
    ["policy", "unknown"],
    ["casepack", "unknown"],
    ["conformance", "unexpected"],
    ["case-report", "-", "--format", "yaml"],
  ]) {
    const result = await invoke(argv, "{}");
    assert.equal(result.code, CLI_EXIT.USAGE, argv.join(" "));
  }
});

test("AP2 dispute CLI resolves materialized evidence and uses conflict exit for gaps", async () => {
  const unresolved = await invoke(
    ["ap2-dispute", "resolve", "-"],
    JSON.stringify({
      transactionId: Buffer.alloc(32).toString("base64url"),
      asOf: "2026-07-23T00:00:00.000Z",
      verificationPlan: {},
      sources: [],
    }),
  );
  assert.equal(unresolved.code, CLI_EXIT.CONFLICT);
  assert.equal(JSON.parse(unresolved.stdout).ok, false);
  assert.equal(JSON.parse(unresolved.stdout).result.status, "unresolved");

  const invalid = await invoke(
    ["ap2-dispute", "resolve", "-"],
    JSON.stringify({ transactionId: "invalid" }),
  );
  assert.equal(invalid.code, CLI_EXIT.INVALID);
  assert.equal(JSON.parse(invalid.stdout).error.code, "ALB_CLI_INPUT");

  const missingAnchor = await invoke(["ap2-dispute", "verify", "-"], "{}");
  assert.equal(missingAnchor.code, CLI_EXIT.USAGE);
  assert.equal(JSON.parse(missingAnchor.stdout).error.code, "ALB_CLI_USAGE");

  const invalidPack = await invoke(
    ["ap2-dispute", "verify", "-", "--expected-pack-digest", DIGEST],
    "{}",
  );
  assert.equal(invalidPack.code, CLI_EXIT.INVALID);
  assert.equal(JSON.parse(invalidPack.stdout).result.packDigest, null);
});

test("AP2 dispute CLI exposes pack, independent verify, and timeline render", async () => {
  const snapshot = {
    kid: "synthetic-key",
    jwk: {
      kty: "EC",
      crv: "P-256",
      x: Buffer.alloc(32, 1).toString("base64url"),
      y: Buffer.alloc(32, 2).toString("base64url"),
    },
    sourceDigest: DIGEST,
    capturedAt: "2026-07-22T00:00:00.000Z",
    validUntil: "2027-07-22T00:00:00.000Z",
  };
  const mandatePlan = {
    issuerKeySnapshot: snapshot,
    expectedIssuerKeySourceDigest: DIGEST,
    expectedIssuer: "https://issuer.example",
    expectedAudience: "https://audience.example",
    expectedNonce: "synthetic-nonce",
  };
  const receiptPlan = {
    issuerKeySnapshot: snapshot,
    expectedIssuerKeySourceDigest: DIGEST,
    expectedIssuer: "https://issuer.example",
  };
  const input = {
    transactionId: Buffer.alloc(32).toString("base64url"),
    asOf: "2026-07-23T00:00:00.000Z",
    createdAt: "2026-07-23T00:00:00.000Z",
    verificationPlan: {
      checkoutMandate: mandatePlan,
      checkoutJwt: {
        merchantKeySnapshot: snapshot,
        expectedMerchantKeySourceDigest: DIGEST,
      },
      checkoutReceipt: receiptPlan,
      paymentMandate: mandatePlan,
      paymentReceipt: receiptPlan,
    },
    sources: [{
      sourceId: "synthetic-source",
      role: "merchant",
      retrievedAt: "2026-07-22T23:59:00.000Z",
      artifacts: [],
    }],
    checkoutVersions: [{
      versionId: "synthetic-version",
      sourceId: "synthetic-source",
      observedAt: "2026-07-22T23:58:00.000Z",
      checkoutJwt: "synthetic-checkout-jwt",
    }],
    revocations: [{
      recordId: "synthetic-checkout-revocation",
      mandateKind: "checkout_mandate",
      sourceId: "synthetic-source",
      checkedAt: "2026-07-22T23:59:10.000Z",
      reportedStatus: "not_revoked",
      snapshotBase64: Buffer.from("checkout not revoked", "utf8").toString("base64"),
    }, {
      recordId: "synthetic-payment-revocation",
      mandateKind: "payment_mandate",
      sourceId: "synthetic-source",
      checkedAt: "2026-07-22T23:59:20.000Z",
      reportedStatus: "not_revoked",
      snapshotBase64: Buffer.from("payment not revoked", "utf8").toString("base64"),
    }],
  };

  const packed = await invoke(["ap2-dispute", "pack", "-"], JSON.stringify(input));
  assert.equal(packed.code, CLI_EXIT.SUCCESS, packed.stdout);
  const pack = JSON.parse(packed.stdout).result;
  assert.equal(pack.schemaId, "MandateBoundAp2EvidencePack/v1");

  const verifyArgs = [
    "ap2-dispute",
    "verify",
    "-",
    "--expected-pack-digest",
    pack.packDigest,
  ];
  const verified = await invoke(verifyArgs, packed.stdout);
  assert.equal(verified.code, CLI_EXIT.CONFLICT);
  assert.equal(JSON.parse(verified.stdout).result.status, "unresolved");
  assert.equal(JSON.parse(verified.stdout).result.anchorMatched, true);

  const overLegacyLimit = `${" ".repeat((4 * 1024 * 1024) + 1)}${packed.stdout}`;
  const largeVerified = await invoke(verifyArgs, overLegacyLimit);
  assert.equal(largeVerified.code, CLI_EXIT.CONFLICT);
  assert.notEqual(JSON.parse(largeVerified.stdout).error?.code, "ALB_CLI_INPUT_LIMIT");

  const renderArgs = [
    "ap2-dispute",
    "render",
    "-",
    "--expected-pack-digest",
    pack.packDigest,
  ];
  const renderedJson = await invoke(renderArgs, packed.stdout);
  assert.equal(renderedJson.code, CLI_EXIT.CONFLICT);
  assert.equal(Array.isArray(JSON.parse(renderedJson.stdout).result.timeline), true);

  const renderedHtml = await invoke(
    [
      "ap2-dispute",
      "render",
      "-",
      "--format",
      "html",
      "--expected-pack-digest",
      pack.packDigest,
    ],
    packed.stdout,
  );
  assert.equal(renderedHtml.code, CLI_EXIT.CONFLICT);
  assert.match(renderedHtml.stdout, /AP2 Evidence Timeline/);
  assert.doesNotMatch(renderedHtml.stdout, /synthetic-checkout-jwt/);
});

test("malformed, duplicate-key, wrong-shape, directory, and oversized inputs fail safely", async () => {
  for (const input of ["{", '{"a":1,"a":2}']) {
    const result = await invoke(["verify", "-"], input);
    assert.equal(result.code, CLI_EXIT.INVALID);
    assert.match(JSON.parse(result.stdout).error.code, /^ALB_JSON_/);
  }

  const wrongShape = await invoke(["replay", "-"], "null");
  assert.equal(wrongShape.code, CLI_EXIT.INVALID);
  assert.equal(JSON.parse(wrongShape.stdout).error.code, "ALB_CLI_INPUT");

  const directory = await mkdtemp(join(tmpdir(), "mandatebound-cli-dir-"));
  try {
    const invalidFile = await invoke(["verify", directory], "");
    assert.equal(invalidFile.code, CLI_EXIT.INVALID);
    assert.equal(JSON.parse(invalidFile.stdout).error.code, "ALB_CLI_INPUT");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }

  const oversized = await invoke(["verify", "-"], "x".repeat(4 * 1024 * 1024 + 1));
  assert.equal(oversized.code, CLI_EXIT.INVALID);
  assert.equal(JSON.parse(oversized.stdout).error.code, "ALB_CLI_INPUT_LIMIT");
});

test("CLI error mapping uses stable exit classes and never reflects exception secrets", async () => {
  const typeFailure = await invoke(["decide", "-"], "{}", {
    engine: engine({ evaluateCase: () => { throw new TypeError("PRIVATE_TYPE_DETAIL"); } }),
  });
  assert.equal(typeFailure.code, CLI_EXIT.INVALID);
  assert.equal(JSON.parse(typeFailure.stdout).error.code, "ALB_ARTIFACT_INVALID");
  assert.equal(typeFailure.stdout.includes("PRIVATE_TYPE_DETAIL"), false);

  const internal = await invoke(["decide", "-"], "{}", {
    engine: engine({ evaluateCase: () => { throw new Error("PRIVATE_INTERNAL_DETAIL"); } }),
  });
  assert.equal(internal.code, CLI_EXIT.INTERNAL);
  assert.equal(internal.stdout.includes("PRIVATE_INTERNAL_DETAIL"), false);

  const coded = await invoke(["simulate", "not-a-scenario"], "");
  assert.equal(coded.code, CLI_EXIT.INVALID);
  assert.equal(JSON.parse(coded.stdout).error.code, "ALB_SCENARIO_UNKNOWN");

  const storeCases = [
    [new StoreError("ALB_STORE_DECISION_NOT_FOUND", "secret"), CLI_EXIT.NOT_FOUND],
    [new StoreError("ALB_STORE_CONFLICT", "secret"), CLI_EXIT.CONFLICT],
    [new StoreError("ALB_STORE_OPEN", "secret"), CLI_EXIT.UNAVAILABLE],
    [new StoreError("ALB_STORE_ARTIFACT_INVALID", "secret"), CLI_EXIT.INVALID],
  ];
  for (const [failure, expected] of storeCases) {
    const store = {
      putDecision: async () => { throw failure; },
      getDecision: async () => undefined,
      appendAppeal: async () => { throw failure; },
      getAppeal: async () => undefined,
      verifyChain: async () => ({ valid: true, records: 0, completeness: "unproven", issues: [] }),
      close: async () => {},
    };
    const result = await invoke(["decide", "-"], "{}", { store });
    assert.equal(result.code, expected);
    assert.equal(result.stdout.includes("secret"), false);
  }
});

test("serve reports its loopback address and returns a stable code", async () => {
  let server;
  const result = await invoke(["serve", "--port", "0"], "", {
    onServer: (value) => { server = value; },
  });
  try {
    assert.equal(result.code, CLI_EXIT.SUCCESS);
    const output = JSON.parse(result.stdout);
    assert.equal(output.result.status, "listening");
    assert.equal(output.result.host, "127.0.0.1");
  } finally {
    await server?.close();
  }
});

test("serve closes an owned store when listen fails", async () => {
  const blocker = createServer();
  await new Promise((resolve, reject) => {
    blocker.once("error", reject);
    blocker.listen(0, "127.0.0.1", resolve);
  });
  const address = blocker.address();
  assert.equal(typeof address, "object");
  try {
    const result = await invoke(["serve", "--port", String(address.port)], "");
    assert.equal(result.code, CLI_EXIT.INTERNAL);
  } finally {
    await new Promise((resolve) => blocker.close(resolve));
  }
});

test("simulate command runs a named synthetic scenario", async () => {
  const result = await invoke(["simulate", "principal"], "");
  assert.equal(result.code, CLI_EXIT.SUCCESS);
  const output = JSON.parse(result.stdout);
  assert.equal(output.result.scenario, "principal");
  assert.equal(output.result.passed, true);

  const option = await invoke(["simulate", "--scenario", "operator", "--format", "json"], "");
  assert.equal(option.code, CLI_EXIT.SUCCESS);
  assert.equal(JSON.parse(option.stdout).result.scenario, "operator");
});
