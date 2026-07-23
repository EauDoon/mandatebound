import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import { CLI_EXIT, runCli } from "../dist/cli.js";
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
