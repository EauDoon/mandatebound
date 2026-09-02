import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { createEvidenceBundle } from "../dist/bundle.js";
import {
  computeSourceEvidenceLeaf,
  createMandateBoundCasePack,
  createSourceCheckpointProof,
  sealDelegationContext,
  sealDeterministicMappingTrace,
  sealEvidenceCoverageContract,
  sealExternalTrustSnapshot,
  sealProtocolEvidenceEnvelope,
  sealSourceCheckpoint,
  verifyMandateBoundCasePack,
} from "../dist/casepack.js";
import {
  compareCasePackStatus,
  diffMandateBoundCasePacks,
  unpackMandateBoundCasePack,
} from "../dist/casepack-tools.js";
import { canonicalBytes, sha256Bytes, sha256Digest } from "../dist/canonical.js";
import { CLI_EXIT, runCli } from "../dist/cli.js";
import { exportPublicJwk } from "../dist/crypto.js";
import {
  createCaseReport,
  isCaseReportFor,
  renderCaseReportHtml,
} from "../dist/report.js";
import { parseStrictJsonObject, StrictJsonError } from "../dist/strict-json.js";
import { buildScenario } from "../dist/simulator.js";

const AS_OF = "2026-07-23T00:00:00.000Z";
const RAW_ALPHA = Buffer.from('{"action":"authorize","amount":"10"}', "utf8");
const RAW_BETA = Buffer.from('{"result":"accepted","sequence":1}', "utf8");

function withoutEmbeddedBundle(input) {
  const { evidenceBundle: _ignored, ...clean } = input;
  return clean;
}

function rawDescriptor(referenceId, bytes) {
  const digest = sha256Bytes(bytes);
  return {
    digest,
    byteLength: bytes.byteLength,
    reference: {
      referenceId,
      kind: "content_addressed",
      value: `urn:sha256:${digest.slice("sha256:".length)}`,
    },
  };
}

function protocolEnvelope({
  bundle,
  envelopeId,
  sourceId,
  eventClass,
  referenceId,
  bytes,
  checkpointInclusion,
}) {
  const output = bundle.manifest.entries.find((entry) => entry.path === "evidence/mandate.json")
    ?? bundle.manifest.entries[0];
  assert.ok(output);
  const rawEvidence = rawDescriptor(referenceId, bytes);
  const mapping = sealDeterministicMappingTrace({
    mapperId: "mandatebound.test-mapper",
    mapperVersion: "1.1.0",
    mappingPolicyDigest: sha256Digest({ mapper: "test-v1.1" }),
    inputDigest: rawEvidence.digest,
    outputArtifacts: [{ path: output.path, digest: output.digest }],
    steps: [{
      index: 0,
      ruleId: "map.raw-to-native",
      inputPointer: "/raw",
      outputPointer: "/bundle",
      status: "satisfied",
    }],
  });
  return sealProtocolEvidenceEnvelope({
    format: "MandateBoundProtocolEvidenceEnvelope/v1",
    envelopeId,
    sourceId,
    eventClass,
    capturedAt: "2026-07-22T12:00:00.000Z",
    mediaType: "application/json",
    rawEvidence,
    upstreamValid: true,
    mapping,
    ...(checkpointInclusion === undefined ? {} : { checkpointInclusion }),
  });
}

function coverageRequirement(requirementId, sourceId, eventClass) {
  return {
    requirementId,
    sourceId,
    eventClass,
    mediaTypes: ["application/json"],
    windowStart: "2026-07-22T00:00:00.000Z",
    windowEnd: "2026-07-22T23:59:59.999Z",
    minEnvelopes: 1,
    checkpointRequirement: "not_applicable",
  };
}

function fixture() {
  const bundle = createEvidenceBundle(withoutEmbeddedBundle(buildScenario("principal").input));
  const alpha = protocolEnvelope({
    bundle,
    envelopeId: "envelope.alpha",
    sourceId: "source.alpha",
    eventClass: "authorization",
    referenceId: "raw.alpha",
    bytes: RAW_ALPHA,
  });
  const beta = protocolEnvelope({
    bundle,
    envelopeId: "envelope.beta",
    sourceId: "source.beta",
    eventClass: "execution",
    referenceId: "raw.beta",
    bytes: RAW_BETA,
  });
  const policyDigest = sha256Digest({ coveragePolicy: "casepack-v1.1" });
  const coverageContract = sealEvidenceCoverageContract({
    format: "MandateBoundEvidenceCoverageContract/v1",
    contractId: "coverage.case-001",
    issuedAt: "2026-07-22T00:00:00.000Z",
    validFrom: "2026-07-22T00:00:00.000Z",
    validUntil: "2027-07-22T00:00:00.000Z",
    coverageScope: "declared_sources_and_windows_only",
    policyDigest,
    nativeBundleRootDigest: bundle.rootDigest,
    requirements: [
      coverageRequirement("requirement.alpha", "source.alpha", "authorization"),
      coverageRequirement("requirement.beta", "source.beta", "execution"),
    ],
  });
  const delegationContext = sealDelegationContext({
    format: "MandateBoundDelegationContext/v1",
    delegationId: "delegation.case-001",
    principalId: "principal.case-001",
    delegateId: "agent.case-001",
    mandateDigest: sha256Digest({ mandate: bundle.rootDigest }),
    scopeDigest: sha256Digest({ scope: "bounded-test" }),
    validFrom: "2026-07-22T00:00:00.000Z",
    validUntil: "2027-07-22T00:00:00.000Z",
    evidenceReferences: [],
    legalEffect: "not-determined",
  });
  const pack = createMandateBoundCasePack({
    format: "MandateBoundCasePack/v1",
    casePackId: "casepack.case-001",
    createdAt: AS_OF,
    nativeEvidenceBundle: bundle,
    protocolEvidence: [alpha, beta],
    delegationContext,
    coverageContract,
    sourceCheckpoints: [],
  });
  const anchors = {
    asOf: AS_OF,
    coveragePolicyDigest: policyDigest,
    coverageContractDigest: coverageContract.contractDigest,
    rawEvidence: [
      { referenceId: "raw.alpha", bytes: RAW_ALPHA },
      { referenceId: "raw.beta", bytes: RAW_BETA },
    ],
  };
  return { bundle, alpha, beta, coverageContract, delegationContext, pack, anchors };
}

function resealPack(pack) {
  const { casePackDigest: _ignored, ...material } = pack;
  return createMandateBoundCasePack(material);
}

function collectStream() {
  let output = "";
  return {
    stream: new Writable({
      write(chunk, _encoding, callback) {
        output += chunk.toString();
        callback();
      },
    }),
    value: () => output,
  };
}

async function invokeCasePackCli(argv, input) {
  const stdout = collectStream();
  const stderr = collectStream();
  const code = await runCli(argv, {
    stdin: Readable.from([JSON.stringify(input)]),
    stdout: stdout.stream,
    stderr: stderr.stream,
  });
  return { code, stdout: stdout.value(), stderr: stderr.value() };
}

function cliAnchors(anchors) {
  return {
    asOf: anchors.asOf,
    coveragePolicyDigest: anchors.coveragePolicyDigest,
    coverageContractDigest: anchors.coverageContractDigest,
    ...(anchors.externalTrustSnapshotDigest === undefined
      ? {}
      : { externalTrustSnapshotDigest: anchors.externalTrustSnapshotDigest }),
    ...(anchors.rawEvidence === undefined
      ? {}
      : {
          rawEvidence: anchors.rawEvidence.map((item) => ({
            referenceId: item.referenceId,
            bytesBase64: Buffer.from(item.bytes).toString("base64"),
          })),
        }),
  };
}

test("CasePack preserves nested EvidenceBundle/v1 bytes and separates assurance dimensions", () => {
  const { bundle, pack, anchors } = fixture();
  const before = canonicalBytes(bundle);
  const after = canonicalBytes(pack.nativeEvidenceBundle);
  assert.deepEqual(after, before);
  assert.equal(pack.nativeEvidenceBundle.rootDigest, bundle.rootDigest);

  const report = verifyMandateBoundCasePack(pack, anchors);
  assert.equal(report.valid, true);
  assert.equal(report.integrityStatus, "satisfied");
  assert.equal(report.coverageStatus, "satisfied");
  assert.equal(report.sourceTruthStatus, "unknown");
  assert.equal(report.upstreamValidStatus, "satisfied");
  assert.equal(report.evidenceEligibilityStatus, "satisfied");
  assert.equal(report.globalCompleteness, "not-established");
  assert.equal(report.nativeBundle.valid, true);
  assert.ok(report.envelopes.every((item) => item.evidenceEligible));
});

test("canonical CasePack bytes round-trip without a transport-token layer", () => {
  const { pack, anchors } = fixture();
  const bytes = canonicalBytes(pack, { maxBytes: 16_777_216, maxDepth: 48, maxNodes: 250_000 });
  const parsed = parseStrictJsonObject(bytes.toString("utf8"), {
    maxBytes: 16_777_216,
    maxDepth: 48,
    maxArrayLength: 10_000,
    maxObjectKeys: 10_000,
    maxStringBytes: 262_144,
    maxNodes: 250_000,
  });
  assert.deepEqual(canonicalBytes(parsed, { maxBytes: 16_777_216, maxDepth: 48, maxNodes: 250_000 }), bytes);
  assert.equal(verifyMandateBoundCasePack(parsed, anchors).valid, true);
});

test("CasePack tooling unpacks only integrity-comparable packs", () => {
  const { pack, anchors } = fixture();
  const valid = unpackMandateBoundCasePack(pack, anchors);
  assert.equal(valid.unpacked, true);
  assert.equal(valid.verification.valid, true);
  assert.equal(valid.contents?.casePackId, pack.casePackId);
  assert.equal(valid.contents?.casePackDigest, pack.casePackDigest);
  assert.deepEqual(valid.contents?.nativeEvidenceBundle, pack.nativeEvidenceBundle);
  assert.deepEqual(valid.contents?.protocolEvidence, pack.protocolEvidence);
  assert.deepEqual(valid.contents?.delegationContext, pack.delegationContext);
  assert.deepEqual(valid.contents?.coverageContract, pack.coverageContract);
  assert.deepEqual(valid.contents?.sourceCheckpoints, pack.sourceCheckpoints);
  assert.equal(Object.hasOwn(valid.contents, "externalTrustSnapshot"), false);

  const externalTrustSnapshot = sealExternalTrustSnapshot({
    format: "MandateBoundExternalTrustSnapshot/v1",
    snapshotId: "external.unpack",
    issuedAt: "2026-07-22T00:00:00.000Z",
    expiresAt: "2027-07-22T00:00:00.000Z",
    trustEffect: "discovery_only",
    nativeTrustPromotion: "forbidden",
    discoveryMaterials: [],
    keys: [],
  });
  const externalPack = resealPack({ ...pack, externalTrustSnapshot });
  const external = unpackMandateBoundCasePack(externalPack, {
    ...anchors,
    externalTrustSnapshotDigest: externalTrustSnapshot.snapshotDigest,
  });
  assert.equal(external.unpacked, true);
  assert.deepEqual(external.contents?.externalTrustSnapshot, externalTrustSnapshot);

  const invalidPack = structuredClone(pack);
  invalidPack.casePackDigest = sha256Digest("tampered-casepack");
  const invalid = unpackMandateBoundCasePack(invalidPack, anchors);
  assert.equal(invalid.unpacked, false);
  assert.equal(invalid.contents, undefined);
  assert.equal(invalid.verification.integrityStatus, "conflicting");
});

test("CasePack diff distinguishes unchanged, changed, and noncomparable inputs", () => {
  const base = fixture();
  const unchanged = diffMandateBoundCasePacks(
    base.pack,
    base.anchors,
    structuredClone(base.pack),
    base.anchors,
  );
  assert.equal(unchanged.comparable, true);
  assert.equal(unchanged.changed, false);
  assert.equal(unchanged.nativeBundleChanged, false);
  assert.equal(unchanged.coverageContractChanged, false);
  assert.equal(unchanged.delegationContextChanged, false);
  assert.equal(unchanged.externalTrustSnapshotChanged, false);
  assert.equal(unchanged.statusChanged, false);
  assert.deepEqual(unchanged.artifacts, []);

  const checkpoint = sealSourceCheckpoint({
    format: "MandateBoundSourceCheckpoint/v1",
    checkpointId: "checkpoint.diff-added",
    sourceId: "source.alpha",
    epoch: "epoch.diff",
    issuedAt: "2026-07-22T12:01:00.000Z",
    windowStart: "2026-07-22T12:00:00.000Z",
    windowEnd: "2026-07-22T12:00:00.000Z",
    firstSequence: 0,
    lastSequence: 0,
    eventCount: 1,
    merkleRoot: computeSourceEvidenceLeaf(base.alpha, 0),
    declaredGaps: [],
  });
  const changedPack = resealPack({
    ...base.pack,
    sourceCheckpoints: [checkpoint],
  });
  const changed = diffMandateBoundCasePacks(
    base.pack,
    base.anchors,
    changedPack,
    base.anchors,
  );
  assert.equal(changed.comparable, true);
  assert.equal(changed.changed, true);
  assert.equal(changed.nativeBundleChanged, false);
  assert.equal(changed.coverageContractChanged, false);
  assert.equal(changed.delegationContextChanged, false);
  assert.equal(changed.statusChanged, false);
  assert.deepEqual(changed.artifacts, [{
    kind: "source_checkpoint",
    id: checkpoint.checkpointId,
    change: "added",
    afterDigest: checkpoint.checkpointDigest,
  }]);

  const invalidAfter = structuredClone(changedPack);
  invalidAfter.casePackDigest = sha256Digest("not-comparable");
  const noncomparable = diffMandateBoundCasePacks(
    base.pack,
    base.anchors,
    invalidAfter,
    base.anchors,
  );
  assert.equal(noncomparable.comparable, false);
  assert.equal(noncomparable.changed, false);
  assert.deepEqual(noncomparable.artifacts, []);
  assert.equal(noncomparable.statusChanged, true);

  assert.ok(compareCasePackStatus("satisfied", "unknown") < 0);
  assert.ok(compareCasePackStatus("conflicting", "missing") > 0);
  assert.equal(compareCasePackStatus("not_applicable", "not_applicable"), 0);
});

test("CasePack diff reports sorted added, removed, and modified artifact identities", () => {
  const base = fixture();
  const changedAlpha = sealProtocolEvidenceEnvelope({
    ...base.alpha,
    capturedAt: "2026-07-22T12:00:00.001Z",
    envelopeDigest: undefined,
  });
  const added = sealProtocolEvidenceEnvelope({
    ...base.beta,
    envelopeId: "envelope.aardvark",
    rawEvidence: rawDescriptor("raw.added", Buffer.from("added", "utf8")),
    mapping: sealDeterministicMappingTrace({
      ...base.beta.mapping,
      inputDigest: sha256Bytes(Buffer.from("added", "utf8")),
      traceDigest: undefined,
    }),
    envelopeDigest: undefined,
  });
  const after = resealPack({
    ...base.pack,
    protocolEvidence: [added, changedAlpha],
  });
  const afterAnchors = {
    ...base.anchors,
    rawEvidence: [
      { referenceId: "raw.added", bytes: Buffer.from("added", "utf8") },
      { referenceId: "raw.alpha", bytes: RAW_ALPHA },
    ],
  };
  const diff = diffMandateBoundCasePacks(base.pack, base.anchors, after, afterAnchors);
  assert.equal(diff.comparable, true);
  assert.equal(diff.changed, true);
  assert.deepEqual(
    diff.artifacts.map((item) => [item.kind, item.id, item.change]),
    [
      ["protocol_evidence", "envelope.aardvark", "added"],
      ["protocol_evidence", "envelope.alpha", "modified"],
      ["protocol_evidence", "envelope.beta", "removed"],
    ],
  );
});

test("CLI builds, verifies, unpacks, diffs, and renders a CasePack with base64 raw evidence", async () => {
  const base = fixture();
  const { casePackDigest: _ignored, ...material } = base.pack;
  const built = await invokeCasePackCli(
    ["casepack", "build", "-"],
    { casePack: material },
  );
  assert.equal(built.code, CLI_EXIT.SUCCESS);
  assert.equal(built.stderr, "");
  const builtBody = JSON.parse(built.stdout);
  assert.equal(builtBody.ok, true);
  assert.deepEqual(builtBody.result, base.pack);

  const invocation = {
    casePack: builtBody.result,
    anchors: cliAnchors(base.anchors),
  };
  const verified = await invokeCasePackCli(["casepack", "verify", "-"], invocation);
  assert.equal(verified.code, CLI_EXIT.SUCCESS);
  assert.equal(verified.stderr, "");
  assert.equal(JSON.parse(verified.stdout).result.valid, true);

  const unpacked = await invokeCasePackCli(["casepack", "unpack", "-"], invocation);
  assert.equal(unpacked.code, CLI_EXIT.SUCCESS);
  assert.equal(unpacked.stderr, "");
  assert.equal(JSON.parse(unpacked.stdout).result.unpacked, true);
  assert.equal(JSON.parse(unpacked.stdout).result.contents.casePackDigest, base.pack.casePackDigest);

  const diffed = await invokeCasePackCli(["casepack", "diff", "-"], {
    before: invocation,
    after: invocation,
  });
  assert.equal(diffed.code, CLI_EXIT.SUCCESS);
  assert.equal(diffed.stderr, "");
  assert.equal(JSON.parse(diffed.stdout).result.comparable, true);
  assert.equal(JSON.parse(diffed.stdout).result.changed, false);

  const html = await invokeCasePackCli(
    ["case-report", "-", "--format", "html"],
    invocation,
  );
  assert.equal(html.code, CLI_EXIT.SUCCESS);
  assert.equal(html.stderr, "");
  assert.equal(html.stdout.startsWith("<!doctype html>"), true);
  assert.equal(html.stdout.includes(base.pack.casePackId), true);
  assert.equal(html.stdout.includes(RAW_ALPHA.toString("utf8")), false);
  assert.equal(html.stdout.includes(RAW_BETA.toString("utf8")), false);

  const invalidInvocation = structuredClone(invocation);
  invalidInvocation.anchors.rawEvidence[0].bytesBase64 = Buffer
    .from("one-byte-different", "utf8")
    .toString("base64");
  const invalid = await invokeCasePackCli(
    ["casepack", "verify", "-"],
    invalidInvocation,
  );
  assert.equal(invalid.code, CLI_EXIT.INVALID);
  assert.equal(invalid.stderr, "");
  assert.equal(JSON.parse(invalid.stdout).ok, false);
  assert.equal(invalid.stdout.includes("one-byte-different"), false);
});

test("case reports use deterministic ordering and exact CasePack binding", () => {
  const base = fixture();
  const reversedContract = sealEvidenceCoverageContract({
    ...base.coverageContract,
    requirements: [...base.coverageContract.requirements].reverse(),
    contractDigest: undefined,
  });
  const reversedPack = resealPack({
    ...base.pack,
    protocolEvidence: [...base.pack.protocolEvidence].reverse(),
    coverageContract: reversedContract,
  });
  const anchors = {
    ...base.anchors,
    coverageContractDigest: reversedContract.contractDigest,
  };
  const first = createCaseReport(reversedPack, anchors);
  const second = createCaseReport(reversedPack, anchors);
  assert.equal(JSON.stringify(second), JSON.stringify(first));
  assert.deepEqual(first.coverage.map((item) => item.requirementId), [
    "requirement.alpha",
    "requirement.beta",
  ]);
  assert.deepEqual(first.envelopes.map((item) => item.envelopeId), [
    "envelope.alpha",
    "envelope.beta",
  ]);
  assert.equal(first.legalEffect, "not-determined");
  assert.equal(first.globalCompleteness, "not-established");
  assert.equal(isCaseReportFor(first, reversedPack), true);
  assert.equal(isCaseReportFor(
    { ...first, casePackDigest: sha256Digest("other") },
    reversedPack,
  ), false);
  assert.equal(isCaseReportFor(
    { ...first, casePackId: "casepack.other" },
    reversedPack,
  ), false);
});

test("static CasePack HTML escapes report strings and contains no raw evidence", () => {
  const base = fixture();
  const report = createCaseReport(base.pack, base.anchors);
  const hostile = "<img src=x onerror=alert(1)>";
  const rendered = renderCaseReportHtml({
    ...report,
    casePackId: hostile,
    assessedAt: `"${hostile}`,
    coverage: [{
      ...report.coverage[0],
      requirementId: hostile,
    }],
    envelopes: [{
      ...report.envelopes[0],
      envelopeId: hostile,
    }],
    findings: [{
      code: hostile,
      path: hostile,
      message: hostile,
    }],
  });
  assert.equal(rendered.startsWith("<!doctype html>"), true);
  assert.equal(rendered.includes(hostile), false);
  assert.equal(rendered.includes("&lt;img src=x onerror=alert(1)&gt;"), true);
  assert.equal(rendered.includes(RAW_ALPHA.toString("utf8")), false);
  assert.equal(rendered.includes(RAW_BETA.toString("utf8")), false);
  assert.equal(rendered.includes("<script"), false);
  assert.equal(rendered.includes("http://"), false);
  assert.equal(rendered.includes("https://"), false);
  assert.equal(rendered.includes("Global completeness is not established"), true);

  const emptyRendered = renderCaseReportHtml({
    ...report,
    casePackId: undefined,
    casePackDigest: undefined,
    coverage: [],
    envelopes: [],
    findings: [],
  });
  assert.equal(emptyRendered.includes("unidentified-casepack"), true);
  assert.equal(emptyRendered.includes("No applicable coverage requirements were reported."), true);
  assert.equal(emptyRendered.includes("No protocol evidence envelopes were reported."), true);
  assert.equal(emptyRendered.includes("No verifier findings."), true);

  const invalidPack = structuredClone(base.pack);
  invalidPack.casePackDigest = sha256Digest("invalid-report");
  const invalidReport = createCaseReport(invalidPack, base.anchors);
  assert.ok(invalidReport.findings.length > 0);
  const invalidHtml = renderCaseReportHtml(invalidReport);
  assert.equal(invalidHtml.includes("CasePack digest does not match"), true);
  assert.equal(invalidHtml.includes(RAW_ALPHA.toString("utf8")), false);
});

test("one-byte raw source mutation fails closed without echoing evidence", () => {
  const { pack, anchors } = fixture();
  const mutated = Buffer.from(RAW_ALPHA);
  mutated[0] = mutated[0] === 0x7b ? 0x5b : 0x7b;
  const report = verifyMandateBoundCasePack(pack, {
    ...anchors,
    rawEvidence: [
      { referenceId: "raw.alpha", bytes: mutated },
      { referenceId: "raw.beta", bytes: RAW_BETA },
    ],
  });
  assert.equal(report.valid, false);
  assert.equal(report.integrityStatus, "conflicting");
  assert.equal(report.envelopes.find((item) => item.envelopeId === "envelope.alpha")?.evidenceEligible, false);
  const diagnostics = report.issues.map((issue) => issue.message).join(" ");
  assert.equal(diagnostics.includes(RAW_ALPHA.toString("utf8")), false);
  assert.equal(diagnostics.includes(mutated.toString("utf8")), false);
});

test("trusted contract pin rejects a structurally valid weakened contract", () => {
  const { pack, anchors } = fixture();
  const weakened = sealEvidenceCoverageContract({
    ...pack.coverageContract,
    requirements: [pack.coverageContract.requirements[0]],
    contractDigest: undefined,
  });
  const candidate = resealPack({ ...pack, coverageContract: weakened });
  const report = verifyMandateBoundCasePack(candidate, anchors);
  assert.equal(report.valid, false);
  assert.equal(report.coverageStatus, "conflicting");
  assert.ok(report.issues.some((issue) => issue.code === "MBCP_COVERAGE_PIN_MISMATCH"));
});

test("omitted required source is reported as bounded coverage missing", () => {
  const { pack, anchors } = fixture();
  const candidate = resealPack({
    ...pack,
    protocolEvidence: [pack.protocolEvidence[0]],
  });
  const report = verifyMandateBoundCasePack(candidate, {
    ...anchors,
    rawEvidence: [{ referenceId: "raw.alpha", bytes: RAW_ALPHA }],
  });
  assert.equal(report.valid, false);
  assert.equal(report.integrityStatus, "satisfied");
  assert.equal(report.coverageStatus, "missing");
  assert.equal(report.requirements.find((item) => item.requirementId === "requirement.beta")?.status, "missing");
  assert.equal(report.globalCompleteness, "not-established");
});

test("equivocating source checkpoints are conflicting, not complete", () => {
  const base = fixture();
  const firstRoot = computeSourceEvidenceLeaf(base.alpha, 0);
  const first = sealSourceCheckpoint({
    format: "MandateBoundSourceCheckpoint/v1",
    checkpointId: "checkpoint.alpha.1",
    sourceId: "source.alpha",
    epoch: "epoch.1",
    issuedAt: "2026-07-22T12:01:00.000Z",
    windowStart: "2026-07-22T12:00:00.000Z",
    windowEnd: "2026-07-22T12:00:00.000Z",
    firstSequence: 0,
    lastSequence: 0,
    eventCount: 1,
    merkleRoot: firstRoot,
    declaredGaps: [],
  });
  const second = sealSourceCheckpoint({
    format: "MandateBoundSourceCheckpoint/v1",
    checkpointId: "checkpoint.alpha.2",
    sourceId: "source.alpha",
    epoch: "epoch.1",
    issuedAt: "2026-07-22T12:01:00.000Z",
    windowStart: "2026-07-22T12:00:00.000Z",
    windowEnd: "2026-07-22T12:00:00.000Z",
    firstSequence: 0,
    lastSequence: 0,
    eventCount: 1,
    merkleRoot: sha256Digest({ equivocation: true }),
    declaredGaps: [],
  });
  const alphaRequirement = {
    ...base.coverageContract.requirements[0],
    checkpointRequirement: "required",
    maxCheckpointAgeSeconds: 86_400,
  };
  const contract = sealEvidenceCoverageContract({
    ...base.coverageContract,
    requirements: [alphaRequirement, base.coverageContract.requirements[1]],
    contractDigest: undefined,
  });
  const candidate = resealPack({
    ...base.pack,
    coverageContract: contract,
    sourceCheckpoints: [first, second],
  });
  const report = verifyMandateBoundCasePack(candidate, {
    ...base.anchors,
    coverageContractDigest: contract.contractDigest,
  });
  assert.equal(report.valid, false);
  assert.equal(report.coverageStatus, "conflicting");
  assert.ok(report.issues.some((issue) => issue.code === "MBCP_CHECKPOINT_EQUIVOCATION"));
});

test("caller-pinned external trust verifies a signed source checkpoint without entering native trust", () => {
  const base = fixture();
  const withInclusion = sealProtocolEvidenceEnvelope({
    ...base.alpha,
    checkpointInclusion: {
      checkpointId: "checkpoint.alpha.signed",
      sequence: 0,
      leafIndex: 0,
      treeSize: 1,
      auditPath: [],
    },
    envelopeDigest: undefined,
  });
  const unsigned = sealSourceCheckpoint({
    format: "MandateBoundSourceCheckpoint/v1",
    checkpointId: "checkpoint.alpha.signed",
    sourceId: "source.alpha",
    epoch: "epoch.signed",
    issuedAt: "2026-07-22T12:01:00.000Z",
    windowStart: "2026-07-22T12:00:00.000Z",
    windowEnd: "2026-07-22T12:00:00.000Z",
    firstSequence: 0,
    lastSequence: 0,
    eventCount: 1,
    merkleRoot: computeSourceEvidenceLeaf(withInclusion, 0),
    declaredGaps: [],
  });
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const keyId = "external.checkpoint-key.1";
  const checkpoint = {
    ...unsigned,
    proofs: [createSourceCheckpointProof(unsigned, privateKey, keyId)],
  };
  const externalTrustSnapshot = sealExternalTrustSnapshot({
    format: "MandateBoundExternalTrustSnapshot/v1",
    snapshotId: "external.snapshot.signed",
    issuedAt: "2026-07-22T00:00:00.000Z",
    expiresAt: "2027-07-22T00:00:00.000Z",
    trustEffect: "discovery_only",
    nativeTrustPromotion: "forbidden",
    discoveryMaterials: [],
    keys: [{
      keyId,
      sourceId: "source.alpha",
      publicJwk: exportPublicJwk(publicKey),
      purposes: ["source_checkpoint"],
      validFrom: "2026-07-22T00:00:00.000Z",
      validUntil: "2027-07-22T00:00:00.000Z",
    }],
  });
  const contract = sealEvidenceCoverageContract({
    ...base.coverageContract,
    requirements: [{
      ...base.coverageContract.requirements[0],
      checkpointRequirement: "required",
      maxCheckpointAgeSeconds: 86_400,
    }, base.coverageContract.requirements[1]],
    contractDigest: undefined,
  });
  const candidate = resealPack({
    ...base.pack,
    protocolEvidence: [withInclusion, base.beta],
    externalTrustSnapshot,
    coverageContract: contract,
    sourceCheckpoints: [checkpoint],
  });
  const anchors = {
    ...base.anchors,
    coverageContractDigest: contract.contractDigest,
    externalTrustSnapshotDigest: externalTrustSnapshot.snapshotDigest,
  };
  const report = verifyMandateBoundCasePack(candidate, anchors);
  assert.equal(report.valid, true);
  assert.equal(report.externalTrustStatus, "satisfied");
  assert.equal(report.coverageStatus, "satisfied");
  assert.equal(report.nativeBundle.trustChecked, false);

  const lateKeySnapshot = sealExternalTrustSnapshot({
    ...externalTrustSnapshot,
    keys: [{
      ...externalTrustSnapshot.keys[0],
      validFrom: "2026-07-22T13:00:00.000Z",
    }],
    snapshotDigest: undefined,
  });
  const lateKeyReport = verifyMandateBoundCasePack(
    resealPack({ ...candidate, externalTrustSnapshot: lateKeySnapshot }),
    {
      ...anchors,
      externalTrustSnapshotDigest: lateKeySnapshot.snapshotDigest,
    },
  );
  assert.equal(lateKeyReport.valid, false);
  assert.equal(lateKeyReport.coverageStatus, "conflicting");

  const futureUnsigned = sealSourceCheckpoint({
    ...unsigned,
    issuedAt: "2026-07-24T00:00:00.000Z",
    checkpointDigest: undefined,
  });
  const futureCheckpoint = {
    ...futureUnsigned,
    proofs: [createSourceCheckpointProof(futureUnsigned, privateKey, keyId)],
  };
  const futureReport = verifyMandateBoundCasePack(
    resealPack({ ...candidate, sourceCheckpoints: [futureCheckpoint] }),
    anchors,
  );
  assert.equal(futureReport.valid, false);
  assert.equal(futureReport.coverageStatus, "missing");

  const excludedUnsigned = sealSourceCheckpoint({
    ...unsigned,
    windowStart: "2026-07-22T12:00:01.000Z",
    windowEnd: "2026-07-22T12:00:01.000Z",
    checkpointDigest: undefined,
  });
  const excludedCheckpoint = {
    ...excludedUnsigned,
    proofs: [createSourceCheckpointProof(excludedUnsigned, privateKey, keyId)],
  };
  const excludedReport = verifyMandateBoundCasePack(
    resealPack({ ...candidate, sourceCheckpoints: [excludedCheckpoint] }),
    anchors,
  );
  assert.equal(excludedReport.valid, false);
  assert.equal(excludedReport.coverageStatus, "conflicting");

  const altered = structuredClone(checkpoint);
  const alteredSignature = Buffer.from(altered.proofs[0].signature, "base64url");
  alteredSignature[0] ^= 1;
  altered.proofs[0].signature = alteredSignature.toString("base64url");
  const rejected = verifyMandateBoundCasePack(
    resealPack({ ...candidate, sourceCheckpoints: [altered] }),
    anchors,
  );
  assert.equal(rejected.valid, false);
  assert.equal(rejected.coverageStatus, "conflicting");
});

test("stale external trust is not eligible and cannot promote native trust", () => {
  const base = fixture();
  const stale = sealExternalTrustSnapshot({
    format: "MandateBoundExternalTrustSnapshot/v1",
    snapshotId: "external.snapshot.1",
    issuedAt: "2026-07-20T00:00:00.000Z",
    expiresAt: "2026-07-22T00:00:00.000Z",
    trustEffect: "discovery_only",
    nativeTrustPromotion: "forbidden",
    discoveryMaterials: [],
    keys: [],
  });
  const stalePack = resealPack({ ...base.pack, externalTrustSnapshot: stale });
  const staleReport = verifyMandateBoundCasePack(stalePack, {
    ...base.anchors,
    externalTrustSnapshotDigest: stale.snapshotDigest,
  });
  assert.equal(staleReport.valid, false);
  assert.equal(staleReport.externalTrustStatus, "missing");

  const promoted = {
    ...stale,
    nativeTrustPromotion: "allowed",
  };
  const promotedPack = resealPack({ ...base.pack, externalTrustSnapshot: promoted });
  const promotedReport = verifyMandateBoundCasePack(promotedPack, {
    ...base.anchors,
    externalTrustSnapshotDigest: stale.snapshotDigest,
  });
  assert.equal(promotedReport.valid, false);
  assert.equal(promotedReport.integrityStatus, "conflicting");
  assert.ok(promotedReport.issues.some((issue) => issue.code === "MBCP_EXTERNAL_TRUST_INVALID"));
  assert.equal(promotedReport.nativeBundle.trustChecked, false);
});

test("unsafe paths, oversized media, and duplicate references reject with bounded diagnostics", () => {
  const base = fixture();

  const unsafeEnvelope = sealProtocolEvidenceEnvelope({
    ...base.alpha,
    rawEvidence: {
      ...base.alpha.rawEvidence,
      reference: {
        referenceId: "raw.alpha",
        kind: "bundle_path",
        value: "../private",
      },
    },
    envelopeDigest: undefined,
  });
  const unsafeReport = verifyMandateBoundCasePack(
    resealPack({ ...base.pack, protocolEvidence: [unsafeEnvelope, base.beta] }),
    base.anchors,
  );
  assert.equal(unsafeReport.valid, false);
  assert.ok(unsafeReport.issues.some((issue) => issue.code === "MBCP_PATH_INVALID"));

  const oversizedEnvelope = sealProtocolEvidenceEnvelope({
    ...base.alpha,
    mediaType: `application/${"x".repeat(200)}`,
    envelopeDigest: undefined,
  });
  const oversizedReport = verifyMandateBoundCasePack(
    resealPack({ ...base.pack, protocolEvidence: [oversizedEnvelope, base.beta] }),
    base.anchors,
  );
  assert.equal(oversizedReport.valid, false);

  const duplicate = sealProtocolEvidenceEnvelope({
    ...base.beta,
    rawEvidence: {
      ...base.beta.rawEvidence,
      reference: base.alpha.rawEvidence.reference,
    },
    envelopeDigest: undefined,
  });
  const duplicateReport = verifyMandateBoundCasePack(
    resealPack({ ...base.pack, protocolEvidence: [base.alpha, duplicate] }),
    base.anchors,
  );
  assert.equal(duplicateReport.valid, false);
  assert.ok(duplicateReport.issues.length <= 128);
});

test("closed-shape validators fail safely across every CasePack artifact layer", () => {
  const base = fixture();
  const validCheckpoint = sealSourceCheckpoint({
    format: "MandateBoundSourceCheckpoint/v1",
    checkpointId: "checkpoint.validation",
    sourceId: "source.alpha",
    epoch: "epoch.validation",
    issuedAt: "2026-07-22T12:01:00.000Z",
    windowStart: "2026-07-22T12:00:00.000Z",
    windowEnd: "2026-07-22T12:00:00.000Z",
    firstSequence: 0,
    lastSequence: 0,
    eventCount: 1,
    merkleRoot: computeSourceEvidenceLeaf(base.alpha, 0),
    declaredGaps: [],
  });
  const { publicKey } = generateKeyPairSync("ed25519");
  const validExternal = sealExternalTrustSnapshot({
    format: "MandateBoundExternalTrustSnapshot/v1",
    snapshotId: "external.validation",
    issuedAt: "2026-07-22T00:00:00.000Z",
    expiresAt: "2027-07-22T00:00:00.000Z",
    trustEffect: "discovery_only",
    nativeTrustPromotion: "forbidden",
    discoveryMaterials: [{
      materialId: "material.validation",
      mediaType: "application/json",
      rawEvidence: base.alpha.rawEvidence,
    }],
    keys: [{
      keyId: "external.validation-key",
      sourceId: "source.alpha",
      publicJwk: exportPublicJwk(publicKey),
      purposes: ["source_checkpoint"],
      validFrom: "2026-07-22T00:00:00.000Z",
      validUntil: "2027-07-22T00:00:00.000Z",
    }],
  });
  const malformed = [
    ["outer unknown field", (pack) => { pack.unexpected = true; }],
    ["outer metadata", (pack) => { pack.format = "CasePack/other"; }],
    ["native bundle", (pack) => { pack.nativeEvidenceBundle = {}; }],
    ["protocol list", (pack) => { pack.protocolEvidence = []; }],
    ["envelope shape", (pack) => { pack.protocolEvidence[0] = null; }],
    ["envelope unknown field", (pack) => { pack.protocolEvidence[0].unexpected = true; }],
    ["envelope identity", (pack) => { pack.protocolEvidence[0].sourceId = "#"; }],
    ["envelope timestamp", (pack) => { pack.protocolEvidence[0].capturedAt = "invalid"; }],
    ["envelope upstream flag", (pack) => { pack.protocolEvidence[0].upstreamValid = "yes"; }],
    ["envelope digest", (pack) => { pack.protocolEvidence[0].envelopeDigest = sha256Digest("wrong"); }],
    ["raw shape", (pack) => { pack.protocolEvidence[0].rawEvidence = null; }],
    ["raw digest", (pack) => { pack.protocolEvidence[0].rawEvidence.digest = "sha256:no"; }],
    ["raw size", (pack) => { pack.protocolEvidence[0].rawEvidence.byteLength = 16_777_217; }],
    ["reference shape", (pack) => { pack.protocolEvidence[0].rawEvidence.reference = null; }],
    ["reference identity", (pack) => { pack.protocolEvidence[0].rawEvidence.reference.referenceId = "#"; }],
    ["reference kind", (pack) => { pack.protocolEvidence[0].rawEvidence.reference.kind = "network"; }],
    ["reference digest", (pack) => { pack.protocolEvidence[0].rawEvidence.reference.value = `urn:sha256:${"0".repeat(64)}`; }],
    ["mapping shape", (pack) => { pack.protocolEvidence[0].mapping = null; }],
    ["mapping identity", (pack) => { pack.protocolEvidence[0].mapping.mapperVersion = "latest"; }],
    ["mapping digest", (pack) => { pack.protocolEvidence[0].mapping.mappingPolicyDigest = "sha256:no"; }],
    ["mapping outputs empty", (pack) => { pack.protocolEvidence[0].mapping.outputArtifacts = []; }],
    ["mapping output shape", (pack) => { pack.protocolEvidence[0].mapping.outputArtifacts = [null]; }],
    ["mapping output duplicate", (pack) => {
      pack.protocolEvidence[0].mapping.outputArtifacts.push(
        structuredClone(pack.protocolEvidence[0].mapping.outputArtifacts[0]),
      );
    }],
    ["mapping steps empty", (pack) => { pack.protocolEvidence[0].mapping.steps = []; }],
    ["mapping step shape", (pack) => { pack.protocolEvidence[0].mapping.steps = [null]; }],
    ["mapping step order", (pack) => { pack.protocolEvidence[0].mapping.steps[0].index = 1; }],
    ["mapping pointer", (pack) => { pack.protocolEvidence[0].mapping.steps[0].inputPointer = "/bad~pointer"; }],
    ["mapping status", (pack) => { pack.protocolEvidence[0].mapping.steps[0].status = "passed"; }],
    ["mapping trace digest", (pack) => { pack.protocolEvidence[0].mapping.traceDigest = sha256Digest("wrong"); }],
    ["inclusion shape", (pack) => { pack.protocolEvidence[0].checkpointInclusion = null; }],
    ["inclusion bounds", (pack) => {
      pack.protocolEvidence[0].checkpointInclusion = {
        checkpointId: "checkpoint.invalid",
        sequence: -1,
        leafIndex: 4_096,
        treeSize: 0,
        auditPath: ["sha256:no"],
      };
    }],
    ["external shape", (pack) => { pack.externalTrustSnapshot = null; }],
    ["external trust effect", (pack) => {
      pack.externalTrustSnapshot = structuredClone(validExternal);
      pack.externalTrustSnapshot.trustEffect = "native";
    }],
    ["external interval", (pack) => {
      pack.externalTrustSnapshot = structuredClone(validExternal);
      pack.externalTrustSnapshot.expiresAt = pack.externalTrustSnapshot.issuedAt;
    }],
    ["external material", (pack) => {
      pack.externalTrustSnapshot = structuredClone(validExternal);
      pack.externalTrustSnapshot.discoveryMaterials = [null];
    }],
    ["external material metadata", (pack) => {
      pack.externalTrustSnapshot = structuredClone(validExternal);
      pack.externalTrustSnapshot.discoveryMaterials[0].mediaType = "invalid";
    }],
    ["external keys", (pack) => {
      pack.externalTrustSnapshot = structuredClone(validExternal);
      pack.externalTrustSnapshot.keys = [null];
    }],
    ["external key metadata", (pack) => {
      pack.externalTrustSnapshot = structuredClone(validExternal);
      pack.externalTrustSnapshot.keys[0].purposes = [];
    }],
    ["external key shape", (pack) => {
      pack.externalTrustSnapshot = structuredClone(validExternal);
      pack.externalTrustSnapshot.keys[0].publicJwk = {};
    }],
    ["external key material", (pack) => {
      pack.externalTrustSnapshot = structuredClone(validExternal);
      pack.externalTrustSnapshot.keys[0].publicJwk.x = "A".repeat(43);
    }],
    ["external digest", (pack) => {
      pack.externalTrustSnapshot = structuredClone(validExternal);
      pack.externalTrustSnapshot.snapshotDigest = sha256Digest("wrong");
    }],
    ["delegation shape", (pack) => { pack.delegationContext = null; }],
    ["delegation metadata", (pack) => { pack.delegationContext.delegateId = pack.delegationContext.principalId; }],
    ["delegation interval", (pack) => { pack.delegationContext.validUntil = pack.delegationContext.validFrom; }],
    ["delegation evidence shape", (pack) => { pack.delegationContext.evidenceReferences = [null]; }],
    ["delegation digest", (pack) => { pack.delegationContext.contextDigest = sha256Digest("wrong"); }],
    ["coverage shape", (pack) => { pack.coverageContract = null; }],
    ["coverage metadata", (pack) => { pack.coverageContract.coverageScope = "global"; }],
    ["coverage interval", (pack) => { pack.coverageContract.validUntil = pack.coverageContract.validFrom; }],
    ["coverage requirements empty", (pack) => { pack.coverageContract.requirements = []; }],
    ["coverage requirement shape", (pack) => { pack.coverageContract.requirements[0] = null; }],
    ["coverage selector duplicate", (pack) => {
      const duplicate = structuredClone(pack.coverageContract.requirements[0]);
      duplicate.requirementId = "requirement.duplicate";
      pack.coverageContract.requirements.push(duplicate);
    }],
    ["coverage window", (pack) => {
      pack.coverageContract.requirements[0].windowStart = "2026-07-23T00:00:00.000Z";
    }],
    ["coverage media types", (pack) => {
      pack.coverageContract.requirements[0].mediaTypes = ["text/plain", "application/json"];
    }],
    ["coverage checkpoint not applicable", (pack) => {
      pack.coverageContract.requirements[0].maxCheckpointAgeSeconds = 1;
    }],
    ["coverage checkpoint bound missing", (pack) => {
      pack.coverageContract.requirements[0].checkpointRequirement = "required";
    }],
    ["coverage digest", (pack) => { pack.coverageContract.contractDigest = sha256Digest("wrong"); }],
    ["checkpoint shape", (pack) => { pack.sourceCheckpoints = [null]; }],
    ["checkpoint unknown field", (pack) => {
      pack.sourceCheckpoints = [structuredClone(validCheckpoint)];
      pack.sourceCheckpoints[0].unexpected = true;
    }],
    ["checkpoint metadata", (pack) => {
      pack.sourceCheckpoints = [structuredClone(validCheckpoint)];
      pack.sourceCheckpoints[0].sourceId = "#";
    }],
    ["checkpoint interval", (pack) => {
      pack.sourceCheckpoints = [structuredClone(validCheckpoint)];
      pack.sourceCheckpoints[0].windowEnd = "2026-07-21T00:00:00.000Z";
    }],
    ["checkpoint sequence count", (pack) => {
      pack.sourceCheckpoints = [structuredClone(validCheckpoint)];
      pack.sourceCheckpoints[0].eventCount = 2;
    }],
    ["checkpoint gap", (pack) => {
      pack.sourceCheckpoints = [structuredClone(validCheckpoint)];
      pack.sourceCheckpoints[0].declaredGaps = [{
        fromSequence: 2,
        toSequence: 1,
        reasonCode: "gap.invalid",
      }];
    }],
    ["checkpoint proof", (pack) => {
      pack.sourceCheckpoints = [structuredClone(validCheckpoint)];
      pack.sourceCheckpoints[0].proofs = [{
        suite: "Ed25519",
        keyId: "external.invalid",
        signedDigest: validCheckpoint.checkpointDigest,
        signature: "not-a-signature",
      }];
    }],
    ["checkpoint digest", (pack) => {
      pack.sourceCheckpoints = [structuredClone(validCheckpoint)];
      pack.sourceCheckpoints[0].checkpointDigest = sha256Digest("wrong");
    }],
    ["checkpoint duplicate", (pack) => {
      pack.sourceCheckpoints = [structuredClone(validCheckpoint), structuredClone(validCheckpoint)];
    }],
  ];

  for (const [name, mutate] of malformed) {
    const candidate = structuredClone(base.pack);
    mutate(candidate);
    const report = verifyMandateBoundCasePack(resealPack(candidate), base.anchors);
    assert.equal(report.valid, false, name);
    assert.ok(report.issues.length > 0, name);
    assert.ok(report.issues.length <= 128, name);
  }

  assert.equal(verifyMandateBoundCasePack(null, base.anchors).valid, false);
  assert.equal(verifyMandateBoundCasePack({}, base.anchors).valid, false);
});

test("strict JSON rejects duplicate CasePack fields before verification", () => {
  const duplicate = `{"format":"MandateBoundCasePack/v1","format":"other"}`;
  assert.throws(
    () => parseStrictJsonObject(duplicate),
    (error) => error instanceof StrictJsonError && error.code === "ALB_JSON_DUPLICATE_KEY",
  );
});

test("v1.1 schemas compile and validate the canonical CasePack", () => {
  const schemaNames = [
    "common.schema.json",
    "protocol-evidence-envelope.schema.json",
    "external-trust-snapshot.schema.json",
    "delegation-context.schema.json",
    "evidence-coverage-contract.schema.json",
    "source-checkpoint.schema.json",
    "case-pack.schema.json",
  ];
  const schemas = schemaNames.map((name) =>
    JSON.parse(readFileSync(new URL(`../schemas/v1.1/${name}`, import.meta.url), "utf8")));
  const v1Common = JSON.parse(readFileSync(new URL("../schemas/v1/common.schema.json", import.meta.url), "utf8"));
  const v1Bundle = JSON.parse(readFileSync(new URL("../schemas/v1/evidence-bundle.schema.json", import.meta.url), "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  ajv.addSchema(v1Common);
  ajv.addSchema(v1Bundle);
  for (const schema of schemas) ajv.addSchema(schema);
  const validate = ajv.getSchema("https://github.com/Oonyl/mandatebound/schemas/v1.1/case-pack.schema.json");
  assert.ok(validate);
  assert.equal(validate(fixture().pack), true, JSON.stringify(validate.errors));
});
