import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import { runCli } from "../dist/cli.js";
import { operatorFixture } from "./fixtures/operator-fixture.mjs";
import * as sdk from "../dist/index.js";

function input(fixture = operatorFixture()) {
  return { casePack: fixture.pack, anchors: fixture.anchors };
}

function repack(value, changes) {
  const { casePackDigest: _ignored, ...material } = value.casePack;
  return { ...value, casePack: sdk.createMandateBoundCasePack({ ...material, ...changes }) };
}

function envelope(item, changes) {
  const { envelopeDigest: _ignored, ...material } = item;
  return sdk.sealProtocolEvidenceEnvelope({ ...material, ...changes });
}

function jsonInput(value) {
  return JSON.parse(JSON.stringify(value, (_key, item) => item instanceof Uint8Array ? { data: [...item] } : item),
    (_key, item) => item?.referenceId && item.bytes?.data
      ? { referenceId: item.referenceId, bytesBase64: Buffer.from(item.bytes.data).toString("base64") } : item);
}

async function cli(action, value) {
  let output = "";
  const code = await runCli(["operator", action], { stdin: Readable.from([JSON.stringify(jsonInput(value))]),
    stdout: new Writable({ write(chunk, _encoding, next) { output += chunk; next(); } }),
    stderr: new Writable({ write(_chunk, _encoding, next) { next(); } }) });
  return { code, body: JSON.parse(output) };
}

test("collection plan requests missing bytes once and rejects conflicting descriptors", async () => {
  const value = input();
  assert.equal(typeof sdk.planCaseCollection, "function");
  const ready = sdk.planCaseCollection(value);
  assert.equal(ready.requests.length, 2);
  assert.ok(ready.requests.every((item) => item.status === "supplied"));
  assert.equal(ready.needsCollection, false);
  const missing = { ...value, anchors: { ...value.anchors, rawEvidence: [] } };
  assert.ok(sdk.planCaseCollection(missing).requests.every((item) => item.status === "missing"));
  assert.equal((await cli("collect", missing)).code, 3);
  assert.equal((await cli("collect", value)).code, 0);
  assert.deepEqual(sdk.planCaseCollection({ ...value, casePack: null }).requests, []);
  const wrong = { ...value, anchors: { ...value.anchors, rawEvidence: [{ referenceId: "raw.alpha", bytes: new Uint8Array([0]) }] } };
  assert.equal(sdk.planCaseCollection(wrong).requests[0].status, "mismatched");
  assert.throws(() => sdk.planCaseCollection({ ...value, anchors: { ...value.anchors, rawEvidence: [value.anchors.rawEvidence[0], value.anchors.rawEvidence[0]] } }));
  const { contextDigest: _ignored, ...delegation } = value.casePack.delegationContext;
  const descriptor = value.casePack.protocolEvidence[0].rawEvidence;
  const shared = repack(value, { delegationContext: sdk.sealDelegationContext({ ...delegation,
    evidenceReferences: [{ digest: descriptor.digest, reference: descriptor.reference }] }) });
  assert.equal(sdk.planCaseCollection(shared).requests[0].consumers.length, 2);
  const conflicting = repack(value, { delegationContext: sdk.sealDelegationContext({ ...delegation,
    evidenceReferences: [{ digest: "sha256:" + "0".repeat(64), reference: { ...descriptor.reference, value: "urn:sha256:" + "0".repeat(64) } }] }) });
  assert.equal(sdk.planCaseCollection(conflicting).requests[0].status, "conflicting");
  const discovery = sdk.sealExternalTrustSnapshot({ format: "MandateBoundExternalTrustSnapshot/v1",
    snapshotId: "snapshot.one", issuedAt: value.anchors.asOf, expiresAt: "2027-07-23T00:00:00.000Z",
    trustEffect: "discovery_only", nativeTrustPromotion: "forbidden", keys: [],
    discoveryMaterials: [{ materialId: "discovery.one", mediaType: "application/json", rawEvidence: descriptor }] });
  const discovered = repack(value, { externalTrustSnapshot: discovery });
  assert.equal(sdk.planCaseCollection(discovered).requests[0].consumers.some((item) => item.kind === "discovery"), true);
});

test("source rollup retains missing declared sources and never counts invalid envelopes as eligible", async () => {
  const value = input();
  assert.equal(typeof sdk.summarizeCaseSources, "function");
  const missing = repack(value, { protocolEvidence: value.casePack.protocolEvidence.slice(1) });
  const report = sdk.summarizeCaseSources(missing);
  assert.equal(report.sources[0].sourceId, "source.alpha");
  assert.equal(report.sources[0].envelopes, 0);
  assert.equal(report.sources[0].requirements[0].status, "missing");
  const invalid = sdk.summarizeCaseSources({ ...value, anchors: { ...value.anchors, rawEvidence: [] } });
  assert.ok(invalid.sources.every((item) => item.eligibleEnvelopes === 0));
  assert.deepEqual(sdk.summarizeCaseSources({ ...value, casePack: null }).sources, []);
  assert.equal((await cli("sources", value)).code, 0);
  assert.equal((await cli("sources", missing)).code, 3);
});

test("capture timeline orders instants, preserves ties, and flags future captures", async () => {
  const value = input();
  assert.equal(typeof sdk.createCaseCaptureTimeline, "function");
  const changed = repack(value, { protocolEvidence: [
    envelope(value.casePack.protocolEvidence[0], { capturedAt: "2026-07-24T00:00:00.000Z" }),
    value.casePack.protocolEvidence[1],
  ] });
  const report = sdk.createCaseCaptureTimeline(changed);
  assert.deepEqual(report.events.map((item) => item.envelopeId), ["envelope.beta", "envelope.alpha"]);
  assert.equal(report.events[1].afterAssessment, true);
  assert.equal(report.events[1].evidenceEligible, false);
  assert.equal(report.events[0].afterAssessment, false);
  const reverse = repack(value, { protocolEvidence: [...value.casePack.protocolEvidence].reverse() });
  assert.deepEqual(sdk.createCaseCaptureTimeline(value).events, sdk.createCaseCaptureTimeline(reverse).events);
  assert.deepEqual(sdk.createCaseCaptureTimeline({ ...value, casePack: null }).events, []);
  assert.equal((await cli("timeline", value)).code, 0);
  assert.equal((await cli("timeline", changed)).code, 3);
});

test("mapping lineage locates native artifacts, broken digests and unreferenced entries", async () => {
  const value = input();
  assert.equal(typeof sdk.traceCaseMappings, "function");
  const report = sdk.traceCaseMappings(value);
  assert.ok(report.links.every((item) => item.digestMatches));
  assert.ok(report.unreferencedPaths.length > 0);
  assert.ok(report.links.every((item) => item.mapperId === "mandatebound.test-mapper"));
  const original = value.casePack.protocolEvidence[0];
  const { traceDigest: _ignored, ...mapping } = original.mapping;
  const changed = repack(value, { protocolEvidence: [envelope(original, { mapping: sdk.sealDeterministicMappingTrace({
    ...mapping, outputArtifacts: [{ ...mapping.outputArtifacts[0], digest: "sha256:" + "0".repeat(64) }],
  }) }), value.casePack.protocolEvidence[1]] });
  assert.equal(sdk.traceCaseMappings(changed).links[0].digestMatches, false);
  assert.equal(sdk.traceCaseMappings(changed).valid, false);
  assert.deepEqual(sdk.traceCaseMappings({ ...value, casePack: null }).links, []);
  assert.equal((await cli("lineage", value)).code, 0);
  assert.equal((await cli("lineage", changed)).code, 3);
});

test("checkpoint inventory exposes declared gaps and dangling inclusion references without implying verification", async () => {
  const value = input();
  assert.equal(typeof sdk.inspectCaseCheckpoints, "function");
  const checkpoint = sdk.sealSourceCheckpoint({ format: "MandateBoundSourceCheckpoint/v1",
    checkpointId: "checkpoint.one", sourceId: "source.alpha", epoch: "epoch.one",
    issuedAt: "2026-07-22T12:01:00.000Z", windowStart: "2026-07-22T12:00:00.000Z",
    windowEnd: "2026-07-22T12:00:00.000Z", firstSequence: 0, lastSequence: 2,
    eventCount: 3, merkleRoot: sdk.computeSourceEvidenceLeaf(value.casePack.protocolEvidence[0], 0),
    declaredGaps: [{ fromSequence: 1, toSequence: 1, reasonCode: "capture.missed" }] });
  const inclusion = { checkpointId: checkpoint.checkpointId, sequence: 0, leafIndex: 0, treeSize: 3, auditPath: [] };
  const changed = repack(value, { sourceCheckpoints: [checkpoint], protocolEvidence: [
    envelope(value.casePack.protocolEvidence[0], { checkpointInclusion: inclusion }), value.casePack.protocolEvidence[1],
  ] });
  const report = sdk.inspectCaseCheckpoints(changed);
  assert.equal(report.checkpoints.length, 1, JSON.stringify(sdk.createCaseReport(changed.casePack, changed.anchors).findings));
  assert.equal(report.checkpoints[0].declaredGaps[0].reasonCode, "capture.missed");
  assert.equal(report.checkpoints[0].proofCount, 0);
  assert.equal(report.checkpoints[0].inclusions[0].envelopeId, "envelope.alpha");
  const dangling = repack(changed, { sourceCheckpoints: [] });
  assert.equal(sdk.inspectCaseCheckpoints(dangling).missingCheckpointReferences[0].checkpointId, "checkpoint.one");
  assert.equal(report.globalCompleteness, "not-established");
  assert.deepEqual(sdk.inspectCaseCheckpoints({ ...value, casePack: null }).checkpoints, []);
  assert.equal((await cli("checkpoints", value)).code, 0);
  assert.equal((await cli("checkpoints", dangling)).code, 0); // This fixture does not require checkpoints.
  assert.equal((await cli("checkpoints", { ...value, casePack: null })).code, 3);
});

test("validity windows use explicit time and exclusive expiry without granting authority", async () => {
  const value = input();
  assert.equal(typeof sdk.inspectCaseValidityWindows, "function");
  const current = sdk.inspectCaseValidityWindows(value);
  assert.ok(current.windows.every((item) => item.state === "within_window"));
  const atEnd = { ...value, anchors: { ...value.anchors, asOf: value.casePack.coverageContract.validUntil } };
  assert.ok(sdk.inspectCaseValidityWindows(atEnd).windows.every((item) => item.state === "expired" && item.remainingSeconds === 0));
  const early = { ...value, anchors: { ...value.anchors, asOf: "2026-07-21T00:00:00.000Z" } };
  assert.ok(sdk.inspectCaseValidityWindows(early).windows.every((item) => item.state === "not_yet_valid"));
  const start = { ...value, anchors: { ...value.anchors, asOf: value.casePack.coverageContract.validFrom } };
  assert.ok(sdk.inspectCaseValidityWindows(start).windows.every((item) => item.state === "within_window"));
  assert.deepEqual(sdk.inspectCaseValidityWindows({ ...value, casePack: null }).windows, []);
  assert.equal((await cli("windows", value)).code, 0);
  assert.equal((await cli("windows", atEnd)).code, 3);
});

test("content reuse groups repeated bytes across distinct references without claiming corroboration", async () => {
  const value = input();
  assert.equal(typeof sdk.findCaseContentReuse, "function");
  assert.deepEqual(sdk.findCaseContentReuse(value).groups, []);
  const first = value.casePack.protocolEvidence[0];
  const second = envelope(first, { envelopeId: "envelope.beta", sourceId: "source.beta", eventClass: "execution",
    rawEvidence: { ...first.rawEvidence, reference: { ...first.rawEvidence.reference, referenceId: "raw.shared" } } });
  const reused = repack(value, { protocolEvidence: [first, second] });
  const report = sdk.findCaseContentReuse(reused);
  assert.equal(report.groups.length, 1);
  assert.deepEqual(report.groups[0].sourceIds, ["source.alpha", "source.beta"]);
  assert.equal(report.groups[0].records.length, 2);
  assert.equal(report.groups[0].allSuppliedMatch, false);
  assert.equal(report.sourceTruth, "unknown");
  assert.equal((await cli("reuse", reused)).body.result.groups.length, 1);
  assert.equal((await cli("reuse", value)).code, 0);
  assert.deepEqual(sdk.findCaseContentReuse({ ...value, casePack: null }).groups, []);
});

test("batch bottlenecks group unmet source requirements and preserve unassessable cases", async () => {
  const value = input();
  assert.equal(typeof sdk.findBatchCollectionBottlenecks, "function");
  const missing = repack(value, { protocolEvidence: value.casePack.protocolEvidence.slice(1) });
  const cases = [{ id: "two", ...missing }, { id: "one", ...missing }, { id: "ready", ...value }, { id: "invalid", ...value, casePack: null }];
  const report = sdk.findBatchCollectionBottlenecks(cases);
  assert.equal(report.bottlenecks.length, 1);
  assert.deepEqual(report.bottlenecks[0].caseIds, ["one", "two"]);
  assert.deepEqual(report.unassessableCaseIds, ["invalid"]);
  assert.equal(report.cases.length, 4);
  assert.deepEqual(report, sdk.findBatchCollectionBottlenecks([...cases].reverse()));
  assert.throws(() => sdk.findBatchCollectionBottlenecks([]));
  assert.throws(() => sdk.findBatchCollectionBottlenecks([cases[0], cases[0]]));
  assert.equal((await cli("bottlenecks", { cases })).code, 3);
  assert.equal((await cli("bottlenecks", { cases: [{ id: "ready", ...value }] })).code, 0);
});

test("batch findings aggregate bounded identities and retain cases without findings", async () => {
  const value = input();
  assert.equal(typeof sdk.summarizeBatchFindings, "function");
  const cases = [{ id: "two", ...value, casePack: null }, { id: "one", ...value, casePack: null }, { id: "ready", ...value }];
  const report = sdk.summarizeBatchFindings(cases);
  assert.ok(report.findings.length > 0);
  assert.deepEqual(report.findings[0].cases.map((item) => item.id), ["one", "two"]);
  assert.equal(report.findings[0].caseCount, 2);
  assert.ok(report.findings.every((item) => item.occurrences === item.cases.reduce((sum, row) => sum + row.count, 0)));
  assert.equal(report.cases.length, 3);
  assert.equal(JSON.stringify(report).includes('"message"'), false);
  assert.deepEqual(report, sdk.summarizeBatchFindings([...cases].reverse()));
  assert.throws(() => sdk.summarizeBatchFindings([]));
  assert.throws(() => sdk.summarizeBatchFindings([cases[0], cases[0]]));
  assert.equal((await cli("findings", { cases })).code, 3);
  assert.deepEqual((await cli("findings", { cases: [{ id: "ready", ...value }] })).body.result.findings, []);
});

test("batch revision comparison retains additions, removals, invalid cases and anchor drift", async () => {
  const value = input();
  assert.equal(typeof sdk.compareCaseBatches, "function");
  const before = [{ id: "same", ...value }, { id: "removed", ...value }];
  const after = [{ id: "same", ...value }, { id: "added", ...value }];
  const report = sdk.compareCaseBatches(before, after);
  assert.deepEqual(report.cases.map((item) => [item.id, item.change]), [["added", "added"], ["removed", "removed"], ["same", "retained"]]);
  assert.equal(report.hasRegression, true);
  assert.deepEqual(report, sdk.compareCaseBatches([...before].reverse(), [...after].reverse()));
  const unchanged = [{ id: "same", ...value }];
  assert.equal(sdk.compareCaseBatches(unchanged, unchanged).needsReview, false);
  const later = [{ id: "same", ...value, anchors: { ...value.anchors, asOf: "2026-07-24T00:00:00.000Z" } }];
  assert.equal(sdk.compareCaseBatches(unchanged, later).hasContextDrift, true);
  const invalid = [{ id: "same", ...value, casePack: null }];
  assert.equal(sdk.compareCaseBatches(invalid, invalid).needsReview, true);
  const missing = [{ id: "same", ...value, anchors: { ...value.anchors, rawEvidence: [] } }];
  assert.equal(sdk.compareCaseBatches(unchanged, missing).hasRegression, true);
  assert.throws(() => sdk.compareCaseBatches([], after));
  assert.throws(() => sdk.compareCaseBatches(before, [after[0], after[0]]));
  assert.equal((await cli("batch-diff", { before, after })).code, 5);
  assert.equal((await cli("batch-diff", { before: unchanged, after: unchanged })).code, 0);
  assert.equal((await cli("batch-diff", { before: unchanged, after: later })).code, 5);
  assert.equal((await cli("batch-diff", { before: invalid, after: invalid })).code, 3);
  assert.equal((await cli("batch-diff", { before, after, extra: true })).code, 3);
});

test("discovery and checkpoint-key windows expose expiry without promoting trust", () => {
  const value = input();
  const publicJwk = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
  const snapshot = sdk.sealExternalTrustSnapshot({ format: "MandateBoundExternalTrustSnapshot/v1",
    snapshotId: "snapshot.windows", issuedAt: "2026-07-22T00:00:00.000Z", expiresAt: "2026-07-25T00:00:00.000Z",
    trustEffect: "discovery_only", nativeTrustPromotion: "forbidden", discoveryMaterials: [],
    keys: [{ keyId: "key.one", sourceId: "source.alpha", publicJwk, purposes: ["source_checkpoint"],
      validFrom: "2026-07-22T00:00:00.000Z", validUntil: value.anchors.asOf }] });
  const changed = repack(value, { externalTrustSnapshot: snapshot });
  const report = sdk.inspectCaseValidityWindows(changed);
  assert.equal(report.windows[0].kind, "checkpoint_key");
  assert.equal(report.windows[0].state, "expired");
  assert.equal(report.windows[1].kind, "discovery");
  assert.equal(report.windows[1].state, "within_window");
  assert.equal(report.legalEffect, "not-determined");
});

test("batch row ordering cannot collide through punctuation inside caller IDs", () => {
  const value = input();
  const withRequirement = (id, requirementId) => {
    const { contractDigest: _ignored, ...contract } = value.casePack.coverageContract;
    const coverageContract = sdk.sealEvidenceCoverageContract({ ...contract, requirements: [
      { ...contract.requirements[0], requirementId }, contract.requirements[1],
    ] });
    const changed = repack(value, { coverageContract, protocolEvidence: value.casePack.protocolEvidence.slice(1) });
    return { id, ...changed, anchors: { ...value.anchors, coverageContractDigest: coverageContract.contractDigest } };
  };
  const cases = [withRequirement("a:b", "c"), withRequirement("a", "b:c")];
  assert.deepEqual(sdk.findBatchCollectionBottlenecks(cases), sdk.findBatchCollectionBottlenecks([...cases].reverse()));
});

test("evidence commands reject extra input fields and preserve all source bytes", async () => {
  const value = input();
  const snapshot = JSON.stringify(value);
  for (const action of ["collect", "sources", "timeline", "lineage", "checkpoints", "windows", "reuse"]) {
    assert.equal((await cli(action, { ...value, extra: true })).code, 3);
    const result = await cli(action, value);
    assert.equal(result.code, 0);
    assert.equal(JSON.stringify(result.body).includes('"bytesBase64"'), false);
    assert.equal(JSON.stringify(result.body).includes('"action":"authorize"'), false);
  }
  assert.equal(JSON.stringify(value), snapshot);
});

test("SDK timing views leave invalid assessment instants unavailable and retain verifier findings", () => {
  const value = input();
  for (const asOf of ["invalid", "July 23, 2026", "2026-02-30T00:00:00.000Z", "+010000-01-01T00:00:00.000Z"]) {
    const changed = { ...value, anchors: { ...value.anchors, asOf } };
    const timeline = sdk.createCaseCaptureTimeline(changed);
    assert.equal(timeline.valid, false);
    assert.equal(timeline.events.length, 2);
    assert.ok(timeline.events.every((item) => item.afterAssessment === null), JSON.stringify(timeline.events));
    assert.ok(timeline.findings.some((item) => item.code === "MBCP_ANCHOR_INVALID"));
    const windows = sdk.inspectCaseValidityWindows(changed);
    assert.equal(windows.valid, false);
    assert.ok(windows.windows.every((item) => item.state === "unknown" && item.remainingSeconds === null));
    assert.deepEqual(windows.findings, timeline.findings);
  }
});

test("CLI timing views return invalid with unavailable comparisons for malformed assessment time", async () => {
  const value = input();
  for (const asOf of ["invalid", "July 23, 2026", "2026-02-30T00:00:00.000Z", "+010000-01-01T00:00:00.000Z"]) {
    const changed = { ...value, anchors: { ...value.anchors, asOf } };
    const timeline = await cli("timeline", changed);
    assert.equal(timeline.code, 3);
    assert.equal(timeline.body.ok, false);
    assert.ok(timeline.body.result.events.every((item) => item.afterAssessment === null), JSON.stringify(timeline.body.result.events));
    assert.ok(timeline.body.result.findings.some((item) => item.code === "MBCP_ANCHOR_INVALID"));
    const windows = await cli("windows", changed);
    assert.equal(windows.code, 3);
    assert.ok(windows.body.result.windows.every((item) => item.state === "unknown" && item.remainingSeconds === null));
    assert.deepEqual(windows.body.result.findings, timeline.body.result.findings);
    assert.equal(JSON.stringify(timeline.body).includes('"bytesBase64"'), false);
  }
});
