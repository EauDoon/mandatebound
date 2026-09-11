import assert from "node:assert/strict";
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
