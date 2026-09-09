import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import { runCli } from "../dist/cli.js";
import { buildScenario } from "../dist/simulator.js";
import { operatorFixture } from "./fixtures/operator-fixture.mjs";
import { inventoryCaseEvidence, compareCaseCoverage, compareCaseEnvelopes, compareCaseFindings, compareCaseAnchorContext, createAssessmentReceipt, verifyAssessmentReceipt } from "../dist/operator-review.js";
import { createMandateBoundCasePack } from "../dist/casepack.js";
import { createCaseReviewQueue, renderCaseReviewQueueCsv } from "../dist/operator.js";

function invocation(fixture = operatorFixture()) {
  return { casePack: fixture.pack, anchors: { ...fixture.anchors, rawEvidence: fixture.anchors.rawEvidence.map((item) =>
    ({ referenceId: item.referenceId, bytesBase64: Buffer.from(item.bytes).toString("base64") })) } };
}

async function cli(args, value, overrides = {}) {
  let output = "";
  const capture = new Writable({ write(chunk, _encoding, next) { output += chunk; next(); } });
  const code = await runCli(args, { stdin: Readable.from([JSON.stringify(value)]), stdout: capture,
    stderr: new Writable({ write(_chunk, _encoding, next) { next(); } }), ...overrides });
  return { code, output, json: () => JSON.parse(output) };
}

test("native preview uses the existing engine without touching a store", async () => {
  const input = buildScenario("unresolved").input;
  const result = await cli(["preview"], input, { store: new Proxy({}, { get() { throw new Error("store touched"); } }) });
  assert.equal(result.code, 0, result.output);
  assert.equal(result.json().result.policyOutcome, "unresolved");
  assert.equal(result.json().result.legalEffect, "not-determined");
  assert.equal((await cli(["preview", "--store", "unused"], input)).code, 2);
  assert.equal((await cli(["preview", "--format", "html"], input)).code, 2);
});

test("receipt verification requires an independent anchor and detects tampering and assessment drift", async () => {
  const fixture = operatorFixture();
  const input = { casePack: fixture.pack, anchors: fixture.anchors };
  const receipt = createAssessmentReceipt(input);
  const digest = receipt.receiptDigest;
  assert.equal(verifyAssessmentReceipt(input, receipt, digest).matches, true);
  assert.equal(verifyAssessmentReceipt(input, { ...receipt, valid: false }, digest).anchored, false);
  assert.equal(verifyAssessmentReceipt(input, receipt, "sha256:" + "0".repeat(64)).matches, false);
  assert.throws(() => verifyAssessmentReceipt(input, receipt, "bad"));
  assert.throws(() => verifyAssessmentReceipt(input, { ...receipt, extra: true }, digest));
  assert.throws(() => verifyAssessmentReceipt(input, { ...receipt, legalEffect: "decided" }, digest));
  const later = { ...input, anchors: { ...input.anchors, asOf: "2026-07-24T00:00:00.000Z" } };
  assert.ok(verifyAssessmentReceipt(later, receipt, digest).differences.includes("anchorDigest"));
  const invalid = { casePack: null, anchors: input.anchors };
  const failedReceipt = createAssessmentReceipt(invalid);
  const verifiedFailure = verifyAssessmentReceipt(invalid, failedReceipt, failedReceipt.receiptDigest);
  assert.equal(verifiedFailure.matches, true);
  assert.equal(verifiedFailure.valid, false);
  const jsonInput = { invocation: invocation(fixture), receipt };
  const args = ["operator", "receipt-verify", "--expected-receipt-digest", digest];
  assert.equal((await cli(args, jsonInput)).code, 0);
  assert.equal((await cli(["operator", "receipt-verify"], jsonInput)).code, 2);
  assert.equal((await cli(args, { ...jsonInput, extra: true })).code, 3);
  assert.equal((await cli(args, { ...jsonInput, receipt: { ...receipt, valid: false } })).code, 3);
  assert.equal((await cli(args, { ...jsonInput, invocation: { ...jsonInput.invocation, anchors: { ...jsonInput.invocation.anchors, asOf: later.anchors.asOf } } })).code, 5);
});

test("assessment receipts bind the case, exact evidence, anchors and verifier result", async () => {
  const fixture = operatorFixture();
  const input = { casePack: fixture.pack, anchors: fixture.anchors };
  const receipt = createAssessmentReceipt(input);
  assert.equal(receipt.valid, true);
  assert.equal(receipt.legalEffect, "not-determined");
  assert.deepEqual(receipt, createAssessmentReceipt(input));
  assert.deepEqual(receipt, createAssessmentReceipt({ ...input, anchors: { ...input.anchors, rawEvidence: [...input.anchors.rawEvidence].reverse() } }));
  assert.notEqual(receipt.receiptDigest, createAssessmentReceipt({ ...input, anchors: { ...input.anchors, rawEvidence: [] } }).receiptDigest);
  assert.equal(createAssessmentReceipt({ casePack: null, anchors: input.anchors }).valid, false);
  assert.equal(Object.keys(receipt).some((key) => ["casePack", "rawEvidence", "report"].includes(key)), false);
  assert.equal((await cli(["operator", "receipt"], invocation(fixture))).json().result.receiptDigest, receipt.receiptDigest);
  assert.equal((await cli(["operator", "receipt"], { casePack: null, anchors: invocation(fixture).anchors })).code, 3);
});

test("anchor comparison exposes changed review context without raw bytes", async () => {
  const fixture = operatorFixture();
  const before = { casePack: fixture.pack, anchors: fixture.anchors };
  const reordered = { ...before, anchors: { ...before.anchors, rawEvidence: [...before.anchors.rawEvidence].reverse() } };
  assert.equal(compareCaseAnchorContext(before, reordered).changed, false);
  const later = { ...before, anchors: { ...before.anchors, asOf: "2026-07-24T00:00:00.000Z" } };
  const report = compareCaseAnchorContext(before, later);
  assert.deepEqual(report.changes, ["asOf"]);
  assert.equal(JSON.stringify(report).includes('"bytes"'), false);
  assert.equal(compareCaseAnchorContext(before, { casePack: null, anchors: before.anchors }).sameCase, false);
  assert.throws(() => compareCaseAnchorContext(before, { ...before, anchors: { ...before.anchors, coveragePolicyDigest: "bad" } }));
  const input = invocation(fixture);
  assert.equal((await cli(["operator", "anchor-diff"], { before: input, after: input })).code, 0);
  assert.equal((await cli(["operator", "anchor-diff"], { before: input, after: { ...input, anchors: { ...input.anchors, asOf: later.anchors.asOf } } })).code, 5);
});

test("finding comparison tracks new occurrences without claiming invalid inputs are resolved", async () => {
  const fixture = operatorFixture();
  const before = { casePack: fixture.pack, anchors: fixture.anchors };
  const after = { ...before, anchors: { ...fixture.anchors, rawEvidence: fixture.anchors.rawEvidence.map((item) => ({ ...item, bytes: Buffer.from("wrong") })) } };
  const result = compareCaseFindings(before, after);
  assert.equal(result.hasRegression, true);
  assert.ok(result.changes.every((item) => item.afterCount > item.beforeCount));
  assert.equal(result.changes.some((item) => Object.hasOwn(item, "message")), false);
  assert.equal(compareCaseFindings(after, before).hasRegression, false);
  assert.deepEqual(compareCaseFindings(before, before).changes, []);
  assert.equal(compareCaseFindings(before, { casePack: null, anchors: fixture.anchors }).comparable, false);
  const input = invocation(fixture);
  const wrong = { ...input, anchors: { ...input.anchors, rawEvidence: input.anchors.rawEvidence.map((item) => ({ ...item, bytesBase64: Buffer.from("wrong").toString("base64") })) } };
  assert.equal((await cli(["operator", "finding-diff"], { before: input, after: wrong })).code, 5);
});

test("envelope comparison preserves removed and newly ineligible evidence", async () => {
  const fixture = operatorFixture();
  const before = { casePack: fixture.pack, anchors: fixture.anchors };
  const missing = { ...before, anchors: { ...fixture.anchors, rawEvidence: [] } };
  assert.equal(compareCaseEnvelopes(before, missing).hasRegression, true);
  assert.equal(compareCaseEnvelopes(missing, before).hasRegression, false);
  assert.deepEqual(compareCaseEnvelopes(before, before).changes, []);
  const removed = compareCaseEnvelopes(before, { casePack: removedEnvelope(fixture).pack, anchors: fixture.anchors });
  assert.equal(removed.changes[0].after, null);
  assert.equal(compareCaseEnvelopes(before, { casePack: null, anchors: fixture.anchors }).comparable, false);
  const input = invocation(fixture);
  assert.equal((await cli(["operator", "envelope-diff"], { before: input, after: { ...input, anchors: { ...input.anchors, rawEvidence: [] } } })).code, 5);
});

function removedEnvelope(fixture) {
  const { casePackDigest: ignored, ...material } = fixture.pack;
  return { ...fixture, pack: createMandateBoundCasePack({ ...material, protocolEvidence: material.protocolEvidence.slice(1) }) };
}

test("coverage comparison locates lost requirements under unchanged coverage pins", async () => {
  const fixture = operatorFixture();
  const revised = removedEnvelope(fixture);
  const before = { casePack: fixture.pack, anchors: fixture.anchors };
  const after = { casePack: revised.pack, anchors: revised.anchors };
  const result = compareCaseCoverage(before, after);
  assert.equal(result.comparable, true);
  assert.equal(result.hasRegression, true);
  assert.equal(result.changes[0].requirementId, "requirement.alpha");
  assert.deepEqual(compareCaseCoverage(before, before).changes, []);
  assert.equal(compareCaseCoverage(before, { casePack: null, anchors: fixture.anchors }).comparable, false);
  assert.equal((await cli(["operator", "coverage-diff"], { before: invocation(fixture), after: invocation(revised) })).code, 5);
  assert.equal((await cli(["operator", "coverage-diff"], { before: invocation(fixture), after: invocation(fixture) })).code, 0);
  assert.equal((await cli(["operator", "coverage-diff"], {})).code, 3);
  const json = invocation(fixture);
  const missingRaw = { ...json, anchors: { ...json.anchors, rawEvidence: [] } };
  const invalidUnchangedCoverage = await cli(["operator", "coverage-diff"], { before: missingRaw, after: missingRaw });
  assert.equal(invalidUnchangedCoverage.code, 3);
  assert.equal(invalidUnchangedCoverage.json().ok, false);
});

test("queue CSV preserves task-free cases and neutralizes hostile presentation fields", async () => {
  const { pack, anchors } = operatorFixture();
  const queue = createCaseReviewQueue([{ id: "ready", casePack: pack, anchors }]);
  assert.match(renderCaseReviewQueueCsv(queue), /No review tasks reported/);
  const hostile = structuredClone(queue);
  hostile.cases[0].id = '=HYPERLINK("bad")';
  assert.ok(renderCaseReviewQueueCsv(hostile).includes('"\'=HYPERLINK(""bad"")"'));
  const input = invocation();
  assert.match((await cli(["operator", "queue", "--format", "csv"], { cases: [{ id: "ready", ...input }] })).output, /^"id",/);
  const invalid = await cli(["operator", "queue", "--format", "csv"], { cases: [{ id: "bad", casePack: null, anchors: input.anchors }] });
  assert.equal(invalid.code, 3);
  assert.match(invalid.output, /not valid/);
  assert.match(invalid.output, /not-determined/);
});

test("review queue prioritizes conflicts without dropping ready or unresolved cases", async () => {
  const { pack, anchors } = operatorFixture();
  const inputs = [{ id: "ready", casePack: pack, anchors }, { id: "missing", casePack: pack, anchors: { ...anchors, rawEvidence: [] } },
    { id: "conflict", casePack: null, anchors }];
  const queue = createCaseReviewQueue(inputs);
  assert.deepEqual(queue.cases.map((item) => item.id), ["conflict", "missing", "ready"]);
  assert.deepEqual(queue.summary, { total: 3, needsReview: 2, highPriority: 1 });
  assert.equal(queue.valid, false);
  assert.deepEqual(queue, createCaseReviewQueue([...inputs].reverse()));
  assert.throws(() => createCaseReviewQueue([inputs[0], inputs[0]]));
  const input = invocation();
  const result = await cli(["operator", "queue"], { cases: [{ id: "ready", ...input }] });
  assert.equal(result.code, 0);
  assert.equal(result.json().result.cases.length, 1);
  assert.equal((await cli(["operator", "queue"], { cases: [] })).code, 3);
});

test("inventory distinguishes missing and wrong bytes without exposing evidence", async () => {
  const { pack, anchors } = operatorFixture();
  const input = { casePack: pack, anchors };
  const report = inventoryCaseEvidence(input);
  assert.ok(report.records.every((item) => item.matches));
  assert.equal(JSON.stringify(report).includes('"amount"'), false);
  assert.equal(inventoryCaseEvidence({ ...input, anchors: { ...anchors, rawEvidence: [] } }).records[0].supplied, false);
  const changed = { ...anchors, rawEvidence: [{ referenceId: "raw.alpha", bytes: Buffer.from("wrong") }, { referenceId: "other", bytes: Buffer.from("extra") }] };
  const bad = inventoryCaseEvidence({ ...input, anchors: changed });
  assert.equal(bad.valid, false);
  assert.equal(bad.records[0].matches, false);
  assert.deepEqual(bad.otherSuppliedReferences, ["other"]);
  assert.deepEqual(inventoryCaseEvidence({ casePack: null, anchors }).records, []);
  assert.throws(() => inventoryCaseEvidence({ ...input, anchors: { ...anchors, rawEvidence: [anchors.rawEvidence[0], anchors.rawEvidence[0]] } }));
  assert.equal((await cli(["operator", "inventory"], invocation())).code, 0);
  assert.equal((await cli(["operator", "inventory"], { casePack: null, anchors: invocation().anchors })).code, 3);
});
