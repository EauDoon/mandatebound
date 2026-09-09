import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import { runCli } from "../dist/cli.js";
import { buildScenario } from "../dist/simulator.js";
import { operatorFixture } from "./fixtures/operator-fixture.mjs";
import { inventoryCaseEvidence } from "../dist/operator-review.js";
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
