import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import { runCli } from "../dist/cli.js";
import { buildScenario } from "../dist/simulator.js";
import { operatorFixture } from "./fixtures/operator-fixture.mjs";
import { inventoryCaseEvidence } from "../dist/operator-review.js";

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
