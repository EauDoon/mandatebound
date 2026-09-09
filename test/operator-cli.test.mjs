import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import { runCli } from "../dist/cli.js";
import { operatorFixture } from "./fixtures/operator-fixture.mjs";

export function jsonInvocation() {
  const { pack, anchors } = operatorFixture();
  return { casePack: pack, anchors: { ...anchors, rawEvidence: anchors.rawEvidence.map((item) =>
    ({ referenceId: item.referenceId, bytesBase64: Buffer.from(item.bytes).toString("base64") })) } };
}

async function cli(args, value) {
  let output = "";
  const capture = new Writable({ write(chunk, _encoding, next) { output += chunk; next(); } });
  const code = await runCli(args, { stdin: Readable.from([JSON.stringify(value)]), stdout: capture,
    stderr: new Writable({ write(_chunk, _encoding, next) { next(); } }) });
  return { code, output };
}

test("operator CLI runs triage, checklist, batches and comparisons through strict evidence decoding", async () => {
  const input = jsonInvocation();
  for (const action of ["triage", "checklist"]) {
    const result = await cli(["operator", action], input);
    assert.equal(result.code, 0);
    assert.equal(JSON.parse(result.output).result.legalEffect, "not-determined");
    assert.equal((await cli(["operator", action], { ...input, extra: true })).code, 3);
  }
  assert.equal((await cli(["operator", "batch"], { cases: [{ id: "one", ...input }] })).code, 0);
  assert.equal((await cli(["operator", "batch"], { cases: [] })).code, 3);
  assert.equal((await cli(["operator", "batch"], { cases: [input] })).code, 3);
  assert.equal((await cli(["operator", "batch"], { cases: [{ id: "one", ...input }, { id: "bad", casePack: null, anchors: input.anchors }] })).code, 3);
  assert.equal((await cli(["operator", "compare"], { before: input, after: input })).code, 0);
  assert.equal((await cli(["operator", "compare"], { before: input, after: { ...input, anchors: { ...input.anchors, rawEvidence: [] } } })).code, 5);
  assert.equal((await cli(["operator", "compare"], { before: input, after: { casePack: null, anchors: input.anchors } })).code, 3);
  assert.equal((await cli(["operator", "compare"], {})).code, 3);
  assert.equal((await cli(["operator", "audit"], {})).code, 3);
  assert.equal((await cli(["operator", "triage", "--store", "unused"], input)).code, 2);
  assert.equal((await cli(["operator", "unknown"], input)).code, 2);
  const bad = structuredClone(input);
  bad.anchors.rawEvidence[0].bytesBase64 = "not base64";
  assert.equal((await cli(["operator", "triage"], bad)).code, 3);
});

test("case-report CLI emits Markdown and CSV through the same verifier", async () => {
  const input = jsonInvocation();
  const markdown = await cli(["case-report", "--format", "markdown"], input);
  assert.equal(markdown.code, 0);
  assert.match(markdown.output, /^# Case report/);
  const csv = await cli(["case-report", "--format", "csv"], input);
  assert.equal(csv.code, 0);
  assert.match(csv.output, /^"casePackId",/);
  const invalid = await cli(["case-report", "--format", "markdown"], { casePack: null, anchors: input.anchors });
  assert.equal(invalid.code, 3);
  assert.match(invalid.output, /Verification: not valid/);
});
