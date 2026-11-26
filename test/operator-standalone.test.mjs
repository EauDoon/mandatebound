import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { operatorFixture } from "./fixtures/operator-fixture.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
function run(args, input) {
  return spawnSync(process.execPath, args, { cwd: root, input, encoding: "utf8", timeout: 20_000 });
}

test("standalone ESM example persists and audits an unresolved synthetic decision", () => {
  const result = run(["examples/operator-workflow.mjs"]);
  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.equal(output.policyOutcome, "unresolved");
  assert.equal(output.unanchoredCompleteness, "unproven");
  assert.equal(output.anchoredCompleteness, "verified");
  assert.equal(output.valid, true);
});

test("standalone CLI reads files, exports reports, and audits without creating writer state", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mandatebound-standalone-"));
  try {
    const { pack, anchors } = operatorFixture();
    const input = { casePack: pack, anchors: { ...anchors, rawEvidence: anchors.rawEvidence.map((item) =>
      ({ referenceId: item.referenceId, bytesBase64: Buffer.from(item.bytes).toString("base64") })) } };
    const inputPath = join(dir, "case.json");
    await writeFile(inputPath, JSON.stringify(input));
    for (const format of ["json", "html", "markdown", "csv"]) {
      const result = run(["dist/cli.js", "case-report", "--input", inputPath, "--format", format]);
      assert.equal(result.status, 0, result.stderr);
      assert.ok(result.stdout.length > 100);
    }
    const exported = (format, doc) => run(["dist/cli.js", "case-report", "--format", format], JSON.stringify(doc));
    const envelopes = exported("envelopes-csv", input);
    assert.equal(envelopes.status, 0, envelopes.stderr);
    assert.match(envelopes.stdout, /"upstreamValid","evidenceEligible","sourceTruth"/);
    assert.match(envelopes.stdout, /"envelope.alpha","[^"]+","[^"]+","true","true","unknown"/);
    const cleanFindings = exported("findings-csv", input);
    assert.equal(cleanFindings.status, 0, cleanFindings.stderr);
    assert.match(cleanFindings.stdout, /"valid","","","","not-determined","not-established"/);
    const invalidInput = { ...input, casePack: null };
    const findings = exported("findings-csv", invalidInput);
    assert.equal(findings.status, 3, findings.stderr);
    assert.match(findings.stdout, /"code","path","message"/);
    assert.match(findings.stdout, /"not valid","MBCP_/);
    const empty = exported("envelopes-csv", invalidInput);
    assert.equal(empty.status, 3, empty.stderr);
    assert.match(empty.stdout, /"not valid","","","","","","","not-determined","not-established"/);
    const invalidCsv = run(["dist/cli.js", "case-report", "--format", "csv"],
      JSON.stringify({ casePack: null, anchors: input.anchors }));
    assert.equal(invalidCsv.status, 3, invalidCsv.stderr);
    const invalidRows = invalidCsv.stdout.split("\r\n");
    assert.equal(invalidRows.length, 3);
    assert.equal(invalidRows[1], `"unidentified-casepack","${anchors.asOf}","not valid","","","","not-determined","not-established"`);
    const snapshot = join(dir, "snapshot.jsonl");
    await writeFile(snapshot, "");
    const audit = run(["dist/cli.js", "operator", "audit", "--store", snapshot], "{}");
    assert.equal(audit.status, 0, audit.stderr);
    assert.equal(JSON.parse(audit.stdout).result.completeness, "unproven");
    assert.equal(await readFile(snapshot, "utf8"), "");
    const corrupt = run(["dist/cli.js", "operator", "triage"], '{"casePack":{},"casePack":{},"anchors":{}}');
    assert.equal(corrupt.status, 3);
    const hostile = run(["dist/cli.js", "operator", "audit", "--store", snapshot], '{"checkpoint":{"sequence":0,"headHash":"invalid"}}');
    assert.equal(hostile.status, 3);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
