import assert from "node:assert/strict";
import test from "node:test";
import { triageCase, createEvidenceChecklist, assessCases, compareCaseAssessments } from "../dist/operator.js";
import { operatorFixture } from "./fixtures/operator-fixture.mjs";
import { createCaseReport, renderCaseReportMarkdown, renderCaseCoverageCsv, renderCaseReportHtml } from "../dist/report.js";

test("triage re-verifies evidence and never asserts source truth", () => {
  const { pack, anchors } = operatorFixture();
  const before = structuredClone(pack);
  const result = triageCase({ casePack: pack, anchors });
  assert.equal(result.valid, true);
  assert.equal(result.casePackId, pack.casePackId);
  assert.equal(result.casePackDigest, pack.casePackDigest);
  assert.deepEqual(result.items, []);
  assert.equal(result.sourceTruth, "unknown");
  assert.equal(result.legalEffect, "not-determined");
  pack.casePackId = "mutated";
  const invalid = triageCase({ casePack: pack, anchors });
  assert.equal(invalid.valid, false);
  assert.equal(invalid.items[0].priority, "high");
  assert.ok(invalid.findings.length > 0);
  assert.equal(before.casePackId, "casepack.case-001");
});

test("triage is deterministic and fails closed for absent evidence", () => {
  const { anchors } = operatorFixture();
  const input = { casePack: null, anchors };
  assert.deepEqual(triageCase(input), triageCase(input));
  assert.equal(triageCase(input).valid, false);
});

test("checklist retains satisfied requirements and exposes missing raw evidence", () => {
  const { pack, anchors } = operatorFixture();
  const ready = createEvidenceChecklist({ casePack: pack, anchors });
  assert.equal(ready.requirements.length, 2);
  assert.equal(ready.casePackDigest, pack.casePackDigest);
  assert.equal(ready.assessedAt, anchors.asOf);
  assert.ok(ready.requirements.every((item) => !item.needsReview));
  const missing = createEvidenceChecklist({ casePack: pack, anchors: { ...anchors, rawEvidence: [] } });
  assert.equal(missing.valid, false);
  assert.ok(missing.assuranceTasks.length > 0);
  assert.ok(missing.assuranceTasks.some((item) => item.status === "unknown"));
  assert.equal(missing.globalCompleteness, "not-established");
});

test("batch assessment preserves identifiers and does not hide invalid cases", () => {
  const { pack, anchors } = operatorFixture();
  const inputs = [{ id: "ready", casePack: pack, anchors }, { id: "absent", casePack: null, anchors }];
  const batch = assessCases(inputs);
  assert.deepEqual(batch.summary, { total: 2, verified: 1, needsReview: 1 });
  assert.equal(batch.valid, false);
  assert.deepEqual(batch.cases.map((item) => item.id), ["ready", "absent"]);
  assert.throws(() => assessCases([]), /between/);
  assert.throws(() => assessCases(Array(101).fill(inputs[0])), /between/);
  assert.throws(() => assessCases([inputs[0], inputs[0]]), /unique/);
  assert.throws(() => assessCases([{ ...inputs[0], id: "<script>" }]), /ASCII/);
  assert.throws(() => assessCases([{ ...inputs[0], extra: true }]), /unique/);
  assert.throws(() => assessCases([null]), /unique/);
});

test("comparison identifies assurance regression without comparing unrelated coverage", () => {
  const { pack, anchors } = operatorFixture();
  const before = { casePack: pack, anchors };
  const after = { casePack: pack, anchors: { ...anchors, rawEvidence: [] } };
  assert.equal(compareCaseAssessments(before, before).hasRegression, false);
  assert.equal(compareCaseAssessments(before, before).before.casePackDigest, pack.casePackDigest);
  assert.equal(compareCaseAssessments(before, after).hasRegression, true);
  assert.equal(compareCaseAssessments(after, before).hasRegression, false);
  assert.ok(compareCaseAssessments(before, after).changes.length > 0);
  assert.equal(compareCaseAssessments(before, { casePack: null, anchors }).comparable, false);
  assert.equal(compareCaseAssessments(before, { ...before, anchors: { ...anchors, coveragePolicyDigest: "sha256:" + "0".repeat(64) } }).comparable, false);
});

test("Markdown reports are portable and escape active markup and table delimiters", () => {
  const { pack, anchors } = operatorFixture();
  const report = createCaseReport(pack, anchors);
  const rendered = renderCaseReportMarkdown(report);
  assert.match(rendered, /Legal effect is not determined/);
  assert.match(rendered, /Coverage requirements/);
  const hostile = renderCaseReportMarkdown({ ...report, casePackId: "<img src=x>|[click](javascript:x)\n# fake", findings: [{ code: "bad", path: "/", message: "<script>alert(1)</script>" }] });
  assert.ok(!hostile.includes("<script>"));
  assert.ok(!hostile.includes("<img"));
  assert.ok(!hostile.includes("\n# fake"));
  assert.ok(hostile.includes("\\|"));
});

test("CSV covers requirements and neutralizes spreadsheet formulas", () => {
  const { pack, anchors } = operatorFixture();
  const report = createCaseReport(pack, anchors);
  const csv = renderCaseCoverageCsv(report);
  assert.equal(csv.split("\r\n").length, 4);
  assert.match(csv, /not-determined/);
  for (const requirementId of ["=1+1", "+cmd", "-2", "@SUM(1)", " \t=1", "\ttext", "\rtext", "\ntext"]) {
    const hostile = renderCaseCoverageCsv({ ...report, coverage: [{ requirementId, status: "missing", matchedEnvelopes: 0 }] });
    assert.ok(hostile.includes(`"'${requirementId}"`));
  }
  const escaped = renderCaseCoverageCsv({ ...report, casePackId: 'a,"b' });
  assert.ok(escaped.includes('"a,""b"'));
  assert.equal(renderCaseCoverageCsv({ ...report, coverage: [] }).split("\r\n").length, 2);
});

test("HTML reports provide safe offline navigation, review summaries, and print styles", () => {
  const { pack, anchors } = operatorFixture();
  const report = createCaseReport(pack, anchors);
  const html = renderCaseReportHtml(report);
  assert.match(html, /Content-Security-Policy/);
  assert.match(html, /default-src 'none'/);
  assert.match(html, /Verification passed/);
  assert.match(html, /0 coverage requirements need review/);
  assert.match(html, /@media print/);
  assert.match(html, /Skip to report/);
  for (const id of ["assurance", "coverage", "evidence", "findings"]) {
    assert.ok(html.includes(`href="#${id}"`));
    assert.ok(html.includes(`id="${id}"`));
  }
  const hostile = renderCaseReportHtml({ ...report, casePackId: '<script>alert("x")</script>', valid: false });
  assert.ok(!hostile.includes("<script>"));
  assert.match(hostile, /Review required/);
});
