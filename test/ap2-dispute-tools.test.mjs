import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import {
  createAp2EvidenceTimeline,
  packAp2DisputeEvidence,
  reconcileAp2DisputeEvidencePack,
  renderAp2EvidenceTimelineCsv,
  renderAp2EvidenceTimelineHtml,
  renderAp2EvidenceTimelineMarkdown,
  verifyAp2DisputeEvidencePack,
} from "../dist/ap2-dispute.js";
import { CLI_EXIT, runCli } from "../dist/cli.js";
import { csvCell, renderCaseCoverageCsv, renderCaseReportMarkdown } from "../dist/report.js";
import { defaultCheckoutConstraints, makeFixture, makePackInput } from "./ap2-dispute-fixture.mjs";

const FIXTURES = new URL("./fixtures/", import.meta.url);
const readPack = (name) => JSON.parse(readFileSync(new URL(name, FIXTURES), "utf8"));
const GOLDEN_120 = "ap2-evidence-pack-1.2.0.json";
const NO_EXP_120 = "ap2-evidence-pack-1.2.0-no-delegated-exp.json";
const OTHER_DIGEST = `sha256:${"0".repeat(64)}`;
const sha256 = (text) => `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`;

function collector() {
  let value = "";
  return {
    stream: new Writable({ write(chunk, _encoding, next) { value += chunk; next(); } }),
    value: () => value,
  };
}

async function cli(argv, input) {
  const stdout = collector();
  const stderr = collector();
  const code = await runCli(argv, { stdin: Readable.from([input]), stdout: stdout.stream, stderr: stderr.stream });
  return { code, stdout: stdout.value(), stderr: stderr.value() };
}

function packFor(fixture, revocationStatus) {
  return packAp2DisputeEvidence(makePackInput(fixture, revocationStatus));
}

function tamper(pack) {
  return { ...pack, createdAt: "2026-07-22T23:00:00.000Z" };
}

// ---------------------------------------------------------------- reconcile

function states(reconciliation) {
  return Object.fromEntries(reconciliation.checks.map(({ check, state }) => [check, state]));
}

test("reconcile reports a consistent payment as three matched checks", () => {
  const pack = packFor(makeFixture());
  const result = reconcileAp2DisputeEvidencePack(pack, { expectedPackDigest: pack.packDigest });
  assert.equal(result.schemaId, "MandateBoundAp2PaymentReconciliation/v1");
  assert.deepEqual(states(result), {
    payee_matches_checkout_merchant: "matched",
    currency_matches_checkout: "matched",
    amount_matches_checkout_total: "matched",
  });
  assert.equal(result.summary, "consistent");
  assert.equal(result.verificationStatus, "verified");
  assert.equal(result.packDigest, pack.packDigest);
  assert.equal(result.legalEffect, "not-determined");
  const again = reconcileAp2DisputeEvidencePack(pack, { expectedPackDigest: pack.packDigest });
  assert.equal(again.reconciliationDigest, result.reconciliationDigest);
  assert.equal(
    result.verificationReportDigest,
    verifyAp2DisputeEvidencePack(pack, { expectedPackDigest: pack.packDigest }).reportDigest,
  );
});

test("reconcile flags a payee or amount mismatch while verify still passes it", () => {
  for (const [paymentClaims, mismatched] of [
    [{ payee: { id: "other-merchant", name: "Other Store" } }, "payee_matches_checkout_merchant"],
    [{ payment_amount: { currency: "USD", amount: 999_999 } }, "amount_matches_checkout_total"],
  ]) {
    const pack = packFor(makeFixture({ paymentClaims }));
    const options = { expectedPackDigest: pack.packDigest };
    const verification = verifyAp2DisputeEvidencePack(pack, options);
    // The signal is non-gating: the verdict and its report are unchanged.
    assert.equal(verification.status, "verified", JSON.stringify(verification.issues));
    const result = reconcileAp2DisputeEvidencePack(pack, options);
    assert.equal(states(result)[mismatched], "mismatched");
    assert.equal(result.checks.filter((entry) => entry.state === "mismatched").length, 1);
    assert.equal(result.summary, "inconsistent");
    assert.equal(result.verificationReportDigest, verification.reportDigest);
  }
});

test("reconcile compares the amount only in the same currency", () => {
  const pack = packFor(makeFixture({ paymentClaims: { payment_amount: { currency: "EUR", amount: 2_500 } } }));
  const result = reconcileAp2DisputeEvidencePack(pack, { expectedPackDigest: pack.packDigest });
  assert.deepEqual(states(result), {
    payee_matches_checkout_merchant: "matched",
    currency_matches_checkout: "mismatched",
    amount_matches_checkout_total: "not_comparable",
  });
  assert.equal(result.summary, "inconsistent");
});

test("reconcile cannot compare a Checkout without a merchant or a single total", () => {
  const lineItemsOnly = defaultCheckoutConstraints().slice(1);
  const noMerchant = packFor(makeFixture({
    checkoutConstraints: lineItemsOnly,
    checkoutClaims: { merchant: undefined },
  }));
  const noMerchantResult = reconcileAp2DisputeEvidencePack(noMerchant, { expectedPackDigest: noMerchant.packDigest });
  assert.equal(noMerchantResult.verificationStatus, "verified");
  assert.equal(states(noMerchantResult).payee_matches_checkout_merchant, "not_comparable");
  assert.equal(states(noMerchantResult).amount_matches_checkout_total, "matched");
  assert.equal(noMerchantResult.summary, "not_comparable");

  for (const totals of [
    [{ type: "subtotal", amount: 2_500 }],
    [{ type: "total", amount: 2_500 }, { type: "total", amount: 2_500 }],
  ]) {
    const pack = packFor(makeFixture({ checkoutClaims: { totals } }));
    const result = reconcileAp2DisputeEvidencePack(pack, { expectedPackDigest: pack.packDigest });
    assert.equal(result.verificationStatus, "verified", JSON.stringify(totals));
    assert.equal(states(result).amount_matches_checkout_total, "not_comparable");
    assert.equal(result.summary, "not_comparable");
  }
});

test("reconcile compares nothing for a tampered, mis-anchored or unresolved Pack", () => {
  const pack = packFor(makeFixture({ paymentClaims: { payee: { id: "other-merchant", name: "Other" } } }));
  const unresolved = packFor(makeFixture({ checkoutMerchantId: "merchant-2" }));
  for (const [value, expectedPackDigest] of [
    [tamper(pack), pack.packDigest],
    [pack, OTHER_DIGEST],
    [unresolved, unresolved.packDigest],
  ]) {
    const result = reconcileAp2DisputeEvidencePack(value, { expectedPackDigest });
    assert.equal(result.verificationStatus, "unresolved");
    assert.deepEqual(new Set(result.checks.map((entry) => entry.state)), new Set(["not_comparable"]));
    assert.equal(result.summary, "not_comparable");
  }
  const invalid = reconcileAp2DisputeEvidencePack({}, { expectedPackDigest: OTHER_DIGEST });
  assert.equal(invalid.packDigest, null);
  assert.equal(invalid.transactionId, null);
  assert.equal(invalid.summary, "not_comparable");
});

test("reconcile emits match states only, never amounts, identifiers or tokens", () => {
  const fixture = makeFixture({
    checkoutMerchantId: "merchant-secret-41",
    allowedMerchantId: "merchant-secret-41",
    paymentClaims: {
      payee: { id: "payee-secret-77", name: "Secret Payee" },
      payment_amount: { currency: "USD", amount: 987_654_321 },
      payment_instrument: { id: "instrument-secret-5", type: "card" },
    },
  });
  const pack = packFor(fixture);
  const result = reconcileAp2DisputeEvidencePack(pack, { expectedPackDigest: pack.packDigest });
  assert.deepEqual(Object.keys(result), [
    "schemaId", "transactionId", "packDigest", "verificationStatus", "verificationReportDigest",
    "checks", "summary", "legalEffect", "reconciliationDigest",
  ]);
  for (const entry of result.checks) assert.deepEqual(Object.keys(entry), ["check", "state"]);
  const rendered = JSON.stringify(result);
  for (const secret of [
    "merchant-secret-41", "payee-secret-77", "Secret Payee", "987654321", "instrument-secret-5", "sku-1",
    fixture.checkoutJwt, fixture.checkoutMandate, fixture.paymentMandate, fixture.paymentReceipt,
  ]) {
    assert.equal(rendered.includes(secret), false, secret.slice(0, 24));
  }
});

test("the frozen 1.2.0 golden Pack reconciles consistent", () => {
  const pack = readPack(GOLDEN_120);
  const result = reconcileAp2DisputeEvidencePack(pack, { expectedPackDigest: pack.packDigest });
  assert.equal(result.verificationStatus, "verified");
  assert.equal(result.summary, "consistent");
});

test("ap2-dispute reconcile exits 0, 5, 3 and 2 as documented", async () => {
  const consistent = packFor(makeFixture());
  const envelope = JSON.stringify({ ok: true, result: consistent });
  const ok = await cli(["ap2-dispute", "reconcile", "-", "--expected-pack-digest", consistent.packDigest], envelope);
  assert.equal(ok.code, CLI_EXIT.SUCCESS, ok.stdout);
  assert.equal(JSON.parse(ok.stdout).ok, true);
  assert.equal(JSON.parse(ok.stdout).result.summary, "consistent");

  const mismatch = packFor(makeFixture({ paymentClaims: { payment_amount: { currency: "USD", amount: 1 } } }));
  const conflict = await cli(
    ["ap2-dispute", "reconcile", "-", "--expected-pack-digest", mismatch.packDigest],
    JSON.stringify(mismatch),
  );
  assert.equal(conflict.code, CLI_EXIT.CONFLICT);
  assert.equal(JSON.parse(conflict.stdout).ok, false);
  const verified = await cli(
    ["ap2-dispute", "verify", "-", "--expected-pack-digest", mismatch.packDigest],
    JSON.stringify(mismatch),
  );
  assert.equal(verified.code, CLI_EXIT.SUCCESS);

  const revoked = packFor(makeFixture(), "revoked");
  const unverified = await cli(
    ["ap2-dispute", "reconcile", "-", "--expected-pack-digest", revoked.packDigest],
    JSON.stringify(revoked),
  );
  assert.equal(unverified.code, CLI_EXIT.CONFLICT);
  assert.equal(JSON.parse(unverified.stdout).result.verificationStatus, "unresolved");

  const invalid = await cli(["ap2-dispute", "reconcile", "-", "--expected-pack-digest", OTHER_DIGEST], "{}");
  assert.equal(invalid.code, CLI_EXIT.INVALID);
  const missingAnchor = await cli(["ap2-dispute", "reconcile", "-"], envelope);
  assert.equal(missingAnchor.code, CLI_EXIT.USAGE);
  const badFormat = await cli(
    ["ap2-dispute", "reconcile", "-", "--format", "csv", "--expected-pack-digest", consistent.packDigest],
    envelope,
  );
  assert.equal(badFormat.code, CLI_EXIT.USAGE);
});

// ----------------------------------------------------- Markdown and CSV

const GOLDEN_HTML = Object.freeze({
  [GOLDEN_120]: "sha256:cad66d1ad865125d08ef4605ec092298348b989b4a99f151caec9e86a61687e8",
  [NO_EXP_120]: "sha256:7857bbf76ee37353f3e797026ae7ab0500ab1d8872dcdbccf11c217a200f75b3",
});
const GOLDEN_TIMELINE_JSON = Object.freeze({
  [GOLDEN_120]: "sha256:21d7e4223cc36f33f3af4b0dfce8ab0ffea201f86c6aeac306cd142dc25cbf5b",
  [NO_EXP_120]: "sha256:754fe26770cc923785307d19e1886bbf0f08a4708d8f37f785d859f9da618652",
});

test("HTML and JSON timeline renderings of the frozen Packs are byte-identical to 2.0.0", () => {
  // Digests of the 2.0.0 tag's own renderings of these Packs.
  for (const name of [GOLDEN_120, NO_EXP_120]) {
    const pack = readPack(name);
    const options = { expectedPackDigest: pack.packDigest };
    assert.equal(sha256(renderAp2EvidenceTimelineHtml(pack, options)), GOLDEN_HTML[name], name);
    assert.equal(sha256(JSON.stringify(createAp2EvidenceTimeline(pack, options))), GOLDEN_TIMELINE_JSON[name], name);
  }
});

test("case-report Markdown and CSV are unchanged by the shared escaper", () => {
  // Digests of the 2.0.0 tag's own renderings of this hostile report.
  const report = {
    casePackId: "<img src=x>|[click](javascript:x)\n# fake_case.v1",
    casePackDigest: `sha256:${"a".repeat(64)}`,
    assessedAt: "2026-07-23T00:00:00.000Z",
    valid: false,
    status: { integrity: "verified", coverage: "unresolved" },
    coverage: [
      { requirementId: "=HYPERLINK(1)", status: "missing", matchedEnvelopes: 0 },
      { requirementId: "​+cmd", status: "verified", matchedEnvelopes: 2 },
    ],
    findings: [{ code: "bad_code", path: "/a-b", message: "<script>alert(1)</script> *x* `y`" }],
  };
  assert.equal(sha256(renderCaseReportMarkdown(report)), "sha256:17091140e2dd69480e88171887b8536b73adf6f91842e5a37a8045bbc348218a");
  assert.equal(sha256(renderCaseCoverageCsv(report)), "sha256:0e319e2b47ccc0155a90a90502e09b5100f49a52836516f878aa35cedddd53db");
  assert.equal(csvCell("⁠=1+2"), "\"'⁠=1+2\"");
});

test("the Markdown timeline is deterministic, escaped and metadata-only", () => {
  const fixture = makeFixture();
  const pack = packFor(fixture);
  const options = { expectedPackDigest: pack.packDigest };
  const markdown = renderAp2EvidenceTimelineMarkdown(pack, options);
  assert.equal(renderAp2EvidenceTimelineMarkdown(pack, options), markdown);
  const verification = verifyAp2DisputeEvidencePack(pack, options);
  assert.ok(markdown.startsWith("# AP2 Evidence Timeline\n"));
  assert.ok(markdown.includes("- Status: verified\n"));
  assert.ok(markdown.includes("Non\\-binding technical evidence report\\."));
  assert.ok(markdown.includes("## Verification issues\n\nNone.\n"));
  assert.ok(markdown.includes(`- Pack digest: ${pack.packDigest}\n`));
  assert.ok(markdown.includes(`- Retained anchor: ${pack.packDigest}\n`));
  assert.ok(markdown.includes(`- Report digest: ${verification.reportDigest}\n`));
  assert.ok(markdown.includes("- Legal effect: not\\-determined\n"));
  // Identifier punctuation is escaped and cannot open a new table column.
  assert.ok(markdown.includes("Checkout version checkout\\-version\\-1"));
  const rows = markdown.split("\n").filter((line) => line.startsWith("| "));
  assert.equal(rows.length, 2 + createAp2EvidenceTimeline(pack, options).length);
  for (const row of rows) assert.equal(row.split(/(?<!\\)\|/u).length, 8, row);
  for (const raw of [fixture.checkoutMandate, fixture.paymentMandate, fixture.checkoutJwt, fixture.paymentReceipt,
    pack.revocations[0].snapshotBase64]) {
    assert.equal(markdown.includes(raw), false);
  }
});

test("the CSV timeline has one quoted row per event and CRLF line endings", () => {
  const fixture = makeFixture();
  const pack = packFor(fixture, "revoked");
  const options = { expectedPackDigest: pack.packDigest };
  const csv = renderAp2EvidenceTimelineCsv(pack, options);
  assert.equal(renderAp2EvidenceTimelineCsv(pack, options), csv);
  assert.ok(csv.endsWith("\r\n"));
  assert.equal(csv.replaceAll("\r\n", "").includes("\n"), false);
  const lines = csv.slice(0, -2).split("\r\n");
  const timeline = createAp2EvidenceTimeline(pack, options);
  assert.equal(lines.length, 1 + timeline.length);
  assert.equal(lines[0], [
    "transactionId", "verificationStatus", "occurredAt", "eventType", "label", "state", "digest",
    "sourceRefs", "legalEffect",
  ].map((name) => `"${name}"`).join(","));
  for (const line of lines) assert.match(line, /^"[^"]*"(,"[^"]*"){8}$/u);
  assert.ok(lines.slice(1).every((line) => line.includes(",\"unresolved\",")));
  assert.ok(lines.some((line) => line.includes("\"revocation_check\"") && line.includes("\"revoked\"")));
  for (const raw of [fixture.checkoutMandate, fixture.paymentMandate, fixture.checkoutJwt,
    pack.revocations[0].snapshotBase64]) {
    assert.equal(csv.includes(raw), false);
  }
});

test("ap2-dispute render prints Markdown and CSV with the HTML exit codes", async () => {
  const pack = packFor(makeFixture());
  const input = JSON.stringify({ ok: true, result: pack });
  for (const [format, check] of [
    ["markdown", (text) => text.startsWith("# AP2 Evidence Timeline\n")],
    ["csv", (text) => text.startsWith("\"transactionId\",")],
  ]) {
    const args = ["ap2-dispute", "render", "-", "--format", format, "--expected-pack-digest"];
    const ok = await cli([...args, pack.packDigest], input);
    assert.equal(ok.code, CLI_EXIT.SUCCESS, format);
    assert.ok(check(ok.stdout), format);
    assert.equal(ok.stdout, format === "markdown"
      ? renderAp2EvidenceTimelineMarkdown(pack, { expectedPackDigest: pack.packDigest })
      : renderAp2EvidenceTimelineCsv(pack, { expectedPackDigest: pack.packDigest }));

    const wrongAnchor = await cli([...args, OTHER_DIGEST], input);
    assert.equal(wrongAnchor.code, CLI_EXIT.CONFLICT, format);
    assert.ok(wrongAnchor.stdout.includes("unresolved"), format);
    const tampered = await cli([...args, pack.packDigest], JSON.stringify(tamper(pack)));
    assert.equal(tampered.code, CLI_EXIT.CONFLICT, format);
    const invalid = await cli([...args, pack.packDigest], "{}");
    assert.equal(invalid.code, CLI_EXIT.INVALID, format);
    const missingAnchor = await cli(["ap2-dispute", "render", "-", "--format", format], input);
    assert.equal(missingAnchor.code, CLI_EXIT.USAGE, format);
  }
});
