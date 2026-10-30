import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import {
  packAp2DisputeEvidence,
  reconcileAp2DisputeEvidencePack,
  verifyAp2DisputeEvidencePack,
} from "../dist/ap2-dispute.js";
import { CLI_EXIT, runCli } from "../dist/cli.js";
import { defaultCheckoutConstraints, makeFixture, makePackInput } from "./ap2-dispute-fixture.mjs";

const FIXTURES = new URL("./fixtures/", import.meta.url);
const readPack = (name) => JSON.parse(readFileSync(new URL(name, FIXTURES), "utf8"));
const GOLDEN_120 = "ap2-evidence-pack-1.2.0.json";
const OTHER_DIGEST = `sha256:${"0".repeat(64)}`;

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
