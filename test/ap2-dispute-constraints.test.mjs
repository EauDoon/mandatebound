import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import fc from "fast-check";
// Importing the helper also pins the global fast-check seed for this file.
import "./fast-check-seed.mjs";
import {
  AP2_DISPUTE_CONSTRAINT_SUPPORT,
  assembleAp2DisputeEvidence,
  packAp2DisputeEvidence,
  verifyAp2DisputeEvidencePack,
} from "../dist/ap2-dispute.js";
import { verifyAp2Mandate, verifyAp2MandateChain } from "../dist/ucp-ap2.js";
import {
  arrayElement,
  asOf,
  codes,
  defaultCheckoutConstraints,
  makeFixture,
  makePackInput,
} from "./ap2-dispute-fixture.mjs";
import { issueCodes, makeClosedAp2Fixture } from "./ucp-ap2-helpers.mjs";

// The presenting agent chooses which issuer-signed disclosures to reveal
// before it signs the terminal hop. A constraint it withholds must never
// widen the Mandate: the pinned AP2 rules match line items only against the
// revealed acceptable items, and every constraint entry has to be evaluated.

const WITHHELD = "AP2_CONSTRAINT_DISCLOSURE_WITHHELD";
const WITHHELD_ENTRY_MESSAGE = "Open Mandate withholds an issuer-signed constraint disclosure";
const WITHHELD_PART_MESSAGE = "Constraint withholds an issuer-signed disclosure needed to evaluate it";

function lineItems(acceptableItems, extraItems = []) {
  return {
    type: "checkout.line_items",
    items: [{ id: "requirement-1", acceptable_items: acceptableItems, quantity: 1 }, ...extraItems],
  };
}

function withheldIssues(result) {
  return result.issues.filter((issue) => issue.code === WITHHELD);
}

test("withholding every acceptable-item disclosure no longer widens line items to any SKU", () => {
  const allowedOnly = arrayElement({ id: "sku-allowed", title: "Allowed item" });
  const fixture = makeFixture({
    checkoutConstraints: [lineItems([allowedOnly.placeholder])],
  });
  const result = assembleAp2DisputeEvidence(fixture.input);
  assert.equal(result.status, "unresolved");
  assert.deepEqual(withheldIssues(result).map(({ path, message, impact }) => ({ path, message, impact })), [{
    path: "artifacts.checkout_mandate.token.claims.constraints[0]",
    message: WITHHELD_PART_MESSAGE,
    impact: "invalid",
  }]);
  // The withheld constraint is not separately reported as failed. (The Payment
  // Mandate's reference then fails too, because the Checkout Mandate it points
  // at was not selected.)
  assert.equal(result.issues.some((issue) => issue.code === "AP2_CONSTRAINT_FAILED"
    && issue.path.startsWith("artifacts.checkout_mandate.")), false);

  // Revealing the same element shows the purchase was outside the mandate.
  const revealed = makeFixture({
    checkoutConstraints: [lineItems([allowedOnly.placeholder])],
    checkoutRootDisclosures: [allowedOnly.encoded],
  });
  const revealedResult = assembleAp2DisputeEvidence(revealed.input);
  assert.equal(revealedResult.status, "unresolved");
  assert.equal(codes(revealedResult).has("AP2_CONSTRAINT_FAILED"), true);
  assert.equal(codes(revealedResult).has(WITHHELD), false);
});

test("a partial reveal that discloses the matching acceptable item stays verified", () => {
  const matching = arrayElement({ id: "sku-1", title: "Synthetic item" });
  const decoy = arrayElement({ id: "sku-decoy", title: "Decoy item" });
  const fixture = makeFixture({
    checkoutConstraints: [lineItems([decoy.placeholder, matching.placeholder])],
    checkoutRootDisclosures: [matching.encoded],
  });
  const result = assembleAp2DisputeEvidence(fixture.input);
  assert.equal(result.status, "evidence_verified", JSON.stringify(result.issues));
});

test("an issuer-signed literal empty acceptable_items keeps the SDK wildcard", () => {
  const fixture = makeFixture({ checkoutConstraints: [lineItems([])] });
  const result = assembleAp2DisputeEvidence(fixture.input);
  assert.equal(result.status, "evidence_verified", JSON.stringify(result.issues));
});

test("a withheld constraint entry fails closed for Checkout and Payment Mandates", () => {
  const merchantConstraint = arrayElement({
    type: "checkout.allowed_merchants",
    allowed: [{ id: "only-this-merchant", name: "Other Store" }],
  });
  const checkout = makeFixture({
    checkoutConstraints: [merchantConstraint.placeholder, ...defaultCheckoutConstraints().slice(1)],
  });
  const checkoutResult = assembleAp2DisputeEvidence(checkout.input);
  assert.equal(checkoutResult.status, "unresolved");
  assert.deepEqual(withheldIssues(checkoutResult).map(({ path, message }) => ({ path, message })), [{
    path: "artifacts.checkout_mandate.token.claims.constraints",
    message: WITHHELD_ENTRY_MESSAGE,
  }]);

  const capConstraint = arrayElement({ type: "payment.amount_range", currency: "USD", max: 100 });
  const payment = makeFixture({
    paymentConstraints: (reference) => [capConstraint.placeholder, reference],
  });
  const paymentResult = assembleAp2DisputeEvidence(payment.input);
  assert.equal(paymentResult.status, "unresolved");
  assert.deepEqual(withheldIssues(paymentResult).map(({ path, message }) => ({ path, message })), [{
    path: "artifacts.payment_mandate.token.claims.constraints",
    message: WITHHELD_ENTRY_MESSAGE,
  }]);
});

test("a withheld line-item requirement entry fails closed", () => {
  const hiddenRequirement = arrayElement({
    id: "requirement-hidden",
    acceptable_items: [{ id: "sku-2", title: "Second item" }],
    quantity: 1,
  });
  const fixture = makeFixture({
    checkoutConstraints: [lineItems([{ id: "sku-1", title: "Synthetic item" }], [hiddenRequirement.placeholder])],
  });
  const result = assembleAp2DisputeEvidence(fixture.input);
  assert.equal(result.status, "unresolved");
  assert.deepEqual(withheldIssues(result).map(({ path, message }) => ({ path, message })), [{
    path: "artifacts.checkout_mandate.token.claims.constraints[0]",
    message: WITHHELD_PART_MESSAGE,
  }]);
});

test("the official SDK claims_to_disclose redaction shape resolves unresolved", () => {
  // MandateClient.present(claims_to_disclose=...) at the pinned commit keeps
  // only the two-element disclosure that carries the delegate payload, so every
  // acceptable-item disclosure of a line_items-only open Checkout Mandate is
  // dropped from the root presentation before the agent signs.
  const item = arrayElement({ id: "sku-1", title: "Synthetic item" });
  const redacted = makeFixture({
    checkoutConstraints: [lineItems([item.placeholder])],
    checkoutRootOptions: { wrapRootPayload: true },
  });
  const redactedResult = assembleAp2DisputeEvidence(redacted.input);
  assert.equal(redactedResult.status, "unresolved");
  assert.deepEqual(withheldIssues(redactedResult).map(({ path }) => path), [
    "artifacts.checkout_mandate.token.claims.constraints[0]",
  ]);

  // The SDK's default presentation reveals the element and still verifies.
  const complete = makeFixture({
    checkoutConstraints: [lineItems([item.placeholder])],
    checkoutRootOptions: { wrapRootPayload: true },
    checkoutRootDisclosures: [item.encoded],
  });
  const completeResult = assembleAp2DisputeEvidence(complete.input);
  assert.equal(completeResult.status, "evidence_verified", JSON.stringify(completeResult.issues));
});

test("an undisclosed alternative delegate payload is not a withheld constraint", () => {
  const alternative = arrayElement({
    vct: "mandate.checkout.open.1",
    constraints: [lineItems([{ id: "sku-9", title: "Other item" }])],
  });
  const fixture = makeFixture({
    checkoutRootOptions: { rootPayloadAlternatives: [alternative.placeholder] },
  });
  const result = assembleAp2DisputeEvidence(fixture.input);
  assert.equal(result.status, "evidence_verified", JSON.stringify(result.issues));
});

test("a withheld constraint survives the Pack round trip and verifies unresolved", () => {
  const allowedOnly = arrayElement({ id: "sku-allowed", title: "Allowed item" });
  const fixture = makeFixture({ checkoutConstraints: [lineItems([allowedOnly.placeholder])] });
  const pack = packAp2DisputeEvidence(makePackInput(fixture));
  const verification = verifyAp2DisputeEvidencePack(pack, { expectedPackDigest: pack.packDigest });
  assert.equal(verification.status, "unresolved");
  assert.equal(verification.digestValid, true);
  assert.equal(verification.anchorMatched, true);
  assert.deepEqual([...codes(verification)], ["AP2_PACK_RESOLUTION_UNRESOLVED"]);
  assert.equal(codes(verification.resolution).has(WITHHELD), true);
});

test("the withheld diagnostic never reflects tokens or disclosed values", () => {
  const allowedOnly = arrayElement({ id: "sku-secret-allowed", title: "Secret title" });
  const capConstraint = arrayElement({ type: "payment.amount_range", currency: "USD", max: 4_321 });
  const fixture = makeFixture({
    checkoutConstraints: [lineItems([allowedOnly.placeholder])],
    paymentConstraints: (reference) => [capConstraint.placeholder, reference],
  });
  const result = assembleAp2DisputeEvidence(fixture.input);
  assert.equal(withheldIssues(result).length, 2);
  const rendered = JSON.stringify(result);
  for (const secret of [
    fixture.checkoutMandate,
    fixture.paymentMandate,
    allowedOnly.encoded,
    allowedOnly.placeholder["..."],
    capConstraint.placeholder["..."],
    "sku-secret-allowed",
    "Secret title",
    "4321",
  ]) {
    assert.equal(rendered.includes(secret), false, secret);
  }
  for (const issue of withheldIssues(result)) {
    assert.ok([WITHHELD_ENTRY_MESSAGE, WITHHELD_PART_MESSAGE].includes(issue.message), issue.message);
  }
});

test("the chain verifier reports a withheld constraint at the open Mandate", () => {
  const capConstraint = arrayElement({ type: "payment.amount_range", currency: "USD", max: 100 });
  const fixture = makeFixture({
    paymentConstraints: (reference) => [capConstraint.placeholder, reference],
  });
  const report = verifyAp2MandateChain({
    ...fixture.verificationPlan.paymentMandate,
    token: fixture.paymentMandate,
    expectedVct: "mandate.payment.1",
    expectedCheckoutHash: fixture.transactionId,
    expectedOpenCheckoutHash: fixture.openCheckoutHash,
    asOf,
  });
  assert.equal(report.upstreamValid, false);
  assert.deepEqual(
    report.issues.filter((issue) => issue.code === WITHHELD).map(({ path, impact }) => ({ path, impact })),
    [{ path: "token.claims.constraints", impact: "upstream_validity" }],
  );
});

// AP2 v0.2.0 open Payment Mandate constraints. The pinned reference shopping
// agent builds every open Payment Mandate as [payment.amount_range,
// payment.allowed_payees, payment.reference], and adds
// payment.allowed_payment_instruments for x402.

const FAILED = "AP2_CONSTRAINT_FAILED";
const INVALID = "AP2_CONSTRAINT_INVALID";
const UNSUPPORTED = "AP2_CONSTRAINT_UNSUPPORTED";
const UNSUPPORTED_MESSAGE = "Unknown or unsupported constraint types fail closed";
const PISP = Object.freeze({
  legal_name: "Synthetic Initiation Ltd",
  brand_name: "SynthPay",
  domain_name: "pisp.example",
});

function paymentWith(constraints, { paymentClaims = {}, paymentRootDisclosures = [] } = {}) {
  return makeFixture({
    paymentConstraints: (reference) => [...constraints, reference],
    paymentClaims,
    paymentRootDisclosures,
  });
}

function paymentConstraintIssues(result) {
  return result.issues
    .filter((issue) => issue.path.startsWith("artifacts.payment_mandate.token.claims.constraints"))
    .map(({ code, path, message }) => ({ code, path, message }));
}

function assertPaymentConstraint(fixture, expected) {
  const result = assembleAp2DisputeEvidence(fixture.input);
  if (expected === null) {
    assert.equal(result.status, "evidence_verified", JSON.stringify(result.issues));
    return result;
  }
  assert.equal(result.status, "unresolved");
  const found = paymentConstraintIssues(result);
  assert.deepEqual(found.map(({ code, path }) => ({ code, path })), [{
    code: expected,
    path: "artifacts.payment_mandate.token.claims.constraints[0]",
  }], JSON.stringify(result.issues));
  return result;
}

test("the reference agent's open Payment Mandate shape resolves and packs verified", () => {
  const payee = arrayElement({ id: "merchant-1", name: "Synthetic Store" });
  const decoy = arrayElement({ id: "merchant-decoy", name: "Decoy Store" });
  const fixture = makeFixture({
    paymentConstraints: (reference) => [
      { type: "payment.amount_range", currency: "USD", min: 0, max: 5_000 },
      { type: "payment.allowed_payees", allowed: [payee.placeholder, decoy.placeholder] },
      reference,
    ],
    paymentRootDisclosures: [payee.encoded],
  });
  const result = assembleAp2DisputeEvidence(fixture.input);
  assert.equal(result.status, "evidence_verified", JSON.stringify(result.issues));
  const pack = packAp2DisputeEvidence(makePackInput(fixture));
  const verification = verifyAp2DisputeEvidencePack(pack, { expectedPackDigest: pack.packDigest });
  assert.equal(verification.status, "verified", JSON.stringify(verification.issues));
});

test("payment.amount_range compares currency and inclusive bounds with the closed amount", () => {
  const range = { type: "payment.amount_range", currency: "USD", min: 1_000, max: 2_500 };
  // The closed Payment Mandate pays USD 2500.
  assertPaymentConstraint(paymentWith([range]), null);
  assertPaymentConstraint(paymentWith([{ ...range, min: 2_500 }]), null);
  assertPaymentConstraint(paymentWith([{ type: range.type, currency: "USD", max: 2_500 }]), null);
  assertPaymentConstraint(paymentWith([{ ...range, max: 2_499 }]), FAILED);
  assertPaymentConstraint(paymentWith([{ ...range, min: 2_501, max: 9_000 }]), FAILED);
  assertPaymentConstraint(paymentWith([{ ...range, currency: "EUR" }]), FAILED);
  const capped = assertPaymentConstraint(paymentWith([{ ...range, min: 0, max: 100 }]), FAILED);
  assert.equal(paymentConstraintIssues(capped)[0].message,
    "Amount-range constraint could not be satisfied by the closed Payment Mandate");
});

test("a malformed payment.amount_range is invalid, including a major-unit string amount", () => {
  // A JSON number with a fraction never reaches the evaluator: the strict
  // token parser rejects every non-integer number first.
  for (const malformed of [
    { type: "payment.amount_range", currency: "USD", max: "25.00" },
    { type: "payment.amount_range", currency: "USD", max: "2500" },
    { type: "payment.amount_range", currency: "USD", min: 3_000, max: 2_500 },
    { type: "payment.amount_range", currency: "USD", min: "0", max: 2_500 },
    { type: "payment.amount_range", max: 2_500 },
    { type: "payment.amount_range", currency: "", max: 2_500 },
    { type: "payment.amount_range", currency: "USD" },
  ]) {
    const result = assertPaymentConstraint(paymentWith([malformed]), INVALID);
    assert.equal(paymentConstraintIssues(result)[0].message, "Amount-range constraint is malformed");
  }
});

test("payment.allowed_payees matches the closed payee by id only", () => {
  const constraint = (allowed) => ({ type: "payment.allowed_payees", allowed });
  assertPaymentConstraint(paymentWith([constraint([{ id: "merchant-1", name: "Synthetic Store" }])]), null);
  assertPaymentConstraint(paymentWith([constraint([{ id: "merchant-2", name: "Synthetic Store" }])]), FAILED);
  // The SDK's name and website fallback is not accepted: merchant.json requires id.
  assertPaymentConstraint(paymentWith([constraint([{ name: "Synthetic Store", website: "https://merchant.example" }])]), FAILED);
  // A list whose elements are all withheld reveals nothing and fails.
  const hidden = arrayElement({ id: "merchant-1", name: "Synthetic Store" });
  assertPaymentConstraint(paymentWith([constraint([hidden.placeholder])]), FAILED);
  assertPaymentConstraint(paymentWith([constraint([hidden.placeholder])], {
    paymentRootDisclosures: [hidden.encoded],
  }), null);
  assertPaymentConstraint(paymentWith([{ type: "payment.allowed_payees" }]), FAILED);
});

test("payment.allowed_payment_instruments matches the closed instrument id", () => {
  const constraint = (allowed) => ({ type: "payment.allowed_payment_instruments", allowed });
  assertPaymentConstraint(paymentWith([constraint([{ id: "instrument-1", type: "card" }])]), null);
  const mismatch = assertPaymentConstraint(paymentWith([constraint([{ id: "instrument-2", type: "card" }])]), FAILED);
  assert.equal(paymentConstraintIssues(mismatch)[0].message,
    "Allowed-payment-instrument constraint could not be satisfied by the closed Payment Mandate");
});

test("payment.allowed_pisps requires a closed pisp equal to one allowed entry", () => {
  const constraint = { type: "payment.allowed_pisps", allowed: [PISP] };
  assertPaymentConstraint(paymentWith([constraint], { paymentClaims: { pisp: PISP } }), null);
  for (const field of ["legal_name", "brand_name", "domain_name"]) {
    assertPaymentConstraint(paymentWith([constraint], {
      paymentClaims: { pisp: { ...PISP, [field]: "different" } },
    }), FAILED);
  }
  const missing = assertPaymentConstraint(paymentWith([constraint]), FAILED);
  assert.equal(paymentConstraintIssues(missing)[0].message,
    "Allowed-PISP constraint could not be satisfied by the closed Payment Mandate");
});

test("payment constraints inside a Checkout Mandate stay unsupported with the unchanged message", () => {
  const fixture = makeFixture({
    checkoutConstraints: [
      ...defaultCheckoutConstraints(),
      { type: "payment.amount_range", currency: "USD", max: 5_000 },
    ],
  });
  const result = assembleAp2DisputeEvidence(fixture.input);
  assert.equal(result.status, "unresolved");
  assert.deepEqual(
    result.issues.filter((issue) => issue.code === UNSUPPORTED).map(({ path, message }) => ({ path, message })),
    [{ path: "artifacts.checkout_mandate.token.claims.constraints[2]", message: UNSUPPORTED_MESSAGE }],
  );
});

test("budget, agent recurrence and execution date keep failing closed with the unchanged message", () => {
  for (const constraint of [
    { type: "payment.budget", currency: "USD", max: 10_000 },
    { type: "payment.agent_recurrence", frequency: "MONTHLY", max_occurrences: 3 },
    { type: "payment.execution_date", not_before: "2026-07-01" },
  ]) {
    const result = assertPaymentConstraint(paymentWith([constraint]), UNSUPPORTED);
    assert.equal(paymentConstraintIssues(result)[0].message, UNSUPPORTED_MESSAGE);
  }
  assert.deepEqual(AP2_DISPUTE_CONSTRAINT_SUPPORT.failClosed, [
    "payment.agent_recurrence",
    "payment.budget",
    "payment.execution_date",
  ]);
  assert.equal(Object.isFrozen(AP2_DISPUTE_CONSTRAINT_SUPPORT), true);
  assert.equal(Object.isFrozen(AP2_DISPUTE_CONSTRAINT_SUPPORT.evaluated), true);
});

test("a malformed closed payee, amount or instrument fails the constraint without throwing", () => {
  const cases = [
    [{ type: "payment.amount_range", currency: "USD", max: 5_000 }, { payment_amount: "2500" }],
    [{ type: "payment.amount_range", currency: "USD", max: 5_000 }, { payment_amount: { currency: "USD", amount: "2500" } }],
    [{ type: "payment.amount_range", currency: "USD", max: 5_000 }, { payment_amount: undefined }],
    [{ type: "payment.allowed_payees", allowed: [{ id: "merchant-1" }] }, { payee: ["merchant-1"] }],
    [{ type: "payment.allowed_payees", allowed: [{ id: "merchant-1" }] }, { payee: { id: 7 } }],
    [{ type: "payment.allowed_payment_instruments", allowed: [{ id: "instrument-1" }] }, { payment_instrument: null }],
    [{ type: "payment.allowed_pisps", allowed: [PISP] }, { pisp: "pisp.example" }],
  ];
  for (const [constraint, paymentClaims] of cases) {
    const result = assembleAp2DisputeEvidence(paymentWith([constraint], { paymentClaims }).input);
    assert.equal(result.status, "unresolved");
    assert.deepEqual(paymentConstraintIssues(result).map(({ code }) => code), [FAILED], JSON.stringify(paymentClaims));
  }
});

test("the v1.1 direct-signed adapter still rejects the newly evaluated payment types", () => {
  for (const constraint of [
    { type: "payment.amount_range", currency: "USD", max: 5_000 },
    { type: "payment.allowed_payees", allowed: [{ id: "merchant-1" }] },
    { type: "payment.allowed_payment_instruments", allowed: [{ id: "instrument-1" }] },
    { type: "payment.allowed_pisps", allowed: [PISP] },
  ]) {
    const fixture = makeClosedAp2Fixture({
      vct: "mandate.payment.1",
      checkout_jwt: undefined,
      checkout_hash: undefined,
      transaction_id: "transaction-1",
      payee: { id: "merchant-1", name: "Synthetic Store" },
      payment_amount: { currency: "USD", amount: 2_500 },
      payment_instrument: { id: "instrument-1", type: "card" },
      pisp: PISP,
      constraints: [constraint],
    });
    const { expectedCheckoutJwt: _jwt, expectedCheckoutHash: _hash, ...options } = fixture.options;
    const result = verifyAp2Mandate({ ...options, expectedVct: "mandate.payment.1" });
    assert.equal(issueCodes(result).has(UNSUPPORTED), true, constraint.type);
  }
});

test("the published constraint support lists the evaluated and fail-closed types", () => {
  assert.deepEqual(AP2_DISPUTE_CONSTRAINT_SUPPORT.evaluated, [
    "checkout.allowed_merchants",
    "checkout.line_items",
    "payment.allowed_payees",
    "payment.allowed_payment_instruments",
    "payment.allowed_pisps",
    "payment.amount_range",
    "payment.reference",
  ]);
});

// Frozen Pack written by the released 2.0.0 code (dist/ built from tag v2.0.0,
// commit 32d525618e23678f86c754e4a536e4d094988a1b) from
// test/ap2-dispute-fixture.mjs: the reference agent's open Payment Mandate
// shape, with the allowed payee revealed and a decoy payee withheld. 2.0.0
// verified it unresolved because both payment constraints were unsupported.
// Synthetic data, public JWKs only. Never regenerate this file.
const PAYMENT_CONSTRAINTS_PACK_URL = new URL(
  "./fixtures/ap2-evidence-pack-2.0.0-payment-constraints.json",
  import.meta.url,
);
const PAYMENT_CONSTRAINTS_PACK_DIGEST = "sha256:6f7dde015569687a3ebbf3dc4efeaaa4a7efdc5501721e51b082282123d1f7fe";
const PAYMENT_CONSTRAINTS_200_REPORT_DIGEST = "sha256:401476c6bf032e371f97f74038ce53ed81c43fc4e4c349877bbd17d9fd65ae69";

test("a 2.0.0 Pack with payment constraints moves from unresolved to verified", () => {
  const pack = JSON.parse(readFileSync(PAYMENT_CONSTRAINTS_PACK_URL, "utf8"));
  assert.equal(pack.releaseVersion, "1.2.0");
  assert.equal(pack.packDigest, PAYMENT_CONSTRAINTS_PACK_DIGEST);
  const verification = verifyAp2DisputeEvidencePack(pack, { expectedPackDigest: PAYMENT_CONSTRAINTS_PACK_DIGEST });
  assert.equal(verification.status, "verified", JSON.stringify(verification.resolution.issues));
  assert.equal(verification.digestValid, true);
  assert.equal(verification.anchorMatched, true);
  assert.equal(verification.packDigest, PAYMENT_CONSTRAINTS_PACK_DIGEST);
  assert.notEqual(verification.reportDigest, PAYMENT_CONSTRAINTS_200_REPORT_DIGEST);
  assert.deepEqual(verification.issues, []);

  const privateMembers = new Set(["d", "p", "q", "dp", "dq", "qi", "k", "oth"]);
  const scan = (value) => Array.isArray(value)
    ? value.some(scan)
    : value !== null && typeof value === "object"
      ? Object.entries(value).some(([key, item]) => privateMembers.has(key) || scan(item))
      : typeof value === "string" && /PRIVATE KEY/u.test(value);
  assert.equal(scan(pack), false);
});

/** One selectively disclosable object property: the digest goes in `_sd`. */
let objectSalt = 0;
function objectProperty(name, value) {
  objectSalt += 1;
  const encoded = Buffer.from(JSON.stringify([`object-salt-${String(objectSalt)}`, name, value]), "utf8")
    .toString("base64url");
  return { encoded, digest: createHash("sha256").update(encoded, "ascii").digest("base64url") };
}

test("a constraint entry that withholds one of its own fields fails closed", () => {
  // The closed Payment Mandate pays USD 2500; the issuer signed min 3000.
  const min = objectProperty("min", 3_000);
  const range = { type: "payment.amount_range", currency: "USD", max: 5_000, _sd: [min.digest] };
  const withheld = assembleAp2DisputeEvidence(paymentWith([range]).input);
  assert.equal(withheld.status, "unresolved");
  assert.deepEqual(paymentConstraintIssues(withheld), [{
    code: WITHHELD,
    path: "artifacts.payment_mandate.token.claims.constraints[0]",
    message: WITHHELD_PART_MESSAGE,
  }]);
  const revealed = assembleAp2DisputeEvidence(paymentWith([range], { paymentRootDisclosures: [min.encoded] }).input);
  assert.deepEqual(paymentConstraintIssues(revealed).map(({ code }) => code), [FAILED]);
  // A fully disclosed field is evaluated like a literal one.
  const lowMin = objectProperty("min", 1_000);
  assertPaymentConstraint(paymentWith(
    [{ type: "payment.amount_range", currency: "USD", max: 5_000, _sd: [lowMin.digest] }],
    { paymentRootDisclosures: [lowMin.encoded] },
  ), null);
});

test("decoy digests where constraints are read fail closed like withheld disclosures", () => {
  // RFC 9901 lets an issuer add decoy digests to arrays and objects; the
  // resolver cannot tell one from a withheld disclosure.
  const decoyEntry = arrayElement({ type: "payment.amount_range", currency: "USD", max: 1 });
  const listDecoy = assembleAp2DisputeEvidence(paymentWith([decoyEntry.placeholder]).input);
  assert.deepEqual(withheldIssues(listDecoy).map(({ path }) => path), [
    "artifacts.payment_mandate.token.claims.constraints",
  ]);
  const fieldDecoy = objectProperty("unused", "decoy");
  const checkout = makeFixture({
    checkoutConstraints: [
      defaultCheckoutConstraints()[0],
      { ...defaultCheckoutConstraints()[1], _sd: [fieldDecoy.digest] },
    ],
  });
  const result = assembleAp2DisputeEvidence(checkout.input);
  assert.equal(result.status, "unresolved");
  assert.deepEqual(withheldIssues(result).map(({ path }) => path), [
    "artifacts.checkout_mandate.token.claims.constraints[1]",
  ]);
  // The withheld line-item constraint still counts as present.
  assert.equal(codes(result).has("AP2_REQUIRED_CONSTRAINT_MISSING"), false);
});

test("verifyAp2MandateChain applies the new payment constraint evaluation directly", () => {
  // 2.0.0 reported AP2_CONSTRAINT_UNSUPPORTED twice for this chain.
  const fixture = makeFixture({
    paymentConstraints: (reference) => [
      { type: "payment.amount_range", currency: "USD", min: 0, max: 3_000 },
      { type: "payment.allowed_payees", allowed: [{ id: "merchant-1", name: "Synthetic Store" }] },
      reference,
    ],
  });
  const report = verifyAp2MandateChain({
    ...fixture.verificationPlan.paymentMandate,
    token: fixture.paymentMandate,
    expectedVct: "mandate.payment.1",
    expectedCheckoutHash: fixture.transactionId,
    expectedOpenCheckoutHash: fixture.openCheckoutHash,
    asOf,
  });
  assert.equal(report.upstreamValid, true, JSON.stringify(report.issues));
  assert.deepEqual(report.issues, []);
});

test("property: the amount-range verdict is min <= amount <= max in the same currency", () => {
  fc.assert(fc.property(
    fc.integer({ min: 0, max: 10_000 }),
    fc.integer({ min: 0, max: 10_000 }),
    fc.integer({ min: 0, max: 10_000 }),
    fc.constantFrom("USD", "EUR"),
    (amount, a, b, currency) => {
      const min = Math.min(a, b);
      const max = Math.max(a, b);
      const fixture = paymentWith([{ type: "payment.amount_range", currency: "USD", min, max }], {
        paymentClaims: { payment_amount: { currency, amount } },
      });
      const result = assembleAp2DisputeEvidence(fixture.input);
      const expected = currency === "USD" && min <= amount && amount <= max;
      return (result.status === "evidence_verified") === expected;
    },
  ), { numRuns: 40 });
});
