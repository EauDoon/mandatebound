import assert from "node:assert/strict";
import test from "node:test";
import {
  assembleAp2DisputeEvidence,
  packAp2DisputeEvidence,
  verifyAp2DisputeEvidencePack,
} from "../dist/ap2-dispute.js";
import { verifyAp2MandateChain } from "../dist/ucp-ap2.js";
import {
  arrayElement,
  asOf,
  codes,
  defaultCheckoutConstraints,
  makeFixture,
  makePackInput,
} from "./ap2-dispute-fixture.mjs";

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
