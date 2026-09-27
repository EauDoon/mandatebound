import assert from "node:assert/strict";
import test from "node:test";
import { verifyAp2CheckoutJwt } from "../dist/ucp-ap2.js";
import {
  createEcPair,
  createJwt,
  evaluationTime,
  keySnapshot,
  sourceDigest,
} from "./ucp-ap2-helpers.mjs";

/**
 * validateAp2CheckoutClaims is the bounded UCP Checkout schema gate. The
 * suite covered the signature, issuer and time paths, but only a handful of
 * its field-level rejections, so most of the fail-closed branches were
 * unexercised. Each case below drives one branch and asserts the report is
 * not upstream valid with the specific reason.
 */

const merchant = createEcPair("merchant-checkout-taxonomy");

const options = {
  merchantKeySnapshot: keySnapshot(merchant),
  expectedMerchantKeySourceDigest: sourceDigest,
  asOf: evaluationTime,
  allowedAlgorithms: ["ES256"],
};

function lineItem(overrides = {}) {
  return {
    id: "li-1",
    item: { id: "item-1", title: "Synthetic item" },
    quantity: 1,
    totals: [],
    ...overrides,
  };
}

function claims(overrides = {}) {
  return {
    id: "chk-1",
    line_items: [lineItem()],
    status: "completed",
    currency: "USD",
    totals: [],
    links: [],
    ...overrides,
  };
}

function schemaRejection(claimSet) {
  const report = verifyAp2CheckoutJwt({ ...options, token: createJwt(claimSet, merchant) });
  assert.equal(report.upstreamValid, false, "a malformed Checkout JWT must fail closed");
  assert.equal(report.value, null, "no value may be returned for a rejected Checkout JWT");
  const issue = report.issues.find((entry) => entry.code === "AP2_CHECKOUT_SCHEMA_INVALID");
  assert.notEqual(issue, undefined, `expected a schema rejection for ${JSON.stringify(claimSet).slice(0, 80)}`);
  assert.equal(issue.path, "checkoutJwt.claims");
  assert.equal(issue.impact, "upstream_validity");
  return issue.message;
}

test("the pinned UCP Checkout schema is accepted for every permitted status", () => {
  for (const status of [
    "incomplete",
    "requires_escalation",
    "ready_for_complete",
    "complete_in_progress",
    "completed",
    "canceled",
  ]) {
    const report = verifyAp2CheckoutJwt({
      ...options,
      token: createJwt(claims({ status }), merchant),
    });
    assert.equal(report.upstreamValid, true, status);
    assert.equal(report.evidenceEligible, true, JSON.stringify(report.issues));
  }

  // The optional merchant object is accepted when complete.
  const withMerchant = verifyAp2CheckoutJwt({
    ...options,
    token: createJwt(claims({ merchant: { id: "m-1", name: "Store" } }), merchant),
  });
  assert.equal(withMerchant.upstreamValid, true, JSON.stringify(withMerchant.issues));
});

test("missing or wrongly typed identity claims are rejected", () => {
  assert.equal(schemaRejection(claims({ id: undefined })), "Expected non-empty string at checkoutJwt.claims.id");
  assert.equal(schemaRejection(claims({ id: 7 })), "Expected non-empty string at checkoutJwt.claims.id");
  assert.equal(schemaRejection(claims({ currency: undefined })), "Expected non-empty string at checkoutJwt.claims.currency");
  assert.equal(schemaRejection(claims({ status: 7 })), "Checkout status is not in the pinned UCP enum");
  assert.equal(schemaRejection(claims({ status: "settled" })), "Checkout status is not in the pinned UCP enum");
});

test("line_items shape, size, and per-item fields are rejected", () => {
  assert.equal(schemaRejection(claims({ line_items: undefined })), "Checkout line_items are missing or exceed the item limit");
  assert.equal(schemaRejection(claims({ line_items: "one" })), "Checkout line_items are missing or exceed the item limit");
  assert.equal(
    schemaRejection(claims({ line_items: Array.from({ length: 129 }, () => lineItem()) })),
    "Checkout line_items are missing or exceed the item limit",
  );
  assert.equal(
    schemaRejection(claims({ line_items: ["not-an-object"] })),
    "Expected JSON object at checkoutJwt.claims.line_items[0]",
  );
  assert.equal(
    schemaRejection(claims({ line_items: [lineItem({ id: undefined })] })),
    "Expected non-empty string at checkoutJwt.claims.line_items[0].id",
  );
  assert.equal(
    schemaRejection(claims({ line_items: [lineItem({ item: undefined })] })),
    "Expected JSON object at checkoutJwt.claims.line_items[0].item",
  );
  assert.equal(
    schemaRejection(claims({ line_items: [lineItem({ item: { id: "item-1" } })] })),
    "Expected non-empty string at checkoutJwt.claims.line_items[0].item.title",
  );
  assert.equal(
    schemaRejection(claims({ line_items: [lineItem({ quantity: "one" })] })),
    "Expected safe integer at checkoutJwt.claims.line_items[0].quantity",
  );
  assert.equal(
    schemaRejection(claims({ line_items: [lineItem({ quantity: 0 })] })),
    "Checkout line-item quantity must be positive",
  );
  assert.equal(
    schemaRejection(claims({ line_items: [lineItem({ quantity: -1 })] })),
    "Checkout line-item quantity must be positive",
  );
});

test("totals on line items and at the top level are bounded and typed", () => {
  assert.equal(
    schemaRejection(claims({ line_items: [lineItem({ totals: "none" })] })),
    "Checkout totals are invalid at checkoutJwt.claims.line_items[0].totals",
  );
  assert.equal(
    schemaRejection(claims({ line_items: [lineItem({ totals: Array.from({ length: 129 }, () => ({ type: "subtotal", amount: 1 })) })] })),
    "Checkout totals are invalid at checkoutJwt.claims.line_items[0].totals",
  );
  assert.equal(
    schemaRejection(claims({ line_items: [lineItem({ totals: [7] })] })),
    "Expected JSON object at checkoutJwt.claims.line_items[0].totals[0]",
  );
  assert.equal(
    schemaRejection(claims({ line_items: [lineItem({ totals: [{ amount: 1 }] })] })),
    "Expected non-empty string at checkoutJwt.claims.line_items[0].totals[0].type",
  );
  assert.equal(
    schemaRejection(claims({ line_items: [lineItem({ totals: [{ type: "subtotal" }] })] })),
    "Expected safe integer at checkoutJwt.claims.line_items[0].totals[0].amount",
  );
  assert.equal(
    schemaRejection(claims({ totals: "none" })),
    "Checkout totals are invalid at checkoutJwt.claims.totals",
  );
  assert.equal(
    schemaRejection(claims({ totals: [7] })),
    "Expected JSON object at checkoutJwt.claims.totals[0]",
  );
});

test("links must be a bounded list of absolute URIs", () => {
  assert.equal(schemaRejection(claims({ links: undefined })), "Checkout links are missing or exceed the item limit");
  assert.equal(
    schemaRejection(claims({ links: Array.from({ length: 129 }, () => ({ type: "self", url: "https://m.example" })) })),
    "Checkout links are missing or exceed the item limit",
  );
  assert.equal(
    schemaRejection(claims({ links: ["nope"] })),
    "Expected JSON object at checkoutJwt.claims.links[0]",
  );
  assert.equal(
    schemaRejection(claims({ links: [{ url: "https://m.example" }] })),
    "Expected non-empty string at checkoutJwt.claims.links[0].type",
  );
  assert.equal(
    schemaRejection(claims({ links: [{ type: "self" }] })),
    "Expected non-empty string at checkoutJwt.claims.links[0].url",
  );
  assert.equal(
    schemaRejection(claims({ links: [{ type: "self", url: "/relative/path" }] })),
    "Checkout link URL is not an absolute URI",
  );
});

test("an incomplete merchant object is rejected", () => {
  assert.equal(schemaRejection(claims({ merchant: "store" })), "Expected JSON object at checkoutJwt.claims.merchant");
  assert.equal(
    schemaRejection(claims({ merchant: { name: "Store" } })),
    "Expected non-empty string at checkoutJwt.claims.merchant.id",
  );
  assert.equal(
    schemaRejection(claims({ merchant: { id: "m-1" } })),
    "Expected non-empty string at checkoutJwt.claims.merchant.name",
  );
});
