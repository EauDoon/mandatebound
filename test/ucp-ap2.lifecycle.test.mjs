import assert from "node:assert/strict";
import test from "node:test";
import { sha256Bytes } from "../dist/canonical.js";
import {
  correlateTransactionLifecycle,
} from "../dist/ucp-ap2.js";

test("lifecycle correlation never claims complete checkout/order history", () => {
  const events = [
    {
      eventId: "evt-checkout",
      kind: "checkout",
      transactionId: "txn-1",
      checkoutId: "chk-1",
      occurredAt: "2026-07-23T00:00:00.000Z",
      sourceDigest: sha256Bytes(Buffer.from("checkout")),
      upstreamValid: true,
      evidenceEligible: true,
    },
    {
      eventId: "evt-order",
      kind: "order",
      transactionId: "txn-1",
      checkoutId: "chk-1",
      orderId: "ord-1",
      parentEventIds: ["evt-checkout"],
      occurredAt: "2026-07-23T00:01:00.000Z",
      sourceDigest: sha256Bytes(Buffer.from("order")),
      upstreamValid: true,
      evidenceEligible: true,
    },
    {
      eventId: "evt-refund",
      kind: "refund",
      transactionId: "txn-1",
      orderId: "ord-1",
      parentEventIds: ["missing-webhook"],
      occurredAt: "2026-07-23T00:02:00.000Z",
      sourceDigest: sha256Bytes(Buffer.from("refund-a")),
      upstreamValid: true,
      evidenceEligible: true,
    },
    {
      eventId: "evt-refund",
      kind: "refund",
      transactionId: "txn-1",
      orderId: "ord-1",
      parentEventIds: ["evt-order"],
      occurredAt: "2026-07-23T00:03:00.000Z",
      sourceDigest: sha256Bytes(Buffer.from("refund-b")),
      upstreamValid: true,
      evidenceEligible: true,
    },
  ];
  const [correlation] = correlateTransactionLifecycle(events);
  assert.equal(correlation.historyCompleteness, "unknown");
  assert.deepEqual(correlation.duplicateEventIds, ["evt-refund"]);
  assert.deepEqual(correlation.conflictingEventIds, ["evt-refund"]);
  assert.deepEqual(correlation.orphanEventIds, ["evt-refund"]);
  assert.equal(
    correlation.coverage.find((entry) => entry.requirement === "complete_upstream_history").state,
    "unknown",
  );
});

test("lifecycle correlation validates inputs, sorts transactions, and distinguishes duplicate from conflict", () => {
  assert.deepEqual(correlateTransactionLifecycle([]), []);
  const sameDigest = sha256Bytes(Buffer.from("same-event"));
  const correlations = correlateTransactionLifecycle([
    {
      eventId: "evt-z",
      kind: "cancel",
      transactionId: "txn-z",
      occurredAt: "2026-07-23T00:02:00.000Z",
      sourceDigest: sameDigest,
      upstreamValid: false,
      evidenceEligible: false,
    },
    {
      eventId: "evt-z",
      kind: "cancel",
      transactionId: "txn-z",
      occurredAt: "2026-07-23T00:02:00.000Z",
      sourceDigest: sameDigest,
      upstreamValid: false,
      evidenceEligible: false,
    },
    {
      eventId: "evt-a",
      kind: "return",
      transactionId: "txn-a",
      occurredAt: "2026-07-23T00:00:00.000Z",
      sourceDigest: sha256Bytes(Buffer.from("return")),
      upstreamValid: true,
      evidenceEligible: true,
    },
    {
      eventId: "evt-adjust",
      kind: "adjustment",
      transactionId: "txn-a",
      parentEventIds: [],
      occurredAt: "2026-07-23T00:03:00.000Z",
      sourceDigest: sha256Bytes(Buffer.from("adjustment")),
      upstreamValid: true,
      evidenceEligible: true,
    },
  ]);
  assert.deepEqual(correlations.map((entry) => entry.transactionId), ["txn-a", "txn-z"]);
  assert.deepEqual(correlations[1].duplicateEventIds, ["evt-z"]);
  assert.deepEqual(correlations[1].conflictingEventIds, []);
  assert.equal(
    correlations[1].coverage.find((entry) => entry.requirement === "checkout_evidence").state,
    "unknown",
  );
  assert.equal(
    correlations[0].coverage.find((entry) => entry.requirement === "post_order_adjustments").state,
    "satisfied",
  );

  const base = {
    eventId: "evt",
    kind: "checkout",
    transactionId: "txn",
    occurredAt: "2026-07-23T00:00:00.000Z",
    sourceDigest: sha256Bytes(Buffer.from("event")),
    upstreamValid: true,
    evidenceEligible: true,
  };
  const contradictory = correlateTransactionLifecycle([base, { ...base, kind: "order" }])[0];
  assert.deepEqual(contradictory.duplicateEventIds, ["evt"]);
  assert.deepEqual(contradictory.conflictingEventIds, ["evt"]);
  assert.equal(
    contradictory.coverage.find((entry) => entry.requirement === "checkout_evidence").state,
    "unknown",
  );
  assert.equal(
    contradictory.coverage.find((entry) => entry.requirement === "order_evidence").state,
    "unknown",
  );
  for (const invalid of [
    { ...base, eventId: "" },
    { ...base, transactionId: "" },
    { ...base, kind: "ship" },
    { ...base, sourceDigest: "sha256:not-a-digest" },
    { ...base, occurredAt: "not-a-time" },
  ]) {
    assert.throws(() => correlateTransactionLifecycle([invalid]));
  }
});
