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

test("lifecycle ordering is locale independent UTF-16 code-unit order", () => {
  // Identifiers chosen so `localeCompare` and code-unit ordering disagree.
  // Under en-US collation "a" sorts before "B"; by code unit (0x61 > 0x42) it
  // does not. Output ordering must follow code units so that the same input
  // correlates identically on every host, which is what byte-identical
  // offline replay depends on.
  const transactionIds = ["txn-a", "txn-B", "txn-C", "txn-_", "txn-A"];
  const events = transactionIds.map((transactionId, index) => ({
    eventId: `evt-${index}`,
    kind: "checkout",
    transactionId,
    checkoutId: `chk-${index}`,
    occurredAt: "2026-07-23T00:00:00.000Z",
    sourceDigest: sha256Bytes(Buffer.from(`event-${index}`, "utf8")),
    upstreamValid: true,
    evidenceEligible: true,
  }));

  const correlations = correlateTransactionLifecycle(events);
  assert.deepEqual(
    correlations.map((entry) => entry.transactionId),
    [...transactionIds].sort(),
  );

  // Same check one level down: event ids inside a single transaction.
  const tied = correlateTransactionLifecycle(
    ["evt-b", "evt-A", "evt-a", "evt-B", "evt-_"].map((eventId, index) => ({
      eventId,
      kind: "order",
      transactionId: "txn-tie",
      checkoutId: "chk-tie",
      occurredAt: "2026-07-23T00:00:00.000Z",
      sourceDigest: sha256Bytes(Buffer.from(`tie-${index}`, "utf8")),
      upstreamValid: true,
      evidenceEligible: true,
    })),
  );
  assert.deepEqual(
    tied[0].events.map((entry) => entry.eventId),
    ["evt-A", "evt-B", "evt-_", "evt-a", "evt-b"],
  );

  // Repeated runs are stable, and the result is unaffected by the default locale.
  const once = JSON.stringify(correlateTransactionLifecycle(events));
  const twice = JSON.stringify(correlateTransactionLifecycle(events));
  assert.equal(once, twice);
});

test("lifecycle events are ordered by instant, not by RFC 3339 text", () => {
  const digest = sha256Bytes(Buffer.from("offset-order"));
  const event = (eventId, occurredAt) => ({
    eventId,
    kind: "order",
    transactionId: "txn-offset",
    occurredAt,
    sourceDigest: digest,
    upstreamValid: true,
    evidenceEligible: true,
  });
  // +14:00 on the next calendar day is earlier than noon Z, but the strings sort the other way.
  const [correlation] = correlateTransactionLifecycle([
    event("later", "2020-01-01T12:00:00Z"),
    event("earlier", "2020-01-02T00:00:00+14:00"),
    event("same-instant-z", "2020-01-01T11:00:00Z"),
    event("same-instant-offset", "2020-01-01T12:00:00+01:00"),
  ]);
  assert.deepEqual(
    correlation.events.map((entry) => entry.eventId),
    ["earlier", "same-instant-offset", "same-instant-z", "later"],
  );
});
