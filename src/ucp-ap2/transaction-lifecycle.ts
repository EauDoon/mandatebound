import { canonicalize, isSha256Digest } from "../canonical.js";
import type {
  EvidenceCoverageItem,
  TransactionLifecycleCorrelation,
  TransactionLifecycleEvidence,
} from "./types.js";
import { UcpAp2ParseError } from "./parse-error.js";
import { parseTimestampMillis } from "./primitives.js";

/**
 * Transaction lifecycle correlation. Groups events by transactionId, detects
 * duplicates and conflicts, surfaces orphan parent references, and emits
 * bounded coverage states per evidence requirement.
 */

export const TRANSACTION_LIFECYCLE_KINDS = Object.freeze([
  "checkout",
  "order",
  "refund",
  "return",
  "cancel",
  "adjustment",
] as const);

export type TransactionLifecycleKind = (typeof TRANSACTION_LIFECYCLE_KINDS)[number];

export function correlateTransactionLifecycle(
  input: readonly TransactionLifecycleEvidence[],
): readonly TransactionLifecycleCorrelation[] {
  const groups = new Map<string, TransactionLifecycleEvidence[]>();
  for (const event of input) {
    if (
      event.eventId.length === 0 ||
      event.transactionId.length === 0 ||
      !TRANSACTION_LIFECYCLE_KINDS.includes(event.kind) ||
      !isSha256Digest(event.sourceDigest)
    ) {
      throw new UcpAp2ParseError("Lifecycle evidence contains an invalid identifier, kind, or digest");
    }
    parseTimestampMillis(event.occurredAt, "lifecycle.occurredAt");
    const group = groups.get(event.transactionId) ?? [];
    group.push(event);
    groups.set(event.transactionId, group);
  }

  const correlations: TransactionLifecycleCorrelation[] = [];
  for (const [transactionId, group] of [...groups.entries()].sort(([left], [right]) =>
    left.localeCompare(right))) {
    const sorted = [...group].sort((left, right) =>
      left.occurredAt.localeCompare(right.occurredAt) || left.eventId.localeCompare(right.eventId));
    const byId = new Map<string, TransactionLifecycleEvidence[]>();
    for (const event of sorted) {
      const entries = byId.get(event.eventId) ?? [];
      entries.push(event);
      byId.set(event.eventId, entries);
    }
    const duplicateEventIds: string[] = [];
    const conflictingEventIds: string[] = [];
    for (const [eventId, entries] of byId) {
      if (entries.length > 1) {
        duplicateEventIds.push(eventId);
        if (new Set(entries.map((entry) => canonicalize(entry))).size > 1) {
          conflictingEventIds.push(eventId);
        }
      }
    }
    const eventIds = new Set(sorted.map((entry) => entry.eventId));
    const orphanEventIds = sorted
      .filter((entry) => (entry.parentEventIds ?? []).some((parent) => !eventIds.has(parent)))
      .map((entry) => entry.eventId);

    const conflictingIds = new Set(conflictingEventIds);
    const eligible = sorted.filter((entry) =>
      entry.upstreamValid && entry.evidenceEligible && !conflictingIds.has(entry.eventId));
    const coverage: EvidenceCoverageItem[] = [
      Object.freeze({
        requirement: "checkout_evidence",
        state: eligible.some((entry) => entry.kind === "checkout") ? "satisfied" : "unknown",
        sourceRefs: Object.freeze(
          eligible.filter((entry) => entry.kind === "checkout").map((entry) => entry.eventId),
        ),
      }),
      Object.freeze({
        requirement: "order_evidence",
        state: eligible.some((entry) => entry.kind === "order") ? "satisfied" : "unknown",
        sourceRefs: Object.freeze(
          eligible.filter((entry) => entry.kind === "order").map((entry) => entry.eventId),
        ),
      }),
      Object.freeze({
        requirement: "post_order_adjustments",
        state: eligible.some((entry) =>
          entry.kind === "refund" ||
          entry.kind === "return" ||
          entry.kind === "cancel" ||
          entry.kind === "adjustment")
          ? "satisfied"
          : "unknown",
        sourceRefs: Object.freeze(
          eligible
            .filter((entry) =>
              entry.kind === "refund" ||
              entry.kind === "return" ||
              entry.kind === "cancel" ||
              entry.kind === "adjustment")
            .map((entry) => entry.eventId),
        ),
      }),
      Object.freeze({
        requirement: "complete_upstream_history",
        state: "unknown",
        sourceRefs: Object.freeze([]),
        note: "Bounded imported evidence cannot prove that no upstream events are missing",
      }),
    ];
    correlations.push(Object.freeze({
      transactionId,
      events: Object.freeze(sorted),
      duplicateEventIds: Object.freeze(duplicateEventIds.sort()),
      conflictingEventIds: Object.freeze(conflictingEventIds.sort()),
      orphanEventIds: Object.freeze([...new Set(orphanEventIds)].sort()),
      historyCompleteness: "unknown",
      coverage: Object.freeze(coverage),
    }));
  }
  return Object.freeze(correlations);
}
