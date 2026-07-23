import assert from "node:assert/strict";
import test from "node:test";
import {
  AppealError,
  appealEventDigest,
  assertAppealAppendable,
  replayAppealEvents,
} from "../dist/appeals.js";

const DIGEST = `sha256:${"a".repeat(64)}`;

function event(overrides = {}) {
  return {
    schemaVersion: "1.0.0",
    artifactId: "appeal-event-1",
    appealId: "appeal-1",
    decisionId: "decision-1",
    sequence: 1,
    eventType: "filed",
    actor: { id: "principal-1", role: "principal" },
    occurredAt: "2026-07-23T00:00:00.000Z",
    reasonCodes: ["review_requested"],
    ...overrides,
  };
}

function child(parent, overrides = {}) {
  return event({
    artifactId: `appeal-event-${parent.sequence + 1}`,
    appealId: parent.appealId,
    decisionId: parent.decisionId,
    sequence: parent.sequence + 1,
    previousEventDigest: appealEventDigest(parent),
    eventType: "review_started",
    actor: { id: "reviewer-1", role: "reviewer" },
    reasonCodes: ["review_started"],
    ...overrides,
  });
}

function expectAppealCode(fn, code) {
  assert.throws(fn, (error) => error instanceof AppealError && error.code === code);
}

test("empty histories and completeness checkpoints are explicit", () => {
  const empty = replayAppealEvents([]);
  assert.equal(empty.status, "conflicted");
  assert.equal(empty.completeness.state, "unproven");
  assert.deepEqual(empty.issues.map((issue) => issue.code), ["ALB_APPEAL_EMPTY"]);

  const checkpointedEmpty = replayAppealEvents([], { sequence: 1, headDigest: DIGEST });
  assert.equal(checkpointedEmpty.completeness.state, "mismatch");

  const filed = event();
  const verified = replayAppealEvents([filed], { sequence: 1, headDigest: appealEventDigest(filed) });
  assert.equal(verified.status, "open");
  assert.equal(verified.completeness.state, "verified");
  filed.reasonCodes.push("caller_mutation");
  assert.deepEqual(verified.events[0].reasonCodes, ["review_requested"]);

  const mismatch = replayAppealEvents([event()], { sequence: 2, headDigest: DIGEST });
  assert.equal(mismatch.status, "conflicted");
  assert.equal(mismatch.completeness.state, "mismatch");
  assert(mismatch.issues.some((issue) => issue.code === "ALB_APPEAL_CHECKPOINT"));
});

test("terminal statuses replay without mutating the original decision lineage", () => {
  for (const eventType of ["upheld", "withdrawn"]) {
    const filed = event();
    const terminal = child(filed, { eventType, reasonCodes: [`appeal_${eventType}`] });
    const history = replayAppealEvents([filed, terminal]);
    assert.equal(history.status, eventType);
    assert.equal(history.issues.length, 0);
  }

  const filed = event();
  const reversed = child(filed, {
    eventType: "reversed",
    reasonCodes: ["appeal_reversed"],
    supersedingDecisionId: "decision-2",
  });
  assert.equal(replayAppealEvents([filed, reversed]).status, "reversed");
});

test("replay exposes binding, sequence, chain, identity, fork, and terminal conflicts", () => {
  const filed = event();
  const firstChild = child(filed);
  const fork = child(filed, { artifactId: "appeal-event-fork", sequence: 3 });
  const afterTerminal = child(firstChild, {
    artifactId: "appeal-event-upheld",
    eventType: "upheld",
  });
  const tooLate = child(afterTerminal, { artifactId: "appeal-event-too-late" });
  const malformed = child(filed, {
    appealId: "another-appeal",
    decisionId: "another-decision",
    sequence: 7,
    previousEventDigest: DIGEST,
  });

  const issueCodes = replayAppealEvents([filed, malformed]).issues.map((issue) => issue.code);
  assert(issueCodes.includes("ALB_APPEAL_BINDING"));
  assert(issueCodes.includes("ALB_APPEAL_SEQUENCE"));
  assert(issueCodes.includes("ALB_APPEAL_CHAIN"));

  const forkCodes = replayAppealEvents([filed, firstChild, fork]).issues.map((issue) => issue.code);
  assert(forkCodes.includes("ALB_APPEAL_FORK"));
  assert(forkCodes.includes("ALB_APPEAL_CHAIN"));

  const duplicateCodes = replayAppealEvents([filed, filed]).issues.map((issue) => issue.code);
  assert(duplicateCodes.includes("ALB_APPEAL_DUPLICATE"));
  const equivocation = { ...filed, eventType: "review_started" };
  assert(replayAppealEvents([filed, equivocation]).issues.some((issue) => issue.code === "ALB_APPEAL_EQUIVOCATION"));
  assert(replayAppealEvents([filed, firstChild, afterTerminal, tooLate]).issues.some(
    (issue) => issue.code === "ALB_APPEAL_TERMINAL",
  ));
});

test("replay reports invalid genesis and event-specific evidence constraints", () => {
  const invalidGenesis = event({ eventType: "review_started", previousEventDigest: DIGEST });
  assert(replayAppealEvents([invalidGenesis]).issues.some((issue) => issue.code === "ALB_APPEAL_GENESIS"));

  const filed = event();
  const evidence = child(filed, { eventType: "evidence_added" });
  assert(replayAppealEvents([filed, evidence]).issues.some((issue) => issue.code === "ALB_APPEAL_EVIDENCE"));

  const reversal = child(filed, { eventType: "reversed" });
  assert(replayAppealEvents([filed, reversal]).issues.some((issue) => issue.code === "ALB_APPEAL_SUPERSESSION"));

  const improper = child(filed, { supersedingDecisionId: "decision-2" });
  assert(replayAppealEvents([filed, improper]).issues.some((issue) => issue.code === "ALB_APPEAL_SUPERSESSION"));
});

test("append guards reject invalid genesis, conflicts, terminal writes, forks, duplicates, and invalid events", () => {
  expectAppealCode(
    () => assertAppealAppendable([], event({ sequence: 2, previousEventDigest: DIGEST })),
    "ALB_APPEAL_GENESIS",
  );

  const filed = event();
  const invalidGenesis = event({ eventType: "review_started" });
  expectAppealCode(() => assertAppealAppendable([invalidGenesis], child(invalidGenesis)), "ALB_APPEAL_CONFLICT");

  const upheld = child(filed, { eventType: "upheld" });
  expectAppealCode(() => assertAppealAppendable([filed, upheld], child(upheld)), "ALB_APPEAL_TERMINAL");

  expectAppealCode(
    () => assertAppealAppendable([filed], child(filed, { appealId: "different" })),
    "ALB_APPEAL_BINDING",
  );
  expectAppealCode(
    () => assertAppealAppendable([filed], child(filed, { sequence: 3 })),
    "ALB_APPEAL_FORK",
  );
  expectAppealCode(
    () => assertAppealAppendable([filed], child(filed, { artifactId: filed.artifactId })),
    "ALB_APPEAL_DUPLICATE",
  );
  expectAppealCode(
    () => assertAppealAppendable([filed], child(filed, { eventType: "evidence_added" })),
    "ALB_APPEAL_EVIDENCE",
  );

  const evidence = child(filed, { eventType: "evidence_added", evidenceBundleDigest: DIGEST });
  assert.doesNotThrow(() => assertAppealAppendable([filed], evidence));
});
