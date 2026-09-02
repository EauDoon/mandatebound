import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { appealEventDigest } from "../dist/appeals.js";
import { canonicalize } from "../dist/canonical.js";
import {
  DEFAULT_JSONL_STORE_LIMITS,
  JsonlStore,
  MemoryStore,
  StoreError,
  storeRecordHash,
  verifyStoreRecords,
} from "../dist/store.js";
import { DEFAULT_STRICT_JSON_LIMITS } from "../dist/strict-json.js";
import { deriveLiabilityDecisionId } from "../dist/validation.js";

const DIGEST = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;

function decision(overrides = {}) {
  const { artifactId: _artifactId, ...fields } = overrides;
  const outcome = fields.outcome ?? "principal";
  const disposition = fields.disposition ?? (outcome === "unresolved" ? "indeterminate" : "allocated");
  const policyOutcome = fields.policyOutcome ?? outcome;
  const reasonCodes = fields.reasonCodes ?? [outcome === "unresolved" ? "unresolved_default" : "inside_mandate"];
  const pins = fields.pins ?? {
    asOf: "2026-07-23T00:00:00.000Z",
    policyDigest: DIGEST,
    trustSnapshotDigest: DIGEST,
    rulebookDigest: DIGEST,
    schemaDigests: [DIGEST],
    engineVersion: "1.0.0",
    bundleRootDigest: DIGEST,
  };
  const material = {
    schemaVersion: "1.0.0",
    caseId: "case-1",
    evaluatedAt: pins.asOf,
    evidenceBundleId: "bundle-1",
    evidenceBundleDigest: pins.bundleRootDigest,
    policyRef: { artifactType: "liability_policy", artifactId: "policy-1", digest: pins.policyDigest },
    rulebookRef: { artifactType: "rulebook", artifactId: "rulebook-1", digest: pins.rulebookDigest },
    trustSnapshotRef: { artifactType: "trust_snapshot", artifactId: "trust-1", digest: pins.trustSnapshotDigest },
    engineVersion: pins.engineVersion,
    outcome,
    disposition,
    policyOutcome,
    appealPolicy: fields.appealPolicy ?? { reviewerIds: ["reviewer-synthetic"], maxAppealEvents: 8 },
    ...(outcome === "unresolved" ? {} : { allocation: { id: `${outcome}-synthetic`, role: outcome } }),
    reasonCodes,
    trace: [],
    missingEvidence: [],
    conflictingEvidence: [],
    cryptographicFacts: [],
    verifiedFacts: [],
    attributedAttestations: [],
    policyConclusions: [{ reasonCode: reasonCodes[0], outcome: policyOutcome, disposition }],
    rejectedEvidence: [],
    deterministicTrace: [],
    pins,
    externalAuthenticity: "established_by_caller_pins",
    legalEffect: "not-determined",
    ...fields,
  };
  return { artifactId: deriveLiabilityDecisionId(material), ...material };
}

function event(overrides = {}) {
  return {
    schemaVersion: "1.0.0",
    artifactId: "appeal-event-1",
    appealId: "appeal-1",
    decisionId: "decision-1",
    sequence: 1,
    eventType: "filed",
    actor: { id: "principal-synthetic", role: "principal" },
    occurredAt: "2026-07-23T00:00:00.000Z",
    reasonCodes: ["review_requested"],
    ...overrides,
  };
}

function recordFor(payload, overrides = {}) {
  const recordType = overrides.recordType ?? "decision";
  const body = {
    format: "agent-liability-store-record/v1",
    sequence: overrides.sequence ?? 1,
    ...(overrides.previousHash === undefined ? {} : { previousHash: overrides.previousHash }),
    recordType,
    recordId: overrides.recordId
      ?? `${recordType === "appeal_event" ? "appeal" : "decision"}:${payload.artifactId}`,
    entityId: overrides.entityId
      ?? (recordType === "appeal_event" ? payload.appealId : payload.artifactId),
    payload,
  };
  return { ...body, recordHash: overrides.recordHash ?? storeRecordHash(body) };
}

test("MemoryStore serializes concurrent appends and preserves immutable decisions", async () => {
  const store = new MemoryStore();
  const first = decision();
  const second = decision({ caseId: "case-2", evidenceBundleId: "bundle-2" });
  await Promise.all([store.putDecision(first), store.putDecision(second)]);

  const fetched = await store.getDecision(first.artifactId);
  assert.deepEqual(fetched, first);
  fetched.reasonCodes.push?.("attempted-mutation");
  assert.deepEqual((await store.getDecision(first.artifactId)).reasonCodes, ["inside_mandate"]);

  const verification = await store.verifyChain();
  assert.equal(verification.valid, true);
  assert.equal(verification.records, 2);
  assert.equal(verification.completeness, "unproven");
  await store.close();
});

test("MemoryStore rejects post-evaluation decision mutation", async () => {
  const store = new MemoryStore();
  const original = decision();
  await store.putDecision(original);
  await assert.rejects(
    store.putDecision({ ...original, outcome: "operator" }),
    (error) => error instanceof StoreError && error.code === "ALB_STORE_ARTIFACT_INVALID",
  );
  assert.equal((await store.getDecision(original.artifactId)).outcome, "principal");
  await store.close();
});

test("MemoryStore is idempotent, reports misses, and fails closed after close", async () => {
  const store = new MemoryStore();
  const original = decision();
  assert.deepEqual(await store.putDecision(original), original);
  assert.deepEqual(await store.putDecision(original), original);
  assert.equal(await store.getDecision("missing-decision"), undefined);
  assert.equal(await store.getAppeal("missing-appeal"), undefined);
  const verification = await store.verifyChain();
  assert.equal(verification.records, 1);
  await store.close();
  await assert.rejects(store.getDecision(original.artifactId), (error) => error.code === "ALB_STORE_CLOSED");
  await assert.rejects(store.verifyChain(), (error) => error.code === "ALB_STORE_CLOSED");
  await assert.rejects(store.putDecision(original), (error) => error.code === "ALB_STORE_CLOSED");
});

test("store record verification is bounded and detects corruption, duplication, forks, and stale checkpoints", () => {
  const firstDecision = decision();
  const first = recordFor(firstDecision);
  const secondDecision = decision({ caseId: "case-2", evidenceBundleId: "bundle-2" });
  const second = recordFor(secondDecision, {
    sequence: 2,
    previousHash: first.recordHash,
  });
  const thirdDecision = decision({ caseId: "case-3", evidenceBundleId: "bundle-3" });
  const third = recordFor(thirdDecision, {
    sequence: 3,
    previousHash: second.recordHash,
  });

  const verified = verifyStoreRecords([first, second, third], { sequence: 3, headHash: third.recordHash });
  assert.equal(verified.valid, true);
  assert.equal(verified.completeness, "verified");

  const stale = verifyStoreRecords([first, second], { sequence: 3, headHash: third.recordHash });
  assert.equal(stale.completeness, "mismatch");
  assert(stale.issues.some((issue) => issue.code === "ALB_STORE_CHECKPOINT"));

  const tampered = { ...first, recordHash: DIGEST_B };
  assert(verifyStoreRecords([tampered]).issues.some((issue) => issue.code === "ALB_STORE_HASH"));
  assert(verifyStoreRecords([null, "bad-record"]).issues.every((issue) => issue.code === "ALB_STORE_RECORD"));

  const duplicate = { ...second, sequence: 3, previousHash: second.recordHash };
  assert(verifyStoreRecords([first, second, duplicate]).issues.some((issue) => issue.code === "ALB_STORE_DUPLICATE"));

  const equivocated = recordFor(thirdDecision, {
    sequence: 3,
    previousHash: second.recordHash,
    recordId: second.recordId,
  });
  assert(verifyStoreRecords([first, second, equivocated]).issues.some((issue) => issue.code === "ALB_STORE_EQUIVOCATION"));

  const fork = recordFor(thirdDecision, {
    sequence: 3,
    previousHash: first.recordHash,
    recordId: "fork-record",
  });
  assert(verifyStoreRecords([first, second, fork]).issues.some((issue) => issue.code === "ALB_STORE_FORK"));

  const invalidPayload = { ...firstDecision, outcome: "operator" };
  const invalidArtifact = recordFor(invalidPayload);
  assert(verifyStoreRecords([invalidArtifact]).issues.some((issue) => issue.code === "ALB_STORE_ARTIFACT"));

  const nonCanonicalPayload = { ...firstDecision, unsupported: 1n };
  const nonCanonical = { ...first, payload: nonCanonicalPayload };
  const nonCanonicalIssues = verifyStoreRecords([nonCanonical]).issues.map((issue) => issue.code);
  assert(nonCanonicalIssues.includes("ALB_STORE_ARTIFACT"));
  assert(nonCanonicalIssues.includes("ALB_STORE_RECORD"));
  const unboundRecord = recordFor(firstDecision, { recordId: "unbound-decision-record" });
  assert(
    verifyStoreRecords([unboundRecord]).issues
      .some((issue) => issue.code === "ALB_STORE_DECISION_BINDING"),
  );
  assert.throws(() => new MemoryStore({ records: [tampered] }), (error) => error.code === "ALB_STORE_CORRUPT");
});

test("supersession and appeal references must exist and remain case-bound", async () => {
  const missingOriginalStore = new MemoryStore();
  await assert.rejects(
    missingOriginalStore.putDecision(decision({
      supersedesDecisionId: "missing-decision",
      appealId: "appeal-1",
    })),
    (error) => error.code === "ALB_STORE_SUPERSESSION",
  );
  await missingOriginalStore.close();

  const store = new MemoryStore();
  const original = decision();
  await store.putDecision(original);
  await assert.rejects(
    store.putDecision(decision({ supersedesDecisionId: original.artifactId, appealId: "missing-appeal" })),
    (error) => error.code === "ALB_STORE_SUPERSESSION",
  );
  await assert.rejects(
    store.appendAppeal(event({ decisionId: "missing-decision" })),
    (error) => error.code === "ALB_STORE_DECISION_NOT_FOUND",
  );
  await assert.rejects(
    store.appendAppeal(event({ decisionId: original.artifactId, sequence: 0 })),
    (error) => error.code === "ALB_STORE_ARTIFACT_INVALID",
  );

  const filed = event({ decisionId: original.artifactId });
  await store.appendAppeal(filed);
  const unrelated = decision({ evidenceBundleId: "bundle-unrelated" });
  await store.putDecision(unrelated);
  const crossBound = decision({
    outcome: "operator",
    supersedesDecisionId: unrelated.artifactId,
    appealId: filed.appealId,
    reasonCodes: ["appeal_reversed"],
  });
  await assert.rejects(
    store.putDecision(crossBound),
    (error) => error.code === "ALB_STORE_SUPERSESSION",
  );

  const originalRecord = recordFor(original);
  const unrelatedRecord = recordFor(unrelated, {
    sequence: 2,
    previousHash: originalRecord.recordHash,
  });
  const appealRecord = recordFor(filed, {
    recordType: "appeal_event",
    sequence: 3,
    previousHash: unrelatedRecord.recordHash,
    entityId: filed.appealId,
  });
  const crossBoundRecord = recordFor(crossBound, {
    sequence: 4,
    previousHash: appealRecord.recordHash,
  });
  assert(
    verifyStoreRecords([originalRecord, unrelatedRecord, appealRecord, crossBoundRecord])
      .issues.some((issue) => issue.code === "ALB_STORE_SUPERSESSION"),
  );
  for (const overrides of [
    { recordId: "appeal:unbound-event" },
    { entityId: "appeal-unbound" },
  ]) {
    const unboundAppealRecord = recordFor(filed, {
      recordType: "appeal_event",
      sequence: 2,
      previousHash: originalRecord.recordHash,
      ...overrides,
    });
    assert(
      verifyStoreRecords([originalRecord, unboundAppealRecord]).issues
        .some((issue) => issue.code === "ALB_STORE_APPEAL_BINDING"),
    );
  }

  await assert.rejects(
    store.putDecision(decision({
      caseId: "different-case",
      supersedesDecisionId: original.artifactId,
      appealId: filed.appealId,
    })),
    (error) => error.code === "ALB_STORE_SUPERSESSION",
  );
  const invalidReversal = event({
    artifactId: "appeal-event-2",
    appealId: filed.appealId,
    decisionId: original.artifactId,
    sequence: 2,
    previousEventDigest: appealEventDigest(filed),
    eventType: "reversed",
    actor: { id: "reviewer-synthetic", role: "reviewer" },
    supersedingDecisionId: "missing-superseding-decision",
  });
  await assert.rejects(store.appendAppeal(invalidReversal), (error) => error.code === "ALB_STORE_SUPERSESSION");

  const conflictingId = event({
    artifactId: filed.artifactId,
    appealId: "appeal-2",
    decisionId: original.artifactId,
    reasonCodes: ["different_assertion"],
  });
  await assert.rejects(store.appendAppeal(conflictingId), (error) => error.code === "ALB_STORE_CONFLICT");
  await store.close();
});

test("one appeal cannot create divergent superseding decisions", async () => {
  const store = new MemoryStore();
  const original = decision();
  const filed = event({ decisionId: original.artifactId });
  await store.putDecision(original);
  await store.appendAppeal(filed);
  const first = decision({
    outcome: "operator",
    supersedesDecisionId: original.artifactId,
    appealId: filed.appealId,
    reasonCodes: ["appeal_reversed"],
  });
  const second = decision({
    outcome: "unresolved",
    supersedesDecisionId: original.artifactId,
    appealId: filed.appealId,
    reasonCodes: ["appeal_reversed"],
  });
  await store.putDecision(first);
  await assert.rejects(
    store.putDecision(second),
    (error) => error.code === "ALB_STORE_SUPERSESSION",
  );

  const originalRecord = recordFor(original);
  const appealRecord = recordFor(filed, {
    recordType: "appeal_event",
    sequence: 2,
    previousHash: originalRecord.recordHash,
  });
  const firstRecord = recordFor(first, {
    sequence: 3,
    previousHash: appealRecord.recordHash,
  });
  const secondRecord = recordFor(second, {
    sequence: 4,
    previousHash: firstRecord.recordHash,
  });
  assert(
    verifyStoreRecords([originalRecord, appealRecord, firstRecord, secondRecord]).issues
      .some((issue) => issue.code === "ALB_STORE_SUPERSESSION"),
  );
  await store.close();
});

test("appeals are append-only, fork-aware, and explicitly checkpointed", async () => {
  const store = new MemoryStore();
  const original = decision();
  await store.putDecision(original);
  const filed = event({ decisionId: original.artifactId });
  const initial = await store.appendAppeal(filed);
  assert.equal(initial.status, "open");
  assert.equal(initial.completeness.state, "unproven");
  assert.equal((await store.appendAppeal(filed)).events.length, 1, "exact retry is idempotent");

  const checkpointed = await store.getAppeal("appeal-1", {
    sequence: 1,
    headDigest: initial.headDigest,
  });
  assert.equal(checkpointed.completeness.state, "verified");

  const review = event({
    appealId: filed.appealId,
    decisionId: original.artifactId,
    artifactId: "appeal-event-2",
    sequence: 2,
    previousEventDigest: appealEventDigest(filed),
    eventType: "review_started",
    actor: { id: "reviewer-synthetic", role: "reviewer" },
  });
  await store.appendAppeal(review);
  await assert.rejects(
    store.appendAppeal(event({
      artifactId: "appeal-event-fork",
      appealId: filed.appealId,
      decisionId: original.artifactId,
      sequence: 2,
      previousEventDigest: appealEventDigest(filed),
    })),
    (error) => error instanceof StoreError && error.code === "ALB_APPEAL_FORK",
  );
  assert.equal((await store.getAppeal("appeal-1")).events.length, 2);
  await store.close();
});

test("decision-bound reviewer assertions and appeal event caps are enforced", async () => {
  const store = new MemoryStore();
  const original = decision({
    appealPolicy: { reviewerIds: ["reviewer-allowed"], maxAppealEvents: 2 },
  });
  await store.putDecision(original);
  const filed = event({ decisionId: original.artifactId });
  await store.appendAppeal(filed);

  const review = event({
    artifactId: "appeal-event-2",
    appealId: filed.appealId,
    decisionId: original.artifactId,
    sequence: 2,
    previousEventDigest: appealEventDigest(filed),
    eventType: "review_started",
    actor: { id: "reviewer-not-allowed", role: "reviewer" },
  });
  await assert.rejects(
    store.appendAppeal(review),
    (error) => error.code === "ALB_APPEAL_REVIEWER_UNAUTHORIZED",
  );
  await assert.rejects(
    store.appendAppeal({ ...review, actor: { id: "reviewer-allowed", role: "principal" } }),
    (error) => error.code === "ALB_APPEAL_REVIEWER_UNAUTHORIZED",
  );

  const authorized = { ...review, actor: { id: "reviewer-allowed", role: "reviewer" } };
  await store.appendAppeal(authorized);
  const capped = event({
    artifactId: "appeal-event-3",
    appealId: filed.appealId,
    decisionId: original.artifactId,
    sequence: 3,
    previousEventDigest: appealEventDigest(authorized),
    eventType: "upheld",
    actor: { id: "reviewer-allowed", role: "reviewer" },
  });
  await assert.rejects(store.appendAppeal(capped), (error) => error.code === "ALB_APPEAL_EVENT_CAP");
  assert.equal((await store.getAppeal(filed.appealId)).events.length, 2);
  await store.close();
});

test("appeal reversal supersedes without mutating the original decision", async () => {
  const store = new MemoryStore();
  const original = decision();
  await store.putDecision(original);
  const filed = event({ decisionId: original.artifactId });
  await store.appendAppeal(filed);
  const superseding = decision({
    outcome: "operator",
    supersedesDecisionId: original.artifactId,
    appealId: filed.appealId,
    reasonCodes: ["appeal_reversed"],
  });
  await store.putDecision(superseding);
  const reversed = event({
    artifactId: "appeal-event-2",
    appealId: filed.appealId,
    decisionId: original.artifactId,
    sequence: 2,
    previousEventDigest: appealEventDigest(filed),
    eventType: "reversed",
    actor: { id: "reviewer-synthetic", role: "reviewer" },
    supersedingDecisionId: superseding.artifactId,
  });
  const history = await store.appendAppeal(reversed);
  assert.equal(history.status, "reversed");
  assert.equal((await store.getDecision(original.artifactId)).outcome, "principal");
  assert.equal((await store.getDecision(superseding.artifactId)).outcome, "operator");
  await assert.rejects(store.appendAppeal(event({
    artifactId: "too-late",
    appealId: filed.appealId,
    decisionId: original.artifactId,
    sequence: 3,
    previousEventDigest: appealEventDigest(reversed),
  })), /Resolved appeal/);
  await store.close();
});

test("JsonlStore enforces one writer and verifies persisted history", async () => {
  const directory = await mkdtemp(join(tmpdir(), "alb-store-"));
  const file = join(directory, "store.jsonl");
  try {
    const writer = await JsonlStore.open(file);
    const stored = decision();
    await writer.putDecision(stored);
    await assert.rejects(
      JsonlStore.open(file),
      (error) => error instanceof StoreError && error.code === "ALB_STORE_LOCKED",
    );
    await writer.close();

    const text = await readFile(file, "utf8");
    assert.equal(text.trim().split("\n").length, 1);
    const reopened = await JsonlStore.open(file);
    assert.equal((await reopened.verifyChain()).valid, true);
    assert.equal((await reopened.getDecision(stored.artifactId)).artifactId, stored.artifactId);
    await reopened.close();
    await reopened.close();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JsonlStore enforces configured limits before appending", async () => {
  const directory = await mkdtemp(join(tmpdir(), "alb-store-append-limit-"));
  try {
    await assert.rejects(JsonlStore.open(join(directory, "invalid.jsonl"), { maxRecords: Number.NaN }), TypeError);

    const recordStore = await JsonlStore.open(join(directory, "records.jsonl"), { maxRecords: 1 });
    await recordStore.putDecision(decision());
    await assert.rejects(
      recordStore.putDecision(decision({ caseId: "case-2", evidenceBundleId: "bundle-2" })),
      (error) => error instanceof StoreError && error.code === "ALB_STORE_LIMIT",
    );
    assert.equal((await recordStore.verifyChain()).records, 1);
    await recordStore.close();

    const byteFile = join(directory, "bytes.jsonl");
    const byteStore = await JsonlStore.open(byteFile, { maxFileBytes: 1 });
    await assert.rejects(
      byteStore.putDecision(decision()),
      (error) => error instanceof StoreError && error.code === "ALB_STORE_LIMIT",
    );
    assert.equal(await readFile(byteFile, "utf8"), "");
    await byteStore.close();

    assert.equal(DEFAULT_JSONL_STORE_LIMITS.maxRecordBytes, DEFAULT_STRICT_JSON_LIMITS.maxBytes);
    const recordFile = join(directory, "record-bytes.jsonl");
    const recordLimited = await JsonlStore.open(recordFile, { maxRecordBytes: 32 });
    await assert.rejects(
      recordLimited.putDecision(decision()),
      (error) => error instanceof StoreError && error.code === "ALB_STORE_LIMIT",
    );
    assert.equal(await readFile(recordFile, "utf8"), "");
    await recordLimited.close();

    const oversizedLine = JSON.stringify({ value: "a".repeat(300) });
    const corruptFile = join(directory, "record-json-limit.jsonl");
    await writeFile(corruptFile, `${oversizedLine}\n`, "utf8");
    await assert.rejects(
      JsonlStore.open(corruptFile, { maxRecordBytes: 64 }),
      (error) => error instanceof StoreError
        && error.code === "ALB_STORE_CORRUPT"
        && error.cause?.code === "ALB_JSON_LIMIT",
    );

    const largeStringFile = join(directory, "record-large-string.jsonl");
    await writeFile(largeStringFile, `${JSON.stringify({ value: "a".repeat(300_000) })}\n`, "utf8");
    await assert.rejects(
      JsonlStore.open(largeStringFile),
      (error) => error instanceof StoreError
        && error.code === "ALB_STORE_CORRUPT"
        && error.cause === undefined,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JsonlStore accepts complete final records and preserves append boundaries", async () => {
  const directory = await mkdtemp(join(tmpdir(), "alb-store-line-endings-"));
  const firstDecision = decision();
  const firstRecord = recordFor(firstDecision);
  const firstLine = canonicalize(firstRecord);
  const lockIsRemoved = async (file) => assert.rejects(
    readFile(`${file}.lock`),
    (error) => error.code === "ENOENT",
  );
  try {
    for (const [name, text, count] of [
      ["empty", "", 0],
      ["lf", `${firstLine}\n`, 1],
      ["crlf", `${firstLine}\r\n`, 1],
      ["no-lf", firstLine, 1],
    ]) {
      const file = join(directory, `${name}.jsonl`);
      await writeFile(file, text, "utf8");
      const store = await JsonlStore.open(file);
      const verification = await store.verifyChain();
      assert.equal(verification.valid, true);
      assert.equal(verification.records, count);
      await store.close();
      await lockIsRemoved(file);
    }

    const secondDecision = decision({ caseId: "case-2", evidenceBundleId: "bundle-2" });
    const secondRecord = recordFor(secondDecision, {
      sequence: 2,
      previousHash: firstRecord.recordHash,
    });
    const limitedFile = join(directory, "no-lf-limit.jsonl");
    await writeFile(limitedFile, firstLine, "utf8");
    const limitWithoutSeparator = Buffer.byteLength(firstLine)
      + Buffer.byteLength(canonicalize(secondRecord))
      + 1;
    const limited = await JsonlStore.open(limitedFile, { maxFileBytes: limitWithoutSeparator });
    await assert.rejects(
      limited.putDecision(secondDecision),
      (error) => error instanceof StoreError && error.code === "ALB_STORE_LIMIT",
    );
    assert.equal(await readFile(limitedFile, "utf8"), firstLine);
    await limited.close();
    await lockIsRemoved(limitedFile);

    const appendFile = join(directory, "no-lf-append.jsonl");
    await writeFile(appendFile, firstLine, "utf8");
    const writer = await JsonlStore.open(appendFile);
    await writer.putDecision(secondDecision);
    await writer.close();
    assert.equal(
      await readFile(appendFile, "utf8"),
      `${firstLine}\n${canonicalize(secondRecord)}\n`,
    );
    const reopened = await JsonlStore.open(appendFile);
    assert.equal((await reopened.verifyChain()).records, 2);
    await reopened.close();
    await lockIsRemoved(appendFile);

    for (const [name, text] of [
      ["blank", `${firstLine}\n\n`],
      ["invalid-no-lf", canonicalize({ ...firstRecord, recordHash: DIGEST_B })],
    ]) {
      const file = join(directory, `${name}.jsonl`);
      await writeFile(file, text, "utf8");
      await assert.rejects(
        JsonlStore.open(file),
        (error) => error instanceof StoreError && error.code === "ALB_STORE_CORRUPT",
      );
      assert.equal(await readFile(file, "utf8"), text);
      await lockIsRemoved(file);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JsonlStore rejects malformed, duplicate-key, oversized, over-count, and invalid-chain files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "alb-corrupt-store-"));
  const file = join(directory, "store.jsonl");
  try {
    for (const text of [
      "{not-json}\n",
      '{"format":"agent-liability-store-record/v1","format":"agent-liability-store-record/v1"}\n',
      '{}\n',
    ]) {
      await writeFile(file, text, "utf8");
      await assert.rejects(
        JsonlStore.open(file),
        (error) => error instanceof StoreError
          && error.code === "ALB_STORE_CORRUPT"
          && error.line === 1
          && error.message === "Store contains an invalid record at line 1.",
      );
    }

    await writeFile(file, "{not-json}\n", "utf8");
    await assert.rejects(
      JsonlStore.open(file),
      (error) => error instanceof StoreError && error.cause instanceof Error,
    );

    const validRecord = recordFor(decision());
    await writeFile(file, `${canonicalize(validRecord)}\n{not-json}\n`, "utf8");
    await assert.rejects(
      JsonlStore.open(file),
      (error) => error instanceof StoreError
        && error.code === "ALB_STORE_CORRUPT"
        && error.line === 2
        && error.message === "Store contains an invalid record at line 2.",
    );

    const valid = recordFor(decision());
    await writeFile(file, `${canonicalize({ ...valid, recordHash: DIGEST_B })}\n`, "utf8");
    await assert.rejects(JsonlStore.open(file), (error) => error.code === "ALB_STORE_CORRUPT");

    await writeFile(file, "1234567890", "utf8");
    await assert.rejects(JsonlStore.open(file, { maxFileBytes: 4 }), (error) => error.code === "ALB_STORE_LIMIT");

    await writeFile(file, `${canonicalize(valid)}\n${canonicalize(valid)}\n`, "utf8");
    await assert.rejects(JsonlStore.open(file, { maxRecords: 1 }), (error) => error.code === "ALB_STORE_LIMIT");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JsonlStore rejects invalid UTF-8 that decodes to a valid record", async () => {
  const directory = await mkdtemp(join(tmpdir(), "alb-invalid-utf8-store-"));
  const file = join(directory, "store.jsonl");
  try {
    const replacementCharacter = String.fromCodePoint(0xfffd);
    const valid = recordFor(decision({
      verifiedFacts: [{ name: "replacement", value: replacementCharacter, sourceRefs: [] }],
    }));
    assert.equal(verifyStoreRecords([valid]).valid, true);
    const canonical = Buffer.from(`${canonicalize(valid)}\n`, "utf8");
    const replacement = Buffer.from(replacementCharacter, "utf8");
    const offset = canonical.indexOf(replacement);
    assert.notEqual(offset, -1);
    const malformed = Buffer.concat([
      canonical.subarray(0, offset),
      Buffer.from([0xc3]),
      canonical.subarray(offset + replacement.length),
    ]);
    await writeFile(file, malformed);

    await assert.rejects(
      JsonlStore.open(file),
      (error) => error instanceof StoreError && error.code === "ALB_STORE_CORRUPT",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JsonlStore maps filesystem-open and append failures to bounded store errors", async () => {
  const directory = await mkdtemp(join(tmpdir(), "alb-store-errors-"));
  const missingParentFile = join(directory, "missing-parent", "store.jsonl");
  await assert.rejects(JsonlStore.open(missingParentFile), (error) => error.code === "ALB_STORE_OPEN");

  const file = join(directory, "store.jsonl");
  const store = await JsonlStore.open(file);
  try {
    await store.dataHandle.close();
    await assert.rejects(store.putDecision(decision()), (error) => error.code === "ALB_STORE_WRITE");
  } finally {
    await store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("JsonlStore fails closed after append succeeds but sync fails", async () => {
  const directory = await mkdtemp(join(tmpdir(), "alb-store-sync-failure-"));
  const file = join(directory, "store.jsonl");
  const stored = decision();
  const store = await JsonlStore.open(file);
  const sync = store.dataHandle.sync.bind(store.dataHandle);
  let syncCalls = 0;
  try {
    store.dataHandle.sync = async () => {
      syncCalls += 1;
      throw new Error("synthetic sync failure");
    };
    await assert.rejects(
      store.putDecision(stored),
      (error) => error instanceof StoreError && error.code === "ALB_STORE_WRITE",
    );
    const appended = await readFile(file, "utf8");
    assert.equal(appended.trim().split("\n").length, 1);

    store.dataHandle.sync = sync;
    await assert.rejects(
      store.putDecision(stored),
      (error) => error instanceof StoreError && error.code === "ALB_STORE_WRITE",
    );
    await assert.rejects(
      store.verifyChain(),
      (error) => error instanceof StoreError && error.code === "ALB_STORE_WRITE",
    );
    assert.equal(await readFile(file, "utf8"), appended);
    assert.equal(syncCalls, 1);
  } finally {
    store.dataHandle.sync = sync;
    await store.close();
  }

  let reopened;
  try {
    reopened = await JsonlStore.open(file);
    assert.equal((await reopened.verifyChain()).valid, true);
    assert.equal((await reopened.getDecision(stored.artifactId)).artifactId, stored.artifactId);
  } finally {
    await reopened?.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("JsonlStore reopen rejects recomputed histories that bypass reviewer or cap policy", async () => {
  const directory = await mkdtemp(join(tmpdir(), "alb-store-policy-reopen-"));
  try {
    for (const [name, appealPolicy, actor] of [
      ["reviewer", { reviewerIds: ["reviewer-allowed"], maxAppealEvents: 2 }, { id: "reviewer-denied", role: "reviewer" }],
      ["cap", { reviewerIds: ["reviewer-allowed"], maxAppealEvents: 1 }, { id: "reviewer-allowed", role: "reviewer" }],
    ]) {
      const file = join(directory, `${name}.jsonl`);
      const original = decision({ appealPolicy, caseId: `case-${name}` });
      const filed = event({
        artifactId: `appeal-${name}-event-1`,
        appealId: `appeal-${name}`,
        decisionId: original.artifactId,
      });
      const writer = await JsonlStore.open(file);
      await writer.putDecision(original);
      await writer.appendAppeal(filed);
      await writer.close();

      const records = (await readFile(file, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
      const prior = records.at(-1);
      const forgedEvent = event({
        artifactId: `appeal-${name}-event-2`,
        appealId: filed.appealId,
        decisionId: original.artifactId,
        sequence: 2,
        previousEventDigest: appealEventDigest(filed),
        eventType: "review_started",
        actor,
      });
      const forgedRecord = recordFor(forgedEvent, {
        recordType: "appeal_event",
        sequence: 3,
        previousHash: prior.recordHash,
        entityId: filed.appealId,
      });
      await writeFile(file, `${records.map(canonicalize).join("\n")}\n${canonicalize(forgedRecord)}\n`, "utf8");
      await assert.rejects(JsonlStore.open(file), (error) => error.code === "ALB_STORE_CORRUPT");
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
