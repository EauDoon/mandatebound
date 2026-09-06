import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import { CLI_EXIT, runCli } from "../dist/cli.js";
import { sha256Bytes } from "../dist/canonical.js";
import {
  EXTERNAL_REVIEW_FORMAT,
  ReviewInputError,
  reviewExternalEvidence,
} from "../dist/review.js";

function collector() {
  let text = "";
  return {
    stream: new Writable({
      write(chunk, _encoding, callback) {
        text += chunk.toString();
        callback();
      },
    }),
    value: () => text,
  };
}

async function invoke(argv, input) {
  const stdout = collector();
  const stderr = collector();
  const code = await runCli(argv, {
    stdin: Readable.from([input]),
    stdout: stdout.stream,
    stderr: stderr.stream,
  });
  return { code, stdout: stdout.value(), stderr: stderr.value() };
}

function railBundle(overrides = {}) {
  return {
    profile: "audit",
    schema_version: "consequence-rail/settlement-bundle/v0.1",
    action: { action_id: "act_review_1", action_digest: `sha256:${"1".repeat(64)}` },
    settlement_receipt: {
      receipt_id: "receipt_review_1",
      action_id: "act_review_1",
      outcome: "compensated",
      recourse_final_status: "consumed",
      event_chain_head: `sha256:${"2".repeat(64)}`,
      action_digest: `sha256:${"1".repeat(64)}`,
    },
    events: [],
    ...overrides,
  };
}

function reviewRequest(bundle, overrides = {}) {
  const raw = Buffer.from(JSON.stringify(bundle), "utf8");
  const digest = sha256Bytes(raw);
  return {
    source: { sourceId: "consequence-rail", eventClass: "settlement" },
    evidence: {
      mediaType: "application/json",
      bytesBase64: raw.toString("base64"),
      digest,
      byteLength: raw.length,
    },
    anchors: { expectedDigest: digest },
    upstream: {
      verifier: "consequence-rail:bundle-verify",
      valid: true,
      actionId: bundle.action.action_id,
      outcome: bundle.settlement_receipt?.outcome ?? "",
      trustedKeyIds: ["demo-connector-key"],
    },
    ...overrides,
  };
}

test("review records same-case evidence with bindings and no legal effect", () => {
  const bundle = railBundle();
  const result = reviewExternalEvidence(reviewRequest(bundle));
  assert.equal(result.format, EXTERNAL_REVIEW_FORMAT);
  assert.equal(result.verdict, "recorded");
  assert.equal(result.legalEffect, "not-determined");
  assert.equal(result.actionId, "act_review_1");
  assert.equal(result.receipt.outcome, "compensated");
  assert.equal(result.receipt.recourseStatus, "consumed");
  assert.equal(result.upstream.valid, true);
  assert.match(result.reviewId, /^review-[0-9a-f]{16}$/);
  assert.match(result.reviewDigest, /^sha256:[0-9a-f]{64}$/);
});

test("review output is byte-identical for identical input", () => {
  const input = reviewRequest(railBundle());
  const first = JSON.stringify(reviewExternalEvidence(input));
  const second = JSON.stringify(reviewExternalEvidence(JSON.parse(JSON.stringify(input))));
  assert.equal(first, second);
});

test("review reports conflicting on digest, anchor, identity, and outcome mismatches", () => {
  const bundle = railBundle();
  const raw = Buffer.from(JSON.stringify(bundle), "utf8");
  const digest = sha256Bytes(raw);

  const anchorMismatch = reviewRequest(bundle, {
    anchors: { expectedDigest: `sha256:${"0".repeat(64)}` },
  });
  assert.equal(reviewExternalEvidence(anchorMismatch).verdict, "conflicting");

  const byteLengthMismatch = reviewRequest(bundle);
  byteLengthMismatch.evidence.byteLength += 1;
  assert.equal(reviewExternalEvidence(byteLengthMismatch).verdict, "conflicting");

  const tampered = railBundle();
  tampered.settlement_receipt.outcome = "settled";
  const tamperedRaw = Buffer.from(JSON.stringify(tampered), "utf8");
  const staleAnchors = reviewRequest(bundle);
  staleAnchors.evidence.bytesBase64 = tamperedRaw.toString("base64");
  staleAnchors.evidence.byteLength = tamperedRaw.length;
  assert.equal(reviewExternalEvidence(staleAnchors).verdict, "conflicting");

  const upstreamMismatch = reviewRequest(bundle, {
    upstream: {
      verifier: "consequence-rail:bundle-verify",
      valid: true,
      actionId: "act_review_1",
      outcome: "settled",
      trustedKeyIds: ["demo-connector-key"],
    },
  });
  assert.equal(reviewExternalEvidence(upstreamMismatch).verdict, "conflicting");

  const internalMismatch = railBundle({
    settlement_receipt: {
      receipt_id: "receipt_review_1",
      action_id: "act_other",
      outcome: "compensated",
      recourse_final_status: "consumed",
      event_chain_head: `sha256:${"2".repeat(64)}`,
      action_digest: `sha256:${"1".repeat(64)}`,
    },
  });
  assert.equal(reviewExternalEvidence(reviewRequest(internalMismatch)).verdict, "conflicting");
  assert.equal(digest, sha256Bytes(raw));
});

test("review reports unsupported for non-JSON bytes, foreign media, and missing receipts", () => {
  const bundle = railBundle();
  const raw = Buffer.from("not a rail bundle", "utf8");
  const opaque = reviewRequest(bundle, {
    evidence: {
      mediaType: "application/json",
      bytesBase64: raw.toString("base64"),
      digest: sha256Bytes(raw),
      byteLength: raw.length,
    },
    anchors: { expectedDigest: sha256Bytes(raw) },
  });
  assert.equal(reviewExternalEvidence(opaque).verdict, "unsupported");

  const foreign = reviewRequest(bundle, {
    evidence: { ...reviewRequest(bundle).evidence, mediaType: "application/octet-stream" },
  });
  assert.equal(reviewExternalEvidence(foreign).verdict, "unsupported");

  const noReceipt = railBundle({ settlement_receipt: undefined });
  const noReceiptRequest = reviewRequest(railBundle(), {
    evidence: reviewRequest(noReceipt).evidence,
    anchors: reviewRequest(noReceipt).anchors,
  });
  assert.equal(reviewExternalEvidence(noReceiptRequest).verdict, "unsupported");
});

test("review records uncertainty instead of failing when upstream is invalid", () => {
  const bundle = railBundle();
  const request = reviewRequest(bundle);
  request.upstream.valid = false;
  const result = reviewExternalEvidence(request);
  assert.equal(result.verdict, "recorded");
  assert.equal(result.upstream.valid, false);
  assert.equal(result.legalEffect, "not-determined");
});

test("review rejects malformed input without emitting a record", () => {
  const bundle = railBundle();
  const valid = reviewRequest(bundle);
  const malformed = [
    {},
    { ...valid, source: { sourceId: "consequence-rail" } },
    { ...valid, evidence: { ...valid.evidence, bytesBase64: "!!!not-base64!!!" } },
    { ...valid, anchors: {} },
    { ...valid, upstream: { ...valid.upstream, valid: "yes" } },
    { ...valid, extra: true },
  ];
  for (const input of malformed) {
    assert.throws(() => reviewExternalEvidence(input), ReviewInputError);
  }
});

test("review CLI maps verdicts to stable exit codes with JSON stdout", async () => {
  const bundle = railBundle();
  const recorded = await invoke(["review", "-"], JSON.stringify(reviewRequest(bundle)));
  assert.equal(recorded.code, CLI_EXIT.SUCCESS);
  assert.equal(JSON.parse(recorded.stdout).ok, true);
  assert.equal(JSON.parse(recorded.stdout).result.verdict, "recorded");

  const tampered = railBundle();
  tampered.settlement_receipt.outcome = "settled";
  const conflictInput = reviewRequest(bundle);
  const tamperedRaw = Buffer.from(JSON.stringify(tampered), "utf8");
  conflictInput.evidence.bytesBase64 = tamperedRaw.toString("base64");
  conflictInput.evidence.byteLength = tamperedRaw.length;
  const conflicting = await invoke(["review", "-"], JSON.stringify(conflictInput));
  assert.equal(conflicting.code, CLI_EXIT.CONFLICT);
  assert.equal(JSON.parse(conflicting.stdout).ok, false);
  assert.equal(JSON.parse(conflicting.stdout).result.verdict, "conflicting");

  const invalid = await invoke(["review", "-"], JSON.stringify({}));
  assert.equal(invalid.code, CLI_EXIT.INVALID);
  assert.equal(JSON.parse(invalid.stdout).ok, false);

  const raw = Buffer.from("not a rail bundle", "utf8");
  const unsupportedInput = reviewRequest(bundle, {
    evidence: {
      mediaType: "application/json",
      bytesBase64: raw.toString("base64"),
      digest: sha256Bytes(raw),
      byteLength: raw.length,
    },
    anchors: { expectedDigest: sha256Bytes(raw) },
  });
  const unsupported = await invoke(["review", "-"], JSON.stringify(unsupportedInput));
  assert.equal(unsupported.code, CLI_EXIT.INVALID);
  assert.equal(JSON.parse(unsupported.stdout).result.verdict, "unsupported");
});

test("review rejects oversized evidence before hashing", () => {
  const bundle = railBundle();
  const request = reviewRequest(bundle);
  request.evidence.bytesBase64 = `AAAA${"A".repeat(2_097_152)}`;
  assert.throws(() => reviewExternalEvidence(request), ReviewInputError);
});
