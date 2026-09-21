import assert from "node:assert/strict";
import test from "node:test";
import { sha256Bytes } from "../dist/canonical.js";
import {
  buildUcpRequestSignatureBase,
  parseUcpSignatureInput,
  verifyUcpRequestEvidence,
} from "../dist/ucp-ap2.js";
import {
  contentDigest,
  createEcPair,
  evaluationTime,
  issueCodes,
  keySnapshot,
  signUcpRequest,
  sourceDigest,
} from "./ucp-ap2-helpers.mjs";

test("RFC 9421 Signature-Input parser accepts the UCP subset and rejects ambiguous grammar", () => {
  const parsed = parseUcpSignatureInput(
    'sig1=("@method" "@authority" "@path" "@query" "x-test");created=1770000000;expires=1800000000;keyid="key-1";nonce="n-1";tag',
  );
  assert.equal(parsed.label, "sig1");
  assert.equal(parsed.created, 1_770_000_000);
  assert.equal(parsed.expires, 1_800_000_000);
  assert.equal(parsed.keyId, "key-1");

  const invalidInputs = [
    null,
    "x".repeat(16_385),
    "sig1",
    'Sig1=("@method");keyid="k"',
    "sig1=token",
    'sig1=();keyid="k"',
    'sig1=("@method"',
    'sig1=("@method"  "@path");keyid="k"',
    'sig1=("@Method");keyid="k"',
    'sig1=("@method" "@method");keyid="k"',
    'sig1=("@method"),keyid="k"',
    'sig1=("@method");1bad="x";keyid="k"',
    'sig1=("@method");keyid="k";keyid="again"',
    'sig1=("@method");keyid',
    'sig1=("@method");keyid=?',
    'sig1=("@method");created=99999999999999999999;keyid="k"',
    'sig1=("@method");alg="ES256";keyid="k"',
    'sig1=("@method");unknown="x";keyid="k"',
    'sig1=("@method");created=1',
    'sig1=("@method");created="1";keyid="k"',
    'sig1=("@method");expires="1";keyid="k"',
    'sig1=("@method");keyid="unterminated',
    'sig1=("@method");keyid="escaped\\"',
  ];
  for (const value of invalidInputs) {
    assert.throws(() => parseUcpSignatureInput(value), undefined, String(value).slice(0, 80));
  }
});

test("request signature-base construction binds query and normalized fields and rejects missing metadata", () => {
  const input = {
    method: "GET",
    authority: "merchant.example",
    path: "/checkout-sessions/chk-1",
    query: "view=summary",
    headers: { "X-Test": "  alpha\t beta  " },
    signatureInput:
      'sig1=("@method" "@authority" "@path" "@query" "x-test");keyid="key-1"',
    signature: "sig1=:AA==:",
    keySnapshot: {
      kid: "key-1",
      jwk: createEcPair("key-1").publicJwk,
      sourceDigest,
      capturedAt: "2026-01-01T00:00:00.000Z",
      validUntil: "2027-01-01T00:00:00.000Z",
    },
    expectedKeySourceDigest: sourceDigest,
    asOf: evaluationTime,
  };
  const base = Buffer.from(buildUcpRequestSignatureBase(input)).toString("utf8");
  assert.equal(base.includes('"@query": ?view=summary'), true);
  assert.equal(base.includes('"x-test": alpha beta'), true);

  assert.throws(() => buildUcpRequestSignatureBase({
    ...input,
    query: undefined,
  }));
  assert.throws(() => buildUcpRequestSignatureBase({
    ...input,
    signatureInput: 'sig1=("@status");keyid="key-1"',
  }));
  assert.throws(() => buildUcpRequestSignatureBase({
    ...input,
    signatureInput: 'sig1=("missing-header");keyid="key-1"',
  }));
  assert.throws(() => buildUcpRequestSignatureBase({
    ...input,
    headers: { "X-Test": "one", "x-test": "two" },
  }));
  assert.throws(() => buildUcpRequestSignatureBase({
    ...input,
    headers: { "bad name": "value" },
  }));
  assert.throws(() => buildUcpRequestSignatureBase({
    ...input,
    headers: { "x-test": "value\r\ninjected: true" },
  }));
});

test("UCP request verifier enforces signed components, raw ECDSA, and idempotent replay", () => {
  const platform = createEcPair("platform-2026");
  const body = Buffer.from('{"checkout":{"line_items":[{"id":"sku-1","quantity":1}]}}', "utf8");
  const idempotencyKey = "9f5f17d0-02ee-4cf3-b7ca-6923f82d38f9";
  const signatureInput =
    'sig1=("@method" "@authority" "@path" "ucp-agent" "idempotency-key" "content-digest" "content-type");created=1770000000;keyid="platform-2026"';
  const unsigned = {
    method: "POST",
    authority: "merchant.example",
    path: "/checkout-sessions",
    headers: {
      "UCP-Agent": 'profile="https://platform.example/.well-known/ucp"',
      "Idempotency-Key": idempotencyKey,
      "Content-Digest": contentDigest(body),
      "Content-Type": "application/json",
    },
    rawBody: body,
    signatureInput,
    signature: "sig1=:AA==:",
    keySnapshot: keySnapshot(platform),
    expectedKeySourceDigest: sourceDigest,
    asOf: evaluationTime,
    replayDisposition: "new",
  };
  const request = signUcpRequest(unsigned, platform);
  const valid = verifyUcpRequestEvidence(request);
  assert.equal(valid.upstreamValid, true, JSON.stringify(valid.issues));
  assert.equal(valid.evidenceEligible, true);
  assert.equal(valid.value.replayStatus, "new");
  assert.deepEqual(
    parseUcpSignatureInput(signatureInput).components,
    ["@method", "@authority", "@path", "ucp-agent", "idempotency-key", "content-digest", "content-type"],
  );

  const missingDigestComponent = signUcpRequest({
    ...unsigned,
    signatureInput:
      'sig1=("@method" "@authority" "@path" "ucp-agent" "idempotency-key" "content-type");created=1770000000;keyid="platform-2026"',
  }, platform);
  const missingReport = verifyUcpRequestEvidence(missingDigestComponent);
  assert.equal(missingReport.upstreamValid, false);
  assert.equal(
    missingReport.issues.some((issue) => issue.code === "UCP_SIGNED_COMPONENT_MISSING"),
    true,
  );

  const derRequest = signUcpRequest(unsigned, platform, "der");
  assert.equal(verifyUcpRequestEvidence(derRequest).upstreamValid, false);

  const ledger = new Map([[
    idempotencyKey,
    {
      operation: "POST /checkout-sessions",
      rawBodyDigest: sha256Bytes(body),
    },
  ]]);
  const cached = verifyUcpRequestEvidence({
    ...request,
    idempotencyLedger: ledger,
    replayDisposition: "cached",
  });
  assert.equal(cached.upstreamValid, true, JSON.stringify(cached.issues));
  assert.equal(cached.evidenceEligible, true);
  assert.equal(cached.value.replayStatus, "cached");

  const unresolved = verifyUcpRequestEvidence({
    ...request,
    idempotencyLedger: ledger,
    replayDisposition: "new",
  });
  assert.equal(unresolved.upstreamValid, true);
  assert.equal(unresolved.evidenceEligible, false);
  assert.equal(unresolved.value.replayStatus, "unresolved");

  const changedBody = Buffer.from('{"checkout":{"line_items":[{"id":"sku-2","quantity":1}]}}', "utf8");
  const changedUnsigned = {
    ...unsigned,
    rawBody: changedBody,
    headers: {
      ...unsigned.headers,
      "Content-Digest": contentDigest(changedBody),
    },
    idempotencyLedger: ledger,
    replayDisposition: "new",
  };
  const conflict = verifyUcpRequestEvidence(signUcpRequest(changedUnsigned, platform));
  assert.equal(conflict.upstreamValid, false);
  assert.equal(conflict.issues.some((issue) => issue.code === "UCP_IDEMPOTENCY_CONFLICT"), true);
});

test("UCP request evidence covers algorithm, time, identity, header, and replay boundaries", () => {
  const makeGet = (pair, overrides = {}) => ({
    method: "GET",
    authority: "merchant.example",
    path: "/checkout-sessions/chk-boundary",
    headers: {},
    signatureInput:
      `sig1=("@method" "@authority" "@path");created=1770000000;expires=1800000000;keyid="${pair.publicJwk.kid}"`,
    signature: "sig1=:AA==:",
    keySnapshot: keySnapshot(pair),
    expectedKeySourceDigest: sourceDigest,
    asOf: evaluationTime,
    ...overrides,
  });

  const p384 = createEcPair("platform-es384", "secp384r1", "ES384");
  const p384Report = verifyUcpRequestEvidence(signUcpRequest(makeGet(p384), p384));
  assert.equal(p384Report.upstreamValid, true, JSON.stringify(p384Report.issues));
  assert.equal(p384Report.value.algorithm, "ES384");

  const p256 = createEcPair("platform-boundary");
  const queryRequest = makeGet(p256, {
    query: "?view=summary",
    signatureInput:
      'sig1=("@method" "@authority" "@path" "@query");keyid="platform-boundary"',
    asOf: 1_774_742_400,
  });
  const queryReport = verifyUcpRequestEvidence(signUcpRequest(queryRequest, p256));
  assert.equal(queryReport.upstreamValid, true, JSON.stringify(queryReport.issues));
  assert.equal(queryReport.value.operation.endsWith("?view=summary"), true);

  for (const overrides of [
    { method: "G ET" },
    { authority: "https://merchant.example" },
    { path: "checkout-sessions" },
    { asOf: -1 },
  ]) {
    const unsigned = makeGet(p256, overrides);
    const report = overrides.asOf === -1
      ? verifyUcpRequestEvidence(signUcpRequest(unsigned, p256))
      : verifyUcpRequestEvidence(signUcpRequest(unsigned, p256));
    assert.equal(report.upstreamValid, false);
    assert.equal(issueCodes(report).has("UCP_REQUEST_EVIDENCE_INVALID"), true);
  }

  const badAgent = makeGet(p256, {
    headers: { "UCP-Agent": 'profile="http://platform.example/ucp"' },
    signatureInput:
      'sig1=("@method" "@authority" "@path" "ucp-agent");keyid="platform-boundary"',
  });
  assert.equal(verifyUcpRequestEvidence(signUcpRequest(badAgent, p256)).upstreamValid, false);

  const mismatchedKid = makeGet(p256, {
    signatureInput:
      'sig1=("@method" "@authority" "@path");keyid="different-platform"',
  });
  const mismatchedKidReport = verifyUcpRequestEvidence(signUcpRequest(mismatchedKid, p256));
  assert.equal(mismatchedKidReport.upstreamValid, false);
  assert.equal(issueCodes(mismatchedKidReport).has("UCP_SIGNATURE_KEY_MISMATCH"), true);

  const p521 = createEcPair("platform-es512", "secp521r1", "ES512");
  const unsupportedCurve = verifyUcpRequestEvidence(signUcpRequest(makeGet(p521), p521));
  assert.equal(unsupportedCurve.upstreamValid, false);
  assert.equal(issueCodes(unsupportedCurve).has("UCP_ALGORITHM_UNSUPPORTED"), true);

  const body = Buffer.from('{"id":"body-with-missing-fields"}', "utf8");
  const stateChanging = {
    method: "POST",
    authority: "merchant.example",
    path: "/checkout-sessions",
    headers: { "Idempotency-Key": "5fbf0fc1-95cb-4732-9074-f935d8fd242c" },
    rawBody: body,
    signatureInput:
      'sig1=("@method" "@authority" "@path" "idempotency-key");keyid="platform-boundary"',
    signature: "sig1=:AA==:",
    keySnapshot: keySnapshot(p256),
    expectedKeySourceDigest: sourceDigest,
    asOf: evaluationTime,
    replayDisposition: "new",
  };
  const missingBodyHeaders = verifyUcpRequestEvidence(signUcpRequest(stateChanging, p256));
  assert.equal(missingBodyHeaders.upstreamValid, false);
  assert.equal(issueCodes(missingBodyHeaders).has("UCP_CONTENT_DIGEST_MISSING"), true);
  assert.equal(issueCodes(missingBodyHeaders).has("UCP_CONTENT_TYPE_MISSING"), true);

  const weakIdempotency = {
    ...stateChanging,
    headers: {
      "Idempotency-Key": "short",
      "Content-Digest": contentDigest(body),
      "Content-Type": "application/json",
    },
    signatureInput:
      'sig1=("@method" "@authority" "@path" "idempotency-key" "content-digest" "content-type");keyid="platform-boundary"',
  };
  const weakIdempotencyReport = verifyUcpRequestEvidence(signUcpRequest(weakIdempotency, p256));
  assert.equal(weakIdempotencyReport.upstreamValid, false);
  assert.equal(issueCodes(weakIdempotencyReport).has("UCP_IDEMPOTENCY_KEY_INVALID"), true);

  const cachedWithoutRecord = {
    ...stateChanging,
    headers: {
      "Idempotency-Key": "690c60e6-838e-49cf-aea6-a406ae44fcfd",
      "Content-Digest": contentDigest(body),
      "Content-Type": "application/json",
    },
    signatureInput:
      'sig1=("@method" "@authority" "@path" "idempotency-key" "content-digest" "content-type");keyid="platform-boundary"',
    replayDisposition: "cached",
  };
  const cachedWithoutRecordReport = verifyUcpRequestEvidence(
    signUcpRequest(cachedWithoutRecord, p256),
  );
  assert.equal(cachedWithoutRecordReport.upstreamValid, false);
  assert.equal(issueCodes(cachedWithoutRecordReport).has("UCP_REPLAY_RECORD_MISSING"), true);

  const future = makeGet(p256, {
    signatureInput:
      'sig1=("@method" "@authority" "@path");created=1900000000;expires=1700000000;keyid="platform-boundary"',
  });
  const futureReport = verifyUcpRequestEvidence(signUcpRequest(future, p256));
  assert.equal(futureReport.upstreamValid, false);
  assert.equal(issueCodes(futureReport).has("UCP_SIGNATURE_CREATED_IN_FUTURE"), true);
  assert.equal(issueCodes(futureReport).has("UCP_SIGNATURE_EXPIRED"), true);

  const validSigned = signUcpRequest(makeGet(p256), p256);
  const labelMismatch = verifyUcpRequestEvidence({
    ...validSigned,
    signature: validSigned.signature.replace("sig1=", "other="),
  });
  assert.equal(labelMismatch.upstreamValid, false);
  const invalidSignature = verifyUcpRequestEvidence({
    ...validSigned,
    signature: `sig1=:${Buffer.alloc(64).toString("base64")}:`,
  });
  assert.equal(invalidSignature.upstreamValid, false);
  assert.equal(issueCodes(invalidSignature).has("UCP_SIGNATURE_INVALID"), true);
});
