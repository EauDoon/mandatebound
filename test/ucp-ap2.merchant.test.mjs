import assert from "node:assert/strict";
import test from "node:test";
import { sha256Bytes } from "../dist/canonical.js";
import {
  verifyDetachedMerchantAuthorization,
} from "../dist/ucp-ap2.js";
import {
  createEcPair,
  encodeJson,
  evaluationTime,
  issueCodes,
  keySnapshot,
  merchantAuthorization,
  mutateCompactSignature,
  sourceDigest,
} from "./ucp-ap2-helpers.mjs";

test("merchant detached JWS verifies JCS checkout-without-ap2 and fails closed", () => {
  const merchant = createEcPair("merchant-2026");
  const checkout = {
    id: "chk-123",
    status: "ready_for_complete",
    currency: "USD",
    totals: [{ type: "total", amount: 10_00 }],
    ap2: { merchant_authorization: "placeholder" },
  };
  const detached = merchantAuthorization(checkout, merchant);
  checkout.ap2.merchant_authorization = detached;
  const options = {
    keySnapshot: keySnapshot(merchant),
    expectedKeySourceDigest: sourceDigest,
    asOf: evaluationTime,
  };
  const valid = verifyDetachedMerchantAuthorization(checkout, detached, options);
  assert.equal(valid.upstreamValid, true, JSON.stringify(valid.issues));
  assert.equal(valid.evidenceEligible, true);
  assert.equal(valid.value.exactCompact, detached);
  for (const keySnapshot of [null, undefined, {}]) {
    const malformedSnapshot = verifyDetachedMerchantAuthorization(checkout, detached, {
      ...options,
      keySnapshot,
    });
    assert.equal(malformedSnapshot.upstreamValid, false);
    assert.equal(malformedSnapshot.value, null);
    assert.equal(malformedSnapshot.issues[0].code, "INTEROP_KEY_SNAPSHOT_INVALID");
  }

  const mutated = {
    ...checkout,
    totals: [{ type: "total", amount: 10_01 }],
  };
  assert.equal(
    verifyDetachedMerchantAuthorization(mutated, detached, options).upstreamValid,
    false,
  );

  const der = merchantAuthorization(checkout, merchant, { encoding: "der" });
  const derReport = verifyDetachedMerchantAuthorization({
    ...checkout,
    ap2: { merchant_authorization: der },
  }, der, options);
  assert.equal(derReport.upstreamValid, false);
  assert.equal(
    derReport.issues.some((issue) => issue.message.includes("fixed-width raw r||s")),
    true,
  );

  const confused = merchantAuthorization(checkout, merchant, { alg: "ES384" });
  assert.equal(
    verifyDetachedMerchantAuthorization({
      ...checkout,
      ap2: { merchant_authorization: confused },
    }, confused, {
      ...options,
      allowedAlgorithms: ["ES256", "ES384"],
    }).upstreamValid,
    false,
  );

  const stale = verifyDetachedMerchantAuthorization(checkout, detached, {
    ...options,
    keySnapshot: keySnapshot(merchant, { validUntil: "2026-05-01T00:00:00.000Z" }),
  });
  assert.equal(stale.upstreamValid, true);
  assert.equal(stale.evidenceEligible, false);
  assert.equal(stale.issues.some((issue) => issue.code === "INTEROP_KEY_SNAPSHOT_STALE"), true);
});

test("merchant authorization enforces JOSE headers, curve binding, trust windows, and strict JWKs", () => {
  for (const [namedCurve, algorithm] of [
    ["secp384r1", "ES384"],
    ["secp521r1", "ES512"],
  ]) {
    const merchant = createEcPair(`merchant-${algorithm}`, namedCurve, algorithm);
    const checkout = {
      id: `chk-${algorithm}`,
      total: 2_500,
      ap2: { merchant_authorization: "placeholder" },
    };
    const detached = merchantAuthorization(checkout, merchant, { alg: algorithm });
    checkout.ap2.merchant_authorization = detached;
    const report = verifyDetachedMerchantAuthorization(checkout, detached, {
      keySnapshot: keySnapshot(merchant),
      expectedKeySourceDigest: sourceDigest,
      asOf: evaluationTime,
      allowedAlgorithms: [algorithm],
    });
    assert.equal(report.upstreamValid, true, `${algorithm}: ${JSON.stringify(report.issues)}`);
  }

  const merchant = createEcPair("merchant-strict");
  const checkout = {
    id: "chk-strict",
    total: 2_500,
    ap2: { merchant_authorization: "placeholder" },
  };
  const detached = merchantAuthorization(checkout, merchant);
  checkout.ap2.merchant_authorization = detached;
  const options = {
    keySnapshot: keySnapshot(merchant),
    expectedKeySourceDigest: sourceDigest,
    asOf: evaluationTime,
  };

  const malformedValues = [
    "",
    "one.two.three",
    `${"a".repeat(65_537)}`,
    `${Buffer.from([0xff]).toString("base64url")}..${Buffer.alloc(64).toString("base64url")}`,
  ];
  for (const value of malformedValues) {
    const report = verifyDetachedMerchantAuthorization(checkout, value, options);
    assert.equal(report.upstreamValid, false);
    assert.equal(issueCodes(report).has("UCP_AP2_MERCHANT_AUTHORIZATION_INVALID"), true);
  }

  const protectedSegment = detached.split(".")[0];
  const signatureSegment = detached.split(".")[2];
  const withHeader = (header) => `${encodeJson(header)}..${signatureSegment}`;
  for (const candidate of [
    withHeader({ alg: "HS256", kid: merchant.publicJwk.kid }),
    withHeader({ alg: "ES256", kid: merchant.publicJwk.kid, crit: ["alg"] }),
    withHeader({ alg: "ES256", kid: merchant.publicJwk.kid, typ: "JWT" }),
    withHeader({ alg: "ES256" }),
  ]) {
    const report = verifyDetachedMerchantAuthorization({
      ...checkout,
      ap2: { merchant_authorization: candidate },
    }, candidate, options);
    assert.equal(report.upstreamValid, false);
  }
  assert.equal(typeof protectedSegment, "string");

  const emptyAllowlist = verifyDetachedMerchantAuthorization(checkout, detached, {
    ...options,
    allowedAlgorithms: [],
  });
  assert.equal(emptyAllowlist.upstreamValid, false);
  const unsupportedAllowlist = verifyDetachedMerchantAuthorization(checkout, detached, {
    ...options,
    allowedAlgorithms: ["HS256"],
  });
  assert.equal(unsupportedAllowlist.upstreamValid, false);

  const alternateKid = merchantAuthorization(checkout, merchant, {
    extraHeader: { kid: "merchant-other" },
  });
  const kidMismatch = verifyDetachedMerchantAuthorization({
    ...checkout,
    ap2: { merchant_authorization: alternateKid },
  }, alternateKid, options);
  assert.equal(kidMismatch.upstreamValid, false);
  assert.equal(issueCodes(kidMismatch).has("UCP_AP2_MERCHANT_KEY_MISMATCH"), true);

  const unbound = verifyDetachedMerchantAuthorization({
    ...checkout,
    ap2: { merchant_authorization: "different-token" },
  }, detached, options);
  assert.equal(unbound.upstreamValid, false);
  assert.equal(issueCodes(unbound).has("UCP_AP2_MERCHANT_AUTHORIZATION_UNBOUND"), true);
  assert.equal(verifyDetachedMerchantAuthorization({ id: "missing-ap2" }, detached, options).upstreamValid, false);

  const mutatedSignature = mutateCompactSignature(detached);
  const invalidSignature = verifyDetachedMerchantAuthorization({
    ...checkout,
    ap2: { merchant_authorization: mutatedSignature },
  }, mutatedSignature, options);
  assert.equal(invalidSignature.upstreamValid, false);
  assert.equal(issueCodes(invalidSignature).has("UCP_AP2_MERCHANT_SIGNATURE_INVALID"), true);

  const pinMismatch = verifyDetachedMerchantAuthorization(checkout, detached, {
    ...options,
    expectedKeySourceDigest: sha256Bytes(Buffer.from("different-pin")),
  });
  assert.equal(pinMismatch.upstreamValid, true);
  assert.equal(pinMismatch.evidenceEligible, false);
  assert.equal(issueCodes(pinMismatch).has("INTEROP_KEY_SOURCE_PIN_MISMATCH"), true);

  const trustWindowCases = [
    {
      overrides: {
        capturedAt: "2027-05-02T00:00:00.000Z",
        validUntil: "2027-05-01T00:00:00.000Z",
      },
      code: "INTEROP_KEY_SNAPSHOT_WINDOW_INVALID",
      upstreamValid: false,
    },
    {
      overrides: { validFrom: "2027-01-01T00:00:00.000Z" },
      code: "INTEROP_KEY_NOT_YET_VALID",
      upstreamValid: true,
    },
    {
      overrides: { invalidFrom: "2026-01-01T00:00:00.000Z" },
      code: "INTEROP_KEY_INVALIDATED",
      upstreamValid: true,
    },
    {
      overrides: { capturedAt: "not-a-time" },
      code: "INTEROP_KEY_SNAPSHOT_TIME_INVALID",
      upstreamValid: false,
    },
  ];
  for (const entry of trustWindowCases) {
    const report = verifyDetachedMerchantAuthorization(checkout, detached, {
      ...options,
      keySnapshot: keySnapshot(merchant, entry.overrides),
    });
    assert.equal(report.upstreamValid, entry.upstreamValid, entry.code);
    assert.equal(issueCodes(report).has(entry.code), true);
    if (entry.upstreamValid) assert.equal(report.evidenceEligible, false);
  }

  const malformedJwks = [
    { ...merchant.publicJwk, attacker_hint: "ignored" },
    { ...merchant.publicJwk, kty: "RSA" },
    { ...merchant.publicJwk, alg: "ES384" },
    { ...merchant.publicJwk, use: "enc" },
    { ...merchant.publicJwk, kid: 7 },
    { ...merchant.publicJwk, key_ops: ["sign"] },
    { ...merchant.publicJwk, x: "AA" },
    { ...merchant.publicJwk, x: Buffer.alloc(32).toString("base64url") },
  ];
  for (const jwk of malformedJwks) {
    const report = verifyDetachedMerchantAuthorization(checkout, detached, {
      ...options,
      keySnapshot: { ...options.keySnapshot, jwk },
    });
    assert.equal(report.upstreamValid, false);
    assert.equal(
      report.issues.every((issue) => !issue.message.includes("attacker_hint")),
      true,
    );
  }
});
