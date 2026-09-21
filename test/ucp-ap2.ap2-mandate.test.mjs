import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { verifyAp2Mandate } from "../dist/ucp-ap2.js";
import {
  createAp2Token,
  createEcPair,
  evaluationTime,
  issueCodes,
  keySnapshot,
  makeClosedAp2Fixture,
  sourceDigest,
} from "./ucp-ap2-helpers.mjs";

test("AP2 verifier handles expiry, temporal, issuer, checkout, and key-binding boundaries", () => {
  const fixture = makeClosedAp2Fixture();
  const verifyClaims = (claimOverrides, tokenOptions = {}, optionOverrides = {}) => {
    const claims = { ...fixture.claims, ...claimOverrides };
    const token = createAp2Token(
      claims,
      fixture.issuer,
      fixture.agent,
      undefined,
      tokenOptions,
    );
    return verifyAp2Mandate({ ...fixture.options, token, ...optionOverrides });
  };

  const missingExpiry = verifyClaims({ exp: undefined });
  assert.equal(missingExpiry.upstreamValid, true);
  assert.equal(missingExpiry.evidenceEligible, false);
  assert.equal(issueCodes(missingExpiry).has("AP2_EXPIRY_MISSING"), true);

  assert.doesNotThrow(() => verifyAp2Mandate({
    ...fixture.options,
    issuerKeySnapshot: null,
  }));
  const malformedSnapshot = verifyAp2Mandate({
    ...fixture.options,
    issuerKeySnapshot: null,
  });
  assert.equal(malformedSnapshot.upstreamValid, false);
  assert.equal(issueCodes(malformedSnapshot).has("INTEROP_KEY_SNAPSHOT_INVALID"), true);

  const temporalFailures = [
    [{ exp: 1_700_000_000 }, "AP2_TOKEN_EXPIRED"],
    [{ exp: "tomorrow" }, "AP2_EXPIRY_INVALID"],
    [{ nbf: 1_900_000_000 }, "AP2_TOKEN_NOT_YET_VALID"],
    [{ nbf: "later" }, "AP2_NBF_INVALID"],
    [{ iat: 1_900_000_000 }, "AP2_IAT_IN_FUTURE"],
    [{ iat: "earlier" }, "AP2_IAT_INVALID"],
  ];
  for (const [overrides, code] of temporalFailures) {
    const report = verifyClaims(overrides);
    assert.equal(report.upstreamValid, false, code);
    assert.equal(issueCodes(report).has(code), true);
  }

  const issuerMismatch = verifyAp2Mandate({
    ...fixture.options,
    expectedIssuer: "https://different-issuer.example",
  });
  assert.equal(issuerMismatch.upstreamValid, false);
  assert.equal(issueCodes(issuerMismatch).has("AP2_ISSUER_MISMATCH"), true);

  const missingCheckout = verifyClaims({
    checkout_jwt: undefined,
    checkout_hash: undefined,
  });
  assert.equal(missingCheckout.upstreamValid, false);
  assert.equal(issueCodes(missingCheckout).has("AP2_CHECKOUT_BINDING_MISSING"), true);

  const expectedJwtMismatch = verifyAp2Mandate({
    ...fixture.options,
    expectedCheckoutJwt: "different-checkout-jwt",
  });
  assert.equal(expectedJwtMismatch.upstreamValid, false);
  assert.equal(issueCodes(expectedJwtMismatch).has("AP2_CHECKOUT_JWT_MISMATCH"), true);
  const expectedHashMismatch = verifyAp2Mandate({
    ...fixture.options,
    expectedCheckoutHash: "different-checkout-hash",
  });
  assert.equal(expectedHashMismatch.upstreamValid, false);
  assert.equal(
    issueCodes(expectedHashMismatch).has("AP2_EXPECTED_CHECKOUT_HASH_MISMATCH"),
    true,
  );

  const issuerJwtOnly = `${fixture.token.split("~")[0]}~`;
  const optionalKeyBinding = verifyAp2Mandate({
    ...fixture.options,
    token: issuerJwtOnly,
    requireKeyBinding: false,
  });
  assert.equal(optionalKeyBinding.upstreamValid, true, JSON.stringify(optionalKeyBinding.issues));
  assert.equal(optionalKeyBinding.value.keyBound, false);
  const requiredKeyBinding = verifyAp2Mandate({
    ...fixture.options,
    token: issuerJwtOnly,
    requireKeyBinding: true,
  });
  assert.equal(requiredKeyBinding.upstreamValid, false);
  assert.equal(issueCodes(requiredKeyBinding).has("AP2_KEY_BINDING_MISSING"), true);

  const missingCnf = verifyClaims({ cnf: undefined });
  assert.equal(missingCnf.upstreamValid, false);
  assert.equal(issueCodes(missingCnf).has("AP2_KEY_BINDING_INVALID"), true);
  const differentAgent = createEcPair("different-agent");
  const agentMismatch = verifyAp2Mandate({
    ...fixture.options,
    expectedAgentJwk: differentAgent.publicJwk,
  });
  assert.equal(agentMismatch.upstreamValid, false);
  assert.equal(issueCodes(agentMismatch).has("AP2_KEY_BINDING_INVALID"), true);

  const wrongSdHash = verifyClaims({}, { kbClaims: { sd_hash: "wrong" } });
  assert.equal(wrongSdHash.upstreamValid, false);
  const audienceArray = verifyClaims({}, {
    kbClaims: { aud: ["https://merchant.example", "https://backup.example"] },
  });
  assert.equal(audienceArray.upstreamValid, true, JSON.stringify(audienceArray.issues));
  const malformedAudience = verifyClaims({}, {
    kbClaims: { aud: ["https://merchant.example", 7] },
  });
  assert.equal(malformedAudience.upstreamValid, false);
  const missingKbExpiry = verifyClaims({}, { kbClaims: { exp: undefined } });
  assert.equal(missingKbExpiry.upstreamValid, true);
  assert.equal(missingKbExpiry.evidenceEligible, false);
  const expiredKb = verifyClaims({}, { kbClaims: { exp: 1_700_000_000 } });
  assert.equal(expiredKb.upstreamValid, false);

  const malformedToken = verifyAp2Mandate({ ...fixture.options, token: "malformed" });
  assert.equal(malformedToken.upstreamValid, false);
  assert.equal(issueCodes(malformedToken).has("AP2_TOKEN_INVALID"), true);
});

test("AP2 v0.2 mandate variants and known constraints verify without broadening authority", () => {
  const fixture = makeClosedAp2Fixture();
  const allowedConstraint = {
    type: "checkout.allowed_merchants",
    allowed: [{
      id: "merchant-1",
      name: "Synthetic Merchant",
      website: "https://merchant.example",
    }],
  };
  const allowedToken = createAp2Token(
    { ...fixture.claims, constraints: [allowedConstraint] },
    fixture.issuer,
    fixture.agent,
  );
  const allowed = verifyAp2Mandate({
    ...fixture.options,
    token: allowedToken,
    expectedMerchant: {
      id: "merchant-1",
      website: "https://merchant.example",
    },
  });
  assert.equal(allowed.upstreamValid, true, JSON.stringify(allowed.issues));
  assert.equal(allowed.value.authorizesNativeRole, false);

  const denied = verifyAp2Mandate({
    ...fixture.options,
    token: allowedToken,
    expectedMerchant: {
      id: "merchant-2",
      website: "https://merchant.example",
    },
  });
  assert.equal(denied.upstreamValid, false);
  assert.equal(issueCodes(denied).has("AP2_CONSTRAINT_FAILED"), true);

  for (const constraints of ["not-an-array", [null], [{ type: 7 }]]) {
    const token = createAp2Token(
      { ...fixture.claims, constraints },
      fixture.issuer,
      fixture.agent,
    );
    const report = verifyAp2Mandate({ ...fixture.options, token });
    assert.equal(report.upstreamValid, false);
    assert.equal(
      issueCodes(report).has("AP2_CONSTRAINTS_INVALID") ||
        issueCodes(report).has("AP2_CONSTRAINT_INVALID"),
      true,
    );
  }

  const openToken = createAp2Token(
    {
      ...fixture.claims,
      vct: "mandate.checkout.open.1",
      checkout_jwt: undefined,
      checkout_hash: undefined,
      constraints: [allowedConstraint],
    },
    fixture.issuer,
    fixture.agent,
  );
  const open = verifyAp2Mandate({
    ...fixture.options,
    token: openToken,
    expectedVct: "mandate.checkout.open.1",
    expectedMerchant: { id: "merchant-1" },
  });
  assert.equal(open.upstreamValid, true, JSON.stringify(open.issues));

  const paymentToken = createAp2Token(
    {
      ...fixture.claims,
      vct: "mandate.payment.1",
      checkout_jwt: undefined,
      checkout_hash: undefined,
      transaction_id: fixture.checkoutHash,
    },
    fixture.issuer,
    fixture.agent,
  );
  const payment = verifyAp2Mandate({
    ...fixture.options,
    token: paymentToken,
    expectedVct: "mandate.payment.1",
  });
  assert.equal(payment.upstreamValid, true, JSON.stringify(payment.issues));
  assert.equal(payment.value.checkoutHash, fixture.checkoutHash);

  const wrongPaymentToken = createAp2Token(
    {
      ...fixture.claims,
      vct: "mandate.payment.1",
      checkout_jwt: undefined,
      checkout_hash: undefined,
      transaction_id: "wrong-checkout-hash",
    },
    fixture.issuer,
    fixture.agent,
  );
  const wrongPayment = verifyAp2Mandate({
    ...fixture.options,
    token: wrongPaymentToken,
    expectedVct: "mandate.payment.1",
  });
  assert.equal(wrongPayment.upstreamValid, false);
  assert.equal(
    issueCodes(wrongPayment).has("AP2_PAYMENT_CHECKOUT_BINDING_MISMATCH"),
    true,
  );

  const issuer384 = createEcPair("issuer-es384", "secp384r1", "ES384");
  const agent384 = createEcPair("agent-es384", "secp384r1", "ES384");
  const claims384 = {
    ...fixture.claims,
    cnf: { jwk: agent384.publicJwk },
  };
  const token384 = createAp2Token(
    claims384,
    issuer384,
    agent384,
    { alg: "ES384", kid: issuer384.publicJwk.kid, typ: "dc+sd-jwt" },
    { kbHeader: { alg: "ES384", typ: "kb+jwt" } },
  );
  const report384 = verifyAp2Mandate({
    ...fixture.options,
    token: token384,
    issuerKeySnapshot: keySnapshot(issuer384),
    expectedAgentJwk: agent384.publicJwk,
    allowedAlgorithms: ["ES256", "ES384"],
  });
  assert.equal(report384.upstreamValid, true, JSON.stringify(report384.issues));
  assert.equal(report384.value.issuerAlgorithm, "ES384");
});

test("AP2 unknown constraints fail and stale issuer keys separate validity from eligibility", () => {
  const issuer = createEcPair("issuer-constraints");
  const agent = createEcPair("agent-constraints");
  const checkoutJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpZCI6ImNoay0xIn0.signature";
  const checkoutHash = createHash("sha256").update(checkoutJwt, "utf8").digest("base64url");
  const claims = {
    iss: "https://trusted-surface.example",
    vct: "mandate.checkout.1",
    iat: 1_770_000_000,
    exp: 1_800_000_000,
    checkout_jwt: checkoutJwt,
    checkout_hash: checkoutHash,
    constraints: [{ type: "com.vendor.unimplemented-budget" }],
    cnf: { jwk: agent.publicJwk },
  };
  const token = createAp2Token(claims, issuer, agent);
  const options = {
    token,
    expectedVct: "mandate.checkout.1",
    issuerKeySnapshot: keySnapshot(issuer),
    expectedIssuerKeySourceDigest: sourceDigest,
    expectedIssuer: "https://trusted-surface.example",
    expectedAudience: "https://merchant.example",
    expectedNonce: "nonce-ap2-123",
    asOf: evaluationTime,
    expectedAgentJwk: agent.publicJwk,
    expectedCheckoutJwt: checkoutJwt,
    expectedCheckoutHash: checkoutHash,
  };
  const unsupported = verifyAp2Mandate(options);
  assert.equal(unsupported.upstreamValid, false);
  assert.equal(
    unsupported.issues.some((issue) => issue.code === "AP2_CONSTRAINT_UNSUPPORTED"),
    true,
  );

  const noConstraintsToken = createAp2Token(
    { ...claims, constraints: undefined },
    issuer,
    agent,
  );
  const stale = verifyAp2Mandate({
    ...options,
    token: noConstraintsToken,
    issuerKeySnapshot: keySnapshot(issuer, {
      validUntil: "2026-05-01T00:00:00.000Z",
    }),
  });
  assert.equal(stale.upstreamValid, true, JSON.stringify(stale.issues));
  assert.equal(stale.evidenceEligible, false);
  assert.equal(stale.issues.some((issue) => issue.code === "INTEROP_KEY_SNAPSHOT_STALE"), true);
});
