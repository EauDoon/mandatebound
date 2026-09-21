import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  AP2_MANDATE_VCTS,
  parseCompactAp2Token,
  verifyAp2Mandate,
} from "../dist/ucp-ap2.js";
import {
  createAp2Token,
  createEcPair,
  createJwt,
  encodeJson,
  evaluationTime,
  issueCodes,
  keySnapshot,
  makeClosedAp2Fixture,
  mutateBase64UrlBytes,
  mutateCompactSignature,
  sourceDigest,
} from "./ucp-ap2-helpers.mjs";

test("compact AP2 parser is strict about JWT, SD-JWT, disclosure, and UTF-8 encodings", () => {
  const fixture = makeClosedAp2Fixture();
  const issuerJwt = fixture.token.split("~")[0];
  const unsignedSdJwt = `${issuerJwt}~`;
  const parsedUnsigned = parseCompactAp2Token(unsignedSdJwt);
  assert.equal(parsedUnsigned.keyBindingJwt, null);
  assert.equal(parsedUnsigned.sdJwtWithoutKeyBinding, unsignedSdJwt);

  for (const value of [
    null,
    "",
    "x".repeat(1_048_577),
    "~",
    "one.two",
    "*.e30.AA",
    `${Buffer.from([0xff]).toString("base64url")}.e30.AA`,
    `${Buffer.from('{"alg":"ES256","alg":"ES256"}').toString("base64url")}.e30.AA`,
  ]) {
    assert.throws(() => parseCompactAp2Token(value));
  }

  const sha512Jwt = createJwt(
    { ...fixture.claims, _sd_alg: "sha-512" },
    fixture.issuer,
    { alg: "ES256", kid: fixture.issuer.publicJwk.kid, typ: "dc+sd-jwt" },
  );
  assert.throws(() => parseCompactAp2Token(sha512Jwt));
  assert.throws(() => parseCompactAp2Token(`${issuerJwt}~~`));
  assert.throws(() => parseCompactAp2Token(`${issuerJwt}~not.a.disclosure~`));
  assert.throws(() => parseCompactAp2Token(`${issuerJwt}~*~`));
  assert.throws(() => parseCompactAp2Token(`${issuerJwt}~${encodeJson({ not: "array" })}~`));
  assert.throws(() => parseCompactAp2Token(`${issuerJwt}~${encodeJson(["short", "claim", true])}~`));

  const disclosure = encodeJson(["long-enough-salt", "merchant_note", "approved"]);
  const parsedDisclosure = parseCompactAp2Token(`${issuerJwt}~${disclosure}~`);
  assert.equal(parsedDisclosure.disclosures.length, 1);
  assert.equal(parsedDisclosure.disclosures[0].exact, disclosure);
});

test("AP2 selective disclosures are hash-bound, top-level, and conflict-free", () => {
  const fixture = makeClosedAp2Fixture();
  const disclosure = encodeJson([
    "disclosure-salt-123",
    "checkout_jwt",
    fixture.checkoutJwt,
  ]);
  const disclosureDigest = createHash("sha256").update(disclosure, "ascii").digest("base64url");
  const disclosedClaims = {
    ...fixture.claims,
    checkout_jwt: undefined,
    _sd_alg: "sha-256",
    _sd: [disclosureDigest],
  };
  const disclosedToken = createAp2Token(
    disclosedClaims,
    fixture.issuer,
    fixture.agent,
    undefined,
    { disclosures: [disclosure] },
  );
  const disclosed = verifyAp2Mandate({
    ...fixture.options,
    token: disclosedToken,
  });
  assert.equal(disclosed.upstreamValid, true, JSON.stringify(disclosed.issues));
  assert.equal(disclosed.value.claims.checkout_jwt, fixture.checkoutJwt);

  const unboundToken = createAp2Token(
    { ...fixture.claims, _sd: [] },
    fixture.issuer,
    fixture.agent,
    undefined,
    { disclosures: [disclosure] },
  );
  const unbound = verifyAp2Mandate({ ...fixture.options, token: unboundToken });
  assert.equal(unbound.upstreamValid, false);
  assert.equal(issueCodes(unbound).has("AP2_DISCLOSURE_UNBOUND"), true);

  const arrayDisclosure = encodeJson(["array-disclosure-salt", { id: "array-value" }]);
  const arrayDigest = createHash("sha256").update(arrayDisclosure, "ascii").digest("base64url");
  const arrayToken = createAp2Token(
    { ...fixture.claims, _sd: [arrayDigest] },
    fixture.issuer,
    fixture.agent,
    undefined,
    { disclosures: [arrayDisclosure] },
  );
  const arrayReport = verifyAp2Mandate({ ...fixture.options, token: arrayToken });
  assert.equal(arrayReport.upstreamValid, false);
  assert.equal(issueCodes(arrayReport).has("AP2_DISCLOSURE_SHAPE_UNSUPPORTED"), true);

  const conflictDisclosure = encodeJson([
    "conflict-disclosure-salt",
    "iss",
    "https://attacker.invalid",
  ]);
  const conflictDigest = createHash("sha256")
    .update(conflictDisclosure, "ascii")
    .digest("base64url");
  const conflictToken = createAp2Token(
    { ...fixture.claims, _sd: [conflictDigest] },
    fixture.issuer,
    fixture.agent,
    undefined,
    { disclosures: [conflictDisclosure] },
  );
  const conflict = verifyAp2Mandate({ ...fixture.options, token: conflictToken });
  assert.equal(conflict.upstreamValid, false);
  assert.equal(issueCodes(conflict).has("AP2_DISCLOSURE_CONFLICT"), true);

  const badSdListToken = createAp2Token(
    { ...fixture.claims, _sd: "not-an-array" },
    fixture.issuer,
    fixture.agent,
  );
  const badSdList = verifyAp2Mandate({ ...fixture.options, token: badSdListToken });
  assert.equal(badSdList.upstreamValid, false);
  assert.equal(issueCodes(badSdList).has("AP2_SD_DIGESTS_INVALID"), true);
});

test("AP2 token preserves compact bytes and verifies vct, issuer, key binding, and checkout hash", () => {
  const issuer = createEcPair("issuer-2026");
  const agent = createEcPair("agent-transaction-key");
  const checkoutJwt = createJwt(
    { id: "chk-123", amount: 1_000, currency: "USD" },
    createEcPair("merchant-checkout-key"),
  );
  const checkoutHash = createHash("sha256").update(checkoutJwt, "utf8").digest("base64url");
  const claims = {
    iss: "https://trusted-surface.example",
    vct: "mandate.checkout.1",
    iat: 1_770_000_000,
    exp: 1_800_000_000,
    checkout_jwt: checkoutJwt,
    checkout_hash: checkoutHash,
    cnf: { jwk: agent.publicJwk },
  };
  const token = createAp2Token(claims, issuer, agent);
  const baseOptions = {
    token,
    expectedVct: "mandate.checkout.1",
    issuerKeySnapshot: keySnapshot(issuer),
    expectedIssuerKeySourceDigest: sourceDigest,
    expectedIssuer: "https://trusted-surface.example",
    expectedAudience: "https://merchant.example",
    expectedNonce: "nonce-ap2-123",
    asOf: evaluationTime,
    allowedAlgorithms: ["ES256"],
    requireKeyBinding: true,
    expectedAgentJwk: agent.publicJwk,
    expectedCheckoutJwt: checkoutJwt,
    expectedCheckoutHash: checkoutHash,
  };
  const valid = verifyAp2Mandate(baseOptions);
  assert.equal(valid.upstreamValid, true, JSON.stringify(valid.issues));
  assert.equal(valid.evidenceEligible, true);
  assert.equal(valid.value.exactToken, token);
  assert.equal(valid.value.keyBound, true);
  assert.equal(valid.value.checkoutHash, checkoutHash);
  assert.equal(valid.value.authorizesNativeRole, false);
  assert.equal(parseCompactAp2Token(token).exact, token);
  assert.deepEqual(AP2_MANDATE_VCTS, [
    "mandate.checkout.1",
    "mandate.checkout.open.1",
    "mandate.payment.1",
    "mandate.payment.open.1",
  ]);

  const wrongVctToken = createAp2Token(
    { ...claims, vct: "mandate.checkout.2" },
    issuer,
    agent,
  );
  const wrongVct = verifyAp2Mandate({ ...baseOptions, token: wrongVctToken });
  assert.equal(wrongVct.upstreamValid, false);
  assert.equal(wrongVct.issues.some((issue) => issue.code === "AP2_VCT_MISMATCH"), true);

  const wrongNonce = verifyAp2Mandate({ ...baseOptions, expectedNonce: "different-nonce" });
  assert.equal(wrongNonce.upstreamValid, false);
  assert.equal(wrongNonce.issues.some((issue) => issue.code === "AP2_KEY_BINDING_INVALID"), true);

  const oneByteMutation = mutateCompactSignature(token);
  assert.equal(verifyAp2Mandate({ ...baseOptions, token: oneByteMutation }).upstreamValid, false);

  const wrongHashToken = createAp2Token(
    { ...claims, checkout_hash: mutateBase64UrlBytes(checkoutHash) },
    issuer,
    agent,
  );
  const wrongHash = verifyAp2Mandate({ ...baseOptions, token: wrongHashToken });
  assert.equal(wrongHash.upstreamValid, false);
  assert.equal(
    wrongHash.issues.some((issue) => issue.code === "AP2_CHECKOUT_HASH_MISMATCH"),
    true,
  );

  const confusedToken = createAp2Token(
    claims,
    issuer,
    agent,
    { alg: "ES384", kid: issuer.publicJwk.kid, typ: "dc+sd-jwt" },
  );
  const confused = verifyAp2Mandate({
    ...baseOptions,
    token: confusedToken,
    allowedAlgorithms: ["ES256", "ES384"],
  });
  assert.equal(confused.upstreamValid, false);
  assert.equal(
    confused.issues.some((issue) => issue.code === "AP2_ISSUER_SIGNATURE_INVALID"),
    true,
  );
});
