import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  AP2_DISPUTE_EVIDENCE_PROFILE,
  assembleAp2DisputeEvidence,
  createAp2EvidenceTimeline,
  packAp2DisputeEvidence,
  renderAp2EvidenceTimelineHtml,
  resolveAp2DisputeEvidence,
  verifyAp2DisputeEvidencePack,
} from "../dist/ap2-dispute.js";
import { sha256Bytes, sha256Digest } from "../dist/canonical.js";
import {
  computeAp2MandateReference,
  computeAp2OpenMandateHash,
  verifyAp2CheckoutJwt,
  verifyAp2MandateChain,
  verifyAp2Receipt,
} from "../dist/ucp-ap2.js";

const asOf = "2026-07-23T00:00:00.000Z";
const sourceDigest = sha256Bytes(Buffer.from("synthetic-ap2-dispute-key-source", "utf8"));

function ecPair(kid) {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return {
    ...pair,
    publicJwk: {
      ...pair.publicKey.export({ format: "jwk" }),
      kid,
      alg: "ES256",
      use: "sig",
      key_ops: ["verify"],
    },
  };
}

function snapshot(pair, overrides = {}) {
  return {
    kid: pair.publicJwk.kid,
    jwk: pair.publicJwk,
    sourceDigest,
    capturedAt: "2026-04-29T00:00:00.000Z",
    validUntil: "2027-04-29T00:00:00.000Z",
    ...overrides,
  };
}

function encodeJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function createJwt(claims, pair, typ = "JWT") {
  const protectedSegment = encodeJson({ alg: "ES256", kid: pair.publicJwk.kid, typ });
  const payloadSegment = encodeJson(claims);
  const signingInput = `${protectedSegment}.${payloadSegment}`;
  const signature = sign("sha256", Buffer.from(signingInput, "ascii"), {
    key: pair.privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${signingInput}.${signature.toString("base64url")}`;
}

function createMandate(claims, issuer, agent, audience, nonce, constraints) {
  const openVct = claims.vct === "mandate.checkout.1"
    ? "mandate.checkout.open.1"
    : "mandate.payment.open.1";
  const rootJwt = createJwt({
    _sd_alg: "sha-256",
    delegate_payload: [{
      vct: openVct,
      iat: 1_770_000_000,
      exp: 1_800_000_000,
      constraints,
      cnf: { jwk: agent.publicJwk },
    }],
  }, issuer, "dc+sd-jwt");
  const rootPresentation = `${rootJwt}~`;
  const terminalJwt = createJwt({
    _sd_alg: "sha-256",
    aud: audience,
    nonce,
    iat: 1_770_000_000,
    sd_hash: createHash("sha256").update(rootPresentation, "ascii").digest("base64url"),
    delegate_payload: [claims],
  }, agent, "kb+sd-jwt");
  return `${rootJwt}~~${terminalJwt}~`;
}

function mutateSignature(token) {
  const dot = token.lastIndexOf(".");
  const bytes = Buffer.from(token.slice(dot + 1), "base64url");
  bytes[0] ^= 1;
  return `${token.slice(0, dot + 1)}${bytes.toString("base64url")}`;
}

function makeFixture({
  checkoutMerchantId = "merchant-1",
  allowedMerchantId = "merchant-1",
  expectedMerchantId,
} = {}) {
  const issuer = ecPair("trusted-surface-key");
  const agent = ecPair("shopping-agent-key");
  const merchant = ecPair("merchant-receipt-key");
  const processor = ecPair("processor-receipt-key");
  const checkoutSigner = ecPair("checkout-key");
  const checkoutJwt = createJwt({
    id: "checkout-synthetic-1",
    merchant: {
      id: checkoutMerchantId,
      name: "Synthetic Store",
      website: "https://merchant.example",
    },
    line_items: [{
      id: "line-item-1",
      item: { id: "sku-1", title: "Synthetic item" },
      quantity: 1,
      totals: [
        { type: "subtotal", amount: 2_500 },
        { type: "total", amount: 2_500 },
      ],
    }],
    status: "incomplete",
    currency: "USD",
    totals: [
      { type: "subtotal", amount: 2_500 },
      { type: "total", amount: 2_500 },
    ],
    links: [],
  }, checkoutSigner);
  const transactionId = createHash("sha256").update(checkoutJwt, "utf8").digest("base64url");
  const checkoutMandate = createMandate({
    iss: "https://trusted-surface.example",
    vct: "mandate.checkout.1",
    checkout_jwt: checkoutJwt,
    checkout_hash: transactionId,
  }, issuer, agent, "https://merchant.example", "checkout-nonce", [{
    type: "checkout.allowed_merchants",
    allowed: [{
      id: allowedMerchantId,
      name: "Synthetic Store",
      website: "https://merchant.example",
    }],
  }, {
    type: "checkout.line_items",
    items: [{
      id: "requirement-1",
      acceptable_items: [{ id: "sku-1", title: "Synthetic item" }],
      quantity: 1,
    }],
  }]);
  const openCheckoutHash = computeAp2OpenMandateHash(checkoutMandate);
  const paymentMandate = createMandate({
    iss: "https://trusted-surface.example",
    vct: "mandate.payment.1",
    iat: 1_770_000_000,
    exp: 1_800_000_000,
    transaction_id: transactionId,
    payee: { id: checkoutMerchantId, name: "Synthetic Store" },
    payment_amount: { currency: "USD", amount: 2_500 },
    payment_instrument: { id: "instrument-1", type: "card" },
  }, issuer, agent, "https://processor.example", "payment-nonce", [{
    type: "payment.reference",
    conditional_transaction_id: openCheckoutHash,
  }]);
  const checkoutReceipt = createJwt({
    status: "Success",
    iss: "https://merchant.example",
    iat: 1_770_000_100,
    reference: computeAp2MandateReference(checkoutMandate),
    order_id: "order-synthetic-1",
  }, merchant);
  const paymentReceipt = createJwt({
    status: "Success",
    iss: "https://processor.example",
    iat: 1_770_000_200,
    reference: computeAp2MandateReference(paymentMandate),
    payment_id: "payment-synthetic-1",
    psp_confirmation_id: "psp-synthetic-1",
    network_confirmation_id: "network-synthetic-1",
  }, processor);
  const verificationPlan = {
    checkoutMandate: {
      issuerKeySnapshot: snapshot(issuer),
      expectedIssuerKeySourceDigest: sourceDigest,
      expectedIssuer: "https://trusted-surface.example",
      expectedAudience: "https://merchant.example",
      expectedNonce: "checkout-nonce",
      allowedAlgorithms: ["ES256"],
      requireKeyBinding: true,
      expectedAgentJwk: agent.publicJwk,
      expectedCheckoutJwt: checkoutJwt,
      ...(expectedMerchantId === undefined
        ? {}
        : { expectedMerchant: { id: expectedMerchantId } }),
    },
    checkoutJwt: {
      merchantKeySnapshot: snapshot(checkoutSigner),
      expectedMerchantKeySourceDigest: sourceDigest,
      allowedAlgorithms: ["ES256"],
    },
    paymentMandate: {
      issuerKeySnapshot: snapshot(issuer),
      expectedIssuerKeySourceDigest: sourceDigest,
      expectedIssuer: "https://trusted-surface.example",
      expectedAudience: "https://processor.example",
      expectedNonce: "payment-nonce",
      allowedAlgorithms: ["ES256"],
      requireKeyBinding: true,
      expectedAgentJwk: agent.publicJwk,
    },
    checkoutReceipt: {
      issuerKeySnapshot: snapshot(merchant),
      expectedIssuerKeySourceDigest: sourceDigest,
      expectedIssuer: "https://merchant.example",
      allowedAlgorithms: ["ES256"],
    },
    paymentReceipt: {
      issuerKeySnapshot: snapshot(processor),
      expectedIssuerKeySourceDigest: sourceDigest,
      expectedIssuer: "https://processor.example",
      allowedAlgorithms: ["ES256"],
    },
  };
  const sources = [{
    sourceId: "merchant-primary",
    role: "merchant",
    retrievedAt: "2026-07-22T23:59:00.000Z",
    artifacts: [
      { kind: "checkout_mandate", token: checkoutMandate },
      { kind: "checkout_receipt", token: checkoutReceipt },
    ],
  }, {
    sourceId: "processor-primary",
    role: "merchant_payment_processor",
    retrievedAt: "2026-07-22T23:59:30.000Z",
    artifacts: [
      { kind: "payment_mandate", token: paymentMandate },
      { kind: "payment_receipt", token: paymentReceipt },
    ],
  }];
  return {
    issuer,
    agent,
    merchant,
    processor,
    checkoutSigner,
    checkoutJwt,
    transactionId,
    openCheckoutHash,
    checkoutMandate,
    paymentMandate,
    checkoutReceipt,
    paymentReceipt,
    verificationPlan,
    sources,
    input: { transactionId, asOf, verificationPlan, sources },
  };
}

function codes(result) {
  return new Set(result.issues.map((issue) => issue.code));
}

function makePackInput(fixture, revocationStatus = "not_revoked") {
  return {
    ...fixture.input,
    createdAt: "2026-07-23T00:00:00.000Z",
    checkoutVersions: [{
      versionId: "checkout-version-1",
      sourceId: "merchant-primary",
      observedAt: "2026-07-22T23:58:30.000Z",
      checkoutJwt: fixture.checkoutJwt,
    }],
    revocations: [{
      recordId: "checkout-revocation-1",
      mandateKind: "checkout_mandate",
      sourceId: "merchant-primary",
      checkedAt: "2026-07-22T23:59:40.000Z",
      reportedStatus: revocationStatus,
      snapshotBase64: Buffer.from(JSON.stringify({
        mandate: "checkout",
        status: revocationStatus,
      }), "utf8").toString("base64"),
    }, {
      recordId: "payment-revocation-1",
      mandateKind: "payment_mandate",
      sourceId: "processor-primary",
      checkedAt: "2026-07-22T23:59:45.000Z",
      reportedStatus: "not_revoked",
      snapshotBase64: Buffer.from(JSON.stringify({
        mandate: "payment",
        status: "not_revoked",
      }), "utf8").toString("base64"),
    }],
  };
}

test("AP2 dispute resolver verifies the four exact artifacts without exposing raw tokens", () => {
  const fixture = makeFixture();
  const first = assembleAp2DisputeEvidence(fixture.input);
  const second = assembleAp2DisputeEvidence({
    ...fixture.input,
    sources: [...fixture.sources].reverse(),
  });
  assert.equal(first.status, "evidence_verified", JSON.stringify(first.issues));
  assert.equal(first.profile.id, AP2_DISPUTE_EVIDENCE_PROFILE.id);
  assert.equal(first.profile.ap2ReleaseCommit, "b4587ac1d055888a73b4b21750973cffba961793");
  assert.equal(first.releaseVersion, "1.2.0");
  assert.equal(first.selectedArtifacts.length, 4);
  assert.equal(first.gates.filter((entry) => entry.state === "passed").length, 5);
  assert.equal(first.historyCompleteness, "unknown");
  assert.equal(first.legalEffect, "not-determined");
  assert.equal(first.disputeOutcome, "not-determined");
  assert.equal(first.resolutionDigest, second.resolutionDigest);
  const rendered = JSON.stringify(first);
  assert.equal(rendered.includes(fixture.checkoutMandate), false);
  assert.equal(rendered.includes(fixture.paymentReceipt), false);
});

test("allowed merchants are evaluated against the bound signed Checkout", () => {
  const fixture = makeFixture({
    checkoutMerchantId: "signed-merchant",
    allowedMerchantId: "caller-selected-merchant",
    expectedMerchantId: "caller-selected-merchant",
  });
  const result = assembleAp2DisputeEvidence(fixture.input);
  assert.equal(result.status, "unresolved");
  assert.equal(codes(result).has("AP2_CONSTRAINT_FAILED"), true);

  const callerPinMismatch = makeFixture({
    checkoutMerchantId: "signed-and-allowed-merchant",
    allowedMerchantId: "signed-and-allowed-merchant",
    expectedMerchantId: "different-caller-pin",
  });
  const pinResult = assembleAp2DisputeEvidence(callerPinMismatch.input);
  assert.equal(pinResult.status, "unresolved");
  assert.equal(codes(pinResult).has("AP2_CONSTRAINT_FAILED"), true);
});

test("AP2 Evidence Pack runs pack, independent verify, and metadata-only render", () => {
  const fixture = makeFixture();
  const pack = packAp2DisputeEvidence(makePackInput(fixture));
  const verificationOptions = { expectedPackDigest: pack.packDigest };
  const verification = verifyAp2DisputeEvidencePack(pack, verificationOptions);
  const timeline = createAp2EvidenceTimeline(pack, verificationOptions);
  const reversedPack = packAp2DisputeEvidence({
    ...makePackInput(fixture),
    sources: [...fixture.sources].reverse(),
  });
  const reversedVerification = verifyAp2DisputeEvidencePack(reversedPack, {
    expectedPackDigest: reversedPack.packDigest,
  });

  assert.equal(pack.schemaId, "MandateBoundAp2EvidencePack/v1");
  assert.equal(verification.status, "verified", JSON.stringify(verification.issues));
  assert.equal(verification.digestValid, true);
  assert.equal(verification.checkoutVersionBinding, "matched");
  assert.equal(verification.revocationCoverage, "provided");
  assert.equal(verification.reportedRevocationState, "not_revoked");
  assert.equal(timeline.length, 6);
  assert.deepEqual(
    timeline.map((event) => `${event.occurredAt}:${event.eventType}:${event.label}`),
    [...timeline]
      .sort((left, right) => left.occurredAt.localeCompare(right.occurredAt)
        || left.eventType.localeCompare(right.eventType)
        || left.label.localeCompare(right.label))
      .map((event) => `${event.occurredAt}:${event.eventType}:${event.label}`),
  );
  assert.equal(reversedVerification.status, "verified", JSON.stringify(reversedVerification.issues));

  const html = renderAp2EvidenceTimelineHtml(pack, verificationOptions);
  assert.match(html, /AP2 Evidence Timeline/);
  assert.match(html, /not authenticated facts/);
  assert.equal(html.includes(fixture.checkoutJwt), false);
  assert.equal(html.includes(fixture.checkoutMandate), false);
  assert.equal(html.includes(pack.revocations[0].snapshotBase64), false);
});

test("Pack verification and rendering require an out-of-band Pack digest", () => {
  const trustedFixture = makeFixture();
  const trustedPack = packAp2DisputeEvidence(makePackInput(trustedFixture));
  const missingAnchor = verifyAp2DisputeEvidencePack(trustedPack);
  assert.equal(missingAnchor.status, "unresolved");
  assert.equal(missingAnchor.expectedPackDigest, null);
  assert.equal(missingAnchor.anchorMatched, false);
  assert.equal(codes(missingAnchor).has("AP2_PACK_TRUST_ANCHOR_MISSING"), true);

  const replacementFixture = makeFixture();
  const replacementPack = packAp2DisputeEvidence(makePackInput(replacementFixture));
  const replacementReport = verifyAp2DisputeEvidencePack(replacementPack, {
    expectedPackDigest: trustedPack.packDigest,
  });
  assert.equal(replacementReport.digestValid, true);
  assert.equal(replacementReport.anchorMatched, false);
  assert.equal(replacementReport.status, "unresolved");
  assert.equal(codes(replacementReport).has("AP2_PACK_TRUST_ANCHOR_MISMATCH"), true);

  const foreignReport = verifyAp2DisputeEvidencePack(replacementPack, {
    expectedPackDigest: replacementPack.packDigest,
  });
  const timeline = createAp2EvidenceTimeline(trustedPack, foreignReport);
  assert.equal(timeline.at(-1).state, "unresolved");
  const html = renderAp2EvidenceTimelineHtml(trustedPack, foreignReport);
  assert.match(html, /<strong class="unresolved">unresolved<\/strong>/u);
  assert.doesNotMatch(html, /<strong class="verified">verified<\/strong>/u);
});

test("AP2 Evidence Pack rejects private JWK material before serialization", () => {
  const fixture = makeFixture();
  const privateCoordinateInput = JSON.parse(JSON.stringify(makePackInput(fixture)));
  privateCoordinateInput.verificationPlan.checkoutMandate.issuerKeySnapshot.jwk.d =
    "synthetic-private-coordinate";
  assert.throws(
    () => packAp2DisputeEvidence(privateCoordinateInput),
    /verification plan shape is invalid/u,
  );

  const symmetricKeyInput = JSON.parse(JSON.stringify(makePackInput(fixture)));
  symmetricKeyInput.verificationPlan.checkoutJwt.merchantKeySnapshot.jwk.k =
    "synthetic-symmetric-key";
  assert.throws(
    () => packAp2DisputeEvidence(symmetricKeyInput),
    /verification plan shape is invalid/u,
  );

  const privateAgentInput = JSON.parse(JSON.stringify(makePackInput(fixture)));
  privateAgentInput.verificationPlan.checkoutMandate.expectedAgentJwk.d =
    "synthetic-private-coordinate";
  assert.throws(
    () => packAp2DisputeEvidence(privateAgentInput),
    /verification plan shape is invalid/u,
  );

  const openMerchantInput = JSON.parse(JSON.stringify(makePackInput(fixture)));
  openMerchantInput.verificationPlan.checkoutMandate.expectedMerchant = {
    id: "merchant-1",
    secret: "synthetic-unrelated-value",
  };
  assert.throws(
    () => packAp2DisputeEvidence(openMerchantInput),
    /verification plan shape is invalid/u,
  );

  const invalidSnapshotTimeInput = JSON.parse(JSON.stringify(makePackInput(fixture)));
  invalidSnapshotTimeInput.verificationPlan.checkoutReceipt.issuerKeySnapshot.capturedAt =
    "not-a-date";
  assert.throws(
    () => packAp2DisputeEvidence(invalidSnapshotTimeInput),
    /verification plan shape is invalid/u,
  );
});

test("AP2 Evidence Pack and verification validate against strict published schemas", () => {
  const fixture = makeFixture();
  const pack = packAp2DisputeEvidence(makePackInput(fixture));
  const verification = verifyAp2DisputeEvidencePack(pack, {
    expectedPackDigest: pack.packDigest,
  });
  const readSchema = (name) => JSON.parse(readFileSync(
    new URL(`../schemas/v1.2/${name}`, import.meta.url),
    "utf8",
  ));
  const packSchema = readSchema("ap2-evidence-pack.schema.json");
  const verificationSchema = readSchema("ap2-evidence-pack-verification.schema.json");
  const resolutionSchema = readSchema("ap2-dispute-evidence-resolution.schema.json");
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  ajv.addSchema(resolutionSchema);
  const validatePack = ajv.compile(packSchema);
  const validateVerification = ajv.compile(verificationSchema);
  assert.equal(validatePack(pack), true, JSON.stringify(validatePack.errors));
  assert.equal(
    validateVerification(verification),
    true,
    JSON.stringify(validateVerification.errors),
  );
  assert.equal(validateVerification({
    ...verification,
    status: "verified",
    packDigest: null,
    digestValid: false,
    checkoutVersionBinding: "missing",
    revocationCoverage: "missing",
    reportedRevocationState: "revoked",
    resolution: null,
    issues: [{
      code: "SYNTHETIC_CONTRADICTION",
      path: "verification",
      message: "Synthetic contradictory positive report",
      impact: "invalid",
      sourceRefs: [],
    }],
  }), false);
  assert.equal(validateVerification({
    ...verification,
    status: "verified",
    expectedPackDigest: null,
    anchorMatched: false,
  }), false);
  const unresolvedResolution = assembleAp2DisputeEvidence({
    ...fixture.input,
    sources: [],
  });
  assert.equal(unresolvedResolution.status, "unresolved");
  assert.equal(validateVerification({
    ...verification,
    status: "verified",
    resolution: unresolvedResolution,
  }), false);
  assert.equal(validatePack({ ...pack, legalEffect: "binding" }), false);
  const packWithPrivateJwk = JSON.parse(JSON.stringify(pack));
  packWithPrivateJwk.verificationPlan.checkoutMandate.issuerKeySnapshot.jwk.d =
    "synthetic-private-coordinate";
  assert.equal(validatePack(packWithPrivateJwk), false);
  const packWithOpenMerchant = JSON.parse(JSON.stringify(pack));
  packWithOpenMerchant.verificationPlan.checkoutMandate.expectedMerchant = {
    id: "merchant-1",
    secret: "synthetic-unrelated-value",
  };
  assert.equal(validatePack(packWithOpenMerchant), false);
  const packWithInvalidSnapshotTime = JSON.parse(JSON.stringify(pack));
  packWithInvalidSnapshotTime.verificationPlan.paymentReceipt.issuerKeySnapshot.validUntil =
    "not-a-date";
  assert.equal(validatePack(packWithInvalidSnapshotTime), false);
});

test("forged pack digests and reported revoked or unknown states fail closed", () => {
  const fixture = makeFixture();
  const pack = packAp2DisputeEvidence(makePackInput(fixture));
  const forged = JSON.parse(JSON.stringify(pack));
  forged.checkoutVersions[0].checkoutJwtDigest = `sha256:${"0".repeat(64)}`;
  const forgedReport = verifyAp2DisputeEvidencePack(forged, {
    expectedPackDigest: pack.packDigest,
  });
  assert.equal(forgedReport.status, "unresolved");
  assert.equal(forgedReport.digestValid, false);
  assert.equal(codes(forgedReport).has("AP2_CHECKOUT_VERSION_DIGEST_MISMATCH"), true);
  assert.equal(codes(forgedReport).has("AP2_PACK_DIGEST_MISMATCH"), true);

  for (const state of ["revoked", "unknown"]) {
    const statePack = packAp2DisputeEvidence(makePackInput(fixture, state));
    const stateReport = verifyAp2DisputeEvidencePack(statePack, {
      expectedPackDigest: statePack.packDigest,
    });
    assert.equal(stateReport.status, "unresolved");
    assert.equal(stateReport.reportedRevocationState, state);
    assert.equal(
      codes(stateReport).has(state === "revoked"
        ? "AP2_REPORTED_REVOCATION_REVOKED"
        : "AP2_REPORTED_REVOCATION_UNKNOWN"),
      true,
    );
  }
});

test("Pack digest verification is independent of evidence array order", () => {
  const fixture = makeFixture();
  const input = makePackInput(fixture);
  input.checkoutVersions.push({
    versionId: "checkout-version-2",
    sourceId: "merchant-primary",
    observedAt: "2026-07-22T23:58:40.000Z",
    checkoutJwt: fixture.checkoutJwt,
  });
  const pack = JSON.parse(JSON.stringify(packAp2DisputeEvidence(input)));
  pack.checkoutVersions.reverse();
  pack.revocations.reverse();
  const material = { ...pack };
  delete material.packDigest;
  pack.packDigest = sha256Digest(material);

  const verification = verifyAp2DisputeEvidencePack(pack, {
    expectedPackDigest: pack.packDigest,
  });
  assert.equal(verification.digestValid, true);
  assert.equal(verification.status, "verified", JSON.stringify(verification.issues));
});

test("strict AP2 profile accepts a directly signed Human Present closed Mandate", () => {
  const fixture = makeFixture();
  const claims = {
    iss: "https://trusted-surface.example",
    vct: "mandate.checkout.1",
    iat: 1_770_000_000,
    exp: 1_800_000_000,
    checkout_jwt: fixture.checkoutJwt,
    checkout_hash: fixture.transactionId,
  };
  const direct = `${createJwt({
    _sd_alg: "sha-256",
    delegate_payload: [claims],
  }, fixture.issuer, "dc+sd-jwt")}~`;
  const report = verifyAp2MandateChain({
    ...fixture.verificationPlan.checkoutMandate,
    token: direct,
    expectedVct: "mandate.checkout.1",
    expectedCheckoutHash: fixture.transactionId,
    requireKeyBinding: false,
    asOf,
  });
  assert.equal(report.evidenceEligible, true, JSON.stringify(report.issues));
  assert.equal(report.value.presentationMode, "human_present");
  assert.equal(report.value.chainDepth, 1);
  assert.equal(computeAp2MandateReference(direct), createHash("sha256")
    .update(direct.split("~", 1)[0], "ascii")
    .digest("base64url"));
});

test("strict AP2 profile accepts frozen vectors generated by the official v0.2.0 SDK", () => {
  const vector = JSON.parse(readFileSync(
    new URL("./fixtures/ap2-v020-official-sdk-golden.json", import.meta.url),
    "utf8",
  ));
  assert.equal(vector.generator.commit, AP2_DISPUTE_EVIDENCE_PROFILE.ap2ReleaseCommit);
  assert.equal(vector.generator.release, "v0.2.0");
  const pinnedSnapshot = {
    kid: vector.issuerJwk.kid,
    jwk: vector.issuerJwk,
    sourceDigest,
    capturedAt: "2026-07-22T00:00:00.000Z",
    validUntil: "2027-07-22T00:00:00.000Z",
  };
  const shared = {
    issuerKeySnapshot: pinnedSnapshot,
    expectedIssuerKeySourceDigest: sourceDigest,
    expectedIssuer: "https://trusted-surface.example",
    expectedAgentJwk: vector.agentJwk,
    requireKeyBinding: true,
    allowedAlgorithms: ["ES256"],
    asOf: vector.asOf,
  };
  const checkout = verifyAp2MandateChain({
    ...shared,
    token: vector.checkoutMandate,
    expectedVct: "mandate.checkout.1",
    expectedAudience: vector.checkoutAudience,
    expectedNonce: vector.checkoutNonce,
    expectedCheckoutHash: vector.transactionId,
  });
  const payment = verifyAp2MandateChain({
    ...shared,
    token: vector.paymentMandate,
    expectedVct: "mandate.payment.1",
    expectedAudience: vector.paymentAudience,
    expectedNonce: vector.paymentNonce,
    expectedCheckoutHash: vector.transactionId,
    expectedOpenCheckoutHash: vector.openCheckoutHash,
  });
  assert.equal(checkout.evidenceEligible, true, JSON.stringify(checkout.issues));
  assert.equal(payment.evidenceEligible, true, JSON.stringify(payment.issues));
  assert.equal(computeAp2OpenMandateHash(vector.checkoutMandate), vector.openCheckoutHash);
});

test("AP2 dispute resolution validates against the published v1.2 schema", () => {
  const fixture = makeFixture();
  const resolution = assembleAp2DisputeEvidence(fixture.input);
  const schema = JSON.parse(readFileSync(
    new URL("../schemas/v1.2/ap2-dispute-evidence-resolution.schema.json", import.meta.url),
    "utf8",
  ));
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  assert.equal(validate(resolution), true, JSON.stringify(validate.errors));
  assert.equal(validate({ ...resolution, legalEffect: "binding" }), false);
});

test("byte-identical evidence from eligible duplicate sources is deduplicated", () => {
  const fixture = makeFixture();
  const duplicate = {
    sourceId: "shopping-agent-copy",
    role: "shopping_agent",
    retrievedAt: "2026-07-22T23:58:00.000Z",
    artifacts: [
      { kind: "checkout_mandate", token: fixture.checkoutMandate },
      { kind: "checkout_receipt", token: fixture.checkoutReceipt },
      { kind: "payment_mandate", token: fixture.paymentMandate },
      { kind: "payment_receipt", token: fixture.paymentReceipt },
    ],
  };
  const result = assembleAp2DisputeEvidence({
    ...fixture.input,
    sources: [...fixture.sources, duplicate],
  });
  assert.equal(result.status, "evidence_verified", JSON.stringify(result.issues));
  assert.equal(
    result.selectedArtifacts.every((artifact) => artifact.sourceRefs.includes("shopping-agent-copy")),
    true,
  );
});

test("conflicting exact bytes fail closed before last-response selection", () => {
  const fixture = makeFixture();
  const conflicting = createMandate({
    iss: "https://trusted-surface.example",
    vct: "mandate.checkout.1",
    checkout_jwt: fixture.checkoutJwt,
    checkout_hash: fixture.transactionId,
  }, fixture.issuer, fixture.agent, "https://merchant.example", "checkout-nonce");
  const result = assembleAp2DisputeEvidence({
    ...fixture.input,
    sources: [...fixture.sources, {
      sourceId: "shopping-agent-conflict",
      role: "shopping_agent",
      retrievedAt: "2026-07-22T23:58:00.000Z",
      artifacts: [{ kind: "checkout_mandate", token: conflicting }],
    }],
  });
  assert.equal(result.status, "unresolved");
  assert.equal(codes(result).has("AP2_DISPUTE_ARTIFACT_CONFLICT"), true);
  assert.equal(codes(result).has("AP2_RECEIPT_REFERENCE_UNANCHORED"), true);
});

test("missing evidence, ineligible source roles, and future retrieval times stay unresolved", () => {
  const fixture = makeFixture();
  const missing = assembleAp2DisputeEvidence({
    ...fixture.input,
    sources: [fixture.sources[0]],
  });
  assert.equal(missing.status, "unresolved");
  assert.equal(codes(missing).has("AP2_DISPUTE_ARTIFACT_MISSING"), true);

  const invalidSource = assembleAp2DisputeEvidence({
    ...fixture.input,
    sources: [{
      sourceId: "credential-provider-invalid",
      role: "credential_provider",
      retrievedAt: "2026-07-24T00:00:00.000Z",
      artifacts: [{ kind: "checkout_mandate", token: fixture.checkoutMandate }],
    }, fixture.sources[1]],
  });
  assert.equal(invalidSource.status, "unresolved");
  assert.equal(codes(invalidSource).has("AP2_DISPUTE_SOURCE_ROLE_INVALID"), true);
  assert.equal(codes(invalidSource).has("AP2_DISPUTE_RETRIEVAL_TIME_INVALID"), true);
});

test("wrong transaction binding, stale caller pins, and receipt mismatch fail closed", () => {
  const fixture = makeFixture();
  const wrongTransaction = Buffer.alloc(32, 7).toString("base64url");
  const wrong = assembleAp2DisputeEvidence({ ...fixture.input, transactionId: wrongTransaction });
  assert.equal(wrong.status, "unresolved");
  assert.equal(codes(wrong).has("AP2_EXPECTED_CHECKOUT_HASH_MISMATCH"), true);
  assert.equal(codes(wrong).has("AP2_PAYMENT_CHECKOUT_BINDING_MISMATCH"), true);

  const stale = assembleAp2DisputeEvidence({
    ...fixture.input,
    verificationPlan: {
      ...fixture.verificationPlan,
      checkoutMandate: {
        ...fixture.verificationPlan.checkoutMandate,
        issuerKeySnapshot: snapshot(fixture.issuer, {
          validUntil: "2026-05-01T00:00:00.000Z",
        }),
      },
    },
  });
  assert.equal(stale.status, "unresolved");
  assert.equal(codes(stale).has("INTEROP_KEY_SNAPSHOT_STALE"), true);

  const badReceipt = createJwt({
    status: "Success",
    iss: "https://merchant.example",
    iat: 1_770_000_100,
    reference: Buffer.alloc(32, 9).toString("base64url"),
    order_id: "order-synthetic-1",
  }, fixture.merchant);
  const mismatched = assembleAp2DisputeEvidence({
    ...fixture.input,
    sources: [{
      ...fixture.sources[0],
      artifacts: [
        { kind: "checkout_mandate", token: fixture.checkoutMandate },
        { kind: "checkout_receipt", token: badReceipt },
      ],
    }, fixture.sources[1]],
  });
  assert.equal(mismatched.status, "unresolved");
  assert.equal(codes(mismatched).has("AP2_RECEIPT_REFERENCE_MISMATCH"), true);
});

test("receipt verification enforces signatures and the pinned AP2 receipt schema", () => {
  const fixture = makeFixture();
  const plan = fixture.verificationPlan.checkoutReceipt;
  const valid = verifyAp2Receipt({
    ...plan,
    token: fixture.checkoutReceipt,
    kind: "checkout_receipt",
    asOf,
    expectedMandateToken: fixture.checkoutMandate,
  });
  assert.equal(valid.evidenceEligible, true, JSON.stringify(valid.issues));

  const mutated = verifyAp2Receipt({
    ...plan,
    token: mutateSignature(fixture.checkoutReceipt),
    kind: "checkout_receipt",
    asOf,
    expectedMandateToken: fixture.checkoutMandate,
  });
  assert.equal(mutated.upstreamValid, false);
  assert.equal(mutated.issues.some((issue) => issue.code === "AP2_RECEIPT_SIGNATURE_INVALID"), true);

  const malformed = createJwt({
    status: "Error",
    iss: "https://merchant.example",
    iat: 1_770_000_100,
    reference: computeAp2MandateReference(fixture.checkoutMandate),
    error: "declined",
  }, fixture.merchant);
  const malformedReport = verifyAp2Receipt({
    ...plan,
    token: malformed,
    kind: "checkout_receipt",
    asOf,
    expectedMandateToken: fixture.checkoutMandate,
  });
  assert.equal(malformedReport.upstreamValid, false);
  assert.equal(malformedReport.issues.some((issue) => issue.code === "AP2_RECEIPT_CLAIMS_INVALID"), true);
});

test("embedded Checkout JWT verification binds the merchant signature and historical key pin", () => {
  const fixture = makeFixture();
  const plan = fixture.verificationPlan.checkoutJwt;
  const valid = verifyAp2CheckoutJwt({ ...plan, token: fixture.checkoutJwt, asOf });
  assert.equal(valid.evidenceEligible, true, JSON.stringify(valid.issues));
  const mutated = verifyAp2CheckoutJwt({
    ...plan,
    token: mutateSignature(fixture.checkoutJwt),
    asOf,
  });
  assert.equal(mutated.upstreamValid, false);
  assert.equal(
    mutated.issues.some((issue) => issue.code === "AP2_CHECKOUT_JWT_SIGNATURE_INVALID"),
    true,
  );
  const schemaInvalidToken = createJwt({ id: "checkout-with-missing-fields" }, fixture.checkoutSigner);
  const schemaInvalid = verifyAp2CheckoutJwt({ ...plan, token: schemaInvalidToken, asOf });
  assert.equal(schemaInvalid.upstreamValid, false);
  assert.equal(
    schemaInvalid.issues.some((issue) => issue.code === "AP2_CHECKOUT_SCHEMA_INVALID"),
    true,
  );
});

test("authentic Error receipts remain valid evidence without deciding a claim", () => {
  const fixture = makeFixture();
  const checkoutError = createJwt({
    status: "Error",
    iss: "https://merchant.example",
    iat: 1_770_000_100,
    reference: computeAp2MandateReference(fixture.checkoutMandate),
    error: "checkout_rejected",
    error_description: "Synthetic rejection",
  }, fixture.merchant);
  const paymentError = createJwt({
    status: "Error",
    iss: "https://processor.example",
    iat: 1_770_000_200,
    reference: computeAp2MandateReference(fixture.paymentMandate),
    payment_id: "payment-synthetic-1",
    error: "payment_rejected",
    error_description: "Synthetic rejection",
  }, fixture.processor);
  const result = assembleAp2DisputeEvidence({
    ...fixture.input,
    sources: [{
      ...fixture.sources[0],
      artifacts: [
        { kind: "checkout_mandate", token: fixture.checkoutMandate },
        { kind: "checkout_receipt", token: checkoutError },
      ],
    }, {
      ...fixture.sources[1],
      artifacts: [
        { kind: "payment_mandate", token: fixture.paymentMandate },
        { kind: "payment_receipt", token: paymentError },
      ],
    }],
  });
  assert.equal(result.status, "evidence_verified", JSON.stringify(result.issues));
  assert.equal(
    result.selectedArtifacts.filter((entry) => entry.receiptStatus === "Error").length,
    2,
  );
  assert.equal(result.disputeOutcome, "not-determined");
});

test("caller-supplied retrieval is deterministic and provider failures do not leak details", async () => {
  const fixture = makeFixture();
  const providers = fixture.sources.map((source) => ({
    id: source.sourceId,
    role: source.role,
    async retrieve(request) {
      assert.equal(request.profileId, AP2_DISPUTE_EVIDENCE_PROFILE.id);
      assert.equal(request.transactionId, fixture.transactionId);
      return { retrievedAt: source.retrievedAt, artifacts: source.artifacts };
    },
  }));
  const resolved = await resolveAp2DisputeEvidence({
    transactionId: fixture.transactionId,
    asOf,
    verificationPlan: fixture.verificationPlan,
    retrievers: [...providers].reverse(),
  });
  assert.equal(resolved.status, "evidence_verified", JSON.stringify(resolved.issues));

  const failed = await resolveAp2DisputeEvidence({
    transactionId: fixture.transactionId,
    asOf,
    verificationPlan: fixture.verificationPlan,
    retrievers: [...providers, {
      id: "network-failed",
      role: "network",
      async retrieve() {
        throw new Error(`secret-provider-detail:${fixture.checkoutJwt}`);
      },
    }],
  });
  assert.equal(failed.status, "unresolved");
  assert.equal(codes(failed).has("AP2_DISPUTE_RETRIEVAL_FAILED"), true);
  assert.equal(JSON.stringify(failed).includes("secret-provider-detail"), false);
  assert.equal(JSON.stringify(failed).includes(fixture.checkoutJwt), false);

  const malformed = await resolveAp2DisputeEvidence({
    transactionId: fixture.transactionId,
    asOf,
    verificationPlan: fixture.verificationPlan,
    retrievers: [...providers, {
      id: "network-malformed",
      role: "network",
      async retrieve() {
        return { retrievedAt: asOf, artifacts: [null] };
      },
    }],
  });
  assert.equal(malformed.status, "unresolved");
  assert.equal(codes(malformed).has("AP2_DISPUTE_RETRIEVAL_FAILED"), true);
});

test("invalid identifiers, duplicated retrievers, and oversized inputs are rejected", async () => {
  const fixture = makeFixture();
  assert.throws(() => assembleAp2DisputeEvidence({
    ...fixture.input,
    transactionId: "not-a-digest",
  }), TypeError);
  assert.throws(() => assembleAp2DisputeEvidence({
    ...fixture.input,
    sources: [...fixture.sources, { ...fixture.sources[0] }],
  }), TypeError);
  await assert.rejects(() => resolveAp2DisputeEvidence({
    transactionId: fixture.transactionId,
    asOf,
    verificationPlan: fixture.verificationPlan,
    retrievers: [{ id: "same", role: "merchant", async retrieve() { return null; } }, {
      id: "same",
      role: "merchant",
      async retrieve() { return null; },
    }],
  }), TypeError);

  assert.throws(() => assembleAp2DisputeEvidence({
    ...fixture.input,
    asOf: "2026-02-31T00:00:00Z",
  }), TypeError);
  assert.throws(() => assembleAp2DisputeEvidence({
    ...fixture.input,
    sources: [{
      sourceId: "oversized",
      role: "merchant",
      retrievedAt: "2026-07-22T23:59:00.000Z",
      artifacts: [{ kind: "checkout_mandate", token: "x".repeat(1_048_577) }],
    }],
  }), TypeError);
});

test("required autonomous constraints, nested Payment fields, and caller trust IDs fail closed", () => {
  const fixture = makeFixture();
  const unconstrained = createMandate({
    iss: "https://trusted-surface.example",
    vct: "mandate.checkout.1",
    checkout_jwt: fixture.checkoutJwt,
    checkout_hash: fixture.transactionId,
  }, fixture.issuer, fixture.agent, "https://merchant.example", "checkout-nonce", []);
  const unconstrainedReport = verifyAp2MandateChain({
    ...fixture.verificationPlan.checkoutMandate,
    token: unconstrained,
    expectedVct: "mandate.checkout.1",
    expectedCheckoutHash: fixture.transactionId,
    asOf,
  });
  assert.equal(unconstrainedReport.upstreamValid, false);
  assert.equal(
    unconstrainedReport.issues.some((issue) => issue.code === "AP2_REQUIRED_CONSTRAINT_MISSING"),
    true,
  );

  const malformedPayment = createMandate({
    iss: "https://trusted-surface.example",
    vct: "mandate.payment.1",
    transaction_id: fixture.transactionId,
    payee: { id: "merchant-1" },
    payment_amount: { amount: 2_500, currency: "USD" },
    payment_instrument: { id: "instrument-1", type: "card" },
  }, fixture.issuer, fixture.agent, "https://processor.example", "payment-nonce", [{
    type: "payment.reference",
    conditional_transaction_id: fixture.openCheckoutHash,
  }]);
  const malformedPaymentReport = verifyAp2MandateChain({
    ...fixture.verificationPlan.paymentMandate,
    token: malformedPayment,
    expectedVct: "mandate.payment.1",
    expectedCheckoutHash: fixture.transactionId,
    expectedOpenCheckoutHash: fixture.openCheckoutHash,
    asOf,
  });
  assert.equal(malformedPaymentReport.upstreamValid, false);
  assert.equal(
    malformedPaymentReport.issues.some((issue) => issue.code === "AP2_PAYMENT_MANDATE_SCHEMA_INVALID"),
    true,
  );

  const emptyIssuer = verifyAp2MandateChain({
    ...fixture.verificationPlan.checkoutMandate,
    expectedIssuer: "",
    token: fixture.checkoutMandate,
    expectedVct: "mandate.checkout.1",
    expectedCheckoutHash: fixture.transactionId,
    asOf,
  });
  assert.equal(emptyIssuer.upstreamValid, false);
  assert.equal(emptyIssuer.value, null);
});

test("future-captured historical key pins are ineligible", () => {
  const fixture = makeFixture();
  const result = assembleAp2DisputeEvidence({
    ...fixture.input,
    verificationPlan: {
      ...fixture.verificationPlan,
      checkoutMandate: {
        ...fixture.verificationPlan.checkoutMandate,
        issuerKeySnapshot: snapshot(fixture.issuer, {
          capturedAt: "2026-07-24T00:00:00.000Z",
        }),
      },
    },
  });
  assert.equal(result.status, "unresolved");
  assert.equal(codes(result).has("INTEROP_KEY_SNAPSHOT_FROM_FUTURE"), true);
});
