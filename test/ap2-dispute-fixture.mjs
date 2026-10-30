import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { sha256Bytes } from "../dist/canonical.js";
import { computeAp2MandateReference, computeAp2OpenMandateHash } from "../dist/ucp-ap2.js";

/**
 * Synthetic AP2 v0.2.0 dispute evidence for the constraint, reconciliation,
 * export and batch tests. It builds the same four-artifact transaction as the
 * helpers in ap2-dispute-v12.test.mjs, and adds the knobs those tests need:
 * replaceable open constraints, selectively disclosable array elements that
 * the presenting agent may reveal or withhold, and closed Payment Mandate and
 * Checkout JWT overrides. Every key is generated per fixture and only public
 * JWKs leave it.
 */

export const asOf = "2026-07-23T00:00:00.000Z";
export const sourceDigest = sha256Bytes(Buffer.from("synthetic-ap2-dispute-key-source", "utf8"));

export function ecPair(kid) {
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

export function snapshot(pair, overrides = {}) {
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

export function createJwt(claims, pair, typ = "JWT") {
  const protectedSegment = encodeJson({ alg: "ES256", kid: pair.publicJwk.kid, typ });
  const payloadSegment = encodeJson(claims);
  const signingInput = `${protectedSegment}.${payloadSegment}`;
  const signature = sign("sha256", Buffer.from(signingInput, "ascii"), {
    key: pair.privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${signingInput}.${signature.toString("base64url")}`;
}

let saltCounter = 0;

/**
 * One selectively disclosable array element. `placeholder` is what the issuer
 * signs in place of the value; `encoded` is the disclosure the presenting
 * agent appends to reveal it, or leaves out to withhold it.
 */
export function arrayElement(value) {
  saltCounter += 1;
  const encoded = encodeJson([`synthetic-salt-${String(saltCounter)}`, value]);
  const digest = createHash("sha256").update(encoded, "ascii").digest("base64url");
  return { value, encoded, placeholder: { "...": digest } };
}

/**
 * A two-hop Delegate SD-JWT chain: the issuer signs the open Mandate, and the
 * agent's terminal hop binds the exact root presentation, including whichever
 * disclosures the agent chose to present.
 *
 * `wrapRootPayload` places the open Mandate itself behind a delegate_payload
 * placeholder and presents its disclosure first, the shape the official SDK
 * emits. `rootPayloadAlternatives` appends further delegate_payload elements,
 * typically placeholders for alternative payloads the agent does not present.
 */
export function createMandate(claims, issuer, agent, audience, nonce, constraints, {
  rootDisclosures = [],
  wrapRootPayload = false,
  rootPayloadAlternatives = [],
} = {}) {
  const openVct = claims.vct === "mandate.checkout.1"
    ? "mandate.checkout.open.1"
    : "mandate.payment.open.1";
  const openPayload = {
    vct: openVct,
    iat: 1_770_000_000,
    exp: 1_800_000_000,
    constraints,
    cnf: { jwk: agent.publicJwk },
  };
  const wrapped = wrapRootPayload ? arrayElement(openPayload) : null;
  const rootJwt = createJwt({
    _sd_alg: "sha-256",
    delegate_payload: [wrapped === null ? openPayload : wrapped.placeholder, ...rootPayloadAlternatives],
  }, issuer, "dc+sd-jwt");
  const presented = wrapped === null ? rootDisclosures : [wrapped.encoded, ...rootDisclosures];
  const rootPresentation = presented.length === 0
    ? `${rootJwt}~`
    : `${rootJwt}~${presented.join("~")}~`;
  const terminalJwt = createJwt({
    _sd_alg: "sha-256",
    aud: audience,
    nonce,
    iat: 1_770_000_000,
    sd_hash: createHash("sha256").update(rootPresentation, "ascii").digest("base64url"),
    delegate_payload: [claims],
  }, agent, "kb+sd-jwt");
  return `${rootPresentation}~${terminalJwt}~`;
}

export function defaultCheckoutConstraints({ allowedMerchantId = "merchant-1" } = {}) {
  return [{
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
  }];
}

/**
 * Build one transaction. `paymentConstraints` receives the payment.reference
 * constraint already bound to the open Checkout Mandate and returns the full
 * open Payment Mandate constraint list. `checkoutClaims` and `paymentClaims`
 * replace top-level claims of the signed Checkout JWT and the closed Payment
 * Mandate; a value of `undefined` removes the claim.
 */
export function makeFixture({
  checkoutMerchantId = "merchant-1",
  allowedMerchantId = "merchant-1",
  expectedMerchantId,
  checkoutConstraints = defaultCheckoutConstraints({ allowedMerchantId }),
  checkoutRootDisclosures = [],
  checkoutRootOptions = {},
  paymentConstraints = (reference) => [reference],
  paymentRootDisclosures = [],
  checkoutClaims = {},
  paymentClaims = {},
} = {}) {
  const issuer = ecPair("trusted-surface-key");
  const agent = ecPair("shopping-agent-key");
  const merchant = ecPair("merchant-receipt-key");
  const processor = ecPair("processor-receipt-key");
  const checkoutSigner = ecPair("checkout-key");
  const checkoutJwt = createJwt(withoutUndefined({
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
    ...checkoutClaims,
  }), checkoutSigner);
  const transactionId = createHash("sha256").update(checkoutJwt, "utf8").digest("base64url");
  const checkoutMandate = createMandate({
    iss: "https://trusted-surface.example",
    vct: "mandate.checkout.1",
    iat: 1_770_000_000,
    exp: 1_800_000_000,
    checkout_jwt: checkoutJwt,
    checkout_hash: transactionId,
  }, issuer, agent, "https://merchant.example", "checkout-nonce", checkoutConstraints, {
    ...checkoutRootOptions,
    rootDisclosures: checkoutRootDisclosures,
  });
  const openCheckoutHash = computeAp2OpenMandateHash(checkoutMandate);
  const paymentMandate = createMandate(withoutUndefined({
    iss: "https://trusted-surface.example",
    vct: "mandate.payment.1",
    iat: 1_770_000_000,
    exp: 1_800_000_000,
    transaction_id: transactionId,
    payee: { id: checkoutMerchantId, name: "Synthetic Store" },
    payment_amount: { currency: "USD", amount: 2_500 },
    payment_instrument: { id: "instrument-1", type: "card" },
    ...paymentClaims,
  }), issuer, agent, "https://processor.example", "payment-nonce", paymentConstraints({
    type: "payment.reference",
    conditional_transaction_id: openCheckoutHash,
  }), {
    rootDisclosures: paymentRootDisclosures,
  });
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

export function makePackInput(fixture, revocationStatus = "not_revoked") {
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

export function codes(result) {
  return new Set(result.issues.map((issue) => issue.code));
}

function withoutUndefined(value) {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined));
}
