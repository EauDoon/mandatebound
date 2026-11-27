import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";

// Synthetic Verifiable Intent v0.1 chains for negative and constraint tests.
// The byte layout follows the reference SDK at the pinned commit: compact JSON
// segments, ES256 raw r||s signatures, array-element disclosures, and
// `<jwt>~<disclosure>~...~` presentations. The golden fixture proves interop
// with the SDK itself; this builder covers the cases the SDK will not emit.

const b64u = (value) => Buffer.from(value).toString("base64url");
export const hashAscii = (value) => createHash("sha256").update(Buffer.from(value, "ascii")).digest("base64url");

export function makeKey(kid) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { kty, crv, x, y } = publicKey.export({ format: "jwk" });
  return { privateKey, jwk: { kty, crv, x, y }, kid };
}

export function signJwt(header, payload, key, encode = (value) => JSON.stringify(value)) {
  const input = `${b64u(encode(header))}.${b64u(encode(payload))}`;
  const signature = sign("sha256", Buffer.from(input, "ascii"), { key: key.privateKey, dsaEncoding: "ieee-p1363" });
  return `${input}.${signature.toString("base64url")}`;
}

export function disclosure(value, name) {
  const salt = randomBytes(16).toString("base64url");
  const encoded = b64u(JSON.stringify(name === undefined ? [salt, value] : [salt, name, value]));
  return { encoded, digest: hashAscii(encoded), value };
}

export const present = (jwt, disclosures) => `${[jwt, ...disclosures.map((entry) => entry.encoded)].join("~")}~`;
const ref = (entry) => ({ "...": entry.digest });

export const MERCHANTS = Object.freeze([
  { id: "merchant-1", name: "Court Supply", website: "https://court-supply.example" },
  { id: "merchant-2", name: "Racket Hall", website: "https://racket-hall.example" },
]);
export const ITEMS = Object.freeze([
  { id: "SKU-1", title: "Racket A" },
  { id: "SKU-2", title: "Racket B" },
]);
export const INSTRUMENT = Object.freeze({ type: "mastercard.srcDigitalCard", id: "card-ref-1", description: "Card ending 1234" });
export const NOW = 1_800_000_000;
const SOURCE_DIGEST = `sha256:${"b".repeat(64)}`;

export function snapshot(key, overrides = {}) {
  return {
    kid: key.kid,
    jwk: { ...key.jwk, kid: key.kid },
    sourceDigest: SOURCE_DIGEST,
    capturedAt: "2026-01-01T00:00:00Z",
    validUntil: "2028-01-01T00:00:00Z",
    ...overrides,
  };
}

/**
 * Build one chain. `options.tweak` receives the mutable claim objects before
 * signing, so a test can change exactly one field and keep every signature
 * valid. The return value is ready for verifyVerifiableIntentChain.
 */
export function makeViChain(options = {}) {
  const mode = options.mode ?? "autonomous";
  const issuer = makeKey("issuer-key-1");
  const user = makeKey("user-key-1");
  const agent = makeKey("agent-key-1");
  const merchant = makeKey("merchant-key-1");
  const tweak = options.tweak ?? {};

  const l1Email = disclosure("holder@example.com", "email");
  const l1Claims = {
    iss: "https://issuer.example",
    sub: "holder-1",
    iat: NOW - 86_400,
    exp: NOW + 86_400 * 300,
    vct: "https://credentials.mastercard.com/card",
    cnf: { jwk: user.jwk },
    pan_last_four: "1234",
    scheme: "Mastercard",
    card_id: INSTRUMENT.id,
    _sd: [l1Email.digest],
    _sd_alg: "sha-256",
  };
  tweak.l1?.(l1Claims);
  const l1Jwt = signJwt({ alg: "ES256", typ: "sd+jwt", kid: issuer.kid }, l1Claims, issuer, options.l1Encode);
  const l1 = present(l1Jwt, [l1Email]);

  const checkoutClaims = {
    iss: "https://court-supply.example",
    sub: "cart_checkout",
    iat: NOW,
    exp: NOW + 3600,
    ...(options.checkoutMerchant === undefined ? {} : { merchant: options.checkoutMerchant }),
    cart: { items: [{ sku: "SKU-1", quantity: 1, unitPriceMinor: 27999 }], currency: "USD" },
  };
  tweak.checkoutJwt?.(checkoutClaims);
  const checkoutJwt = signJwt({ alg: "ES256", typ: "JWT", kid: merchant.kid }, checkoutClaims, merchant);
  const checkoutHash = hashAscii(checkoutJwt);

  const anchors = {
    l2Audience: "https://agent.example",
    l2Nonce: "l2-nonce",
    l3PaymentAudience: "https://network.example",
    l3PaymentNonce: "l3a-nonce",
    l3CheckoutAudience: "https://court-supply.example",
    l3CheckoutNonce: "l3b-nonce",
  };
  const keys = { issuer, user, agent, merchant };
  const base = {
    issuerKeySnapshot: snapshot(issuer),
    expectedIssuerKeySourceDigest: SOURCE_DIGEST,
    merchantKeySnapshot: snapshot(merchant),
    expectedMerchantKeySourceDigest: SOURCE_DIGEST,
    asOf: NOW + 30,
  };

  if (mode === "immediate") {
    const checkoutMandate = { vct: "mandate.checkout.1", checkout_jwt: checkoutJwt, checkout_hash: checkoutHash };
    const paymentMandate = {
      vct: "mandate.payment.1",
      payment_instrument: INSTRUMENT,
      payee: MERCHANTS[0],
      payment_amount: { currency: "USD", amount: 27999 },
      transaction_id: checkoutHash,
    };
    tweak.checkoutMandate?.(checkoutMandate);
    tweak.paymentMandate?.(paymentMandate);
    const mandates = [disclosure(checkoutMandate), disclosure(paymentMandate)];
    const l2Claims = {
      nonce: anchors.l2Nonce,
      aud: anchors.l2Audience,
      iat: NOW,
      sd_hash: hashAscii(l1),
      delegate_payload: mandates.map(ref),
      _sd_alg: "sha-256",
      _sd: mandates.map((entry) => entry.digest),
      exp: NOW + 900,
    };
    tweak.l2?.(l2Claims);
    const l2 = present(signJwt({ alg: "ES256", typ: "kb-sd-jwt", kid: user.kid }, l2Claims, user), mandates);
    return {
      keys,
      checkoutHash,
      input: { ...base, l1, l2, expected: { l2Audience: anchors.l2Audience, l2Nonce: anchors.l2Nonce } },
    };
  }

  const merchantDisclosures = MERCHANTS.map((entry) => disclosure(entry));
  const itemDisclosures = ITEMS.map((entry) => disclosure(entry));
  const agentCnf = { jwk: { ...agent.jwk, kid: agent.kid } };
  const checkoutMandate = {
    vct: "mandate.checkout.open.1",
    cnf: agentCnf,
    constraints: [
      { type: "mandate.checkout.allowed_merchants", allowed: merchantDisclosures.map(ref) },
      {
        type: "mandate.checkout.line_items",
        items: [{ id: "line-1", acceptable_items: itemDisclosures.map(ref), quantity: 1 }],
        match_mode: "minimum",
      },
    ],
  };
  tweak.checkoutMandate?.(checkoutMandate, { merchantDisclosures, itemDisclosures });
  const checkoutDisclosure = disclosure(checkoutMandate);
  const paymentMandate = {
    vct: "mandate.payment.open.1",
    cnf: agentCnf,
    constraints: [
      { type: "mandate.payment.amount_range", currency: "USD", min: 10000, max: 40000 },
      { type: "mandate.payment.allowed_payees", allowed: merchantDisclosures.map(ref) },
      { type: "mandate.payment.reference", conditional_transaction_id: checkoutDisclosure.digest },
    ],
    payment_instrument: INSTRUMENT,
  };
  tweak.paymentMandate?.(paymentMandate, { merchantDisclosures, itemDisclosures, checkoutDisclosure });
  const paymentDisclosure = disclosure(paymentMandate);
  const l2Disclosures = [...merchantDisclosures, ...itemDisclosures, checkoutDisclosure, paymentDisclosure];
  const l2Claims = {
    nonce: anchors.l2Nonce,
    aud: anchors.l2Audience,
    iat: NOW - 3600,
    sd_hash: hashAscii(l1),
    delegate_payload: [ref(checkoutDisclosure), ref(paymentDisclosure)],
    _sd_alg: "sha-256",
    _sd: l2Disclosures.map((entry) => entry.digest),
    exp: NOW + 86_400,
  };
  tweak.l2?.(l2Claims, { checkoutDisclosure, paymentDisclosure });
  const l2Jwt = signJwt({ alg: "ES256", typ: "kb-sd-jwt+kb", kid: user.kid }, l2Claims, user);
  const l2Discloses = options.l2Discloses ?? l2Disclosures;
  const l2 = present(l2Jwt, l2Discloses);

  const payee = options.payee ?? MERCHANTS[0];
  const paymentPresentationDisclosures = options.paymentPresentation ?? [paymentDisclosure, merchantDisclosures[0]];
  const checkoutPresentationDisclosures = options.checkoutPresentation ?? [checkoutDisclosure, itemDisclosures[0]];
  const l2PaymentPresentation = present(l2Jwt, paymentPresentationDisclosures);
  const l2CheckoutPresentation = present(l2Jwt, checkoutPresentationDisclosures);

  const finalPayment = {
    vct: "mandate.payment.1",
    transaction_id: checkoutHash,
    payee,
    payment_amount: { currency: "USD", amount: options.amount ?? 27999 },
    payment_instrument: INSTRUMENT,
  };
  tweak.finalPayment?.(finalPayment);
  const l3aDisclosures = [disclosure(payee), disclosure(finalPayment)];
  const l3aClaims = {
    nonce: anchors.l3PaymentNonce,
    aud: anchors.l3PaymentAudience,
    sd_hash: hashAscii(l2PaymentPresentation),
    iat: NOW,
    delegate_payload: l3aDisclosures.map(ref),
    _sd_alg: "sha-256",
    iss: "https://agent.example",
    exp: NOW + 300,
  };
  tweak.l3a?.(l3aClaims);
  const l3aHeader = { alg: "ES256", typ: "kb-sd-jwt", kid: agent.kid };
  tweak.l3aHeader?.(l3aHeader);
  const l3Payment = present(signJwt(l3aHeader, l3aClaims, options.l3aSigner ?? agent), l3aDisclosures);

  const finalCheckout = {
    vct: "mandate.checkout.1",
    checkout_jwt: checkoutJwt,
    checkout_hash: checkoutHash,
    ...(options.l3LineItems === undefined ? {} : { line_items: options.l3LineItems }),
  };
  tweak.finalCheckout?.(finalCheckout);
  const l3bDisclosures = [disclosure(finalCheckout)];
  const l3bClaims = {
    nonce: anchors.l3CheckoutNonce,
    aud: anchors.l3CheckoutAudience,
    sd_hash: hashAscii(l2CheckoutPresentation),
    iat: NOW,
    delegate_payload: l3bDisclosures.map(ref),
    _sd_alg: "sha-256",
    iss: "https://agent.example",
    exp: NOW + 300,
  };
  tweak.l3b?.(l3bClaims);
  const l3Checkout = present(signJwt({ alg: "ES256", typ: "kb-sd-jwt", kid: agent.kid }, l3bClaims, agent), l3bDisclosures);

  return {
    keys,
    checkoutHash,
    input: {
      ...base,
      l1,
      l2,
      l2PaymentPresentation,
      l2CheckoutPresentation,
      l3Payment,
      l3Checkout,
      expected: anchors,
    },
  };
}
