import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { canonicalBytes, sha256Bytes } from "../dist/canonical.js";
import {
  AP2_MANDATE_VCTS,
  UCP_AP2_EVIDENCE_PROFILE,
  buildUcpRequestSignatureBase,
  correlateTransactionLifecycle,
  parseCompactAp2Token,
  parseContentDigest,
  parseUcpSignatureInput,
  verifyAp2Mandate,
  verifyDetachedMerchantAuthorization,
  verifyRawBodyContentDigest,
  verifyUcpProfileSnapshot,
  verifyUcpRequestEvidence,
} from "../dist/ucp-ap2.js";

const evaluationTime = "2026-07-23T00:00:00.000Z";
const sourceDigest = sha256Bytes(Buffer.from("synthetic-pinned-source", "utf8"));

function createEcPair(kid, namedCurve = "prime256v1", algorithm = "ES256") {
  const pair = generateKeyPairSync("ec", { namedCurve });
  const exported = pair.publicKey.export({ format: "jwk" });
  const publicJwk = {
    ...exported,
    kid,
    alg: algorithm,
    use: "sig",
    key_ops: ["verify"],
  };
  return { ...pair, publicJwk };
}

function keySnapshot(pair, overrides = {}) {
  return {
    kid: pair.publicJwk.kid,
    jwk: pair.publicJwk,
    sourceDigest,
    capturedAt: "2026-04-09T00:00:00.000Z",
    validUntil: "2027-04-09T00:00:00.000Z",
    ...overrides,
  };
}

function encodeJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function mutateBase64UrlBytes(value) {
  const bytes = Buffer.from(value, "base64url");
  assert.notEqual(bytes.length, 0);
  bytes[0] ^= 1;
  return bytes.toString("base64url");
}

function mutateCompactSignature(value) {
  const finalDot = value.lastIndexOf(".");
  assert.notEqual(finalDot, -1);
  const signature = value.slice(finalDot + 1);
  return `${value.slice(0, finalDot + 1)}${mutateBase64UrlBytes(signature)}`;
}

function joseSign(privateKey, algorithm, input, encoding = "ieee-p1363") {
  const hash = { ES256: "sha256", ES384: "sha384", ES512: "sha512" }[algorithm];
  return sign(hash, Buffer.from(input, "ascii"), {
    key: privateKey,
    dsaEncoding: encoding,
  });
}

function createJwt(claims, pair, header = { alg: "ES256", kid: pair.publicJwk.kid, typ: "JWT" }) {
  const protectedSegment = encodeJson(header);
  const payloadSegment = encodeJson(claims);
  const signingInput = `${protectedSegment}.${payloadSegment}`;
  const signature = joseSign(pair.privateKey, header.alg, signingInput);
  return `${signingInput}.${signature.toString("base64url")}`;
}

function createAp2Token(claims, issuerPair, agentPair, issuerHeader, tokenOptions = {}) {
  const issuerJwt = createJwt(
    claims,
    issuerPair,
    issuerHeader ?? { alg: "ES256", kid: issuerPair.publicJwk.kid, typ: "dc+sd-jwt" },
  );
  const disclosures = tokenOptions.disclosures ?? [];
  const presentation = `${[issuerJwt, ...disclosures].join("~")}~`;
  const kbClaims = {
    aud: "https://merchant.example",
    nonce: "nonce-ap2-123",
    iat: 1_770_000_000,
    exp: 1_800_000_000,
    sd_hash: createHash("sha256").update(presentation, "ascii").digest("base64url"),
    ...(tokenOptions.kbClaims ?? {}),
  };
  const keyBindingJwt = createJwt(
    kbClaims,
    agentPair,
    tokenOptions.kbHeader ?? { alg: "ES256", typ: "kb+jwt" },
  );
  return `${presentation}${keyBindingJwt}`;
}

function merchantAuthorization(checkout, pair, {
  alg = "ES256",
  encoding = "ieee-p1363",
  extraHeader,
} = {}) {
  const header = { alg, kid: pair.publicJwk.kid, ...extraHeader };
  const protectedSegment = encodeJson(header);
  const { ap2: _ap2, ...payload } = checkout;
  const signingInput = `${protectedSegment}.${Buffer.from(canonicalBytes(payload)).toString("base64url")}`;
  const signature = joseSign(pair.privateKey, alg, signingInput, encoding);
  return `${protectedSegment}..${signature.toString("base64url")}`;
}

function makeUcpProfile(version = UCP_AP2_EVIDENCE_PROFILE.ucpVersion) {
  return {
    ucp: {
      version,
      services: {
        "dev.ucp.shopping": [{
          version,
          transport: "rest",
          spec: `https://ucp.dev/${version}/specification/overview`,
          schema: `https://ucp.dev/${version}/services/shopping/rest.openapi.json`,
        }],
      },
      capabilities: {
        "dev.ucp.shopping.checkout": [{
          version,
          spec: `https://ucp.dev/${version}/specification/checkout`,
          schema: `https://ucp.dev/${version}/schemas/shopping/checkout.json`,
        }],
        "dev.ucp.shopping.ap2_mandate": [{
          version,
          spec: `https://ucp.dev/${version}/specification/ap2-mandates`,
          schema: `https://ucp.dev/${version}/schemas/shopping/ap2_mandate.json`,
          extends: "dev.ucp.shopping.checkout",
        }],
      },
    },
    signing_keys: [],
  };
}

function profileSnapshot(profile, overrides = {}) {
  const profileBytes = Buffer.from(JSON.stringify(profile), "utf8");
  return {
    profileBytes,
    profileDigest: sha256Bytes(profileBytes),
    profileUrl: "https://merchant.example/.well-known/ucp",
    capturedAt: "2026-04-09T00:00:00.000Z",
    validUntil: "2027-04-09T00:00:00.000Z",
    ap2Version: "0.2.0",
    ...overrides,
  };
}

function contentDigest(body) {
  return `sha-256=:${createHash("sha256").update(body).digest("base64")}:`;
}

function signUcpRequest(unsigned, pair, encoding = "ieee-p1363") {
  const base = buildUcpRequestSignatureBase(unsigned);
  const hash = { ES256: "sha256", ES384: "sha384", ES512: "sha512" }[pair.publicJwk.alg];
  const signature = sign(hash, base, {
    key: pair.privateKey,
    dsaEncoding: encoding,
  });
  return {
    ...unsigned,
    signature: `sig1=:${signature.toString("base64")}:`,
  };
}

function makeClosedAp2Fixture(claimOverrides = {}, tokenOptions = {}) {
  const issuer = createEcPair("issuer-boundary");
  const agent = createEcPair("agent-boundary");
  const checkoutJwt = createJwt(
    { id: "chk-boundary", amount: 2_500, currency: "USD" },
    createEcPair("merchant-boundary"),
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
    ...claimOverrides,
  };
  const token = createAp2Token(claims, issuer, agent, undefined, tokenOptions);
  return {
    issuer,
    agent,
    claims,
    checkoutJwt,
    checkoutHash,
    token,
    options: {
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
    },
  };
}

function issueCodes(report) {
  return new Set(report.issues.map((issue) => issue.code));
}

test("exact UCP 2026-04-08 REST plus AP2 v0.2.0 profile is pinned offline", () => {
  const snapshot = profileSnapshot(makeUcpProfile());
  const report = verifyUcpProfileSnapshot(snapshot, {
    expectedProfileDigest: snapshot.profileDigest,
    asOf: evaluationTime,
  });
  assert.equal(report.upstreamValid, true, JSON.stringify(report.issues));
  assert.equal(report.evidenceEligible, true);
  assert.equal(report.value.profileId, UCP_AP2_EVIDENCE_PROFILE.id);
  assert.equal(report.value.authorizesNativeRole, false);

  const wrongVersion = profileSnapshot(makeUcpProfile("2026-01-23"));
  const wrongVersionReport = verifyUcpProfileSnapshot(wrongVersion, {
    expectedProfileDigest: wrongVersion.profileDigest,
    asOf: evaluationTime,
  });
  assert.equal(wrongVersionReport.upstreamValid, false);
  assert.equal(
    wrongVersionReport.issues.some((issue) => issue.code === "UCP_VERSION_UNSUPPORTED"),
    true,
  );

  const wrongAp2 = profileSnapshot(makeUcpProfile(), { ap2Version: "0.1.0" });
  assert.equal(verifyUcpProfileSnapshot(wrongAp2, {
    expectedProfileDigest: wrongAp2.profileDigest,
    asOf: evaluationTime,
  }).upstreamValid, false);
});

test("UCP profile importer distinguishes malformed, stale, unpinned, and incompatible snapshots", () => {
  const valid = profileSnapshot(makeUcpProfile());
  const stale = verifyUcpProfileSnapshot({
    ...valid,
    validUntil: "2026-05-01T00:00:00.000Z",
  }, {
    expectedProfileDigest: valid.profileDigest,
    asOf: evaluationTime,
  });
  assert.equal(stale.upstreamValid, true);
  assert.equal(stale.evidenceEligible, false);
  assert.equal(issueCodes(stale).has("UCP_PROFILE_SNAPSHOT_STALE"), true);

  const invalidWindow = verifyUcpProfileSnapshot({
    ...valid,
    capturedAt: "2027-05-01T00:00:00.000Z",
  }, {
    expectedProfileDigest: valid.profileDigest,
    asOf: evaluationTime,
  });
  assert.equal(invalidWindow.upstreamValid, false);
  assert.equal(issueCodes(invalidWindow).has("UCP_PROFILE_WINDOW_INVALID"), true);

  for (const profileUrl of [
    "not a url",
    "http://merchant.example/.well-known/ucp",
    "https://user:secret@merchant.example/.well-known/ucp",
    "https://merchant.example/.well-known/ucp#fragment",
  ]) {
    const report = verifyUcpProfileSnapshot({ ...valid, profileUrl }, {
      expectedProfileDigest: valid.profileDigest,
      asOf: evaluationTime,
    });
    assert.equal(report.upstreamValid, false, profileUrl);
    assert.equal(issueCodes(report).has("UCP_PROFILE_INVALID"), true);
  }

  const invalidUtf8 = Buffer.from([0xff]);
  const invalidUtf8Report = verifyUcpProfileSnapshot({
    ...valid,
    profileBytes: invalidUtf8,
    profileDigest: sha256Bytes(invalidUtf8),
  }, {
    expectedProfileDigest: sha256Bytes(invalidUtf8),
    asOf: evaluationTime,
  });
  assert.equal(invalidUtf8Report.upstreamValid, false);
  assert.equal(issueCodes(invalidUtf8Report).has("UCP_PROFILE_INVALID"), true);

  const unpinned = verifyUcpProfileSnapshot({
    ...valid,
    profileDigest: sourceDigest,
  }, {
    expectedProfileDigest: sourceDigest,
    asOf: evaluationTime,
  });
  assert.equal(unpinned.upstreamValid, false);
  assert.equal(unpinned.evidenceEligible, false);
  assert.equal(issueCodes(unpinned).has("UCP_PROFILE_DIGEST_MISMATCH"), true);
  assert.equal(issueCodes(unpinned).has("UCP_PROFILE_PIN_MISMATCH"), true);

  const wrongService = makeUcpProfile();
  wrongService.ucp.services["dev.ucp.shopping"] = [
    null,
    { version: "2026-01-23", transport: "mcp" },
  ];
  const wrongServiceSnapshot = profileSnapshot(wrongService);
  const wrongServiceReport = verifyUcpProfileSnapshot(wrongServiceSnapshot, {
    expectedProfileDigest: wrongServiceSnapshot.profileDigest,
    asOf: evaluationTime,
  });
  assert.equal(wrongServiceReport.upstreamValid, false);
  assert.equal(issueCodes(wrongServiceReport).has("UCP_REST_PROFILE_MISSING"), true);

  const wrongCapabilities = makeUcpProfile();
  wrongCapabilities.ucp.capabilities["dev.ucp.shopping.checkout"][0].version = "2026-01-23";
  wrongCapabilities.ucp.capabilities["dev.ucp.shopping.ap2_mandate"][0].version = "2026-01-23";
  const wrongCapabilitiesSnapshot = profileSnapshot(wrongCapabilities);
  const wrongCapabilitiesReport = verifyUcpProfileSnapshot(wrongCapabilitiesSnapshot, {
    expectedProfileDigest: wrongCapabilitiesSnapshot.profileDigest,
    asOf: evaluationTime,
  });
  assert.equal(wrongCapabilitiesReport.upstreamValid, false);
  assert.equal(issueCodes(wrongCapabilitiesReport).has("UCP_CHECKOUT_VERSION_UNSUPPORTED"), true);
  assert.equal(
    issueCodes(wrongCapabilitiesReport).has("UCP_AP2_EXTENSION_VERSION_UNSUPPORTED"),
    true,
  );

  for (const malformedProfile of [
    {},
    { ucp: { version: "2026-04-08", services: {} } },
    {
      ucp: {
        version: "2026-04-08",
        services: { "dev.ucp.shopping": {} },
        capabilities: {},
      },
    },
    {
      ...makeUcpProfile(),
      ucp: {
        ...makeUcpProfile().ucp,
        capabilities: {
          ...makeUcpProfile().ucp.capabilities,
          "dev.ucp.shopping.checkout": [false],
        },
      },
    },
  ]) {
    const snapshot = profileSnapshot(malformedProfile);
    const report = verifyUcpProfileSnapshot(snapshot, {
      expectedProfileDigest: snapshot.profileDigest,
      asOf: evaluationTime,
    });
    assert.equal(report.upstreamValid, false);
    assert.equal(issueCodes(report).has("UCP_PROFILE_SHAPE_INVALID"), true);
  }
});

test("RFC 9530 Content-Digest binds exact raw bytes and rejects alternate syntax", () => {
  const body = Buffer.from('{"checkout":{"id":"chk-1"}}', "utf8");
  const header = contentDigest(body);
  const parsed = parseContentDigest(header);
  assert.equal(parsed.algorithm, "sha-256");
  assert.equal(parsed.digest.byteLength, 32);
  assert.equal(verifyRawBodyContentDigest(body, header).upstreamValid, true);

  const oneByteMutation = Buffer.from(body);
  oneByteMutation[oneByteMutation.length - 2] ^= 1;
  assert.equal(verifyRawBodyContentDigest(oneByteMutation, header).upstreamValid, false);
  assert.throws(() => parseContentDigest(`sha-512=:${Buffer.alloc(64).toString("base64")}:`));
  assert.throws(() => parseContentDigest(`${header}, sha-512=:AAAA:`));
});

test("Content-Digest parser rejects noncanonical, malformed, and wrong-length values safely", () => {
  assert.throws(() => parseContentDigest(null));
  assert.throws(() => parseContentDigest("sha-256=::"));
  assert.throws(() => parseContentDigest("sha-256=:AB==:"));
  assert.throws(() => parseContentDigest(`sha-256=:${Buffer.alloc(31).toString("base64")}:`));
  const report = verifyRawBodyContentDigest(Buffer.alloc(0), "not-a-digest");
  assert.equal(report.upstreamValid, false);
  assert.equal(issueCodes(report).has("UCP_CONTENT_DIGEST_INVALID"), true);
});

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

test("lifecycle correlation never claims complete checkout/order history", () => {
  const events = [
    {
      eventId: "evt-checkout",
      kind: "checkout",
      transactionId: "txn-1",
      checkoutId: "chk-1",
      occurredAt: "2026-07-23T00:00:00.000Z",
      sourceDigest: sha256Bytes(Buffer.from("checkout")),
      upstreamValid: true,
      evidenceEligible: true,
    },
    {
      eventId: "evt-order",
      kind: "order",
      transactionId: "txn-1",
      checkoutId: "chk-1",
      orderId: "ord-1",
      parentEventIds: ["evt-checkout"],
      occurredAt: "2026-07-23T00:01:00.000Z",
      sourceDigest: sha256Bytes(Buffer.from("order")),
      upstreamValid: true,
      evidenceEligible: true,
    },
    {
      eventId: "evt-refund",
      kind: "refund",
      transactionId: "txn-1",
      orderId: "ord-1",
      parentEventIds: ["missing-webhook"],
      occurredAt: "2026-07-23T00:02:00.000Z",
      sourceDigest: sha256Bytes(Buffer.from("refund-a")),
      upstreamValid: true,
      evidenceEligible: true,
    },
    {
      eventId: "evt-refund",
      kind: "refund",
      transactionId: "txn-1",
      orderId: "ord-1",
      parentEventIds: ["evt-order"],
      occurredAt: "2026-07-23T00:03:00.000Z",
      sourceDigest: sha256Bytes(Buffer.from("refund-b")),
      upstreamValid: true,
      evidenceEligible: true,
    },
  ];
  const [correlation] = correlateTransactionLifecycle(events);
  assert.equal(correlation.historyCompleteness, "unknown");
  assert.deepEqual(correlation.duplicateEventIds, ["evt-refund"]);
  assert.deepEqual(correlation.conflictingEventIds, ["evt-refund"]);
  assert.deepEqual(correlation.orphanEventIds, ["evt-refund"]);
  assert.equal(
    correlation.coverage.find((entry) => entry.requirement === "complete_upstream_history").state,
    "unknown",
  );
});

test("lifecycle correlation validates inputs, sorts transactions, and distinguishes duplicate from conflict", () => {
  assert.deepEqual(correlateTransactionLifecycle([]), []);
  const sameDigest = sha256Bytes(Buffer.from("same-event"));
  const correlations = correlateTransactionLifecycle([
    {
      eventId: "evt-z",
      kind: "cancel",
      transactionId: "txn-z",
      occurredAt: "2026-07-23T00:02:00.000Z",
      sourceDigest: sameDigest,
      upstreamValid: false,
      evidenceEligible: false,
    },
    {
      eventId: "evt-z",
      kind: "cancel",
      transactionId: "txn-z",
      occurredAt: "2026-07-23T00:02:00.000Z",
      sourceDigest: sameDigest,
      upstreamValid: false,
      evidenceEligible: false,
    },
    {
      eventId: "evt-a",
      kind: "return",
      transactionId: "txn-a",
      occurredAt: "2026-07-23T00:00:00.000Z",
      sourceDigest: sha256Bytes(Buffer.from("return")),
      upstreamValid: true,
      evidenceEligible: true,
    },
    {
      eventId: "evt-adjust",
      kind: "adjustment",
      transactionId: "txn-a",
      parentEventIds: [],
      occurredAt: "2026-07-23T00:03:00.000Z",
      sourceDigest: sha256Bytes(Buffer.from("adjustment")),
      upstreamValid: true,
      evidenceEligible: true,
    },
  ]);
  assert.deepEqual(correlations.map((entry) => entry.transactionId), ["txn-a", "txn-z"]);
  assert.deepEqual(correlations[1].duplicateEventIds, ["evt-z"]);
  assert.deepEqual(correlations[1].conflictingEventIds, []);
  assert.equal(
    correlations[1].coverage.find((entry) => entry.requirement === "checkout_evidence").state,
    "unknown",
  );
  assert.equal(
    correlations[0].coverage.find((entry) => entry.requirement === "post_order_adjustments").state,
    "satisfied",
  );

  const base = {
    eventId: "evt",
    kind: "checkout",
    transactionId: "txn",
    occurredAt: "2026-07-23T00:00:00.000Z",
    sourceDigest: sha256Bytes(Buffer.from("event")),
    upstreamValid: true,
    evidenceEligible: true,
  };
  const contradictory = correlateTransactionLifecycle([base, { ...base, kind: "order" }])[0];
  assert.deepEqual(contradictory.duplicateEventIds, ["evt"]);
  assert.deepEqual(contradictory.conflictingEventIds, ["evt"]);
  assert.equal(
    contradictory.coverage.find((entry) => entry.requirement === "checkout_evidence").state,
    "unknown",
  );
  assert.equal(
    contradictory.coverage.find((entry) => entry.requirement === "order_evidence").state,
    "unknown",
  );
  for (const invalid of [
    { ...base, eventId: "" },
    { ...base, transactionId: "" },
    { ...base, kind: "ship" },
    { ...base, sourceDigest: "sha256:not-a-digest" },
    { ...base, occurredAt: "not-a-time" },
  ]) {
    assert.throws(() => correlateTransactionLifecycle([invalid]));
  }
});
