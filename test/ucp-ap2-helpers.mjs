import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { canonicalBytes, sha256Bytes } from "../dist/canonical.js";
import {
  UCP_AP2_EVIDENCE_PROFILE,
  buildUcpRequestSignatureBase,
} from "../dist/ucp-ap2.js";

export const evaluationTime = "2026-07-23T00:00:00.000Z";
export const sourceDigest = sha256Bytes(Buffer.from("synthetic-pinned-source", "utf8"));

export function createEcPair(kid, namedCurve = "prime256v1", algorithm = "ES256") {
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

export function keySnapshot(pair, overrides = {}) {
  return {
    kid: pair.publicJwk.kid,
    jwk: pair.publicJwk,
    sourceDigest,
    capturedAt: "2026-04-09T00:00:00.000Z",
    validUntil: "2027-04-09T00:00:00.000Z",
    ...overrides,
  };
}

export function encodeJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

export function mutateBase64UrlBytes(value) {
  const bytes = Buffer.from(value, "base64url");
  assert.notEqual(bytes.length, 0);
  bytes[0] ^= 1;
  return bytes.toString("base64url");
}

export function mutateCompactSignature(value) {
  const finalDot = value.lastIndexOf(".");
  assert.notEqual(finalDot, -1);
  const signature = value.slice(finalDot + 1);
  return `${value.slice(0, finalDot + 1)}${mutateBase64UrlBytes(signature)}`;
}

export function joseSign(privateKey, algorithm, input, encoding = "ieee-p1363") {
  const hash = { ES256: "sha256", ES384: "sha384", ES512: "sha512" }[algorithm];
  return sign(hash, Buffer.from(input, "ascii"), {
    key: privateKey,
    dsaEncoding: encoding,
  });
}

export function createJwt(claims, pair, header = { alg: "ES256", kid: pair.publicJwk.kid, typ: "JWT" }) {
  const protectedSegment = encodeJson(header);
  const payloadSegment = encodeJson(claims);
  const signingInput = `${protectedSegment}.${payloadSegment}`;
  const signature = joseSign(pair.privateKey, header.alg, signingInput);
  return `${signingInput}.${signature.toString("base64url")}`;
}

export function createAp2Token(claims, issuerPair, agentPair, issuerHeader, tokenOptions = {}) {
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

export function merchantAuthorization(checkout, pair, {
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

export function makeUcpProfile(version = UCP_AP2_EVIDENCE_PROFILE.ucpVersion) {
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

export function profileSnapshot(profile, overrides = {}) {
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

export function contentDigest(body) {
  return `sha-256=:${createHash("sha256").update(body).digest("base64")}:`;
}

export function signUcpRequest(unsigned, pair, encoding = "ieee-p1363") {
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

export function makeClosedAp2Fixture(claimOverrides = {}, tokenOptions = {}) {
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

export function issueCodes(report) {
  return new Set(report.issues.map((issue) => issue.code));
}
