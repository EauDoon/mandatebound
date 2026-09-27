import assert from "node:assert/strict";
import { createHash, sign } from "node:crypto";
import test from "node:test";
import { verifyAp2MandateChain } from "../dist/ucp-ap2.js";
import {
  createEcPair,
  evaluationTime,
  keySnapshot,
  sourceDigest,
} from "./ucp-ap2-helpers.mjs";

/**
 * resolveAp2SegmentClaims is the SD-JWT disclosure resolver that turns a raw
 * AP2 v0.2.0 Delegate chain into the closed claim set the policy engine sees.
 * Every one of its rejection branches has to stay fail-closed, so they are
 * exercised here directly against hand-built chains.
 */

const AS_OF = evaluationTime;
const IAT = 1_770_000_000;
const EXP = 1_800_000_000;
const AUDIENCE = "https://merchant.example";
const NONCE = "nonce-ap2-123";
const SALT = "salt-salt-salt-1";

function joseSign(privateKey, input) {
  return sign("sha256", Buffer.from(input, "ascii"), { key: privateKey, dsaEncoding: "ieee-p1363" })
    .toString("base64url");
}

function encodeJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function signJwt(claims, pair, typ) {
  const protectedSegment = encodeJson({ alg: "ES256", kid: pair.publicJwk.kid, typ });
  const payloadSegment = encodeJson(claims);
  const signature = joseSign(pair.privateKey, `${protectedSegment}.${payloadSegment}`);
  return `${protectedSegment}.${payloadSegment}.${signature}`;
}

function disclosure(parts) {
  return encodeJson(parts);
}

function digestOf(encoded) {
  return createHash("sha256").update(encoded, "utf8").digest("base64url");
}

/**
 * Build a two-hop Delegate chain. `rootClaims` is signed by the issuer and its
 * disclosures are appended in order; the terminal hop binds to the exact root
 * presentation so a well-formed chain reaches the later mandate checks.
 */
function buildChain(issuer, agent, rootClaims, disclosures) {
  const rootJwt = signJwt({ _sd_alg: "sha-256", ...rootClaims }, issuer, "dc+sd-jwt");
  const rootPresentation = disclosures.length === 0
    ? `${rootJwt}~`
    : `${rootJwt}~${disclosures.join("~")}~`;
  const terminalJwt = signJwt({
    _sd_alg: "sha-256",
    aud: AUDIENCE,
    nonce: NONCE,
    iat: IAT,
    sd_hash: digestOf(rootPresentation),
    delegate_payload: [{ vct: "mandate.checkout.1", iat: IAT, exp: EXP }],
  }, agent, "kb+sd-jwt");
  return disclosures.length === 0
    ? `${rootJwt}~~${terminalJwt}~`
    : `${rootJwt}~${disclosures.join("~")}~~${terminalJwt}~`;
}

function setup() {
  const issuer = createEcPair("issuer-disclosure");
  const agent = createEcPair("agent-disclosure");
  return {
    issuer,
    agent,
    baseClaims: {
      iat: IAT,
      exp: EXP,
      iss: "https://trusted-surface.example",
      delegate_payload: [{
        vct: "mandate.checkout.open.1",
        iat: IAT,
        exp: EXP,
        cnf: { jwk: agent.publicJwk },
      }],
    },
    options: {
      expectedVct: "mandate.checkout.1",
      issuerKeySnapshot: keySnapshot(issuer),
      expectedIssuerKeySourceDigest: sourceDigest,
      expectedIssuer: "https://trusted-surface.example",
      expectedAudience: AUDIENCE,
      expectedNonce: NONCE,
      asOf: AS_OF,
      allowedAlgorithms: ["ES256"],
    },
  };
}

/** Verify and return the AP2_MANDATE_CHAIN_INVALID message, or null. */
function chainRejection(token, options) {
  const report = verifyAp2MandateChain({ ...options, token });
  assert.equal(report.upstreamValid, false, "chain must fail closed");
  assert.equal(report.value, null, "no value may be returned for a rejected chain");
  const issue = report.issues.find((entry) => entry.code === "AP2_MANDATE_CHAIN_INVALID");
  return issue === undefined ? null : issue.message;
}

test("a well-formed SD-JWT disclosure resolves without a chain rejection", () => {
  const { issuer, agent, baseClaims, options } = setup();
  // A three-element object-property disclosure referenced through `_sd`.
  const nameDisclosure = disclosure([SALT, "merchant", { id: "merchant-1", name: "Store" }]);
  const token = buildChain(
    issuer,
    agent,
    { ...baseClaims, _sd: [digestOf(nameDisclosure)] },
    [nameDisclosure],
  );
  assert.equal(chainRejection(token, options), null);
});

test("duplicate SD-JWT disclosures are rejected", () => {
  const { issuer, agent, baseClaims, options } = setup();
  const value = disclosure([SALT, "merchant", { id: "merchant-1" }]);
  const token = buildChain(
    issuer,
    agent,
    { ...baseClaims, _sd: [digestOf(value)] },
    [value, value],
  );
  assert.equal(chainRejection(token, options), "AP2 SD-JWT contains duplicate disclosures");
});

test("a disclosure referenced more than once is rejected", () => {
  const { issuer, agent, baseClaims, options } = setup();
  const value = disclosure([SALT, { id: "merchant-1" }]);
  const digest = digestOf(value);
  // The same two-element disclosure is consumed by two array placeholders.
  const token = buildChain(
    issuer,
    agent,
    {
      ...baseClaims,
      delegate_payload: [
        baseClaims.delegate_payload[0],
        { "...": digest },
        { "...": digest },
      ],
    },
    [value],
  );
  assert.equal(chainRejection(token, options), "AP2 SD-JWT disclosure is referenced more than once");
});

test("a disclosure with the wrong contextual shape is rejected", () => {
  const { issuer, agent, baseClaims, options } = setup();
  // A three-element disclosure used through the two-element array placeholder.
  const value = disclosure([SALT, "merchant", { id: "merchant-1" }]);
  const digest = digestOf(value);
  const token = buildChain(
    issuer,
    agent,
    {
      ...baseClaims,
      delegate_payload: [baseClaims.delegate_payload[0], { "...": digest }],
    },
    [value],
  );
  assert.equal(chainRejection(token, options), "AP2 SD-JWT disclosure has the wrong contextual shape");
});

test("a non-string disclosure placeholder is rejected", () => {
  const { issuer, agent, baseClaims, options } = setup();
  const token = buildChain(
    issuer,
    agent,
    {
      ...baseClaims,
      delegate_payload: [baseClaims.delegate_payload[0], { "...": 7 }],
    },
    [],
  );
  assert.equal(chainRejection(token, options), "AP2 SD-JWT contains an invalid disclosure placeholder");
});

test("a non-string _sd entry is rejected", () => {
  const { issuer, agent, baseClaims, options } = setup();
  const token = buildChain(issuer, agent, { ...baseClaims, _sd: [7] }, []);
  assert.equal(chainRejection(token, options), "AP2 SD-JWT _sd must contain digest strings");
});

test("duplicate _sd digests are rejected", () => {
  const { issuer, agent, baseClaims, options } = setup();
  const value = disclosure([SALT, "merchant", { id: "merchant-1" }]);
  const digest = digestOf(value);
  const token = buildChain(issuer, agent, { ...baseClaims, _sd: [digest, digest] }, [value]);
  assert.equal(chainRejection(token, options), "AP2 SD-JWT _sd contains duplicate digests");
});

test("a two-element disclosure bound as an object property is rejected", () => {
  const { issuer, agent, baseClaims, options } = setup();
  // `_sd` entries must resolve to a three-element disclosure carrying a name.
  const value = disclosure([SALT, { id: "merchant-1" }]);
  const token = buildChain(
    issuer,
    agent,
    { ...baseClaims, _sd: [digestOf(value)] },
    [value],
  );
  assert.equal(chainRejection(token, options), "AP2 object-property disclosure is malformed");
});

test("a disclosure conflicting with an existing claim is rejected", () => {
  const { issuer, agent, baseClaims, options } = setup();
  // The disclosure wants to introduce `iat`, which the root already sets.
  const value = disclosure([SALT, "iat", 1_770_000_001]);
  const token = buildChain(
    issuer,
    agent,
    { ...baseClaims, _sd: [digestOf(value)] },
    [value],
  );
  assert.equal(chainRejection(token, options), "AP2 disclosure conflicts with an existing claim");
});

test("a disclosure that conflicts on a prototype key is rejected", () => {
  const { issuer, agent, baseClaims, options } = setup();
  const value = disclosure([SALT, "__proto__", { polluted: true }]);
  const token = buildChain(
    issuer,
    agent,
    { ...baseClaims, _sd: [digestOf(value)] },
    [value],
  );
  assert.equal(chainRejection(token, options), "AP2 disclosure conflicts with an existing claim");
});

test("an unreferenced disclosure is rejected", () => {
  const { issuer, agent, baseClaims, options } = setup();
  const bound = disclosure([SALT, "merchant", { id: "merchant-1" }]);
  const orphan = disclosure(["salt-salt-salt-2", "unused", { id: "never-referenced" }]);
  const token = buildChain(
    issuer,
    agent,
    { ...baseClaims, _sd: [digestOf(bound)] },
    [bound, orphan],
  );
  assert.equal(chainRejection(token, options), "AP2 SD-JWT contains an unbound disclosure");
});
