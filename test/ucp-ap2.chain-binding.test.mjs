import assert from "node:assert/strict";
import { createHash, sign } from "node:crypto";
import test from "node:test";
import { verifyAp2MandateChain } from "../dist/ucp-ap2.js";
import {
  createEcPair,
  createJwt,
  evaluationTime,
  keySnapshot,
  sourceDigest,
} from "./ucp-ap2-helpers.mjs";

/**
 * The hop checks of the AP2 v0.2.0 Delegate chain are what stop a forged or
 * spliced chain: each hop must be signed by the key the previous hop
 * delegated to, must bind the exact previous hop by hash, must sit in the
 * position its protected typ claims, and the terminal hop must answer the
 * caller's audience and nonce. Each case below changes one property of an
 * otherwise valid chain, so the control proves the rejection comes from that
 * property alone.
 */

const AS_OF = evaluationTime;
const AS_OF_SECONDS = Date.parse(AS_OF) / 1_000;
const IAT = 1_770_000_000;
const EXP = 1_800_000_000;
const ISSUER = "https://trusted-surface.example";
const AUDIENCE = "https://merchant.example";
const NONCE = "checkout-nonce-binding";

const issuer = createEcPair("issuer-chain-binding");
const agent = createEcPair("agent-chain-binding");
const stranger = createEcPair("stranger-chain-binding");
const merchant = createEcPair("merchant-chain-binding");

const checkoutJwt = createJwt({
  id: "chk-binding",
  line_items: [{ id: "line-1", item: { id: "sku-1", title: "Item sku-1" }, quantity: 1, totals: [] }],
  status: "completed",
  currency: "USD",
  totals: [],
  links: [],
}, merchant);
const checkoutHash = createHash("sha256").update(checkoutJwt).digest("base64url");

function signJwt(claims, signer, typ, kid = signer.publicJwk.kid) {
  const protectedSegment = Buffer.from(JSON.stringify({ alg: "ES256", kid, typ }), "utf8")
    .toString("base64url");
  const payloadSegment = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  const input = `${protectedSegment}.${payloadSegment}`;
  const signature = sign("sha256", Buffer.from(input, "ascii"), {
    key: signer.privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${input}.${signature.toString("base64url")}`;
}

const digest = (value) => createHash("sha256").update(value, "ascii").digest("base64url");

function openPayload(overrides = {}) {
  return {
    vct: "mandate.checkout.open.1",
    iat: IAT,
    exp: EXP,
    constraints: [{
      type: "checkout.line_items",
      items: [{
        id: "requirement-1",
        acceptable_items: [{ id: "sku-1", title: "Item sku-1" }],
        quantity: 1,
      }],
    }],
    cnf: { jwk: agent.publicJwk },
    ...overrides,
  };
}

function closedPayload(overrides = {}) {
  return {
    iss: ISSUER,
    vct: "mandate.checkout.1",
    iat: IAT,
    exp: EXP,
    checkout_jwt: checkoutJwt,
    checkout_hash: checkoutHash,
    ...overrides,
  };
}

function rootJwtFor({ root = openPayload(), rootClaims = {}, rootTyp = "dc+sd-jwt" } = {}) {
  return signJwt({ _sd_alg: "sha-256", ...rootClaims, delegate_payload: [root] }, issuer, rootTyp);
}

/**
 * Build `root~~terminal~`. The terminal hop binds the root presentation
 * through `sd_hash` by default, or the root issuer JWT through
 * `issuer_jwt_hash`; `hop` overrides or (with undefined) removes hop claims.
 */
function buildChain({
  rootJwt = rootJwtFor(),
  terminal = closedPayload(),
  terminalTyp = "kb+sd-jwt",
  signer = agent,
  signerKid = agent.publicJwk.kid,
  binding = "sd_hash",
  hop = {},
} = {}) {
  const bindings = {
    sd_hash: { sd_hash: digest(`${rootJwt}~`) },
    issuer_jwt_hash: { issuer_jwt_hash: digest(rootJwt) },
    both: { sd_hash: digest(`${rootJwt}~`), issuer_jwt_hash: digest(rootJwt) },
    none: {},
  };
  const claims = {
    _sd_alg: "sha-256",
    aud: AUDIENCE,
    nonce: NONCE,
    iat: IAT,
    ...bindings[binding],
    delegate_payload: [terminal],
    ...hop,
  };
  for (const [name, value] of Object.entries(claims)) {
    if (value === undefined) delete claims[name];
  }
  return `${rootJwt}~~${signJwt(claims, signer, terminalTyp, signerKid)}~`;
}

function verify(token, overrides = {}) {
  return verifyAp2MandateChain({
    token,
    expectedVct: "mandate.checkout.1",
    issuerKeySnapshot: keySnapshot(issuer),
    expectedIssuerKeySourceDigest: sourceDigest,
    expectedIssuer: ISSUER,
    expectedAudience: AUDIENCE,
    expectedNonce: NONCE,
    expectedAgentJwk: agent.publicJwk,
    expectedCheckoutJwt: checkoutJwt,
    requireKeyBinding: true,
    asOf: AS_OF,
    allowedAlgorithms: ["ES256"],
    ...overrides,
  });
}

/** The chain-level rejection message, after asserting the chain failed closed. */
function rejection(report) {
  assert.equal(report.upstreamValid, false, "chain must fail closed");
  assert.equal(report.value, null, "a rejected chain must not return claims");
  const issue = report.issues.find((entry) => entry.code === "AP2_MANDATE_CHAIN_INVALID");
  assert.notEqual(issue, undefined, JSON.stringify(report.issues));
  return issue.message;
}

function assertValid(report) {
  assert.deepEqual(report.issues, [], JSON.stringify(report.issues));
  assert.equal(report.upstreamValid, true);
  assert.equal(report.evidenceEligible, true);
}

test("a two-hop chain verifies when bound by sd_hash or by issuer_jwt_hash", () => {
  for (const binding of ["sd_hash", "issuer_jwt_hash"]) {
    const report = verify(buildChain({ binding }));
    assertValid(report);
    assert.equal(report.value.keyBound, true);
    assert.equal(report.value.chainDepth, 2);
    assert.equal(report.value.checkoutHash, checkoutHash);
  }
});

test("a terminal hop spliced onto a different root fails the binding hash", () => {
  // Both chains are individually valid and signed by the same agent; only the
  // pairing of one chain's root with the other's terminal hop is forged.
  const first = buildChain();
  const second = buildChain({ rootJwt: rootJwtFor({ rootClaims: { jti: "second-root" } }) });
  assertValid(verify(second));
  const spliced = `${first.slice(0, first.indexOf("~~"))}${second.slice(second.indexOf("~~"))}`;
  assert.equal(
    rejection(verify(spliced)),
    "Delegate hop binding hash does not match the previous hop",
  );
  for (const binding of ["sd_hash", "issuer_jwt_hash"]) {
    assert.equal(
      rejection(verify(buildChain({ binding, hop: { [binding]: digest("some-other-hop") } }))),
      "Delegate hop binding hash does not match the previous hop",
    );
  }
});

test("a terminal hop must carry exactly one binding hash", () => {
  for (const binding of ["none", "both"]) {
    assert.equal(
      rejection(verify(buildChain({ binding }))),
      "Delegate hop must contain exactly one binding hash",
    );
  }
});

test("a terminal hop must be signed by the key the root delegated to", () => {
  // The protected kid still names the agent key; only the signer differs.
  assert.equal(
    rejection(verify(buildChain({ signer: stranger }))),
    "JWT signature verification failed",
  );
  assert.equal(
    rejection(verify(buildChain({ signer: stranger, signerKid: stranger.publicJwk.kid }))),
    "Protected kid does not match the pinned key",
  );
});

test("the root may delegate only to the caller's expected agent key, and only through cnf", () => {
  assert.equal(
    rejection(verify(buildChain(), { expectedAgentJwk: stranger.publicJwk })),
    "Root cnf key does not match the expected agent key",
  );
  const { cnf: _cnf, ...withoutCnf } = openPayload();
  assert.equal(
    rejection(verify(buildChain({ rootJwt: rootJwtFor({ root: withoutCnf }) }))),
    "Open root Mandate is missing cnf.jwk",
  );
});

test("the terminal hop must answer the caller's audience and nonce", () => {
  for (const hop of [{ aud: "https://other-merchant.example" }, { nonce: "replayed-nonce" }]) {
    assert.equal(
      rejection(verify(buildChain({ hop }))),
      "Terminal Delegate SD-JWT audience or nonce does not match",
    );
  }
});

test("each segment's protected typ must match its position in the chain", () => {
  assert.equal(
    rejection(verify(buildChain({ terminalTyp: "kb+sd-jwt+kb" }))),
    "Delegate SD-JWT hop has the wrong terminal shape",
  );
  assert.equal(
    rejection(verify(buildChain({ terminal: closedPayload({ cnf: { jwk: stranger.publicJwk } }) }))),
    "Delegate hop cnf does not match its protected typ",
  );
  assert.equal(
    rejection(verify(buildChain({ rootJwt: rootJwtFor({ rootTyp: "kb+sd-jwt" }) }))),
    "Root SD-JWT typ is not supported by the AP2 profile",
  );
});

test("the terminal hop's iat, nbf and exp bound the evaluation time", () => {
  const path = "token.chain[1].claims";
  assert.equal(rejection(verify(buildChain({ hop: { iat: undefined } }))), `Missing iat at ${path}`);
  // Up to 60 seconds of issuer clock skew is tolerated, and no more.
  assertValid(verify(buildChain({ hop: { iat: AS_OF_SECONDS + 60 } })));
  assert.equal(
    rejection(verify(buildChain({ hop: { iat: AS_OF_SECONDS + 61 } }))),
    `Invalid iat at ${path}`,
  );
  assertValid(verify(buildChain({ hop: { nbf: AS_OF_SECONDS } })));
  assert.equal(
    rejection(verify(buildChain({ hop: { nbf: AS_OF_SECONDS + 1 } }))),
    `Invalid nbf at ${path}`,
  );
  assertValid(verify(buildChain({ hop: { exp: AS_OF_SECONDS + 1 } })));
  assert.equal(
    rejection(verify(buildChain({ hop: { exp: AS_OF_SECONDS } }))),
    `Invalid exp at ${path}`,
  );
});

test("a closed Mandate cannot drop or change a claim the open Mandate fixed", () => {
  const rootJwt = rootJwtFor({ root: openPayload({ payment_method: "card-on-file" }) });
  assertValid(verify(buildChain({
    rootJwt,
    terminal: closedPayload({ payment_method: "card-on-file" }),
  })));
  for (const terminal of [closedPayload({ payment_method: "new-card" }), closedPayload()]) {
    const report = verify(buildChain({ rootJwt, terminal }));
    assert.equal(report.upstreamValid, false);
    assert.deepEqual(
      report.issues.map((issue) => `${issue.code} ${issue.path}`),
      ["AP2_DELEGATED_CLAIM_MISMATCH token.chain[0].delegate_payload.payment_method"],
    );
  }
});

test("the open Mandate type and the root issuer must match the caller's expectations", () => {
  const wrongOpenType = verify(buildChain({
    rootJwt: rootJwtFor({ root: openPayload({ vct: "mandate.payment.open.1" }) }),
  }));
  assert.equal(wrongOpenType.upstreamValid, false);
  assert.equal(
    wrongOpenType.issues.some((issue) => issue.code === "AP2_DELEGATION_VCT_MISMATCH"
      && issue.path === "token.chain[0].delegate_payload.vct"),
    true,
    JSON.stringify(wrongOpenType.issues),
  );

  assertValid(verify(buildChain({ rootJwt: rootJwtFor({ rootClaims: { iss: ISSUER } }) })));
  const wrongIssuer = verify(buildChain({
    rootJwt: rootJwtFor({ rootClaims: { iss: "https://untrusted-surface.example" } }),
  }));
  assert.equal(wrongIssuer.upstreamValid, false);
  assert.deepEqual(
    wrongIssuer.issues.map((issue) => `${issue.code} ${issue.path}`),
    ["AP2_ISSUER_MISMATCH token.chain[0].claims.iss"],
  );
});

test("chain framing must be canonical SD-JWT", () => {
  const token = buildChain();
  assert.equal(
    rejection(verify(token.slice(0, -1))),
    "AP2 Mandate chain must end with an SD-JWT separator",
  );
  assert.match(
    rejection(verify(buildChain({ rootJwt: signJwt({
      _sd_alg: "sha-512",
      delegate_payload: [openPayload()],
    }, issuer, "dc+sd-jwt") }))),
    /only sha-256 SD-JWT/i,
  );
});
