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
 * The `checkout.line_items` constraint is decided by a bounded bipartite
 * max-flow: each cart SKU can be assigned to at most one requirement, and the
 * assigned quantities must exactly meet each requirement. The branch
 * coverage for that decision, and for the "empty acceptable_items matches any
 * SKU" rule, was left unexercised.
 *
 * This constraint is only evaluated on the AP2 v0.2.0 Delegate chain path,
 * which is where the closed Mandate (and therefore the bound Checkout JWT the
 * cart is read from) is available to the verifier.
 */

const AS_OF = evaluationTime;
const IAT = 1_770_000_000;
const EXP = 1_800_000_000;
const AUDIENCE = "https://merchant.example";
const NONCE = "checkout-nonce-line-items";

const issuer = createEcPair("issuer-line-items");
const agent = createEcPair("agent-line-items");
const merchant = createEcPair("merchant-line-items");

function signJwt(claims, pair, typ) {
  const protectedSegment = Buffer.from(JSON.stringify({ alg: "ES256", kid: pair.publicJwk.kid, typ }), "utf8")
    .toString("base64url");
  const payloadSegment = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  const input = `${protectedSegment}.${payloadSegment}`;
  const signature = sign("sha256", Buffer.from(input, "ascii"), {
    key: pair.privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${input}.${signature.toString("base64url")}`;
}

function lineItem(sku, quantity) {
  return { id: `line-${sku}-${quantity}`, item: { id: sku, title: `Item ${sku}` }, quantity, totals: [] };
}

function checkoutJwtFor(lineItems) {
  return createJwt({
    id: "chk-line-items",
    line_items: lineItems,
    status: "completed",
    currency: "USD",
    totals: [],
    links: [],
  }, merchant);
}

/** Build a two-hop Delegate chain carrying `constraints` in the open root. */
function chainFor(closedClaims, constraints) {
  const rootJwt = signJwt({
    _sd_alg: "sha-256",
    delegate_payload: [{
      vct: "mandate.checkout.open.1",
      iat: IAT,
      exp: EXP,
      constraints,
      cnf: { jwk: agent.publicJwk },
    }],
  }, issuer, "dc+sd-jwt");
  const rootPresentation = `${rootJwt}~`;
  const terminalJwt = signJwt({
    _sd_alg: "sha-256",
    aud: AUDIENCE,
    nonce: NONCE,
    iat: IAT,
    sd_hash: createHash("sha256").update(rootPresentation, "ascii").digest("base64url"),
    delegate_payload: [closedClaims],
  }, agent, "kb+sd-jwt");
  return `${rootJwt}~~${terminalJwt}~`;
}

/** Verify a chain whose only constraint is `checkout.line_items`. */
function check(items, cartItems) {
  const checkoutJwt = checkoutJwtFor(cartItems);
  return verifyAp2MandateChain({
    token: chainFor({
      iss: "https://trusted-surface.example",
      vct: "mandate.checkout.1",
      iat: IAT,
      exp: EXP,
      checkout_jwt: checkoutJwt,
      checkout_hash: "sha256-unused-here",
    }, [{ type: "checkout.line_items", items }]),
    expectedVct: "mandate.checkout.1",
    issuerKeySnapshot: keySnapshot(issuer),
    expectedIssuerKeySourceDigest: sourceDigest,
    expectedIssuer: "https://trusted-surface.example",
    expectedAudience: AUDIENCE,
    expectedNonce: NONCE,
    expectedAgentJwk: agent.publicJwk,
    asOf: AS_OF,
    allowedAlgorithms: ["ES256"],
  });
}

const requirement = (quantity, ids = ["sku-1"]) => ({
  id: "requirement-1",
  acceptable_items: ids.map((id) => ({ id, title: `Item ${id}` })),
  quantity,
});

const failed = (report) => report.issues.some((issue) => issue.code === "AP2_CONSTRAINT_FAILED");

test("a cart that exactly meets the requirement satisfies the constraint", () => {
  const report = check([requirement(1)], [lineItem("sku-1", 1)]);
  assert.equal(failed(report), false, JSON.stringify(report.issues));
});

test("quantities must match exactly on both sides", () => {
  assert.equal(failed(check([requirement(2)], [lineItem("sku-1", 1)])), true, "underfilled");
  assert.equal(failed(check([requirement(1)], [lineItem("sku-1", 2)])), true, "overfilled");
});

test("a SKU outside every acceptable_items list is not assignable", () => {
  assert.equal(failed(check([requirement(1, ["sku-2"])], [lineItem("sku-1", 1)])), true);
  assert.equal(failed(check([requirement(1, ["sku-2"])], [lineItem("sku-2", 1)])), false);
});

test("one cart unit cannot satisfy two requirements at once", () => {
  const report = check(
    [requirement(1), { ...requirement(1), id: "requirement-2" }],
    [lineItem("sku-1", 1)],
  );
  assert.equal(failed(report), true, "a single unit is assigned to at most one requirement");
});

test("duplicate line items for one SKU accumulate", () => {
  const report = check([requirement(2)], [lineItem("sku-1", 1), lineItem("sku-1", 1)]);
  assert.equal(failed(report), false, JSON.stringify(report.issues));
});

test("quantities are matched per requirement, not pooled across SKUs", () => {
  // Two units exist, but each requirement wants one of a *specific* SKU, and
  // no single SKU has two units to give.
  const report = check(
    [requirement(1, ["sku-1"]), { ...requirement(1, ["sku-2"]), id: "requirement-2" }],
    [lineItem("sku-1", 1), lineItem("sku-2", 1)],
  );
  assert.equal(failed(report), false, JSON.stringify(report.issues));
});

test("an empty acceptable_items list accepts any SKU", () => {
  // A requirement with no acceptable items links to every SKU, so it behaves
  // as a quantity floor rather than a specific item list.
  const wildcard = { id: "requirement-1", acceptable_items: [], quantity: 1 };
  assert.equal(failed(check([wildcard], [lineItem("sku-1", 1)])), false);
  assert.equal(failed(check([wildcard], [lineItem("sku-anything", 1)])), false);
  assert.equal(failed(check([wildcard], [lineItem("sku-1", 2)])), true);
});

test("malformed requirements are refused rather than ignored", () => {
  const malformed = [
    { id: "", acceptable_items: [{ id: "sku-1", title: "t" }], quantity: 1 },
    { id: "r", acceptable_items: "sku-1", quantity: 1 },
    { id: "r", acceptable_items: [{ id: "sku-1", title: "t" }], quantity: 0 },
    { id: "r", acceptable_items: [{ id: "sku-1", title: "t" }], quantity: -1 },
    { id: "r", acceptable_items: [{ id: "sku-1", title: "t" }], quantity: 1.5 },
    { id: "r", acceptable_items: [{ id: "", title: "t" }], quantity: 1 },
    { id: "r", acceptable_items: [{ id: "sku-1" }], quantity: 1 },
  ];
  for (const items of malformed) {
    // A malformed requirement is refused, whether by the constraint schema
    // guard or by the satisfiability check itself.
    const report = check([items], [lineItem("sku-1", 1)]);
    assert.equal(report.upstreamValid, false, JSON.stringify(items));
  }
});

test("a malformed or empty cart cannot satisfy the constraint", () => {
  assert.equal(failed(check([requirement(1)], [])), true, "an empty cart meets nothing");
  assert.equal(failed(check([requirement(1)], [lineItem("sku-1", 0)])), true);
  assert.equal(failed(check([requirement(1)], [lineItem("sku-1", -1)])), true);
  assert.equal(failed(check([requirement(1)], [{ id: "l", quantity: 1 }])), true);
  assert.equal(
    failed(check([requirement(129)], Array.from({ length: 129 }, () => lineItem("sku-1", 1)))),
    true,
    "a cart beyond the 128 line-item cap is refused",
  );
});

test("per-SKU quantity accumulation is bounded to safe integers", () => {
  const huge = Number.MAX_SAFE_INTEGER;
  assert.equal(
    failed(check([requirement(1)], [lineItem("sku-1", huge), lineItem("sku-1", huge)])),
    true,
    "an overflowing per-SKU total is refused rather than wrapped",
  );
});
