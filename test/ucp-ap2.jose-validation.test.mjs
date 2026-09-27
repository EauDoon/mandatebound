import assert from "node:assert/strict";
import test from "node:test";
import { verifyAp2CheckoutJwt } from "../dist/ucp-ap2.js";
import {
  createEcPair,
  createJwt,
  evaluationTime,
  keySnapshot,
  sourceDigest,
} from "./ucp-ap2-helpers.mjs";

/**
 * The JOSE layer is where algorithm confusion, curve mismatch and private key
 * material would be caught. Its guards sit behind the public verifiers, so
 * they are driven through verifyAp2CheckoutJwt here: every case below is a
 * merchant-signed Checkout JWT that must be refused, with the specific
 * structural reason preserved.
 */

const merchant = createEcPair("merchant-jose-taxonomy");

const validClaims = {
  id: "chk-jose",
  line_items: [],
  status: "completed",
  currency: "USD",
  totals: [],
  links: [],
};

function verify(token, snapshot = keySnapshot(merchant)) {
  return verifyAp2CheckoutJwt({
    token,
    merchantKeySnapshot: snapshot,
    expectedMerchantKeySourceDigest: sourceDigest,
    asOf: evaluationTime,
    allowedAlgorithms: ["ES256"],
  });
}

function signatureRejection(token, expectedMessage, snapshot) {
  const report = verify(token, snapshot);
  assert.equal(report.upstreamValid, false, expectedMessage);
  assert.equal(report.value, null, expectedMessage);
  const issue = report.issues.find((entry) => entry.code === "AP2_CHECKOUT_JWT_SIGNATURE_INVALID");
  assert.notEqual(issue, undefined, `expected a signature rejection: ${expectedMessage}`);
  assert.equal(issue.message, expectedMessage);
}

test("a well-formed merchant Checkout JWT is accepted", () => {
  const report = verify(createJwt(validClaims, merchant));
  assert.equal(report.upstreamValid, true, JSON.stringify(report.issues));
  assert.equal(report.evidenceEligible, true, JSON.stringify(report.issues));
});

test("unsupported and non-allowlisted JOSE algorithms are refused", () => {
  // alg=none is refused by the compact-segment parser before the header is
  // even inspected, because the unsigned form has an empty signature segment.
  const noneHeader = { alg: "none", kid: merchant.publicJwk.kid, typ: "JWT" };
  const noneProtected = Buffer.from(JSON.stringify(noneHeader), "utf8").toString("base64url");
  const nonePayload = Buffer.from(JSON.stringify(validClaims), "utf8").toString("base64url");
  const algNone = verify(`${noneProtected}.${nonePayload}.`);
  assert.equal(algNone.upstreamValid, false);
  assert.equal(
    algNone.issues.some((entry) => entry.code === "AP2_CHECKOUT_JWT_INVALID"),
    true,
    JSON.stringify(algNone.issues),
  );

  // Every other unsupported algorithm reaches the JOSE allowlist check.
  for (const alg of ["HS256", "RS256", "EdDSA"]) {
    signatureRejection(
      createJwt(validClaims, merchant, { alg, kid: merchant.publicJwk.kid, typ: "JWT" }),
      "Unsupported JOSE algorithm at protected.alg",
    );
  }

  // A supported JOSE algorithm that the caller did not allowlist.
  const p384 = createEcPair("merchant-p384", "secp384r1", "ES384");
  const es384Header = { alg: "ES384", kid: p384.publicJwk.kid, typ: "JWT" };
  const protectedSegment = Buffer.from(JSON.stringify(es384Header), "utf8").toString("base64url");
  const payloadSegment = Buffer.from(JSON.stringify(validClaims), "utf8").toString("base64url");
  const unsignedJwt = `${protectedSegment}.${payloadSegment}`;
  signatureRejection(
    `${unsignedJwt}.${Buffer.alloc(96, 1).toString("base64url")}`,
    "Protected JOSE algorithm is not allowlisted",
  );
});

test("attacker-controlled and unknown JOSE header parameters are refused", () => {
  for (const extra of [
    { crit: [] },
    { jku: "https://attacker.example/keys" },
    { jwk: merchant.publicJwk },
    { x5u: "https://attacker.example/certs" },
    { x5c: ["cert"] },
    { b64: false },
  ]) {
    const header = { alg: "ES256", kid: merchant.publicJwk.kid, typ: "JWT", ...extra };
    signatureRejection(
      createJwt(validClaims, merchant, header),
      "Unsupported or attacker-controlled JOSE header parameter",
    );
  }

  signatureRejection(
    createJwt(validClaims, merchant, { alg: "ES256", kid: merchant.publicJwk.kid, typ: "JWT", nonce: "x" }),
    "Unexpected protected JOSE header parameter",
  );
});

test("an issuer-mode protected header without kid is refused", () => {
  const header = { alg: "ES256", typ: "JWT" };
  const protectedSegment = Buffer.from(JSON.stringify(header), "utf8").toString("base64url");
  const payloadSegment = Buffer.from(JSON.stringify(validClaims), "utf8").toString("base64url");
  const unsignedJwt = `${protectedSegment}.${payloadSegment}`;
  signatureRejection(
    `${unsignedJwt}.${Buffer.alloc(64, 1).toString("base64url")}`,
    "Protected JOSE header is missing kid",
  );
});

test("malformed JWK members are refused", () => {
  const signed = createJwt(validClaims, merchant);
  // The snapshot kid stays pinned to the header kid so these cases reach the
  // JWK-level guards instead of being refused earlier by the kid pin.
  const withJwk = (jwk) => keySnapshot(merchant, { jwk, kid: merchant.publicJwk.kid });

  signatureRejection(
    signed,
    "JWK contains an unsupported member",
    withJwk({ ...merchant.publicJwk, ext: true }),
  );
  signatureRejection(
    signed,
    "JOSE algorithm and EC key curve do not match",
    withJwk({ ...merchant.publicJwk, crv: "P-384" }),
  );
  signatureRejection(
    signed,
    "JOSE algorithm and EC key curve do not match",
    withJwk({ ...merchant.publicJwk, kty: "RSA" }),
  );
  // `d` and `k` are not in the JWK member allowlist, so the allowlist guard
  // refuses them before the dedicated private-material guard is reached. That
  // is defence in depth: both paths fail closed, the allowlist simply fires
  // first and names the member it did not expect.
  signatureRejection(
    signed,
    "JWK contains an unsupported member",
    withJwk({ ...merchant.publicJwk, d: "AAAA" }),
  );
  signatureRejection(
    signed,
    "JWK contains an unsupported member",
    withJwk({ ...merchant.publicJwk, k: "AAAA" }),
  );
  signatureRejection(
    signed,
    "JWK alg does not match the protected algorithm",
    withJwk({ ...merchant.publicJwk, alg: "ES512" }),
  );
  signatureRejection(
    signed,
    "JWK use is not signature verification",
    withJwk({ ...merchant.publicJwk, use: "enc" }),
  );
  signatureRejection(
    signed,
    "JWK kid must be a non-empty string",
    withJwk({ ...merchant.publicJwk, kid: 7 }),
  );
  signatureRejection(
    signed,
    "JWK key_ops must be the verification operation",
    withJwk({ ...merchant.publicJwk, key_ops: ["sign"] }),
  );
  signatureRejection(
    signed,
    "JWK key_ops must be the verification operation",
    withJwk({ ...merchant.publicJwk, key_ops: "verify" }),
  );
  signatureRejection(
    signed,
    "EC coordinate length does not match the selected curve",
    withJwk({ ...merchant.publicJwk, x: Buffer.alloc(16, 7).toString("base64url") }),
  );
  signatureRejection(
    signed,
    "EC coordinate length does not match the selected curve",
    withJwk({ ...merchant.publicJwk, y: Buffer.alloc(48, 7).toString("base64url") }),
  );
  signatureRejection(
    signed,
    "JWK kid does not match the pinned key identifier",
    withJwk({ ...merchant.publicJwk, kid: "some-other-kid" }),
  );
});

test("a signature that is not a fixed-width raw r||s value is refused", () => {
  for (const length of [0, 63, 65]) {
    const header = { alg: "ES256", kid: merchant.publicJwk.kid, typ: "JWT" };
    const protectedSegment = Buffer.from(JSON.stringify(header), "utf8").toString("base64url");
    const payloadSegment = Buffer.from(JSON.stringify(validClaims), "utf8").toString("base64url");
    const unsignedJwt = `${protectedSegment}.${payloadSegment}`;
    if (length === 0) {
      // A zero-length signature fails the segment check in the parser.
      const report = verify(`${unsignedJwt}.`);
      assert.equal(report.upstreamValid, false);
      assert.equal(
        report.issues.some((entry) => entry.code === "AP2_CHECKOUT_JWT_INVALID"),
        true,
      );
      continue;
    }
    signatureRejection(
      `${unsignedJwt}.${Buffer.alloc(length, 3).toString("base64url")}`,
      "ECDSA signature must use 64-byte fixed-width raw r||s encoding",
    );
  }
});

test("a valid signature under the wrong key is refused", () => {
  // Same pinned kid, different key material: the kid pin matches and the
  // signature itself is what must fail.
  const other = createEcPair(merchant.publicJwk.kid);
  const token = createJwt(validClaims, other);
  const report = verify(token);
  assert.equal(report.upstreamValid, false);
  const issue = report.issues.find((entry) => entry.code === "AP2_CHECKOUT_JWT_SIGNATURE_INVALID");
  assert.equal(issue.message, "JWT signature verification failed");
});

test("the verified merchant key identity is echoed back", () => {
  const report = verify(createJwt(validClaims, merchant));
  assert.equal(report.value.merchantKid, merchant.publicJwk.kid);
  assert.equal(report.value.merchantAlgorithm, "ES256");
  assert.equal(report.value.authorizesNativeRole, false);
});

test("the exact presented token is preserved, not a re-encoding", () => {
  const token = createJwt(validClaims, merchant);
  const report = verify(token);
  assert.equal(report.value.exactToken, token);
});
