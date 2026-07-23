import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { sha256Digest } from "../dist/canonical.js";
import {
  createDetachedProof,
  createSignedArtifact,
  decodeProofHeader,
  exportPublicJwk,
  jwkThumbprint,
  verifyDetachedProof,
  verifySignedArtifactDigest,
} from "../dist/crypto.js";
import {
  resolveTrustedKey,
  verifyDigestPinnedTrustSnapshot,
  verifyPinnedTrustSnapshot,
  verifyProofWithTrust,
} from "../dist/trust.js";
import { createSchemaRegistry, schemaDigestForArtifactType, SCHEMA_IDS } from "../dist/validation.js";

const signedAt = "2026-01-01T00:00:00.000Z";

test("proofs bind Ed25519 key, artifact type, schema, purpose, and payload", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const other = generateKeyPairSync("ed25519");
  const publicJwk = exportPublicJwk(publicKey);
  const schemaDigest = sha256Digest({ schema: 1 });
  const payload = { artifactId: "example-1", value: 7 };
  const proof = createDetachedProof(payload, privateKey, {
    artifactType: "runtime_event",
    schemaDigest,
    purpose: "runtime_observation",
    signedAt,
  });

  const verified = verifyDetachedProof(payload, proof, publicJwk, {
    artifactType: "runtime_event", schemaDigest, purpose: "runtime_observation",
  });
  assert.equal(verified.ok, true);
  assert.equal(verified.value.kid, jwkThumbprint(publicJwk));
  assert.equal(verifyDetachedProof({ ...payload, value: 8 }, proof, publicJwk).ok, false);
  assert.equal(verifyDetachedProof(payload, proof, exportPublicJwk(other.publicKey)).ok, false);
  assert.equal(verifyDetachedProof(payload, proof, publicJwk, { purpose: "incident_filing" }).ok, false);
  assert.equal(verifyDetachedProof(payload, proof, publicJwk, { schemaDigest: sha256Digest({ other: 1 }) }).ok, false);
  assert.equal(verifyDetachedProof(payload, proof, publicJwk, { schemaDigest: schemaDigestForArtifactType("incident_report") }).ok, false);
  assert.equal(verifyDetachedProof(payload, proof, publicJwk, { signedAt: "2026-01-02T00:00:00.000Z" }).ok, false);
  assert.equal(verifyDetachedProof(payload, proof, publicJwk, { typ: "application/json" }).ok, false);
});

test("malformed proof headers, signatures, and key confusion fail closed", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicJwk = exportPublicJwk(publicKey);
  const schemaDigest = sha256Digest({ schema: 1 });
  const payload = { artifactId: "example-2" };
  const proof = createDetachedProof(payload, privateKey, {
    artifactType: "runtime_event", schemaDigest, purpose: "runtime_observation", signedAt,
  });
  const header = JSON.parse(Buffer.from(proof.protected, "base64url").toString("utf8"));
  const wrongAlgorithm = {
    ...proof,
    protected: Buffer.from(JSON.stringify({ ...header, alg: "HS256" }), "utf8").toString("base64url"),
  };
  const missingHeaderMember = { ...header };
  delete missingHeaderMember.typ;
  assert.equal(decodeProofHeader(wrongAlgorithm).ok, false);
  assert.equal(decodeProofHeader({
    ...proof,
    protected: Buffer.from(JSON.stringify(missingHeaderMember), "utf8").toString("base64url"),
  }).ok, false);
  assert.equal(decodeProofHeader({ protected: "***", signature: proof.signature }).ok, false);
  assert.equal(verifyDetachedProof(payload, { ...proof, signature: `${proof.signature}=` }, publicJwk).ok, false);
  assert.throws(() => createDetachedProof(payload, privateKey, {
    artifactType: "runtime_event", schemaDigest, purpose: "runtime_observation", signedAt,
    kid: `urn:agent-liability:jwk:${"A".repeat(43)}`,
  }), TypeError);
  assert.throws(() => createDetachedProof(payload, privateKey, {
    artifactType: "runtime_event", schemaDigest, purpose: "runtime_observation", signedAt, typ: "application/json",
  }), TypeError);
  assert.throws(() => createDetachedProof(payload, privateKey, {
    artifactType: "runtime_event", schemaDigest: "bad", purpose: "runtime_observation", signedAt,
  }), TypeError);
  assert.throws(() => createDetachedProof(payload, privateKey, {
    artifactType: "runtime_event", schemaDigest, purpose: "runtime_observation", signedAt: "not-a-time",
  }), TypeError);
  assert.throws(() => createDetachedProof(payload, publicKey, {
    artifactType: "runtime_event", schemaDigest, purpose: "runtime_observation", signedAt,
  }), TypeError);
  assert.throws(() => createDetachedProof(payload, privateKey, {
    artifactType: "not_an_artifact", schemaDigest, purpose: "runtime_observation", signedAt,
  }), TypeError);
  assert.throws(() => exportPublicJwk(generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey), TypeError);
  assert.throws(() => jwkThumbprint({ ...publicJwk, d: "attacker-private-material" }), TypeError);
  assert.throws(() => jwkThumbprint({ ...publicJwk, x: "short" }), TypeError);
  assert.throws(() => jwkThumbprint({ ...publicJwk, kty: "RSA" }), TypeError);
  assert.throws(() => jwkThumbprint({ ...publicJwk, key_ops: ["sign"] }), TypeError);
  assert.throws(() => jwkThumbprint({ ...publicJwk, attackerKeyHint: "ignored-no-longer" }), TypeError);
  assert.throws(() => jwkThumbprint(Object.create(publicJwk)), TypeError);
});

test("strict Ed25519 validation rejects identity, torsion, non-canonical, and off-curve public keys", () => {
  const identity = Buffer.alloc(32);
  identity[0] = 1;
  const orderFourPositive = Buffer.alloc(32);
  const orderFourNegative = Buffer.alloc(32);
  orderFourNegative[31] = 0x80;
  const orderTwo = Buffer.alloc(32, 0xff);
  orderTwo[0] = 0xec;
  orderTwo[31] = 0x7f;
  const nonCanonicalY = Buffer.alloc(32, 0xff);
  nonCanonicalY[0] = 0xed;
  nonCanonicalY[31] = 0x7f;
  const xZeroWithSign = Buffer.from(identity);
  xZeroWithSign[31] |= 0x80;
  const offCurve = Buffer.alloc(32);
  offCurve[0] = 2;

  const jwk = (bytes) => ({
    kty: "OKP", crv: "Ed25519", x: bytes.toString("base64url"), alg: "EdDSA", use: "sig", key_ops: ["verify"],
  });
  for (const encoded of [identity, orderFourPositive, orderFourNegative, orderTwo, nonCanonicalY, xZeroWithSign, offCurve]) {
    assert.throws(() => jwkThumbprint(jwk(encoded)), TypeError);
  }
});

test("identity-key signature forgery and non-canonical signature encodings fail closed", () => {
  const identity = Buffer.alloc(32);
  identity[0] = 1;
  const identityJwk = {
    kty: "OKP", crv: "Ed25519", x: identity.toString("base64url"), alg: "EdDSA", use: "sig", key_ops: ["verify"],
  };
  const payload = { artifactId: "identity-forgery-regression" };
  const forgedHeader = {
    alg: "EdDSA",
    artifactType: "runtime_event",
    canonicalization: "RFC8785",
    kid: `urn:agent-liability:jwk:${"A".repeat(43)}`,
    purpose: "runtime_observation",
    schemaDigest: sha256Digest({ schema: 1 }),
    signedAt,
    typ: "application/vnd.agent-liability.runtime-event+json",
  };
  const identityForgery = {
    protected: Buffer.from(JSON.stringify(forgedHeader), "utf8").toString("base64url"),
    signature: Buffer.concat([identity, Buffer.alloc(32)]).toString("base64url"),
  };
  assert.equal(verifyDetachedProof(payload, identityForgery, identityJwk).ok, false);

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const validJwk = exportPublicJwk(publicKey);
  const valid = createDetachedProof(payload, privateKey, {
    artifactType: "runtime_event",
    schemaDigest: sha256Digest({ schema: 1 }),
    purpose: "runtime_observation",
    signedAt,
  });
  const signatureBytes = Buffer.from(valid.signature, "base64url");
  const groupOrderEncoding = Buffer.from([
    "edd3f55c1a631258",
    "d69cf7a2def9de14",
    "0000000000000000",
    "0000000000000010",
  ].join(""), "hex");
  const nonCanonicalScalar = Buffer.from(signatureBytes);
  groupOrderEncoding.copy(nonCanonicalScalar, 32);

  const orderFourR = Buffer.alloc(32);
  const orderTwoR = Buffer.alloc(32, 0xff);
  orderTwoR[0] = 0xec;
  orderTwoR[31] = 0x7f;
  const nonCanonicalR = Buffer.alloc(32, 0xff);
  nonCanonicalR[0] = 0xed;
  nonCanonicalR[31] = 0x7f;
  const negativeZeroR = Buffer.from(identity);
  negativeZeroR[31] |= 0x80;
  const offCurveR = Buffer.alloc(32);
  offCurveR[0] = 2;

  const malformedSignatures = [
    signatureBytes.subarray(0, 63),
    Buffer.concat([signatureBytes, Buffer.from([0])]),
    nonCanonicalScalar,
    ...[orderFourR, orderTwoR, nonCanonicalR, negativeZeroR, offCurveR].map((r) => Buffer.concat([r, signatureBytes.subarray(32)])),
  ];
  for (const malformed of malformedSignatures) {
    assert.equal(
      verifyDetachedProof(payload, { ...valid, signature: malformed.toString("base64url") }, validJwk).ok,
      false,
    );
  }
});

test("signed artifact digest rejects payload mutation", () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const schemaDigest = sha256Digest({ schema: 1 });
  const artifact = createSignedArtifact({ artifactId: "a-1" }, privateKey, {
    artifactType: "incident_report",
    schemaId: SCHEMA_IDS.incident_report,
    schemaDigest,
    purpose: "incident_filing",
    signedAt,
  });
  assert.equal(verifySignedArtifactDigest(artifact).ok, true);
  assert.equal(verifySignedArtifactDigest({ ...artifact, payload: { artifactId: "a-2" } }).ok, false);
  assert.equal(verifySignedArtifactDigest({ ...artifact, payload: { unsupported: undefined } }).issues[0].code, "ALB_PROOF_INVALID");
});

test("trust accepts only exact pinned snapshots and keys within them", () => {
  const registry = createSchemaRegistry();
  const root = generateKeyPairSync("ed25519");
  const operator = generateKeyPairSync("ed25519");
  const attacker = generateKeyPairSync("ed25519");
  const operatorJwk = exportPublicJwk(operator.publicKey);
  const operatorKid = jwkThumbprint(operatorJwk);
  const snapshot = {
    schemaVersion: "1.0.0",
    artifactId: "trust-1",
    revision: 1,
    issuedAt: "2025-12-31T00:00:00.000Z",
    asOf: signedAt,
    issuer: { id: "root-1", role: "trust_publisher" },
    keys: [{
      kid: operatorKid,
      publicKey: operatorJwk,
      roles: ["operator"],
      purposes: ["execution_attestation"],
      validFrom: "2025-01-01T00:00:00.000Z",
      validUntil: "2027-01-01T00:00:00.000Z",
      scopes: ["operator-1"],
    }],
  };
  const schemaDigest = registry.schemaDigest("trust_snapshot");
  const signTrust = (payload, proofTime = signedAt) => createSignedArtifact(payload, root.privateKey, {
    artifactType: "trust_snapshot",
    schemaId: SCHEMA_IDS.trust_snapshot,
    schemaDigest,
    purpose: "trust_snapshot_issuance",
    signedAt: proofTime,
  });
  const signedSnapshot = signTrust(snapshot);
  const pin = sha256Digest(snapshot);
  const verified = verifyPinnedTrustSnapshot(signedSnapshot, pin, exportPublicJwk(root.publicKey));
  assert.equal(verified.ok, true, JSON.stringify(verified.issues));
  assert.equal(verified.value.publisherAuthenticated, true);
  assert.equal(Object.isFrozen(verified.value.snapshot), true);
  assert.equal(Object.isFrozen(verified.value.snapshot.keys), true);
  assert.equal(Object.isFrozen(verified.value.snapshot.keys[0].publicKey), true);
  assert.equal(verifyPinnedTrustSnapshot(signedSnapshot, sha256Digest({ wrong: true }), exportPublicJwk(root.publicKey)).ok, false);
  assert.equal(verifyPinnedTrustSnapshot(signedSnapshot, pin, exportPublicJwk(attacker.publicKey)).ok, false);
  assert.equal(verifyPinnedTrustSnapshot(signedSnapshot, pin, exportPublicJwk(root.publicKey), "2025-01-01T00:00:00.000Z").ok, false);
  assert.equal(verifyPinnedTrustSnapshot(signedSnapshot, pin, exportPublicJwk(root.publicKey), "not-a-time").issues[0].code, "ALB_SCHEMA_INVALID");
  assert.equal(verifyPinnedTrustSnapshot(signedSnapshot, pin, { ...exportPublicJwk(root.publicKey), x: "short" }).issues[0].code, "ALB_TRUST_ROOT_INVALID");
  assert.equal(verifyPinnedTrustSnapshot({ ...signedSnapshot, artifactType: "runtime_event" }, pin).issues[0].code, "ALB_TRUST_ROOT_INVALID");
  assert.equal(verifyPinnedTrustSnapshot({ ...signedSnapshot, format: "wrong-format" }, pin).issues[0].code, "ALB_TRUST_ROOT_INVALID");
  assert.equal(verifyPinnedTrustSnapshot({
    ...signedSnapshot,
    payload: { ...snapshot, artifactId: "trust-mutated" },
  }, pin).issues[0].code, "ALB_DIGEST_MISMATCH");

  const invalidSnapshots = [
    { ...snapshot, artifactId: "bad-issuer", issuer: { id: "root-1", role: "operator" } },
    { ...snapshot, artifactId: "duplicate-kid", keys: [snapshot.keys[0], snapshot.keys[0]] },
    { ...snapshot, artifactId: "mismatched-kid", keys: [{ ...snapshot.keys[0], kid: `urn:agent-liability:jwk:${"B".repeat(43)}` }] },
    { ...snapshot, artifactId: "bad-public-key", keys: [{ ...snapshot.keys[0], publicKey: { ...operatorJwk, x: "short" } }] },
    { ...snapshot, artifactId: "bad-window", keys: [{ ...snapshot.keys[0], validUntil: snapshot.keys[0].validFrom }] },
    { ...snapshot, artifactId: "bad-revocation", keys: [{ ...snapshot.keys[0], invalidFrom: "not-a-time" }] },
  ];
  for (const invalidSnapshot of invalidSnapshots) {
    const artifact = signTrust(invalidSnapshot);
    assert.equal(verifyDigestPinnedTrustSnapshot(artifact, sha256Digest(invalidSnapshot)).ok, false);
  }

  const digestOnly = verifyDigestPinnedTrustSnapshot(signedSnapshot, pin);
  assert.equal(digestOnly.ok, true);
  assert.equal(digestOnly.value.publisherAuthenticated, false);
  assert.equal(resolveTrustedKey(verified.value, {
    kid: operatorKid, role: "operator", purpose: "execution_attestation", at: signedAt, scope: "operator-1",
  }).ok, true);
  assert.equal(resolveTrustedKey(verified.value, {
    kid: jwkThumbprint(exportPublicJwk(attacker.publicKey)), role: "operator", purpose: "execution_attestation", at: signedAt,
  }).ok, false);
  const expired = resolveTrustedKey(verified.value, {
    kid: operatorKid, role: "operator", purpose: "execution_attestation", at: "2027-01-01T00:00:00.000Z",
  });
  assert.equal(expired.ok, false);
  assert.equal(expired.issues[0].code, "ALB_TRUST_KEY_EXPIRED");
  const notYetValid = resolveTrustedKey(verified.value, {
    kid: operatorKid, role: "operator", purpose: "execution_attestation", at: "2024-12-31T23:59:59.999Z",
  });
  assert.equal(notYetValid.ok, false);
  assert.equal(notYetValid.issues[0].code, "ALB_TRUST_KEY_NOT_YET_VALID");
  assert.equal(resolveTrustedKey(verified.value, {
    kid: operatorKid, role: "operator", purpose: "incident_filing", at: signedAt,
  }).issues[0].code, "ALB_TRUST_PURPOSE_DENIED");
  assert.equal(resolveTrustedKey(verified.value, {
    kid: operatorKid, role: "operator", purpose: "execution_attestation", at: signedAt, scope: "other-operator",
  }).issues[0].code, "ALB_TRUST_SCOPE_DENIED");
  assert.equal(resolveTrustedKey(verified.value, {
    kid: operatorKid, role: "operator", purpose: "execution_attestation", at: "not-a-time",
  }).issues[0].code, "ALB_SCHEMA_INVALID");
  assert.equal(resolveTrustedKey({ snapshot }, {
    kid: operatorKid, role: "operator", purpose: "execution_attestation", at: signedAt,
  }).issues[0].code, "ALB_TRUST_PIN_MISMATCH");

  const revokedSnapshot = {
    ...snapshot,
    artifactId: "trust-2",
    revision: 2,
    keys: [{ ...snapshot.keys[0], invalidFrom: "2025-12-01T00:00:00.000Z" }],
  };
  const revokedArtifact = createSignedArtifact(revokedSnapshot, root.privateKey, {
    artifactType: "trust_snapshot",
    schemaId: SCHEMA_IDS.trust_snapshot,
    schemaDigest,
    purpose: "trust_snapshot_issuance",
    signedAt,
  });
  const revokedTrust = verifyDigestPinnedTrustSnapshot(revokedArtifact, sha256Digest(revokedSnapshot));
  assert.equal(revokedTrust.ok, true);
  const revoked = resolveTrustedKey(revokedTrust.value, {
    kid: operatorKid, role: "operator", purpose: "execution_attestation", at: signedAt,
  });
  assert.equal(revoked.ok, false);
  assert.equal(revoked.issues[0].code, "ALB_TRUST_KEY_REVOKED");

  const receiptPayload = { artifactId: "receipt-1", executionId: "exec-1" };
  const receiptProof = createDetachedProof(receiptPayload, operator.privateKey, {
    artifactType: "execution_receipt",
    schemaDigest: sha256Digest({ receiptSchema: 1 }),
    purpose: "execution_attestation",
    signedAt,
  });
  assert.equal(verifyProofWithTrust(receiptPayload, receiptProof, verified.value, {
    role: "operator",
    purpose: "execution_attestation",
    artifactType: "execution_receipt",
    at: "2026-01-01T00:00:01.000Z",
    scope: "operator-1",
  }).ok, true);
  assert.equal(verifyProofWithTrust(receiptPayload, receiptProof, verified.value, {
    role: "principal",
    purpose: "execution_attestation",
    artifactType: "execution_receipt",
    at: "2026-01-01T00:00:01.000Z",
  }).ok, false);
  assert.equal(verifyProofWithTrust(receiptPayload, receiptProof, verified.value, {
    role: "operator",
    purpose: "execution_attestation",
    artifactType: "execution_receipt",
    at: "2025-12-31T23:59:59.999Z",
  }).ok, false);
  assert.equal(verifyProofWithTrust(receiptPayload, receiptProof, verified.value, {
    role: "operator",
    purpose: "incident_filing",
    artifactType: "execution_receipt",
    at: "2026-01-01T00:00:01.000Z",
  }).issues[0].code, "ALB_PROOF_BINDING");
  assert.equal(verifyProofWithTrust(receiptPayload, receiptProof, verified.value, {
    role: "operator",
    purpose: "execution_attestation",
    artifactType: "execution_receipt",
    at: "not-a-time",
  }).issues[0].code, "ALB_SCHEMA_INVALID");
  assert.equal(verifyProofWithTrust(receiptPayload, { ...receiptProof, protected: "***" }, verified.value, {
    role: "operator",
    purpose: "execution_attestation",
    artifactType: "execution_receipt",
    at: "2026-01-01T00:00:01.000Z",
  }).ok, false);

  const mutableSnapshot = {
    ...snapshot,
    artifactId: "trust-mutation-isolation",
    keys: [{ ...snapshot.keys[0], scopes: ["operator-1"] }],
  };
  const mutableArtifact = signTrust(mutableSnapshot);
  const isolated = verifyDigestPinnedTrustSnapshot(mutableArtifact, sha256Digest(mutableSnapshot));
  assert.equal(isolated.ok, true);
  mutableSnapshot.keys[0].scopes.push("post-verification-attacker");
  assert.equal(resolveTrustedKey(isolated.value, {
    kid: operatorKid,
    role: "operator",
    purpose: "execution_attestation",
    at: signedAt,
    scope: "post-verification-attacker",
  }).issues[0].code, "ALB_TRUST_SCOPE_DENIED");
});

test("future-dated root proofs cannot authenticate a historical trust decision", () => {
  const root = generateKeyPairSync("ed25519");
  const trusted = generateKeyPairSync("ed25519");
  const trustedJwk = exportPublicJwk(trusted.publicKey);
  const snapshot = {
    schemaVersion: "1.0.0",
    artifactId: "trust-future-proof",
    revision: 1,
    issuedAt: "2026-01-01T00:00:00.000Z",
    asOf: "2026-01-01T00:00:00.000Z",
    issuer: { id: "root-1", role: "trust_publisher" },
    keys: [{
      kid: jwkThumbprint(trustedJwk), publicKey: trustedJwk, roles: ["operator"],
      purposes: ["execution_attestation"], validFrom: "2025-01-01T00:00:00.000Z",
      validUntil: "2027-01-01T00:00:00.000Z", scopes: [],
    }],
  };
  const artifact = createSignedArtifact(snapshot, root.privateKey, {
    artifactType: "trust_snapshot",
    schemaId: SCHEMA_IDS.trust_snapshot,
    schemaDigest: schemaDigestForArtifactType("trust_snapshot"),
    purpose: "trust_snapshot_issuance",
    signedAt: "2026-02-01T00:00:00.000Z",
  });
  const result = verifyPinnedTrustSnapshot(
    artifact,
    sha256Digest(snapshot),
    exportPublicJwk(root.publicKey),
    "2026-01-15T00:00:00.000Z",
  );
  assert.equal(result.ok, false);
  assert.equal(result.issues[0].code, "ALB_TRUST_ROOT_INVALID");
});
