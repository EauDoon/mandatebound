import { equalDigest, sha256Digest } from "./canonical.js";
import {
  decodeProofHeader,
  jwkThumbprint,
  verifyDetachedProof,
  verifySignedArtifactDigest,
  type ProofExpectation,
} from "./crypto.js";
import type {
  ActorRole,
  DetachedProof,
  Ed25519PublicJwk,
  KeyId,
  ProofHeader,
  ProofPurpose,
  Rfc3339Timestamp,
  Sha256Digest,
  SignedArtifact,
  TrustKey,
  TrustSnapshot,
  ValidationIssue,
  ValidationResult,
} from "./domain.js";

const RFC3339_MILLISECONDS = /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/;

const VERIFIED_SNAPSHOT: unique symbol = Symbol("verified-trust-snapshot");

/** Can only be constructed by exact digest pinning plus a pinned-root proof. */
export interface VerifiedTrustSnapshot {
  readonly [VERIFIED_SNAPSHOT]: true;
  readonly snapshot: TrustSnapshot;
  readonly digest: Sha256Digest;
  readonly pinnedRootKid?: KeyId;
  readonly publisherAuthenticated: boolean;
}

export interface TrustResolutionRequirements {
  readonly kid: KeyId;
  readonly role: ActorRole;
  readonly purpose: ProofPurpose;
  readonly at: Rfc3339Timestamp;
  readonly scope?: string;
}

export interface TrustedProofRequirements extends Omit<TrustResolutionRequirements, "kid" | "at" | "purpose">, Omit<ProofExpectation, "purpose"> {
  /** Evaluation cutoff. Proofs after this instant are rejected. */
  readonly at: Rfc3339Timestamp;
  readonly purpose: ProofPurpose;
}

function fail<T>(code: ValidationIssue["code"], path: string, message: string): ValidationResult<T> {
  return { ok: false, issues: [{ code, path, message }] };
}

function isTimestamp(value: string): boolean {
  if (!RFC3339_MILLISECONDS.test(value)) return false;
  const date = new Date(value);
  return !Number.isNaN(date.valueOf()) && date.toISOString() === value;
}

function validateSnapshotKeySet(snapshot: TrustSnapshot): ValidationResult<TrustSnapshot> {
  if (snapshot.issuer.role !== "trust_publisher" || !isTimestamp(snapshot.issuedAt) || !isTimestamp(snapshot.asOf)) {
    return fail("ALB_SCHEMA_INVALID", "/issuer", "Trust snapshot publisher or timestamp is invalid");
  }
  const seen = new Set<string>();
  for (let index = 0; index < snapshot.keys.length; index += 1) {
    const entry = snapshot.keys[index] as TrustKey;
    if (seen.has(entry.kid)) {
      return fail("ALB_SCHEMA_INVALID", `/keys/${index}/kid`, "Trust snapshot contains a duplicate key identifier");
    }
    seen.add(entry.kid);
    try {
      if (jwkThumbprint(entry.publicKey) !== entry.kid) {
        return fail("ALB_TRUST_KEY_NOT_FOUND", `/keys/${index}/kid`, "Trust key identifier does not match its public key");
      }
    } catch {
      return fail("ALB_TRUST_KEY_NOT_FOUND", `/keys/${index}/publicKey`, "Trust snapshot contains an invalid public key");
    }
    if (!isTimestamp(entry.validFrom) || !isTimestamp(entry.validUntil) || entry.validFrom >= entry.validUntil) {
      return fail("ALB_SCHEMA_INVALID", `/keys/${index}`, "Trust key validity window is invalid");
    }
    if (entry.invalidFrom !== undefined && !isTimestamp(entry.invalidFrom)) {
      return fail("ALB_SCHEMA_INVALID", `/keys/${index}/invalidFrom`, "Trust key invalidation time is invalid");
    }
  }
  return { ok: true, value: snapshot, issues: [] };
}

function freezeTrustSnapshot(snapshot: TrustSnapshot): TrustSnapshot {
  const keys = snapshot.keys.map((entry) => {
    const keyOperations = entry.publicKey.key_ops;
    const publicKey: Ed25519PublicJwk = Object.freeze({
      kty: entry.publicKey.kty,
      crv: entry.publicKey.crv,
      x: entry.publicKey.x,
      ...(entry.publicKey.alg === undefined ? {} : { alg: entry.publicKey.alg }),
      ...(entry.publicKey.use === undefined ? {} : { use: entry.publicKey.use }),
      ...(keyOperations === undefined
        ? {}
        : { key_ops: Object.freeze([...keyOperations]) as NonNullable<Ed25519PublicJwk["key_ops"]> }),
    });
    return Object.freeze({
      kid: entry.kid,
      publicKey,
      roles: Object.freeze([...entry.roles]),
      purposes: Object.freeze([...entry.purposes]),
      validFrom: entry.validFrom,
      validUntil: entry.validUntil,
      ...(entry.invalidFrom === undefined ? {} : { invalidFrom: entry.invalidFrom }),
      scopes: Object.freeze([...entry.scopes]),
    });
  });
  return Object.freeze({
    schemaVersion: snapshot.schemaVersion,
    artifactId: snapshot.artifactId,
    revision: snapshot.revision,
    issuedAt: snapshot.issuedAt,
    asOf: snapshot.asOf,
    issuer: Object.freeze({ id: snapshot.issuer.id, role: snapshot.issuer.role }),
    ...(snapshot.previousSnapshotDigest === undefined
      ? {}
      : { previousSnapshotDigest: snapshot.previousSnapshotDigest }),
    keys: Object.freeze(keys),
  });
}

export function trustSnapshotDigest(snapshot: TrustSnapshot | SignedArtifact<TrustSnapshot>): Sha256Digest {
  return sha256Digest("payload" in snapshot ? snapshot.payload : snapshot);
}

/**
 * Authenticate a snapshot solely through caller-pinned material. Keys embedded
 * in the snapshot are never used to authenticate the snapshot itself.
 */
export function verifyPinnedTrustSnapshot(
  artifact: SignedArtifact<TrustSnapshot>,
  pinnedDigest: Sha256Digest,
  pinnedRootJwk?: Ed25519PublicJwk,
  evaluationCutoff?: Rfc3339Timestamp,
): ValidationResult<VerifiedTrustSnapshot> {
  if (artifact.artifactType !== "trust_snapshot" || artifact.format !== "agent-liability-signed-artifact/v1") {
    return fail("ALB_TRUST_ROOT_INVALID", "/artifactType", "Pinned trust artifact type is invalid");
  }
  const digestCheck = verifySignedArtifactDigest(artifact);
  if (!digestCheck.ok) return digestCheck as ValidationResult<VerifiedTrustSnapshot>;
  let actualDigest: Sha256Digest;
  try {
    actualDigest = trustSnapshotDigest(artifact);
  } catch {
    return fail("ALB_DIGEST_MISMATCH", "/payload", "Trust snapshot payload cannot be content addressed");
  }
  if (!equalDigest(actualDigest, pinnedDigest)) {
    return fail("ALB_TRUST_PIN_MISMATCH", "/payloadDigest", "Trust snapshot does not match the exact pinned digest");
  }
  const keySet = validateSnapshotKeySet(artifact.payload);
  if (!keySet.ok) return keySet as ValidationResult<VerifiedTrustSnapshot>;
  const stableSnapshot = freezeTrustSnapshot(artifact.payload);
  if (evaluationCutoff !== undefined) {
    if (!isTimestamp(evaluationCutoff)) {
      return fail("ALB_SCHEMA_INVALID", "/evaluationCutoff", "Trust evaluation timestamp is invalid");
    }
    if (artifact.payload.asOf > evaluationCutoff) {
      return fail("ALB_PROOF_BINDING", "/payload/asOf", "Trust snapshot is newer than the evaluation cutoff");
    }
  }

  if (pinnedRootJwk === undefined) {
    const result: VerifiedTrustSnapshot = {
      [VERIFIED_SNAPSHOT]: true,
      snapshot: stableSnapshot,
      digest: actualDigest,
      publisherAuthenticated: false,
    };
    return { ok: true, value: result, issues: [] };
  }

  let rootKid: KeyId;
  try {
    rootKid = jwkThumbprint(pinnedRootJwk);
  } catch {
    return fail("ALB_TRUST_ROOT_INVALID", "/pinnedRoot", "Pinned trust root is not a valid Ed25519 public key");
  }

  for (const proof of artifact.proofs) {
    const header = decodeProofHeader(proof);
    if (!header.ok || header.value.kid !== rootKid) continue;
    if (evaluationCutoff !== undefined && header.value.signedAt > evaluationCutoff) continue;
    const verified = verifyDetachedProof(artifact.payload, proof, pinnedRootJwk, {
      artifactType: "trust_snapshot",
      purpose: "trust_snapshot_issuance",
      kid: rootKid,
    });
    if (verified.ok) {
      const result: VerifiedTrustSnapshot = {
        [VERIFIED_SNAPSHOT]: true,
        snapshot: stableSnapshot,
        digest: actualDigest,
        pinnedRootKid: rootKid,
        publisherAuthenticated: true,
      };
      return { ok: true, value: result, issues: [] };
    }
  }
  return fail("ALB_TRUST_ROOT_INVALID", "/proofs", "Trust snapshot lacks a valid proof from the pinned root");
}

/** Exact caller pin is the trust anchor when publisher authentication is unavailable. */
export function verifyDigestPinnedTrustSnapshot(
  artifact: SignedArtifact<TrustSnapshot>,
  pinnedDigest: Sha256Digest,
  evaluationCutoff?: Rfc3339Timestamp,
): ValidationResult<VerifiedTrustSnapshot> {
  return verifyPinnedTrustSnapshot(artifact, pinnedDigest, undefined, evaluationCutoff);
}

export function resolveTrustedKey(
  verified: VerifiedTrustSnapshot,
  requirements: TrustResolutionRequirements,
): ValidationResult<TrustKey> {
  if (verified[VERIFIED_SNAPSHOT] !== true) {
    return fail("ALB_TRUST_PIN_MISMATCH", "/trustSnapshot", "Trust snapshot has not been pinned and authenticated");
  }
  if (!isTimestamp(requirements.at)) {
    return fail("ALB_SCHEMA_INVALID", "/at", "Trust evaluation timestamp is invalid");
  }
  const matches = verified.snapshot.keys.filter((entry) => entry.kid === requirements.kid);
  if (matches.length !== 1) {
    return fail("ALB_TRUST_KEY_NOT_FOUND", "/proof/kid", "Proof key is not uniquely present in the pinned trust snapshot");
  }
  const entry = matches[0] as TrustKey;
  try {
    if (jwkThumbprint(entry.publicKey) !== entry.kid) {
      return fail("ALB_TRUST_KEY_NOT_FOUND", "/proof/kid", "Trusted key identifier is invalid");
    }
  } catch {
    return fail("ALB_TRUST_KEY_NOT_FOUND", "/proof/kid", "Trusted public key is invalid");
  }
  if (!entry.roles.includes(requirements.role)) {
    return fail("ALB_TRUST_ROLE_DENIED", "/proof/kid", "Trusted key is not authorized for the required role");
  }
  if (!entry.purposes.includes(requirements.purpose)) {
    return fail("ALB_TRUST_PURPOSE_DENIED", "/proof/purpose", "Trusted key is not authorized for the required purpose");
  }
  if (requirements.scope !== undefined && !entry.scopes.includes(requirements.scope)) {
    return fail("ALB_TRUST_SCOPE_DENIED", "/proof/kid", "Trusted key is not authorized for the required scope");
  }
  if (requirements.at < entry.validFrom) {
    return fail("ALB_TRUST_KEY_NOT_YET_VALID", "/proof/signedAt", "Trusted key was not valid at the proof time");
  }
  if (requirements.at >= entry.validUntil) {
    return fail("ALB_TRUST_KEY_EXPIRED", "/proof/signedAt", "Trusted key had expired at the proof time");
  }
  if (entry.invalidFrom !== undefined && requirements.at >= entry.invalidFrom) {
    return fail("ALB_TRUST_KEY_REVOKED", "/proof/signedAt", "Trusted key was invalid at the proof time");
  }
  return { ok: true, value: entry, issues: [] };
}

export function verifyProofWithTrust(
  payload: unknown,
  proof: DetachedProof,
  verified: VerifiedTrustSnapshot,
  requirements: TrustedProofRequirements,
): ValidationResult<ProofHeader> {
  const decoded = decodeProofHeader(proof);
  if (!decoded.ok) return decoded;
  const header = decoded.value;
  if (!isTimestamp(requirements.at)) {
    return fail("ALB_SCHEMA_INVALID", "/at", "Trust evaluation timestamp is invalid");
  }
  if (header.signedAt > requirements.at) {
    return fail("ALB_PROOF_BINDING", "/proof/signedAt", "Proof was created after the evaluation cutoff");
  }
  if (header.purpose !== requirements.purpose) {
    return fail("ALB_PROOF_BINDING", "/proof/purpose", "Proof purpose binding does not match");
  }
  const key = resolveTrustedKey(verified, {
    kid: header.kid,
    role: requirements.role,
    purpose: requirements.purpose,
    at: header.signedAt,
    ...(requirements.scope === undefined ? {} : { scope: requirements.scope }),
  });
  if (!key.ok) return key as ValidationResult<ProofHeader>;
  return verifyDetachedProof(payload, proof, key.value.publicKey, {
    ...requirements,
    kid: header.kid,
    purpose: requirements.purpose,
  });
}
