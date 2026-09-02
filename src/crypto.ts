import { Buffer } from "node:buffer";
import {
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify,
  type JsonWebKeyInput,
  type KeyObject,
} from "node:crypto";
import { CanonicalizationError, canonicalBytes, canonicalize, equalDigest, isSha256Digest, sha256Digest } from "./canonical.js";
import {
  ARTIFACT_TYPES,
  PROOF_PURPOSES,
  type ArtifactType,
  type DetachedProof,
  type Ed25519PublicJwk,
  type KeyId,
  type ProofHeader,
  type ProofPurpose,
  type Rfc3339Timestamp,
  type Sha256Digest,
  type SignedArtifact,
  type ValidationIssue,
  type ValidationResult,
} from "./domain.js";
import { parseStrictJsonObject, StrictJsonError } from "./strict-json.js";

const DOMAIN = Buffer.from("AGENT-LIABILITY-PROOF-V1\0", "ascii");
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const RFC3339_MILLISECONDS = /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/;
const KEY_ID_PATTERN = /^urn:agent-liability:jwk:[A-Za-z0-9_-]{43}$/;
const ED25519_FIELD_MODULUS = (1n << 255n) - 19n;
const ED25519_GROUP_ORDER = (1n << 252n) + 27_742_317_777_372_353_535_851_937_790_883_648_493n;
const ED25519_D = 37_095_705_934_669_439_343_138_083_508_754_565_189_542_113_879_843_219_016_388_785_533_085_940_283_555n;
const ED25519_SQRT_MINUS_ONE = 19_681_161_376_707_505_956_807_079_304_988_542_015_446_066_515_923_890_162_744_021_073_123_829_784_752n;
const HEADER_KEYS = [
  "alg",
  "artifactType",
  "canonicalization",
  "kid",
  "purpose",
  "schemaDigest",
  "signedAt",
  "typ",
] as const;

interface EdwardsPoint {
  readonly x: bigint;
  readonly y: bigint;
  readonly z: bigint;
  readonly t: bigint;
}

const ED25519_IDENTITY: EdwardsPoint = Object.freeze({ x: 0n, y: 1n, z: 1n, t: 0n });

function field(value: bigint): bigint {
  const reduced = value % ED25519_FIELD_MODULUS;
  return reduced < 0n ? reduced + ED25519_FIELD_MODULUS : reduced;
}

function fieldPow(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  let factor = field(base);
  let remaining = exponent;
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) result = field(result * factor);
    factor = field(factor * factor);
    remaining >>= 1n;
  }
  return result;
}

function littleEndianInteger(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index] as number);
  }
  return value;
}

function encodeEd25519Point(point: EdwardsPoint): Buffer {
  if (point.z !== 1n) throw new TypeError("Ed25519 point is not affine");
  let y = field(point.y);
  const encoded = Buffer.alloc(32);
  for (let index = 0; index < encoded.length; index += 1) {
    encoded[index] = Number(y & 0xffn);
    y >>= 8n;
  }
  if (y !== 0n) throw new TypeError("Ed25519 point is not encodable");
  encoded[31] = (encoded[31] as number) | (Number(field(point.x) & 1n) << 7);
  return encoded;
}

function decodeEd25519Point(encoded: Uint8Array): EdwardsPoint {
  if (encoded.length !== 32) throw new TypeError("Invalid Ed25519 point length");
  const bytes = Buffer.from(encoded);
  const sign = (bytes[31] as number) >>> 7;
  bytes[31] = (bytes[31] as number) & 0x7f;
  const y = littleEndianInteger(bytes);
  if (y >= ED25519_FIELD_MODULUS) throw new TypeError("Non-canonical Ed25519 point encoding");

  const ySquared = field(y * y);
  const numerator = field(ySquared - 1n);
  const denominator = field(ED25519_D * ySquared + 1n);
  if (denominator === 0n) throw new TypeError("Invalid Ed25519 point");
  const xSquared = field(numerator * fieldPow(denominator, ED25519_FIELD_MODULUS - 2n));
  let x = fieldPow(xSquared, (ED25519_FIELD_MODULUS + 3n) >> 3n);
  if (field(x * x) !== xSquared) x = field(x * ED25519_SQRT_MINUS_ONE);
  if (field(x * x) !== xSquared) throw new TypeError("Encoded Ed25519 point is not on the curve");
  if (x === 0n && sign === 1) throw new TypeError("Non-canonical Ed25519 point sign");
  if (Number(x & 1n) !== sign) x = field(-x);
  const point = { x, y, z: 1n, t: field(x * y) };
  if (!encodeEd25519Point(point).equals(encoded)) {
    throw new TypeError("Non-canonical Ed25519 point encoding");
  }
  return point;
}

function addEd25519Points(left: EdwardsPoint, right: EdwardsPoint): EdwardsPoint {
  const a = field((left.y - left.x) * (right.y - right.x));
  const b = field((left.y + left.x) * (right.y + right.x));
  const c = field(2n * ED25519_D * left.t * right.t);
  const d = field(2n * left.z * right.z);
  const e = field(b - a);
  const f = field(d - c);
  const g = field(d + c);
  const h = field(b + a);
  return {
    x: field(e * f),
    y: field(g * h),
    z: field(f * g),
    t: field(e * h),
  };
}

function multiplyEd25519Point(point: EdwardsPoint, scalar: bigint): EdwardsPoint {
  let result = ED25519_IDENTITY;
  let addend = point;
  let remaining = scalar;
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) result = addEd25519Points(result, addend);
    addend = addEd25519Points(addend, addend);
    remaining >>= 1n;
  }
  return result;
}

function isEd25519Identity(point: EdwardsPoint): boolean {
  return field(point.x) === 0n && field(point.y - point.z) === 0n;
}

function assertPrimeOrderEd25519Point(encoded: Uint8Array, allowIdentity: boolean): void {
  const point = decodeEd25519Point(encoded);
  if (!allowIdentity && isEd25519Identity(point)) {
    throw new TypeError("Ed25519 public key must not be the identity point");
  }
  if (!isEd25519Identity(multiplyEd25519Point(point, ED25519_GROUP_ORDER))) {
    throw new TypeError("Ed25519 point is not in the prime-order subgroup");
  }
}

function assertEd25519SignatureEncoding(signature: Uint8Array): void {
  if (signature.length !== 64) throw new TypeError("Invalid Ed25519 signature length");
  assertPrimeOrderEd25519Point(signature.subarray(0, 32), true);
  if (littleEndianInteger(signature.subarray(32)) >= ED25519_GROUP_ORDER) {
    throw new TypeError("Non-canonical Ed25519 signature scalar");
  }
}

export interface ProofOptions {
  readonly artifactType: ArtifactType;
  readonly schemaDigest: Sha256Digest;
  readonly purpose: ProofPurpose;
  readonly signedAt: Rfc3339Timestamp;
  readonly kid?: KeyId;
  readonly typ?: string;
}

export interface ProofExpectation {
  readonly artifactType?: ArtifactType;
  readonly schemaDigest?: Sha256Digest;
  readonly purpose?: ProofPurpose;
  readonly signedAt?: Rfc3339Timestamp;
  readonly kid?: KeyId;
  readonly typ?: string;
}

export interface SignedArtifactOptions extends ProofOptions {
  readonly schemaId: string;
}

function issue(code: ValidationIssue["code"], message: string): ValidationResult<never> {
  return { ok: false, issues: [{ code, path: "/proof", message }] };
}

function base64UrlEncode(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function base64UrlDecode(value: string, maxBytes: number): Buffer {
  if (!BASE64URL_PATTERN.test(value) || value.includes("=") || value.length > Math.ceil((maxBytes * 4) / 3) + 2) {
    throw new TypeError("Invalid base64url value");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length > maxBytes || decoded.toString("base64url") !== value) {
    throw new TypeError("Non-canonical base64url value");
  }
  return decoded;
}

function isTimestamp(value: unknown): value is Rfc3339Timestamp {
  if (typeof value !== "string" || !RFC3339_MILLISECONDS.test(value)) return false;
  const date = new Date(value);
  return !Number.isNaN(date.valueOf()) && date.toISOString() === value;
}

function mediaTypeFor(artifactType: ArtifactType): string {
  return `application/vnd.agent-liability.${artifactType.replaceAll("_", "-")}+json`;
}

function toPrivateKey(input: KeyObject | string | Buffer): KeyObject {
  const key = typeof input === "string" || Buffer.isBuffer(input) ? createPrivateKey(input) : input;
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    throw new TypeError("An Ed25519 private key is required");
  }
  return key;
}

function assertPublicJwk(value: Ed25519PublicJwk): void {
  const record = value as unknown as Record<string, unknown>;
  const allowedMembers = new Set(["kty", "crv", "x", "alg", "use", "key_ops"]);
  const members = Reflect.ownKeys(record);
  if (
    members.some((member) => typeof member !== "string" || !allowedMembers.has(member))
    || !Object.hasOwn(record, "kty")
    || !Object.hasOwn(record, "crv")
    || !Object.hasOwn(record, "x")
  ) {
    throw new TypeError("Public JWK contains an unsupported member");
  }
  if (record["d"] !== undefined || value.kty !== "OKP" || value.crv !== "Ed25519" || typeof value.x !== "string") {
    throw new TypeError("A public Ed25519 JWK is required");
  }
  if (value.alg !== undefined && value.alg !== "EdDSA") throw new TypeError("Invalid JWK algorithm binding");
  if (value.use !== undefined && value.use !== "sig") throw new TypeError("Invalid JWK use binding");
  if (value.key_ops !== undefined && (
    !Array.isArray(value.key_ops) ||
    value.key_ops.length !== 1 ||
    value.key_ops[0] !== "verify"
  )) {
    throw new TypeError("Invalid JWK operation binding");
  }
  const decoded = base64UrlDecode(value.x, 32);
  if (decoded.length !== 32) throw new TypeError("Invalid Ed25519 public key length");
  assertPrimeOrderEd25519Point(decoded, false);
}

export function exportPublicJwk(keyInput: KeyObject | string | Buffer): Ed25519PublicJwk {
  const key = typeof keyInput === "string" || Buffer.isBuffer(keyInput) ? createPublicKey(keyInput) : keyInput;
  const publicKey = key.type === "private"
    ? createPublicKey(key.export({ format: "pem", type: "pkcs8" }))
    : key;
  if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") {
    throw new TypeError("An Ed25519 key is required");
  }
  const exported = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  const jwk: Ed25519PublicJwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: String(exported["x"]),
    alg: "EdDSA",
    use: "sig",
    key_ops: ["verify"],
  };
  assertPublicJwk(jwk);
  return jwk;
}

/** RFC 7638 member selection and canonicalization for an OKP public key. */
export function jwkThumbprint(jwk: Ed25519PublicJwk): KeyId {
  assertPublicJwk(jwk);
  const digest = Buffer.from(sha256Digest({ crv: "Ed25519", kty: "OKP", x: jwk.x }).slice("sha256:".length), "hex");
  return `urn:agent-liability:jwk:${digest.toString("base64url")}`;
}

function signatureInput(protectedValue: string, payload: unknown): Buffer {
  const jwsInput = Buffer.from(`${protectedValue}.${base64UrlEncode(canonicalBytes(payload))}`, "ascii");
  return Buffer.concat([DOMAIN, jwsInput]);
}

export function createDetachedProof(
  payload: unknown,
  privateKeyInput: KeyObject | string | Buffer,
  options: ProofOptions,
): DetachedProof {
  if (!ARTIFACT_TYPES.includes(options.artifactType) || !PROOF_PURPOSES.includes(options.purpose)) {
    throw new TypeError("Invalid proof binding");
  }
  if (!isSha256Digest(options.schemaDigest) || !isTimestamp(options.signedAt)) {
    throw new TypeError("Invalid proof digest or timestamp binding");
  }
  const privateKey = toPrivateKey(privateKeyInput);
  const publicJwk = exportPublicJwk(privateKey);
  const actualKid = jwkThumbprint(publicJwk);
  if (options.kid !== undefined && options.kid !== actualKid) {
    throw new TypeError("Proof key identifier does not match the signing key");
  }
  const expectedType = mediaTypeFor(options.artifactType);
  if (options.typ !== undefined && options.typ !== expectedType) {
    throw new TypeError("Proof media type must match the bound artifact type");
  }
  const header: ProofHeader = {
    alg: "EdDSA",
    kid: actualKid,
    typ: expectedType,
    artifactType: options.artifactType,
    schemaDigest: options.schemaDigest,
    purpose: options.purpose,
    signedAt: options.signedAt,
    canonicalization: "RFC8785",
  };
  const protectedValue = base64UrlEncode(Buffer.from(canonicalize(header), "utf8"));
  const signature = nodeSign(null, signatureInput(protectedValue, payload), privateKey);
  return { protected: protectedValue, signature: base64UrlEncode(signature) };
}

export function decodeProofHeader(proof: DetachedProof): ValidationResult<ProofHeader> {
  try {
    const encoded = base64UrlDecode(proof.protected, 4_096);
    const parsed = parseStrictJsonObject(encoded.toString("utf8"), { maxBytes: 4_096, maxDepth: 4, maxObjectKeys: 16 });
    if (!encoded.equals(Buffer.from(canonicalize(parsed), "utf8"))) {
      return issue("ALB_PROOF_BINDING", "Protected proof header is not canonically encoded");
    }
    const keys = Object.keys(parsed).sort();
    if (keys.length !== HEADER_KEYS.length || HEADER_KEYS.some((key, index) => keys[index] !== key)) {
      return issue("ALB_PROOF_BINDING", "Protected proof header has an invalid shape");
    }
    if (
      parsed["alg"] !== "EdDSA"
      || parsed["canonicalization"] !== "RFC8785"
      || typeof parsed["kid"] !== "string"
      || !KEY_ID_PATTERN.test(parsed["kid"])
      || typeof parsed["artifactType"] !== "string"
      || !ARTIFACT_TYPES.includes(parsed["artifactType"] as ArtifactType)
      || typeof parsed["typ"] !== "string"
      || parsed["typ"] !== mediaTypeFor(parsed["artifactType"] as ArtifactType)
      || typeof parsed["schemaDigest"] !== "string"
      || !isSha256Digest(parsed["schemaDigest"])
      || typeof parsed["purpose"] !== "string"
      || !PROOF_PURPOSES.includes(parsed["purpose"] as ProofPurpose)
      || !isTimestamp(parsed["signedAt"])
    ) {
      return issue("ALB_PROOF_BINDING", "Protected proof header contains an invalid binding");
    }
    return { ok: true, value: parsed as unknown as ProofHeader, issues: [] };
  } catch (error: unknown) {
    if (error instanceof StrictJsonError || error instanceof TypeError) {
      return issue("ALB_PROOF_INVALID", "Protected proof header is malformed");
    }
    throw error;
  }
}

export function verifyDetachedProof(
  payload: unknown,
  proof: DetachedProof,
  publicJwk: Ed25519PublicJwk,
  expected: ProofExpectation = {},
): ValidationResult<ProofHeader> {
  const decoded = decodeProofHeader(proof);
  if (!decoded.ok) return decoded;
  const header = decoded.value;
  try {
    assertPublicJwk(publicJwk);
    const keyKid = jwkThumbprint(publicJwk);
    if (header.kid !== keyKid) return issue("ALB_PROOF_BINDING", "Proof key binding does not match");
    if (expected.kid !== undefined && header.kid !== expected.kid) return issue("ALB_PROOF_BINDING", "Proof key binding does not match");
    if (expected.artifactType !== undefined && header.artifactType !== expected.artifactType) return issue("ALB_PROOF_BINDING", "Proof artifact binding does not match");
    if (expected.schemaDigest !== undefined && !equalDigest(header.schemaDigest, expected.schemaDigest)) return issue("ALB_PROOF_BINDING", "Proof schema binding does not match");
    if (expected.purpose !== undefined && header.purpose !== expected.purpose) return issue("ALB_PROOF_BINDING", "Proof purpose binding does not match");
    if (expected.signedAt !== undefined && header.signedAt !== expected.signedAt) return issue("ALB_PROOF_BINDING", "Proof time binding does not match");
    if (expected.typ !== undefined && header.typ !== expected.typ) return issue("ALB_PROOF_BINDING", "Proof media-type binding does not match");
    const signature = base64UrlDecode(proof.signature, 64);
    assertEd25519SignatureEncoding(signature);
    const publicKey = createPublicKey({ key: publicJwk as unknown as JsonWebKeyInput["key"], format: "jwk" });
    if (!nodeVerify(null, signatureInput(proof.protected, payload), publicKey, signature)) {
      return issue("ALB_PROOF_INVALID", "Proof signature verification failed");
    }
    return { ok: true, value: header, issues: [] };
  } catch (error: unknown) {
    if (error instanceof CanonicalizationError || error instanceof TypeError || error instanceof RangeError) {
      return issue("ALB_PROOF_INVALID", "Proof or public key is malformed");
    }
    throw error;
  }
}

export function createSignedArtifact<T>(
  payload: T,
  privateKey: KeyObject | string | Buffer,
  options: SignedArtifactOptions,
): SignedArtifact<T> {
  const payloadDigest = sha256Digest(payload);
  const proof = createDetachedProof(payload, privateKey, options);
  return {
    format: "agent-liability-signed-artifact/v1",
    artifactType: options.artifactType,
    schemaId: options.schemaId,
    payload,
    payloadDigest,
    proofs: [proof],
  };
}

export function verifySignedArtifactDigest<T>(artifact: SignedArtifact<T>): ValidationResult<SignedArtifact<T>> {
  try {
    const actual = sha256Digest(artifact.payload);
    if (!equalDigest(actual, artifact.payloadDigest)) {
      return { ok: false, issues: [{ code: "ALB_DIGEST_MISMATCH", path: "/payloadDigest", message: "Artifact payload digest does not match" }] };
    }
    return { ok: true, value: artifact, issues: [] };
  } catch (error: unknown) {
    if (error instanceof CanonicalizationError || error instanceof TypeError || error instanceof RangeError) {
      return { ok: false, issues: [{ code: "ALB_PROOF_INVALID", path: "/payload", message: "Artifact payload is not canonical protocol JSON" }] };
    }
    throw error;
  }
}
