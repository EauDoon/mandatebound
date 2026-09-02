import { Buffer } from "node:buffer";
import {
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify,
  type JsonWebKeyInput,
  type KeyObject,
} from "node:crypto";
import {
  canonicalBytes,
  digestBytes,
  isSha256Digest,
  sha256Bytes,
} from "./canonical.js";
import { isSafeBundlePath, verifyEvidenceBundle } from "./bundle.js";
import type {
  AsciiIdentifier,
  BundleVerificationReport,
  Ed25519PublicJwk,
  EvidenceBundle,
  Rfc3339Timestamp,
  Sha256Digest,
  ValidationIssue,
} from "./domain.js";

export const CASEPACK_STATUSES = [
  "satisfied",
  "missing",
  "conflicting",
  "unsupported",
  "unknown",
  "not_applicable",
] as const;

export type CasePackStatus = (typeof CASEPACK_STATUSES)[number];

export interface RawEvidenceReference {
  readonly referenceId: AsciiIdentifier;
  readonly kind: "bundle_path" | "content_addressed";
  readonly value: string;
}

export interface RawEvidenceDescriptor {
  readonly digest: Sha256Digest;
  readonly byteLength: number;
  readonly reference: RawEvidenceReference;
}

export interface MappedArtifactReference {
  readonly path: string;
  readonly digest: Sha256Digest;
}

export interface MappingTraceStep {
  readonly index: number;
  readonly ruleId: AsciiIdentifier;
  readonly inputPointer: string;
  readonly outputPointer: string;
  readonly status: CasePackStatus;
}

export interface DeterministicMappingTrace {
  readonly mapperId: AsciiIdentifier;
  readonly mapperVersion: string;
  readonly mappingPolicyDigest: Sha256Digest;
  readonly inputDigest: Sha256Digest;
  readonly outputArtifacts: readonly MappedArtifactReference[];
  readonly steps: readonly MappingTraceStep[];
  readonly traceDigest: Sha256Digest;
}

export interface SourceCheckpointInclusion {
  readonly checkpointId: AsciiIdentifier;
  readonly sequence: number;
  readonly leafIndex: number;
  readonly treeSize: number;
  readonly auditPath: readonly Sha256Digest[];
}

export interface ProtocolEvidenceEnvelope {
  readonly format: "MandateBoundProtocolEvidenceEnvelope/v1";
  readonly envelopeId: AsciiIdentifier;
  readonly sourceId: AsciiIdentifier;
  readonly eventClass: AsciiIdentifier;
  readonly capturedAt: Rfc3339Timestamp;
  readonly mediaType: string;
  readonly rawEvidence: RawEvidenceDescriptor;
  readonly upstreamValid: boolean;
  readonly mapping: DeterministicMappingTrace;
  readonly checkpointInclusion?: SourceCheckpointInclusion;
  readonly envelopeDigest: Sha256Digest;
}

export interface ExternalDiscoveryMaterial {
  readonly materialId: AsciiIdentifier;
  readonly mediaType: string;
  readonly rawEvidence: RawEvidenceDescriptor;
}

export interface ExternalTrustKey {
  readonly keyId: AsciiIdentifier;
  readonly sourceId: AsciiIdentifier;
  readonly publicJwk: Ed25519PublicJwk;
  readonly purposes: readonly ["source_checkpoint"];
  readonly validFrom: Rfc3339Timestamp;
  readonly validUntil: Rfc3339Timestamp;
}

export interface ExternalTrustSnapshot {
  readonly format: "MandateBoundExternalTrustSnapshot/v1";
  readonly snapshotId: AsciiIdentifier;
  readonly issuedAt: Rfc3339Timestamp;
  readonly expiresAt: Rfc3339Timestamp;
  readonly trustEffect: "discovery_only";
  readonly nativeTrustPromotion: "forbidden";
  readonly discoveryMaterials: readonly ExternalDiscoveryMaterial[];
  readonly keys: readonly ExternalTrustKey[];
  readonly snapshotDigest: Sha256Digest;
}

export interface DelegationEvidenceReference {
  readonly digest: Sha256Digest;
  readonly reference: RawEvidenceReference;
}

export interface DelegationContext {
  readonly format: "MandateBoundDelegationContext/v1";
  readonly delegationId: AsciiIdentifier;
  readonly principalId: AsciiIdentifier;
  readonly delegateId: AsciiIdentifier;
  readonly mandateDigest: Sha256Digest;
  readonly scopeDigest: Sha256Digest;
  readonly validFrom: Rfc3339Timestamp;
  readonly validUntil: Rfc3339Timestamp;
  readonly evidenceReferences: readonly DelegationEvidenceReference[];
  readonly legalEffect: "not-determined";
  readonly contextDigest: Sha256Digest;
}

export interface EvidenceCoverageRequirement {
  readonly requirementId: AsciiIdentifier;
  readonly sourceId: AsciiIdentifier;
  readonly eventClass: AsciiIdentifier;
  readonly mediaTypes: readonly string[];
  readonly windowStart: Rfc3339Timestamp;
  readonly windowEnd: Rfc3339Timestamp;
  readonly minEnvelopes: number;
  readonly checkpointRequirement: "required" | "optional" | "not_applicable";
  readonly maxCheckpointAgeSeconds?: number;
}

export interface EvidenceCoverageContract {
  readonly format: "MandateBoundEvidenceCoverageContract/v1";
  readonly contractId: AsciiIdentifier;
  readonly issuedAt: Rfc3339Timestamp;
  readonly validFrom: Rfc3339Timestamp;
  readonly validUntil: Rfc3339Timestamp;
  readonly coverageScope: "declared_sources_and_windows_only";
  readonly policyDigest: Sha256Digest;
  readonly nativeBundleRootDigest: Sha256Digest;
  readonly requirements: readonly EvidenceCoverageRequirement[];
  readonly contractDigest: Sha256Digest;
}

export interface SourceCheckpointGap {
  readonly fromSequence: number;
  readonly toSequence: number;
  readonly reasonCode: AsciiIdentifier;
}

export interface SourceCheckpointProof {
  readonly suite: "Ed25519";
  readonly keyId: AsciiIdentifier;
  readonly signedDigest: Sha256Digest;
  readonly signature: string;
}

export interface SourceCheckpoint {
  readonly format: "MandateBoundSourceCheckpoint/v1";
  readonly checkpointId: AsciiIdentifier;
  readonly sourceId: AsciiIdentifier;
  readonly epoch: AsciiIdentifier;
  readonly issuedAt: Rfc3339Timestamp;
  readonly windowStart: Rfc3339Timestamp;
  readonly windowEnd: Rfc3339Timestamp;
  readonly firstSequence: number;
  readonly lastSequence: number;
  readonly eventCount: number;
  readonly merkleRoot: Sha256Digest;
  readonly previousCheckpointDigest?: Sha256Digest;
  readonly declaredGaps: readonly SourceCheckpointGap[];
  readonly checkpointDigest: Sha256Digest;
  readonly proofs: readonly SourceCheckpointProof[];
}

export interface MandateBoundCasePack {
  readonly format: "MandateBoundCasePack/v1";
  readonly casePackId: AsciiIdentifier;
  readonly createdAt: Rfc3339Timestamp;
  readonly nativeEvidenceBundle: EvidenceBundle;
  readonly protocolEvidence: readonly ProtocolEvidenceEnvelope[];
  readonly externalTrustSnapshot?: ExternalTrustSnapshot;
  readonly delegationContext: DelegationContext;
  readonly coverageContract: EvidenceCoverageContract;
  readonly sourceCheckpoints: readonly SourceCheckpoint[];
  readonly casePackDigest: Sha256Digest;
}

export interface SuppliedRawEvidence {
  readonly referenceId: AsciiIdentifier;
  readonly bytes: Uint8Array;
}

export interface CasePackVerificationAnchors {
  readonly asOf: Rfc3339Timestamp;
  readonly coveragePolicyDigest: Sha256Digest;
  readonly coverageContractDigest: Sha256Digest;
  readonly externalTrustSnapshotDigest?: Sha256Digest;
  readonly rawEvidence?: readonly SuppliedRawEvidence[];
}

export interface EnvelopeVerificationResult {
  readonly envelopeId: AsciiIdentifier;
  readonly integrityStatus: CasePackStatus;
  readonly coverageStatus: CasePackStatus;
  readonly sourceTruthStatus: "unknown";
  readonly upstreamValid: boolean;
  readonly evidenceEligible: boolean;
}

export interface CoverageRequirementResult {
  readonly requirementId: AsciiIdentifier;
  readonly status: CasePackStatus;
  readonly matchedEnvelopes: number;
}

export interface CasePackVerificationReport {
  readonly valid: boolean;
  readonly casePackId?: AsciiIdentifier;
  readonly casePackDigest?: Sha256Digest;
  readonly integrityStatus: CasePackStatus;
  readonly coverageStatus: CasePackStatus;
  readonly sourceTruthStatus: "unknown" | "not_applicable";
  readonly upstreamValidStatus: CasePackStatus;
  readonly evidenceEligibilityStatus: CasePackStatus;
  readonly externalTrustStatus: CasePackStatus;
  readonly delegationStatus: CasePackStatus;
  readonly globalCompleteness: "not-established";
  readonly nativeBundle: BundleVerificationReport;
  readonly envelopes: readonly EnvelopeVerificationResult[];
  readonly requirements: readonly CoverageRequirementResult[];
  readonly issues: readonly ValidationIssue[];
}

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SEMVER_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+$/;
const MEDIA_TYPE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]+$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const JSON_POINTER_PATTERN = /^(?:|\/(?:[^~/]|~0|~1)*)$/;
const CASEPACK_CANONICAL_LIMITS = Object.freeze({
  maxDepth: 48,
  maxNodes: 250_000,
  maxBytes: 16_777_216,
});
const MAX_PROTOCOL_EVIDENCE = 1_024;
const MAX_CHECKPOINTS = 1_024;
const MAX_RAW_EVIDENCE_BYTES = 16_777_216;
const MAX_TOTAL_RAW_EVIDENCE_BYTES = 67_108_864;
const MAX_ISSUES = 128;
const CHECKPOINT_DOMAIN = Buffer.from("MANDATEBOUND-SOURCE-CHECKPOINT-V1\0", "ascii");

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort(compareAscii);
  const wanted = [...expected].sort(compareAscii);
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function expectedKeys(required: readonly string[], value: Record<string, unknown>, optional: readonly string[]): string[] {
  return [...required, ...optional.filter((key) => Object.hasOwn(value, key))];
}

function addIssue(
  issues: ValidationIssue[],
  path: string,
  code: string,
  message: string,
): void {
  if (issues.length < MAX_ISSUES) issues.push({ path, code, message });
}

function isIdentifier(value: unknown): value is AsciiIdentifier {
  return typeof value === "string" && IDENTIFIER_PATTERN.test(value);
}

function isTimestamp(value: unknown): value is Rfc3339Timestamp {
  if (typeof value !== "string" || value.length !== 24 || value[19] !== "." || value[23] !== "Z") {
    return false;
  }
  const parsed = new Date(value);
  return !Number.isNaN(parsed.valueOf()) && parsed.toISOString() === value;
}

function timestampMillis(value: Rfc3339Timestamp): number {
  return new Date(value).valueOf();
}

function isMediaType(value: unknown): value is string {
  return typeof value === "string" && value.length <= 160 && MEDIA_TYPE_PATTERN.test(value);
}

function isBoundedInteger(value: unknown, minimum: number, maximum: number): value is number {
  return Number.isSafeInteger(value) && (value as number) >= minimum && (value as number) <= maximum;
}

function isStatus(value: unknown): value is CasePackStatus {
  return typeof value === "string" && CASEPACK_STATUSES.includes(value as CasePackStatus);
}

function digestCanonical(value: unknown): Sha256Digest {
  return sha256Bytes(canonicalBytes(value, CASEPACK_CANONICAL_LIMITS));
}

function envelopeMaterial(value: Omit<ProtocolEvidenceEnvelope, "envelopeDigest">): unknown {
  return value;
}

function mappingMaterial(value: Omit<DeterministicMappingTrace, "traceDigest">): unknown {
  return value;
}

function externalTrustMaterial(value: Omit<ExternalTrustSnapshot, "snapshotDigest">): unknown {
  return value;
}

function delegationMaterial(value: Omit<DelegationContext, "contextDigest">): unknown {
  return value;
}

function coverageMaterial(value: Omit<EvidenceCoverageContract, "contractDigest">): unknown {
  return value;
}

function checkpointMaterial(
  value: Omit<SourceCheckpoint, "checkpointDigest" | "proofs">,
): unknown {
  return value;
}

function casePackMaterial(value: Omit<MandateBoundCasePack, "casePackDigest">): unknown {
  return value;
}

function withoutProperty<T extends object, K extends PropertyKey>(
  value: T,
  property: K,
): Omit<T, K> {
  const result: Record<PropertyKey, unknown> = {};
  for (const key of Reflect.ownKeys(value)) {
    if (key !== property) result[key] = (value as Record<PropertyKey, unknown>)[key];
  }
  return result as Omit<T, K>;
}

export function sealDeterministicMappingTrace(
  value: Omit<DeterministicMappingTrace, "traceDigest">,
): DeterministicMappingTrace {
  const material = withoutProperty(
    value as Omit<DeterministicMappingTrace, "traceDigest"> & Partial<Pick<DeterministicMappingTrace, "traceDigest">>,
    "traceDigest",
  );
  return { ...material, traceDigest: digestCanonical(mappingMaterial(material)) };
}

export function sealProtocolEvidenceEnvelope(
  value: Omit<ProtocolEvidenceEnvelope, "envelopeDigest">,
): ProtocolEvidenceEnvelope {
  const material = withoutProperty(
    value as Omit<ProtocolEvidenceEnvelope, "envelopeDigest"> & Partial<Pick<ProtocolEvidenceEnvelope, "envelopeDigest">>,
    "envelopeDigest",
  );
  return { ...material, envelopeDigest: digestCanonical(envelopeMaterial(material)) };
}

export function sealExternalTrustSnapshot(
  value: Omit<ExternalTrustSnapshot, "snapshotDigest">,
): ExternalTrustSnapshot {
  const material = withoutProperty(
    value as Omit<ExternalTrustSnapshot, "snapshotDigest"> & Partial<Pick<ExternalTrustSnapshot, "snapshotDigest">>,
    "snapshotDigest",
  );
  return { ...material, snapshotDigest: digestCanonical(externalTrustMaterial(material)) };
}

export function sealDelegationContext(
  value: Omit<DelegationContext, "contextDigest">,
): DelegationContext {
  const material = withoutProperty(
    value as Omit<DelegationContext, "contextDigest"> & Partial<Pick<DelegationContext, "contextDigest">>,
    "contextDigest",
  );
  return { ...material, contextDigest: digestCanonical(delegationMaterial(material)) };
}

export function sealEvidenceCoverageContract(
  value: Omit<EvidenceCoverageContract, "contractDigest">,
): EvidenceCoverageContract {
  const material = withoutProperty(
    value as Omit<EvidenceCoverageContract, "contractDigest"> & Partial<Pick<EvidenceCoverageContract, "contractDigest">>,
    "contractDigest",
  );
  return { ...material, contractDigest: digestCanonical(coverageMaterial(material)) };
}

export function sealSourceCheckpoint(
  value: Omit<SourceCheckpoint, "checkpointDigest" | "proofs"> & {
    readonly proofs?: readonly SourceCheckpointProof[];
  },
): SourceCheckpoint {
  const {
    proofs = [],
    format,
    checkpointId,
    sourceId,
    epoch,
    issuedAt,
    windowStart,
    windowEnd,
    firstSequence,
    lastSequence,
    eventCount,
    merkleRoot,
    previousCheckpointDigest,
    declaredGaps,
  } = value;
  const unsigned = {
    format,
    checkpointId,
    sourceId,
    epoch,
    issuedAt,
    windowStart,
    windowEnd,
    firstSequence,
    lastSequence,
    eventCount,
    merkleRoot,
    ...(previousCheckpointDigest === undefined ? {} : { previousCheckpointDigest }),
    declaredGaps,
  };
  return {
    ...unsigned,
    checkpointDigest: digestCanonical(checkpointMaterial(unsigned)),
    proofs,
  };
}

export function createSourceCheckpointProof(
  checkpoint: SourceCheckpoint,
  privateKeyInput: KeyObject | string | Buffer,
  keyId: AsciiIdentifier,
): SourceCheckpointProof {
  if (!isIdentifier(keyId) || !isSha256Digest(checkpoint.checkpointDigest)) {
    throw new TypeError("Invalid source checkpoint proof binding");
  }
  const privateKey = typeof privateKeyInput === "string" || Buffer.isBuffer(privateKeyInput)
    ? createPrivateKey(privateKeyInput)
    : privateKeyInput;
  if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
    throw new TypeError("An Ed25519 private key is required");
  }
  const input = Buffer.concat([CHECKPOINT_DOMAIN, Buffer.from(digestBytes(checkpoint.checkpointDigest))]);
  return {
    suite: "Ed25519",
    keyId,
    signedDigest: checkpoint.checkpointDigest,
    signature: nodeSign(null, input, privateKey).toString("base64url"),
  };
}

export function createMandateBoundCasePack(
  value: Omit<MandateBoundCasePack, "casePackDigest">,
): MandateBoundCasePack {
  const material = withoutProperty(
    value as Omit<MandateBoundCasePack, "casePackDigest"> & Partial<Pick<MandateBoundCasePack, "casePackDigest">>,
    "casePackDigest",
  );
  return { ...material, casePackDigest: digestCanonical(casePackMaterial(material)) };
}

export function computeSourceEvidenceLeaf(
  envelope: Pick<ProtocolEvidenceEnvelope, "envelopeId" | "sourceId" | "rawEvidence">,
  sequence: number,
): Sha256Digest {
  if (!isBoundedInteger(sequence, 0, Number.MAX_SAFE_INTEGER)) {
    throw new TypeError("Invalid source evidence sequence");
  }
  const material = canonicalBytes({
    envelopeId: envelope.envelopeId,
    sourceId: envelope.sourceId,
    sequence,
    rawDigest: envelope.rawEvidence.digest,
  });
  return sha256Bytes(Buffer.concat([Buffer.from([0]), Buffer.from(material)]));
}

function validateRawReference(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
  expectedDigest?: Sha256Digest,
): value is RawEvidenceReference {
  if (!isPlainObject(value) || !exactKeys(value, ["referenceId", "kind", "value"])) {
    addIssue(issues, path, "MBCP_SCHEMA_INVALID", "Raw evidence reference has an invalid shape");
    return false;
  }
  let valid = true;
  if (!isIdentifier(value["referenceId"])) {
    addIssue(issues, `${path}.referenceId`, "MBCP_SCHEMA_INVALID", "Raw evidence reference identifier is invalid");
    valid = false;
  }
  if (value["kind"] !== "bundle_path" && value["kind"] !== "content_addressed") {
    addIssue(issues, `${path}.kind`, "MBCP_SCHEMA_INVALID", "Raw evidence reference kind is unsupported");
    valid = false;
  } else if (value["kind"] === "bundle_path") {
    if (!isSafeBundlePath(value["value"])) {
      addIssue(issues, `${path}.value`, "MBCP_PATH_INVALID", "Raw evidence path is unsafe");
      valid = false;
    }
  } else {
    const expected = expectedDigest === undefined
      ? undefined
      : `urn:sha256:${expectedDigest.slice("sha256:".length)}`;
    if (
      typeof value["value"] !== "string"
      || !/^urn:sha256:[a-f0-9]{64}$/.test(value["value"])
      || (expected !== undefined && value["value"] !== expected)
    ) {
      addIssue(issues, `${path}.value`, "MBCP_REFERENCE_INVALID", "Content-addressed reference does not match evidence digest");
      valid = false;
    }
  }
  return valid;
}

function validateRawEvidence(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
): value is RawEvidenceDescriptor {
  if (!isPlainObject(value) || !exactKeys(value, ["digest", "byteLength", "reference"])) {
    addIssue(issues, path, "MBCP_SCHEMA_INVALID", "Raw evidence descriptor has an invalid shape");
    return false;
  }
  let valid = true;
  if (!isSha256Digest(value["digest"])) {
    addIssue(issues, `${path}.digest`, "MBCP_SCHEMA_INVALID", "Raw evidence digest is invalid");
    valid = false;
  }
  if (!isBoundedInteger(value["byteLength"], 0, MAX_RAW_EVIDENCE_BYTES)) {
    addIssue(issues, `${path}.byteLength`, "MBCP_LIMIT_EXCEEDED", "Raw evidence byte length is invalid");
    valid = false;
  }
  if (!validateRawReference(
    value["reference"],
    `${path}.reference`,
    issues,
    isSha256Digest(value["digest"]) ? value["digest"] : undefined,
  )) {
    valid = false;
  }
  return valid;
}

function validateMappedArtifact(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
): value is MappedArtifactReference {
  if (!isPlainObject(value) || !exactKeys(value, ["path", "digest"])) {
    addIssue(issues, path, "MBCP_SCHEMA_INVALID", "Mapped artifact reference has an invalid shape");
    return false;
  }
  let valid = true;
  if (!isSafeBundlePath(value["path"])) {
    addIssue(issues, `${path}.path`, "MBCP_PATH_INVALID", "Mapped artifact path is unsafe");
    valid = false;
  }
  if (!isSha256Digest(value["digest"])) {
    addIssue(issues, `${path}.digest`, "MBCP_SCHEMA_INVALID", "Mapped artifact digest is invalid");
    valid = false;
  }
  return valid;
}

function validateMappingTrace(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
): value is DeterministicMappingTrace {
  if (
    !isPlainObject(value)
    || !exactKeys(value, [
      "mapperId",
      "mapperVersion",
      "mappingPolicyDigest",
      "inputDigest",
      "outputArtifacts",
      "steps",
      "traceDigest",
    ])
  ) {
    addIssue(issues, path, "MBCP_SCHEMA_INVALID", "Mapping trace has an invalid shape");
    return false;
  }
  let valid = true;
  if (!isIdentifier(value["mapperId"]) || typeof value["mapperVersion"] !== "string" || !SEMVER_PATTERN.test(value["mapperVersion"])) {
    addIssue(issues, path, "MBCP_SCHEMA_INVALID", "Mapping identity is invalid");
    valid = false;
  }
  for (const key of ["mappingPolicyDigest", "inputDigest", "traceDigest"] as const) {
    if (!isSha256Digest(value[key])) {
      addIssue(issues, `${path}.${key}`, "MBCP_SCHEMA_INVALID", "Mapping digest is invalid");
      valid = false;
    }
  }
  if (!Array.isArray(value["outputArtifacts"]) || value["outputArtifacts"].length < 1 || value["outputArtifacts"].length > 1_024) {
    addIssue(issues, `${path}.outputArtifacts`, "MBCP_LIMIT_EXCEEDED", "Mapped artifact reference count is invalid");
    valid = false;
  } else {
    let previousPath: string | undefined;
    for (const [index, item] of value["outputArtifacts"].entries()) {
      if (!validateMappedArtifact(item, `${path}.outputArtifacts[${String(index)}]`, issues)) {
        valid = false;
      } else if (previousPath !== undefined && compareAscii(previousPath, item.path) >= 0) {
        addIssue(issues, `${path}.outputArtifacts`, "MBCP_DUPLICATE_OR_UNSORTED", "Mapped artifact references must be unique and sorted");
        valid = false;
      } else {
        previousPath = item.path;
      }
    }
  }
  if (!Array.isArray(value["steps"]) || value["steps"].length < 1 || value["steps"].length > 4_096) {
    addIssue(issues, `${path}.steps`, "MBCP_LIMIT_EXCEEDED", "Mapping trace step count is invalid");
    valid = false;
  } else {
    const ruleIds = new Set<string>();
    for (const [index, item] of value["steps"].entries()) {
      const itemPath = `${path}.steps[${String(index)}]`;
      if (!isPlainObject(item) || !exactKeys(item, ["index", "ruleId", "inputPointer", "outputPointer", "status"])) {
        addIssue(issues, itemPath, "MBCP_SCHEMA_INVALID", "Mapping trace step has an invalid shape");
        valid = false;
        continue;
      }
      if (item["index"] !== index || !isIdentifier(item["ruleId"]) || ruleIds.has(item["ruleId"] as string)) {
        addIssue(issues, itemPath, "MBCP_DUPLICATE_OR_UNSORTED", "Mapping trace steps must be contiguous with unique rule identifiers");
        valid = false;
      } else {
        ruleIds.add(item["ruleId"]);
      }
      if (
        typeof item["inputPointer"] !== "string"
        || item["inputPointer"].length > 512
        || !JSON_POINTER_PATTERN.test(item["inputPointer"])
        || typeof item["outputPointer"] !== "string"
        || item["outputPointer"].length > 512
        || !JSON_POINTER_PATTERN.test(item["outputPointer"])
      ) {
        addIssue(issues, itemPath, "MBCP_SCHEMA_INVALID", "Mapping trace JSON pointer is invalid");
        valid = false;
      }
      if (!isStatus(item["status"])) {
        addIssue(issues, `${itemPath}.status`, "MBCP_SCHEMA_INVALID", "Mapping trace status is invalid");
        valid = false;
      }
    }
  }
  if (valid) {
    const typed = value as unknown as DeterministicMappingTrace;
    const material: Omit<DeterministicMappingTrace, "traceDigest"> = {
      mapperId: typed.mapperId,
      mapperVersion: typed.mapperVersion,
      mappingPolicyDigest: typed.mappingPolicyDigest,
      inputDigest: typed.inputDigest,
      outputArtifacts: typed.outputArtifacts,
      steps: typed.steps,
    };
    if (typed.traceDigest !== digestCanonical(mappingMaterial(material))) {
      addIssue(issues, `${path}.traceDigest`, "MBCP_DIGEST_MISMATCH", "Mapping trace digest does not match");
      valid = false;
    }
  }
  return valid;
}

function validateCheckpointInclusion(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
): value is SourceCheckpointInclusion {
  if (!isPlainObject(value) || !exactKeys(value, ["checkpointId", "sequence", "leafIndex", "treeSize", "auditPath"])) {
    addIssue(issues, path, "MBCP_SCHEMA_INVALID", "Checkpoint inclusion metadata has an invalid shape");
    return false;
  }
  let valid = true;
  if (!isIdentifier(value["checkpointId"])) valid = false;
  if (!isBoundedInteger(value["sequence"], 0, Number.MAX_SAFE_INTEGER)) valid = false;
  if (!isBoundedInteger(value["leafIndex"], 0, 4_095)) valid = false;
  if (!isBoundedInteger(value["treeSize"], 1, 4_096)) valid = false;
  if (
    !Array.isArray(value["auditPath"])
    || value["auditPath"].length > 12
    || value["auditPath"].some((digest) => !isSha256Digest(digest))
  ) {
    valid = false;
  }
  if (!valid) addIssue(issues, path, "MBCP_SCHEMA_INVALID", "Checkpoint inclusion metadata is invalid");
  return valid;
}

function validateProtocolEnvelope(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
): value is ProtocolEvidenceEnvelope {
  if (!isPlainObject(value)) {
    addIssue(issues, path, "MBCP_SCHEMA_INVALID", "Protocol evidence envelope must be an object");
    return false;
  }
  const required = [
    "format",
    "envelopeId",
    "sourceId",
    "eventClass",
    "capturedAt",
    "mediaType",
    "rawEvidence",
    "upstreamValid",
    "mapping",
    "envelopeDigest",
  ];
  if (!exactKeys(value, expectedKeys(required, value, ["checkpointInclusion"]))) {
    addIssue(issues, path, "MBCP_SCHEMA_INVALID", "Protocol evidence envelope has missing or unknown properties");
    return false;
  }
  let valid = true;
  if (
    value["format"] !== "MandateBoundProtocolEvidenceEnvelope/v1"
    || !isIdentifier(value["envelopeId"])
    || !isIdentifier(value["sourceId"])
    || !isIdentifier(value["eventClass"])
    || !isTimestamp(value["capturedAt"])
    || !isMediaType(value["mediaType"])
    || typeof value["upstreamValid"] !== "boolean"
    || !isSha256Digest(value["envelopeDigest"])
  ) {
    addIssue(issues, path, "MBCP_SCHEMA_INVALID", "Protocol evidence envelope metadata is invalid");
    valid = false;
  }
  if (!validateRawEvidence(value["rawEvidence"], `${path}.rawEvidence`, issues)) valid = false;
  if (!validateMappingTrace(value["mapping"], `${path}.mapping`, issues)) valid = false;
  if (
    value["checkpointInclusion"] !== undefined
    && !validateCheckpointInclusion(value["checkpointInclusion"], `${path}.checkpointInclusion`, issues)
  ) {
    valid = false;
  }
  if (valid) {
    const typed = value as unknown as ProtocolEvidenceEnvelope;
    const material: Omit<ProtocolEvidenceEnvelope, "envelopeDigest"> = {
      format: typed.format,
      envelopeId: typed.envelopeId,
      sourceId: typed.sourceId,
      eventClass: typed.eventClass,
      capturedAt: typed.capturedAt,
      mediaType: typed.mediaType,
      rawEvidence: typed.rawEvidence,
      upstreamValid: typed.upstreamValid,
      mapping: typed.mapping,
      ...(typed.checkpointInclusion === undefined ? {} : { checkpointInclusion: typed.checkpointInclusion }),
    };
    if (typed.envelopeDigest !== digestCanonical(envelopeMaterial(material))) {
      addIssue(issues, `${path}.envelopeDigest`, "MBCP_DIGEST_MISMATCH", "Protocol evidence envelope digest does not match");
      valid = false;
    }
  }
  return valid;
}

function validatePublicJwk(value: unknown, path: string, issues: ValidationIssue[]): value is Ed25519PublicJwk {
  if (!isPlainObject(value)) {
    addIssue(issues, path, "MBCP_SCHEMA_INVALID", "External public key must be an object");
    return false;
  }
  const required = ["kty", "crv", "x"];
  if (!exactKeys(value, expectedKeys(required, value, ["alg", "use", "key_ops"]))) {
    addIssue(issues, path, "MBCP_SCHEMA_INVALID", "External public key has an invalid shape");
    return false;
  }
  const x = value["x"];
  if (
    value["kty"] !== "OKP"
    || value["crv"] !== "Ed25519"
    || typeof x !== "string"
    || !BASE64URL_PATTERN.test(x)
    || Buffer.from(x, "base64url").length !== 32
    || Buffer.from(x, "base64url").toString("base64url") !== x
    || (value["alg"] !== undefined && value["alg"] !== "EdDSA")
    || (value["use"] !== undefined && value["use"] !== "sig")
    || (value["key_ops"] !== undefined && (
      !Array.isArray(value["key_ops"])
      || value["key_ops"].length !== 1
      || value["key_ops"][0] !== "verify"
    ))
  ) {
    addIssue(issues, path, "MBCP_SCHEMA_INVALID", "External public key is invalid");
    return false;
  }
  try {
    const key = createPublicKey({ key: value as unknown as JsonWebKeyInput["key"], format: "jwk" });
    if (key.asymmetricKeyType !== "ed25519") throw new TypeError("Unexpected key type");
  } catch {
    addIssue(issues, path, "MBCP_SCHEMA_INVALID", "External public key is malformed");
    return false;
  }
  return true;
}

function validateExternalTrust(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
): value is ExternalTrustSnapshot {
  if (
    !isPlainObject(value)
    || !exactKeys(value, [
      "format",
      "snapshotId",
      "issuedAt",
      "expiresAt",
      "trustEffect",
      "nativeTrustPromotion",
      "discoveryMaterials",
      "keys",
      "snapshotDigest",
    ])
  ) {
    addIssue(issues, path, "MBCP_EXTERNAL_TRUST_INVALID", "External trust snapshot has an invalid shape");
    return false;
  }
  let valid = true;
  if (
    value["format"] !== "MandateBoundExternalTrustSnapshot/v1"
    || !isIdentifier(value["snapshotId"])
    || !isTimestamp(value["issuedAt"])
    || !isTimestamp(value["expiresAt"])
    || value["trustEffect"] !== "discovery_only"
    || value["nativeTrustPromotion"] !== "forbidden"
    || !isSha256Digest(value["snapshotDigest"])
  ) {
    addIssue(issues, path, "MBCP_EXTERNAL_TRUST_INVALID", "External trust metadata is invalid");
    valid = false;
  }
  if (
    isTimestamp(value["issuedAt"])
    && isTimestamp(value["expiresAt"])
    && timestampMillis(value["issuedAt"]) >= timestampMillis(value["expiresAt"])
  ) {
    addIssue(issues, `${path}.expiresAt`, "MBCP_EXTERNAL_TRUST_INVALID", "External trust validity interval is invalid");
    valid = false;
  }
  if (!Array.isArray(value["discoveryMaterials"]) || value["discoveryMaterials"].length > 128) {
    addIssue(issues, `${path}.discoveryMaterials`, "MBCP_LIMIT_EXCEEDED", "External discovery material count is invalid");
    valid = false;
  } else {
    const materialIds = new Set<string>();
    for (const [index, item] of value["discoveryMaterials"].entries()) {
      const itemPath = `${path}.discoveryMaterials[${String(index)}]`;
      if (!isPlainObject(item) || !exactKeys(item, ["materialId", "mediaType", "rawEvidence"])) {
        addIssue(issues, itemPath, "MBCP_SCHEMA_INVALID", "External discovery material has an invalid shape");
        valid = false;
        continue;
      }
      if (!isIdentifier(item["materialId"]) || materialIds.has(item["materialId"] as string) || !isMediaType(item["mediaType"])) {
        addIssue(issues, itemPath, "MBCP_DUPLICATE_OR_UNSORTED", "External discovery material metadata is invalid");
        valid = false;
      } else {
        materialIds.add(item["materialId"]);
      }
      if (!validateRawEvidence(item["rawEvidence"], `${itemPath}.rawEvidence`, issues)) valid = false;
    }
  }
  if (!Array.isArray(value["keys"]) || value["keys"].length > 128) {
    addIssue(issues, `${path}.keys`, "MBCP_LIMIT_EXCEEDED", "External trust key count is invalid");
    valid = false;
  } else {
    const keyIds = new Set<string>();
    for (const [index, item] of value["keys"].entries()) {
      const itemPath = `${path}.keys[${String(index)}]`;
      if (!isPlainObject(item) || !exactKeys(item, ["keyId", "sourceId", "publicJwk", "purposes", "validFrom", "validUntil"])) {
        addIssue(issues, itemPath, "MBCP_SCHEMA_INVALID", "External trust key has an invalid shape");
        valid = false;
        continue;
      }
      if (
        !isIdentifier(item["keyId"])
        || keyIds.has(item["keyId"] as string)
        || !isIdentifier(item["sourceId"])
        || !Array.isArray(item["purposes"])
        || item["purposes"].length !== 1
        || item["purposes"][0] !== "source_checkpoint"
        || !isTimestamp(item["validFrom"])
        || !isTimestamp(item["validUntil"])
      ) {
        addIssue(issues, itemPath, "MBCP_DUPLICATE_OR_UNSORTED", "External trust key metadata is invalid");
        valid = false;
      } else {
        keyIds.add(item["keyId"]);
        if (timestampMillis(item["validFrom"]) >= timestampMillis(item["validUntil"])) {
          addIssue(issues, itemPath, "MBCP_EXTERNAL_TRUST_INVALID", "External trust key validity interval is invalid");
          valid = false;
        }
      }
      if (!validatePublicJwk(item["publicJwk"], `${itemPath}.publicJwk`, issues)) valid = false;
    }
  }
  if (valid) {
    const typed = value as unknown as ExternalTrustSnapshot;
    const material: Omit<ExternalTrustSnapshot, "snapshotDigest"> = {
      format: typed.format,
      snapshotId: typed.snapshotId,
      issuedAt: typed.issuedAt,
      expiresAt: typed.expiresAt,
      trustEffect: typed.trustEffect,
      nativeTrustPromotion: typed.nativeTrustPromotion,
      discoveryMaterials: typed.discoveryMaterials,
      keys: typed.keys,
    };
    if (typed.snapshotDigest !== digestCanonical(externalTrustMaterial(material))) {
      addIssue(issues, `${path}.snapshotDigest`, "MBCP_DIGEST_MISMATCH", "External trust snapshot digest does not match");
      valid = false;
    }
  }
  return valid;
}

function validateDelegationContext(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
): value is DelegationContext {
  if (
    !isPlainObject(value)
    || !exactKeys(value, [
      "format",
      "delegationId",
      "principalId",
      "delegateId",
      "mandateDigest",
      "scopeDigest",
      "validFrom",
      "validUntil",
      "evidenceReferences",
      "legalEffect",
      "contextDigest",
    ])
  ) {
    addIssue(issues, path, "MBCP_DELEGATION_INVALID", "Delegation context has an invalid shape");
    return false;
  }
  let valid = true;
  if (
    value["format"] !== "MandateBoundDelegationContext/v1"
    || !isIdentifier(value["delegationId"])
    || !isIdentifier(value["principalId"])
    || !isIdentifier(value["delegateId"])
    || value["principalId"] === value["delegateId"]
    || !isSha256Digest(value["mandateDigest"])
    || !isSha256Digest(value["scopeDigest"])
    || !isTimestamp(value["validFrom"])
    || !isTimestamp(value["validUntil"])
    || value["legalEffect"] !== "not-determined"
    || !isSha256Digest(value["contextDigest"])
  ) {
    addIssue(issues, path, "MBCP_DELEGATION_INVALID", "Delegation context metadata is invalid");
    valid = false;
  }
  if (
    isTimestamp(value["validFrom"])
    && isTimestamp(value["validUntil"])
    && timestampMillis(value["validFrom"]) >= timestampMillis(value["validUntil"])
  ) {
    addIssue(issues, `${path}.validUntil`, "MBCP_DELEGATION_INVALID", "Delegation validity interval is invalid");
    valid = false;
  }
  if (!Array.isArray(value["evidenceReferences"]) || value["evidenceReferences"].length > 128) {
    addIssue(issues, `${path}.evidenceReferences`, "MBCP_LIMIT_EXCEEDED", "Delegation evidence reference count is invalid");
    valid = false;
  } else {
    const referenceIds = new Set<string>();
    for (const [index, item] of value["evidenceReferences"].entries()) {
      const itemPath = `${path}.evidenceReferences[${String(index)}]`;
      if (!isPlainObject(item) || !exactKeys(item, ["digest", "reference"]) || !isSha256Digest(item["digest"])) {
        addIssue(issues, itemPath, "MBCP_SCHEMA_INVALID", "Delegation evidence reference has an invalid shape");
        valid = false;
        continue;
      }
      if (!validateRawReference(item["reference"], `${itemPath}.reference`, issues, item["digest"])) {
        valid = false;
      } else if (referenceIds.has(item["reference"].referenceId)) {
        addIssue(issues, itemPath, "MBCP_DUPLICATE_OR_UNSORTED", "Delegation evidence reference is duplicated");
        valid = false;
      } else {
        referenceIds.add(item["reference"].referenceId);
      }
    }
  }
  if (valid) {
    const typed = value as unknown as DelegationContext;
    const material: Omit<DelegationContext, "contextDigest"> = {
      format: typed.format,
      delegationId: typed.delegationId,
      principalId: typed.principalId,
      delegateId: typed.delegateId,
      mandateDigest: typed.mandateDigest,
      scopeDigest: typed.scopeDigest,
      validFrom: typed.validFrom,
      validUntil: typed.validUntil,
      evidenceReferences: typed.evidenceReferences,
      legalEffect: typed.legalEffect,
    };
    if (typed.contextDigest !== digestCanonical(delegationMaterial(material))) {
      addIssue(issues, `${path}.contextDigest`, "MBCP_DIGEST_MISMATCH", "Delegation context digest does not match");
      valid = false;
    }
  }
  return valid;
}

function validateCoverageRequirement(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
): value is EvidenceCoverageRequirement {
  if (!isPlainObject(value)) {
    addIssue(issues, path, "MBCP_COVERAGE_INVALID", "Coverage requirement must be an object");
    return false;
  }
  const required = [
    "requirementId",
    "sourceId",
    "eventClass",
    "mediaTypes",
    "windowStart",
    "windowEnd",
    "minEnvelopes",
    "checkpointRequirement",
  ];
  if (!exactKeys(value, expectedKeys(required, value, ["maxCheckpointAgeSeconds"]))) {
    addIssue(issues, path, "MBCP_COVERAGE_INVALID", "Coverage requirement has missing or unknown properties");
    return false;
  }
  let valid = true;
  if (
    !isIdentifier(value["requirementId"])
    || !isIdentifier(value["sourceId"])
    || !isIdentifier(value["eventClass"])
    || !isTimestamp(value["windowStart"])
    || !isTimestamp(value["windowEnd"])
    || !isBoundedInteger(value["minEnvelopes"], 1, 1_024)
    || (
      value["checkpointRequirement"] !== "required"
      && value["checkpointRequirement"] !== "optional"
      && value["checkpointRequirement"] !== "not_applicable"
    )
  ) {
    addIssue(issues, path, "MBCP_COVERAGE_INVALID", "Coverage requirement metadata is invalid");
    valid = false;
  }
  if (
    isTimestamp(value["windowStart"])
    && isTimestamp(value["windowEnd"])
    && timestampMillis(value["windowStart"]) > timestampMillis(value["windowEnd"])
  ) {
    addIssue(issues, `${path}.windowEnd`, "MBCP_COVERAGE_INVALID", "Coverage window is invalid");
    valid = false;
  }
  if (
    !Array.isArray(value["mediaTypes"])
    || value["mediaTypes"].length < 1
    || value["mediaTypes"].length > 32
    || value["mediaTypes"].some((mediaType) => !isMediaType(mediaType))
    || value["mediaTypes"].some((mediaType, index, values) =>
      index > 0 && (values[index - 1] as string) >= (mediaType as string))
  ) {
    addIssue(issues, `${path}.mediaTypes`, "MBCP_DUPLICATE_OR_UNSORTED", "Coverage media types must be unique and sorted");
    valid = false;
  }
  if (value["checkpointRequirement"] === "not_applicable") {
    if (value["maxCheckpointAgeSeconds"] !== undefined) {
      addIssue(issues, `${path}.maxCheckpointAgeSeconds`, "MBCP_COVERAGE_INVALID", "Checkpoint age is not applicable");
      valid = false;
    }
  } else if (!isBoundedInteger(value["maxCheckpointAgeSeconds"], 0, 31_536_000)) {
    addIssue(issues, `${path}.maxCheckpointAgeSeconds`, "MBCP_COVERAGE_INVALID", "Checkpoint age bound is required and invalid");
    valid = false;
  }
  return valid;
}

function validateCoverageContract(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
): value is EvidenceCoverageContract {
  if (
    !isPlainObject(value)
    || !exactKeys(value, [
      "format",
      "contractId",
      "issuedAt",
      "validFrom",
      "validUntil",
      "coverageScope",
      "policyDigest",
      "nativeBundleRootDigest",
      "requirements",
      "contractDigest",
    ])
  ) {
    addIssue(issues, path, "MBCP_COVERAGE_INVALID", "Coverage contract has an invalid shape");
    return false;
  }
  let valid = true;
  if (
    value["format"] !== "MandateBoundEvidenceCoverageContract/v1"
    || !isIdentifier(value["contractId"])
    || !isTimestamp(value["issuedAt"])
    || !isTimestamp(value["validFrom"])
    || !isTimestamp(value["validUntil"])
    || value["coverageScope"] !== "declared_sources_and_windows_only"
    || !isSha256Digest(value["policyDigest"])
    || !isSha256Digest(value["nativeBundleRootDigest"])
    || !isSha256Digest(value["contractDigest"])
  ) {
    addIssue(issues, path, "MBCP_COVERAGE_INVALID", "Coverage contract metadata is invalid");
    valid = false;
  }
  if (
    isTimestamp(value["validFrom"])
    && isTimestamp(value["validUntil"])
    && timestampMillis(value["validFrom"]) >= timestampMillis(value["validUntil"])
  ) {
    addIssue(issues, `${path}.validUntil`, "MBCP_COVERAGE_INVALID", "Coverage contract validity interval is invalid");
    valid = false;
  }
  if (!Array.isArray(value["requirements"]) || value["requirements"].length < 1 || value["requirements"].length > 256) {
    addIssue(issues, `${path}.requirements`, "MBCP_LIMIT_EXCEEDED", "Coverage requirement count is invalid");
    valid = false;
  } else {
    const requirementIds = new Set<string>();
    const selectors = new Set<string>();
    for (const [index, item] of value["requirements"].entries()) {
      if (!validateCoverageRequirement(item, `${path}.requirements[${String(index)}]`, issues)) {
        valid = false;
        continue;
      }
      const selector = `${item.sourceId}\0${item.eventClass}`;
      if (requirementIds.has(item.requirementId) || selectors.has(selector)) {
        addIssue(issues, `${path}.requirements[${String(index)}]`, "MBCP_DUPLICATE_OR_UNSORTED", "Coverage requirement is duplicated");
        valid = false;
      }
      requirementIds.add(item.requirementId);
      selectors.add(selector);
    }
  }
  if (valid) {
    const typed = value as unknown as EvidenceCoverageContract;
    const material: Omit<EvidenceCoverageContract, "contractDigest"> = {
      format: typed.format,
      contractId: typed.contractId,
      issuedAt: typed.issuedAt,
      validFrom: typed.validFrom,
      validUntil: typed.validUntil,
      coverageScope: typed.coverageScope,
      policyDigest: typed.policyDigest,
      nativeBundleRootDigest: typed.nativeBundleRootDigest,
      requirements: typed.requirements,
    };
    if (typed.contractDigest !== digestCanonical(coverageMaterial(material))) {
      addIssue(issues, `${path}.contractDigest`, "MBCP_DIGEST_MISMATCH", "Coverage contract digest does not match");
      valid = false;
    }
  }
  return valid;
}

function validateCheckpoint(
  value: unknown,
  path: string,
  issues: ValidationIssue[],
): value is SourceCheckpoint {
  if (!isPlainObject(value)) {
    addIssue(issues, path, "MBCP_CHECKPOINT_INVALID", "Source checkpoint must be an object");
    return false;
  }
  const required = [
    "format",
    "checkpointId",
    "sourceId",
    "epoch",
    "issuedAt",
    "windowStart",
    "windowEnd",
    "firstSequence",
    "lastSequence",
    "eventCount",
    "merkleRoot",
    "declaredGaps",
    "checkpointDigest",
    "proofs",
  ];
  if (!exactKeys(value, expectedKeys(required, value, ["previousCheckpointDigest"]))) {
    addIssue(issues, path, "MBCP_CHECKPOINT_INVALID", "Source checkpoint has missing or unknown properties");
    return false;
  }
  let valid = true;
  if (
    value["format"] !== "MandateBoundSourceCheckpoint/v1"
    || !isIdentifier(value["checkpointId"])
    || !isIdentifier(value["sourceId"])
    || !isIdentifier(value["epoch"])
    || !isTimestamp(value["issuedAt"])
    || !isTimestamp(value["windowStart"])
    || !isTimestamp(value["windowEnd"])
    || !isBoundedInteger(value["firstSequence"], 0, Number.MAX_SAFE_INTEGER)
    || !isBoundedInteger(value["lastSequence"], 0, Number.MAX_SAFE_INTEGER)
    || !isBoundedInteger(value["eventCount"], 1, 4_096)
    || !isSha256Digest(value["merkleRoot"])
    || (value["previousCheckpointDigest"] !== undefined && !isSha256Digest(value["previousCheckpointDigest"]))
    || !isSha256Digest(value["checkpointDigest"])
  ) {
    addIssue(issues, path, "MBCP_CHECKPOINT_INVALID", "Source checkpoint metadata is invalid");
    valid = false;
  }
  if (
    isTimestamp(value["windowStart"])
    && isTimestamp(value["windowEnd"])
    && timestampMillis(value["windowStart"]) > timestampMillis(value["windowEnd"])
  ) {
    addIssue(issues, `${path}.windowEnd`, "MBCP_CHECKPOINT_INVALID", "Source checkpoint window is invalid");
    valid = false;
  }
  if (
    isBoundedInteger(value["firstSequence"], 0, Number.MAX_SAFE_INTEGER)
    && isBoundedInteger(value["lastSequence"], 0, Number.MAX_SAFE_INTEGER)
    && isBoundedInteger(value["eventCount"], 1, 4_096)
    && value["lastSequence"] - value["firstSequence"] + 1 !== value["eventCount"]
  ) {
    addIssue(issues, path, "MBCP_CHECKPOINT_INVALID", "Source checkpoint sequence range does not match event count");
    valid = false;
  }
  if (!Array.isArray(value["declaredGaps"]) || value["declaredGaps"].length > 128) {
    addIssue(issues, `${path}.declaredGaps`, "MBCP_LIMIT_EXCEEDED", "Declared checkpoint gap count is invalid");
    valid = false;
  } else {
    let previousEnd = -1;
    for (const [index, gap] of value["declaredGaps"].entries()) {
      const itemPath = `${path}.declaredGaps[${String(index)}]`;
      if (
        !isPlainObject(gap)
        || !exactKeys(gap, ["fromSequence", "toSequence", "reasonCode"])
        || !isBoundedInteger(gap["fromSequence"], 0, Number.MAX_SAFE_INTEGER)
        || !isBoundedInteger(gap["toSequence"], 0, Number.MAX_SAFE_INTEGER)
        || gap["fromSequence"] > gap["toSequence"]
        || gap["fromSequence"] <= previousEnd
        || !isIdentifier(gap["reasonCode"])
      ) {
        addIssue(issues, itemPath, "MBCP_CHECKPOINT_INVALID", "Declared checkpoint gaps must be valid, disjoint, and sorted");
        valid = false;
      } else {
        previousEnd = gap["toSequence"];
      }
    }
  }
  if (!Array.isArray(value["proofs"]) || value["proofs"].length > 8) {
    addIssue(issues, `${path}.proofs`, "MBCP_LIMIT_EXCEEDED", "Source checkpoint proof count is invalid");
    valid = false;
  } else {
    const keyIds = new Set<string>();
    for (const [index, proof] of value["proofs"].entries()) {
      const itemPath = `${path}.proofs[${String(index)}]`;
      if (
        !isPlainObject(proof)
        || !exactKeys(proof, ["suite", "keyId", "signedDigest", "signature"])
        || proof["suite"] !== "Ed25519"
        || !isIdentifier(proof["keyId"])
        || keyIds.has(proof["keyId"] as string)
        || !isSha256Digest(proof["signedDigest"])
        || proof["signedDigest"] !== value["checkpointDigest"]
        || typeof proof["signature"] !== "string"
        || !BASE64URL_PATTERN.test(proof["signature"])
        || Buffer.from(proof["signature"], "base64url").length !== 64
        || Buffer.from(proof["signature"], "base64url").toString("base64url") !== proof["signature"]
      ) {
        addIssue(issues, itemPath, "MBCP_CHECKPOINT_INVALID", "Source checkpoint proof is invalid");
        valid = false;
      } else {
        keyIds.add(proof["keyId"]);
      }
    }
  }
  if (valid) {
    const typed = value as unknown as SourceCheckpoint;
    const material: Omit<SourceCheckpoint, "checkpointDigest" | "proofs"> = {
      format: typed.format,
      checkpointId: typed.checkpointId,
      sourceId: typed.sourceId,
      epoch: typed.epoch,
      issuedAt: typed.issuedAt,
      windowStart: typed.windowStart,
      windowEnd: typed.windowEnd,
      firstSequence: typed.firstSequence,
      lastSequence: typed.lastSequence,
      eventCount: typed.eventCount,
      merkleRoot: typed.merkleRoot,
      ...(typed.previousCheckpointDigest === undefined ? {} : { previousCheckpointDigest: typed.previousCheckpointDigest }),
      declaredGaps: typed.declaredGaps,
    };
    if (typed.checkpointDigest !== digestCanonical(checkpointMaterial(material))) {
      addIssue(issues, `${path}.checkpointDigest`, "MBCP_DIGEST_MISMATCH", "Source checkpoint digest does not match");
      valid = false;
    }
  }
  return valid;
}

function emptyBundleReport(): BundleVerificationReport {
  return {
    valid: false,
    verifiedEntries: 0,
    totalEntries: 0,
    trustChecked: false,
    issues: [{ path: "$", code: "ALB_SCHEMA_INVALID", message: "Malformed evidence bundle" }],
  };
}

interface ShapeResult {
  readonly valid: boolean;
  readonly pack?: MandateBoundCasePack;
  readonly nativeBundle: BundleVerificationReport;
}

function validateCasePackShape(value: unknown, issues: ValidationIssue[]): ShapeResult {
  if (!isPlainObject(value)) {
    addIssue(issues, "$", "MBCP_SCHEMA_INVALID", "CasePack must be an object");
    return { valid: false, nativeBundle: emptyBundleReport() };
  }
  const required = [
    "format",
    "casePackId",
    "createdAt",
    "nativeEvidenceBundle",
    "protocolEvidence",
    "delegationContext",
    "coverageContract",
    "sourceCheckpoints",
    "casePackDigest",
  ];
  if (!exactKeys(value, expectedKeys(required, value, ["externalTrustSnapshot"]))) {
    addIssue(issues, "$", "MBCP_SCHEMA_INVALID", "CasePack has missing or unknown properties");
    return { valid: false, nativeBundle: emptyBundleReport() };
  }
  let valid = true;
  if (
    value["format"] !== "MandateBoundCasePack/v1"
    || !isIdentifier(value["casePackId"])
    || !isTimestamp(value["createdAt"])
    || !isSha256Digest(value["casePackDigest"])
  ) {
    addIssue(issues, "$", "MBCP_SCHEMA_INVALID", "CasePack metadata is invalid");
    valid = false;
  }
  const nativeBundle = verifyEvidenceBundle(value["nativeEvidenceBundle"] as EvidenceBundle);
  if (!nativeBundle.valid) {
    addIssue(issues, "$.nativeEvidenceBundle", "MBCP_NATIVE_BUNDLE_INVALID", "Nested native EvidenceBundle/v1 is invalid");
    valid = false;
  }
  if (
    !Array.isArray(value["protocolEvidence"])
    || value["protocolEvidence"].length < 1
    || value["protocolEvidence"].length > MAX_PROTOCOL_EVIDENCE
  ) {
    addIssue(issues, "$.protocolEvidence", "MBCP_LIMIT_EXCEEDED", "Protocol evidence count is invalid");
    valid = false;
  } else {
    const envelopeIds = new Set<string>();
    const referenceIds = new Set<string>();
    for (const [index, envelope] of value["protocolEvidence"].entries()) {
      if (!validateProtocolEnvelope(envelope, `$.protocolEvidence[${String(index)}]`, issues)) {
        valid = false;
        continue;
      }
      if (envelopeIds.has(envelope.envelopeId) || referenceIds.has(envelope.rawEvidence.reference.referenceId)) {
        addIssue(issues, `$.protocolEvidence[${String(index)}]`, "MBCP_DUPLICATE_OR_UNSORTED", "Protocol evidence identifier or reference is duplicated");
        valid = false;
      }
      envelopeIds.add(envelope.envelopeId);
      referenceIds.add(envelope.rawEvidence.reference.referenceId);
    }
  }
  if (
    value["externalTrustSnapshot"] !== undefined
    && !validateExternalTrust(value["externalTrustSnapshot"], "$.externalTrustSnapshot", issues)
  ) {
    valid = false;
  }
  if (!validateDelegationContext(value["delegationContext"], "$.delegationContext", issues)) valid = false;
  if (!validateCoverageContract(value["coverageContract"], "$.coverageContract", issues)) valid = false;
  if (
    !Array.isArray(value["sourceCheckpoints"])
    || value["sourceCheckpoints"].length > MAX_CHECKPOINTS
  ) {
    addIssue(issues, "$.sourceCheckpoints", "MBCP_LIMIT_EXCEEDED", "Source checkpoint count is invalid");
    valid = false;
  } else {
    const checkpointIds = new Set<string>();
    for (const [index, checkpoint] of value["sourceCheckpoints"].entries()) {
      if (!validateCheckpoint(checkpoint, `$.sourceCheckpoints[${String(index)}]`, issues)) {
        valid = false;
        continue;
      }
      if (checkpointIds.has(checkpoint.checkpointId)) {
        addIssue(issues, `$.sourceCheckpoints[${String(index)}]`, "MBCP_DUPLICATE_OR_UNSORTED", "Source checkpoint identifier is duplicated");
        valid = false;
      }
      checkpointIds.add(checkpoint.checkpointId);
    }
  }
  if (valid) {
    const typed = value as unknown as MandateBoundCasePack;
    const material: Omit<MandateBoundCasePack, "casePackDigest"> = {
      format: typed.format,
      casePackId: typed.casePackId,
      createdAt: typed.createdAt,
      nativeEvidenceBundle: typed.nativeEvidenceBundle,
      protocolEvidence: typed.protocolEvidence,
      ...(typed.externalTrustSnapshot === undefined ? {} : { externalTrustSnapshot: typed.externalTrustSnapshot }),
      delegationContext: typed.delegationContext,
      coverageContract: typed.coverageContract,
      sourceCheckpoints: typed.sourceCheckpoints,
    };
    if (typed.casePackDigest !== digestCanonical(casePackMaterial(material))) {
      addIssue(issues, "$.casePackDigest", "MBCP_DIGEST_MISMATCH", "CasePack digest does not match");
      valid = false;
    }
    return { valid, pack: typed, nativeBundle };
  }
  return { valid: false, nativeBundle };
}

const STATUS_PRIORITY: Readonly<Record<CasePackStatus, number>> = Object.freeze({
  not_applicable: 0,
  satisfied: 1,
  unknown: 2,
  missing: 3,
  unsupported: 4,
  conflicting: 5,
});

function combineStatuses(values: readonly CasePackStatus[], empty: CasePackStatus): CasePackStatus {
  if (values.length === 0) return empty;
  return values.reduce((worst, candidate) =>
    STATUS_PRIORITY[candidate] > STATUS_PRIORITY[worst] ? candidate : worst);
}

function mappingStatus(mapping: DeterministicMappingTrace): CasePackStatus {
  const relevant = mapping.steps
    .map((step) => step.status)
    .filter((status) => status !== "not_applicable");
  return combineStatuses(relevant, "not_applicable");
}

function rawEvidenceMap(
  values: readonly SuppliedRawEvidence[] | undefined,
  issues: ValidationIssue[],
): ReadonlyMap<string, Uint8Array> {
  const result = new Map<string, Uint8Array>();
  if (values === undefined) return result;
  let totalBytes = 0;
  if (values.length > MAX_PROTOCOL_EVIDENCE + 256) {
    addIssue(issues, "$anchors.rawEvidence", "MBCP_LIMIT_EXCEEDED", "Supplied raw evidence count is invalid");
    return result;
  }
  for (const item of values) {
    if (
      !isPlainObject(item)
      || !exactKeys(item, ["referenceId", "bytes"])
      || !isIdentifier(item.referenceId)
      || !(item.bytes instanceof Uint8Array)
      || item.bytes.byteLength > MAX_RAW_EVIDENCE_BYTES
      || result.has(item.referenceId)
    ) {
      addIssue(issues, "$anchors.rawEvidence", "MBCP_RAW_EVIDENCE_INVALID", "Supplied raw evidence metadata is invalid");
      continue;
    }
    totalBytes += item.bytes.byteLength;
    if (totalBytes > MAX_TOTAL_RAW_EVIDENCE_BYTES) {
      addIssue(issues, "$anchors.rawEvidence", "MBCP_LIMIT_EXCEEDED", "Supplied raw evidence total byte limit exceeded");
      break;
    }
    result.set(item.referenceId, item.bytes);
  }
  return result;
}

function verifyMappedOutputs(
  envelope: ProtocolEvidenceEnvelope,
  bundle: EvidenceBundle,
  issues: ValidationIssue[],
): CasePackStatus {
  if (envelope.mapping.inputDigest !== envelope.rawEvidence.digest) {
    addIssue(issues, "$.protocolEvidence[].mapping.inputDigest", "MBCP_DIGEST_MISMATCH", "Mapping input digest does not match raw evidence");
    return "conflicting";
  }
  for (const output of envelope.mapping.outputArtifacts) {
    const entry = bundle.manifest.entries.find((candidate) => candidate.path === output.path);
    if (entry === undefined) {
      addIssue(issues, "$.protocolEvidence[].mapping.outputArtifacts", "MBCP_MAPPING_MISSING", "Mapped artifact is absent from the native bundle");
      return "missing";
    }
    if (entry.digest !== output.digest) {
      addIssue(issues, "$.protocolEvidence[].mapping.outputArtifacts", "MBCP_DIGEST_MISMATCH", "Mapped artifact digest conflicts with the native bundle");
      return "conflicting";
    }
  }
  return mappingStatus(envelope.mapping);
}

function verifyCheckpointProof(
  checkpoint: SourceCheckpoint,
  snapshot: ExternalTrustSnapshot | undefined,
  snapshotTrusted: boolean,
): CasePackStatus {
  if (checkpoint.proofs.length === 0) return "missing";
  if (snapshot === undefined) return "missing";
  if (!snapshotTrusted) return "unknown";
  const instant = timestampMillis(checkpoint.issuedAt);
  for (const proof of checkpoint.proofs) {
    const key = snapshot.keys.find((candidate) =>
      candidate.keyId === proof.keyId
      && candidate.sourceId === checkpoint.sourceId
      && candidate.purposes.includes("source_checkpoint"));
    if (key === undefined) continue;
    if (instant < timestampMillis(key.validFrom) || instant >= timestampMillis(key.validUntil)) continue;
    try {
      const publicKey = createPublicKey({
        key: key.publicJwk as unknown as JsonWebKeyInput["key"],
        format: "jwk",
      });
      const input = Buffer.concat([CHECKPOINT_DOMAIN, Buffer.from(digestBytes(checkpoint.checkpointDigest))]);
      const signature = Buffer.from(proof.signature, "base64url");
      if (nodeVerify(null, input, publicKey, signature)) return "satisfied";
    } catch {
      return "conflicting";
    }
  }
  return "conflicting";
}

function verifyCheckpointInclusion(
  envelope: ProtocolEvidenceEnvelope,
  checkpoint: SourceCheckpoint,
): CasePackStatus {
  const inclusion = envelope.checkpointInclusion;
  if (inclusion === undefined) return "missing";
  const capturedAt = timestampMillis(envelope.capturedAt);
  if (
    inclusion.checkpointId !== checkpoint.checkpointId
    || checkpoint.sourceId !== envelope.sourceId
    || capturedAt < timestampMillis(checkpoint.windowStart)
    || capturedAt > timestampMillis(checkpoint.windowEnd)
    || inclusion.treeSize !== checkpoint.eventCount
    || inclusion.leafIndex >= inclusion.treeSize
    || inclusion.sequence !== checkpoint.firstSequence + inclusion.leafIndex
    || inclusion.sequence > checkpoint.lastSequence
    || (inclusion.treeSize & (inclusion.treeSize - 1)) !== 0
    || inclusion.auditPath.length !== Math.log2(inclusion.treeSize)
  ) {
    return "conflicting";
  }
  let current = computeSourceEvidenceLeaf(envelope, inclusion.sequence);
  let index = inclusion.leafIndex;
  for (const sibling of inclusion.auditPath) {
    const left = index % 2 === 0 ? current : sibling;
    const right = index % 2 === 0 ? sibling : current;
    current = sha256Bytes(Buffer.concat([
      Buffer.from([1]),
      Buffer.from(digestBytes(left)),
      Buffer.from(digestBytes(right)),
    ]));
    index = Math.floor(index / 2);
  }
  return current === checkpoint.merkleRoot ? "satisfied" : "conflicting";
}

function checkpointConflicts(checkpoints: readonly SourceCheckpoint[]): ReadonlySet<string> {
  const roots = new Map<string, string>();
  const conflictedSources = new Set<string>();
  for (const checkpoint of checkpoints) {
    const key = [
      checkpoint.sourceId,
      checkpoint.epoch,
      checkpoint.lastSequence,
      checkpoint.windowEnd,
    ].join("\0");
    const previous = roots.get(key);
    if (previous !== undefined && previous !== checkpoint.merkleRoot) {
      conflictedSources.add(checkpoint.sourceId);
    } else {
      roots.set(key, checkpoint.merkleRoot);
    }
  }
  return conflictedSources;
}

function verifyCheckpointForEnvelope(
  envelope: ProtocolEvidenceEnvelope,
  requirement: EvidenceCoverageRequirement,
  checkpoints: readonly SourceCheckpoint[],
  conflictedSources: ReadonlySet<string>,
  snapshot: ExternalTrustSnapshot | undefined,
  snapshotTrusted: boolean,
  asOf: Rfc3339Timestamp,
): CasePackStatus {
  if (requirement.checkpointRequirement === "not_applicable") return "not_applicable";
  if (conflictedSources.has(requirement.sourceId)) return "conflicting";
  const inclusion = envelope.checkpointInclusion;
  if (inclusion === undefined) return requirement.checkpointRequirement === "required" ? "missing" : "not_applicable";
  const checkpoint = checkpoints.find((candidate) => candidate.checkpointId === inclusion.checkpointId);
  if (checkpoint === undefined) return "missing";
  if (checkpoint.declaredGaps.length > 0) return "missing";
  const verificationTime = timestampMillis(asOf);
  const checkpointTime = timestampMillis(checkpoint.issuedAt);
  if (checkpointTime > verificationTime) return "missing";
  const maximumAge = requirement.maxCheckpointAgeSeconds;
  if (
    maximumAge !== undefined
    && verificationTime - checkpointTime > maximumAge * 1_000
  ) {
    return "missing";
  }
  const inclusionStatus = verifyCheckpointInclusion(envelope, checkpoint);
  if (inclusionStatus !== "satisfied") return inclusionStatus;
  const proofStatus = verifyCheckpointProof(checkpoint, snapshot, snapshotTrusted);
  if (requirement.checkpointRequirement === "optional" && proofStatus === "missing") return "satisfied";
  return proofStatus;
}

function genericInvalidReport(
  nativeBundle: BundleVerificationReport,
  issues: readonly ValidationIssue[],
): CasePackVerificationReport {
  return {
    valid: false,
    integrityStatus: "conflicting",
    coverageStatus: "unknown",
    sourceTruthStatus: "not_applicable",
    upstreamValidStatus: "unknown",
    evidenceEligibilityStatus: "missing",
    externalTrustStatus: "unknown",
    delegationStatus: "unknown",
    globalCompleteness: "not-established",
    nativeBundle,
    envelopes: [],
    requirements: [],
    issues,
  };
}

/**
 * Verifies a CasePack without I/O or network access. Source truth and global
 * completeness remain unestablished even when bounded coverage is satisfied.
 */
export function verifyMandateBoundCasePack(
  value: unknown,
  anchors: CasePackVerificationAnchors,
): CasePackVerificationReport {
  const issues: ValidationIssue[] = [];
  const shape = validateCasePackShape(value, issues);
  if (!shape.valid || shape.pack === undefined) return genericInvalidReport(shape.nativeBundle, issues);
  const pack = shape.pack;
  const rawEvidence = rawEvidenceMap(anchors.rawEvidence, issues);
  let integrityStatus: CasePackStatus = issues.length === 0 ? "satisfied" : "conflicting";

  const contract = pack.coverageContract;
  let coverageTrustStatus: CasePackStatus = "satisfied";
  if (
    !isTimestamp(anchors.asOf)
    || !isSha256Digest(anchors.coveragePolicyDigest)
    || !isSha256Digest(anchors.coverageContractDigest)
  ) {
    addIssue(issues, "$anchors", "MBCP_ANCHOR_INVALID", "Coverage verification anchors are invalid");
    coverageTrustStatus = "unknown";
  } else if (
    contract.contractDigest !== anchors.coverageContractDigest
    || contract.policyDigest !== anchors.coveragePolicyDigest
    || contract.nativeBundleRootDigest !== pack.nativeEvidenceBundle.rootDigest
  ) {
    addIssue(issues, "$.coverageContract", "MBCP_COVERAGE_PIN_MISMATCH", "Coverage contract does not match caller-owned pins");
    coverageTrustStatus = "conflicting";
  } else if (
    timestampMillis(anchors.asOf) < timestampMillis(contract.validFrom)
    || timestampMillis(anchors.asOf) >= timestampMillis(contract.validUntil)
  ) {
    addIssue(issues, "$.coverageContract", "MBCP_COVERAGE_EXPIRED", "Coverage contract is not valid at the verification instant");
    coverageTrustStatus = "missing";
  }

  let externalTrustStatus: CasePackStatus = "not_applicable";
  let snapshotTrusted = false;
  if (pack.externalTrustSnapshot !== undefined) {
    const snapshot = pack.externalTrustSnapshot;
    if (anchors.externalTrustSnapshotDigest === undefined) {
      externalTrustStatus = "unknown";
    } else if (snapshot.snapshotDigest !== anchors.externalTrustSnapshotDigest) {
      externalTrustStatus = "conflicting";
      addIssue(issues, "$.externalTrustSnapshot", "MBCP_EXTERNAL_TRUST_PIN_MISMATCH", "External trust snapshot does not match caller-owned pin");
    } else if (
      timestampMillis(anchors.asOf) < timestampMillis(snapshot.issuedAt)
      || timestampMillis(anchors.asOf) >= timestampMillis(snapshot.expiresAt)
    ) {
      externalTrustStatus = "missing";
      addIssue(issues, "$.externalTrustSnapshot", "MBCP_EXTERNAL_TRUST_STALE", "External trust snapshot is not current at the verification instant");
    } else {
      externalTrustStatus = "satisfied";
      snapshotTrusted = true;
    }
  }

  let delegationStatus: CasePackStatus = "satisfied";
  if (
    timestampMillis(anchors.asOf) < timestampMillis(pack.delegationContext.validFrom)
    || timestampMillis(anchors.asOf) >= timestampMillis(pack.delegationContext.validUntil)
  ) {
    delegationStatus = "missing";
    addIssue(issues, "$.delegationContext", "MBCP_DELEGATION_EXPIRED", "Delegation context is not current at the verification instant");
  }

  const envelopeBase = new Map<string, {
    integrity: CasePackStatus;
    mapping: CasePackStatus;
  }>();
  for (const envelope of pack.protocolEvidence) {
    const supplied = rawEvidence.get(envelope.rawEvidence.reference.referenceId);
    let rawStatus: CasePackStatus = "unknown";
    if (supplied !== undefined) {
      rawStatus = supplied.byteLength === envelope.rawEvidence.byteLength
        && sha256Bytes(supplied) === envelope.rawEvidence.digest
        ? "satisfied"
        : "conflicting";
      if (rawStatus === "conflicting") {
        addIssue(issues, "$.protocolEvidence[].rawEvidence", "MBCP_RAW_DIGEST_MISMATCH", "Supplied raw evidence does not match its committed bytes");
      }
    }
    const mapped = verifyMappedOutputs(envelope, pack.nativeEvidenceBundle, issues);
    envelopeBase.set(envelope.envelopeId, {
      integrity: combineStatuses([rawStatus, mapped], "unknown"),
      mapping: mapped,
    });
  }

  const conflictedSources = checkpointConflicts(pack.sourceCheckpoints);
  if (conflictedSources.size > 0) {
    addIssue(issues, "$.sourceCheckpoints", "MBCP_CHECKPOINT_EQUIVOCATION", "Source checkpoints contain conflicting commitments");
  }

  const requirementResults: CoverageRequirementResult[] = [];
  const requirementStatus = new Map<string, CasePackStatus>();
  for (const requirement of contract.requirements) {
    const matches = pack.protocolEvidence.filter((envelope) =>
      envelope.sourceId === requirement.sourceId
      && envelope.eventClass === requirement.eventClass
      && requirement.mediaTypes.includes(envelope.mediaType)
      && timestampMillis(envelope.capturedAt) >= timestampMillis(requirement.windowStart)
      && timestampMillis(envelope.capturedAt) <= timestampMillis(requirement.windowEnd));
    let status: CasePackStatus;
    if (coverageTrustStatus !== "satisfied") {
      status = coverageTrustStatus;
    } else if (conflictedSources.has(requirement.sourceId)) {
      status = "conflicting";
    } else if (matches.length < requirement.minEnvelopes) {
      status = "missing";
    } else {
      const statuses: CasePackStatus[] = [];
      for (const envelope of matches) {
        const base = envelopeBase.get(envelope.envelopeId);
        if (base !== undefined) statuses.push(base.integrity);
        if (!envelope.upstreamValid) statuses.push("missing");
        statuses.push(verifyCheckpointForEnvelope(
          envelope,
          requirement,
          pack.sourceCheckpoints,
          conflictedSources,
          pack.externalTrustSnapshot,
          snapshotTrusted,
          anchors.asOf,
        ));
      }
      status = combineStatuses(
        statuses.filter((candidate) => candidate !== "not_applicable"),
        "satisfied",
      );
    }
    requirementStatus.set(requirement.requirementId, status);
    requirementResults.push({
      requirementId: requirement.requirementId,
      status,
      matchedEnvelopes: matches.length,
    });
  }

  const coverageStatus = combineStatuses(
    [coverageTrustStatus, ...requirementResults.map((result) => result.status)]
      .filter((status) => status !== "not_applicable"),
    "unknown",
  );
  const envelopeResults: EnvelopeVerificationResult[] = pack.protocolEvidence.map((envelope) => {
    const matchingRequirements = contract.requirements.filter((requirement) =>
      requirement.sourceId === envelope.sourceId
      && requirement.eventClass === envelope.eventClass
      && requirement.mediaTypes.includes(envelope.mediaType)
      && timestampMillis(envelope.capturedAt) >= timestampMillis(requirement.windowStart)
      && timestampMillis(envelope.capturedAt) <= timestampMillis(requirement.windowEnd));
    const envelopeCoverage = matchingRequirements.length === 0
      ? "missing"
      : combineStatuses(
        matchingRequirements.map((requirement) => requirementStatus.get(requirement.requirementId) ?? "unknown"),
        "unknown",
      );
    const base = envelopeBase.get(envelope.envelopeId);
    const envelopeIntegrity = base?.integrity ?? "unknown";
    const evidenceEligible = envelopeIntegrity === "satisfied"
      && envelope.upstreamValid
      && envelopeCoverage === "satisfied"
      && delegationStatus === "satisfied";
    return {
      envelopeId: envelope.envelopeId,
      integrityStatus: envelopeIntegrity,
      coverageStatus: envelopeCoverage,
      sourceTruthStatus: "unknown",
      upstreamValid: envelope.upstreamValid,
      evidenceEligible,
    };
  });

  const envelopeIntegrityStatus = combineStatuses(
    envelopeResults.map((result) => result.integrityStatus),
    "unknown",
  );
  integrityStatus = combineStatuses([integrityStatus, envelopeIntegrityStatus], "unknown");
  const upstreamValidStatus = pack.protocolEvidence.every((envelope) => envelope.upstreamValid)
    ? "satisfied"
    : "missing";
  const evidenceEligibilityStatus = envelopeResults.every((result) => result.evidenceEligible)
    ? "satisfied"
    : "missing";
  const valid = integrityStatus === "satisfied"
    && coverageStatus === "satisfied"
    && upstreamValidStatus === "satisfied"
    && evidenceEligibilityStatus === "satisfied"
    && delegationStatus === "satisfied"
    && (externalTrustStatus === "satisfied" || externalTrustStatus === "not_applicable");

  return {
    valid,
    casePackId: pack.casePackId,
    casePackDigest: pack.casePackDigest,
    integrityStatus,
    coverageStatus,
    sourceTruthStatus: "unknown",
    upstreamValidStatus,
    evidenceEligibilityStatus,
    externalTrustStatus,
    delegationStatus,
    globalCompleteness: "not-established",
    nativeBundle: shape.nativeBundle,
    envelopes: envelopeResults,
    requirements: requirementResults,
    issues,
  };
}
