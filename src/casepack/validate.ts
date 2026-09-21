import { Buffer } from "node:buffer";
import {
  createPublicKey,
  type JsonWebKeyInput,
} from "node:crypto";
import {
  isSha256Digest,
} from "../canonical.js";
import {
  isSafeBundlePath,
  verifyEvidenceBundle,
} from "../bundle.js";
import type {
  BundleVerificationReport,
  Ed25519PublicJwk,
  EvidenceBundle,
  Sha256Digest,
  ValidationIssue,
} from "../domain.js";
import {
  addIssue,
  BASE64URL_PATTERN,
  casePackMaterial,
  checkpointMaterial,
  compareAscii,
  coverageMaterial,
  delegationMaterial,
  digestCanonical,
  envelopeMaterial,
  exactKeys,
  expectedKeys,
  externalTrustMaterial,
  isBoundedInteger,
  isIdentifier,
  isMediaType,
  isPlainObject,
  isStatus,
  isTimestamp,
  JSON_POINTER_PATTERN,
  mappingMaterial,
  MAX_CHECKPOINTS,
  MAX_PROTOCOL_EVIDENCE,
  MAX_RAW_EVIDENCE_BYTES,
  SEMVER_PATTERN,
  timestampMillis,
} from "./primitives.js";
import type {
  DelegationContext,
  DeterministicMappingTrace,
  EvidenceCoverageContract,
  EvidenceCoverageRequirement,
  ExternalTrustSnapshot,
  MappedArtifactReference,
  MandateBoundCasePack,
  ProtocolEvidenceEnvelope,
  RawEvidenceDescriptor,
  RawEvidenceReference,
  SourceCheckpoint,
  SourceCheckpointInclusion,
} from "./types.js";

export interface ShapeResult {
  readonly valid: boolean;
  readonly pack?: MandateBoundCasePack;
  readonly nativeBundle: BundleVerificationReport;
}

export function emptyBundleReport(): BundleVerificationReport {
  return {
    valid: false,
    verifiedEntries: 0,
    totalEntries: 0,
    trustChecked: false,
    issues: [{ path: "$", code: "ALB_SCHEMA_INVALID", message: "Malformed evidence bundle" }],
  };
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

export function validateCasePackShape(value: unknown, issues: ValidationIssue[]): ShapeResult {
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
