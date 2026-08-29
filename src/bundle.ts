import { Buffer } from "node:buffer";
import {
  canonicalBytes,
  digestBytes,
  isSha256Digest,
  sha256Bytes,
  sha256Digest,
} from "./canonical.js";
import { decodeProofHeader, verifySignedArtifactDigest } from "./crypto.js";
import type {
  BundleEntry,
  BundleManifest,
  BundleObject,
  BundlePins,
  BundleVerificationReport,
  EvaluationAnchors,
  EvaluationCase,
  EvidenceBundle,
  LiabilityDecision,
  Sha256Digest,
  SignedArtifact,
  ValidationIssue,
} from "./domain.js";
import {
  SCHEMA_IDS,
  schemaDigestForArtifactType,
  validateArtifact,
  validateSignedArtifact,
} from "./validation.js";

const ASCII_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ASCII_LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const ASCII_DIGITS = "0123456789";
const ASCII_IDENTIFIER_LEAD = ASCII_UPPERCASE + ASCII_LOWERCASE + ASCII_DIGITS;
const ASCII_IDENTIFIER_CHARACTERS = ASCII_IDENTIFIER_LEAD + "._:-";
const SAFE_BUNDLE_PATH_CHARACTERS = ASCII_LOWERCASE + ASCII_DIGITS + "._-/";

const CASE_INDEX_PATH = "case/index.json";
const MANDATE_PATH = "evidence/mandate.json";
const RECEIPT_PATH = "evidence/execution-receipt.json";
const INCIDENT_PATH = "evidence/incident-report.json";
const POLICY_PATH = "policy/liability-policy.json";
const RULEBOOK_PATH = "policy/rulebook.json";
const TRUST_PATH = "trust/snapshot.json";
const PRIOR_DECISION_PATH = "history/prior-decision.json";
const DECISION_PATH = "decision/liability-decision.json";
const JSON_MEDIA_TYPE = "application/agent-liability+json";

interface BundleCaseIndex {
  readonly caseId: string;
  readonly asOf: string;
  readonly mandatePath?: typeof MANDATE_PATH;
  readonly executionReceiptPath?: typeof RECEIPT_PATH;
  readonly incidentReportPath?: typeof INCIDENT_PATH;
  readonly runtimeEventPaths: readonly string[];
  readonly priorReceiptPaths: readonly string[];
  readonly causationAttestationPaths: readonly string[];
  readonly priorDecisionPath?: typeof PRIOR_DECISION_PATH;
  readonly decisionPath?: typeof DECISION_PATH;
  readonly appealId?: string;
}

/** External replay anchors. They are never read from the bundle being tested. */
export type BundleReplayAnchors = Pick<EvaluationAnchors, "pins" | "trustRootJwk">;

interface ObjectWithEntry {
  readonly object: BundleObject;
  readonly entry: BundleEntry;
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort(compareAscii);
  const wanted = [...expected].sort(compareAscii);
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function isProtocolIdentifier(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 128) return false;
  const first = value[0];
  if (first === undefined || !ASCII_IDENTIFIER_LEAD.includes(first)) {
    return false;
  }
  for (const character of value) if (!ASCII_IDENTIFIER_CHARACTERS.includes(character)) return false;
  return true;
}

function isProtocolTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 24 || value[19] !== "." || value[23] !== "Z") {
    return false;
  }
  const parsed = new Date(value);
  return !Number.isNaN(parsed.valueOf()) && parsed.toISOString() === value;
}

/** Safe bundle paths are relative, lowercase ASCII, and cannot traverse. */
export function isSafeBundlePath(path: unknown): path is string {
  if (typeof path !== "string" || path.length === 0 || path.length > 240) return false;
  if (path.startsWith("/") || path.endsWith("/") || path.includes("\\") || path.includes("//")) {
    return false;
  }
  const segments = path.split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    return false;
  }
  for (const character of path) {
    if (!SAFE_BUNDLE_PATH_CHARACTERS.includes(character)) return false;
  }
  return true;
}

function artifactOrder<T extends { readonly artifactId: string }>(
  left: SignedArtifact<T>,
  right: SignedArtifact<T>,
): number {
  return compareAscii(left.payload.artifactId, right.payload.artifactId) || compareAscii(left.payloadDigest, right.payloadDigest);
}

function runtimeOrder(
  left: EvaluationCase["runtimeEvents"][number],
  right: EvaluationCase["runtimeEvents"][number],
): number {
  return (
    left.payload.sequence - right.payload.sequence ||
    compareAscii(left.payload.artifactId, right.payload.artifactId) ||
    compareAscii(left.payloadDigest, right.payloadDigest)
  );
}

function numberedPath(prefix: string, index: number): string {
  return `${prefix}/${String(index).padStart(6, "0")}.json`;
}

function makeObject(path: string, content: unknown, schemaId?: string): ObjectWithEntry {
  if (!isSafeBundlePath(path)) throw new TypeError("Unsafe evidence bundle path");
  const bytes = canonicalBytes(content);
  const object: BundleObject = { path, encoding: "jcs-json", content };
  const baseEntry = {
    path,
    mediaType: JSON_MEDIA_TYPE,
    size: bytes.byteLength,
    classification: "internal" as const,
    digest: sha256Bytes(bytes),
  };
  const entry: BundleEntry = schemaId === undefined ? baseEntry : { ...baseEntry, schemaId };
  return { object, entry };
}

function merkleLeaf(entry: BundleEntry): Sha256Digest {
  const metadata = canonicalBytes({
    path: entry.path,
    mediaType: entry.mediaType,
    size: entry.size,
    classification: entry.classification,
    digest: entry.digest,
    ...(entry.schemaId === undefined ? {} : { schemaId: entry.schemaId }),
  });
  return sha256Bytes(Buffer.concat([Buffer.from([0]), metadata]));
}

export function computeMerkleRoot(entries: readonly BundleEntry[]): Sha256Digest {
  if (entries.length === 0) return sha256Bytes(Buffer.from([0]));
  let level = entries.map(merkleLeaf);
  while (level.length > 1) {
    const next: Sha256Digest[] = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      if (left === undefined) throw new Error("Unreachable Merkle state");
      const right = level[index + 1] ?? left;
      next.push(
        sha256Bytes(
          Buffer.concat([Buffer.from([1]), Buffer.from(digestBytes(left)), Buffer.from(digestBytes(right))]),
        ),
      );
    }
    level = next;
  }
  const root = level[0];
  if (root === undefined) throw new Error("Unreachable Merkle state");
  return root;
}

function manifestMaterial(manifest: Omit<BundleManifest, "manifestDigest">): unknown {
  return {
    format: manifest.format,
    evidenceCutoff: manifest.evidenceCutoff,
    pins: manifest.pins,
    entries: manifest.entries,
    merkleRoot: manifest.merkleRoot,
  };
}

function rootMaterial(manifest: BundleManifest): unknown {
  return {
    schemaVersion: "1.0.0",
    manifestDigest: manifest.manifestDigest,
    merkleRoot: manifest.merkleRoot,
  };
}

function rootHex(rootDigest: Sha256Digest): string {
  return rootDigest.slice("sha256:".length);
}

function bundleIdentity(rootDigest: Sha256Digest): {
  readonly artifactId: string;
  readonly bundleId: EvidenceBundle["bundleId"];
} {
  const hex = rootHex(rootDigest);
  return {
    artifactId: `bundle-${hex.slice(0, 24)}`,
    bundleId: `urn:agent-liability:bundle:${hex}`,
  };
}

function normalizedObjects(input: EvaluationCase, decision?: LiabilityDecision): readonly ObjectWithEntry[] {
  const runtimeEvents = [...input.runtimeEvents].sort(runtimeOrder);
  const priorReceipts = [...input.priorReceipts].sort(artifactOrder);
  const causationAttestations = [...input.causationAttestations].sort(artifactOrder);
  const runtimeEventPaths = runtimeEvents.map((_event, index) =>
    numberedPath("evidence/runtime-events", index),
  );
  const causationAttestationPaths = causationAttestations.map((_attestation, index) =>
    numberedPath("evidence/causation-attestations", index),
  );
  const priorReceiptPaths = priorReceipts.map((_receipt, index) =>
    numberedPath("history/prior-receipts", index),
  );
  const caseIndex: BundleCaseIndex = {
    caseId: input.caseId,
    asOf: input.asOf,
    ...(input.mandate === undefined ? {} : { mandatePath: MANDATE_PATH }),
    ...(input.executionReceipt === undefined ? {} : { executionReceiptPath: RECEIPT_PATH }),
    ...(input.incidentReport === undefined ? {} : { incidentReportPath: INCIDENT_PATH }),
    runtimeEventPaths,
    priorReceiptPaths,
    causationAttestationPaths,
    ...(input.priorDecision === undefined ? {} : { priorDecisionPath: PRIOR_DECISION_PATH }),
    ...(decision === undefined ? {} : { decisionPath: DECISION_PATH }),
    ...(input.appealId === undefined ? {} : { appealId: input.appealId }),
  };

  const values: ObjectWithEntry[] = [
    makeObject(CASE_INDEX_PATH, caseIndex),
    makeObject(POLICY_PATH, input.policy, input.policy.schemaId),
    makeObject(RULEBOOK_PATH, input.rulebook, input.rulebook.schemaId),
    makeObject(TRUST_PATH, input.trustSnapshot, input.trustSnapshot.schemaId),
  ];
  if (input.mandate !== undefined) {
    values.push(makeObject(MANDATE_PATH, input.mandate, input.mandate.schemaId));
  }
  if (input.executionReceipt !== undefined) {
    values.push(makeObject(RECEIPT_PATH, input.executionReceipt, input.executionReceipt.schemaId));
  }
  if (input.incidentReport !== undefined) {
    values.push(makeObject(INCIDENT_PATH, input.incidentReport, input.incidentReport.schemaId));
  }
  for (const [index, artifact] of runtimeEvents.entries()) {
    const path = runtimeEventPaths[index];
    if (path === undefined) throw new Error("Unreachable runtime event path state");
    values.push(makeObject(path, artifact, artifact.schemaId));
  }
  for (const [index, artifact] of causationAttestations.entries()) {
    const path = causationAttestationPaths[index];
    if (path === undefined) throw new Error("Unreachable causation path state");
    values.push(makeObject(path, artifact, artifact.schemaId));
  }
  for (const [index, artifact] of priorReceipts.entries()) {
    const path = priorReceiptPaths[index];
    if (path === undefined) throw new Error("Unreachable prior receipt path state");
    values.push(makeObject(path, artifact, artifact.schemaId));
  }
  if (input.priorDecision !== undefined) {
    values.push(makeObject(PRIOR_DECISION_PATH, input.priorDecision, input.priorDecision.schemaId));
  }
  if (decision !== undefined) values.push(makeObject(DECISION_PATH, decision));
  return values.sort((left, right) => compareAscii(left.object.path, right.object.path));
}

/**
 * Creates the single-file canonical ALBX object. No clock, randomness, I/O, or
 * signing key is consulted; identical inputs produce byte-identical output.
 */
export function createEvidenceBundle(input: EvaluationCase, decision?: LiabilityDecision): EvidenceBundle {
  const normalized = normalizedObjects(input, decision);
  const entries = normalized.map((item) => item.entry);
  const objects = normalized.map((item) => item.object);
  const merkleRoot = computeMerkleRoot(entries);
  const manifestWithoutDigest: Omit<BundleManifest, "manifestDigest"> = {
    format: "agent-liability-bundle-manifest/v1",
    evidenceCutoff: input.asOf,
    pins: input.pins,
    entries,
    merkleRoot,
  };
  const manifest: BundleManifest = {
    ...manifestWithoutDigest,
    manifestDigest: sha256Digest(manifestMaterial(manifestWithoutDigest)),
  };
  const rootDigest = sha256Digest(rootMaterial(manifest));
  return {
    schemaVersion: "1.0.0",
    ...bundleIdentity(rootDigest),
    rootDigest,
    manifest,
    objects,
    proofs: [],
  };
}

function issue(path: string, code: ValidationIssue["code"], message: string): ValidationIssue {
  return { path, code, message };
}

function verifyClosedShapes(bundle: EvidenceBundle, issues: ValidationIssue[]): void {
  if (!isPlainObject(bundle) || !exactKeys(bundle, ["schemaVersion", "artifactId", "bundleId", "rootDigest", "manifest", "objects", "proofs"])) {
    issues.push(issue("$", "ALB_SCHEMA_INVALID", "Bundle has missing or unknown properties"));
    return;
  }
  if (
    !isPlainObject(bundle.manifest) ||
    !exactKeys(bundle.manifest, ["format", "evidenceCutoff", "pins", "entries", "manifestDigest", "merkleRoot"])
  ) {
    issues.push(issue("$.manifest", "ALB_SCHEMA_INVALID", "Manifest has missing or unknown properties"));
    return;
  }
  if (
    !isPlainObject(bundle.manifest.pins) ||
    !exactKeys(bundle.manifest.pins, [
      "asOf",
      "policyDigest",
      "trustSnapshotDigest",
      "rulebookDigest",
      "schemaDigests",
      "engineVersion",
    ])
  ) {
    issues.push(issue("$.manifest.pins", "ALB_SCHEMA_INVALID", "Pins have missing or unknown properties"));
  }
}

function verifyEntries(bundle: EvidenceBundle, issues: ValidationIssue[]): void {
  if (!Array.isArray(bundle.manifest.entries) || !Array.isArray(bundle.objects)) {
    issues.push(issue("$.manifest.entries", "ALB_SCHEMA_INVALID", "Entries and objects must be arrays"));
    return;
  }
  if (bundle.manifest.entries.length === 0 || bundle.manifest.entries.length !== bundle.objects.length) {
    issues.push(issue("$.manifest.entries", "ALB_SCHEMA_INVALID", "Manifest and object counts must match"));
  }
  const paths = new Set<string>();
  for (let index = 0; index < bundle.manifest.entries.length; index += 1) {
    const entry = bundle.manifest.entries[index];
    const object = bundle.objects[index];
    const path = `$.manifest.entries[${String(index)}]`;
    if (!isPlainObject(entry)) {
      issues.push(issue(path, "ALB_SCHEMA_INVALID", "Entry must be an object"));
      continue;
    }
    const expectedEntryKeys = entry.schemaId === undefined
      ? ["path", "mediaType", "size", "classification", "digest"]
      : ["path", "mediaType", "schemaId", "size", "classification", "digest"];
    if (!exactKeys(entry, expectedEntryKeys)) {
      issues.push(issue(path, "ALB_SCHEMA_INVALID", "Entry has missing or unknown properties"));
    }
    if (!isSafeBundlePath(entry.path)) {
      issues.push(issue(`${path}.path`, "ALB_SCHEMA_INVALID", "Unsafe bundle path"));
      continue;
    }
    if (paths.has(entry.path)) {
      issues.push(issue(`${path}.path`, "ALB_SCHEMA_INVALID", "Duplicate bundle path"));
    }
    paths.add(entry.path);
    if (index > 0) {
      const previous = bundle.manifest.entries[index - 1];
      if (previous !== undefined && compareAscii(previous.path, entry.path) >= 0) {
        issues.push(issue(`${path}.path`, "ALB_SCHEMA_INVALID", "Manifest is not strictly sorted"));
      }
    }
    if (!isPlainObject(object) || !exactKeys(object, ["path", "encoding", "content"])) {
      issues.push(issue(`$.objects[${String(index)}]`, "ALB_SCHEMA_INVALID", "Object has missing or unknown properties"));
      continue;
    }
    if (object.path !== entry.path || object.encoding !== "jcs-json") {
      issues.push(issue(`$.objects[${String(index)}]`, "ALB_SCHEMA_INVALID", "Object does not match its manifest entry"));
      continue;
    }
    try {
      const bytes = canonicalBytes(object.content);
      if (!Number.isSafeInteger(entry.size) || entry.size !== bytes.byteLength) {
        issues.push(issue(`${path}.size`, "ALB_DIGEST_MISMATCH", "Entry size mismatch"));
      }
      if (entry.digest !== sha256Bytes(bytes)) {
        issues.push(issue(`${path}.digest`, "ALB_DIGEST_MISMATCH", "Entry digest mismatch"));
      }
    } catch {
      issues.push(issue(`$.objects[${String(index)}].content`, "ALB_CANONICAL_UNSUPPORTED", "Object is not canonicalizable"));
    }
  }
}

function exactNumberedPaths(paths: readonly string[], prefix: string): boolean {
  return paths.every((path, index) => path === numberedPath(prefix, index));
}

function semanticSignedObject(
  bundle: EvidenceBundle,
  path: string,
  expectedType: SignedArtifact<unknown>["artifactType"],
  issues: ValidationIssue[],
): void {
  const object = bundle.objects.find((candidate) => candidate.path === path);
  const entry = bundle.manifest.entries.find((candidate) => candidate.path === path);
  if (object === undefined || entry === undefined) return;
  const artifact = object.content as SignedArtifact<unknown>;
  const schema = validateSignedArtifact(artifact);
  const digest = verifySignedArtifactDigest(artifact);
  if (!schema.ok || !digest.ok || artifact.artifactType !== expectedType) {
    issues.push(issue(`$.objects[path=${path}]`, "ALB_SCHEMA_INVALID", "Bundle object has the wrong signed artifact type"));
    return;
  }
  if (entry.schemaId !== artifact.schemaId || artifact.schemaId !== SCHEMA_IDS[expectedType]) {
    issues.push(issue(`$.manifest.entries[path=${path}].schemaId`, "ALB_SCHEMA_INVALID", "Entry schema does not match its artifact"));
  }
  const expectedSchemaDigest = schemaDigestForArtifactType(expectedType);
  if (artifact.proofs.length !== 1) {
    issues.push(issue(`$.objects[path=${path}].proofs`, "ALB_PROOF_BINDING", "Signed bundle artifact must have one proof"));
    return;
  }
  const proof = artifact.proofs[0];
  const header = proof === undefined ? undefined : decodeProofHeader(proof);
  if (
    header === undefined ||
    !header.ok ||
    header.value.schemaDigest !== expectedSchemaDigest ||
    !bundle.manifest.pins.schemaDigests.includes(expectedSchemaDigest)
  ) {
    issues.push(issue(`$.objects[path=${path}].proofs`, "ALB_PROOF_BINDING", "Artifact proof is not bound to its exact pinned schema"));
  }
}

function verifySemanticClosure(bundle: EvidenceBundle, issues: ValidationIssue[]): void {
  const indexObject = bundle.objects.find((candidate) => candidate.path === CASE_INDEX_PATH);
  if (indexObject === undefined || !isBundleCaseIndex(indexObject.content)) {
    issues.push(issue(`$.objects[path=${CASE_INDEX_PATH}]`, "ALB_SCHEMA_INVALID", "Bundle case index is missing or invalid"));
    return;
  }
  const index = indexObject.content;
  if (
    index.asOf !== bundle.manifest.evidenceCutoff ||
    index.asOf !== bundle.manifest.pins.asOf
  ) {
    issues.push(issue(`$.objects[path=${CASE_INDEX_PATH}].content.asOf`, "ALB_DIGEST_MISMATCH", "Case index cutoff does not match manifest pins"));
  }
  const expected = new Set<string>([CASE_INDEX_PATH, POLICY_PATH, RULEBOOK_PATH, TRUST_PATH]);
  if (index.mandatePath !== undefined) expected.add(index.mandatePath);
  if (index.executionReceiptPath !== undefined) expected.add(index.executionReceiptPath);
  if (index.incidentReportPath !== undefined) expected.add(index.incidentReportPath);
  if (index.priorDecisionPath !== undefined) expected.add(index.priorDecisionPath);
  if (index.decisionPath !== undefined) expected.add(index.decisionPath);
  for (const path of index.runtimeEventPaths) expected.add(path);
  for (const path of index.priorReceiptPaths) expected.add(path);
  for (const path of index.causationAttestationPaths) expected.add(path);
  const actual = new Set(bundle.manifest.entries.map((entry) => entry.path));
  if (
    actual.size !== expected.size ||
    [...actual].some((path) => !expected.has(path)) ||
    [...expected].some((path) => !actual.has(path))
  ) {
    issues.push(issue("$.manifest.entries", "ALB_SCHEMA_INVALID", "Manifest is not semantically closed by case/index.json"));
  }

  semanticSignedObject(bundle, POLICY_PATH, "liability_policy", issues);
  semanticSignedObject(bundle, RULEBOOK_PATH, "rulebook", issues);
  semanticSignedObject(bundle, TRUST_PATH, "trust_snapshot", issues);
  if (index.mandatePath !== undefined) semanticSignedObject(bundle, index.mandatePath, "mandate_envelope", issues);
  if (index.executionReceiptPath !== undefined) {
    semanticSignedObject(bundle, index.executionReceiptPath, "execution_receipt", issues);
  }
  if (index.incidentReportPath !== undefined) {
    semanticSignedObject(bundle, index.incidentReportPath, "incident_report", issues);
  }
  for (const path of index.runtimeEventPaths) semanticSignedObject(bundle, path, "runtime_event", issues);
  for (const path of index.priorReceiptPaths) semanticSignedObject(bundle, path, "execution_receipt", issues);
  for (const path of index.causationAttestationPaths) {
    semanticSignedObject(bundle, path, "causation_attestation", issues);
  }
  if (index.priorDecisionPath !== undefined) {
    semanticSignedObject(bundle, index.priorDecisionPath, "liability_decision", issues);
  }
  if (index.decisionPath !== undefined) {
    const decision = contentAt(bundle, index.decisionPath);
    if (!validateArtifact("liability_decision", decision).ok) {
      issues.push(issue(`$.objects[path=${index.decisionPath}]`, "ALB_SCHEMA_INVALID", "Bundled decision is schema-invalid"));
    }
  }

  const policy = contentAt(bundle, POLICY_PATH) as SignedArtifact<unknown>;
  const rulebook = contentAt(bundle, RULEBOOK_PATH) as SignedArtifact<unknown>;
  const trust = contentAt(bundle, TRUST_PATH) as SignedArtifact<unknown>;
  if (
    policy.payloadDigest !== bundle.manifest.pins.policyDigest ||
    rulebook.payloadDigest !== bundle.manifest.pins.rulebookDigest ||
    trust.payloadDigest !== bundle.manifest.pins.trustSnapshotDigest
  ) {
    issues.push(issue("$.manifest.pins", "ALB_DIGEST_MISMATCH", "Pinned artifacts do not match bundle content"));
  }
}

export function verifyEvidenceBundle(bundle: EvidenceBundle): BundleVerificationReport {
  const issues: ValidationIssue[] = [];
  let verifiedEntries = 0;
  let reportedBundleId: string | undefined;
  let reportedManifestDigest: Sha256Digest | undefined;
  let reportedMerkleRoot: Sha256Digest | undefined;
  let totalEntries = 0;
  try {
    const schema = validateArtifact<EvidenceBundle>("evidence_bundle", bundle);
    if (!schema.ok) issues.push(...schema.issues);
    verifyClosedShapes(bundle, issues);
    if (bundle.schemaVersion !== "1.0.0" || bundle.manifest.format !== "agent-liability-bundle-manifest/v1") {
      issues.push(issue("$", "ALB_SCHEMA_INVALID", "Unsupported bundle format"));
    }
    verifyEntries(bundle, issues);
    verifySemanticClosure(bundle, issues);
    reportedBundleId = typeof bundle.bundleId === "string" ? bundle.bundleId : undefined;
    reportedManifestDigest = isSha256Digest(bundle.manifest.manifestDigest)
      ? bundle.manifest.manifestDigest
      : undefined;
    reportedMerkleRoot = isSha256Digest(bundle.manifest.merkleRoot)
      ? bundle.manifest.merkleRoot
      : undefined;
    totalEntries = Array.isArray(bundle.manifest.entries) ? bundle.manifest.entries.length : 0;
    verifiedEntries = bundle.manifest.entries.filter((entry, index) => {
      const object = bundle.objects[index];
      if (object === undefined || object.path !== entry.path || object.encoding !== "jcs-json") return false;
      try {
        const bytes = canonicalBytes(object.content);
        return bytes.byteLength === entry.size && sha256Bytes(bytes) === entry.digest;
      } catch {
        return false;
      }
    }).length;

    const schemaPins = bundle.manifest.pins.schemaDigests;
    if (
      !Array.isArray(schemaPins) ||
      schemaPins.some((digest) => !isSha256Digest(digest)) ||
      schemaPins.some((digest, index) => index > 0 && schemaPins[index - 1] !== undefined && schemaPins[index - 1] >= digest)
    ) {
      issues.push(issue("$.manifest.pins.schemaDigests", "ALB_SCHEMA_INVALID", "Schema pins must be unique sorted digests"));
    }
    if (bundle.manifest.evidenceCutoff !== bundle.manifest.pins.asOf) {
      issues.push(issue("$.manifest.evidenceCutoff", "ALB_DIGEST_MISMATCH", "Evidence cutoff does not match pinned asOf"));
    }
    const expectedMerkle = computeMerkleRoot(bundle.manifest.entries);
    if (bundle.manifest.merkleRoot !== expectedMerkle) {
      issues.push(issue("$.manifest.merkleRoot", "ALB_DIGEST_MISMATCH", "Merkle root mismatch"));
    }
    const manifestWithoutDigest: Omit<BundleManifest, "manifestDigest"> = {
      format: bundle.manifest.format,
      evidenceCutoff: bundle.manifest.evidenceCutoff,
      pins: bundle.manifest.pins,
      entries: bundle.manifest.entries,
      merkleRoot: bundle.manifest.merkleRoot,
    };
    const expectedManifest = sha256Digest(manifestMaterial(manifestWithoutDigest));
    if (bundle.manifest.manifestDigest !== expectedManifest) {
      issues.push(issue("$.manifest.manifestDigest", "ALB_DIGEST_MISMATCH", "Manifest digest mismatch"));
    }
    const expectedRoot = sha256Digest(rootMaterial(bundle.manifest));
    if (bundle.rootDigest !== expectedRoot) {
      issues.push(issue("$.rootDigest", "ALB_DIGEST_MISMATCH", "Bundle root digest mismatch"));
    }
    const expectedIdentity = bundleIdentity(expectedRoot);
    if (bundle.bundleId !== expectedIdentity.bundleId || bundle.artifactId !== expectedIdentity.artifactId) {
      issues.push(issue("$.bundleId", "ALB_DIGEST_MISMATCH", "Bundle identity does not match root digest"));
    }
    if (!Array.isArray(bundle.proofs) || bundle.proofs.length !== 0) {
      issues.push(issue("$.proofs", "ALB_PROOF_INVALID", "This verifier accepts only unsigned deterministic bundle roots"));
    }
    canonicalBytes(bundle);
  } catch {
    issues.push(issue("$", "ALB_SCHEMA_INVALID", "Malformed evidence bundle"));
  }
  return {
    valid: issues.length === 0,
    ...(reportedBundleId === undefined ? {} : { bundleId: reportedBundleId }),
    ...(reportedManifestDigest === undefined ? {} : { manifestDigest: reportedManifestDigest }),
    ...(reportedMerkleRoot === undefined ? {} : { merkleRoot: reportedMerkleRoot }),
    verifiedEntries,
    totalEntries,
    trustChecked: false,
    issues,
  };
}

function contentAt(bundle: EvidenceBundle, path: string): unknown {
  const object = bundle.objects.find((candidate) => candidate.path === path);
  if (object === undefined) throw new TypeError(`Missing bundle object: ${path}`);
  return object.content;
}

function isBundleCaseIndex(value: unknown): value is BundleCaseIndex {
  if (!isPlainObject(value)) return false;
  const expected = [
    "caseId",
    "asOf",
    "runtimeEventPaths",
    "priorReceiptPaths",
    "causationAttestationPaths",
  ];
  if (value.mandatePath !== undefined) expected.push("mandatePath");
  if (value.executionReceiptPath !== undefined) expected.push("executionReceiptPath");
  if (value.incidentReportPath !== undefined) expected.push("incidentReportPath");
  if (value.priorDecisionPath !== undefined) expected.push("priorDecisionPath");
  if (value.decisionPath !== undefined) expected.push("decisionPath");
  if (value.appealId !== undefined) expected.push("appealId");
  const shapeValid = (
    exactKeys(value, expected) &&
    isProtocolIdentifier(value.caseId) &&
    isProtocolTimestamp(value.asOf) &&
    (value.mandatePath === undefined || value.mandatePath === MANDATE_PATH) &&
    (value.executionReceiptPath === undefined || value.executionReceiptPath === RECEIPT_PATH) &&
    (value.incidentReportPath === undefined || value.incidentReportPath === INCIDENT_PATH) &&
    Array.isArray(value.runtimeEventPaths) &&
    value.runtimeEventPaths.every(isSafeBundlePath) &&
    Array.isArray(value.priorReceiptPaths) &&
    value.priorReceiptPaths.every(isSafeBundlePath) &&
    Array.isArray(value.causationAttestationPaths) &&
    value.causationAttestationPaths.every(isSafeBundlePath) &&
    (value.priorDecisionPath === undefined || value.priorDecisionPath === PRIOR_DECISION_PATH) &&
    (value.decisionPath === undefined || value.decisionPath === DECISION_PATH) &&
    (value.appealId === undefined || isProtocolIdentifier(value.appealId))
  );
  if (!shapeValid) return false;
  if (
    !exactNumberedPaths(value.runtimeEventPaths as string[], "evidence/runtime-events") ||
    !exactNumberedPaths(value.priorReceiptPaths as string[], "history/prior-receipts") ||
    !exactNumberedPaths(value.causationAttestationPaths as string[], "evidence/causation-attestations")
  ) {
    return false;
  }
  const referenced = [
    ...(value.mandatePath === undefined ? [] : [value.mandatePath]),
    ...(value.executionReceiptPath === undefined ? [] : [value.executionReceiptPath]),
    ...(value.incidentReportPath === undefined ? [] : [value.incidentReportPath]),
    ...(value.priorDecisionPath === undefined ? [] : [value.priorDecisionPath]),
    ...(value.decisionPath === undefined ? [] : [value.decisionPath]),
    ...(value.runtimeEventPaths as string[]),
    ...(value.priorReceiptPaths as string[]),
    ...(value.causationAttestationPaths as string[]),
  ];
  return new Set(referenced).size === referenced.length;
}

/** Extracts the exact normalized replay input after full bundle integrity checks. */
export function evaluationCaseFromBundle(
  bundle: EvidenceBundle,
  anchors: BundleReplayAnchors,
): EvaluationCase {
  const report = verifyEvidenceBundle(bundle);
  if (!report.valid) throw new TypeError("Evidence bundle failed integrity verification");
  const index = contentAt(bundle, CASE_INDEX_PATH);
  if (!isBundleCaseIndex(index)) throw new TypeError("Invalid bundle case index");
  const value: EvaluationCase = {
    caseId: index.caseId,
    asOf: index.asOf,
    pins: anchors.pins,
    ...(anchors.trustRootJwk === undefined ? {} : { trustRootJwk: anchors.trustRootJwk }),
    ...(index.mandatePath === undefined
      ? {}
      : {
          mandate: contentAt(bundle, index.mandatePath) as NonNullable<EvaluationCase["mandate"]>,
        }),
    runtimeEvents: index.runtimeEventPaths.map(
      (path) => contentAt(bundle, path) as EvaluationCase["runtimeEvents"][number],
    ),
    priorReceipts: index.priorReceiptPaths.map(
      (path) => contentAt(bundle, path) as EvaluationCase["priorReceipts"][number],
    ),
    ...(index.executionReceiptPath === undefined
      ? {}
      : {
          executionReceipt: contentAt(bundle, index.executionReceiptPath) as NonNullable<
            EvaluationCase["executionReceipt"]
          >,
        }),
    ...(index.incidentReportPath === undefined
      ? {}
      : {
          incidentReport: contentAt(bundle, index.incidentReportPath) as NonNullable<
            EvaluationCase["incidentReport"]
          >,
        }),
    causationAttestations: index.causationAttestationPaths.map(
      (path) => contentAt(bundle, path) as EvaluationCase["causationAttestations"][number],
    ),
    policy: contentAt(bundle, POLICY_PATH) as EvaluationCase["policy"],
    rulebook: contentAt(bundle, RULEBOOK_PATH) as EvaluationCase["rulebook"],
    trustSnapshot: contentAt(bundle, TRUST_PATH) as EvaluationCase["trustSnapshot"],
    evidenceBundle: bundle,
    ...(index.priorDecisionPath === undefined
      ? {}
      : {
          priorDecision: contentAt(bundle, index.priorDecisionPath) as NonNullable<
            EvaluationCase["priorDecision"]
          >,
        }),
    ...(index.appealId === undefined ? {} : { appealId: index.appealId }),
  };
  return value;
}
