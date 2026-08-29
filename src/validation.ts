import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv2020, type AnySchemaObject, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import formatsModule, { type FormatsPlugin } from "ajv-formats";
import { assertCanonicalizable, sha256Digest } from "./canonical.js";
import type {
  ArtifactType,
  SignedArtifact,
  ValidationIssue,
  ValidationResult,
} from "./domain.js";
import {
  parseStrictJson,
  StrictJsonError,
  type StrictJsonLimits,
} from "./strict-json.js";

export const SCHEMA_FILES = {
  common: "common.schema.json",
  mandate_envelope: "mandate-envelope.schema.json",
  runtime_event: "runtime-event.schema.json",
  execution_receipt: "execution-receipt.schema.json",
  incident_report: "incident-report.schema.json",
  causation_attestation: "causation-attestation.schema.json",
  liability_policy: "liability-policy.schema.json",
  liability_decision: "liability-decision.schema.json",
  evidence_bundle: "evidence-bundle.schema.json",
  trust_snapshot: "trust-snapshot.schema.json",
  appeal_event: "appeal-event.schema.json",
  rulebook: "rulebook.schema.json",
  signed_artifact: "signed-artifact.schema.json",
} as const;

export type SchemaKey = keyof typeof SCHEMA_FILES;

export const SCHEMA_IDS: Readonly<Record<SchemaKey, string>> = Object.freeze(
  Object.fromEntries(
    Object.entries(SCHEMA_FILES).map(([key, file]) => [key, `https://github.com/Oonyl/mandatebound/schemas/v1/${file}`]),
  ) as Record<SchemaKey, string>,
);

const ARTIFACT_SCHEMA_KEYS = new Set<SchemaKey>([
  "mandate_envelope", "runtime_event", "execution_receipt", "incident_report",
  "causation_attestation", "liability_policy", "liability_decision",
  "evidence_bundle", "trust_snapshot", "appeal_event", "rulebook",
]);

function schemaDirectory(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "..", "schemas", "v1");
}

function genericIssues(errors: readonly ErrorObject[] | null | undefined): readonly ValidationIssue[] {
  if (errors === null || errors === undefined || errors.length === 0) {
    return [{ code: "ALB_SCHEMA_INVALID", path: "", message: "Schema validation failed" }];
  }
  return errors.slice(0, 64).map((error) => ({
    code: "ALB_SCHEMA_INVALID",
    path: error.instancePath || "/",
    message: `Schema validation failed (${error.keyword})`,
  }));
}

function semanticIssue(path: string, message: string): ValidationIssue {
  return { code: "ALB_SCHEMA_INVALID", path, message };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Derive the stable v1 decision identifier from every decision field except
 * artifactId. This makes any post-evaluation mutation detectable even before
 * a decision is wrapped in a signature.
 */
export function deriveLiabilityDecisionId(
  decision: Readonly<Record<string, unknown>>,
): `decision-${string}` {
  assertCanonicalizable(decision);
  const material: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of Object.keys(decision)) {
    if (key !== "artifactId") material[key] = decision[key];
  }
  return `decision-${sha256Digest(material).slice("sha256:".length)}`;
}

function semanticValidation(key: SchemaKey, value: unknown): readonly ValidationIssue[] {
  if (!isRecord(value)) return [];
  const issues: ValidationIssue[] = [];
  const before = (left: unknown, right: unknown, path: string): void => {
    if (typeof left === "string" && typeof right === "string" && left >= right) {
      issues.push(semanticIssue(path, "Protocol validity interval is not strictly increasing"));
    }
  };

  if (key === "mandate_envelope") {
    before(value["validFrom"], value["expiresAt"], "/expiresAt");
    const roles = [["principal", "principal"], ["operator", "operator"], ["agent", "agent"], ["modelVendor", "model_vendor"]] as const;
    for (const [field, role] of roles) {
      const actor = value[field];
      if (actor !== undefined && isRecord(actor) && actor["role"] !== role) {
        issues.push(semanticIssue(`/${field}/role`, "Actor role does not match its protocol position"));
      }
    }
  } else if (key === "runtime_event") {
    if (value["eventType"] === "mandate_revoked") {
      const actor = value["actor"];
      if (!isRecord(actor) || actor["role"] !== "principal") {
        issues.push(semanticIssue("/actor/role", "Mandate revocation must be asserted by a principal-role actor"));
      }
    }
  } else if (key === "execution_receipt") {
    const operator = value["operator"];
    if (isRecord(operator) && operator["role"] !== "operator") {
      issues.push(semanticIssue("/operator/role", "Receipt operator must have the operator role"));
    }
  } else if (key === "causation_attestation") {
    const subject = value["subject"];
    const attestor = value["attestor"];
    if (isRecord(subject) && subject["role"] !== "model_vendor") {
      issues.push(semanticIssue("/subject/role", "Causation subject must have the model_vendor role"));
    }
    if (isRecord(attestor) && attestor["role"] !== "causation_attestor") {
      issues.push(semanticIssue("/attestor/role", "Causation attestor must have the causation_attestor role"));
    }
    if (isRecord(subject) && isRecord(attestor) && subject["id"] === attestor["id"]) {
      issues.push(semanticIssue("/attestor/id", "Independent causation attestor must differ from the subject"));
    }
  } else if (key === "liability_policy") {
    before(value["effectiveFrom"], value["effectiveUntil"], "/effectiveUntil");
  } else if (key === "liability_decision") {
    const pins = value["pins"];
    const allocation = value["allocation"];
    const outcome = value["outcome"];
    const policyOutcome = value["policyOutcome"];
    const disposition = value["disposition"];
    if (outcome !== policyOutcome) {
      issues.push(semanticIssue("/policyOutcome", "Policy outcome must equal the final outcome"));
    }
    if (outcome === "unresolved") {
      if (disposition === "allocated") {
        issues.push(semanticIssue("/disposition", "An unresolved decision cannot be allocated"));
      }
      if (allocation !== undefined) {
        issues.push(semanticIssue("/allocation", "An unresolved decision cannot name an allocation"));
      }
    } else {
      if (disposition !== "allocated") {
        issues.push(semanticIssue("/disposition", "A resolved outcome must be allocated"));
      }
      if (!isRecord(allocation)) {
        issues.push(semanticIssue("/allocation", "A resolved outcome must name an allocation"));
      } else if (allocation["role"] !== outcome) {
        issues.push(semanticIssue("/allocation/role", "Allocation role must match the outcome"));
      }
    }
    if (isRecord(pins)) {
      if (value["evaluatedAt"] !== pins["asOf"]) {
        issues.push(semanticIssue("/evaluatedAt", "Decision time must equal its pinned evaluation time"));
      }
      if (value["engineVersion"] !== pins["engineVersion"]) {
        issues.push(semanticIssue("/engineVersion", "Decision engine version must equal its pinned version"));
      }
      const pinnedRefs = [
        ["policyRef", "policyDigest", "liability_policy"],
        ["rulebookRef", "rulebookDigest", "rulebook"],
        ["trustSnapshotRef", "trustSnapshotDigest", "trust_snapshot"],
      ] as const;
      for (const [referenceName, digestName, artifactType] of pinnedRefs) {
        const reference = value[referenceName];
        if (isRecord(reference) && reference["digest"] !== pins[digestName]) {
          issues.push(semanticIssue(`/${referenceName}/digest`, "Decision reference must match its pinned digest"));
        }
        if (isRecord(reference) && reference["artifactType"] !== artifactType) {
          issues.push(semanticIssue(`/${referenceName}/artifactType`, "Decision reference has the wrong artifact type"));
        }
      }
      if (value["evidenceBundleDigest"] !== pins["bundleRootDigest"]) {
        issues.push(semanticIssue("/evidenceBundleDigest", "Decision bundle digest must match its pinned root"));
      }
    }
    if (typeof value["artifactId"] === "string" && value["artifactId"] !== deriveLiabilityDecisionId(value)) {
      issues.push(semanticIssue("/artifactId", "Decision identifier does not match its canonical decision material"));
    }
  } else if (key === "trust_snapshot") {
    const keys = value["keys"];
    if (Array.isArray(keys)) {
      const seen = new Set<string>();
      keys.forEach((entry, index) => {
        if (!isRecord(entry) || typeof entry["kid"] !== "string") return;
        if (seen.has(entry["kid"])) issues.push(semanticIssue(`/keys/${index}/kid`, "Trust key identifier must be unique"));
        seen.add(entry["kid"]);
        before(entry["validFrom"], entry["validUntil"], `/keys/${index}/validUntil`);
      });
    }
  } else if (key === "rulebook") {
    const rules = value["rules"];
    if (Array.isArray(rules)) {
      const ids = new Set<string>();
      const priorities = new Set<number>();
      rules.forEach((rule, index) => {
        if (!isRecord(rule)) return;
        if (typeof rule["id"] === "string") {
          if (ids.has(rule["id"])) issues.push(semanticIssue(`/rules/${index}/id`, "Rule identifiers must be unique"));
          ids.add(rule["id"]);
        }
        if (typeof rule["priority"] === "number") {
          if (priorities.has(rule["priority"])) issues.push(semanticIssue(`/rules/${index}/priority`, "Rule priorities must be unique"));
          priorities.add(rule["priority"]);
        }
      });
    }
  } else if (key === "evidence_bundle") {
    const manifest = value["manifest"];
    const objects = value["objects"];
    if (isRecord(manifest) && Array.isArray(manifest["entries"]) && Array.isArray(objects)) {
      const entryPaths = manifest["entries"].map((entry) => isRecord(entry) ? entry["path"] : undefined);
      const objectPaths = objects.map((entry) => isRecord(entry) ? entry["path"] : undefined);
      const sorted = [...entryPaths].sort();
      if (entryPaths.some((path, index) => path !== sorted[index])) {
        issues.push(semanticIssue("/manifest/entries", "Bundle manifest entries must be sorted by path"));
      }
      if (new Set(entryPaths).size !== entryPaths.length || new Set(objectPaths).size !== objectPaths.length) {
        issues.push(semanticIssue("/objects", "Bundle paths must be unique"));
      }
      if (entryPaths.length !== objectPaths.length || entryPaths.some((path, index) => path !== objectPaths[index])) {
        issues.push(semanticIssue("/objects", "Bundle objects must exactly match manifest entry order"));
      }
    }
  }
  return issues;
}

export class SchemaRegistry {
  readonly #ajv: Ajv2020;
  readonly #validators = new Map<SchemaKey, ValidateFunction>();
  readonly #schemas = new Map<SchemaKey, unknown>();

  public constructor(directory = schemaDirectory()) {
    this.#ajv = new Ajv2020({
      strict: true,
      allErrors: true,
      validateFormats: true,
      removeAdditional: false,
      coerceTypes: false,
      useDefaults: false,
      unicodeRegExp: true,
    });
    const addFormats = ((formatsModule as unknown as { readonly default?: FormatsPlugin }).default
      ?? formatsModule as unknown as FormatsPlugin);
    addFormats(this.#ajv);

    for (const [key, filename] of Object.entries(SCHEMA_FILES) as [SchemaKey, string][]) {
      const text = readFileSync(join(directory, filename), "utf8");
      const schema = parseStrictJson(text, { maxBytes: 262_144, maxDepth: 64, maxNodes: 100_000 });
      this.#schemas.set(key, schema);
      this.#ajv.addSchema(schema as AnySchemaObject, SCHEMA_IDS[key]);
    }
    for (const key of Object.keys(SCHEMA_FILES) as SchemaKey[]) {
      this.#validators.set(key, this.#ajv.getSchema(SCHEMA_IDS[key]) as ValidateFunction);
    }
  }

  public validate<T>(key: SchemaKey, value: unknown): ValidationResult<T> {
    const validator = this.#validators.get(key);
    if (validator === undefined) {
      return { ok: false, issues: [{ code: "ALB_SCHEMA_UNKNOWN", path: "", message: "Unknown protocol schema" }] };
    }
    try {
      assertCanonicalizable(value);
    } catch {
      return { ok: false, issues: [{ code: "ALB_CANONICAL_UNSUPPORTED", path: "", message: "Value is outside the supported canonical JSON subset" }] };
    }
    if (!validator(value)) return { ok: false, issues: genericIssues(validator.errors) };
    const semantic = semanticValidation(key, value);
    if (semantic.length > 0) return { ok: false, issues: semantic };
    return { ok: true, value: value as T, issues: [] };
  }

  public schemaDigest(key: SchemaKey): ReturnType<typeof sha256Digest> {
    const schema = this.#schemas.get(key);
    if (schema === undefined) throw new TypeError("Unknown protocol schema");
    return sha256Digest(schema);
  }

  public schemaDigestForArtifactType(type: ArtifactType): ReturnType<typeof sha256Digest> {
    return this.schemaDigest(schemaKeyForArtifactType(type));
  }
}

let defaultRegistry: SchemaRegistry | undefined;

export function createSchemaRegistry(directory?: string): SchemaRegistry {
  return directory === undefined ? new SchemaRegistry() : new SchemaRegistry(directory);
}

function registry(): SchemaRegistry {
  defaultRegistry ??= createSchemaRegistry();
  return defaultRegistry;
}

export function validateArtifact<T>(key: SchemaKey, value: unknown): ValidationResult<T> {
  return registry().validate<T>(key, value);
}

export function parseAndValidateArtifact<T>(
  key: SchemaKey,
  text: string,
  limits?: Partial<StrictJsonLimits>,
): ValidationResult<T> {
  try {
    const parsed = parseStrictJson(text, limits);
    return validateArtifact<T>(key, parsed);
  } catch (error: unknown) {
    if (error instanceof StrictJsonError) {
      return {
        ok: false,
        issues: [{
          code: error.code,
          path: "",
          message: `Strict JSON parsing failed (offset ${String(error.offset)})`,
        }],
      };
    }
    if (error instanceof TypeError || error instanceof RangeError) {
      return { ok: false, issues: [{ code: "ALB_JSON_INVALID", path: "", message: "JSON input is invalid" }] };
    }
    throw error;
  }
}

export function validateSignedArtifact<T>(artifact: SignedArtifact<T>): ValidationResult<SignedArtifact<T>> {
  const wrapper = validateArtifact<SignedArtifact<T>>("signed_artifact", artifact);
  if (!wrapper.ok) return wrapper;
  const payloadKey = artifact.artifactType as SchemaKey;
  if (!ARTIFACT_SCHEMA_KEYS.has(payloadKey)) {
    return { ok: false, issues: [{ code: "ALB_SCHEMA_UNKNOWN", path: "/artifactType", message: "Signed artifact payload schema is unknown" }] };
  }
  const payload = validateArtifact<T>(payloadKey, artifact.payload);
  if (!payload.ok) return payload as ValidationResult<SignedArtifact<T>>;
  if (SCHEMA_IDS[payloadKey] !== artifact.schemaId) {
    return { ok: false, issues: [{ code: "ALB_SCHEMA_INVALID", path: "/schemaId", message: "Signed artifact schema identifier does not match its type" }] };
  }
  return { ok: true, value: artifact, issues: [] };
}

export function schemaKeyForArtifactType(type: ArtifactType): SchemaKey {
  if (!ARTIFACT_SCHEMA_KEYS.has(type as SchemaKey)) throw new TypeError("Unsupported artifact type");
  return type as SchemaKey;
}

export function schemaDigestForArtifactType(type: ArtifactType): ReturnType<typeof sha256Digest> {
  return registry().schemaDigestForArtifactType(type);
}
