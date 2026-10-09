import type { EvaluationInput } from "./domain.js";

/*
 * The complete-case boundary shared by the reference API and the CLI. The
 * engine fails closed on anything else by fabricating a `malformed-case`
 * decision, which is right for a library caller but wrong at a boundary that
 * would persist or print it as a successful evaluation. Internal module: it is
 * deliberately not re-exported from the package entry points.
 */

export type EvaluationInputErrorCode = "ALB_EVALUATION_SHAPE" | "ALB_EXTERNAL_PINS_REQUIRED";

const MESSAGES: Readonly<Record<EvaluationInputErrorCode, string>> = Object.freeze({
  ALB_EVALUATION_SHAPE: "Evaluation input has an invalid shape.",
  ALB_EXTERNAL_PINS_REQUIRED: "A complete evaluation case with external pins is required.",
});

export class EvaluationInputError extends Error {
  public readonly code: EvaluationInputErrorCode;

  public constructor(code: EvaluationInputErrorCode) {
    super(MESSAGES[code]);
    this.name = "EvaluationInputError";
    this.code = code;
  }
}

const ALLOWED_KEYS: ReadonlySet<string> = new Set([
  "caseId",
  "asOf",
  "pins",
  "trustRootJwk",
  "mandate",
  "runtimeEvents",
  "executionReceipt",
  "priorReceipts",
  "incidentReport",
  "causationAttestations",
  "policy",
  "rulebook",
  "trustSnapshot",
  "evidenceBundle",
  "priorDecision",
  "appealId",
]);

const OPTIONAL_ARTIFACTS = [
  "trustRootJwk",
  "mandate",
  "executionReceipt",
  "incidentReport",
  "evidenceBundle",
  "priorDecision",
] as const;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Accept only a complete evaluation case: known top-level keys, external pins,
 * the required artifact arrays and objects, and object-shaped optional
 * artifacts. Artifact contents are left to the engine's own validation.
 */
export function assertEvaluationInput(value: unknown): EvaluationInput {
  if (!isObject(value) || Object.keys(value).some((key) => !ALLOWED_KEYS.has(key))) {
    throw new EvaluationInputError("ALB_EVALUATION_SHAPE");
  }
  const pins = value["pins"];
  if (
    typeof value["caseId"] !== "string"
    || typeof value["asOf"] !== "string"
    || !isObject(pins)
    || typeof pins["asOf"] !== "string"
    || typeof pins["policyDigest"] !== "string"
    || typeof pins["trustSnapshotDigest"] !== "string"
    || typeof pins["rulebookDigest"] !== "string"
    || !Array.isArray(pins["schemaDigests"])
    || typeof pins["engineVersion"] !== "string"
    || !Array.isArray(value["runtimeEvents"])
    || !Array.isArray(value["priorReceipts"])
    || !Array.isArray(value["causationAttestations"])
    || !isObject(value["policy"])
    || !isObject(value["rulebook"])
    || !isObject(value["trustSnapshot"])
  ) {
    throw new EvaluationInputError("ALB_EXTERNAL_PINS_REQUIRED");
  }
  for (const optionalArtifact of OPTIONAL_ARTIFACTS) {
    const candidate = value[optionalArtifact];
    if (candidate !== undefined && !isObject(candidate)) {
      throw new EvaluationInputError("ALB_EVALUATION_SHAPE");
    }
  }
  return value as unknown as EvaluationInput;
}
