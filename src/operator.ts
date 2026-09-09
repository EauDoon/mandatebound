import type { CasePackVerificationAnchors, CasePackStatus } from "./casepack.js";
import { createCaseReport, type MandateBoundCaseReport } from "./report.js";

export interface CaseAssessmentInput {
  readonly casePack: unknown;
  readonly anchors: CasePackVerificationAnchors;
}

export class OperatorInputError extends Error {
  readonly code = "ALB_OPERATOR_INPUT";
  constructor(message: string) {
    super(message);
    this.name = "OperatorInputError";
  }
}

export interface NamedCaseAssessment extends CaseAssessmentInput {
  readonly id: string;
}

export const MAX_ASSESSMENT_CASES = 100;

/** Input order is preserved and each case retains its own independently supplied anchors. */
export function assessCases(inputs: readonly NamedCaseAssessment[]) {
  if (!Array.isArray(inputs) || inputs.length === 0 || inputs.length > MAX_ASSESSMENT_CASES) {
    throw new OperatorInputError("Provide between 1 and 100 cases.");
  }
  const ids = new Set<string>();
  for (const input of inputs) {
    if (input === null || typeof input !== "object" || typeof input.id !== "string"
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.id) || ids.has(input.id)
      || !Object.hasOwn(input, "casePack") || !Object.hasOwn(input, "anchors")
      || Object.keys(input).some((key) => !["id", "casePack", "anchors"].includes(key))) {
      throw new OperatorInputError("Each case requires a unique ASCII id, casePack, and anchors.");
    }
    ids.add(input.id);
  }
  const cases = inputs.map((input) => ({ id: input.id, report: createCaseReport(input.casePack, input.anchors) }));
  const verified = cases.filter((item) => item.report.valid).length;
  return {
    format: "MandateBoundCaseBatch/v1" as const,
    valid: verified === cases.length,
    legalEffect: "not-determined" as const,
    summary: { total: cases.length, verified, needsReview: cases.length - verified },
    cases,
  };
}

export interface CaseTriageItem {
  readonly area: string;
  readonly status: CasePackStatus;
  readonly priority: "high" | "normal";
  readonly action: string;
}

const ACTIONS: Record<CasePackStatus, string> = {
  satisfied: "Retain verified evidence and its independently held anchors.",
  not_applicable: "No collection action for this declared requirement.",
  conflicting: "Investigate conflicting bytes or bindings. Preserve the original evidence.",
  missing: "Collect the required evidence and independently verify its provenance.",
  unsupported: "Use a supported evidence format or arrange a separate manual review.",
  unknown: "Establish the missing trust or verification context before relying on this evidence.",
};

function triageReport(report: MandateBoundCaseReport): CaseTriageItem[] {
  const statuses: [string, CasePackStatus][] = Object.entries(report.status)
    .filter(([area]) => area !== "sourceTruth") as [string, CasePackStatus][];
  return statuses
    .filter(([, status]) => status !== "satisfied" && status !== "not_applicable")
    .map(([area, status]): CaseTriageItem => ({
      area, status, priority: status === "conflicting" ? "high" : "normal", action: ACTIONS[status],
    }))
    .sort((a, b) => Number(b.priority === "high") - Number(a.priority === "high")
      || (a.area < b.area ? -1 : a.area > b.area ? 1 : 0));
}

/** Re-verifies source evidence; triage never upgrades policy or legal assurance. */
export function triageCase(input: CaseAssessmentInput) {
  const report = createCaseReport(input.casePack, input.anchors);
  return {
    format: "MandateBoundCaseTriage/v1" as const,
    assessedAt: report.assessedAt,
    valid: report.valid,
    legalEffect: "not-determined" as const,
    globalCompleteness: "not-established" as const,
    sourceTruth: "unknown" as const,
    items: triageReport(report),
    findings: report.findings,
  };
}

/** A collection task does not establish that newly supplied evidence is true. */
export function createEvidenceChecklist(input: CaseAssessmentInput) {
  const report = createCaseReport(input.casePack, input.anchors);
  return {
    format: "MandateBoundEvidenceChecklist/v1" as const,
    valid: report.valid,
    legalEffect: "not-determined" as const,
    globalCompleteness: "not-established" as const,
    requirements: report.coverage.map((item) => ({
      ...item,
      needsReview: item.status !== "satisfied" && item.status !== "not_applicable",
      action: ACTIONS[item.status],
    })),
    assuranceTasks: triageReport(report),
    findings: report.findings,
  };
}

export function compareCaseAssessments(before: CaseAssessmentInput, after: CaseAssessmentInput) {
  const left = createCaseReport(before.casePack, before.anchors);
  const right = createCaseReport(after.casePack, after.anchors);
  const comparable = left.casePackId !== undefined && left.casePackId === right.casePackId
    && before.anchors.coveragePolicyDigest === after.anchors.coveragePolicyDigest
    && before.anchors.coverageContractDigest === after.anchors.coverageContractDigest;
  const changes = comparable ? Object.keys(left.status).flatMap((key) => {
    const area = key as keyof typeof left.status;
    const previous = left.status[area];
    const current = right.status[area];
    return previous === current ? [] : [{ area, before: previous, after: current,
      regression: previous === "satisfied" && current !== "not_applicable" }];
  }) : [];
  return {
    format: "MandateBoundAssessmentComparison/v1" as const,
    comparable,
    legalEffect: "not-determined" as const,
    before: { assessedAt: left.assessedAt, valid: left.valid },
    after: { assessedAt: right.assessedAt, valid: right.valid },
    changes,
    hasRegression: comparable && ((left.valid && !right.valid) || changes.some((item) => item.regression)),
    reason: comparable ? "Same case identifier and coverage anchors." : "Case identifier or coverage anchors differ or are unavailable.",
  };
}
