import type { CasePackVerificationAnchors, CasePackStatus } from "./casepack.js";
import { createCaseReport, type MandateBoundCaseReport } from "./report.js";

export interface CaseAssessmentInput {
  readonly casePack: unknown;
  readonly anchors: CasePackVerificationAnchors;
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
