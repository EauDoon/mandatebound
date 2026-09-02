import type {
  CasePackStatus,
  CasePackVerificationAnchors,
  MandateBoundCasePack,
} from "./casepack.js";
import { verifyMandateBoundCasePack } from "./casepack.js";
import type { Sha256Digest } from "./domain.js";

export interface CaseReportFinding {
  readonly code: string;
  readonly path: string;
  readonly message: string;
}

export interface CaseReportCoverage {
  readonly requirementId: string;
  readonly status: CasePackStatus;
  readonly matchedEnvelopes: number;
}

export interface CaseReportEnvelope {
  readonly envelopeId: string;
  readonly integrityStatus: CasePackStatus;
  readonly coverageStatus: CasePackStatus;
  readonly sourceTruthStatus: "unknown";
  readonly upstreamValid: boolean;
  readonly evidenceEligible: boolean;
}

export interface MandateBoundCaseReport {
  readonly format: "MandateBoundCaseReport/v1";
  readonly casePackId?: string;
  readonly casePackDigest?: Sha256Digest;
  readonly assessedAt: string;
  readonly valid: boolean;
  readonly legalEffect: "not-determined";
  readonly globalCompleteness: "not-established";
  readonly status: {
    readonly integrity: CasePackStatus;
    readonly coverage: CasePackStatus;
    readonly sourceTruth: "unknown" | "not_applicable";
    readonly upstreamValidity: CasePackStatus;
    readonly evidenceEligibility: CasePackStatus;
    readonly externalTrust: CasePackStatus;
    readonly delegation: CasePackStatus;
  };
  readonly nativeBundle: {
    readonly valid: boolean;
    readonly verifiedEntries: number;
    readonly totalEntries: number;
    readonly trustChecked: boolean;
  };
  readonly coverage: readonly CaseReportCoverage[];
  readonly envelopes: readonly CaseReportEnvelope[];
  readonly findings: readonly CaseReportFinding[];
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function createCaseReport(
  casePack: unknown,
  anchors: CasePackVerificationAnchors,
): MandateBoundCaseReport {
  const verification = verifyMandateBoundCasePack(casePack, anchors);
  return {
    format: "MandateBoundCaseReport/v1",
    ...(verification.casePackId === undefined
      ? {}
      : { casePackId: verification.casePackId }),
    ...(verification.casePackDigest === undefined
      ? {}
      : { casePackDigest: verification.casePackDigest }),
    assessedAt: anchors.asOf,
    valid: verification.valid,
    legalEffect: "not-determined",
    globalCompleteness: verification.globalCompleteness,
    status: {
      integrity: verification.integrityStatus,
      coverage: verification.coverageStatus,
      sourceTruth: verification.sourceTruthStatus,
      upstreamValidity: verification.upstreamValidStatus,
      evidenceEligibility: verification.evidenceEligibilityStatus,
      externalTrust: verification.externalTrustStatus,
      delegation: verification.delegationStatus,
    },
    nativeBundle: {
      valid: verification.nativeBundle.valid,
      verifiedEntries: verification.nativeBundle.verifiedEntries,
      totalEntries: verification.nativeBundle.totalEntries,
      trustChecked: verification.nativeBundle.trustChecked,
    },
    coverage: [...verification.requirements]
      .sort((left, right) => compareAscii(left.requirementId, right.requirementId)),
    envelopes: [...verification.envelopes]
      .sort((left, right) => compareAscii(left.envelopeId, right.envelopeId)),
    findings: verification.issues.map((issue) => ({
      code: issue.code,
      path: issue.path,
      message: issue.message,
    })),
  };
}

function escapeHtml(value: unknown): string {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}

function statusCell(status: string): string {
  return `<span class="status status-${escapeHtml(status)}">${escapeHtml(status)}</span>`;
}

export function renderCaseReportHtml(report: MandateBoundCaseReport): string {
  const statusRows = Object.entries(report.status)
    .map(([name, value]) => `<tr><th scope="row">${escapeHtml(name)}</th><td>${statusCell(value)}</td></tr>`)
    .join("");
  const coverageRows = report.coverage.length === 0
    ? "<tr><td colspan=\"3\">No applicable coverage requirements were reported.</td></tr>"
    : report.coverage.map((item) =>
      `<tr><td>${escapeHtml(item.requirementId)}</td><td>${statusCell(item.status)}</td><td>${escapeHtml(item.matchedEnvelopes)}</td></tr>`)
      .join("");
  const envelopeRows = report.envelopes.length === 0
    ? "<tr><td colspan=\"5\">No protocol evidence envelopes were reported.</td></tr>"
    : report.envelopes.map((item) =>
      `<tr><td>${escapeHtml(item.envelopeId)}</td><td>${statusCell(item.integrityStatus)}</td><td>${statusCell(item.coverageStatus)}</td><td>${escapeHtml(item.upstreamValid)}</td><td>${escapeHtml(item.evidenceEligible)}</td></tr>`)
      .join("");
  const findingRows = report.findings.length === 0
    ? "<li>No verifier findings.</li>"
    : report.findings.map((finding) =>
      `<li><code>${escapeHtml(finding.code)}</code> at <code>${escapeHtml(finding.path)}</code>: ${escapeHtml(finding.message)}</li>`)
      .join("");
  const titleId = report.casePackId ?? "unidentified-casepack";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MandateBound case report: ${escapeHtml(titleId)}</title>
<style>
:root{color-scheme:light dark;font-family:ui-sans-serif,system-ui,sans-serif}
body{max-width:70rem;margin:0 auto;padding:2rem;line-height:1.5}
h1,h2{line-height:1.2}table{width:100%;border-collapse:collapse;margin:1rem 0 2rem}
th,td{border:1px solid #8888;padding:.55rem;text-align:left;vertical-align:top}
code{overflow-wrap:anywhere}.meta{display:grid;grid-template-columns:max-content 1fr;gap:.35rem 1rem}
.status{font-weight:650}.boundary{border-left:.3rem solid #b36b00;padding:.75rem 1rem;background:#b36b0018}
</style>
</head>
<body>
<header>
<p>MandateBoundCaseReport/v1</p>
<h1>Case report: ${escapeHtml(titleId)}</h1>
<div class="meta">
<strong>CasePack digest</strong><code>${escapeHtml(report.casePackDigest ?? "unavailable")}</code>
<strong>Assessed at</strong><time>${escapeHtml(report.assessedAt)}</time>
<strong>Verification</strong><span>${report.valid ? "valid" : "not valid"}</span>
</div>
<p class="boundary">This report is policy-relative decision support. Global completeness is not established and legal effect is not determined.</p>
</header>
<main>
<h2>Assurance status</h2>
<table><tbody>${statusRows}</tbody></table>
<h2>Coverage requirements</h2>
<table><thead><tr><th>Requirement</th><th>Status</th><th>Matched envelopes</th></tr></thead><tbody>${coverageRows}</tbody></table>
<h2>Protocol evidence</h2>
<table><thead><tr><th>Envelope</th><th>Integrity</th><th>Coverage</th><th>Upstream valid</th><th>Evidence eligible</th></tr></thead><tbody>${envelopeRows}</tbody></table>
<h2>Verifier findings</h2>
<ul>${findingRows}</ul>
</main>
</body>
</html>
`;
}

export function isCaseReportFor(
  report: MandateBoundCaseReport,
  casePack: MandateBoundCasePack,
): boolean {
  return report.casePackId === casePack.casePackId
    && report.casePackDigest === casePack.casePackDigest;
}
