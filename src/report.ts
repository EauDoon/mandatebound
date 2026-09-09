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
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>MandateBound case report: ${escapeHtml(titleId)}</title>
<style>
:root{color-scheme:light dark;font-family:ui-sans-serif,system-ui,sans-serif}
body{max-width:70rem;margin:0 auto;padding:2rem;line-height:1.5}
*{box-sizing:border-box}a{color:inherit;text-underline-offset:.2em}:focus-visible{outline:3px solid #1675dc;outline-offset:4px}
.skip{position:absolute;top:-5rem}.skip:focus{top:0;background:Canvas;padding:1rem}
nav{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}.summary{display:flex;gap:1rem;flex-wrap:wrap;padding:1rem;background:#1675dc12}
.table-scroll{overflow-x:auto}.table-scroll table{min-width:36rem}caption{text-align:left;font-weight:650;padding:.5rem 0}
h1,h2{line-height:1.2}table{width:100%;border-collapse:collapse;margin:1rem 0 2rem}
th,td{border:1px solid #8888;padding:.55rem;text-align:left;vertical-align:top}
code{overflow-wrap:anywhere}.meta{display:grid;grid-template-columns:max-content 1fr;gap:.35rem 1rem}
.status{font-weight:650}.boundary{border-left:.3rem solid #b36b00;padding:.75rem 1rem;background:#b36b0018}
td,th,li,h1{overflow-wrap:anywhere}.meta{min-width:0}.meta>*{min-width:0}
@media(max-width:40rem){body{padding:1rem}.meta{grid-template-columns:1fr}h1{font-size:1.6rem}}
@media print{body{max-width:none;padding:0;color:#000;background:#fff}nav,.skip{display:none}thead{display:table-header-group}tr{break-inside:avoid}.table-scroll{overflow:visible}.table-scroll table{min-width:0}.boundary{border-color:#555}a{text-decoration:none}}
</style>
</head>
<body>
<a class="skip" href="#main">Skip to report</a>
<header>
<p>MandateBoundCaseReport/v1</p>
<h1>Case report: ${escapeHtml(titleId)}</h1>
<div class="meta">
<strong>CasePack digest</strong><code>${escapeHtml(report.casePackDigest ?? "unavailable")}</code>
<strong>Assessed at</strong><time>${escapeHtml(report.assessedAt)}</time>
<strong>Verification</strong><span>${report.valid ? "valid" : "not valid"}</span>
</div>
<p class="boundary">This report is policy-relative decision support. Global completeness is not established and legal effect is not determined.</p>
<div class="summary" aria-label="Report summary">
<strong>${report.valid ? "Verification passed" : "Review required"}</strong>
<span>${report.coverage.filter((item) => item.status !== "satisfied" && item.status !== "not_applicable").length} coverage requirements need review</span>
<span>${report.findings.length} verifier findings</span>
</div>
<nav aria-label="Report sections"><a href="#assurance">Assurance</a><a href="#coverage">Coverage</a><a href="#evidence">Evidence</a><a href="#findings">Findings</a></nav>
</header>
<main id="main" tabindex="-1">
<h2 id="assurance">Assurance status</h2>
<table><tbody>${statusRows}</tbody></table>
<h2 id="coverage">Coverage requirements</h2>
<div class="table-scroll" role="region" aria-label="Coverage requirements" tabindex="0"><table><caption>Declared requirements only</caption><thead><tr><th scope="col">Requirement</th><th scope="col">Status</th><th scope="col">Matched envelopes</th></tr></thead><tbody>${coverageRows}</tbody></table></div>
<h2 id="evidence">Protocol evidence</h2>
<div class="table-scroll" role="region" aria-label="Protocol evidence" tabindex="0"><table><caption>Envelope verification, source truth remains unknown</caption><thead><tr><th scope="col">Envelope</th><th scope="col">Integrity</th><th scope="col">Coverage</th><th scope="col">Upstream valid</th><th scope="col">Evidence eligible</th></tr></thead><tbody>${envelopeRows}</tbody></table></div>
<h2 id="findings">Verifier findings</h2>
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

function markdownText(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replace(/[\\`*_{}\[\]()#+.!|>-]/g, "\\$&").replace(/[\r\n]+/g, " ");
}

/** Presentation only. Re-verify the source CasePack to establish assurance. */
export function renderCaseReportMarkdown(report: MandateBoundCaseReport): string {
  const lines = [
    `# Case report: ${markdownText(report.casePackId ?? "unidentified-casepack")}`,
    "", `Assessed at: ${markdownText(report.assessedAt)}`,
    `Verification: ${report.valid ? "valid" : "not valid"}`,
    `CasePack digest: ${markdownText(report.casePackDigest ?? "unavailable")}`,
    "", "Legal effect is not determined. Global completeness is not established. Source truth remains unknown.",
    "", "## Assurance status", "", "| Area | Status |", "| --- | --- |",
    ...Object.entries(report.status).map(([key, value]) => `| ${markdownText(key)} | ${markdownText(value)} |`),
    "", "## Coverage requirements", "", "| Requirement | Status | Matched envelopes |", "| --- | --- | --- |",
    ...report.coverage.map((item) => `| ${markdownText(item.requirementId)} | ${markdownText(item.status)} | ${item.matchedEnvelopes} |`),
    "", "## Verifier findings", "",
    ...(report.findings.length === 0 ? ["No verifier findings."] : report.findings.map((item) =>
      `- ${markdownText(item.code)} at ${markdownText(item.path)}: ${markdownText(item.message)}`)),
  ];
  return `${lines.join("\n")}\n`;
}

function csvCell(value: string | number): string {
  const text = String(value);
  // Quoting alone does not prevent spreadsheet formulas, including whitespace-prefixed ones.
  const safe = /^[\s\u0000-\u001f]*[=+@-]/u.test(text) || /^[\t\r\n]/u.test(text) ? `'${text}` : text;
  return `"${safe.replaceAll('"', '""')}"`;
}

/** RFC 4180 coverage export, with formula-neutralized cells and explicit assurance boundaries. */
export function renderCaseCoverageCsv(report: MandateBoundCaseReport): string {
  const coverage = report.coverage.length === 0
    ? [{ requirementId: "", status: "", matchedEnvelopes: "" }]
    : report.coverage;
  const rows: (string | number)[][] = [[
    "casePackId", "assessedAt", "verification", "requirementId", "status", "matchedEnvelopes",
    "legalEffect", "globalCompleteness",
  ], ...coverage.map((item) => [
    report.casePackId ?? "unidentified-casepack", report.assessedAt, report.valid ? "valid" : "not valid",
    item.requirementId, item.status, item.matchedEnvelopes, "not-determined", "not-established",
  ])];
  return `${rows.map((row) => row.map(csvCell).join(",")).join("\r\n")}\r\n`;
}
