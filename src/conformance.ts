export type CapabilityStatus = "supported" | "deferred" | "unsupported";

export interface CapabilityDeclaration {
  readonly id: string;
  readonly status: CapabilityStatus;
  readonly scope: string;
  readonly boundary: string;
}

export interface ConformanceStatement {
  readonly release: "1.2.0";
  readonly legalEffect: "not-determined";
  readonly evidenceProfile: {
    readonly id: "ucp-2026-04-08-rest+ap2-mandates-0.2.0";
    readonly ucpVersion: "2026-04-08";
    readonly ucpTransport: "REST";
    readonly ap2Version: "0.2.0";
  };
  readonly capabilities: readonly CapabilityDeclaration[];
  readonly fixtureCommand: "npm run conformance";
  readonly claim: "bounded-evidence-profile";
}

const CAPABILITIES: readonly CapabilityDeclaration[] = Object.freeze([
  Object.freeze({
    id: "native_evidence_bundle_v1",
    status: "supported",
    scope: "Create, verify, and replay the frozen EvidenceBundle/v1 format.",
    boundary: "The caller supplies external replay and trust anchors.",
  }),
  Object.freeze({
    id: "mandatebound_casepack_v1",
    status: "supported",
    scope: "Build and verify a deterministic CasePack/v1 around an unchanged EvidenceBundle/v1.",
    boundary: "Coverage is policy-relative and never proves global completeness.",
  }),
  Object.freeze({
    id: "ucp_2026_04_08_rest_evidence_import",
    status: "supported",
    scope: "Verify pinned UCP profile bytes, REST request signatures, body digests, and replay evidence.",
    boundary: "This is an evidence-import profile, not general UCP certification.",
  }),
  Object.freeze({
    id: "ap2_0_2_0_mandates_evidence_import",
    status: "supported",
    scope: "Verify preserved compact AP2 Mandate tokens, key binding, claims, constraints, and checkout binding.",
    boundary: "This does not implement or certify the complete AP2 protocol.",
  }),
  Object.freeze({
    id: "transaction_lifecycle_correlation",
    status: "supported",
    scope: "Correlate checkout, order, refund, return, cancellation, and price-adjustment evidence.",
    boundary: "A correlated snapshot does not prove that every lifecycle event was captured.",
  }),
  Object.freeze({
    id: "ap2_0_2_0_dispute_evidence_resolution",
    status: "supported",
    scope: "Retrieve through caller-supplied adapters, assemble, and verify direct or delegated AP2 dispute artifacts for one transaction.",
    boundary: "Resolution establishes bounded evidence integrity only, never a claim outcome, legal finding, or complete upstream history.",
  }),
  Object.freeze({
    id: "ap2_0_2_0_evidence_pack",
    status: "supported",
    scope: "Pack exact AP2 evidence, independently verify digests and gates, and render a metadata-only deterministic timeline.",
    boundary: "The Pack is sensitive, and imported revocation states are reports rather than authenticated protocol facts.",
  }),
  Object.freeze({
    id: "ucp_mcp_transport",
    status: "deferred",
    scope: "UCP transport over MCP.",
    boundary: "No MCP transport conformance claim is made.",
  }),
  Object.freeze({
    id: "ucp_a2a_transport",
    status: "deferred",
    scope: "UCP transport over A2A.",
    boundary: "No A2A transport conformance claim is made.",
  }),
  Object.freeze({
    id: "external_trust_auto_promotion",
    status: "unsupported",
    scope: "Automatic promotion of discovered profiles or external keys into native trust.",
    boundary: "External trust snapshots remain separate from native TrustSnapshot/v1.",
  }),
  Object.freeze({
    id: "normative_liability_waterfall",
    status: "unsupported",
    scope: "Binding monetary allocation or damages calculation.",
    boundary: "Outputs remain non-binding policy recommendations.",
  }),
  Object.freeze({
    id: "legal_adjudication",
    status: "unsupported",
    scope: "Legal findings, compliance certification, claims handling, or insurance decisions.",
    boundary: "Every decision retains legalEffect set to not-determined.",
  }),
]);

const STATEMENT: ConformanceStatement = Object.freeze({
  release: "1.2.0",
  legalEffect: "not-determined",
  evidenceProfile: Object.freeze({
    id: UCP_AP2_EVIDENCE_PROFILE.id,
    ucpVersion: "2026-04-08",
    ucpTransport: "REST",
    ap2Version: "0.2.0",
  }),
  capabilities: CAPABILITIES,
  fixtureCommand: "npm run conformance",
  claim: "bounded-evidence-profile",
});

export function getConformanceStatement(): ConformanceStatement {
  return STATEMENT;
}
import { UCP_AP2_EVIDENCE_PROFILE } from "./ucp-ap2.js";
