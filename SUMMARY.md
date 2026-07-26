# MandateBound: Summary

## In one sentence

MandateBound is an open-source evidence-readiness and deterministic dispute-replay toolkit for agentic commerce that preserves a UCP/AP2 transaction record, verifies bounded AP2 dispute evidence, exposes evidence gaps, and replays a non-binding policy branch offline.

## v1.2 addition

MandateBound v1.2 retrieves through caller-supplied adapters or assembles materialized responses for the four AP2 v0.2.0 dispute artifacts. It verifies direct and delegated Mandates, required autonomous constraints, the merchant Checkout JWT, Receipt signatures and terminal-Mandate references, historical key pins, and cross-source consistency.

The Evidence Pack workflow is `pack -> verify -> render`. The sensitive Pack preserves exact Mandates, Checkout versions, Receipts, caller pins, and imported revocation snapshot bytes. Independent verification requires an expected Pack digest retained outside the Pack and recomputes every digest and evidence gate. The metadata-only HTML timeline omits the raw artifacts and recomputes verification instead of trusting a supplied report.

The resolver emits `evidence_verified` only when every integrity gate passes. Pack verification emits `verified` only when the Pack matches its independently retained expected digest, the exact Checkout version is bound, both Mandates have reported revocation coverage, every report says `not_revoked`, and the embedded resolution passes. Revocation state is imported evidence, not an authenticated protocol fact. Missing, stale, unsupported, mismatched, conflicting, forged, empty, unknown, or failed evidence emits `unresolved`. `historyCompleteness`, the dispute outcome, and legal effect remain unknown or not determined.

## v1.1 focus

MandateBound v1.1 implements one exact target:

**UCP 2026-04-08 REST + AP2 Mandates Extension / AP2 v0.2.0 evidence-import profile**

This is a version-pinned evidence-import claim. It is not generic UCP compliance, generic AP2 compliance, legal adjudication, or production-service certification.

## The problem

A disputed agent transaction may span signed checkout exchanges, mandates, payment evidence, order events, refund events, runtime controls, and changing trust material. A signature check alone does not show whether the full record exists, whether a signer was trusted for a particular role, or whether the same case can be reproduced later.

MandateBound makes that evidence state explicit before policy is applied.

## What v1.1 adds

- exact preservation and verification of supported UCP/AP2 source evidence
- checkout-to-order/refund lifecycle capture for supplied artifacts
- `DelegationContext` for a digest-bound principal-to-delegate mandate, scope, validity window, and evidence references
- `ExternalTrustSnapshot` for pinned discovery material and source-checkpoint keys that cannot auto-promote into native trust
- separate `upstreamValid` and `evidenceEligible` judgments
- readiness states for `satisfied`, `missing`, `conflicting`, `unsupported`, `unknown`, and `not_applicable` requirements
- an outer `CasePack` that preserves the existing v1 `.albx.json` evidence bundle
- source checkpoints, policy-relative coverage contracts, policy-pack test and diff tools, and a versioned conformance statement
- CLI workflows for CasePack build, verify, unpack, diff, JSON or HTML review reports, policy tools, and the bounded conformance statement
- deterministic offline replay under identical source, trust, policy, schema, rulebook, time, and engine pins

CasePack verification, unpacking, and reporting consume `{casePack, anchors}`. Raw evidence uses `{referenceId, bytesBase64}` at the JSON CLI boundary. Build seals the outer CasePack only after nested components have been sealed through the SDK.

## The central distinction

`upstreamValid` means an artifact passed the exact source-profile checks.

`evidenceEligible` means it may also contribute to this MandateBound case under pinned local trust, role, timing, support, and case-binding rules.

An authentic artifact can still be ineligible. Neither result proves real-world identity, authority, truth, causation, loss, or legal responsibility.

## Evidence readiness

MandateBound reports each expected evidence item as:

- `satisfied`
- `missing`
- `conflicting`
- `unsupported`
- `unknown`
- `not_applicable`

The report is scoped to the exact profile and requested lifecycle. It does not claim that every relevant fact was disclosed.

Artifact failures remain separate and visible through `upstreamValid`, `evidenceEligible`, and bounded issue codes. Invalid or ineligible material does not satisfy a coverage requirement.

Every report keeps global completeness as not established and source truth as unknown. Source checkpoints prove only bounded inclusion under their declared source, window, sequence, and gap record.

## Compatibility

The v1.1 `CasePack` is an outer case layer. It binds source evidence, external trust, delegation context, readiness, and replay inputs around the native v1 bundle.

The inner v1 bundle remains byte-preserved and independently verifiable. v1.1 does not silently rewrite v1 artifacts or merge external and native trust.

## Policy boundary

The native engine still emits principal, operator, model-vendor, or unresolved policy branches. Missing, unsupported, contradictory, and multi-causal evidence fails closed.

Every policy result retains:

```json
{
  "legalEffect": "not-determined"
}
```

MandateBound does not determine liability, damages, enforceability, insurance coverage, or an amount owed.

## Deliberate limits

MandateBound does not include:

- multi-party dollar waterfalls or contribution percentages
- full A2A, MCP, Visa Trusted Agent Protocol, or x402 adapters
- automated dispute or claims submission
- a hosted, authenticated, multi-tenant production service

Dollar waterfalls are deferred because the implemented UCP/AP2 profile does not supply the contractual caps, priorities, exclusions, valuation, contribution, and governing terms needed for a defensible calculation.

## Intended use

The strongest first use is shadow evidence capture. Merchant, agent-platform, payment, risk, assurance, and dispute teams can test whether a transaction produces a reviewable record without changing authorization, settlement, or claims decisions.

Any real deployment requires separately governed trust, privacy, retention, security, legal, contractual, and reviewer-authority decisions.

## Project

MandateBound is published by Oonyl under the Apache License 2.0. Examples are synthetic. The repository is not affiliated with or endorsed by UCP, AP2, a payment network, regulator, insurer, or model provider.
