# Changelog

All notable changes are documented here.

## Unreleased corrective candidate

### Changed

- Public `EvaluationAnchors` now matches `evaluateBundle`: nested `pins`, optional `trustRootJwk`, and optional `expectedBundleRootDigest`. The previous flattened `BundlePins` shape was never accepted at runtime. `EngineEvaluationAnchors` remains an alias.
- `PlatformEngine.explainDecision` is typed as returning a string, matching `explainDecision`.
- CLI `--help` now lists commands and the JSON input convention. Unknown commands, a missing bundle path on an interactive terminal, and empty evidence documents fail with actionable usage or input errors instead of a generic parse failure.

### Security

- Removed the remote-binding escape hatch from the API and CLI. The reference server now requires a loopback bind and rejects non-loopback peers, mismatched Host headers, and foreign Origins before routing.

## 1.2.0

### Added

- Added a deterministic AP2 v0.2.0 Evidence Pack and dispute evidence resolver pinned to upstream commit `b4587ac1d055888a73b4b21750973cffba961793`.
- Added protocol-neutral, caller-supplied retrieval adapters plus an offline materialized-source assembler.
- Added exact four-artifact selection for Checkout Mandate, Checkout Receipt, Payment Mandate, and Payment Receipt evidence.
- Added strict direct and Delegate SD-JWT chain verification, terminal closed-Mandate Receipt references, required `checkout.line_items` and `payment.reference` constraints, and closed Payment schema checks.
- Bound `checkout.allowed_merchants` to the merchant in the signed Checkout JWT, with any caller expected-merchant value treated only as an additional pin.
- Added bounded merchant Checkout JWT schema and signature verification, cross-artifact transaction binding, AP2 Receipt JWT verification, and exact Receipt-reference checks.
- Added duplicate-source deduplication and fail-closed conflict detection without last-response-wins behavior.
- Added `MandateBoundAp2DisputeEvidenceResolution/v1`, its JSON Schema, content digest, integrity gates, coverage, retrieval attempts, and bounded issue codes.
- Added sensitive `MandateBoundAp2EvidencePack/v1`, independently retained digest anchored Pack verification, exact Checkout-version binding, imported reported-revocation snapshots, and metadata-only deterministic HTML timelines that recompute verification.
- Restricted Pack verification plans to closed public EC JWK shapes so private, symmetric, and unrelated key members fail before serialization.
- Added schemas for the Evidence Pack and Pack-verification report.
- Added the `@oonyl/mandatebound/ap2-dispute` package export and `mandatebound ap2-dispute resolve|pack|verify|render` CLI commands.
- Added official AP2 v0.2.0 SDK-generated frozen vectors plus adversarial fixtures for missing, stale, future-captured, oversized, malformed, mutated, mismatched, conflicting, forged, empty, and failed retrieval cases.
- Added the v1.2 boundary guide in [`docs/V1_2.md`](docs/V1_2.md) and the design decision in [ADR 0002](docs/adr/0002-ap2-dispute-resolver-boundary.md).

### Compatibility

- Preserved native v1 schemas, bundle roots, rulebooks, decision bytes, protocol version `1.0.0`, and engine version `1.0.0`.
- Preserved v1.1 CasePack and UCP/AP2 evidence-import APIs.
- Kept every resolver output non-binding with `disputeOutcome: "not-determined"` and `legalEffect: "not-determined"`.

### Scope

- The positive `evidence_verified` result establishes only integrity under the named profile. It does not decide a claim, refund, chargeback, fraud allegation, liability, causation, damages, settlement, or legal right.
- Retrieval authentication, authorization, endpoints, transport security, privacy, and retention remain caller responsibilities.
- Revocation snapshots are imported reports, not authenticated revocation facts. The library performs no revocation-service lookup.
- Evidence Packs contain raw sensitive artifacts. Resolution and timeline outputs omit them.
- Positive Pack verification requires an expected Pack digest retained outside the Pack; timeline renderers do not trust supplied verification reports.
- Complete upstream history and general AP2 conformance remain unestablished.

## 1.1.0

### Added

- Added the exact `UCP 2026-04-08 REST + AP2 Mandates Extension / AP2 v0.2.0 evidence-import profile`.
- Added checkout-to-order/refund lifecycle capture, including returns, cancellations, and price adjustments, for evidence supplied to the importer.
- Added source-representation preservation for signed UCP HTTP evidence and compact AP2 material where upstream verification depends on exact bytes.
- Added `DelegationContext` to bind principal, delegate, mandate, scope, validity window, and evidence references while keeping legal effect not determined.
- Added `ExternalTrustSnapshot` for discovery material and source-checkpoint keys, with automatic native-trust promotion forbidden.
- Added separate `upstreamValid` and `evidenceEligible` results so a source-valid artifact is not promoted automatically into local policy evidence.
- Added evidence-readiness reporting for `satisfied`, `missing`, `conflicting`, `unsupported`, `unknown`, and `not_applicable` requirements.
- Added the outer `CasePack` for source evidence, lifecycle state, readiness, external trust, delegation context, replay pins, and the preserved native v1 evidence bundle.
- Added source checkpoints and policy-relative evidence-coverage contracts while keeping global completeness not established.
- Added policy-pack validation, fixture testing, and deterministic rulebook change-impact reporting.
- Added a versioned conformance statement and a narrow exact-profile fixture command.
- Added `mandatebound casepack build|verify|unpack|diff`, `mandatebound policy validate|test|diff`, `mandatebound case-report --format json|html`, and `mandatebound conformance`.
- Added a strict `{casePack, anchors}` CLI boundary for CasePack verification, unpacking, and reporting, with raw evidence encoded as `{referenceId, bytesBase64}`.
- Added deterministic offline case replay under identical source, trust, policy, schema, rulebook, time, and engine pins.
- Added the v1.1 profile and boundary guide in [`docs/V1_1.md`](docs/V1_1.md).

### Compatibility

- Preserved native v1 artifact, rulebook, decision, and `.albx.json` bundle semantics.
- Kept the native v1 bundle independently verifiable inside a v1.1 `CasePack`.
- Kept all policy outputs non-binding with `legalEffect: "not-determined"`.

### Scope

- The new interoperability claim is limited to the named evidence-import profile. It is not a generic UCP or AP2 compliance claim.
- Multi-party dollar waterfalls and contribution percentages remain unsupported.
- UCP over A2A and MCP remains deferred. Visa Trusted Agent Protocol and x402 adapters remain unsupported.
- Automated dispute submission and a hosted production service remain unsupported.

## 1.0.0

- Added normative v1 evidence schemas.
- Added strict parsing, canonicalization, content addressing, Ed25519 proof verification, and pinned trust snapshots.
- Added deterministic principal, operator, model-vendor, and unresolved policy outcomes.
- Added portable evidence bundles and offline verification.
- Added immutable decisions and append-only appeals.
- Added CLI, localhost API, simulator, OpenAPI contract, and synthetic test suite.
- Added security, privacy, interoperability, governance, and legal-boundary documentation.
