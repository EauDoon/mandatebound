# Changelog

All notable changes are documented here.

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
