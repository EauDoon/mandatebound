# MandateBound: Agentic Commerce Evidence Readiness

MandateBound is a TypeScript reference toolkit for preserving and verifying signed UCP/AP2 transaction evidence, making evidence gaps explicit, and replaying a bounded policy offline.

> [!IMPORTANT]
> MandateBound is experimental reference software. It is not legal advice, legal adjudication, insurance, a claims service, a compliance certification, or a hosted production service. Every policy result keeps `legalEffect: "not-determined"`.

## Flagship story: reviewing a disputed synthetic purchase

A shopping agent's purchase enters review after a synthetic incident report alleges economic loss. The reviewer needs to answer a bounded question: does the recorded evidence show what the mandate covered, which controls passed, and whether the same result can be reproduced later?

The existing simulator supplies a USD 25.00 purchase (`2500` minor units) at `merchant.synthetic`, with `supplier.synthetic` as counterparty. The signed mandate allows one purchase up to USD 100.00 (`10000` minor units), the runtime trail records five signed events, the execution receipt records all four required controls as passing, and the incident report is bound to the receipt. No causation attestation is supplied.

The closed native bundle verifies with 12 of 12 entries. The reference policy selects the `principal` branch with reason `inside_mandate_without_vendor_causation`. That is a policy output, not a finding about a real party.

```text
complete case   principal   allocated     inside_mandate_without_vendor_causation
missing case    unresolved  indeterminate missing_required_evidence
tampered case   unresolved  invalid       invalid_evidence
```

Run the exact **source-checkout-only** reproducer in [`CASE_STUDY.md`](docs/CASE_STUDY.md). The published npm package intentionally excludes `examples/`:

```bash
npm run build
node examples/case-study.mjs
```

The missing and tampered variants stay `unresolved`. The engine preserves the difference between an incomplete case and invalid evidence, while keeping `legalEffect` as `not-determined` in every path.

## What this project proves within its boundary

Within its synthetic and reference boundary, MandateBound demonstrates that a reviewer can:

- preserve exact signed artifacts from a supported commerce evidence profile;
- verify schema, digest, signature, role, purpose, scope, time, and cross-artifact bindings;
- distinguish upstream validity from local evidence eligibility;
- report each declared evidence requirement as `satisfied`, `missing`, `conflicting`, `unsupported`, `unknown`, or `not_applicable`;
- seal the source record around an unchanged native v1 evidence bundle;
- replay the same accepted bytes under explicit policy, trust, schema, rulebook, engine, and time pins;
- fail closed when evidence is missing, invalid, stale, tampered, contradictory, or multi-causal.

The v1.2 implementation supports one exact target: UCP 2026-04-08 REST with the UCP AP2 Mandates Extension and AP2 v0.2.0. It also provides an AP2 dispute Evidence Pack and resolver, caller-supplied retrieval adapters, metadata-only timeline rendering, native v1 policy tools, and local operator review workflows. These are bounded implementation claims, not protocol certification or production fitness.

## How it works

```text
UCP/AP2 source bytes
  -> exact profile import and upstream verification
  -> local evidence eligibility and readiness
  -> content-addressed CasePack
  -> deterministic offline replay
  -> non-binding policy branch
```

The evaluator performs no live key, schema, policy, revocation, DNS, or clock lookup. A `CasePack` can preserve sensitive source evidence, so any deployment still needs access control, retention, redaction, and privacy governance.

## Key engineering choices

| Choice | Why it matters |
| --- | --- |
| Strict JSON and schema validation | Duplicate keys, unknown properties, oversized input, and malformed structures fail before evaluation. |
| Exact-byte and canonical domains | Source representations remain intact where upstream signatures or digests depend on them; native artifacts use RFC 8785 canonical JSON. |
| SHA-256 content addressing and Ed25519 proofs | Artifacts, manifests, bundles, and proof metadata are bound to explicit bytes and purposes. |
| Pinned trust and explicit `asOf` time | Historical replay does not silently adopt newer keys, policies, schemas, revocation positions, or current time. |
| Separate `upstreamValid` and `evidenceEligible` | A valid source artifact can remain ineligible for a particular case, role, scope, or time window. |
| Closed bundles and immutable decisions | The evidence set and policy result can be checked again without changing an earlier decision. |
| Caller-owned AP2 retrieval | The core defines no endpoint and performs no built-in network access; retrieval authority stays with the adapter owner. |

## Quick start

Requirements: Node.js 22.12 or newer.

For the **source-checkout-only** quick start below, clone the repository first. The published npm package intentionally excludes `examples/`:

```bash
git clone https://github.com/EauDoon/mandatebound.git
cd mandatebound
npm ci --ignore-scripts
npm run verify
npm run conformance
node examples/case-study.mjs
```

The focused simulator is also available through the CLI:

```bash
node dist/cli.js simulate --scenario principal
node dist/cli.js simulate --scenario unresolved
node dist/cli.js simulate --scenario tamper
```

`npm run demo` runs all named synthetic scenarios. Generated keys exist only in memory. The demos do not contact a network, move funds, submit a dispute, or write private keys to disk.

## Command map

Build first, then use the local `dist/cli.js` binary or the installed `mandatebound` binary.

| Area | Commands | Guide |
| --- | --- | --- |
| Native evidence and policy | `verify`, `decide`, `preview`, `explain`, `appeal`, `replay`, `simulate` | [`docs/PROTOCOL.md`](docs/PROTOCOL.md) |
| Local review | `review`, `operator triage`, `operator checklist`, `operator batch`, `operator queue`, `operator compare`, `operator receipt`, `operator audit` | [`docs/OPERATOR_WORKFLOWS.md`](docs/OPERATOR_WORKFLOWS.md) |
| Evidence operations | `operator collect`, `operator sources`, `operator timeline`, `operator lineage`, `operator checkpoints`, `operator windows`, `operator reuse`, `operator bottlenecks`, `operator findings`, `operator batch-diff` | [`docs/EVIDENCE_OPERATIONS.md`](docs/EVIDENCE_OPERATIONS.md) |
| CasePack | `casepack build`, `casepack verify`, `casepack unpack`, `casepack diff`, `case-report` | [`docs/V1_1.md`](docs/V1_1.md) |
| Policy tools | `policy validate`, `policy test`, `policy diff` | [`BRIEF.md`](BRIEF.md) |
| AP2 dispute evidence | `ap2-dispute resolve`, `ap2-dispute pack`, `ap2-dispute verify`, `ap2-dispute render` | [`docs/V1_2.md`](docs/V1_2.md) |
| Capability statement | `conformance` | [`conformance/v1.2/README.md`](conformance/v1.2/README.md) |

JSON commands accept one strict document from `--input PATH`, a positional path, or stdin. The CLI returns `{ok, result}` envelopes and bounded error codes. `casepack verify`, `case-report`, and the operator workflows require caller-owned anchors when the case contract declares them. See the linked guides for exact input shapes, limits, output formats, and exit codes.

## Visible limits

| Boundary | Repository position |
| --- | --- |
| Legal effect | Policy branches do not determine liability, contractual responsibility, causation, damages, coverage, enforceability, or an amount owed. |
| Identity and truth | Signatures authenticate bytes under configured trust; they do not prove real-world identity, authority, consent, intent, or truth. |
| Completeness | Readiness is scoped to declared sources and windows. `globalCompleteness` remains `not-established`; omitted sources and withheld log tails remain possible. |
| Protocol scope | The importer targets the named UCP/AP2 profile only. It does not claim generic UCP or AP2 compliance, every transport, or every extension. |
| Production deployment | The server is loopback-only reference software. Authentication, TLS, tenant isolation, key custody, quotas, monitoring, recovery, and independent security review remain deployment work. |
| Value actions | The project does not move funds, submit disputes, operate checkout, confirm settlement, underwrite insurance, or compute multi-party dollar waterfalls. |

Read the [`DISCLAIMER.md`](DISCLAIMER.md), [legal boundary](docs/LEGAL_BOUNDARY.md), [threat model](docs/THREAT_MODEL.md), and [privacy model](docs/PRIVACY_MODEL.md) before using the reference code with real data.

## Deeper documentation

- [Worked case study](docs/CASE_STUDY.md): synthetic disputed purchase, actual run output, and fail-closed variants.
- [Architecture](docs/ARCHITECTURE.md): components, trust boundaries, and determinism requirements.
- [V1.1 profile](docs/V1_1.md): exact import profile, CasePack, readiness, and replay.
- [V1.2 profile](docs/V1_2.md): AP2 dispute resolver, Evidence Pack, and metadata-only timeline.
- [Operator workflows](docs/OPERATOR_WORKFLOWS.md): triage, checklists, queues, comparisons, receipts, and audits.
- [Evidence operations](docs/EVIDENCE_OPERATIONS.md): collection, chronology, mappings, checkpoints, and batch analysis.
- [Interoperability](docs/INTEROPERABILITY.md): supported profile and deferred adapters.
- [Trust model](docs/TRUST_MODEL.md): roles, purposes, scopes, and pins.
- [Threat model](docs/THREAT_MODEL.md): adversarial inputs and deployment responsibilities.
- [Privacy model](docs/PRIVACY_MODEL.md): classifications, minimization, retention, and sensitive Packs.
- [Legal boundary](docs/LEGAL_BOUNDARY.md): what cryptography and policy outputs do and do not establish.
- [Summary](SUMMARY.md) and [brief](BRIEF.md): one-page and product-level context.

## Development and verification

```bash
npm ci --ignore-scripts
npm run typecheck
npm test
npm run test:coverage
npm run package:check
npm run verify
```

`npm run verify` is the release gate. It runs linting, dependency-license checks, advisory checks, strict type checking, coverage-enforced tests, and package-content verification. The repository fixture suite is synthetic and does not establish third-party certification.

## Upstream references and license

The supported evidence-import profile is pinned to:

- [UCP 2026-04-08 specification](https://ucp.dev/2026-04-08/specification/overview/)
- [UCP AP2 Mandates Extension](https://ucp.dev/specification/ap2-mandates/)
- [AP2 v0.2.0 release](https://github.com/google-agentic-commerce/AP2/releases/tag/v0.2.0)
- [AP2 v0.2.0 immutable specification commit](https://github.com/google-agentic-commerce/AP2/blob/b4587ac1d055888a73b4b21750973cffba961793/docs/ap2/specification.md)
- [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421)
- [RFC 9530 Content-Digest](https://www.rfc-editor.org/rfc/rfc9530)

MandateBound is published by EauDoon under the [Apache License 2.0](LICENSE). It is not affiliated with or endorsed by UCP, AP2, a payment network, regulator, insurer, or model provider.
