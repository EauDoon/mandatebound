# MandateBound: Product and Policy Brief

## Executive brief

MandateBound v1.2 is an open-source evidence-readiness and deterministic dispute-replay toolkit for agentic commerce.

Its first external profile is deliberately exact:

**UCP 2026-04-08 REST + AP2 Mandates Extension / AP2 v0.2.0 evidence-import profile**

MandateBound preserves the signed source record from checkout through order and refund review, reports what is ready or missing, seals the case around the existing v1 evidence bundle, and replays a non-binding policy branch offline.

v1.2 also resolves one bounded AP2 evidence question before policy: whether exact Checkout Mandate, Checkout Receipt, Payment Mandate, and Payment Receipt artifacts form one cryptographically consistent record under caller-owned historical trust pins. Its `pack -> verify -> render` workflow preserves exact evidence in a sensitive Pack and produces a metadata-only review timeline. Retrieval is caller-supplied, conflicting bytes fail closed, and the dispute outcome remains not determined.

The product does not decide legal liability. Every policy result keeps `legalEffect: "not-determined"`.

## 1. The institutional gap

Authorization, payment, order, and dispute systems answer different questions. Together they may produce:

- signed checkout terms
- user and agent mandate material
- payment receipts
- order and refund state
- runtime control evidence
- incident and causation assertions

Those records are often stored in different formats under changing trust assumptions. A later review can fail even when the transaction succeeded because the exact signed bytes, key context, profile version, lifecycle links, or evidence obligations were not preserved.

The problem is not only verification. It is evidence readiness:

- Is the expected record present?
- Did it pass the exact source profile?
- Is it eligible under the local trust and policy?
- Is a required lifecycle link missing?
- Does accepted evidence contradict another record?
- Can the same case be replayed without live infrastructure?

## 2. Product decision

v1.1 focuses on a narrow, operational wedge: prepare one UCP/AP2 transaction record for later dispute review while the evidence is still available.

This is stronger than a broad "agent liability" claim because it solves a concrete precursor problem. A policy engine cannot produce a defensible result from evidence that was never captured, cannot be verified, or cannot be replayed.

The product therefore leads with:

1. exact source preservation
2. profile-scoped verification
3. local evidence eligibility
4. lifecycle readiness
5. deterministic offline replay

Loss-allocation policy remains a bounded downstream use of the evidence, not the headline legal claim.

## 3. v1.1 evidence system and v1.2 Evidence Pack

### AP2 dispute evidence resolution

The v1.2 resolver uses AP2 `transaction_id` only as a correlation key. It does not treat that identifier as retrieval authority. Materialized sources or caller-supplied adapters provide exact tokens; MandateBound verifies direct and delegated Mandates, required autonomous constraints, issuer and merchant signatures, Checkout bindings, both terminal-Mandate Receipt references, and cross-source consistency.

The positive `evidence_verified` status is an integrity statement under the named AP2 v0.2.0 profile. It is not a claim result, proof of complete history, or legal finding.

### Evidence Pack and timeline

The sensitive Pack stores exact Mandates, Checkout versions, Receipts, caller-owned public verification pins, and imported revocation snapshot bytes. Independent verification requires an expected Pack digest retained outside the Pack, recomputes the Pack and sub-artifact digests, reruns the resolver, binds the expected Checkout version, and treats revocation state only as reported evidence.

The HTML timeline omits raw tokens and snapshots and recomputes anchored verification rather than accepting a supplied report. A positive Pack result requires reported coverage for both closed Mandates and only `not_revoked` reports, but this is not an authenticated revocation-protocol claim.

### Exact evidence import

The importer targets only UCP 2026-04-08 REST with the UCP AP2 Mandates Extension and AP2 v0.2.0.

It preserves raw signed HTTP material and exact compact AP2 token representations where source signatures, content digests, disclosures, or artifact hashes depend on those bytes. It pins the applicable profile and schema material instead of tracking a default branch or "latest" version.

### Delegation context

`DelegationContext` binds a principal, delegate, mandate digest, scope digest, validity window, and evidence references used to interpret the source record.

It makes the evaluator's delegation assumptions inspectable and keeps legal effect not determined. It does not prove real-world identity, legal capacity, informed consent, or enforceability.

### External trust

`ExternalTrustSnapshot` freezes external discovery material and the public keys authorized only to verify bounded source checkpoints.

It has discovery-only trust effect and forbids automatic promotion into the native v1 trust snapshot. This separation prevents an upstream key or discovered profile from silently acquiring authority inside the native policy engine.

### Two-stage decision

MandateBound separates:

- `upstreamValid`: the artifact passed the exact upstream profile
- `evidenceEligible`: the artifact may contribute evidence to this case under pinned local trust, role, timing, support, and case-binding rules

A valid upstream signature is not enough. An artifact can be authentic to a key yet unsupported, out of role, unrelated to the case, stale, contradicted, or otherwise ineligible.

### Evidence readiness

Each expected requirement is reported as `satisfied`, `missing`, `conflicting`, `unsupported`, `unknown`, or `not_applicable`. Artifact-level validation failures remain visible through `upstreamValid`, `evidenceEligible`, and bounded issue codes.

The report is scoped to the exact profile and lifecycle. It is not a universal completeness score and cannot prove that a party disclosed every relevant fact.

### CasePack

The outer `CasePack` binds:

- source evidence and import results
- lifecycle state and correlations
- `DelegationContext`
- `ExternalTrustSnapshot`
- readiness output
- the existing v1 evidence bundle
- the inputs required for offline replay

The inner `.albx.json` bundle remains unchanged and independently verifiable. v1.1 does not rewrite v1 evidence or merge external and native trust.

Source checkpoints can bind event inclusion to a declared source, time window, sequence range, Merkle root, and explicit gaps. Evidence-coverage contracts make the required source classes, windows, media types, and minimum envelope counts policy-relative. Neither mechanism proves global completeness or source truth.

### Offline replay

Replay uses the same accepted bytes, explicit time, source profile, external trust, delegation context, native trust, policy, schemas, rulebook, and engine semantics.

It performs no live key, schema, policy, revocation, identity, or clock lookup. Identical accepted inputs produce the same policy result.

### Policy and conformance tools

Policy-pack tools validate a policy against its exact rulebook, run closed-fact fixtures, and report deterministic structural and case-level behavior changes between rulebooks.

The CLI exposes `casepack build`, `casepack verify`, `casepack unpack`, and `casepack diff`; `policy validate`, `policy test`, and `policy diff`; JSON or HTML `case-report`; and the versioned `conformance` statement. CasePack verification, unpacking, and reporting require an explicit `{casePack, anchors}` input. Raw evidence crosses the JSON boundary only as `{referenceId, bytesBase64}`.

CasePack build seals only the outer object after its native bundle, mapping traces, evidence envelopes, trust snapshot, delegation context, coverage contract, and checkpoints have been sealed through SDK helpers. The conformance fixture suite is a bounded implementation check, not a third-party certification.

## 4. Lifecycle covered

The v1.1 case layer covers evidence supplied across:

1. checkout creation and updates
2. Checkout Mandate and Payment Mandate material
3. payment handoff and result evidence
4. order creation and status evidence
5. refund, return, cancellation, and price-adjustment evidence

Capture means preservation, linking, verification, and readiness assessment. MandateBound does not operate the checkout, move funds, monitor the merchant, confirm settlement independently, or submit a dispute.

## 5. Native policy boundary

The v1 engine still applies a bounded, data-only rulebook to accepted evidence:

- valid in-scope execution can select the principal branch
- trustworthy evidence of out-of-mandate operator execution can select the operator branch
- the model-vendor branch requires trusted, sufficient, non-conflicting causal evidence plus otherwise compliant controls
- missing, invalid, unsupported, contradictory, or multi-causal evidence stays unresolved

These are policy branches. They are not findings of legal liability, fault, damages, or insurance coverage.

A signature authenticates a protected statement under accepted trust assumptions. It does not establish that the statement is true.

## 6. Intended users

MandateBound is intended for:

- merchant and agent-platform teams capturing transaction evidence
- payment, risk, assurance, and dispute teams preparing reviewable cases
- policy owners testing evidence obligations and decision branches
- infrastructure and standards teams building version-pinned adapters
- researchers studying post-transaction accountability

The first adoption mode should be shadow evidence capture. MandateBound can run alongside an existing transaction flow without changing authorization, settlement, or claims decisions.

## 7. Adoption path

### Stage 1: synthetic conformance

Run intact, incomplete, mutated, contradictory, and out-of-mandate fixtures against the exact profile.

### Stage 2: shadow capture

Preserve evidence beside an existing UCP/AP2 flow. Measure missing artifacts, rejected source material, unsupported features, and review effort without making production decisions.

### Stage 3: governed pilot

Bind profile, evidence obligations, trust distribution, retention, reviewer authority, and policy versions into a controlled bilateral pilot. Obtain independent legal, security, privacy, compliance, insurance, and operational review.

### Stage 4: institution-specific integration

Add governed trust and policy mappings. Keep source import, native evidence, and legal decision-making as separate boundaries.

## 8. Success measures

A v1.1 pilot should measure:

- percentage of required evidence items captured before dispute
- number and cause of rejected or unsupported artifacts
- time to produce a review-ready case
- percentage of sealed cases replayed without network access
- rate of byte-identical policy replay under identical pins
- frequency of unresolved results caused by missing or contradictory evidence
- operational and privacy cost of retaining the required source record

The project should not use transaction volume, damages allocated, or "liability accuracy" as a success metric without independent ground truth and a governed legal basis.

## 9. Risks and controls

### False legal confidence

Risk: a policy branch is mistaken for a legal decision.

Control: visible disclaimers, machine-readable `legalEffect: "not-determined"`, neutral branch language, and explicit unsupported legal questions.

### Valid signature, wrong meaning

Risk: cryptographic validity is treated as proof of authority or truth.

Control: separate `upstreamValid` from `evidenceEligible`, bind signer roles and scope, and preserve attributed assertions as assertions.

### Evidence omission

Risk: a case appears complete because undisclosed material is absent.

Control: profile-scoped readiness states, no universal completeness percentage, explicit missing items, and no completeness guarantee.

### Historical drift

Risk: newer keys, schemas, policies, or revocation positions change an old result.

Control: discovery-only `ExternalTrustSnapshot`, native trust snapshots, digest pins, explicit time, and offline replay.

### Source normalization error

Risk: parsed or reserialized data no longer matches signed bytes.

Control: preserve exact source representations where upstream verification depends on them and keep native canonicalization separate.

### Sensitive-data accumulation

Risk: a dispute case becomes a high-value collection of personal and commercial data.

Control: minimization, classifications, access control, encryption, retention limits, redaction lineage, and deployment-specific privacy review.

## 10. Deliberate deferrals

### Multi-party dollar waterfalls

v1.1 does not compute dollar amounts or contribution percentages.

A defensible waterfall would require explicit contractual terms for caps, deductibles, aggregate limits, exclusions, priority, subrogation, valuation, allocation basis, and governing-law exceptions. UCP and AP2 evidence does not establish those inputs. Inventing percentages would create false precision and conflict with the engine's unresolved treatment of multi-causal evidence.

Any future simulator must accept explicit, signed terms, expose every assumption and unallocated remainder, retain `legalEffect: "not-determined"`, and avoid terms such as "amount owed."

### Additional protocol families

UCP over A2A and MCP is deferred. Visa Trusted Agent Protocol and x402 adapters are unsupported in v1.2. Each would require an exact versioned profile, source-preservation rules, trust semantics, mutation fixtures, and a narrow conformance claim.

### Hosted service

Authentication, tenant isolation, production key management, TLS termination, distributed replay protection, retention operations, monitoring, and incident response remain deployment responsibilities.

## 11. Public claim

The supported public claim is:

> MandateBound v1.2 implements the UCP 2026-04-08 REST + AP2 Mandates Extension / AP2 v0.2.0 evidence-import profile and a bounded AP2 dispute evidence resolver for evidence readiness and deterministic offline replay.

The unsupported claim is:

> MandateBound is UCP compliant, AP2 compliant, legally determines liability, or is production ready.

The profile is pinned to the [UCP 2026-04-08 specification](https://ucp.dev/2026-04-08/specification/overview/), the [UCP AP2 Mandates Extension](https://ucp.dev/specification/ap2-mandates/), and the [AP2 v0.2.0 release](https://github.com/google-agentic-commerce/AP2/releases/tag/v0.2.0).

## 12. Open-source posture

MandateBound is published by Oonyl under Apache License 2.0. Public examples use synthetic identities and data.

External teams can adopt the evidence model without adopting the reference policy. Any real trust model, policy, contract, retention rule, reviewer authority, or dispute procedure must be separately governed.
