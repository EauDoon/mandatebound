# MandateBound: Product and Policy Brief

## Executive brief

Autonomous agents increasingly receive signed mandates, invoke tools, and initiate economic actions. When an action causes loss, existing infrastructure can often answer fragments of the story: who issued a key, what a mandate allowed, what an operator logged, or whether a transaction settled. The fragments do not produce a reproducible allocation rule.

MandateBound is an open-source reference implementation of that evidence-to-policy bridge. It accepts a closed bundle of signed artifacts, verifies their integrity and authority against pinned snapshots, derives a bounded fact set, applies a versioned rulebook, and emits a non-binding recommendation for institutional or human review.

The v1 goal is not to declare who is legally liable. The goal is to make the policy reasoning explicit, testable, replayable, and difficult to manipulate silently.

## 1. The gap

Payment authorization and settlement answer whether value can move. Identity and signing answer whether a key produced an artifact. Runtime controls answer whether configured checks ran. Post-transaction allocation asks a different set of questions:

- Was the execution inside the exact mandate?
- Was the mandate valid at the relevant time?
- Did the operator follow the controls it represented?
- Was a nonce replayed or a trust root substituted?
- Is a causal allegation supported by an authorized, method-bound attestation?
- Is the evidence complete enough to apply a policy at all?

Without a common model, the answer tends to depend on mutable dashboards, private logs, current configuration, and undocumented discretion. That is weak evidence engineering even before legal doctrine begins.

## 2. Product definition

MandateBound has five parts.

### Evidence protocol

Versioned schemas define mandates, runtime events, execution receipts, incident reports, causation attestations, policies, rulebooks, trust snapshots, decisions, bundles, and appeals. Unknown properties fail validation. Amounts use integer minor units. Times are explicit UTC values.

### Verification pipeline

The verifier performs strict JSON parsing, canonicalization, digest checks, Ed25519 proof checks, signer-role checks, time checks, revocation checks, replay checks, scope comparison, and closed-manifest verification. It performs no network lookup.

### Policy engine

The engine converts accepted evidence into a small set of typed facts. A bounded data-only rulebook evaluates those facts. Rules cannot execute code, call a network, use floating point, inspect arbitrary JSON paths, or read system time.

### Decision and explanation

The result records:

- cryptographically verified facts
- attributed attestations
- rejected evidence and reasons
- missing or conflicting evidence
- matched rule and deterministic trace
- exact policy, trust, schema, rulebook, and bundle digests, plus the engine semantics version
- policy outcome and legal-effect boundary

### History and appeal

Decisions are immutable. Appeals append schema-validated, actor-attributed events to a hash chain and may reference a genuine superseding decision. The original result remains available and replayable under its original inputs. Production deployments must authenticate appeal actors at their own trust boundary.

## 3. Reference allocation logic

The bundled rulebook implements a narrow provisional skeleton.

### Principal branch

Use when a valid principal mandate covers the executed action kind, target, amount, asset, counterparty, validity window, nonce, and usage limit, and when required operator controls complied.

### Operator branch

Use when a trustworthy operator receipt proves that the operator executed despite a mandate being out of scope, expired, revoked, replayed, or otherwise invalid for that execution. An invalid bundle by itself is not enough to select the operator.

### Model-vendor branch

Use only when all required conditions hold:

1. model provenance matches the mandate, execution receipt, and signed runtime evidence
2. operator controls otherwise complied
3. an authorized independent attestor used a policy-allowed method
4. the attestation binds the case, transaction, model, and cited evidence
5. causal evidence is marked sufficient
6. no valid conflicting or superseding cause remains

A forged mandate or failed signature does not establish model-vendor fault.

### Unresolved branch

Use when evidence is missing, stale, invalid, tampered, contradictory, equivocated, multi-causal, or outside the rulebook's supported facts. Unresolved is a correct output, not an engine failure.

## 4. Trust and historical determinism

Every evaluation receives explicit policy and trust snapshots. Their exact digests are pinned into the decision. Keys have roles, scopes, validity windows, and invalidation times. Artifacts cannot introduce their own trusted key.

The engine does not resolve a DID, fetch a key, download a schema, check a current revocation service, or select a policy named “latest.” This prevents silent state changes from altering a historical result.

Later evidence or a new revocation position can support an appeal. It cannot rewrite what the earlier engine concluded from the earlier accepted inputs.

## 5. Evidence bundle

The portable `.albx.json` format is a canonical JSON document with a closed manifest. Each entry records a safe relative path, media type, classification, optional schema identifier, size, and content digest. Proof headers bind artifacts to exact schema digests. Entries are sorted and committed into a deterministic Merkle root. The bundle root binds the manifest digest and Merkle root.

The format avoids archive extraction in the trusted path. Absolute paths, parent traversal, backslashes, case-fold collisions, duplicate entries, and unlisted attachments are rejected.

The bundle can show integrity. It cannot prove that a claimant disclosed every relevant fact. Completeness remains a governance and adjudication question.

## 6. Privacy model

The core protocol prefers digests, classifications, and bounded metadata. Raw prompts, full model conversations, credentials, personal data, and full transaction payloads are excluded by default.

The v1 bundle embeds only canonical protocol JSON. Raw private attachments remain outside the reference format. A production adapter may add separately governed digest commitments, access controls, retention, and redaction lineage without weakening the core verifier.

Logs and errors do not echo artifact bodies, absolute paths, environment values, or key material.

## 7. Interoperability

The native format is deliberately protocol-neutral.

AP2 can provide upstream mandate artifacts, but an adapter must pin the exact AP2 version, profile, `vct`, and schema digest. Compact JWT and SD-JWT material must retain its exact serialization for upstream hash verification. This project does not claim AP2 conformance.

SAFR-style mandate, policy, risk-boundary, validation, and audit checkpoints can map into runtime evidence. The public framework is treated as a source of design concepts, not a published machine protocol or certification target. This project does not claim SAFR compliance or MAS endorsement.

Transport signatures, including RFC 9421 profiles, protect an HTTP exchange. They do not replace signed evidence artifacts inside the bundle.

## 8. Adoption path

### Stage 1: simulation

Use synthetic scenarios to test whether an institution's proposed allocation policy produces expected outcomes and appropriately unresolved cases.

### Stage 2: shadow evidence

Generate native evidence alongside an existing agent transaction flow without changing authorization or claims decisions. Compare evidence completeness, operational cost, and review time.

### Stage 3: contractual pilot

If legal and commercial owners choose to proceed, bind a policy version and evidence obligations into a controlled bilateral pilot. Independent legal and insurance review is required.

### Stage 4: institution-specific adapters

Add version-pinned mandate, receipt, trust, and evidence-store adapters. Keep the core rule engine independent of any payment rail or vendor.

## 9. Risks

### False legal confidence

The largest risk is semantic, not cryptographic. A technically valid decision can be mistaken for a legal judgment. The project counters this through machine-readable legal-effect fields, visible disclaimers, unresolved states, and separated fact categories.

### Evidence capture failure

An engine cannot evaluate evidence that was never captured. Shadow deployments should measure missing artifacts and timestamp reliability before policy use.

### Trust-root governance

Pinned trust improves reproducibility but moves responsibility to trust-root distribution, key custody, revocation semantics, and snapshot approval.

### Causation quality

A signature authenticates an attestor's statement, not the truth of the statement. Policies must define allowed methods and reviewers, and must preserve conflicting evidence.

### Policy gaming

Parties may optimize behavior around amount, timing, counterparty, scope, and usage boundaries. Property tests and adversarial fixtures should accompany every rulebook change.

### Demand risk

The infrastructure is only useful if autonomous economic activity produces losses worth allocating. The reference implementation intentionally avoids claims about market size or commercial readiness.

## 10. Success criteria

The v1 release succeeds if it can:

- reproduce the four reference outcomes from synthetic evidence
- fail closed on missing and conflicting evidence
- detect any mutation to canonical bundle content or committed metadata
- reject replay, scope expansion, policy substitution, and trust substitution
- replay a historical decision byte for byte
- append an appeal without mutating the original
- run offline after dependency installation
- pass type, schema, property, security, API, CLI, privacy, package, and release-tree checks
- explain its limits in the first screen of the README and every machine decision

## 11. Non-goals

The v1 project does not:

- create or recognize agent legal personhood
- extend credit or custody value
- underwrite insurance or settle claims
- replace payment authorization or identity systems
- apportion shared fault across many actors
- decide governing law or evidentiary standards
- certify external protocol or regulatory compliance
- operate as a production multi-tenant service

## 12. Open-source posture

The reference implementation is released under Apache License 2.0 to encourage review and extension while providing an explicit patent grant. Public examples are synthetic. Product direction, requirements, and evaluation are attributed to Oonyl, with AI-assisted implementation disclosed plainly.

External projects may adopt the schemas or code without adopting the reference allocation rule. Any production policy should be separately governed, versioned, reviewed, and contractually grounded.
