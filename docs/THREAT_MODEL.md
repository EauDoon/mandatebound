# Threat Model

## Assets

- mandate scope and authorization evidence
- artifact and bundle integrity
- key roles and trust snapshots
- policy and rulebook identity
- evidence completeness and causation lineage
- replay and revocation state
- deterministic decision bytes
- immutable appeal history
- private evidence and release integrity

## Adversaries

The design assumes that a principal, operator, claimant, agent, evidence provider, policy administrator, API client, local file contributor, insider, dependency, or build runner may be compromised or dishonest.

## Trust boundaries

1. Hostile JSON and HTTP bodies
2. Schema and canonicalization
3. Proof and trust verification
4. Bundle closure and path handling
5. Policy and evidence evaluation
6. Store and appeal history
7. API, CLI, logs, and errors
8. Build, package, and public release

## Fail-closed invariants

| Area | Invariant |
| --- | --- |
| Parsing | Duplicate keys, unsafe numbers, invalid Unicode, byte-order marks, unknown fields, and exceeded limits are rejected before evaluation. |
| Proofs | Type, schema, purpose, actor, key, algorithm, and payload are bound. No algorithm fallback or embedded key is accepted. |
| Trust | The exact snapshot digest is pinned. Missing, stale, invalid, or unavailable required trust never becomes a pass. |
| Scope | Amount, time, asset, action, target, counterparty, nonce, usage, policy, and party bindings are exact. Delegation data is preserved and cannot widen these evaluated bounds. |
| Replay | Completed prior receipts count only when they bind the exact mandate, operator, policy, and nonce. Reused execution identity with changed content, or excess execution under a bounded mandate, is a replay violation and can select the operator branch. Contradictory receipt identities or bindings stay conflicted. Missing required replay state stays unresolved. |
| Policy | Policy is selected by digest. Unknown facts or operators fail validation. No code, network, randomness, floating point, or ambient time is available. |
| Evidence | The manifest is closed. Missing, extra, altered, equivocated, or conflicting evidence cannot yield a confident allocation. |
| Causation | An attestation is an attributed assertion. Model-vendor allocation requires a complete causal gate and no valid conflict. |
| Appeals | Events are append-only and chained. Original decisions are immutable. Forks, gaps, cycles, and truncation uncertainty remain visible. |
| Privacy | Errors and logs do not echo artifact bodies, keys, environment values, control characters, or absolute paths. |
| Legal effect | Every result says `not-determined` and separates proof, assertion, policy, and legal meaning. |
| Determinism | Same accepted inputs, pins, engine, and explicit time produce identical result bytes. |

## Required adversarial suites

### Signature and canonicalization

- cross-type and cross-purpose signature reuse
- unsupported algorithms and wrong key types
- attacker-carried keys and key-role mismatch
- malformed and noncanonical base64url
- field reordering versus one-byte value mutation
- duplicate keys, invalid Unicode, unsafe numbers, and oversized input

### Replay, time, and revocation

- duplicate one-use execution
- changed-content reuse under the same nonce
- exact validity boundaries
- revocation before, during, and after execution
- stale trust and unavailable replay state

### Scope and policy

- exact cap and cap-plus-one
- wrong asset, counterparty, target, runtime actor, or action
- delegation data that attempts to widen an evaluated bound
- same policy identifier with changed bytes
- trust substitution and engine-version mismatch
- unknown facts, operators, or duplicate rule priorities

### Evidence and bundles

- one-byte mutation for every artifact class
- missing, extra, duplicated, or case-colliding entries
- parent traversal, absolute path, drive path, backslash, and reserved-name inputs
- omitted, circular, future, or cross-case evidence references
- conflicting authorized causation attestations

### API and privacy

- oversized, slow, malformed, duplicate-key, and deeply nested bodies
- expensive invalid-signature floods and bounded concurrency
- canary secrets and personal data in every field
- control-character log injection
- filesystem and unexpected-exception path leakage
- localhost binding and absent permissive CORS

### Appeals and release

- reordered, deleted, duplicated, forked, or truncated appeal events
- unauthorized actor and cross-case reference
- package allowlist and clean-install checks
- exact Git-tree privacy scan and remote-byte verification

## Residual risks

The engine cannot prove evidence completeness, real-world events, honest identity binding, causal truth, legal authority, governing law, external log-tail completeness, or secure production key custody. These remain explicit governance requirements.
