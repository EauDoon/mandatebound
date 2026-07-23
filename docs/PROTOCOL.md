# Protocol v1

## Conventions

- JSON Schema dialect: 2020-12
- JSON profile: I-JSON-compatible values accepted by the strict parser
- Canonical JSON: RFC 8785
- Digest: SHA-256, rendered as `sha256:<lowercase hex>`
- Signature: Ed25519 in the native domain-separated proof profile
- Time: UTC RFC 3339 with milliseconds
- Amount: non-negative integer minor-unit string plus an explicit asset identifier
- Identifiers: bounded ASCII strings with artifact-specific prefixes
- Network resolution during evaluation: none

## Native signed artifact

A signed artifact contains:

- artifact type and schema version
- a typed payload
- exactly one proof in the v1 reference evaluator

The proof input binds protected metadata and the complete artifact payload. Protected metadata includes domain, artifact type, schema digest, proof purpose, key identifier, and creation time. The actor is part of the signed payload and must also match the key role and configured scope. The verifier accepts Ed25519 only and resolves the key only from the pinned trust snapshot.

A proof is accepted only for its exact artifact type and purpose. A mandate proof cannot be reused as a receipt or causation proof.

## Core artifacts

### Mandate envelope

Defines the asserted principal, operator, agent, optional model vendor, validity window, one-time nonce, usage limit, delegation limit, allowed action scope, required controls, and policy reference.

### Runtime event

Records a bounded, content-addressed checkpoint such as a control result, tool invocation, approval, or execution request. Raw prompts and secrets are excluded by default.

### Execution receipt

Binds an execution to a mandate digest, policy digest, nonce, idempotency key, action, economic effect, runtime-event root, model and tool provenance, control disposition, and operator proof.

### Incident report

Records an allegation and supporting evidence references. It does not record an adjudicated fact.

### Causation attestation

Records an attributed causal assertion, allowed method, cited evidence, competing causes, conclusion, and attestor proof.

### Liability policy

Defines the authority bindings, exact rulebook and trust references, accepted causation methods and attestor role, effective window, and appeal authority. The separately pinned rulebook defines the supported facts and deterministic rule order.

### Trust snapshot

Defines accepted keys, roles, purposes, scopes, validity, key invalidation, and snapshot lineage. The evaluator receives an exact out-of-band digest pin.

### Liability decision

Binds exact inputs and records disposition, policy outcome, trace, facts, assertions, rejected evidence, missing evidence, content pins, and non-binding legal-effect status.

### Appeal event

Appends a schema-validated, actor-attributed event to a case-specific hash chain. Sequence, predecessor digest, decision, actor, action, and time are bound by the event digest. Each decision commits to the evaluated policy's reviewer allowlist and event cap. The reference store enforces that cap and checks the asserted reviewer ID and role for review, uphold, and reversal events. It does not authenticate the actor assertion; deployments must add reviewer authentication at their trust boundary.

## Evaluation

Evaluation is pure with respect to accepted inputs:

1. Parse hostile JSON with limits and duplicate-key rejection.
2. Validate artifact schemas and reject unknown properties.
3. Recompute canonical bytes and content digests.
4. Confirm exact policy and trust pins.
5. Verify proof algorithm, key role, purpose, actor binding, scope, time, and invalidation.
6. Verify the closed evidence bundle. If the caller supplies a bundle, require its reconstructed case to match the exact normalized evaluation case.
7. Reconcile every verified event for each required control against the receipt. Omitted, mismatched, incomplete, or contradictory results fail closed.
8. Count a prior receipt for replay or usage only after exact mandate, operator, policy, nonce, and execution-identity binding.
9. Derive typed facts for mandate validity, scope, replay, controls, receipt trust, provenance, and causation.
10. Apply the bounded rulebook.
11. Emit a deterministic decision with a stable trace.

The engine never substitutes a newer schema, policy, trust snapshot, rulebook, or current time.

## Bundle root

The native `.albx.json` document contains a closed manifest and embedded canonical artifacts.

For each entry sorted by path, canonicalize its metadata with JCS and prefix the bytes with the leaf domain byte:

```text
leaf = SHA256(0x00 || JCS({path, mediaType, size, classification, digest[, schemaId]}))
```

For each pair:

```text
parent = SHA256(0x01 || raw(leftDigest) || raw(rightDigest))
```

An odd final node is duplicated. The empty-tree value is `SHA256(0x00)`, although a valid case bundle contains entries.

The manifest and bundle root are:

```text
manifestDigest = SHA256(JCS({format, evidenceCutoff, pins, entries, merkleRoot}))
rootDigest = SHA256(JCS({schemaVersion: "1.0.0", manifestDigest, merkleRoot}))
bundleId = "urn:agent-liability:bundle:" || hex(rootDigest)
```

The bundle artifact identifier uses the first 24 hexadecimal characters of `rootDigest`. Bundle proofs are empty in v1. Any accepted canonical content or committed metadata change changes an entry digest or Merkle leaf and therefore changes the bundle root.

## Replay

A mandate binds its principal and operator, mandate ID, authorization nonce, transaction scope, and maximum execution count. A caller that intends to identify the same execution again must reuse the same execution ID and idempotency key. A completed prior receipt still consumes the mandate usage limit; changed-content reuse or a second execution under a one-use mandate is a replay violation.

If required replay state is unavailable, the engine remains unresolved.

## Versioning

Protocol, schema, rulebook, policy, trust, engine, and bundle versions are distinct. A display name or semantic version never substitutes for an exact digest where a digest is required.
