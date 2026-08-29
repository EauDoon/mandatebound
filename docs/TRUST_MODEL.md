# Trust Model

## Principle

Trust is an explicit input, not a live discovery process.

Each evaluation receives a complete trust snapshot and an exact digest pin established outside the artifact being verified. The snapshot cannot make itself trusted merely by containing its own publisher key.

## Key entries

Each trusted key records:

- key identifier derived from its public JWK
- Ed25519 public JWK
- allowed roles
- allowed proof purposes
- allowed actor scopes
- required `validFrom` and `validUntil`
- optional `invalidFrom` for compromise or revocation semantics

The verifier rejects algorithm negotiation, unknown key types, embedded replacement keys, role mismatch, purpose mismatch, scope mismatch, and use outside the valid window.

## Snapshot pinning

The caller supplies the expected snapshot digest. The engine recomputes the digest before using any key. A matching snapshot name with a different digest is rejected.

The decision records the accepted trust digest so later replay never resolves a key against current state.

## Library call order

`evaluateCase` and `evaluateBundle` validate the signed-artifact envelope, bind it to the exact installed trust-snapshot schema, confirm the caller pin, and only then resolve keys. Direct library callers using `verifyPinnedTrustSnapshot` or `verifyDigestPinnedTrustSnapshot` must preserve that order. Those functions are low-level trust-anchor primitives, not substitutes for signed-artifact and exact-schema validation.

`evaluateBundle` takes `EvaluationAnchors`: `{ pins, trustRootJwk?, expectedBundleRootDigest? }`. The nested `pins` object is the same `BundlePins` used by `evaluateCase`. Flattened pin fields (`asOf`, `policyDigest`, and the other `BundlePins` members at the top level) are not anchors and do not allocate. `EngineEvaluationAnchors` is an alias of that shape.

A caller-supplied digest pin is itself a trust decision. Supplying the optional root public key adds publisher-proof authentication but does not establish real-world identity or authority.

## Revocation

The snapshot can record:

- key invalidation effective at a stated time
- predecessor snapshot digest

Revocation semantics are explicit. A later snapshot can support an appeal but cannot rewrite an earlier decision evaluated under an earlier pinned snapshot.

## What trust does not prove

A key entry expresses the evaluator's configured trust that a key may sign for specified roles, purposes, and actor scopes. It does not by itself prove legal identity, actual key custody, corporate authority, informed consent, or truth of a signed assertion.

## Operational requirements outside v1

Production users need a separately governed process for root distribution, identity proofing, role approval, key custody, compromise response, snapshot publication, audit, recovery, and reviewer authorization.
