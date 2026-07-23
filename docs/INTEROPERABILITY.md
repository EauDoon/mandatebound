# Interoperability

## Native profile

The v1 core uses JSON Schema 2020-12, strict UTC timestamps, integer minor-unit amounts, [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785), SHA-256, and Ed25519.

The native proof profile is intentionally local and domain-separated. A future adapter may project suitable assertions into [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/) and [Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/). Such an export would authenticate an assertion, not prove its truth or legal effect.

## UCP

MandateBound v1.1 implements one bounded import target: the [UCP 2026-04-08](https://ucp.dev/2026-04-08/specification/overview/) REST profile with the AP2 Mandates Extension. The adapter pins profile bytes and their caller-owned digest, accepts only the REST shopping service and exact capability version, and preserves request bytes needed for later verification.

The adapter does not implement UCP over MCP or A2A, operate a checkout service, discover profiles live, or claim general UCP conformance.

## AP2

The [AP2 repository](https://github.com/google-agentic-commerce/AP2) is an upstream mandate source, not the core model. The v1.1 evidence adapter pins [AP2 v0.2.0](https://github.com/google-agentic-commerce/AP2/releases/tag/v0.2.0) and:

- enforce exact versioned `vct` values
- preserve compact JWT, SD-JWT, disclosure, and receipt representations byte for byte where upstream hashes depend on them
- reject unknown constraints
- verify issuer signature, disclosure integrity, key binding, audience, nonce, expiry, and artifact-hash relationships
- keep deterministic validation and trust pins outside agent-generated interpretation

AP2 continues to evolve, so this repository does not silently track its default branch and does not claim general AP2 conformance.

[RFC 9901](https://www.rfc-editor.org/rfc/rfc9901) standardizes base Selective Disclosure for JWTs. Other AP2-adjacent delegation and SD-JWT VC profiles may still be drafts and require separate version pins.

## SAFR

The public Singapore framework describes mandate, policy, risk-boundary, validation, and audit checkpoints. It is useful as a conceptual source for runtime evidence, but it is not treated here as a published machine protocol or certification scheme.

A SAFR-oriented adapter should map checkpoint results into vendor-neutral `RuntimeEvent` artifacts while preserving source-version and source-digest references. This repository does not claim SAFR compliance, regulatory approval, or endorsement. See the official [Singapore Government announcement](https://www.sgpc.gov.sg/detail?HomePage=home&page=%2Fdetail&url=%2Fmedia_releases%2Fmas%2Fpress_release%2FP-20260703-2).

## HTTP evidence

The v1.1 REST evidence adapter verifies [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421) and [RFC 9530 Content-Digest](https://www.rfc-editor.org/rfc/rfc9530). It binds method, authority, path, query when present, UCP agent profile, idempotency key for state-changing requests, content type, exact body digest, creation, expiry, and a caller-pinned EC key snapshot.

Transport authentication remains separate from evidence-artifact proofs. A valid HTTP signature does not replace the mandate, receipt, incident, or causation artifact inside the bundle.

## Adapter contract

Every external adapter should return:

- source protocol and exact version
- source schema or profile digest
- preserved source artifact digest
- verification status and stable reason codes
- normalized native artifact
- explicit unsupported constraints

The UCP/AP2 implementation returns these fields through typed verification reports and stable issue codes. Any future adapter must meet the same contract and fail closed when a source feature cannot be represented without loss.
