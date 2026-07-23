# Interoperability

## Native profile

The v1 core uses JSON Schema 2020-12, strict UTC timestamps, integer minor-unit amounts, [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785), SHA-256, and Ed25519.

The native proof profile is intentionally local and domain-separated. A future adapter may project suitable assertions into [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/) and [Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/). Such an export would authenticate an assertion, not prove its truth or legal effect.

## AP2

The [AP2 repository](https://github.com/google-agentic-commerce/AP2) is an upstream mandate source, not the core model. A production adapter must:

- pin an exact AP2 release or commit and schema digest
- enforce exact versioned `vct` values
- preserve compact JWT, SD-JWT, disclosure, and receipt representations byte for byte where upstream hashes depend on them
- reject unknown constraints
- verify issuer signature, disclosure integrity, key binding, audience, nonce, expiry, and artifact-hash relationships
- keep deterministic validation and trusted-user surfaces outside agent-generated interpretation

The initial public target reviewed for this project was [AP2 v0.2.0](https://github.com/google-agentic-commerce/AP2/releases/tag/v0.2.0). AP2 continues to evolve, so this repository does not silently track its default branch and does not claim AP2 compliance.

[RFC 9901](https://www.rfc-editor.org/rfc/rfc9901) standardizes base Selective Disclosure for JWTs. Other AP2-adjacent delegation and SD-JWT VC profiles may still be drafts and require separate version pins.

## SAFR

The public Singapore framework describes mandate, policy, risk-boundary, validation, and audit checkpoints. It is useful as a conceptual source for runtime evidence, but it is not treated here as a published machine protocol or certification scheme.

A SAFR-oriented adapter should map checkpoint results into vendor-neutral `RuntimeEvent` artifacts while preserving source-version and source-digest references. This repository does not claim SAFR compliance, regulatory approval, or endorsement. See the official [Singapore Government announcement](https://www.sgpc.gov.sg/detail?HomePage=home&page=%2Fdetail&url=%2Fmedia_releases%2Fmas%2Fpress_release%2FP-20260703-2).

## HTTP transport

[RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421) and [RFC 9530 Content-Digest](https://www.rfc-editor.org/rfc/rfc9530) can protect a transport exchange. A transport profile should bind method, authority, path, content type, content digest, creation, short expiry, and replay nonce.

Transport authentication remains separate from evidence-artifact proofs. A valid HTTP signature does not replace the mandate, receipt, incident, or causation artifact inside the bundle.

## Adapter contract

Every external adapter should return:

- source protocol and exact version
- source schema or profile digest
- preserved source artifact digest
- verification status and stable reason codes
- normalized native artifact
- explicit unsupported constraints

An adapter must fail closed when a source feature cannot be represented without loss.
