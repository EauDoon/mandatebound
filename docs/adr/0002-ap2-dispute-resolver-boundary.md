# ADR 0002: AP2 Dispute Evidence Resolver Boundary

## Status

Accepted for v1.2.

## Context

AP2 v0.2.0 identifies a Checkout Mandate, Checkout Receipt, Payment Mandate, and Payment Receipt as dispute evidence. It defines integrity checks over their signatures, transaction binding, Checkout JWT, and Receipt references. It intentionally leaves evidence retrieval, retention, revocation transport, and the actual dispute-resolution process outside the protocol.

MandateBound needs a reproducible way to gather these four artifacts without inventing a transport, treating a transaction identifier as retrieval authority, or presenting cryptographic integrity as a claim decision.

The AP2 v0.2.0 text and SDK also leave room for incompatible interpretations of the Receipt reference representation. Trying several formulas until one passes would hide that ambiguity.

## Decision

Add an optional AP2 Evidence Pack and dispute evidence resolver with these boundaries:

- pin AP2 release `v0.2.0` at commit `b4587ac1d055888a73b4b21750973cffba961793`;
- accept direct closed SD-JWT Mandates and AP2 Delegate SD-JWT chains, while rejecting the non-AP2 trailing plain `kb+jwt` shape in the resolver profile;
- accept exact compact Mandate and Receipt bytes from materialized sources or caller-supplied retrieval adapters;
- keep issuer keys, source digests, expected audiences, nonces, merchants, and evaluation time in one caller-owned verification plan;
- enforce the pinned required `checkout.line_items` and `payment.reference` constraints, with unsupported constraints failing closed;
- verify the merchant-signed Checkout JWT and its bounded pinned UCP Checkout shape;
- require `H(checkout_jwt)`, Checkout Mandate `checkout_hash`, Payment Mandate `transaction_id`, and the requested transaction identifier to agree;
- bind the open Payment Mandate to the `sd_hash` of the associated open Checkout Mandate;
- verify both Receipt JWTs and bind each reference to its exact closed Mandate;
- use the named `sha256-terminal-compact-jws` Receipt reference profile, matching the pinned AP2 v0.2.0 SDK behavior;
- detect conflicting exact bytes without selecting the last response;
- provide `pack`, independent expected-digest anchored `verify`, and metadata-only `render` operations that recompute verification rather than trust a supplied report;
- preserve exact Checkout versions and imported revocation snapshots inside a sensitive content-addressed Pack;
- describe revocation states only as imported reports, never authenticated protocol facts;
- emit only `evidence_verified` or `unresolved`;
- retain `historyCompleteness: "unknown"`, `disputeOutcome: "not-determined"`, and `legalEffect: "not-determined"`; and
- exclude raw Mandates, Checkout data, Receipts, revocation snapshots, and provider exception text from the resolution and timeline artifacts.

The core library performs no network access. A retrieval adapter is executable caller code. Its owner is responsible for endpoint authentication, authorization, privacy, retention, rate limits, and transport security. Knowledge of `transaction_id` is not authority to retrieve evidence.

## Consequences

MandateBound can fill AP2's evidence-assembly gap and produce a deterministic, content-addressed integrity report. A cryptographically authentic `Error` Receipt remains valid evidence of rejection and does not force the resolver to `unresolved`.

The Evidence Pack is intentionally more sensitive than the resolution or rendered timeline because it contains raw signed artifacts and imported snapshot bytes. It requires separate encrypted storage, access control, retention, and disclosure governance.

The Pack is not its own identity authority. A positive verification requires an expected Pack digest retained under independent case-record integrity controls. Timeline and HTML rendering recompute that anchored verification, so a forged or foreign verification report cannot mark another Pack as verified.

Pack verification requires reported revocation coverage for both closed Mandates and only `not_revoked` imported reports. This is an evidence-readiness gate, not a revocation-protocol conformance claim. The library does not contact or authenticate a revocation service.

The resolver does not decide refunds, chargebacks, fraud, causation, liability, damages, fulfillment, settlement finality, or legal rights. It does not establish complete upstream history or general AP2 conformance.

Evidence using an unsupported Mandate representation, constraint, hash algorithm, trust interpretation, revocation source, or Receipt reference profile remains unresolved. Supporting a different interpretation requires a new named profile and fixtures, not a compatibility fallback.
