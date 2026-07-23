# Legal Boundary

## Machine meaning

`LiabilityDecision` is the schema name for an engine output. It means that a named policy selected or declined to select a reference allocation branch from a specific evidence snapshot.

It does not mean that a court, regulator, insurer, scheme, issuer, merchant, model provider, operator, or contracting party has accepted that allocation.

## What cryptography establishes

Depending on accepted trust assumptions, cryptography can establish that:

- bytes have not changed since a digest was computed
- a key produced a signature over a protected message
- a closed manifest commits to listed artifacts
- a replay uses the same pinned inputs

It does not independently establish:

- who controlled the key
- whether the signer had legal authority
- whether a principal understood or intended an action
- whether an event happened outside the logged system
- whether an attestation is true
- whether a model caused a loss
- which law applies
- whether a policy term is enforceable
- whether insurance responds

## Required deployment work

Any real use requires explicit governing documents, party identity and authority checks, evidence-retention rules, privacy basis, reviewer authority, dispute procedures, appeal standards, security controls, and professional advice appropriate to the jurisdiction and product.

The repository intentionally leaves those decisions outside the reference engine.
