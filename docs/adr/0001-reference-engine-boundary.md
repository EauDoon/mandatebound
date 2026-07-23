# ADR 0001: Reference Engine Boundary

## Status

Accepted for v1.

## Context

The project needs to demonstrate how mandate and runtime evidence can feed a loss-allocation policy without pretending to solve legal personhood, insurance, credit, jurisdiction, or real claims adjudication.

## Decision

Build a deterministic, offline-capable reference engine with:

- normative JSON schemas
- strict parsing and canonical content addressing
- Ed25519 evidence proofs
- exact policy and trust pins
- a bounded data-only rulebook
- portable closed evidence bundles
- immutable decisions and append-only appeals
- local CLI, localhost API, and synthetic simulator

Every decision records `legalEffect: "not-determined"`.

The v1 engine does not perform live resolution, production authorization, fund movement, insurance, credit, external adjudication, or jurisdiction-specific doctrine.

## Consequences

The project can be reproduced, tested, and challenged as technical infrastructure. Production users must supply separate identity, contractual, legal, privacy, operational, and security governance.

Some real incidents will remain unresolved by design. That is preferable to forcing a confident allocation from incomplete evidence.
