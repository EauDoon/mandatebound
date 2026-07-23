# MandateBound: Summary

## In one sentence

MandateBound is an open-source Agent Loss Allocation Protocol and AI agent liability policy engine that verifies autonomous-agent transaction evidence and applies a versioned policy to produce a reproducible, non-binding loss-allocation recommendation.

## Why it exists

Agent systems can authenticate, receive mandates, and execute payments, but post-transaction responsibility is still handled through fragmented logs and institution-specific judgment. A mandate can show what was authorized. A receipt can show what an operator says it executed. Runtime telemetry can show which controls fired. None of those artifacts, alone, answers who should absorb a loss.

The missing bridge is an evidence discipline plus an explicit allocation rule.

## The solution

The project provides:

- a canonical evidence model for mandates, runtime events, execution receipts, incidents, and causal attestations
- strict validation, canonicalization, signatures, digests, trust snapshots, replay checks, and revocation checks
- a deterministic reference rulebook with principal, operator, model-vendor, and unresolved outcomes
- an explainable decision that separates verified facts, attributed claims, policy conclusions, and legal effect
- a portable, tamper-evident bundle that can be verified offline
- immutable decisions and append-only appeals
- a CLI, localhost API, simulator, OpenAPI contract, and synthetic test suite

## The core policy

1. Valid execution inside a valid mandate selects the principal branch.
2. Trustworthy evidence of execution outside a valid mandate selects the operator branch.
3. The model-vendor branch requires sufficient, trusted, non-conflicting causal evidence and otherwise compliant operator controls.
4. Missing, invalid, tampered, contradictory, or multi-causal evidence stays unresolved.

This is configurable reference policy, not current law.

## Design principles

- **Fail closed:** uncertainty produces an unresolved result, not a guessed party.
- **Deterministic:** evaluation uses explicit time and exact content digests, with no live lookup.
- **Portable:** a single evidence bundle carries the case material for offline verification and deterministic replay; allocation additionally requires exact external caller pins.
- **Historically honest:** later policy or trust changes cannot silently alter an earlier decision.
- **Privacy-minimizing:** core artifacts favor digests and classified metadata, while raw prompts and personal data are excluded by default and still require deployment-level controls.
- **Legally bounded:** every decision states that legal effect is not determined.

## Intended users

- teams designing agent transaction controls and post-incident evidence
- policy, assurance, risk, and dispute teams testing allocation logic
- standards and infrastructure builders evaluating interoperable evidence formats
- researchers simulating how mandate evidence could connect to loss-allocation policy

## Not included

The project does not create legal personhood, provide agent-native credit, underwrite insurance, settle claims, replace legal counsel, or certify compliance with AP2, SAFR, or any regulatory framework.

## Release standard

The public release is required to pass strict type checking, schema tests, security and property tests, API and CLI tests, coverage thresholds, package-content review, dependency audit, privacy scan, exact Git-tree scan, and independent remote verification.
