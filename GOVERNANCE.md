# Governance

## Project scope

MandateBound maintains a neutral evidence model, deterministic reference policy engine, verification tools, and synthetic conformance suite for autonomous-agent transaction review.

It does not govern a real claims scheme, legal standard, insurer product, payment network, or regulatory regime.

## Maintainer

Oonyl is the initial maintainer and final reviewer for v1 repository changes.

## Decision process

Changes are evaluated against five questions:

1. Does the change preserve or improve deterministic replay?
2. Does it make trust and evidence assumptions more explicit?
3. Does it fail closed under missing or conflicting evidence?
4. Does it reduce the chance of false legal confidence?
5. Can a stranger reproduce the claimed behavior from the repository?

Protocol-affecting decisions are recorded under `docs/adr` before release.

## Versions

- Patch releases fix implementation defects without changing accepted evidence meaning.
- Minor releases may add optional artifacts, adapters, facts, or tools while preserving v1 replay.
- Major releases may change normative semantics, proof inputs, bundle roots, or decision bytes.

No release may silently reinterpret an earlier content-addressed decision.

## Rulebooks

The bundled rulebook is a reference policy. External users may create other rulebooks, but each must use supported facts and operators, receive a unique content digest, and avoid claiming legal authority.

## Security

Security reports follow [SECURITY.md](SECURITY.md). A security fix may be developed privately until a safe release is available.
