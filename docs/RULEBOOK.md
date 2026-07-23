# Reference Rulebook v1

## Status

This rulebook is a configurable policy example. It is not law, contract language, an insurance determination, or a claim that any jurisdiction follows these allocations.

## Parties

- `principal`: the party represented as issuing the mandate
- `operator`: the party represented as operating the executing agent or control plane
- `model_vendor`: the party named in verified execution provenance and a qualifying causal attestation

An identifier in a signed artifact is still an assertion. Real-world identity and authority require governance outside this engine.

## Outcomes

### Principal

The principal branch requires all of the following:

- the mandate proof is accepted
- the mandate covers the exact action kind, target, counterparty, asset, amount, execution time, nonce, and usage
- the policy, trust snapshot, and evidence are valid at the explicit evaluation cutoff
- the execution receipt is trustworthy
- required operator controls complied
- no qualifying conflicting causal evidence exists

### Operator

The operator branch requires a trustworthy operator receipt that proves execution despite one or more of these facts:

- out-of-scope action, resource, counterparty, asset, or amount
- execution outside the mandate window
- revoked mandate
- replay or usage-limit breach
- required operator control bypass

An invalid evidence bundle alone does not allocate to the operator.

### Model vendor

The model-vendor branch is available only when:

- the recorded model provenance matches the mandate, receipt, and signed runtime evidence
- operator controls otherwise complied
- a trusted attestor has the required role and method
- the attestation binds the incident, execution, model, and cited evidence
- the attestation concludes that model behavior was a sufficient material cause
- no valid conflicting or superseding cause exists

A forged mandate, prompt injection allegation, or failed signature without qualifying causal evidence stays unresolved.

### Unresolved

Unresolved applies when evidence is missing, invalid, stale, tampered, equivocated, contradictory, multi-causal, unsupported by the rulebook, or insufficient to select exactly one branch.

## Dispositions

The engine separates policy outcome from evaluation disposition:

- `allocated`: exactly one reference branch matched
- `indeterminate`: required evidence is missing or insufficient
- `conflicted`: valid evidence supports incompatible facts or outcomes
- `invalid`: the closed bundle or required snapshot failed integrity checks

Only `allocated` carries a party role. Every disposition keeps `legalEffect: "not-determined"`.

## Rule precedence

1. Reject invalid input, evidence, policy, schema, algorithm, or trust.
2. Preserve contradictory or multi-causal evidence as unresolved.
3. Apply the operator branch only with a trustworthy receipt proving a supported violation.
4. Apply the model-vendor branch only when its complete causal gate passes and operator controls otherwise complied.
5. Apply the principal branch only with complete, compliant, in-scope evidence.
6. Treat missing evidence and the default rule as unresolved.

Rule identifiers, priorities, facts, and reason codes are stable and appear in the decision trace.

## Changes and appeals

A rulebook change creates a new content digest. It cannot alter an earlier decision. Re-evaluation with new rules is an appeal or a separate simulation and must reference the earlier decision explicitly.
