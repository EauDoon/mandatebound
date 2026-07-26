# MandateBound v1.2 conformance fixtures

This directory identifies the bounded conformance surface exercised by `npm run conformance`.

The v1.2 suite retains the v1.1 evidence-import and CasePack fixtures and adds:

- exact AP2 v0.2.0 dispute-profile pinning at commit `b4587ac1d055888a73b4b21750973cffba961793`;
- direct closed SD-JWT and Delegate SD-JWT chain verification with official SDK-generated frozen vectors;
- required autonomous Checkout and Payment constraints plus terminal closed-Mandate Receipt references;
- deterministic four-artifact assembly across caller-supplied sources;
- merchant Checkout JWT, Mandate, Receipt, transaction, and reference verification;
- sensitive Evidence Pack creation, independent digest verification, exact Checkout-version binding, and metadata-only rendering;
- imported reported-revocation coverage with revoked and unknown states failing closed;
- duplicate-source deduplication without last-response-wins behavior;
- fail-closed missing, stale, future-captured, oversized, malformed, mutated, mismatched, conflicting, forged, and retrieval-failure fixtures;
- raw-token and provider-error non-reflection checks; and
- frozen native v1 compatibility checks.

Passing these fixtures supports only the named evidence-import, Mandate-chain, dispute-integrity, and Evidence Pack profiles. It does not establish general AP2 conformance, authenticated revocation state, complete transaction history, claim correctness, legal effect, or production readiness.
