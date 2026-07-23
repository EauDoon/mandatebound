# MandateBound v1.1 conformance fixtures

This directory identifies the bounded conformance surface exercised by `npm run conformance`.

The suite covers:

- frozen EvidenceBundle/v1 schema bytes and golden outputs;
- deterministic CasePack/v1 construction, validation, coverage, and diff behavior;
- UCP 2026-04-08 REST evidence import with RFC 9421 signatures and RFC 9530 body digests;
- AP2 v0.2.0 Mandates evidence import, including compact-token preservation and key binding; and
- policy-pack validation, tests, and deterministic rulebook diffs.

Passing these fixtures supports only the named evidence-import profile. It does not establish general UCP or AP2 conformance, complete transaction history, legal correctness, or production readiness.
