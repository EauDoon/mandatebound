# Security Policy

## Supported versions

Security fixes are provided for the latest `1.2.x` release. Native v1 wire compatibility remains covered by frozen-schema and golden-derivation tests.

## Reporting a vulnerability

Please use GitHub's private security-advisory flow for this repository. Do not open a public issue for a suspected vulnerability, private-data exposure, or credential leak.

Include:

- affected version or commit
- a concise impact statement
- minimal reproduction steps using synthetic data
- whether the issue can expose evidence, keys, policy, trust, or decision integrity
- any safe mitigation already identified

Do not include real credentials, personal data, production evidence, or third-party confidential material.

## Security model

The trusted core assumes:

- a caller supplies an exact, pinned trust snapshot and policy
- private keys remain outside the evaluator
- artifact inputs are hostile until strict parsing, schema validation, digest verification, and proof verification pass
- cryptographic validity does not establish real-world truth, authority, causation, or legal effect
- UCP/AP2 evidence is accepted only under the exact version-pinned evidence-import profile
- AP2 Delegate SD-JWT chains are bounded by byte, segment, disclosure, constraint, artifact, source, and diagnostic limits
- external discovery material and source-checkpoint keys never enter native `TrustSnapshot/v1` automatically
- CasePack coverage is relative to caller-pinned declared sources and windows; source truth and global completeness remain unestablished
- imported revocation snapshots are reported evidence, not authenticated revocation facts
- the reference API is local development infrastructure, not a production security boundary; it binds only to loopback and rejects non-loopback peers, mismatched Host headers, and foreign Origins, but it has no production authentication, TLS, tenant isolation, or DDoS controls

The engine, CasePack verifier, and UCP/AP2 adapter perform no built-in live key, schema, policy, DID, DNS, revocation, timestamp, profile, or network resolution. The AP2 dispute resolver can invoke caller-supplied retrieval adapters, but the caller owns their transport authentication, authorization, privacy, and retention controls.

## AP2 Evidence Pack handling

`MandateBoundAp2EvidencePack/v1` is a sensitive container. Unlike the resolution and rendered timeline, it contains exact Mandates, Receipt JWTs, Checkout JWTs, caller-owned public trust pins, and imported revocation snapshot bytes. Treat Pack files as transaction evidence, not ordinary reports.

Deployments should encrypt Packs at rest and in transit, restrict access by case and role, log access, define retention and deletion rules, and avoid collecting unrelated personal or payment data. The HTML renderer omits raw artifacts, but its identifiers and digests may still be case-sensitive metadata.

The default HTML renderer escapes displayed values and uses a restrictive content security policy. Applications that re-render Pack fields must preserve equivalent output encoding and must not embed raw JWTs or snapshots into review pages.

Store each expected Pack digest separately from the Pack under the case system's own integrity controls. Positive verification requires that out-of-band digest. A digest copied from the Pack at verification time proves only self-consistency. The exported timeline and HTML functions recompute anchored verification and do not accept a caller-supplied verification report.

## Production gaps

The reference server does not provide production authentication, TLS termination, tenant isolation, KMS integration, distributed replay protection, durable consensus, external timestamping, or DDoS protection. It enforces the reviewer allowlist and event cap committed into each decision, but reviewer identity and role remain actor assertions. Deployments must authenticate those assertions and independently review reviewer authorization controls.

## Private keys

The repository contains no tracked private keys. Simulator and test keys are generated ephemerally in memory. JavaScript cannot guarantee memory zeroization, so production signing should remain isolated from this verifier.

## Dependency and release controls

- Dependencies are exact-version locked.
- Dependency lifecycle scripts are disabled in the documented install, packaging, and CI commands.
- `npm run verify` must pass before release.
- The packed package is checked against an explicit content allowlist.
- The release workflow produces an SPDX SBOM and a GitHub artifact attestation for the package tarball.
- Public release bytes receive a separate exact Git-tree privacy and secret scan.

See [Threat model](docs/THREAT_MODEL.md) for attack classes and fail-closed invariants.
