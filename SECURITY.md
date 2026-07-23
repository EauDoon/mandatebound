# Security Policy

## Supported versions

Security fixes are provided for the latest `1.0.x` release while v1 remains maintained.

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
- the reference API is local development infrastructure, not a production security boundary

The engine performs no live key, schema, policy, DID, DNS, revocation, timestamp, or network resolution.

## Production gaps

The reference server does not provide production authentication, TLS termination, tenant isolation, KMS integration, distributed replay protection, durable consensus, external timestamping, or DDoS protection. It enforces the reviewer allowlist and event cap committed into each decision, but reviewer identity and role remain actor assertions. Deployments must authenticate those assertions and independently review reviewer authorization controls.

## Private keys

The repository contains no tracked private keys. Simulator and test keys are generated ephemerally in memory. JavaScript cannot guarantee memory zeroization, so production signing should remain isolated from this verifier.

## Dependency and release controls

- Dependencies are exact-version locked.
- Dependency lifecycle scripts are disabled in the documented install, packaging, and CI commands.
- `npm run verify` must pass before release.
- The packed package is checked against an explicit content allowlist.
- Public release bytes receive a separate exact Git-tree privacy and secret scan.

See [Threat model](docs/THREAT_MODEL.md) for attack classes and fail-closed invariants.
