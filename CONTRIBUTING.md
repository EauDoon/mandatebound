# Contributing

Contributions that improve determinism, interoperability, explainability, privacy, or adversarial coverage are welcome.

## Setup

```bash
npm ci --ignore-scripts
npm run verify
```

Node.js 22.12 or newer is required.

## Pull requests

Keep changes narrow and explain:

- the behavior or risk being addressed
- any schema, rulebook, trust, proof, bundle, or decision compatibility effect
- tests added or changed
- privacy and legal-confidence implications
- whether historical replay remains byte-identical

Do not include real transaction evidence, identities, keys, prompts, logs, screenshots, or production infrastructure details.

## Compatibility rules

- Normative schemas live under a versioned directory.
- Unknown artifact properties remain rejected.
- A semantic change to policy facts, rule precedence, proof input, canonical form, bundle root, or decision bytes requires an explicit protocol version decision.
- Existing decisions and bundles must remain verifiable under their recorded engine version.
- New evidence can support an appeal, but cannot mutate an earlier decision.

## Tests

Every behavior change needs focused positive and negative tests. Security-sensitive changes should include adversarial cases and property invariants.

The release gate is:

```bash
npm run verify
```

## Public language

Do not describe a policy output as a legal judgment, insurance determination, compliance certification, or proof of causation. Do not imply regulator, standards-body, network, insurer, or vendor endorsement.

## Provenance

If a contribution uses generated code or text, review it as carefully as human-authored material and disclose material third-party provenance or licensing obligations.
