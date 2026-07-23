# Privacy Model

## Data minimization

The protocol is designed to carry only what the policy needs. Prefer:

- stable synthetic or institution-scoped identifiers
- content digests instead of raw payloads
- categorized control results instead of prompt text
- bounded allegation and reason codes instead of narrative case files
- explicit private attachment classifications

Do not place credentials, private keys, full prompts, model conversations, payment credentials, government identifiers, personal addresses, or unrelated production logs in a core artifact.

## Evidence references

The v1 bundle embeds canonical protocol JSON only. Raw private attachments should remain in an authorized external system and are not verified by the core engine. Any adapter that commits external evidence must define its own digest, media type, size, access, retention, and disclosure rules explicitly.

## Redaction

A redacted artifact is a derivative, not the signed original. Applications should assign it a new digest and retain governed derivation metadata outside the v1 core. Redaction must never preserve an old proof as though the bytes were unchanged.

## Logs and errors

Machine error responses use stable codes and generic messages. They do not echo hostile input. Local diagnostic logs avoid request bodies, evidence values, public-key material, private paths, or environment data.

## Retention

The reference engine does not define a legal retention period. Deployments must choose retention, deletion, access, audit, legal-hold, and cross-border rules based on their actual data and jurisdiction.

## Public fixtures

Tracked examples use unmistakably synthetic identities and ephemeral runtime keys. The source research thesis and private project context are not included in the public package.
