# Contributing

Contributions that improve determinism, interoperability, explainability, privacy, or adversarial coverage are welcome.

## Setup

```bash
npm ci --ignore-scripts
npm run verify
```

Node.js 22.12 or newer is required.

## Dependency advisories

`scripts/check-dependencies.mjs` compares every installed package against the advisory windows recorded at the top of that script, and runs as part of `npm run verify`. It fails closed on a vulnerable version, an unreadable manifest, or a missing dependency tree. When a dependency needs a minimum safe version, add an entry there with a window no wider than the published advisory, and keep any matching `overrides` floor in `package.json` at or above the recorded fixed version.

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
- Existing decisions and bundles must remain verifiable under their recorded engine version, except where a documented implementation regression reused that identifier. The [RFC8785 separator correction](docs/PROTOCOL.md#separator-correction-and-historical-compatibility) requires the exact producer revision for affected historical replay and rejects the regressed form in the corrected verifier.
- New evidence can support an appeal, but cannot mutate an earlier decision.

## Tests

Every behavior change needs focused positive and negative tests. Security-sensitive changes should include adversarial cases and property invariants.

The release gate is:

```bash
npm run verify
```

## Releasing

`package.json` `version` is the single source of the package release. The
lockfile, the `RELEASE_VERSION` literal in `src/version.ts`, the conformance
declaration for that major.minor, OpenAPI `info.version`, the newest dated
CHANGELOG section and, at release time, the Git tag must all agree with it.
`npm run version:check` enforces that agreement and runs inside
`npm run verify:static`, so CI fails on drift even where npm lifecycle scripts
were disabled during the bump.

1. Record each change under `## [Unreleased]` in `CHANGELOG.md` as it lands,
   following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
2. Bump with `npm version X.Y.Z --no-git-tag-version`. npm updates
   `package.json` and `package-lock.json`, then its `version` lifecycle script
   runs `node scripts/version.mjs sync`, which edits the other targets in place.
   If lifecycle scripts are disabled, run that sync command yourself. A new
   major.minor needs the previous `conformance/vX.Y/` declaration moved first.
3. Turn `## [Unreleased]` into `## [X.Y.Z] - YYYY-MM-DD`, add a fresh empty
   `## [Unreleased]` above it, and update the compare links at the bottom.
4. Run `npm run verify` and `node scripts/version.mjs check --tag vX.Y.Z`.
5. After merging, write the notes with
   `node scripts/version.mjs notes X.Y.Z > notes.md` and create the release with
   `gh release create vX.Y.Z --target <merge commit> --notes-file notes.md`.
   Publishing the release runs `.github/workflows/release.yml`, which verifies
   the tag again and attaches the tarball, SBOM and checksums.

## Public language

Do not describe a policy output as a legal judgment, insurance determination, compliance certification, or proof of causation. Do not imply regulator, standards-body, network, insurer, or vendor endorsement.

## Provenance

If a contribution uses generated code or text, review it as carefully as human-authored material and disclose material third-party provenance or licensing obligations.
