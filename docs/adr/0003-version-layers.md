# ADR 0003: Version Layers

## Status

Accepted. Takes effect with the first package release after 1.2.0.

## Context

Until 1.2.0, one constant, `RELEASE_VERSION`, served two purposes. It labelled the package release, and it was also written into every AP2 dispute resolution, Evidence Pack and Pack verification report. Pack verification required it to equal the running package's value, and the published `schemas/v1.2` files pin it as the constant `"1.2.0"`.

Any package release after 1.2.0 would therefore have invalidated every retained Pack and produced artifacts that violate the published schemas. The release was held at 1.2.0 for that reason while a removed public option, CLI behavior changes and an RFC 8785 serialization correction accumulated under the same label. The label then could not distinguish builds inside the [separator regression window](../PROTOCOL.md#separator-correction-and-historical-compatibility) from corrected ones.

The CLI also printed `version` (the protocol version) beside `releaseVersion` without saying which layer each value described, and nothing checked OpenAPI, the lockfile or the release tag against the package.

## Decision

MandateBound has separate version layers. Each one moves only for its own reason.

| Layer | Where it lives | Moves when |
| --- | --- | --- |
| Package release | `package.json` `version`, mirrored by `RELEASE_VERSION` | Any release. It follows Semantic Versioning for the package API, CLI and HTTP API. |
| Protocol | `PROTOCOL_VERSION`, `1.0.0` | Policy facts, rule precedence, proof input, canonical form, bundle root or decision bytes change. Decision pins depend on it. |
| Engine | `ENGINE_VERSION`, `1.0.0` | Engine evaluation semantics change. Decision pins depend on it. |
| Schema directories | `schemas/v1`, `schemas/v1.1`, `schemas/v1.2` | A new artifact format is published. Published directories are never edited; `schemas/v1` is digest-pinned. |
| AP2 Pack format release | `AP2_DISPUTE_FORMAT_RELEASE`, frozen at `1.2.0` | Never, for the existing formats. A changed AP2 resolution, Pack or verification format needs a new schema directory and a new constant. |
| OpenAPI document | `openapi/openapi.json` `info.version` | It tracks the package release, because the HTTP API ships with the package. |
| Conformance declaration | `conformance/v<major>.<minor>/capabilities.json` | One directory per package major.minor. Earlier declarations stay retrievable from their release tag and tarball. |

`package.json` is the single source of the package release. `scripts/version.mjs sync` propagates it to `RELEASE_VERSION`, the conformance declaration and OpenAPI, and `scripts/version.mjs check` fails CI on any drift, including the lockfile, the newest CHANGELOG section and, at release time, the Git tag.

AP2 resolutions, Packs and verification reports carry `AP2_DISPUTE_FORMAT_RELEASE` as their `releaseVersion`, and Pack verification requires that value. The field name is kept for wire compatibility; its meaning is the format release. The metadata-only HTML timeline labels it "Pack format".

The CLI `--version` and `--help` output name every layer: `protocolVersion`, `releaseVersion`, `engineVersion` and `ap2PackFormatRelease`. `version` remains as an alias of the protocol version for existing callers.

Operator assessment receipts embed the package `releaseVersion` together with the engine and protocol versions, by design. A receipt records which validator build produced an assessment, so verifying a receipt made by another release reports the version difference as a change for review.

## Consequences

The package release can move without changing the format label, Pack digest or anchor match of any retained AP2 artifact. Pack verification still re-derives the resolution from the embedded evidence under the verifying build's gates, so a gate tightened after a Pack was written can make it verify as `unresolved` with `AP2_PACK_RESOLUTION_UNRESOLVED`, while `digestValid` and `anchorMatched` stay true. Delegated Mandate payloads require `exp` since 2.0.0, so a 1.2.0 Pack whose delegated Mandate payload has no `exp` verifies that way.

Two frozen Packs written by the released 1.2.0 code are kept as test fixtures. One was packed after its Checkout Mandate was given `iat` and `exp` and must keep verifying unchanged. The other was packed from the tag's unmodified test helpers, has no delegated `exp`, and must keep verifying as `unresolved` with a valid digest and a matched anchor.

Native artifact bytes, decision pins, protocol `1.0.0` and engine `1.0.0` do not move with a package release.

Assessment receipts created before a package release verify with a `releaseVersion` difference after it. Operators who retain receipts across releases must expect that review step; it is not evidence of tampering.

A package major release can be required by package, CLI or HTTP API changes alone, even when every artifact format is unchanged. The CHANGELOG states which layers each release touched.
