# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the package
release follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

The package release is one version layer among several. The protocol, engine,
schema-directory and AP2 Pack format versions move separately and are described
in [Protocol v1](docs/PROTOCOL.md).

## [Unreleased]

## [2.0.0] - 2026-10-09

### Upgrading from 1.2.0

2.0.0 is a major release because the package API and CLI changed in ways a 1.2.0
caller can notice. Protocol `1.0.0`, engine `1.0.0`, native artifact bytes,
schemas and decision pins are unchanged, and Node.js 22.12 or newer is still
required.

- `CreateApiServerOptions.allowRemote` and `serve --allow-remote` are removed.
  The server binds only to loopback; put a reverse proxy you operate in front of
  it for remote access.
- CLI `decide` and `preview` reject an incomplete evaluation case with exit 3
  instead of exit 0 with a fabricated `malformed-case` decision. Send the
  complete case the API's `POST /v1/evaluations` accepts.
- A held store lock exits 6 instead of 5, a busy or unbindable `serve` port
  exits 6 instead of 70, and an invalid `serve --host` exits 2 instead of 3.
- `operator compare` exits 3 instead of 0 when the current assessment is
  invalid without a regression. CLI `replay` rejects a malformed checkpoint or
  extra envelope keys with exit 3 instead of reporting a mismatch (exit 5), and
  `appeal` rejects keys beside `{event, decision?}`.
- Public `EvaluationAnchors` uses the nested `pins` shape, and strict JSON, API
  and JSONL store limit overrides reject unknown limit names.
- Operator assessment receipts embed the package release, so a receipt made by
  a 1.2.0 or earlier build reports a `releaseVersion` difference (exit 5 from
  `receipt-verify`) under 2.0.0. Review and re-issue it; this is not evidence of
  tampering.
- AP2 resolutions, Evidence Packs and Pack verification reports keep
  `releaseVersion` `1.2.0`, the frozen format release, and Packs retained from
  1.2.0 verify unchanged.
- Artifacts from the RFC 8785 separator regression window carry 1.2.0 labels,
  as does every other build before this release; 2.0.0 and later always include
  the correction. See
  [Protocol compatibility](docs/PROTOCOL.md#separator-correction-and-historical-compatibility).
- OpenAPI `info.version` now tracks the package release and reads `2.0.0`.

### Added

- `docs/CLI.md`, a CLI reference covering every command's input shape, output
  and exit codes, the input limits, the `review` input and verdicts, and the
  `serve` loopback, Host and Origin rules, store lock and signal behavior. A
  test fails when a command, action, scenario, exit code or limit drifts from it.
- CLI `--help` now lists each subcommand family's `actions` (`casepack`,
  `policy`, `ap2-dispute` and the 23 `operator` actions), the `simulate`
  `scenarios`, and `exitCodes` with a one-line meaning for each code. The
  dispatcher validates against the same lists, so help cannot drift from it.
  The change is additive JSON.
- `isAppealCheckpoint` type guard for the exact `{sequence, headDigest}`
  appeal checkpoint shape, exported from the package root.
- `scripts/version.mjs` makes `package.json` the single source of the release
  version: `check` fails on drift in the lockfile, `src/version.ts`, the
  conformance declaration, OpenAPI `info.version`, the CHANGELOG and the release
  tag, and runs in `npm run verify:static`; `sync` is the npm `version`
  lifecycle hook; `notes` prints a CHANGELOG section for the GitHub Release.
  OpenAPI `info.version` now tracks the package release.
- Add a Windows Node 22.12.0 CLI, persistent-store and installed-package gate,
  including command shims in a path with spaces and explicit symlink skips.
- Exercise the actual packed tarball in a fresh production-only consumer during
  `package:check`: public exports, both binaries, signed source import, CasePack
  readiness, failure diagnostics, and byte-identical offline replay.
- Ship a public-export integration example and handoff guide with separate caller
  anchors; missing or tampered source evidence withholds native policy evaluation.
- Add stateless native decision preview and metadata-only raw-evidence inventory.
- Prioritize case review queues and export formula-neutralized CSV task rows.
- Compare individual coverage requirements, envelope eligibility, finding counts
  and caller-supplied anchor context without upgrading assurance.
- Create deterministic assessment receipts and recheck them against independently
  retained digests, preserving invalid results and exposing changed inputs.
- New `review` CLI command binds external source evidence to a deterministic review record, declared as the supported `external_evidence_review_v1` capability in the conformance statement. It digest-binds caller-supplied evidence bytes to anchors, extracts the source action identity and receipt outcome, cross-checks caller-asserted upstream verification, and reports `recorded`, `conflicting`, or `unsupported` verdicts with stable exit codes. Source truth stays unknown, legal effect stays not determined, and no rail signatures are re-verified here: upstream validity remains a caller assertion over separately supplied trust inputs.

### Changed

- CI runs the full test suite on Windows instead of four files, adds Node
  26.11.1 to the static and coverage matrices, and the coverage gate now
  includes the CLI module. The `@types/node` development dependency follows the
  Node 22.12 support floor, and Dependabot no longer proposes its major updates.
- AP2 dispute resolutions, Evidence Packs and Pack verification reports now
  carry `AP2_DISPUTE_FORMAT_RELEASE` (frozen at `1.2.0`, exported from the
  package root) as their `releaseVersion` instead of the package release, so a
  package release no longer invalidates retained Packs or the `schemas/v1.2`
  constants. Resolution, Pack and verification bytes are unchanged; the HTML
  timeline now labels the value "Pack format" instead of "MandateBound". CLI
  `--version` and `--help` add `protocolVersion` and `ap2PackFormatRelease`;
  `version` remains the protocol alias. The version layers are recorded in
  [ADR 0003](docs/adr/0003-version-layers.md).
- **Breaking (CLI only):** `decide` and `preview` now apply the reference API's
  complete-case boundary before the engine runs or a store opens. An incomplete
  case exits 3 with `ALB_EXTERNAL_PINS_REQUIRED` or `ALB_EVALUATION_SHAPE`
  instead of printing, and for `decide` persisting, a fabricated
  `malformed-case` decision with exit 0. The API boundary and its messages are
  unchanged. `examples/README.md` no longer tells users to `decide` a saved
  bundle; a bundle belongs to `verify`.
- Preserve 1.2.0 release pins, native engine/protocol bytes and historical AP2 packs.
- Public `EvaluationAnchors` now matches `evaluateBundle`: nested `pins`, optional `trustRootJwk`, and optional `expectedBundleRootDigest`. The previous flattened `BundlePins` shape was never accepted at runtime. `EngineEvaluationAnchors` remains an alias.
- `PlatformEngine.explainDecision` is typed as returning a string, matching `explainDecision`.
- CLI `--help` now lists commands and the JSON input convention. Unknown commands, a missing bundle path on an interactive terminal, and empty evidence documents fail with actionable usage or input errors instead of a generic parse failure.
- CLI, API, and `parseAndValidateArtifact` JSON parse failures now keep their diagnostic code and include the UTF-16 parse offset. JsonlStore names the failing record line and preserves the exception cause. API logger events include the bounded detail.
- Evidence-bundle verification now rejects duplicate signed-artifact identifiers, duplicate runtime-event sequences, extra case-index keys, decorated or oversized path lists, and non-protocol media types or classifications even when Merkle metadata is otherwise self-consistent.
- CLI, API, and JsonlStore JSON parsers now honor the configured document-size cap for string values instead of silently applying the 256 KiB strict-JSON default. `DEFAULT_API_LIMITS` and `DEFAULT_JSONL_STORE_LIMITS` are exported; API `maxJsonStringBytes` follows `maxBodyBytes` unless a tighter cap is set, and JsonlStore `maxRecordBytes` follows the file cap.
- Decision and appeal stores now bind persisted record keys to their artifact identifiers and reject divergent appeal supersessions.
- Strict JSON limit overrides now reject unknown limit names, so a misspelled parser bound fails loudly instead of silently falling back to the default budget.
- External evidence review parses caller-supplied receipt bytes with the strict JSON parser, so duplicate keys and over-nested documents can no longer be resolved differently by different readers.
- `compareCasePackStatus` now orders `missing` and `unsupported` the same way the CasePack verifier aggregates worst-status, so an exported comparison cannot contradict a report.
- External evidence review now rejects empty, malformed, or repeated upstream trusted key identifiers instead of attesting to them under `reviewDigest`.
- Reference API limit overrides now reject unknown limit names, so a misspelled request bound fails loudly instead of silently falling back to the default budget.
- Supplied raw-evidence reference count is now one shared 1,024 cap. The CasePack verifier previously accepted 1,280 references that the operator views and the CLI refused, so a case the verifier called clean threw downstream.
- AP2 imports now require delegated expiry, bound key-snapshot sizes, non-future source checkpoints, capture-window consistency, issuance-valid checkpoint keys, exact required line-item quantities, and consistent lifecycle duplicates.
- Direct policy-fact evaluation, appeal replay input, trust-snapshot cutoffs, and CLI simulation arguments now fail closed on malformed, future-issued, or ambiguous input.
- License and package checks now resolve the repository from their script location and include nested installed dependencies.
- `npm run verify` now runs `scripts/check-dependencies.mjs`, which fails closed when an installed dependency falls inside a recorded advisory window, when a manifest cannot be parsed, or when the dependency tree is absent. An `overrides` floor keeps a clean install resolved above the fast-uri advisory window.
- Transaction lifecycle correlation now orders events by the RFC 3339 instant. Offset timestamps no longer sort ahead of or behind an earlier or later instant because their strings compare that way.
- CSV exports now prefix a formula trigger that sits behind a Unicode format character, such as a zero-width space, word joiner, or Mongolian vowel separator, so quoting alone cannot hide it from a spreadsheet.
- Additive AP2 mandate verification now rejects a negative `iat`, `nbf`, or `exp`. Those instants previously counted as already valid or not in the future, unlike the v0.2.0 chain verifier.
- Merchant Checkout JWT verification now rejects a negative `iat`, `nbf`, or `exp` instead of treating a negative issuance or not-before time as already valid.
- Jsonl store open and audit now reject unknown limit names. A misspelled record or file bound previously fell back to the default budget and looked successful.
- The dependency advisory scan now follows a symlinked package directory. A vulnerable package installed only through a symlink was previously invisible, and the check reported a clear tree.
- The license scan now follows a symlinked package directory. An unapproved license installed only through a symlink was previously invisible, and the check reported that every package was approved.
- `explainDecision` now requires a schema-valid decision. A record that changes `legalEffect` away from `not-determined` was previously narrated as if that effect were the protocol result.
- `validateRulebook` now requires `issuedAt` to be a real UTC millisecond timestamp. A non-timestamp previously passed the DSL and could be compared as text during evaluation.
- External key snapshots now compare capture, validity, and evaluation instants in milliseconds. Flooring those timestamps to a second treated a key captured or expired later in that second as still current.

### Removed

- **Breaking:** Removed the remote-binding escape hatch from the API and CLI:
  the public `CreateApiServerOptions.allowRemote` option and the
  `serve --allow-remote` flag that 1.2.0 shipped no longer exist. The reference
  server now requires a loopback bind and rejects non-loopback peers, mismatched
  Host headers, and foreign Origins before routing. Migration: keep a loopback
  bind behind a reverse proxy you operate.

### Fixed

- Documentation no longer claims a 4 MiB cap for operator batches, the CLI
  overall, or operator receipt canonical input: operator actions, `casepack`
  and `case-report` read up to 17 MiB (depth 48, 250,000 nodes) and receipt
  canonical input is bounded to 16 MiB. The repository issue chooser now offers
  only the forms that carry the synthetic-data warning.
- The metadata-only AP2 evidence timeline HTML now uses column header scopes, a
  caption and a keyboard-focusable scroll region, and its Content Security
  Policy adds `base-uri 'none'` and `form-action 'none'`, matching the case
  report. Escaping and raw-token omission are unchanged.
- `npm run conformance` and the published `fixtureTests` now include the
  external evidence review fixtures behind the supported
  `external_evidence_review_v1` capability. The published declaration also lists
  every capability with its status, and a test fails when that list, the fixture
  list or the npm script drift from the runtime statement.
- The license check now fails closed when `node_modules` is missing or holds no
  package manifests, matching the dependency advisory check. It previously
  reported that 0 installed packages used approved licenses and exited 0.
- CLI `replay` accepts only a bare events array or exactly
  `{events, checkpoint?}`, and rejects a checkpoint that is not
  `{sequence, headDigest}` with exit 3 and a fixed message. A malformed
  checkpoint was previously reported as a history mismatch (exit 5) and echoed
  back verbatim. CLI `appeal` rejects any key beside `{event, decision?}`, so a
  misspelled `decision` is no longer silently dropped. The library's
  `replayAppealEvents` semantics are unchanged.
- `serve --host` is validated before the store is opened: anything but a
  loopback IP literal such as `127.0.0.1` or `::1` exits 2 with a usage message
  that names the accepted form, instead of exit 3 "Protocol artifact is invalid"
  after the store was already locked. An invalid `--port` is also rejected
  before the store opens.
- A busy, unbindable or forbidden `serve` port now exits 6 with
  `ALB_SERVE_UNAVAILABLE` instead of exit 70 (internal error).
- An unknown `simulate` scenario still exits 3 with `ALB_SCENARIO_UNKNOWN`, but
  the message now lists every valid scenario instead of "Artifact validation
  failed."
- `serve` now closes its server and store on SIGINT or SIGTERM, removing the
  JSONL writer lock and exiting 130 or 143. Ctrl+C previously left a stale
  `.lock` file that blocked every later writer.
- A held store lock now exits 6 (unavailable) with `ALB_STORE_LOCKED` and a
  path-free hint about stale `.lock` files, instead of exit 5 with a message
  blaming a state conflict.
- `operator compare` now exits 3 with `ok: false` when the current assessment is
  invalid and no regression is found. It read only the `afterValid` field of the
  targeted comparisons, so a pair of equally tampered revisions exited 0.
- Restore RFC 8785 UTF-8 serialization of U+2028 and U+2029 in values and keys.
  Independent byte and signature checks reject the regressed escaped form.
  Existing affected artifacts require the explicit historical-replay and
  reissuance handling in [Protocol compatibility](docs/PROTOCOL.md#separator-correction-and-historical-compatibility).
- Fix npm-installed `mandatebound` and `alb` commands silently exiting through bin
  symlinks. Resolve entrypoint paths while keeping SDK imports inert.

### Security

- The release workflow verifies and packs in a read-only job and attests and
  uploads in a separate job that installs nothing and runs no repository code,
  so OIDC and attestation write scopes no longer reach npm, TypeScript or the
  tests. It checks every version surface against the release tag, re-checks
  the files against SHA-256 checksums before attesting them, and no longer
  configures an npm registry for a publish that never happens. The package
  check now rejects packed files that contain a PEM private-key block.
  `SECURITY.md` lists the release controls that actually run, replacing a
  claimed Git-tree secret scan that no automation performed.
- Raise the `fast-uri` override and lock to 3.1.8 or later for
  [GHSA-hrr3-gc8f-f4qj](https://github.com/fastify/fast-uri/security/advisories/GHSA-hrr3-gc8f-f4qj),
  and add the published affected window to the existing dependency checker.
- Upgraded the transitive `fast-uri` dependency out of the 3.0.0 to 3.1.5 URI parsing advisory window (GHSA-5jgf-p345-68v8, GHSA-7p8r-x3mc-p8w7, GHSA-f65p-4m7j-42xc, GHSA-fph4-wmhf-6fwf, GHSA-jqff-g426-hqxp), which covers host confusion and server-side request forgery through URI normalization.
- Detached proof verification now requires canonical protected-header bytes, report rendering escapes every table value, and appeal replay rejects repeated genesis events.

## [1.2.0] - 2026-07-26

### Added

- Added a deterministic AP2 v0.2.0 Evidence Pack and dispute evidence resolver pinned to upstream commit `b4587ac1d055888a73b4b21750973cffba961793`.
- Added protocol-neutral, caller-supplied retrieval adapters plus an offline materialized-source assembler.
- Added exact four-artifact selection for Checkout Mandate, Checkout Receipt, Payment Mandate, and Payment Receipt evidence.
- Added strict direct and Delegate SD-JWT chain verification, terminal closed-Mandate Receipt references, required `checkout.line_items` and `payment.reference` constraints, and closed Payment schema checks.
- Bound `checkout.allowed_merchants` to the merchant in the signed Checkout JWT, with any caller expected-merchant value treated only as an additional pin.
- Added bounded merchant Checkout JWT schema and signature verification, cross-artifact transaction binding, AP2 Receipt JWT verification, and exact Receipt-reference checks.
- Added duplicate-source deduplication and fail-closed conflict detection without last-response-wins behavior.
- Added `MandateBoundAp2DisputeEvidenceResolution/v1`, its JSON Schema, content digest, integrity gates, coverage, retrieval attempts, and bounded issue codes.
- Added sensitive `MandateBoundAp2EvidencePack/v1`, independently retained digest anchored Pack verification, exact Checkout-version binding, imported reported-revocation snapshots, and metadata-only deterministic HTML timelines that recompute verification.
- Restricted Pack verification plans to closed public EC JWK shapes so private, symmetric, and unrelated key members fail before serialization.
- Added schemas for the Evidence Pack and Pack-verification report.
- Added the `@oonyl/mandatebound/ap2-dispute` package export and `mandatebound ap2-dispute resolve|pack|verify|render` CLI commands.
- Added official AP2 v0.2.0 SDK-generated frozen vectors plus adversarial fixtures for missing, stale, future-captured, oversized, malformed, mutated, mismatched, conflicting, forged, empty, and failed retrieval cases.
- Added the v1.2 boundary guide in [`docs/V1_2.md`](docs/V1_2.md) and the design decision in [ADR 0002](docs/adr/0002-ap2-dispute-resolver-boundary.md).

### Compatibility

- Preserved native v1 schemas, bundle roots, rulebooks, decision bytes, protocol version `1.0.0`, and engine version `1.0.0`.
- Preserved v1.1 CasePack and UCP/AP2 evidence-import APIs.
- Kept every resolver output non-binding with `disputeOutcome: "not-determined"` and `legalEffect: "not-determined"`.

### Scope

- The positive `evidence_verified` result establishes only integrity under the named profile. It does not decide a claim, refund, chargeback, fraud allegation, liability, causation, damages, settlement, or legal right.
- Retrieval authentication, authorization, endpoints, transport security, privacy, and retention remain caller responsibilities.
- Revocation snapshots are imported reports, not authenticated revocation facts. The library performs no revocation-service lookup.
- Evidence Packs contain raw sensitive artifacts. Resolution and timeline outputs omit them.
- Positive Pack verification requires an expected Pack digest retained outside the Pack; timeline renderers do not trust supplied verification reports.
- Complete upstream history and general AP2 conformance remain unestablished.

## [1.1.0] - 2026-07-23

### Added

- Added the exact `UCP 2026-04-08 REST + AP2 Mandates Extension / AP2 v0.2.0 evidence-import profile`.
- Added checkout-to-order/refund lifecycle capture, including returns, cancellations, and price adjustments, for evidence supplied to the importer.
- Added source-representation preservation for signed UCP HTTP evidence and compact AP2 material where upstream verification depends on exact bytes.
- Added `DelegationContext` to bind principal, delegate, mandate, scope, validity window, and evidence references while keeping legal effect not determined.
- Added `ExternalTrustSnapshot` for discovery material and source-checkpoint keys, with automatic native-trust promotion forbidden.
- Added separate `upstreamValid` and `evidenceEligible` results so a source-valid artifact is not promoted automatically into local policy evidence.
- Added evidence-readiness reporting for `satisfied`, `missing`, `conflicting`, `unsupported`, `unknown`, and `not_applicable` requirements.
- Added the outer `CasePack` for source evidence, lifecycle state, readiness, external trust, delegation context, replay pins, and the preserved native v1 evidence bundle.
- Added source checkpoints and policy-relative evidence-coverage contracts while keeping global completeness not established.
- Added policy-pack validation, fixture testing, and deterministic rulebook change-impact reporting.
- Added a versioned conformance statement and a narrow exact-profile fixture command.
- Added `mandatebound casepack build|verify|unpack|diff`, `mandatebound policy validate|test|diff`, `mandatebound case-report --format json|html`, and `mandatebound conformance`.
- Added a strict `{casePack, anchors}` CLI boundary for CasePack verification, unpacking, and reporting, with raw evidence encoded as `{referenceId, bytesBase64}`.
- Added deterministic offline case replay under identical source, trust, policy, schema, rulebook, time, and engine pins.
- Added the v1.1 profile and boundary guide in [`docs/V1_1.md`](docs/V1_1.md).

### Compatibility

- Preserved native v1 artifact, rulebook, decision, and `.albx.json` bundle semantics.
- Kept the native v1 bundle independently verifiable inside a v1.1 `CasePack`.
- Kept all policy outputs non-binding with `legalEffect: "not-determined"`.

### Scope

- The new interoperability claim is limited to the named evidence-import profile. It is not a generic UCP or AP2 compliance claim.
- Multi-party dollar waterfalls and contribution percentages remain unsupported.
- UCP over A2A and MCP remains deferred. Visa Trusted Agent Protocol and x402 adapters remain unsupported.
- Automated dispute submission and a hosted production service remain unsupported.

## [1.0.0] - 2026-07-23

- Added normative v1 evidence schemas.
- Added strict parsing, canonicalization, content addressing, Ed25519 proof verification, and pinned trust snapshots.
- Added deterministic principal, operator, model-vendor, and unresolved policy outcomes.
- Added portable evidence bundles and offline verification.
- Added immutable decisions and append-only appeals.
- Added CLI, localhost API, simulator, OpenAPI contract, and synthetic test suite.
- Added security, privacy, interoperability, governance, and legal-boundary documentation.

[Unreleased]: https://github.com/EauDoon/mandatebound/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/EauDoon/mandatebound/compare/v1.2.0...v2.0.0
[1.2.0]: https://github.com/EauDoon/mandatebound/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/EauDoon/mandatebound/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/EauDoon/mandatebound/tree/v1.0.0
