# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the package
release follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

The package release is one version layer among several. The protocol, engine,
schema-directory and AP2 Pack format versions move separately and are described
in [Protocol v1](docs/PROTOCOL.md).

## [Unreleased]

### Upgrading from 2.0.0

Protocol `1.0.0`, engine `1.0.0`, the AP2 Pack format `1.2.0`, the
`schemas/v1.2` documents, the dispute profile and every Pack digest are
unchanged. Pack verification re-derives the resolution under the current gates,
so a retained Pack's verdict moves only where the gates below changed, and its
`digestValid` and `anchorMatched` stay true. `verifyAp2MandateChain` from
`@oonyl/mandatebound/ucp-ap2`, which the resolver runs on each Mandate chain,
changes in the same cases: its `upstreamValid` and issues move as described
below for direct callers too.

- AP2 evidence whose open Mandate withholds a constraint disclosure now resolves
  `unresolved` with `AP2_CONSTRAINT_DISCLOSURE_WITHHELD` where it used to
  resolve `evidence_verified`. So does evidence whose issuer placed an RFC 9901
  decoy digest in a constraint list, a constraint entry or a line-item
  requirement list, because a decoy cannot be told apart from a withheld
  disclosure. That includes honest evidence redacted with the
  official SDK's `MandateClient.present(claims_to_disclose=...)`, which drops
  every acceptable-item disclosure of a `checkout.line_items` constraint; the
  pinned AP2 rules match line items only against the revealed acceptable items,
  so such evidence never established the constraint. Present the open Mandate
  with its constraint disclosures, as the SDK's default presentation does.
  Packs whose Mandates reveal their constraints produce byte-identical
  verification reports.
- AP2 evidence whose open Payment Mandate carries `payment.amount_range`,
  `payment.allowed_payees`, `payment.allowed_payment_instruments` or
  `payment.allowed_pisps` used to resolve `unresolved` with
  `AP2_CONSTRAINT_UNSUPPORTED`. It now resolves `evidence_verified` when the
  closed Payment Mandate satisfies them, or `unresolved` with a precise
  `AP2_CONSTRAINT_FAILED` or `AP2_CONSTRAINT_INVALID` when it does not. Payees
  match by `id` only, so evidence an SDK verifier accepts through its
  name-and-website fallback stays `unresolved` here. `payment.budget`,
  `payment.agent_recurrence` and `payment.execution_date` keep their code and
  message.

### Added

- The AP2 v0.2.0 dispute resolver evaluates the open Payment Mandate
  constraints the pinned reference shopping agent emits:
  `payment.amount_range` (same currency, inclusive integer minor-unit bounds),
  `payment.allowed_payees` and `payment.allowed_payment_instruments` (the
  closed `payee.id` or `payment_instrument.id` equals a revealed allowed `id`)
  and `payment.allowed_pisps` (all three PISP names equal one allowed entry).
  The agent builds every open Payment Mandate as `[payment.amount_range,
  payment.allowed_payees, payment.reference]`, so each of its
  human-not-present payment chains resolved `unresolved`, and a purchase that
  broke the user's cap looked the same as one that respected it.
  `AP2_DISPUTE_CONSTRAINT_SUPPORT` from `@oonyl/mandatebound/ap2-dispute` lists
  the evaluated and the still fail-closed types, and the conformance
  declaration publishes them as the optional
  `disputeProfile.evaluatedConstraints` and
  `disputeProfile.failClosedConstraints`.
- `ap2-dispute batch` and `verifyAp2DisputeEvidencePacks` re-verify up to 100
  retained AP2 Evidence Packs at once, each against its own independently
  retained digest, and flag every Pack whose status differs from the
  `previousStatus` the caller recorded. Package upgrades change verdicts for
  retained Packs, as 2.0.0 did for delegated `exp` and this release does again,
  and Packs could only be checked one at a time. The
  `MandateBoundAp2EvidencePackBatch/v1` output reports each Pack's status,
  anchor and digest fields, sorted issue codes and full verification report in
  input order, with summary counts and a `batchDigest`. It exits 3 for a
  malformed batch or Pack, 5 when any Pack is unresolved or changed, and 0
  otherwise.
- `ap2-dispute reconcile` and `reconcileAp2DisputeEvidencePack` compare the
  closed Payment Mandate's payee, currency and amount with the merchant-signed
  Checkout it is bound to. The resolver binds the two only through
  `transaction_id`, so a payment of 999999 against a signed Checkout total of
  2500, in another currency, or to another payee resolved `evidence_verified`
  and nothing in the resolution, the Pack verification or the timeline showed
  the difference. The `MandateBoundAp2PaymentReconciliation/v1` output carries
  only `matched`, `mismatched` or `not_comparable` per check, never amounts or
  identifiers, and reads only claims verified inside an anchored,
  `evidence_verified` Pack. It is a review signal: it never changes the
  resolution or `verify`.
- `ap2-dispute render --format markdown|csv`, with
  `renderAp2EvidenceTimelineMarkdown` and `renderAp2EvidenceTimelineCsv`, export
  the metadata-only AP2 evidence timeline for tickets and spreadsheets, as
  `case-report` already does for CasePacks. Like the HTML rendering, both verify
  the Pack against the retained digest themselves. The Markdown uses the
  CasePack report escaper, and the CSV quotes every cell, neutralizes formulas
  and ends lines with CRLF. JSON and HTML output are unchanged.

### Changed

- The AP2 dispute module now shares the UCP/AP2 RFC 3339 timestamp guard
  instead of carrying a second copy of the same grammar, calendar bounds and
  instant parse. The accepted values, the parsed instants and the
  dispute-facing error type and message are unchanged.
- Own-property checks use the platform `Object.hasOwn`, and the memory store
  calls `structuredClone` directly. Behavior is unchanged.

### Fixed

- `assembleAp2DisputeEvidence`, `resolveAp2DisputeEvidence` and
  `packAp2DisputeEvidence`, and with them `ap2-dispute pack`, reject an `asOf`
  or `createdAt` that is not a string. A one-element array such as
  `["2026-07-23T00:00:00.000Z"]` stringified to a valid timestamp and was copied
  into the output, so `ap2-dispute pack` exited 0 and printed a Pack that the
  published Pack schema and `ap2-dispute verify` both reject as malformed.
  String timestamps, retained Packs and their digests are unaffected.
- Canonical JSON now enforces its UTF-8 byte budget during serialization, rather
  than after allocating the complete output. Repeated shared values cannot
  expand a small input into an unbounded intermediate string before rejection;
  accepted canonical bytes and digest values remain unchanged.

### Security

- The AP2 v0.2.0 dispute resolver no longer lets withheld SD-JWT disclosures
  widen an open Mandate's constraints. The chain verifier silently dropped every
  `{"...": digest}` array placeholder and `_sd` digest whose disclosure the
  presenting agent left out, and the agent chooses that before it signs the
  terminal hop. Withholding every acceptable item of a `checkout.line_items`
  requirement turned it into a wildcard that any SKU satisfied, and withholding
  a whole constraint entry, or one requirement of a line-item constraint, meant
  it was never evaluated. Each case reported `evidence_verified` for a purchase
  outside the user's mandate. They now fail closed with
  `AP2_CONSTRAINT_DISCLOSURE_WITHHELD`, as does a constraint entry that hides
  one of its own fields, such as the optional `min` of the newly evaluated
  `payment.amount_range`. A partial reveal is evaluated against what it reveals,
  an issuer-signed literal empty `acceptable_items` keeps its any-item meaning,
  and undisclosed alternative `delegate_payload` elements stay legitimate. The
  defect was present in 1.2.0 and 2.0.0. `verifyAp2MandateChain` from
  `@oonyl/mandatebound/ucp-ap2` carries the same fix; the v1.1
  `verifyAp2Mandate` adapter and the native engine are unaffected. Undisclosed
  `_sd` digests elsewhere in an open Mandate payload, which could hide a pre-set
  payee, amount or payment instrument from the inheritance check, remain a
  documented residual risk.
- Raise the `fast-uri` override and lock to 3.1.9 or later, and record the
  advisories published on 2026-10-23 in the dependency gate:
  [GHSA-w74x-v6f9-j3xg](https://github.com/advisories/GHSA-w74x-v6f9-j3xg),
  [GHSA-xhq7-xmqj-769h](https://github.com/advisories/GHSA-xhq7-xmqj-769h) and
  [GHSA-333x-w4r6-6crp](https://github.com/advisories/GHSA-333x-w4r6-6crp)
  affect 3.0.0 to 3.1.8, and
  [GHSA-wjr9-j795-jxcr](https://github.com/advisories/GHSA-wjr9-j795-jxcr)
  affects 3.1.3 to 3.1.8. The gate passed the locked 3.1.8 because it did not
  know them, while `npm audit` reported the lockfile as vulnerable.

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
  `releaseVersion` `1.2.0`, the frozen format release, so a Pack retained from
  1.2.0 keeps its format label and Pack digest and still matches its retained
  anchor. Pack verification re-derives the resolution from the embedded
  evidence under the current gates, though, and delegated Mandate payloads
  require `exp` since this release. A 1.2.0 Pack whose delegated Mandate
  payload has no `exp` now verifies as `unresolved` with
  `AP2_PACK_RESOLUTION_UNRESOLVED`, while `digestValid` and `anchorMatched`
  stay true. That reflects the stricter gate, not tampering.
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
  package release label on its own no longer invalidates retained Packs or the
  `schemas/v1.2` constants. Resolution, Pack and verification bytes are
  unchanged; the HTML timeline now labels the value "Pack format" instead of
  "MandateBound". CLI
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
