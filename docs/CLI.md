# CLI reference

The package installs two equivalent binaries, `mandatebound` and `alb`. From a
source checkout, run `npm run build` and then `node dist/cli.js`. This page
covers every command, its input shape, its output and its exit codes. Task
guides with worked examples are linked from each section.

## Input conventions

- A JSON command reads exactly one document: `--input PATH`, a single
  positional path, or stdin. `-` names stdin explicitly. Passing both a
  positional path and `--input` is a usage error.
- An interactive terminal never supplies implicit stdin: without a path the
  command exits 2 and asks for one.
- A path must name a regular file, not a symbolic link or directory, within the
  size limit below. An empty or whitespace-only document is rejected.
- Parsing is strict: UTF-8 only, no duplicate keys, no `__proto__`,
  `constructor` or `prototype` keys, at most 10,000 array items and 10,000
  object keys, and a string may use the whole document budget. A parse error
  reports its code and UTF-16 `offset`, never the offending text.
- Output is one JSON line on stdout: `{"ok": true|false, "result": ...}`, or
  `{"ok": false, "error": {"code", "message"}}` on failure. The same diagnostic
  is written to stderr as one JSON line with `"level": "error"`. Messages never
  reflect paths, input values or exception text.
- `--format json` is accepted everywhere JSON is the output. Only
  `case-report`, `ap2-dispute render` and `operator queue` offer other formats.

### Input limits

| Input | Maximum size | Maximum depth | Maximum nodes |
| --- | --- | --- | --- |
| Every JSON command not listed below | 4 MiB | 32 | 100,000 |
| `casepack`, `case-report` and every `operator` action | 17 MiB | 48 | 250,000 |
| `ap2-dispute` | 17 MiB | 32 | 100,000 |
| Canonical CasePack input bound into an operator receipt | 16 MiB | 48 | 250,000 |

The 17 MiB documents leave room for a CasePack or Pack inside its 16 MiB
canonical bound plus the surrounding JSON. External evidence for `review` is
also capped at 1 MiB of decoded bytes. `operator audit` reads a store snapshot
of at most 32 MiB, 100,000 records and 1 MiB per record.

## Native evidence and policy

### verify

Input: a native `EvidenceBundle` (`.albx.json`). Output: the bundle
verification report. Exit 0 when the bundle verifies, 3 when it does not or the
input is invalid. Verification never evaluates policy.

### decide and preview

Input: a complete evaluation case, the same object the reference API accepts at
`POST /v1/evaluations`: `caseId`, `asOf`, `pins` (`asOf`, `policyDigest`,
`trustSnapshotDigest`, `rulebookDigest`, `schemaDigests`, `engineVersion`),
`policy`, `rulebook`, `trustSnapshot`, and the `runtimeEvents`,
`priorReceipts` and `causationAttestations` arrays, plus optional object-valued
`trustRootJwk`, `mandate`, `executionReceipt`, `incidentReport`,
`evidenceBundle`, `priorDecision` and string `appealId`. No other key is
accepted.

An incomplete case exits 3 with `ALB_EXTERNAL_PINS_REQUIRED`, and an unknown key
or non-object input exits 3 with `ALB_EVALUATION_SHAPE`. Both happen before the
engine runs or a store opens. A complete case exits 0 with the decision, whatever
its outcome: `unresolved` is a successful evaluation and `legalEffect` stays
`not-determined`.

`decide` appends the decision to `--store PATH`, a JSONL store, or to a
throwaway in-memory store when no path is given. It can also exit 5 for a store
state conflict, 6 when the store is unavailable or locked (see
[Store locking](OPERATOR_WORKFLOWS.md#store-locking)), and 3 for a corrupt store
record, with the failing `line` reported. `preview` never opens a store and
rejects `--store` with exit 2.

### explain

Input: a schema-valid native decision. Output:
`{explanation, legalEffect: "not-determined"}`. Exit 0, or 3 for an invalid
decision.

### appeal

Input: an appeal event, or exactly `{event, decision?}` to seed the store with
the decision first. Any other key beside `event` exits 3. Uses `--store PATH`
like `decide`. Exit 0 with the appeal state after appending, 3 for an invalid
event or envelope, 4 when the appealed decision is not in the store, 5 for an
out-of-sequence, forked, duplicate, terminal or superseding conflict, and 6 when
the store is unavailable or locked.

### replay

Input: a bare array of appeal events, or exactly `{events, checkpoint?}`. A
checkpoint is `{sequence, headDigest}`: a safe integer of at least 1 and a
sha256 digest of the last event, retained independently. Exit 0 when the
history replays without issues, 5 for any replay issue including a checkpoint
mismatch, and 3 for an invalid envelope, event or checkpoint. A malformed
checkpoint is rejected without echoing it.

### simulate

Runs one named synthetic scenario, or every scenario with `all` (the default).
Name it positionally or with `--scenario`, not both. Scenarios: `all`,
`principal`, `operator`, `model_vendor`, `unresolved`, `expiry`, `replay`,
`tamper`, `conflict`, `appeal`. Exit 0; an unknown name exits 3 with
`ALB_SCENARIO_UNKNOWN` and the list above.

## review

Binds caller-supplied external source evidence to a deterministic
`MandateBoundExternalEvidenceReview/v1` record. Input, with exactly these keys
at every level:

```json
{
  "source": { "sourceId": "rail-1", "eventClass": "settlement" },
  "evidence": {
    "mediaType": "application/json",
    "bytesBase64": "<canonical base64 of the exact evidence bytes>",
    "digest": "sha256:<hex of those bytes>",
    "byteLength": 1234
  },
  "anchors": { "expectedDigest": "sha256:<independently retained digest>" },
  "upstream": {
    "verifier": "rail-verifier",
    "valid": true,
    "actionId": "<action id the upstream verifier reported>",
    "outcome": "<outcome the upstream verifier reported>",
    "trustedKeyIds": ["key-1"]
  }
}
```

Identifiers are 1 to 128 ASCII characters. `trustedKeyIds` must not repeat an
identifier. The decoded evidence is 1 byte to 1 MiB.

When the evidence is a JSON object, the review extracts `action.action_id` and
the `settlement_receipt` fields `action_id`, `receipt_id`, `outcome`,
`recourse_final_status`, `event_chain_head` and `action_digest`, each a
non-empty string.

| Verdict | When | Exit |
| --- | --- | --- |
| `recorded` | Bytes match both digests and the length, the receipt is bound to the action, and the action ID and outcome equal the upstream assertion | 0 |
| `conflicting` | A length or digest mismatch, a receipt bound to another action, or an action ID or outcome that differs from the upstream assertion | 5 |
| `unsupported` | A media type other than `application/json`, or evidence without the extracted fields | 3 |

Malformed input exits 3 with a message naming the failing field. `upstream.valid`
is recorded as the caller's assertion and never re-verified: no source signature
is checked here. Source truth stays unknown and `legalEffect` stays
`not-determined`.

## serve

Runs the loopback-only reference HTTP API in the foreground until it is
stopped. Options:

- `--host`: a loopback IP literal, `127.0.0.1` by default. Any other value,
  including the name `localhost`, `0.0.0.0` or `::`, exits 2 before a store
  opens. `::1` is accepted where the platform provides IPv6 loopback.
- `--port`: 0 to 65535. The default 0 picks an ephemeral port. A busy,
  unbindable or forbidden port exits 6 with `ALB_SERVE_UNAVAILABLE`.
- `--store PATH`: persist decisions and appeals to a JSONL store, which the
  server holds as its only writer. Without it the store is in memory.

Once listening it prints `{"ok": true, "result": {"status": "listening",
"host", "port"}}`. Every request must come from a loopback peer and carry
exactly one `Host` header equal to `<host>:<port>` (IPv6 in brackets, for
example `[::1]:8787`). An `Origin` header, when present, must equal
`http://<host>:<port>`. Anything else is answered with HTTP 403 before routing.
The routes and their Problem Details errors are specified in
[`openapi/openapi.json`](../openapi/openapi.json).

SIGINT (Ctrl+C) or SIGTERM closes the server and its store, removes the store
lock and exits 130 or 143. A second signal terminates at once. A store whose
lock is already held exits 6; see
[Store locking](OPERATOR_WORKFLOWS.md#store-locking) for recovering a stale
lock.

## CasePack, reports and policy

`casepack` actions: `build` (an unsealed CasePack, bare or as `{casePack}`),
`verify` and `unpack` (`{casePack, anchors}`), and `diff` (`{before, after}`,
each `{casePack, anchors}`). Exit 0 when the CasePack is built, valid, unpacked
or comparable, otherwise 3. Raw evidence in `anchors.rawEvidence` is encoded as
`{referenceId, bytesBase64}` with canonical standard base64 of at most 8 MiB of
text per entry and 1,024 entries. See [V1.1 profile](V1_1.md).

`case-report` reads `{casePack, anchors}` and renders `--format json`, `html`,
`markdown` or `csv`. Exit 0 for a valid report, 3 otherwise; the report is
printed either way.

`policy` actions: `validate` (`{policy, rulebook}`), `test`
(`{policy, rulebook, cases}`) and `diff` (`{before, after}` rulebooks). Exit 0
when valid, 3 when invalid, and 5 when `test` runs but an expectation fails.

## ap2-dispute

Actions: `resolve`, `pack`, `verify`, `render`. `resolve` reads
`{transactionId, asOf, verificationPlan, sources}`; `pack` adds `createdAt`,
`checkoutVersions` and `revocations`. `verify` and `render` read a Pack, or the
`{ok: true, result}` envelope that `pack` printed, and require an independently
retained `--expected-pack-digest`, without which they exit 2. `render` accepts
`--format json` or `html`.

Exit 0 for `evidence_verified` or `verified`, 5 for `unresolved`, and 3 for
invalid input or a Pack that is not even well formed. `pack` exits 0 or 3. See
[V1.2 profile](V1_2.md).

## operator

Actions: `triage`, `checklist`, `batch`, `compare`, `audit`, `inventory`,
`queue`, `coverage-diff`, `envelope-diff`, `finding-diff`, `anchor-diff`,
`receipt`, `receipt-verify`, `collect`, `sources`, `timeline`, `lineage`,
`checkpoints`, `windows`, `reuse`, `bottlenecks`, `findings`, `batch-diff`.

Input shapes, outputs and the per-action exit rules are in
[Operator workflows](OPERATOR_WORKFLOWS.md) and
[Evidence operations](EVIDENCE_OPERATIONS.md). In short: 0 for a valid result
without regression, 3 for invalid evidence, input or noncomparable cases, 5 for
a regression, changed context or a receipt mismatch, and 6 when an audit
snapshot cannot be opened. `audit` requires `--store`, and `receipt-verify`
requires `--expected-receipt-digest`.

## conformance, help and version

`conformance` takes no input and prints the runtime capability statement. The
published declaration for this release, which a test keeps equal to it, is
described in [the conformance README](../conformance/v2.0/README.md).

`help` (or `--help`) and `version` (or `--version`) take no input and exit 0.
Both print `name`, `version`, `protocolVersion`, `releaseVersion`,
`engineVersion` and `ap2PackFormatRelease`. `version` is kept as an alias of
`protocolVersion` for existing callers; `releaseVersion` is the package release
and `ap2PackFormatRelease` the frozen AP2 Pack format release. Help adds
`usage`, `commands` (with each subcommand family's `actions`), `input`,
`scenarios` and `exitCodes`. See [ADR 0003](adr/0003-version-layers.md) for the
version layers.

## Exit codes

| Code | Name | Meaning |
| --- | --- | --- |
| 0 | `SUCCESS` | Completed. An unresolved policy outcome is still a successful evaluation. |
| 2 | `USAGE` | Unknown command, action or option, or an invalid option value. |
| 3 | `INVALID` | Invalid input, evidence or artifact, or a noncomparable or failed verification. |
| 4 | `NOT_FOUND` | A requested stored resource does not exist. |
| 5 | `CONFLICT` | A regression, conflict, mismatch or unresolved verification that needs review. |
| 6 | `UNAVAILABLE` | Storage, a held store lock, or the requested loopback address or port is unavailable. |
| 70 | `INTERNAL` | Unexpected internal failure; the command could not be completed. |

`serve` additionally exits 130 after SIGINT and 143 after SIGTERM.
