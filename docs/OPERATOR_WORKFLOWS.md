# Local operator workflows

These workflows turn verifier output into review tasks and portable reports. They do not change native decisions, establish source truth, determine legal liability, or authorize payments. No command fetches evidence, contacts a provider, or enables remote service access.

## Assess one case

`mandatebound preview --input evaluation.json` uses the same native evaluation
input and engine as `decide`, but never opens or writes a store. It rejects
`--store`. An unresolved result remains a successful evaluation with
`legalEffect: "not-determined"`; preview neither approves nor executes a transaction.

Use the same `{casePack, anchors}` JSON input accepted by `case-report`. Keep coverage policy and contract digests in an independently trusted case record. Encode optional `anchors.rawEvidence` entries as `{referenceId, bytesBase64}` using canonical standard base64.

```bash
mandatebound operator triage --input case-invocation.json
mandatebound operator checklist --input case-invocation.json
mandatebound case-report --input case-invocation.json --format markdown
mandatebound case-report --input case-invocation.json --format csv
mandatebound case-report --input case-invocation.json --format html
```

Triage prioritizes conflicting assurance dimensions. The checklist includes every declared coverage requirement, its observed envelope count, and an action for review. A missing raw-evidence input can leave integrity unknown even when the declared coverage counts are satisfied. Read assurance tasks alongside coverage rows.

Reports contain metadata and verifier findings, not raw evidence. Treat identifiers and finding metadata as potentially sensitive. HTML is a static offline document with section navigation, keyboard-accessible tables, a review summary, and print styles. Markdown escapes active markup. CSV quotes every cell and prefixes spreadsheet formula-like content with an apostrophe. CSV is a presentation export, not an artifact to re-import for verification.

When no coverage requirements are reported, CSV still contains one metadata row with the case identifier, assessment time, verification result, and assurance boundaries. Its requirement, status, and matched-envelope cells are empty. An invalid empty report therefore remains visibly invalid in the exported file.

## Assess a queue

`operator inventory` accepts the same case invocation and lists each protocol
envelope's declared raw reference, expected digest/length and supplied-byte match.
It lists other supplied reference IDs separately; these may belong to external
trust material. It does not fetch missing bytes or expose raw bodies/reference
locations. Invalid CasePack shapes yield no claimed inventory. Duplicate or
malformed supplied raw references fail instead of selecting one copy.

`operator batch` accepts `{cases: [{id, casePack, anchors}]}`. Each case carries separate anchors. IDs must be unique ASCII identifiers, at most 128 characters. Batches contain 1 to 100 cases and share the CLI's 4 MiB document cap. Split larger queues into smaller files.

```bash
mandatebound operator batch --input queue.json
```

The output preserves input order, returns each report, and counts verified cases and cases needing review. Invalid evidence remains visible and makes the batch exit with code 3. The batch does not evaluate liability or write decisions.

`operator queue` consumes the same bounded batch and prioritizes conflicts first,
then other review cases, then cases with no review tasks. ASCII ID order breaks
ties deterministically. Each row retains its digest, assessment time, assurance
tasks and unmet coverage requirements. Invalid cases remain visible and exit 3.
Priority is a work-order suggestion, never a probability or liability ranking.

`operator queue --format csv` exports one row per assurance/coverage task, or a
summary row for a case with no tasks. Each row carries its case digest, assessment
time, validity and nonbinding boundary. It uses the existing formula-neutralized
CSV cells. Redirection is controlled by the caller; the command writes no files.

## Detect assurance regressions

`operator compare` accepts `{before: {casePack, anchors}, after: {casePack, anchors}}`. It re-verifies both inputs. Comparison requires the same case identifier and coverage policy and contract anchors; unrelated or repinned cases are noncomparable. Assessment times may differ and are shown explicitly.

```bash
mandatebound operator compare --input comparison.json
```

A lost satisfied assurance status or a previously valid case becoming invalid is flagged as a regression. This is a comparison of verifier assurance dimensions, not proof that facts improved or worsened. A change between two unresolved dimensions remains a change without an ordinal confidence score. Use `casepack diff` to inspect artifact-level additions, removals, and modifications.

## Audit a persisted snapshot

`operator coverage-diff` accepts the same `{before, after}` invocations and
compares individual requirement statuses and matched-envelope counts. It requires
the same case ID and coverage anchors; noncomparable inputs exit 3. Losing a
previously satisfied requirement exits 5, even if the aggregate coverage status
was already unresolved. Other changes are reported without a confidence score.
Both assessment times and overall verification results remain visible.

`operator envelope-diff` uses that same comparison input and boundary to show
added, removed or changed per-envelope integrity, upstream validity and evidence
eligibility. Loss of eligible evidence or satisfied integrity exits 5. This helps
locate individual failures that an already unresolved aggregate status can hide.
It compares verifier results; use `casepack diff` for committed artifact bytes.

`operator finding-diff` compares verifier code/path pairs and their occurrence
counts under the same case and coverage anchors. Repeated findings remain counted;
new occurrences set the review-regression flag and exit 5. Disappearing findings
are not proof of closure or truth. The result excludes evidence bodies and finding
message text. Noncomparable cases exit 3 and never claim findings were resolved.

Provide an existing JSONL file and a JSON input containing `{}` or `{checkpoint: {sequence, headHash}}`. Retain checkpoints independently before an incident. Deriving an anchor from the file currently under investigation cannot establish that historical records were never removed.

```bash
mandatebound operator audit --store snapshot.jsonl --input checkpoint.json
```

Audit opens the existing file read-only. It neither creates a store nor takes a writer lock, repairs records, or appends data. It checks strict JSON, artifact bindings, hash chain, appeal transitions, and optional checkpoint completeness. Missing files fail without creating anything. Detected concurrent changes fail; use a stable snapshot for repeatable results. A file size and modification-time check cannot guarantee atomic reads against a hostile concurrent writer.

Without a checkpoint, completeness is `unproven` even when the local chain is valid. A matching independent checkpoint establishes completeness only relative to that checkpoint. Defaults are 32 MiB, 100,000 records, and 1 MiB per record. The SDK accepts tighter limits. Empty stores are locally valid but have no checkpoint head.

## Exit codes and SDK

| Workflow result | Exit code |
| --- | --- |
| Verified assessment, valid audit, or comparable assessment without regression | 0 |
| Invalid usage or unsupported option | 2 |
| Invalid evidence, input, or noncomparable assessment | 3 |
| Comparable assurance regression | 5 |
| Snapshot cannot be opened | 6 |

An unresolved native policy decision remains a successful evaluation. These operator exit codes report evidence verification, not a change to the existing `decide` contract.

The root package exports `triageCase`, `createEvidenceChecklist`, `assessCases`, `compareCaseAssessments`, and `auditJsonlStore`. The report entry point also exports `renderCaseReportMarkdown` and `renderCaseCoverageCsv`. SDK assessment anchors contain raw `Uint8Array` bytes; base64 conversion applies only to the JSON CLI boundary. Report renderers accept derived reports as presentation data; re-verify the source CasePack before relying on their contents.

Run the self-cleaning persistence demonstration from a source checkout:

```bash
npm run build
node examples/operator-workflow.mjs
```

It stores a synthetic unresolved decision, checks an unanchored and demonstration-anchored snapshot, prints bounded metadata, and removes its temporary directory.
