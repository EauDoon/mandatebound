# Evidence operations

These additive SDK and `operator` commands reverify the supplied CasePack with its
caller-owned anchors. They preserve failed assessments, expose metadata only, and
never retrieve evidence, write a store, establish source truth, or decide legal
effect. Version 1.2.0, artifact bytes and policy semantics remain unchanged.

## Collection plan

`mandatebound operator collect --input invocation.json` accepts the same exact
`{casePack, anchors}` document as `casepack verify`. The SDK exports
`planCaseCollection`. Protocol, discovery and delegation references are grouped by
reference ID, with every consumer retained. Status is `missing`, `mismatched`,
`conflicting` (incompatible expected hashes or lengths), or `supplied`.
Delegation references do not declare a byte length. No reference locations or raw
bodies are emitted. Matching bytes do not establish their provenance. Resolve
conflicting descriptors before collecting replacements. Exit 0 means the existing
CasePack verifier passed, 3 means it did not; `needsCollection` is a separate
collection-work flag, including ancillary references the verifier does not require.

## Source collection coverage

`operator sources` (`summarizeCaseSources`) uses a case invocation and retains
every source declared by the coverage contract, even when no envelope was supplied.
It separates received envelope count from verifier-eligible count, and lists each
requirement's actual verifier status, matched count and declared minimum. Use this
view to direct collection to the missing source; counts are not completeness scores.

## Capture chronology

`operator timeline` (`createCaseCaptureTimeline`) orders protocol envelopes by
capture instant, then ASCII envelope ID for ties. Each row retains its verifier
eligibility and integrity, and flags a capture after the explicit assessment time.
Use it to investigate timing gaps without exposing payloads. Capture times are
source assertions, not proof of actual event order, causation, or settlement.

## Mapping lineage

`operator lineage` (`traceCaseMappings`) connects each protocol envelope's mapping
trace to its named native bundle paths, comparing expected and manifest digests.
It includes the mapper version and policy digest for reproducible investigation,
and lists native entries with no mapping reference. Unreferenced entries are not
automatically defects. Matching links do not prove the mapper's interpretation is
correct; eligibility remains the verifier's result. Artifact bodies are omitted.

## Checkpoint review

`operator checkpoints` (`inspectCaseCheckpoints`) lists checkpoint sequence bounds,
declared gaps, predecessor digests, proof counts and the envelopes that reference
each checkpoint. References to an absent checkpoint remain visible separately.
This helps reviewers find a broken capture chain without printing proofs or raw
evidence. A listed reference or nonzero proof count is not an inclusion-verification
result. Even authenticated bounded inclusion cannot establish global completeness.

## Validity windows

`operator windows` (`inspectCaseValidityWindows`) shows coverage, delegation,
external discovery and checkpoint-key windows, sorted by expiry. It compares each
window to the caller's explicit `asOf`, never the machine clock. Starts are inclusive,
ends exclusive. States are `not_yet_valid`, `within_window`, `expired`, or `unknown`
for an unusable assessment instant. Remaining seconds are clamped to zero after
expiry. Window membership grants no authority and does not validate a key or proof.

## Reused content

`operator reuse` (`findCaseContentReuse`) groups protocol envelopes that declare the
same raw-evidence digest under distinct references. It retains each expected size,
source, reference, and supplied-byte match result. Use this to recognize duplicated
material during review. Shared hashes do not establish independent corroboration,
fraud, or truth; missing bytes remain missing and no evidence is deduplicated away.

## Cross-case collection bottlenecks

`operator bottlenecks` (`findBatchCollectionBottlenecks`) accepts `{cases}` with
1 to 100 unique named `{id, casePack, anchors}` entries, like `operator batch`.
It groups unmet requirements by source ID and event class, retaining each case,
requirement status, count and coverage-contract digest. Every case remains listed;
structurally rejected packs also appear under `unassessableCaseIds`. Source names
are caller-scoped labels, not authenticated cross-case identities. Grouping work
does not combine policies or establish evidence completeness.
