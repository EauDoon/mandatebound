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
