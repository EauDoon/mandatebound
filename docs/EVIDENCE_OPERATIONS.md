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
