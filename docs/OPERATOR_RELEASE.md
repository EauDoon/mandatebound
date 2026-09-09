# Local review and assessment receipt release

This additive release connects evidence inventory, review queues, targeted revision
comparisons and reproducible receipts. It leaves the native engine, rulebooks,
versioned schemas, bundle roots and AP2 verification unchanged. Package and release
metadata remain 1.2.0 because that value is also pinned inside existing AP2 packs;
this operator update does not silently migrate historical artifacts.

| Command | Input and result |
| --- | --- |
| `preview` | Native evaluation input; the existing nonbinding decision without store access. |
| `operator inventory` | Case invocation; protocol references and supplied-byte matches, no bodies. |
| `operator queue` | Named case batch; prioritized assurance and coverage review tasks. |
| `operator queue --format csv` | The same queue as formula-neutralized task rows, retaining ready cases. |
| `operator coverage-diff` | Before/after invocations; requirement status and envelope-count changes. |
| `operator envelope-diff` | Before/after invocations; individual eligibility and integrity changes. |
| `operator finding-diff` | Before/after invocations; verifier code/path occurrence changes. |
| `operator anchor-diff` | Before/after invocations; time, caller pins and raw-evidence digest changes. |
| `operator receipt` | Case invocation; reproducible metadata receipt, including failed assessments. |
| `operator receipt-verify` | Invocation, receipt and independently retained digest; anchored re-verification and drift. |

All JSON input remains strict and bounded. Commands do not retrieve evidence,
contact providers, submit disputes, write decisions or expand remote API access.
Comparison flags describe verifier changes, not source truth, causation or legal
liability. Matching receipts cannot authenticate their authors or establish that
reviewers were independent. Use the [operator guide](OPERATOR_WORKFLOWS.md) for
exact inputs, limits, exit codes and caller responsibilities.
