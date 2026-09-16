# Worked case: a synthetic disputed purchase

> [!IMPORTANT]
> This is a synthetic reference case. It uses generated identities, ephemeral Ed25519 keys, and a fictional purchase. It demonstrates repository behavior only. It is not evidence of a real transaction, user, loss, causation, liability, or production performance.

## The review question

A shopping agent's purchase is disputed after a synthetic incident report alleges economic loss. Can a reviewer show what the recorded mandate covered, which runtime controls passed, and what the reference policy does when evidence is removed or changed?

The existing `principal` simulator scenario supplies this case. The purchase is USD 25.00 (`2500` minor units), within a one-time mandate capped at USD 100.00 (`10000` minor units).

## Input evidence

| Evidence | Synthetic record in the scenario |
| --- | --- |
| Mandate | Signed principal mandate for a `purchase` at `merchant.synthetic`, with `supplier.synthetic` as counterparty, USD scope, a USD 100.00 maximum, and one execution. |
| Runtime trail | Five signed events: `mandate_checked`, `mandate_checked` for the not-revoked control, `policy_checked`, `model_invoked`, and `execution_completed`. |
| Execution receipt | Signed operator receipt for an executed USD 25.00 purchase, with all four required controls recorded as passing. |
| Incident report | Signed principal report with the synthetic harm code `synthetic-economic-loss`, bound to the execution receipt and runtime evidence. |
| Causation | No causation attestation is supplied, so the model-vendor branch is not eligible. |
| Native bundle | A closed evidence bundle verifies with 12 of 12 entries and no issues. |

The scenario uses the existing native v1 policy and engine. A valid mandate, in-scope execution, compliant controls, and no sufficient model-vendor causation select the `principal` policy branch. `allocated` describes the policy disposition; it is not a legal allocation.

## Observed output

Run the existing SDK reproducer from a clean source checkout. The published npm package intentionally excludes `examples/`, so clone the repository before running this source-checkout-only example:

```bash
git clone https://github.com/EauDoon/mandatebound.git
cd mandatebound
npm ci --ignore-scripts
npm run build
node examples/case-study.mjs
```

The script asserts every result before printing a stable summary. Artifact IDs and cryptographic digests are omitted from the summary because the simulator intentionally generates ephemeral keys on each run.

Selected fields from the actual output in this checkout:

```json
{
  "case": {
    "scenario": "principal",
    "caseId": "case-synthetic",
    "purchase": { "asset": "USD", "minorUnits": "2500" },
    "bundleVerification": { "valid": true, "verifiedEntries": 12, "totalEntries": 12, "issues": [] }
  },
  "result": {
    "outcome": "principal",
    "disposition": "allocated",
    "reasonCodes": ["inside_mandate_without_vendor_causation"],
    "missingEvidence": [],
    "rejectedEvidence": [],
    "legalEffect": "not-determined"
  },
  "variants": [
    {
      "scenario": "unresolved",
      "result": {
        "outcome": "unresolved",
        "disposition": "indeterminate",
        "reasonCodes": ["missing_required_evidence", "evidence_missing"],
        "missingEvidence": ["execution_receipt", "incident_report", "mandate"],
        "legalEffect": "not-determined"
      }
    },
    {
      "scenario": "tamper",
      "result": {
        "outcome": "unresolved",
        "disposition": "invalid",
        "reasonCodes": ["invalid_evidence", "evidence_rejected"],
        "rejectedEvidence": ["evidence_bundle_invalid", "execution_receipt_digest_invalid"],
        "legalEffect": "not-determined"
      },
      "bundleVerification": {
        "valid": false,
        "issues": ["ALB_SCHEMA_INVALID", "ALB_DIGEST_MISMATCH"]
      }
    }
  ]
}
```

The missing variant is `buildScenario("unresolved")`; it omits the mandate, execution receipt, and incident report. The tampered variant is `buildScenario("tamper")`; it changes the signed execution receipt payload and the bundle root. Both remain `unresolved`, with different dispositions that preserve the distinction between an incomplete case and invalid evidence.

The CLI exposes the same synthetic scenarios:

```bash
node dist/cli.js simulate --scenario principal
node dist/cli.js simulate --scenario unresolved
node dist/cli.js simulate --scenario tamper
```

The CLI simulator's tamper wrapper reports `observed: "invalid"` for its bundle-verification result. The SDK call in `examples/case-study.mjs` also evaluates the same tampered input and shows the policy decision as `outcome: "unresolved"`, `disposition: "invalid"`.

## What this case demonstrates

Within the synthetic and reference boundary, the case demonstrates:

- exact signed artifacts can be assembled into a closed, content-addressed bundle;
- mandate scope and required runtime controls are checked before a policy branch is selected;
- a present signature is not enough to create a model-vendor attribution;
- missing evidence produces an explicit evidence gap rather than a default party;
- changed evidence fails closed and retains rejection codes;
- the machine-readable legal effect remains `not-determined` in every path.

The result is reproducible at the outcome and reason-code level for the same scenario inputs. The simulator's generated keys intentionally make each run's artifact IDs and digests different.

## Relevant implementation and tests

- [`examples/case-study.mjs`](../examples/case-study.mjs) is the runnable SDK reproducer and assertion check.
- [`src/simulator.ts`](../src/simulator.ts) builds the existing synthetic scenarios and ephemeral keys.
- [`src/engine.ts`](../src/engine.ts) verifies pins, trust, artifact bindings, runtime controls, evidence state, and policy disposition.
- [`test/engine.test.mjs`](../test/engine.test.mjs) covers principal, missing, tampered, conflicting, and replay behavior.
- [`test/platform-simulator.test.mjs`](../test/platform-simulator.test.mjs) checks all named simulator scenarios and their fail-closed states.

## Limits

This case does not demonstrate real-world identity, authority, consent, source truth, complete history, legal causation, damages, insurance response, standards certification, interoperability outside the pinned profile, or production readiness. MandateBound does not contact a network, move funds, submit a dispute, or make a hosted production decision. See the [legal boundary](LEGAL_BOUNDARY.md), [threat model](THREAT_MODEL.md), [privacy model](PRIVACY_MODEL.md), and [disclaimer](../DISCLAIMER.md).
