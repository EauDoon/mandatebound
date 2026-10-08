# Examples

The tracked repository does not contain static private keys or production evidence.

Run the simulator to generate ephemeral signed evidence in memory:

```bash
npm run demo
```

Available scenarios cover principal, operator, model-vendor, unresolved, expiry, replay, bundle tampering, causal conflict, and appeal history.

The repository ships no saved bundle file. To check an evidence bundle you saved
yourself, for example the JSON of a synthetic bundle from the SDK's
`createEvidenceBundle` or `buildScenario(name).bundle`, use `verify`. It reports
bundle integrity only and never evaluates policy:

```bash
npm run build
node dist/cli.js verify --input synthetic-case.albx.json
```

`decide` and `preview` take a complete evaluation case instead: the case
identifier, `asOf`, external pins, the policy, rulebook and trust snapshot, and
the runtime-event, prior-receipt and causation-attestation arrays. They reject
an incomplete case, including a bare bundle, with exit code 3 before evaluating
it or opening a store. `npm run demo` builds and evaluates complete synthetic
cases for every scenario above.

Do not use real credentials, personal data, prompts, or transaction evidence in a public issue or fixture.
