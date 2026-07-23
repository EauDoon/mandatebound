# Examples

The tracked repository does not contain static private keys or production evidence.

Run the simulator to generate ephemeral signed evidence in memory:

```bash
npm run demo
```

Available scenarios cover principal, operator, model-vendor, unresolved, expiry, replay, bundle tampering, causal conflict, and appeal history.

To evaluate a saved synthetic bundle:

```bash
npm run build
node dist/cli.js decide --input synthetic-case.albx.json --format json
```

Do not use real credentials, personal data, prompts, or transaction evidence in a public issue or fixture.
