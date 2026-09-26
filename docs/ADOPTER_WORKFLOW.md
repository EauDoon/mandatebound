# Install, import, export, and replay

This acceptance example uses only the public exports of an installed package. It
ships in `docs/examples/adopter-workflow.mjs`; no source files, test fixtures,
TypeScript compiler, or author checkout are needed to run it. Node.js 22.12 or
newer is required. The CI release gate tests Node 22.12.0 and 24.18.0.

All evidence is **synthetic**. The example verifies the UCP 2026-04-08 REST profile
declaration and an ES256 detached merchant authorization under its AP2 Mandates
Extension. It associates that checkout with the existing synthetic native receipt.
It does not create a complete AP2 mandate chain, infer a native receipt from a
checkout, or promote a merchant key into native trust. This association is an
illustrative local mapping policy, not a general importer or protocol certification.

## Build an installable candidate

From a fresh source checkout:

```bash
git clone https://github.com/EauDoon/mandatebound.git
cd mandatebound
npm ci --ignore-scripts
npm run build
npm run package:check
npm pack --ignore-scripts --pack-destination ..
cd ..
```

`package:check` packs the actual candidate, checks its file inventory, installs it
in a temporary consumer with lifecycle scripts disabled and no dev dependencies,
and runs the handoff below. Dependency installation needs npm registry or cache
access. The subsequent verification processes disable network APIs and use the
package's shipped schemas. A failure names the install, export, CLI, or evidence
assertion that failed. The temporary consumer is removed on completion.

For version 1.2.0 the archive is `oonyl-mandatebound-1.2.0.tgz`. Use the filename
printed by `npm pack` if building a later version. This guide uses the candidate
tarball so it exercises these changes without assuming a new registry release.

## Run as a consumer

In a new directory next to the archive:

```bash
mkdir mandatebound-consumer
cd mandatebound-consumer
npm init -y
npm install --ignore-scripts --omit=dev ../oonyl-mandatebound-1.2.0.tgz
cp node_modules/@oonyl/mandatebound/docs/examples/adopter-workflow.mjs workflow.mjs
node workflow.mjs create synthetic-case > accepted.json
```

The `.mjs` extension enables ESM without changing your project's module setting.
The script refuses to overwrite an existing output directory. It generates
ephemeral signing keys in memory, exports public keys only, and writes:

| File | Purpose |
| --- | --- |
| `synthetic-case/invocation.json` | CasePack plus exact source bytes encoded as canonical standard base64; directly accepted by `casepack verify` and `case-report`. |
| `synthetic-case/anchors.json` | Separately retained CasePack digest, coverage contract/policy pins, native replay pins and trust root, merchant public key, source-profile digest, and explicit evaluation time. |
| `accepted.json` | Readiness, bounded diagnostics, and the complete native decision from the creator process. |

Anchors are generated alongside evidence **only for this synthetic example**. In
an integration, the reviewer must obtain pins and authorized public keys from an
independently trusted record. Accepting replacement anchors from the evidence
sender defeats this boundary. Preserve the originally accepted engine/package
and schema version for historical replay. No current key, profile, or clock
lookup is performed.

## Independently replay the handoff

Copy `synthetic-case/invocation.json`, the separately trusted
`synthetic-case/anchors.json`, and the original `accepted.json` to another
directory or machine with the same installed package and the copied script.
Keep the two evidence files in a `synthetic-case` directory and `accepted.json`
beside the script for these commands:

```bash
node workflow.mjs replay synthetic-case/invocation.json synthetic-case/anchors.json > replayed.json
node --input-type=module -e 'import { readFileSync } from "node:fs"; import assert from "node:assert/strict"; assert.deepEqual(readFileSync("accepted.json"), readFileSync("replayed.json"));'
```

The replay process has no generated private keys or in-memory creator state. It
rechecks the source signature and profile pin, verifies coverage and CasePack
integrity under caller-owned anchors, then calls `evaluateBundle` using the
retained native pins and trust root. Its entire output is byte-identical to the
accepted result. Creating a *new* synthetic case generates new keys and digests;
only replay of the same exported evidence is byte-identical.

The installed CLI can inspect the same handoff:

```bash
./node_modules/.bin/mandatebound casepack verify --input synthetic-case/invocation.json
./node_modules/.bin/mandatebound case-report --input synthetic-case/invocation.json --format html > report.html
```

For CLI review, supply the independently trusted coverage anchors in the
invocation. The example replay command always uses its separate trusted file.
The CLI's top-level `replay` command replays **appeal events**, not CasePacks.

## Failure behavior

| Supplied evidence | Example result | Diagnostic |
| --- | --- | --- |
| Complete captured checkout | `ready: true`, native outcome `principal`, exit 0 | Coverage requirement `checkout.required` is satisfied. |
| `raw.checkout` entry removed from `anchors.rawEvidence` | `ready: false`, `outcome: unresolved`, `decision: null`, exit 2 | `EXAMPLE_CHECKOUT_MISSING`; CasePack integrity is `unknown`. |
| Checkout amount changed without resigning | `ready: false`, `outcome: unresolved`, `decision: null`, exit 2 | `UCP_AP2_MERCHANT_SIGNATURE_INVALID` plus raw-evidence integrity findings. |
| Substitute sealed CasePack | `ready: false`, `outcome: unresolved`, `decision: null`, exit 2 | `EXAMPLE_CASEPACK_PIN_MISMATCH`. |
| Malformed input or inaccessible file | No accepted result, exit 2 | Bounded `EXAMPLE_INPUT_OR_IO_INVALID` on stderr; input bodies are not echoed. |

The package check executes these evidence cases and rejects a wrong merchant key
even when the stored envelope says `upstreamValid: true`. It also tests the existing
native missing and tampered scenarios, which retain `indeterminate` and `invalid`
dispositions respectively. The outer integration gate does not fabricate a native
decision: when source review fails, `decision` is null and the integration outcome
is unresolved. Every returned result keeps `legalEffect: "not-determined"` and
`globalCompleteness: "not-established"`.

## Source boundaries

The signing example follows the [pinned UCP AP2 merchant authorization procedure](https://ucp.dev/2026-04-08/specification/ap2-mandates/#business-authorization):
exclude the complete `ap2` object, canonicalize the checkout with JCS, and sign the
protected header and payload. The [UCP profile specification](https://ucp.dev/2026-04-08/specification/overview/)
defines discovery and exact version declarations. Full AP2 mandate credentials
are defined separately by the [pinned AP2 v0.2.0 specification](https://github.com/google-agentic-commerce/AP2/blob/b4587ac1d055888a73b4b21750973cffba961793/docs/ap2/specification.md);
see [V1.2](V1_2.md) for that resolver workflow.

Read the [legal boundary](LEGAL_BOUNDARY.md) and [privacy model](PRIVACY_MODEL.md)
before adapting the example. Signed bytes do not prove source truth, consent,
real-world authority, loss, or liability.
