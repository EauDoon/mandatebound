# mandatebound regression baseline: 2026-09-23

## Scope
TypeScript project `mandatebound` (`@oonyl/mandatebound@1.2.0`). Test target
invoked: `npm test`, which runs `npm run build && node --test`.

## Environment
- Default branch: `main`.
- Toolchain: Node v24.18.0, npm 12.0.2 on Windows.
- Audit branch: `imp/portfolio-triage-phase9-2026-09-23`.
- Dependency install required: `npm install` (ajv, ajv-formats, @types/node,
  fast-check, typescript, plus the `@typescript/typescript-win32-x64` platform
  binary from the optional set).

## Results
- tests: 273
- pass: 272
- fail: 0
- skipped: 1
- error: 0
- duration_ms: 10,347.9

## Verdict
- Build (`tsc -p tsconfig.json`) succeeded with no type errors.
- All 273 node:test cases ran cleanly. 1 skip is pre-existing and unrelated to
  this audit.
- No failures, no cancelled runs, no errors.
- Audit branch is a no-op against source, tests, and schemas. Only this report
  is added under `audits/`.

## Notes
- First install attempt used `--omit=optional` and tripped the typescript
  platform binary (`@typescript/typescript-win32-x64`). Re-ran with default
  optional resolution. No code changes were made; the manifest already lists
  the platform binary correctly.

## Follow-ups (out of scope for this commit)
- No PR is opened by this worker; the human opens the PR per the standing rule.