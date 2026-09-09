import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import { runCli } from "../dist/cli.js";
import { buildScenario } from "../dist/simulator.js";

async function cli(args, value, overrides = {}) {
  let output = "";
  const capture = new Writable({ write(chunk, _encoding, next) { output += chunk; next(); } });
  const code = await runCli(args, { stdin: Readable.from([JSON.stringify(value)]), stdout: capture,
    stderr: new Writable({ write(_chunk, _encoding, next) { next(); } }), ...overrides });
  return { code, output, json: () => JSON.parse(output) };
}

test("native preview uses the existing engine without touching a store", async () => {
  const input = buildScenario("unresolved").input;
  const result = await cli(["preview"], input, { store: new Proxy({}, { get() { throw new Error("store touched"); } }) });
  assert.equal(result.code, 0, result.output);
  assert.equal(result.json().result.policyOutcome, "unresolved");
  assert.equal(result.json().result.legalEffect, "not-determined");
  assert.equal((await cli(["preview", "--store", "unused"], input)).code, 2);
  assert.equal((await cli(["preview", "--format", "html"], input)).code, 2);
});
