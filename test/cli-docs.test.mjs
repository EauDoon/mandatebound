import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import { CASEPACK_CANONICAL_LIMITS, MAX_RAW_EVIDENCE_REFERENCES } from "../dist/casepack/primitives.js";
import { CLI_EXIT, CLI_INPUT_LIMITS, runCli } from "../dist/cli.js";
import { EXTERNAL_REVIEW_MAX_EVIDENCE_BYTES } from "../dist/review.js";
import { SIMULATION_SCENARIOS } from "../dist/simulator.js";
import { DEFAULT_STRICT_JSON_LIMITS } from "../dist/strict-json.js";

// docs/CLI.md is the one page that lists every command, action, scenario,
// limit and exit code. These checks fail when the CLI grows something the page
// does not mention, or when a documented number stops matching the code.
const doc = readFileSync(new URL("../docs/CLI.md", import.meta.url), "utf8");
const flatDoc = doc.replace(/\s+/gu, " ");
const MiB = 1024 * 1024;

async function help() {
  let text = "";
  const code = await runCli(["--help"], {
    stdin: Readable.from([]),
    stdout: new Writable({ write(chunk, _encoding, next) { text += chunk; next(); } }),
    stderr: new Writable({ write(_chunk, _encoding, next) { next(); } }),
  });
  assert.equal(code, CLI_EXIT.SUCCESS);
  return JSON.parse(text).result;
}

function section(heading) {
  const start = doc.indexOf(`\n## ${heading}\n`);
  assert.ok(start >= 0, `docs/CLI.md has no "## ${heading}" section`);
  const end = doc.indexOf("\n## ", start + 1);
  return doc.slice(start, end < 0 ? undefined : end);
}

// A command is documented when a heading names it or a paragraph opens with it.
function documentsCommand(name) {
  return doc.split("\n").some((line) =>
    (/^#{2,3} /u.test(line) && line.split(/[ ,]+/u).includes(name))
    || line.startsWith(`\`${name}\``));
}

function formatCount(value) {
  return value.toLocaleString("en-US");
}

test("CLI reference documents every command, action and scenario", async () => {
  const { commands, scenarios } = await help();
  for (const command of commands) {
    assert.ok(documentsCommand(command.name), command.name);
    for (const action of command.actions ?? []) {
      assert.ok(doc.includes(`\`${action}\``), `${command.name} ${action}`);
    }
  }
  for (const name of ["help", "version"]) assert.ok(documentsCommand(name), name);
  assert.deepEqual(scenarios, ["all", ...SIMULATION_SCENARIOS]);
  const simulate = doc.slice(doc.indexOf("### simulate"), doc.indexOf("\n## review"));
  for (const scenario of scenarios) assert.ok(simulate.includes(`\`${scenario}\``), scenario);
});

test("CLI reference exit table matches CLI_EXIT exactly", () => {
  const table = section("Exit codes");
  const rows = [...table.matchAll(/^\| (\d+) \| `([A-Z_]+)` \| [^|]+ \|$/gmu)]
    .map((match) => [match[2], Number(match[1])]);
  assert.deepEqual(Object.fromEntries(rows), { ...CLI_EXIT });
  assert.equal(rows.length, Object.keys(CLI_EXIT).length);
});

test("CLI reference input limits match the limits the CLI reads with", () => {
  const limits = section("Input conventions");
  const flatLimits = limits.replace(/\s+/gu, " ");
  const row = (label, { maxBytes, maxDepth, maxNodes }) =>
    `| ${label} | ${maxBytes / MiB} MiB | ${maxDepth} | ${formatCount(maxNodes)} |`;
  for (const expected of [
    row("Every JSON command not listed below", CLI_INPUT_LIMITS.default),
    row("`casepack`, `case-report` and every `operator` action", CLI_INPUT_LIMITS.casepack),
    row("`ap2-dispute`", CLI_INPUT_LIMITS.ap2Dispute),
    row("Canonical CasePack input bound into an operator receipt", CASEPACK_CANONICAL_LIMITS),
  ]) {
    assert.ok(limits.includes(expected), `missing or stale limits row: ${expected}`);
  }
  assert.ok(flatLimits.includes(`at most ${formatCount(DEFAULT_STRICT_JSON_LIMITS.maxArrayLength)} array items`));
  assert.ok(flatLimits.includes(`${formatCount(DEFAULT_STRICT_JSON_LIMITS.maxObjectKeys)} object keys`));
  assert.ok(flatLimits.includes(`capped at ${EXTERNAL_REVIEW_MAX_EVIDENCE_BYTES / MiB} MiB of decoded bytes`));
  assert.ok(flatDoc.includes(`text per entry and ${formatCount(MAX_RAW_EVIDENCE_REFERENCES)} entries`));
});
