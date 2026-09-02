import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const checker = fileURLToPath(new URL("../scripts/check-licenses.mjs", import.meta.url));
const packageChecker = fileURLToPath(new URL("../scripts/check-package.mjs", import.meta.url));

function writeManifest(directory, manifest) {
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, "package.json"), JSON.stringify(manifest));
}

test("license check inspects nested installed dependencies", () => {
  const directory = mkdtempSync(join(tmpdir(), "mandatebound-license-"));
  try {
    const fixtureChecker = join(directory, "scripts", "check-licenses.mjs");
    mkdirSync(join(directory, "scripts"));
    copyFileSync(checker, fixtureChecker);
    writeManifest(join(directory, "node_modules", "parent"), {
      name: "parent",
      version: "1.0.0",
      license: "MIT",
    });
    writeManifest(join(directory, "node_modules", "parent", "node_modules", "nested"), {
      name: "nested",
      version: "1.0.0",
      license: "GPL-3.0",
    });
    const unrelatedDirectory = join(directory, "unrelated");
    mkdirSync(unrelatedDirectory);
    const result = spawnSync(process.execPath, [fixtureChecker], {
      cwd: unrelatedDirectory,
      encoding: "utf8",
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /nested@1\.0\.0 has unapproved license GPL-3\.0/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("package check resolves the repository independently of caller cwd", () => {
  const directory = mkdtempSync(join(tmpdir(), "mandatebound-package-check-"));
  try {
    const result = spawnSync(process.execPath, [packageChecker], {
      cwd: directory,
      encoding: "utf8",
      env: { ...process.env, npm_config_cache: join(directory, "npm-cache") },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /package check: \d+ files allowed/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
