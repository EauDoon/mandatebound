import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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

function fixtureLicenseChecker(directory) {
  mkdirSync(join(directory, "scripts"));
  const fixtureChecker = join(directory, "scripts", "check-licenses.mjs");
  copyFileSync(checker, fixtureChecker);
  return fixtureChecker;
}

test("license check fails closed when node_modules is missing", () => {
  const directory = mkdtempSync(join(tmpdir(), "mandatebound-license-missing-"));
  try {
    const result = spawnSync(process.execPath, [fixtureLicenseChecker(directory)], { cwd: directory, encoding: "utf8" });
    assert.equal(result.status, 1, result.stdout);
    assert.match(result.stderr, /license check failed: node_modules is missing; run npm ci --ignore-scripts/u);
    assert.equal(result.stdout, "");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("license check fails closed when node_modules holds no package manifests", () => {
  const directory = mkdtempSync(join(tmpdir(), "mandatebound-license-empty-"));
  try {
    const fixtureChecker = fixtureLicenseChecker(directory);
    mkdirSync(join(directory, "node_modules", ".bin"), { recursive: true });
    mkdirSync(join(directory, "node_modules", "not-a-package"));
    const result = spawnSync(process.execPath, [fixtureChecker], { cwd: directory, encoding: "utf8" });
    assert.equal(result.status, 1, result.stdout);
    assert.match(result.stderr, /license check failed: no installed package manifests were found/u);
    assert.equal(result.stdout, "");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("license check still passes a tree of approved licenses", () => {
  const directory = mkdtempSync(join(tmpdir(), "mandatebound-license-approved-"));
  try {
    const fixtureChecker = fixtureLicenseChecker(directory);
    writeManifest(join(directory, "node_modules", "approved"), { name: "approved", version: "1.0.0", license: "MIT" });
    const result = spawnSync(process.execPath, [fixtureChecker], { cwd: directory, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "license check: 1 installed packages use approved licenses\n");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

// Windows only permits symlink creation for elevated or Developer Mode
// processes. Where the platform refuses, skip rather than report a false
// failure; the Linux CI runners still exercise these paths.
function linkOrSkip(t, target, path, type) {
  try {
    symlinkSync(target, path, type);
  } catch (error) {
    if (["EPERM", "EACCES", "ENOSYS"].includes(error.code)) {
      t.skip("symlinks are unavailable on this platform");
      return false;
    }
    throw error;
  }
  return true;
}

test("license check follows a symlinked installed package", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "mandatebound-license-symlink-"));
  try {
    mkdirSync(join(directory, "scripts"));
    const fixtureChecker = join(directory, "scripts", "check-licenses.mjs");
    copyFileSync(checker, fixtureChecker);
    const realPackage = join(directory, "real-gpl");
    writeManifest(realPackage, { name: "copyleft", version: "1.0.0", license: "GPL-3.0" });
    mkdirSync(join(directory, "node_modules"));
    if (!linkOrSkip(t, realPackage, join(directory, "node_modules", "copyleft"), "dir")) return;
    const result = spawnSync(process.execPath, [fixtureChecker], { cwd: directory, encoding: "utf8" });
    assert.equal(result.status, 1, result.stdout);
    assert.match(result.stderr, /copyleft@1\.0\.0 has unapproved license GPL-3\.0/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("package check rejects packed content holding a PEM private key and reports only the path", () => {
  const directory = mkdtempSync(join(tmpdir(), "mandatebound-package-secret-"));
  try {
    mkdirSync(join(directory, "scripts"));
    for (const name of ["check-package.mjs", "check-package-consumer.mjs"]) {
      copyFileSync(fileURLToPath(new URL(`../scripts/${name}`, import.meta.url)), join(directory, "scripts", name));
    }
    writeFileSync(join(directory, "package.json"), JSON.stringify({
      name: "secret-scan-fixture",
      version: "1.0.0",
      license: "Apache-2.0",
      files: ["docs", "DISCLAIMER.md", "NOTICE", "README.md", "SECURITY.md", "LICENSE"],
    }));
    for (const name of ["DISCLAIMER.md", "NOTICE", "README.md", "SECURITY.md", "LICENSE"]) {
      writeFileSync(join(directory, name), "synthetic\n");
    }
    mkdirSync(join(directory, "docs", "examples"), { recursive: true });
    writeFileSync(join(directory, "docs", "ADOPTER_WORKFLOW.md"), "synthetic\n");
    writeFileSync(join(directory, "docs", "examples", "adopter-workflow.mjs"), "export {};\n");
    // Assembled at runtime so this source file never holds a key block itself.
    const body = "SYNTHETICKEYBODYCANARY";
    const label = ["PRIVATE", "KEY"].join(" ");
    writeFileSync(
      join(directory, "docs", "notes.md"),
      `Notes\n\n-----BEGIN EC ${label}-----\n${body}\n-----END EC ${label}-----\n`,
    );
    const result = spawnSync(process.execPath, [join(directory, "scripts", "check-package.mjs")], {
      cwd: tmpdir(),
      encoding: "utf8",
      env: { ...process.env, npm_config_cache: join(directory, "npm-cache") },
    });
    assert.equal(result.status, 1, result.stdout);
    assert.match(result.stderr, /package check failed: private key material in packed files: docs\/notes\.md/u);
    assert.equal(result.stderr.includes(body), false);
    assert.equal(result.stdout.includes(body), false);
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
