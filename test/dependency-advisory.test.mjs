import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { compareVersions, isVulnerable, parseVersion } from "../scripts/check-dependencies.mjs";

const checker = fileURLToPath(new URL("../scripts/check-dependencies.mjs", import.meta.url));

function writeManifest(directory, manifest) {
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, "package.json"), JSON.stringify(manifest));
}

function runChecker(directory, manifest) {
  mkdirSync(join(directory, "scripts"));
  const fixtureChecker = join(directory, "scripts", "check-dependencies.mjs");
  copyFileSync(checker, fixtureChecker);
  if (manifest !== null) {
    writeManifest(join(directory, "node_modules", "fast-uri"), manifest);
  }
  return spawnSync(process.execPath, [fixtureChecker], {
    cwd: directory,
    encoding: "utf8",
  });
}

test("parseVersion accepts plain releases and rejects malformed input", () => {
  assert.deepEqual(parseVersion("3.1.5"), { major: 3, minor: 1, patch: 5, prerelease: null });
  assert.deepEqual(parseVersion("3.1.6-rc.1"), { major: 3, minor: 1, patch: 6, prerelease: "rc.1" });
  assert.equal(parseVersion("3.1"), null);
  assert.equal(parseVersion("3.1.5.7"), null);
  assert.equal(parseVersion("v3.1.5"), null);
  assert.equal(parseVersion(""), null);
  assert.deepEqual(parseVersion(" 3.1.5 "), { major: 3, minor: 1, patch: 5, prerelease: null });
  assert.equal(parseVersion(3.15), null);
  assert.equal(parseVersion(undefined), null);
});

test("compareVersions orders releases and ranks prereleases below releases", () => {
  assert.equal(compareVersions("3.1.5", "3.1.6"), -1);
  assert.equal(compareVersions("3.1.6", "3.1.5"), 1);
  assert.equal(compareVersions("3.1.5", "3.1.5"), 0);
  assert.equal(compareVersions("3.10.0", "3.9.0"), 1);
  assert.equal(compareVersions("4.0.0", "3.99.99"), 1);
  assert.equal(compareVersions("3.1.6-rc.1", "3.1.6"), -1);
  assert.equal(compareVersions("3.1.6", "3.1.6-rc.1"), 1);
  assert.equal(compareVersions("1.0.0-rc.2", "1.0.0-rc.10"), -1);
  assert.equal(compareVersions("1.0.0-rc.10", "1.0.0-rc.2"), 1);
  assert.equal(compareVersions("1.0.0-alpha", "1.0.0-alpha.1"), -1);
  assert.equal(compareVersions("1.0.0-alpha.1", "1.0.0-alpha.beta"), -1);
  assert.equal(compareVersions("nonsense", "3.1.6"), null);
  assert.equal(compareVersions("3.1.6", "nonsense"), null);
});

test("isVulnerable treats unparseable versions as vulnerable", () => {
  const rule = { minimumVulnerable: "3.0.0", maximumVulnerable: "3.1.5", fixedIn: "3.1.6" };
  assert.equal(isVulnerable("3.0.0", rule), true);
  assert.equal(isVulnerable("3.1.4", rule), true);
  assert.equal(isVulnerable("3.1.5", rule), true);
  assert.equal(isVulnerable("3.1.6", rule), false);
  assert.equal(isVulnerable("3.1.7", rule), false);
  assert.equal(isVulnerable("2.9.9", rule), false);
  assert.equal(isVulnerable("4.0.0", rule), false);
  assert.equal(isVulnerable("not-a-version", rule), true);
  const prerelease = {
    minimumVulnerable: "1.2.3-rc.2",
    maximumVulnerable: "1.2.3-rc.10",
    fixedIn: "1.2.3",
  };
  assert.equal(isVulnerable("1.2.3-rc.9", prerelease), true);
  assert.equal(isVulnerable("1.2.3-rc.10", prerelease), true);
  assert.equal(isVulnerable("1.2.3-rc.11", prerelease), false);
});

test("dependency check fails closed on a vulnerable installed version", () => {
  const directory = mkdtempSync(join(tmpdir(), "mandatebound-deps-vulnerable-"));
  try {
    const result = runChecker(directory, { name: "fast-uri", version: "3.1.5" });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /fast-uri@3\.1\.5 is inside the vulnerable window 3\.0\.0 to 3\.1\.5/);
    assert.match(result.stderr, /GHSA-f65p-4m7j-42xc/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("dependency check accepts the fixed version and reports the scanned tree", () => {
  const directory = mkdtempSync(join(tmpdir(), "mandatebound-deps-safe-"));
  try {
    const result = runChecker(directory, { name: "fast-uri", version: "3.1.8" });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /dependency check: 1 installed packages clear of recorded advisories/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("dependency check rejects the host normalization advisory's last affected release", () => {
  const directory = mkdtempSync(join(tmpdir(), "mandatebound-deps-host-"));
  try {
    const result = runChecker(directory, { name: "fast-uri", version: "3.1.7" });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /GHSA-hrr3-gc8f-f4qj/);
    assert.match(result.stderr, /upgrade to 3\.1\.8/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("dependency check fails closed when the dependency tree is absent", () => {
  const directory = mkdtempSync(join(tmpdir(), "mandatebound-deps-missing-"));
  try {
    const result = runChecker(directory, null);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /node_modules is missing/);
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

test("dependency check follows a symlinked installed package", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "mandatebound-deps-symlink-"));
  try {
    mkdirSync(join(directory, "scripts"));
    const fixtureChecker = join(directory, "scripts", "check-dependencies.mjs");
    copyFileSync(checker, fixtureChecker);
    const realPackage = join(directory, "real-fast-uri");
    writeManifest(realPackage, { name: "fast-uri", version: "3.1.5" });
    mkdirSync(join(directory, "node_modules"));
    if (!linkOrSkip(t, realPackage, join(directory, "node_modules", "fast-uri"), "dir")) return;
    const result = spawnSync(process.execPath, [fixtureChecker], { cwd: directory, encoding: "utf8" });
    assert.equal(result.status, 1, result.stdout);
    assert.match(result.stderr, /fast-uri@3\.1\.5 is inside the vulnerable window/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("dependency check inspects nested installed dependencies", () => {
  const directory = mkdtempSync(join(tmpdir(), "mandatebound-deps-nested-"));
  try {
    mkdirSync(join(directory, "scripts"));
    const fixtureChecker = join(directory, "scripts", "check-dependencies.mjs");
    copyFileSync(checker, fixtureChecker);
    writeManifest(join(directory, "node_modules", "ajv"), { name: "ajv", version: "8.20.0" });
    writeManifest(join(directory, "node_modules", "ajv", "node_modules", "fast-uri"), {
      name: "fast-uri",
      version: "3.1.4",
    });
    const result = spawnSync(process.execPath, [fixtureChecker], { cwd: directory, encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /fast-uri@3\.1\.4 is inside the vulnerable window/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
