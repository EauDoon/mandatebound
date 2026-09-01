import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const checker = fileURLToPath(new URL("../scripts/check-licenses.mjs", import.meta.url));

function writeManifest(directory, manifest) {
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, "package.json"), JSON.stringify(manifest));
}

test("license check inspects nested installed dependencies", () => {
  const directory = mkdtempSync(join(tmpdir(), "mandatebound-license-"));
  try {
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
    const result = spawnSync(process.execPath, [checker], {
      cwd: directory,
      encoding: "utf8",
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /nested@1\.0\.0 has unapproved license GPL-3\.0/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
