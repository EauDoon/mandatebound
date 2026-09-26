import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const cli = fileURLToPath(new URL("../dist/cli.js", import.meta.url));

test("npm-style bin symlinks invoke the CLI and preserve failure exit codes", {
  skip: process.platform === "win32" ? "npm uses command shims on Windows" : false,
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mandatebound-bin-"));
  try {
    for (const name of ["mandatebound", "alb"]) {
      const link = join(directory, name);
      await symlink(cli, link);
      const version = spawnSync(process.execPath, [link, "version"], { encoding: "utf8" });
      assert.equal(version.status, 0, version.stderr);
      assert.equal(JSON.parse(version.stdout).result.name, "MandateBound");
      const invalid = spawnSync(process.execPath, [link, "unknown-command"], { encoding: "utf8" });
      assert.equal(invalid.status, 2, invalid.stderr);
      assert.equal(JSON.parse(invalid.stdout).error.code, "ALB_CLI_USAGE");
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("SDK import stays inert with another or unavailable entrypoint", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mandatebound-import-"));
  try {
    const script = join(directory, "consumer.mjs");
    const moduleUrl = new URL("../dist/index.js", import.meta.url).href;
    await writeFile(script, `
if (process.env.MISSING_ENTRY === "1") process.argv[1] = "nonexistent-entry.mjs";
await import(${JSON.stringify(moduleUrl)});
console.log("sdk-import-only");
`);
    for (const missing of ["0", "1"]) {
      const result = spawnSync(process.execPath, [script, "version"], {
        encoding: "utf8", env: { ...process.env, MISSING_ENTRY: missing },
      });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, "sdk-import-only\n");
      assert.equal(result.stderr, "");
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
