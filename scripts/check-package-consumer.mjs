import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { delimiter, dirname, join, resolve } from "node:path";

/** Exercise the shipped bytes from a new npm project outside the source tree. */
export function checkInstalledPackage({ archive, temporaryRoot, manifest, npmCommand, npmPrefix }) {
  const consumer = join(temporaryRoot, "consumer");
  mkdirSync(consumer);
  writeFileSync(join(consumer, "package.json"), JSON.stringify({ private: true, type: "module" }));
  const env = { ...process.env, NODE_PATH: "", NODE_OPTIONS: "",
    PATH: `${dirname(process.execPath)}${delimiter}${process.env.PATH ?? ""}` };
  // npm accepts a relative cache path; preserve its original location when changing cwd.
  if (env.npm_config_cache) env.npm_config_cache = resolve(env.npm_config_cache);
  const install = spawnSync(npmCommand, [...npmPrefix, "install", "--ignore-scripts", "--omit=dev",
    "--no-audit", "--no-fund", "--package-lock=false", archive], {
    cwd: consumer, env, encoding: "utf8", timeout: 120_000,
  });
  assert.equal(install.status, 0,
    `tarball install failed (exit ${install.status ?? "unavailable"}); check npm registry/cache access`);
  const installed = join(consumer, "node_modules", ...manifest.name.split("/"));
  for (const path of ["src", "test", "examples", "scripts", "node_modules/typescript"]) {
    assert.equal(existsSync(join(installed, path)), false, `unexpected checkout content: ${path}`);
  }
  assert.equal(existsSync(join(consumer, "node_modules/typescript")), false);

  // Copy only the shipped example, so package self-resolution cannot conceal missing exports.
  copyFileSync(join(installed, "docs/examples/adopter-workflow.mjs"), join(consumer, "workflow.mjs"));
  writeFileSync(join(consumer, "offline.mjs"), `
import net from "node:net";
import dgram from "node:dgram";
import dns from "node:dns";
import { syncBuiltinESMExports } from "node:module";
const blocked = () => { throw new Error("Acceptance forbids network access"); };
net.Socket.prototype.connect = blocked;
dgram.createSocket = blocked;
dns.lookup = blocked;
dns.resolve = blocked;
globalThis.fetch = blocked;
syncBuiltinESMExports();
`);
  const node = (args, expected = 0) => {
    const result = spawnSync(process.execPath, ["--import", "./offline.mjs", ...args], {
      cwd: consumer, env, encoding: "utf8", timeout: 30_000, maxBuffer: 4_194_304,
    });
    assert.equal(result.status, expected, `${args[0]} exited ${result.status}: ${result.stderr.slice(0, 500)}`);
    return result.stdout;
  };

  // All JS exports must resolve from the consumer, and both installed bins must work.
  const imports = Object.keys(manifest.exports).filter((name) => name !== "./package.json")
    .map((name) => `await import(${JSON.stringify(name === "." ? manifest.name : manifest.name + name.slice(1))});`);
  writeFileSync(join(consumer, "exports.mjs"), imports.join("\n"));
  node(["exports.mjs"]);
  for (const name of Object.keys(manifest.bin)) {
    const bin = process.platform === "win32" ? join(installed, manifest.bin[name])
      : join(consumer, "node_modules/.bin", name);
    const output = node([bin, "version"]);
    assert.notEqual(output.trim(), "", `${name} returned no output through the installed bin`);
    const version = JSON.parse(output);
    assert.equal(version.result.releaseVersion, manifest.version);
    if (process.platform !== "win32") {
      const direct = spawnSync(bin, ["version"], { cwd: consumer, env, encoding: "utf8", timeout: 30_000 });
      assert.equal(direct.status, 0, `${name} must be executable using its npm-installed shebang`);
      assert.equal(direct.stdout, output);
    }
  }

  const createdText = node(["workflow.mjs", "create", "exported"]);
  const created = JSON.parse(createdText);
  assert.equal(created.ready, true);
  assert.equal(created.outcome, "principal");
  assert.equal(created.decision.legalEffect, "not-determined");
  assert.equal(created.globalCompleteness, "not-established");
  const invocationPath = join(consumer, "exported/invocation.json");
  const anchorsPath = join(consumer, "exported/anchors.json");
  const invocation = JSON.parse(readFileSync(invocationPath, "utf8"));
  const trusted = JSON.parse(readFileSync(anchorsPath, "utf8"));
  const cli = join(installed, manifest.bin.mandatebound);
  assert.equal(JSON.parse(node([cli, "casepack", "verify", "--input", invocationPath])).ok, true);
  assert.equal(JSON.parse(node([cli, "case-report", "--input", invocationPath])).result.valid, true);

  // Move the handoff to a different directory; replay uses neither generated keys nor creator state.
  mkdirSync(join(consumer, "reviewer"));
  copyFileSync(invocationPath, join(consumer, "reviewer/case.json"));
  copyFileSync(anchorsPath, join(consumer, "reviewer/trusted.json"));
  const replayArgs = ["workflow.mjs", "replay", "reviewer/case.json", "reviewer/trusted.json"];
  assert.equal(node(replayArgs), createdText, "new-process replay must be byte-identical");

  const replayVariant = (name, mutate, cliValid = false) => {
    const value = structuredClone(invocation);
    mutate(value);
    const path = join(consumer, `${name}.json`);
    writeFileSync(path, JSON.stringify(value));
    const output = JSON.parse(node(["workflow.mjs", "replay", path, anchorsPath], 2));
    assert.equal(output.ready, false, name);
    assert.equal(output.outcome, "unresolved", name);
    assert.equal(output.decision, null, name);
    assert.equal(output.legalEffect, "not-determined", name);
    assert.equal(JSON.parse(node([cli, "casepack", "verify", "--input", path], cliValid ? 0 : 3)).ok, cliValid, name);
    return output;
  };
  const missing = replayVariant("missing", (value) => {
    value.anchors.rawEvidence = value.anchors.rawEvidence.filter((item) => item.referenceId !== "raw.checkout");
  });
  assert.ok(missing.source.issues.some((item) => item.code === "EXAMPLE_CHECKOUT_MISSING"));
  assert.equal(missing.readiness.integrity, "unknown");
  const tampered = replayVariant("tampered", (value) => {
    const raw = value.anchors.rawEvidence.find((item) => item.referenceId === "raw.checkout");
    const checkout = JSON.parse(Buffer.from(raw.bytesBase64, "base64"));
    checkout.totals[1].amount += 1;
    raw.bytesBase64 = Buffer.from(JSON.stringify(checkout)).toString("base64");
  });
  assert.ok(tampered.source.issues.some((item) => item.code === "UCP_AP2_MERCHANT_SIGNATURE_INVALID"));
  assert.ok(tampered.readiness.findings.some((item) => item.code === "MBCP_RAW_DIGEST_MISMATCH"));

  // Profile verification is a separate source check; outer checkout coverage alone is insufficient.
  const missingProfile = replayVariant("missing-profile", (value) => {
    value.anchors.rawEvidence = value.anchors.rawEvidence.filter((item) => item.referenceId !== "raw.profile");
  }, true);
  assert.ok(missingProfile.source.issues.some((item) => item.code === "EXAMPLE_PROFILE_MISSING"));
  const changedProfile = replayVariant("changed-profile", (value) => {
    const raw = value.anchors.rawEvidence.find((item) => item.referenceId === "raw.profile");
    const profile = JSON.parse(Buffer.from(raw.bytesBase64, "base64"));
    profile.ucp.version = "2026-01-11";
    raw.bytesBase64 = Buffer.from(JSON.stringify(profile)).toString("base64");
  }, true);
  assert.ok(changedProfile.source.issues.some((item) => item.code === "UCP_PROFILE_PIN_MISMATCH"));
  assert.ok(changedProfile.source.issues.some((item) => item.code === "UCP_VERSION_UNSUPPORTED"));

  // The saved envelope's upstreamValid flag must never substitute for a fresh signature check.
  const badKey = structuredClone(trusted);
  badKey.merchant.keySnapshot.kid = "different-key";
  writeFileSync(join(consumer, "bad-key.json"), JSON.stringify(badKey));
  const sourceRejected = JSON.parse(node(["workflow.mjs", "replay", invocationPath, "bad-key.json"], 2));
  assert.equal(sourceRejected.readiness.valid, true);
  assert.equal(sourceRejected.source.upstreamValid, false);
  assert.equal(sourceRejected.decision, null);

  // A correctly sealed substitute CasePack must still be rejected by the separately retained pin.
  writeFileSync(join(consumer, "substitute.mjs"), `
import { readFileSync, writeFileSync } from "node:fs";
import { createMandateBoundCasePack } from "@oonyl/mandatebound/casepack";
const value = JSON.parse(readFileSync("exported/invocation.json", "utf8"));
const { casePackDigest, ...material } = value.casePack;
value.casePack = createMandateBoundCasePack({ ...material, casePackId: "substitute.synthetic" });
writeFileSync("substitute.json", JSON.stringify(value));
`);
  node(["substitute.mjs"]);
  const substituted = JSON.parse(node(["workflow.mjs", "replay", "substitute.json", anchorsPath], 2));
  assert.equal(substituted.readiness.valid, true);
  assert.equal(substituted.findings[0].code, "EXAMPLE_CASEPACK_PIN_MISMATCH");
  assert.equal(substituted.decision, null);

  // Existing native missing/tampered behavior also has to work through the installed root export.
  writeFileSync(join(consumer, "native.mjs"), `
import assert from "node:assert/strict";
import { buildScenario, evaluateCase } from "@oonyl/mandatebound";
for (const [name, disposition] of [["unresolved", "indeterminate"], ["tamper", "invalid"]]) {
  const decision = evaluateCase(buildScenario(name).input);
  assert.equal(decision.outcome, "unresolved");
  assert.equal(decision.disposition, disposition);
  assert.equal(decision.legalEffect, "not-determined");
}
`);
  node(["native.mjs"]);
  process.stdout.write("package consumer: public exports, bins, signed import, readiness, export, missing/tampered evidence, caller pins, and byte-identical offline replay passed\n");
}
