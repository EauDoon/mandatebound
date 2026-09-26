import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkInstalledPackage } from "./check-package-consumer.mjs";

const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));
const temporaryRoot = mkdtempSync(join(tmpdir(), "mandatebound-package-"));
process.on("exit", () => rmSync(temporaryRoot, { recursive: true, force: true }));
const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const entryPoints = new Set();

function collectEntryPoints(value) {
  if (typeof value === "string") {
    if (value.startsWith("./")) entryPoints.add(value.slice(2));
    return;
  }
  if (value && typeof value === "object") {
    for (const target of Object.values(value)) collectEntryPoints(target);
  }
}

for (const field of [manifest.main, manifest.types, manifest.bin, manifest.exports]) {
  collectEntryPoints(field);
}

const npmCli = process.env["npm_execpath"];
const useNpmCli = typeof npmCli === "string" && npmCli.endsWith(".js");
const useWindowsNpmShim = process.platform === "win32" && !useNpmCli;
const npmCommand = useNpmCli
  ? process.execPath
  : useWindowsNpmShim
    ? process.env.ComSpec ?? "cmd.exe"
    : "npm";
const npmArgs = [
  ...(useNpmCli ? [npmCli] : []),
  ...(useWindowsNpmShim ? ["/d", "/s", "/c", "npm.cmd"] : []),
  "pack",
  "--pack-destination",
  temporaryRoot,
  "--json",
  "--ignore-scripts",
];
const result = spawnSync(npmCommand, npmArgs, {
  cwd: repositoryRoot,
  encoding: "utf8",
  shell: false,
});

if (result.status !== 0) {
  process.stderr.write(`package check failed: npm pack did not complete (exit ${result.status ?? "unavailable"}). Run npm run build first and check npm cache permissions.\n`);
  process.exit(1);
}

let report;
try {
  report = JSON.parse(result.stdout);
} catch {
  process.stderr.write("package check failed: npm returned non-JSON output\n");
  process.exit(1);
}

const packageReports = Array.isArray(report)
  ? report
  : report && typeof report === "object"
    ? Object.values(report)
    : [];
const packageReport = packageReports.length === 1 ? packageReports[0] : undefined;
if (!packageReport || !Array.isArray(packageReport.files)) {
  process.stderr.write("package check failed: missing file inventory\n");
  process.exit(1);
}

const allowedExact = new Set([
  "BRIEF.md",
  "CHANGELOG.md",
  "CONTRIBUTING.md",
  "DISCLAIMER.md",
  "LICENSE",
  "NOTICE",
  "README.md",
  "SECURITY.md",
  "SUMMARY.md",
  "package.json",
]);
const allowedPrefixes = ["conformance/", "dist/", "docs/", "openapi/", "rulebooks/", "schemas/"];
const required = new Set([
  "DISCLAIMER.md",
  "LICENSE",
  "NOTICE",
  "README.md",
  "SECURITY.md",
  "package.json",
  "docs/ADOPTER_WORKFLOW.md",
  "docs/examples/adopter-workflow.mjs",
  ...entryPoints,
]);
const rejected = [];

for (const entry of packageReport.files) {
  const path = entry.path;
  if (typeof path !== "string") {
    rejected.push("<non-string path>");
    continue;
  }
  if (!allowedExact.has(path) && !allowedPrefixes.some((prefix) => path.startsWith(prefix))) {
    rejected.push(path);
  }
  required.delete(path);
  if (/\.(?:env|key|log|map|p8|pem|tgz)$/iu.test(path) || path.includes("..")) {
    rejected.push(path);
  }
}

if (rejected.length > 0 || required.size > 0) {
  if (rejected.length > 0) {
    process.stderr.write(`package check failed: unexpected files: ${[...new Set(rejected)].join(", ")}\n`);
  }
  if (required.size > 0) {
    process.stderr.write(`package check failed: missing files: ${[...required].join(", ")}\n`);
  }
  process.exit(1);
}

process.stdout.write(`package check: ${packageReport.files.length} files allowed\n`);
try {
  const archive = join(temporaryRoot, packageReport.filename);
  checkInstalledPackage({ archive, temporaryRoot, manifest, npmCommand,
    npmPrefix: npmArgs.slice(0, npmArgs.indexOf("pack")) });
} catch (error) {
  process.stderr.write(`package check failed: ${error instanceof Error ? error.message : "consumer acceptance failed"}\n`);
  process.exitCode = 1;
}
