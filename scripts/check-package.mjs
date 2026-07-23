import { spawnSync } from "node:child_process";

const npmCli = process.env["npm_execpath"];
const useNpmCli = typeof npmCli === "string" && npmCli.endsWith(".js");
const npmCommand = useNpmCli ? process.execPath : process.platform === "win32" ? "npm.cmd" : "npm";
const npmArgs = [
  ...(useNpmCli ? [npmCli] : []),
  "pack",
  "--dry-run",
  "--json",
  "--ignore-scripts",
];
const result = spawnSync(npmCommand, npmArgs, {
  encoding: "utf8",
  shell: false,
});

if (result.status !== 0) {
  const detail = result.error instanceof Error ? `: ${result.error.message}` : "";
  process.stderr.write(`package check failed: npm pack did not complete${detail}\n`);
  process.exit(1);
}

let report;
try {
  report = JSON.parse(result.stdout);
} catch {
  process.stderr.write("package check failed: npm returned non-JSON output\n");
  process.exit(1);
}

const packageReport = report[0];
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
  "dist/index.js",
  "dist/index.d.ts",
  "package.json",
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
