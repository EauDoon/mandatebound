import { existsSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));
const root = join(repositoryRoot, "node_modules");

export const advisoryRules = [
  {
    name: "fast-uri",
    minimumVulnerable: "3.0.0",
    maximumVulnerable: "3.1.5",
    fixedIn: "3.1.6",
    advisories: [
      "GHSA-5jgf-p345-68v8",
      "GHSA-7p8r-x3mc-p8w7",
      "GHSA-f65p-4m7j-42xc",
      "GHSA-fph4-wmhf-6fwf",
      "GHSA-jqff-g426-hqxp",
    ],
  },
];

export function parseVersion(value) {
  if (typeof value !== "string") return null;
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/u.exec(value.trim());
  if (!match) return null;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (!Number.isSafeInteger(major) || !Number.isSafeInteger(minor) || !Number.isSafeInteger(patch)) {
    return null;
  }
  return { major, minor, patch, prerelease: match[4] ?? null };
}

export function compareVersions(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  if (a === null || b === null) return null;
  for (const field of ["major", "minor", "patch"]) {
    if (a[field] !== b[field]) return a[field] < b[field] ? -1 : 1;
  }
  if (a.prerelease === b.prerelease) return 0;
  if (a.prerelease === null) return 1;
  if (b.prerelease === null) return -1;
  return a.prerelease < b.prerelease ? -1 : 1;
}

export function isVulnerable(version, rule) {
  const floor = compareVersions(version, rule.minimumVulnerable);
  const ceiling = compareVersions(version, rule.maximumVulnerable);
  if (floor === null || ceiling === null) return true;
  return floor >= 0 && ceiling <= 0;
}

export function evaluateAdvisories(packages, rules = advisoryRules) {
  const issues = [];
  for (const entry of packages) {
    if (!entry || typeof entry.name !== "string" || typeof entry.version !== "string") {
      issues.push("dependency manifest could not be parsed");
      continue;
    }
    for (const rule of rules) {
      if (entry.name !== rule.name) continue;
      if (isVulnerable(entry.version, rule)) {
        issues.push(
          `${entry.name}@${entry.version} is inside the vulnerable window ${rule.minimumVulnerable} to ${rule.maximumVulnerable}; upgrade to ${rule.fixedIn} or later (${rule.advisories.join(", ")})`,
        );
      }
    }
  }
  return issues;
}

const packages = [];

function readPackage(directory) {
  const manifestPath = join(directory, "package.json");
  if (!existsSync(manifestPath)) return;
  try {
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    packages.push({
      name: String(manifest.name ?? "unknown"),
      version: String(manifest.version ?? "unknown"),
    });
  } catch {
    packages.push({ name: null, version: null });
  }
}

function scanNodeModules(directory) {
  if (!existsSync(directory)) return;
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name === ".bin") continue;
    const candidate = join(directory, entry.name);
    if (entry.name.startsWith("@")) {
      for (const scoped of readdirSync(candidate, { withFileTypes: true })) {
        if (!scoped.isDirectory()) continue;
        readPackage(join(candidate, scoped.name));
        scanNodeModules(join(candidate, scoped.name, "node_modules"));
      }
    } else {
      readPackage(candidate);
      scanNodeModules(join(candidate, "node_modules"));
    }
  }
}

export function main() {
  if (!existsSync(root)) {
    process.stderr.write("dependency check failed: node_modules is missing; run npm ci --ignore-scripts\n");
    process.exit(1);
  }
  scanNodeModules(root);
  const issues = evaluateAdvisories(packages);
  if (issues.length > 0) {
    for (const issue of issues) {
      process.stderr.write(`dependency check failed: ${issue}\n`);
    }
    process.exit(1);
  }
  process.stdout.write(`dependency check: ${packages.length} installed packages clear of recorded advisories\n`);
}

function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  let resolvedEntry;
  try {
    resolvedEntry = realpathSync(entry);
  } catch {
    resolvedEntry = resolve(entry);
  }
  return fileURLToPath(import.meta.url) === resolvedEntry;
}

if (invokedDirectly()) main();
