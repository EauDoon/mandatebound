import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));
const root = join(repositoryRoot, "node_modules");

export const advisoryRules = [
  {
    name: "fast-uri",
    minimumVulnerable: "3.0.0",
    maximumVulnerable: "3.1.7",
    fixedIn: "3.1.8",
    advisories: ["GHSA-hrr3-gc8f-f4qj"],
  },
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

function comparePrerelease(left, right) {
  if (left === right) return 0;
  if (left === null) return 1;
  if (right === null) return -1;
  const a = left.split(".");
  const b = right.split(".");
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const leftId = a[index];
    const rightId = b[index];
    if (leftId === undefined) return -1;
    if (rightId === undefined) return 1;
    const leftNumeric = /^[0-9]+$/u.test(leftId);
    const rightNumeric = /^[0-9]+$/u.test(rightId);
    if (leftNumeric && rightNumeric) {
      const leftValue = BigInt(leftId);
      const rightValue = BigInt(rightId);
      if (leftValue !== rightValue) return leftValue < rightValue ? -1 : 1;
      continue;
    }
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    if (leftId !== rightId) return leftId < rightId ? -1 : 1;
  }
  return 0;
}

export function compareVersions(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  if (a === null || b === null) return null;
  for (const field of ["major", "minor", "patch"]) {
    if (a[field] !== b[field]) return a[field] < b[field] ? -1 : 1;
  }
  return comparePrerelease(a.prerelease, b.prerelease);
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

function isInstalledDirectory(candidate) {
  try {
    return statSync(candidate).isDirectory();
  } catch {
    return false;
  }
}

function scanNodeModules(directory, seen = new Set()) {
  if (!existsSync(directory)) return;
  let realDirectory;
  try {
    realDirectory = realpathSync(directory);
  } catch {
    return;
  }
  if (seen.has(realDirectory)) return;
  seen.add(realDirectory);
  for (const entry of readdirSync(realDirectory, { withFileTypes: true })) {
    if (entry.name === ".bin") continue;
    const candidate = join(realDirectory, entry.name);
    // Dirent.isDirectory() is false for a symlink, which is how some installs
    // place a package. stat follows the link; a cycle is stopped by seen.
    if (!isInstalledDirectory(candidate)) continue;
    if (entry.name.startsWith("@")) {
      for (const scoped of readdirSync(candidate, { withFileTypes: true })) {
        const packageDirectory = join(candidate, scoped.name);
        if (!isInstalledDirectory(packageDirectory)) continue;
        readPackage(packageDirectory);
        scanNodeModules(join(packageDirectory, "node_modules"), seen);
      }
    } else {
      readPackage(candidate);
      scanNodeModules(join(candidate, "node_modules"), seen);
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
