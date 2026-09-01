import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const root = resolve("node_modules");
const allowed = new Set(["Apache-2.0", "BSD-3-Clause", "MIT"]);
const packages = [];
const issues = [];

function readPackage(directory) {
  const manifestPath = join(directory, "package.json");
  if (!existsSync(manifestPath)) {
    return;
  }
  try {
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    packages.push({
      name: String(manifest.name ?? "unknown"),
      version: String(manifest.version ?? "unknown"),
      license: String(manifest.license ?? "missing"),
    });
  } catch {
    issues.push("dependency manifest could not be parsed");
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
        const packageDirectory = join(candidate, scoped.name);
        readPackage(packageDirectory);
        scanNodeModules(join(packageDirectory, "node_modules"));
      }
    } else {
      readPackage(candidate);
      scanNodeModules(join(candidate, "node_modules"));
    }
  }
}

scanNodeModules(root);

for (const dependency of packages) {
  if (!allowed.has(dependency.license)) {
    issues.push(`${dependency.name}@${dependency.version} has unapproved license ${dependency.license}`);
  }
}

if (issues.length > 0) {
  for (const issue of issues) {
    process.stderr.write(`license check failed: ${issue}\n`);
  }
  process.exit(1);
}

process.stdout.write(`license check: ${packages.length} installed packages use approved licenses\n`);
