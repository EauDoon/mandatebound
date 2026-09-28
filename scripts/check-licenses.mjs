import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));
const root = join(repositoryRoot, "node_modules");
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
    // A symlinked package is not a Dirent directory. stat follows the link.
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
