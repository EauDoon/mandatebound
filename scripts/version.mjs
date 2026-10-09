import { existsSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/*
 * One source of truth for the package release: package.json `version`.
 *
 *   node scripts/version.mjs check [--tag vX.Y.Z]   fail on any drift
 *   node scripts/version.mjs sync                   propagate the version
 *   node scripts/version.mjs notes X.Y.Z            print release notes
 *
 * Every command accepts `--root DIR` so the tests can run it against a
 * fixture tree. Without it the repository is resolved from this script's own
 * location, like the other scripts, so the caller's cwd never matters.
 *
 * `sync` edits each target in place with a single targeted replacement and
 * never re-serializes a JSON document: openapi/openapi.json does not survive a
 * JSON.stringify round trip, and a rewrite would bury the one changed line.
 */

const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/u;
const RELEASE_LITERAL = /^(export const RELEASE_VERSION = ")([^"]*)(" as const;)$/gmu;
const RELEASED_HEADING = /^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})$/u;
const UNRELEASED_HEADING = "## [Unreleased]";
const LINK_REFERENCE = /^\[([^\]]+)\]: (\S+)$/u;

class VersionError extends Error {
  constructor(file, message) {
    super(`${file}: ${message}`);
    this.file = file;
  }
}

function readText(root, file) {
  const path = join(root, file);
  if (!existsSync(path)) {
    throw new VersionError(file, "is missing");
  }
  return readFileSync(path, "utf8");
}

function readJson(root, file) {
  const text = readText(root, file);
  try {
    return { text, value: JSON.parse(text) };
  } catch {
    throw new VersionError(file, "is not valid JSON");
  }
}

function packageVersion(root) {
  const { value } = readJson(root, "package.json");
  const version = value?.version;
  if (typeof version !== "string" || !SEMVER.test(version)) {
    throw new VersionError("package.json", "version must be a plain X.Y.Z release");
  }
  return version;
}

function conformanceFile(version) {
  const [, major, minor] = SEMVER.exec(version);
  return `conformance/v${major}.${minor}/capabilities.json`;
}

function repositoryUrl(root) {
  const { value } = readJson(root, "package.json");
  const raw = typeof value?.repository === "string" ? value.repository : value?.repository?.url;
  if (typeof raw !== "string") return undefined;
  return raw.replace(/^git\+/u, "").replace(/\.git$/u, "");
}

function releaseLiterals(text) {
  return [...text.matchAll(RELEASE_LITERAL)];
}

function isCalendarDate(value) {
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

function parseChangelog(text) {
  const lines = text.split("\n");
  const headings = [];
  const references = new Map();
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.startsWith("## ")) headings.push({ line, index });
    const reference = LINK_REFERENCE.exec(line);
    if (reference) references.set(reference[1], reference[2]);
  }
  return { lines, headings, references };
}

function checkChangelog(root, version, problems) {
  const file = "CHANGELOG.md";
  let text;
  try {
    text = readText(root, file);
  } catch (error) {
    problems.push(error.message);
    return;
  }
  const { headings, references } = parseChangelog(text);
  if (headings[0]?.line !== UNRELEASED_HEADING) {
    problems.push(`${file}: the first section must be "${UNRELEASED_HEADING}"`);
  }
  const released = [];
  for (const heading of headings) {
    if (heading.line === UNRELEASED_HEADING) continue;
    const match = RELEASED_HEADING.exec(heading.line);
    if (!match || !isCalendarDate(match[2])) {
      problems.push(`${file}: "${heading.line}" is not a "## [X.Y.Z] - YYYY-MM-DD" release heading`);
      continue;
    }
    released.push(match[1]);
  }
  if (released.length === 0) {
    problems.push(`${file}: has no dated release section`);
  } else if (released[0] !== version) {
    problems.push(`${file}: newest release section is ${released[0]}, expected ${version}`);
  }
  for (const name of ["Unreleased", ...released]) {
    if (!references.has(name)) {
      problems.push(`${file}: section [${name}] has no link reference`);
    }
  }
  const unreleasedLink = references.get("Unreleased");
  if (unreleasedLink !== undefined && !unreleasedLink.endsWith(`/compare/v${version}...HEAD`)) {
    problems.push(`${file}: the [Unreleased] link must compare v${version}...HEAD`);
  }
}

/** Return every drift problem as a `file: message` string, empty when aligned. */
export function checkVersions(root, { tag } = {}) {
  const problems = [];
  let version;
  try {
    version = packageVersion(root);
  } catch (error) {
    return [error.message];
  }

  const expect = (file, label, actual) => {
    if (actual !== version) {
      problems.push(`${file}: ${label} is ${JSON.stringify(actual)}, expected ${JSON.stringify(version)}`);
    }
  };
  const guarded = (action) => {
    try {
      action();
    } catch (error) {
      if (!(error instanceof VersionError)) throw error;
      problems.push(error.message);
    }
  };

  guarded(() => {
    const { value } = readJson(root, "package-lock.json");
    expect("package-lock.json", "version", value?.version);
    expect("package-lock.json", 'packages[""].version', value?.packages?.[""]?.version);
  });
  guarded(() => {
    const literals = releaseLiterals(readText(root, "src/version.ts"));
    if (literals.length !== 1) {
      throw new VersionError("src/version.ts", "must declare exactly one RELEASE_VERSION string literal");
    }
    expect("src/version.ts", "RELEASE_VERSION", literals[0][2]);
  });
  guarded(() => {
    const file = conformanceFile(version);
    const { value } = readJson(root, file);
    expect(file, "release", value?.release);
  });
  guarded(() => {
    const { value } = readJson(root, "openapi/openapi.json");
    expect("openapi/openapi.json", "info.version", value?.info?.version);
  });
  checkChangelog(root, version, problems);
  if (tag !== undefined && tag !== `v${version}`) {
    problems.push(`release tag: ${JSON.stringify(tag)} does not equal "v${version}"`);
  }
  return problems;
}

function replaceOnce(file, text, pattern, replacement) {
  const matches = [...text.matchAll(new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`))];
  if (matches.length !== 1) {
    throw new VersionError(file, `expected exactly one version field to update, found ${matches.length}`);
  }
  const [match] = matches;
  return text.slice(0, match.index) + replacement(match) + text.slice(match.index + match[0].length);
}

function sameExcept(before, after, path) {
  const strip = (value) => {
    const copy = structuredClone(value);
    let cursor = copy;
    for (const key of path.slice(0, -1)) cursor = cursor?.[key];
    if (cursor && typeof cursor === "object") delete cursor[path.at(-1)];
    return JSON.stringify(copy);
  };
  return strip(before) === strip(after);
}

/**
 * Propagate package.json `version` into the RELEASE_VERSION literal, the
 * conformance declaration for that major.minor, and OpenAPI `info.version`.
 * Returns the list of files that changed. Nothing is written unless every
 * target can be updated and still parses to the same document apart from the
 * one version field.
 */
export function syncVersions(root) {
  const version = packageVersion(root);
  const writes = [];

  const versionTs = readText(root, "src/version.ts");
  if (releaseLiterals(versionTs).length !== 1) {
    throw new VersionError("src/version.ts", "must declare exactly one RELEASE_VERSION string literal");
  }
  writes.push({
    file: "src/version.ts",
    before: versionTs,
    after: versionTs.replace(RELEASE_LITERAL, (_, head, __, tail) => `${head}${version}${tail}`),
  });

  const capabilities = conformanceFile(version);
  if (!existsSync(join(root, capabilities))) {
    throw new VersionError(
      capabilities,
      "is missing; move the previous conformance declaration to this path before syncing",
    );
  }
  const capabilitiesDocument = readJson(root, capabilities);
  const capabilitiesAfter = replaceOnce(
    capabilities,
    capabilitiesDocument.text,
    /^( {2}"release": ")([^"]*)(",?)$/mu,
    (match) => `${match[1]}${version}${match[3]}`,
  );
  writes.push({ file: capabilities, before: capabilitiesDocument.text, after: capabilitiesAfter, path: ["release"] });

  const openapi = readJson(root, "openapi/openapi.json");
  const openapiAfter = replaceOnce(
    "openapi/openapi.json",
    openapi.text,
    /("info"\s*:\s*\{[^{}]*?"version"\s*:\s*")([^"]*)(")/u,
    (match) => `${match[1]}${version}${match[3]}`,
  );
  writes.push({ file: "openapi/openapi.json", before: openapi.text, after: openapiAfter, path: ["info", "version"] });

  for (const write of writes) {
    if (!write.path) continue;
    const before = JSON.parse(write.before);
    const after = JSON.parse(write.after);
    let cursor = after;
    for (const key of write.path) cursor = cursor?.[key];
    if (cursor !== version || !sameExcept(before, after, write.path)) {
      throw new VersionError(write.file, "a targeted update would change more than the version field");
    }
  }

  const changed = [];
  for (const write of writes) {
    if (write.after === write.before) continue;
    writeFileSync(join(root, write.file), write.after);
    changed.push(write.file);
  }
  return { version, changed };
}

/**
 * Return the body of the `## [X.Y.Z]` CHANGELOG section for a GitHub Release.
 * Relative Markdown links are rewritten to the tagged tree, because a release
 * page would otherwise resolve them against its own URL.
 */
export function releaseNotes(root, version) {
  if (!SEMVER.test(version)) {
    throw new VersionError("notes", "expects a plain X.Y.Z release version");
  }
  const { lines, headings } = parseChangelog(readText(root, "CHANGELOG.md"));
  const position = headings.findIndex((heading) => {
    const match = RELEASED_HEADING.exec(heading.line);
    return match?.[1] === version;
  });
  if (position < 0) {
    throw new VersionError("CHANGELOG.md", `has no dated [${version}] section`);
  }
  const start = headings[position].index + 1;
  let end = headings[position + 1]?.index ?? lines.length;
  for (let index = start; index < end; index += 1) {
    if (LINK_REFERENCE.test(lines[index])) {
      end = index;
      break;
    }
  }
  const body = lines.slice(start, end).join("\n").trim();
  if (body.length === 0) {
    throw new VersionError("CHANGELOG.md", `section [${version}] is empty`);
  }
  const repository = repositoryUrl(root);
  const rewritten = repository === undefined
    ? body
    : body.replace(/\]\((?!https?:|mailto:|#)([^)\s]+)\)/gu, (_, target) => {
      return `](${repository}/blob/v${version}/${target.replace(/^\.\//u, "")})`;
    });
  return `${rewritten}\n`;
}

function parseArguments(argv) {
  const positional = [];
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--root" || argument === "--tag") {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("--")) {
        throw new VersionError("usage", `${argument} needs a value`);
      }
      options[argument.slice(2)] = value;
      index += 1;
    } else if (argument.startsWith("--")) {
      throw new VersionError("usage", `unknown option ${argument}`);
    } else {
      positional.push(argument);
    }
  }
  return { positional, options };
}

const USAGE = "node scripts/version.mjs check [--tag vX.Y.Z] | sync | notes X.Y.Z [--root DIR]";

export function main(argv) {
  const { positional, options } = parseArguments(argv);
  const root = options.root === undefined
    ? fileURLToPath(new URL("..", import.meta.url))
    : resolve(options.root);
  const [command, value, ...rest] = positional;

  if (command === "check" && value === undefined) {
    const problems = checkVersions(root, { tag: options.tag });
    if (problems.length > 0) {
      for (const problem of problems) process.stderr.write(`version check failed: ${problem}\n`);
      return 1;
    }
    const version = packageVersion(root);
    const suffix = options.tag === undefined ? "" : ` and tag ${options.tag}`;
    process.stdout.write(`version check: ${version} agrees across the manifest, lockfile, source, conformance, OpenAPI and CHANGELOG${suffix}\n`);
    return 0;
  }
  if (command === "sync" && value === undefined && options.tag === undefined) {
    const { version, changed } = syncVersions(root);
    const detail = changed.length === 0 ? "already aligned" : `updated ${changed.join(", ")}`;
    process.stdout.write(`version sync: ${version} ${detail}\n`);
    return 0;
  }
  if (command === "notes" && value !== undefined && rest.length === 0 && options.tag === undefined) {
    process.stdout.write(releaseNotes(root, value));
    return 0;
  }
  throw new VersionError("usage", USAGE);
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
  return realpathSync(fileURLToPath(import.meta.url)) === resolvedEntry;
}

if (invokedDirectly()) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (error) {
    if (!(error instanceof VersionError)) throw error;
    process.stderr.write(`version script failed: ${error.message}\n`);
    process.exitCode = error.file === "usage" ? 2 : 1;
  }
}
