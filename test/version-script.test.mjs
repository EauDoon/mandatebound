import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("../scripts/version.mjs", import.meta.url));

// openapi.json is deliberately written in a shape JSON.stringify would not
// reproduce (inline objects, a second "version" key elsewhere), so a sync that
// re-serializes the document instead of editing one line fails the
// byte-identity assertions below.
const OPENAPI = `{
  "openapi": "3.1.0",
  "info": {
    "title": "Fixture API",
    "version": "1.2.0",
    "summary": "fixture"
  },
  "tags": [
    { "name": "Verification" },
    { "name": "Evaluations" }
  ],
  "components": { "schemas": { "Version": { "type": "object", "properties": { "version": { "const": "1.2.0" } } } } }
}
`;

const CHANGELOG = `# Changelog

Preamble.

## [Unreleased]

### Added

- Something new.

## [1.2.0] - 2026-07-26

### Added

- Added the [boundary guide](docs/GUIDE.md) and [upstream](https://example.com/x).

### Compatibility

- Preserved bytes.

## [1.1.0] - 2026-07-23

- Older entry.

[Unreleased]: https://github.com/example/fixture/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/example/fixture/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/example/fixture/tree/v1.1.0
`;

function fixtureFiles(version = "1.2.0") {
  return {
    "package.json": `${JSON.stringify({
      name: "fixture",
      version,
      repository: { type: "git", url: "git+https://github.com/example/fixture.git" },
    }, null, 2)}\n`,
    "package-lock.json": `${JSON.stringify({
      name: "fixture",
      version,
      lockfileVersion: 3,
      packages: { "": { name: "fixture", version } },
    }, null, 2)}\n`,
    "src/version.ts": [
      'export const PROTOCOL_VERSION = "1.0.0" as const;',
      'export const ENGINE_VERSION = "1.0.0" as const;',
      `export const RELEASE_VERSION = "${version}" as const;`,
      'export const LEGAL_EFFECT = "not-determined" as const;',
      "",
    ].join("\n"),
    "conformance/v1.2/capabilities.json": `{\n  "release": "${version}",\n  "claim": "bounded-evidence-profile",\n  "fixtureTests": ["a", "b"]\n}\n`,
    "openapi/openapi.json": OPENAPI,
    "CHANGELOG.md": CHANGELOG,
  };
}

function withTree(files, action) {
  const root = mkdtempSync(join(tmpdir(), "mandatebound-version-"));
  try {
    for (const [file, text] of Object.entries(files)) {
      mkdirSync(dirname(join(root, file)), { recursive: true });
      writeFileSync(join(root, file), text);
    }
    return action(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function run(root, ...args) {
  return spawnSync(process.execPath, [script, ...args, "--root", root], { encoding: "utf8" });
}

function read(root, file) {
  return readFileSync(join(root, file), "utf8");
}

test("version check passes an aligned tree, with or without the matching tag", () => {
  withTree(fixtureFiles(), (root) => {
    const plain = run(root, "check");
    assert.equal(plain.status, 0, plain.stderr);
    assert.match(plain.stdout, /version check: 1\.2\.0 agrees/u);
    const tagged = run(root, "check", "--tag", "v1.2.0");
    assert.equal(tagged.status, 0, tagged.stderr);
    assert.match(tagged.stdout, /and tag v1\.2\.0/u);
  });
});

const drifts = [
  {
    name: "lockfile top-level version",
    edit: (files) => ({ ...files, "package-lock.json": files["package-lock.json"].replace('"version": "1.2.0",\n  "lockfileVersion"', '"version": "1.1.0",\n  "lockfileVersion"') }),
    expected: /package-lock\.json: version is "1\.1\.0", expected "1\.2\.0"/u,
  },
  {
    name: "lockfile root package version",
    edit: (files) => ({ ...files, "package-lock.json": files["package-lock.json"].replace(/("fixture",\n\s+"version": )"1\.2\.0"(\n\s+\})/u, '$1"1.1.0"$2') }),
    expected: /package-lock\.json: packages\[""\]\.version is "1\.1\.0"/u,
  },
  {
    name: "src/version.ts literal",
    edit: (files) => ({ ...files, "src/version.ts": files["src/version.ts"].replace('RELEASE_VERSION = "1.2.0"', 'RELEASE_VERSION = "1.1.9"') }),
    expected: /src\/version\.ts: RELEASE_VERSION is "1\.1\.9"/u,
  },
  {
    name: "missing conformance directory",
    edit: (files) => {
      const next = { ...files };
      delete next["conformance/v1.2/capabilities.json"];
      next["conformance/v1.1/capabilities.json"] = files["conformance/v1.2/capabilities.json"];
      return next;
    },
    expected: /conformance\/v1\.2\/capabilities\.json: is missing/u,
  },
  {
    name: "conformance release",
    edit: (files) => ({ ...files, "conformance/v1.2/capabilities.json": files["conformance/v1.2/capabilities.json"].replace('"release": "1.2.0"', '"release": "1.1.0"') }),
    expected: /conformance\/v1\.2\/capabilities\.json: release is "1\.1\.0"/u,
  },
  {
    name: "OpenAPI info.version",
    edit: (files) => ({ ...files, "openapi/openapi.json": OPENAPI.replace('"version": "1.2.0"', '"version": "1.0.0"') }),
    expected: /openapi\/openapi\.json: info\.version is "1\.0\.0"/u,
  },
  {
    name: "missing [Unreleased] heading",
    edit: (files) => ({ ...files, "CHANGELOG.md": CHANGELOG.replace("## [Unreleased]\n\n### Added\n\n- Something new.\n\n", "") }),
    expected: /CHANGELOG\.md: the first section must be "## \[Unreleased\]"/u,
  },
  {
    name: "undated first release heading",
    edit: (files) => ({ ...files, "CHANGELOG.md": CHANGELOG.replace("## [1.2.0] - 2026-07-26", "## [1.2.0]") }),
    expected: /CHANGELOG\.md: "## \[1\.2\.0\]" is not a "## \[X\.Y\.Z\] - YYYY-MM-DD" release heading/u,
  },
  {
    name: "impossible release date",
    edit: (files) => ({ ...files, "CHANGELOG.md": CHANGELOG.replace("2026-07-26", "2026-02-30") }),
    expected: /"## \[1\.2\.0\] - 2026-02-30" is not a/u,
  },
  {
    name: "stale first release heading",
    edit: (files) => ({
      ...files,
      "CHANGELOG.md": CHANGELOG
        .replace("## [1.2.0] - 2026-07-26\n\n### Added\n\n- Added the [boundary guide](docs/GUIDE.md) and [upstream](https://example.com/x).\n\n### Compatibility\n\n- Preserved bytes.\n\n", "")
        .replace("[1.2.0]: https://github.com/example/fixture/compare/v1.1.0...v1.2.0\n", ""),
    }),
    expected: /CHANGELOG\.md: newest release section is 1\.1\.0, expected 1\.2\.0/u,
  },
  {
    name: "missing link reference",
    edit: (files) => ({ ...files, "CHANGELOG.md": CHANGELOG.replace("[1.1.0]: https://github.com/example/fixture/tree/v1.1.0\n", "") }),
    expected: /CHANGELOG\.md: section \[1\.1\.0\] has no link reference/u,
  },
  {
    name: "stale [Unreleased] comparison base",
    edit: (files) => ({ ...files, "CHANGELOG.md": CHANGELOG.replace("compare/v1.2.0...HEAD", "compare/v1.1.0...HEAD") }),
    expected: /CHANGELOG\.md: the \[Unreleased\] link must compare v1\.2\.0\.\.\.HEAD/u,
  },
];

for (const drift of drifts) {
  test(`version check fails and names the file on ${drift.name}`, () => {
    withTree(drift.edit(fixtureFiles()), (root) => {
      const result = run(root, "check");
      assert.equal(result.status, 1, result.stdout);
      assert.match(result.stderr, drift.expected);
      assert.equal(result.stdout, "");
    });
  });
}

test("version check rejects a release tag that is not v<package version>", () => {
  withTree(fixtureFiles(), (root) => {
    for (const tag of ["v1.2.1", "1.2.0", "v1.2.0-rc.1"]) {
      const result = run(root, "check", "--tag", tag);
      assert.equal(result.status, 1, tag);
      assert.match(result.stderr, /release tag: .* does not equal "v1\.2\.0"/u);
    }
  });
});

test("version sync edits only the targeted lines and leaves every other byte alone", () => {
  const files = fixtureFiles();
  files["package.json"] = files["package.json"].replace('"version": "1.2.0"', '"version": "1.2.1"');
  withTree(files, (root) => {
    const result = run(root, "sync");
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /updated src\/version\.ts, conformance\/v1\.2\/capabilities\.json, openapi\/openapi\.json/u);
    assert.equal(
      read(root, "src/version.ts"),
      files["src/version.ts"].replace('RELEASE_VERSION = "1.2.0"', 'RELEASE_VERSION = "1.2.1"'),
    );
    assert.equal(
      read(root, "conformance/v1.2/capabilities.json"),
      files["conformance/v1.2/capabilities.json"].replace('"release": "1.2.0"', '"release": "1.2.1"'),
    );
    // Only info.version moves; the unrelated "version" const keeps 1.2.0.
    assert.equal(
      read(root, "openapi/openapi.json"),
      OPENAPI.replace('"title": "Fixture API",\n    "version": "1.2.0"', '"title": "Fixture API",\n    "version": "1.2.1"'),
    );
    assert.match(read(root, "openapi/openapi.json"), /"const": "1\.2\.0"/u);
    // The lockfile and CHANGELOG are npm's and the author's to move.
    assert.equal(read(root, "package-lock.json"), files["package-lock.json"]);
    assert.equal(read(root, "CHANGELOG.md"), CHANGELOG);
    const again = run(root, "sync");
    assert.equal(again.status, 0, again.stderr);
    assert.match(again.stdout, /already aligned/u);
  });
});

test("version sync refuses a new major.minor until the conformance declaration moves", () => {
  const files = fixtureFiles();
  files["package.json"] = files["package.json"].replace('"version": "1.2.0"', '"version": "2.0.0"');
  withTree(files, (root) => {
    const refused = run(root, "sync");
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /conformance\/v2\.0\/capabilities\.json: is missing; move the previous/u);
    assert.equal(read(root, "src/version.ts"), files["src/version.ts"], "nothing may be written on refusal");
    assert.equal(read(root, "openapi/openapi.json"), OPENAPI);

    mkdirSync(join(root, "conformance", "v2.0"));
    renameSync(
      join(root, "conformance", "v1.2", "capabilities.json"),
      join(root, "conformance", "v2.0", "capabilities.json"),
    );
    const moved = run(root, "sync");
    assert.equal(moved.status, 0, moved.stderr);
    assert.match(read(root, "conformance/v2.0/capabilities.json"), /"release": "2\.0\.0"/u);
  });
});

test("version sync refuses an OpenAPI document whose info.version it cannot isolate", () => {
  const files = fixtureFiles();
  files["package.json"] = files["package.json"].replace('"version": "1.2.0"', '"version": "1.2.1"');
  files["openapi/openapi.json"] = OPENAPI.replace(
    '"title": "Fixture API",\n    "version": "1.2.0",',
    '"title": "Fixture API",\n    "contact": { "name": "x" },\n    "version": "1.2.0",',
  );
  withTree(files, (root) => {
    const result = run(root, "sync");
    assert.equal(result.status, 1);
    assert.match(result.stderr, /openapi\/openapi\.json: expected exactly one version field to update, found 0/u);
    assert.equal(read(root, "src/version.ts"), files["src/version.ts"]);
  });
});

test("version notes prints exactly one CHANGELOG section with links pinned to the tag", () => {
  withTree(fixtureFiles(), (root) => {
    const result = run(root, "notes", "1.2.0");
    assert.equal(result.status, 0, result.stderr);
    assert.equal(
      result.stdout,
      [
        "### Added",
        "",
        "- Added the [boundary guide](https://github.com/example/fixture/blob/v1.2.0/docs/GUIDE.md) and [upstream](https://example.com/x).",
        "",
        "### Compatibility",
        "",
        "- Preserved bytes.",
        "",
      ].join("\n"),
    );
    const last = run(root, "notes", "1.1.0");
    assert.equal(last.status, 0, last.stderr);
    assert.equal(last.stdout, "- Older entry.\n", "link references are not part of a section");
    const missing = run(root, "notes", "9.9.9");
    assert.equal(missing.status, 1);
    assert.match(missing.stderr, /CHANGELOG\.md: has no dated \[9\.9\.9\] section/u);
  });
});

test("version script rejects unknown commands and options as usage errors", () => {
  withTree(fixtureFiles(), (root) => {
    for (const args of [["publish"], ["check", "--force"], ["notes"], ["sync", "extra"], ["check", "--tag"]]) {
      const result = spawnSync(process.execPath, [script, ...args, "--root", root], { encoding: "utf8" });
      assert.equal(result.status, 2, args.join(" "));
      assert.match(result.stderr, /usage/u);
    }
  });
});

test("the repository itself passes the version check", () => {
  const result = spawnSync(process.execPath, [script, "check"], { cwd: tmpdir(), encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});
