import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";
import { lintRepository } from "../scripts/lint.mjs";

/**
 * scripts/lint.mjs is a hand-rolled gate that every pull request passes
 * through, and a false negative in any rule silently disables that check.
 * These tests drive each rule against a fixture tree so a regression in the
 * linter itself is caught by the linter's own suite.
 */

const EM_DASH = String.fromCodePoint(0x2014);
// Built rather than written literally: this repository lints for these exact
// strings, so a test that spells them out fails its own gate.
const UNFINISHED = [["TO", "DO"], ["FIX", "ME"], ["T", "BD"]].map((parts) => parts.join(""));
const HOME_PATHS = [`/${"home"}/${"alice"}/project`, `/${"Users"}/${"bob"}/project`];

function withTree(build) {
  const root = mkdtempSync(join(tmpdir(), "mandatebound-lint-"));
  try {
    build(root);
    return lintRepository(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function write(root, path, contents) {
  const full = join(root, path);
  mkdirSync(join(full, ".."), { recursive: true });
  writeFileSync(full, contents);
}

test("a clean tree reports no findings", () => {
  const result = withTree((root) => {
    write(root, "README.md", "# Title\n\nA clean document.\n");
    write(root, "package.json", '{\n  "name": "fixture",\n  "version": "1.0.0"\n}\n');
    write(root, "src/index.ts", "export const value = 1;\n");
    write(root, "docs/guide.md", "See [other](other.md).\n");
    write(root, "docs/other.md", "# Other\n");
    write(root, "LICENSE", "Apache-2.0\n");
    write(root, ".editorconfig", "root = true\n");
  });
  assert.deepEqual(result.errors, [], result.errors.join("\n"));
  assert.equal(result.files, 7);
});

test("a UTF-8 byte-order mark is reported", () => {
  const result = withTree((root) => write(root, "a.md", `\uFEFF# Title\n`));
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /contains a UTF-8 byte-order mark/);
});

test("a missing final newline is reported, and an empty file is not", () => {
  const missing = withTree((root) => write(root, "a.md", "# Title"));
  assert.equal(missing.errors.length, 1);
  assert.match(missing.errors[0], /does not end with a final newline/);

  const empty = withTree((root) => write(root, "a.md", ""));
  assert.deepEqual(empty.errors, [], "an empty file is not a missing newline");
});

test("CR and CRLF line endings are reported", () => {
  const result = withTree((root) => write(root, "a.md", "# Title\r\nbody\r\n"));
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /contains CR or CRLF line endings/);
});

test("an em dash is reported in prose and in source", () => {
  for (const path of ["a.md", "src/a.ts"]) {
    const result = withTree((root) => write(root, path, `const x = "${EM_DASH}";\n`));
    assert.equal(result.errors.length, 1, path);
    assert.match(result.errors[0], /contains an em dash/);
  }
});

test("private local path markers are reported", () => {
  for (const marker of HOME_PATHS) {
    const result = withTree((root) => write(root, "a.md", `See ${marker}/x\n`));
    assert.equal(result.errors.length, 1, marker);
    assert.match(result.errors[0], /contains a private local path marker/);
  }
  // A relative path fragment that is not a user home must not trip the rule.
  const clean = withTree((root) => write(root, "a.md", "See ./homepage/index.md\n"));
  assert.deepEqual(clean.errors, [], clean.errors.join("\n"));
});

test("unfinished-work markers are reported", () => {
  for (const marker of UNFINISHED) {
    const result = withTree((root) => write(root, "a.md", `${marker}: finish this\n`));
    assert.equal(result.errors.length, 1, marker);
    assert.match(result.errors[0], /contains an unfinished-work marker/);
  }
  // The marker must be a whole word, not a substring of an identifier.
  const clean = withTree((root) => write(root, "a.ts", "const todosDone = true;\n"));
  assert.deepEqual(clean.errors, [], clean.errors.join("\n"));
});

test("trailing whitespace is reported in every text type, including markdown", () => {
  for (const [path, body] of [
    ["a.md", "value  \n"],
    ["a.ts", "value  \n"],
    ["a.json", '{"value":1}  \n'],
  ]) {
    const result = withTree((root) => write(root, path, body));
    assert.equal(result.errors.length, 1, path);
    assert.match(result.errors[0], /line 1 has trailing whitespace/);
  }
});

test("tabs are reported outside markdown", () => {
  const source = withTree((root) => write(root, "a.ts", "const x =\t1;\n"));
  assert.equal(source.errors.length, 1);
  assert.match(source.errors[0], /line 1 contains a tab/);

  // Markdown is allowed tabs, matching the .editorconfig and the linter rule.
  const markdown = withTree((root) => write(root, "a.md", "\tindented\n"));
  assert.deepEqual(markdown.errors, [], markdown.errors.join("\n"));
});

test("invalid JSON is reported, and valid JSON is not", () => {
  const broken = withTree((root) => write(root, "a.json", "{ oops }\n"));
  assert.equal(broken.errors.length, 1);
  assert.match(broken.errors[0], /is not valid JSON/);

  const valid = withTree((root) => write(root, "a.json", '{"ok":true}\n'));
  assert.deepEqual(valid.errors, [], valid.errors.join("\n"));
});

test("markdown links are checked for existence and for escaping the root", () => {
  const broken = withTree((root) => {
    write(root, "README.md", "See [missing](nope.md).\n");
  });
  assert.equal(broken.errors.length, 1);
  assert.match(broken.errors[0], /broken or escaping relative link: nope\.md/);

  const escaping = withTree((root) => {
    write(root, "README.md", "See [out](../outside.md).\n");
  });
  assert.equal(escaping.errors.length, 1);
  assert.match(escaping.errors[0], /broken or escaping relative link/);

  // External, anchor and mailto links are not resolved against the tree.
  const external = withTree((root) => {
    write(root, "README.md", [
      "[ext](https://example.com/x)",
      "[anchor](#section)",
      "[mail](mailto:a@example.com)",
      "[ok](present.md)",
      "",
    ].join("\n"));
    write(root, "present.md", "# Present\n");
  });
  assert.deepEqual(external.errors, [], external.errors.join("\n"));
});

test("a link into a sibling directory that extends the root name is an escape", () => {
  const root = mkdtempSync(join(tmpdir(), "mandatebound-lint-"));
  const sibling = `${root}-outside`;
  try {
    mkdirSync(sibling, { recursive: true });
    writeFileSync(join(sibling, "secret.md"), "# Secret\n");
    write(root, "README.md", `See [secret](../${basename(sibling)}/secret.md).\n`);
    const result = lintRepository(root);
    assert.equal(
      result.errors.some((error) => error.includes("broken or escaping relative link")),
      true,
      result.errors.join("\n"),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(sibling, { recursive: true, force: true });
  }
});

test("a malformed percent-encoding in a markdown link is reported", () => {
  const result = withTree((root) => {
    write(root, "README.md", "See [bad](file%zz.md).\n");
  });
  assert.equal(
    result.errors.some((error) => error.includes("broken or escaping relative link")),
    true,
    result.errors.join("\n"),
  );
});

test("the linter ignores generated and vendored directories", () => {
  const result = withTree((root) => {
    for (const skipped of [".git", "coverage", "dist", "node_modules"]) {
      mkdirSync(join(root, skipped, "nested"), { recursive: true });
      writeFileSync(join(root, skipped, "nested", "bad.md"), `${EM_DASH} trailing  `);
    }
    write(root, "a.md", "# Clean\n");
  });
  assert.deepEqual(result.errors, [], result.errors.join("\n"));
  assert.equal(result.files, 1);
});
