import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const skippedDirectories = new Set([".git", "coverage", "dist", "node_modules"]);
const textExtensions = new Set([".cff", ".json", ".md", ".mjs", ".ts", ".txt", ".yaml", ".yml"]);
const textNames = new Set([
  ".editorconfig",
  ".gitattributes",
  ".gitignore",
  "LICENSE",
]);
const emDash = String.fromCodePoint(0x2014);
const unfinishedTokens = [["TO", "DO"], ["FIX", "ME"], ["T", "BD"]].map((parts) => parts.join(""));
const unfinishedPattern = new RegExp(`\\b(?:${unfinishedTokens.join("|")})\\b`, "u");
const windowsPathSeparator = String.fromCodePoint(0x5c);
const regexWindowsPathSeparator = windowsPathSeparator.repeat(2);
const escapedLineFeed = `${windowsPathSeparator}n`;
const escapedCarriageReturn = `${windowsPathSeparator}r`;
const windowsAbsolutePathPattern = new RegExp(
  `[A-Za-z]:${regexWindowsPathSeparator}[^${regexWindowsPathSeparator}${escapedLineFeed}${escapedCarriageReturn}]+`,
  "u",
);
const unixUserHomePathPattern = /\/(?:home|Users)\/[^/\s]+/u;
const errors = [];
const files = [];

function walk(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!skippedDirectories.has(entry.name)) {
        walk(join(directory, entry.name));
      }
      continue;
    }
    const fullPath = join(directory, entry.name);
    if (textExtensions.has(extname(entry.name)) || textNames.has(entry.name)) {
      files.push(fullPath);
    }
  }
}

function report(file, message) {
  errors.push(`${relative(root, file)}: ${message}`);
}

function checkMarkdownLinks(file, text) {
  const linkPattern = /\[[^\]]+\]\(([^)]+)\)/g;
  for (const match of text.matchAll(linkPattern)) {
    const rawTarget = match[1]?.trim();
    if (!rawTarget || /^(?:https?:|mailto:|#)/i.test(rawTarget)) {
      continue;
    }
    const withoutTitle = rawTarget.split(/\s+["']/u, 1)[0] ?? rawTarget;
    const target = decodeURIComponent(withoutTitle.replace(/^<|>$/g, "").split("#", 1)[0] ?? "");
    if (!target) {
      continue;
    }
    const resolved = resolve(dirname(file), target);
    if (!resolved.startsWith(root) || !existsSync(resolved)) {
      report(file, `broken or escaping relative link: ${target}`);
    }
  }
}

walk(root);

for (const file of files) {
  const size = statSync(file).size;
  if (size > 1_500_000) {
    report(file, `text file exceeds 1.5 MB (${size} bytes)`);
    continue;
  }

  let text;
  try {
    const bytes = readFileSync(file);
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    report(file, "is not valid UTF-8");
    continue;
  }

  if (text.startsWith("\uFEFF")) {
    report(file, "contains a UTF-8 byte-order mark");
  }
  if (text.includes("\r")) {
    report(file, "contains CR or CRLF line endings");
  }
  if (text.includes(emDash)) {
    report(file, "contains an em dash, which public prose forbids");
  }
  if (windowsAbsolutePathPattern.test(text) || unixUserHomePathPattern.test(text)) {
    report(file, "contains a private local path marker");
  }
  if (unfinishedPattern.test(text)) {
    report(file, "contains an unfinished-work marker");
  }

  const lines = text.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (/[ \t]+$/u.test(line)) {
      report(file, `line ${index + 1} has trailing whitespace`);
    }
    if (line.includes("\t") && extname(file) !== ".md") {
      report(file, `line ${index + 1} contains a tab`);
    }
  }

  if (extname(file) === ".json") {
    try {
      JSON.parse(text);
    } catch {
      report(file, "is not valid JSON");
    }
  }
  if (extname(file) === ".md") {
    checkMarkdownLinks(file, text);
  }
}

if (errors.length > 0) {
  for (const error of errors) {
    process.stderr.write(`${error}\n`);
  }
  process.exitCode = 1;
} else {
  process.stdout.write(`lint: ${files.length} text files checked\n`);
}
