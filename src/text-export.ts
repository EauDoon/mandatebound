/**
 * Internal escaping shared by the Markdown and CSV exports of CasePack reports
 * and AP2 evidence timelines. This module is not in the package exports map;
 * `csvCell` stays public through `@oonyl/mandatebound/report`.
 */

/** Escape a value for inline Markdown text, collapsing line breaks to a space. */
export function markdownText(value: string): string {
  // Make terminal controls and invisible direction/format overrides visible.
  // Do this before Markdown escaping so the diagnostic backslash stays literal.
  const visible = value.replace(/[\r\n]+/g, " ").replace(/[\p{Cc}\p{Cf}]/gu,
    (char) => {
      const code = char.codePointAt(0)!;
      return code > 0xffff ? `\\u{${code.toString(16)}}` : `\\u${code.toString(16).padStart(4, "0")}`;
    });
  return visible.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replace(/[\\`*_{}\[\]()#+.!|>-]/g, "\\$&").replace(/[\r\n]+/g, " ");
}

function needsFormulaNeutralization(text: string): boolean {
  // A leading tab, CR, or LF is itself a spreadsheet trigger.
  if (/^[\t\r\n]/u.test(text)) return true;
  // Spreadsheets skip whitespace, controls, and Unicode format characters
  // (zero-width space, word joiner, BOM) before =, +, -, or @.
  const stripped = text.replace(/^[\s\p{Cf}\u0000-\u001F\u007F]+/u, "");
  return /^[=+@-]/.test(stripped);
}

/** One RFC 4180 cell, quoted, with spreadsheet formulas neutralized. */
export function csvCell(value: string | number): string {
  const text = String(value);
  const safe = needsFormulaNeutralization(text) ? `'${text}` : text;
  return `"${safe.replaceAll('"', '""')}"`;
}
