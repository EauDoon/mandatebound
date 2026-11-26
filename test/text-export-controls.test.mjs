import assert from "node:assert/strict";
import test from "node:test";
import { markdownText } from "../dist/text-export.js";

test("Markdown exposes terminal controls and invisible direction overrides", () => {
  for (const char of ["\u0000", "\u001b", "\u007f", "\u0085", "\u202e", "\u2066", "\u200b", "\ufeff", "\u{e0001}"]) {
    const rendered = markdownText(`before${char}after`);
    assert.equal(rendered.includes(char), false);
    const code = char.codePointAt(0);
    const escaped = code > 0xffff ? `\\\\u\\{${code.toString(16)}\\}` : `\\\\u${code.toString(16).padStart(4, "0")}`;
    assert.equal(rendered, `before${escaped}after`);
  }
});

test("Markdown retains ordinary Unicode and existing line and syntax escaping", () => {
  assert.equal(markdownText("雪 café 💡"), "雪 café 💡");
  assert.equal(markdownText("first\r\nsecond\nthird"), "first second third");
  assert.equal(markdownText("first\u2028second\u2029third"), "first second third");
  assert.equal(markdownText("[link](https://example.test)|<tag>"), "\\[link\\]\\(https://example\\.test\\)\\|&lt;tag&gt;");
  assert.equal(markdownText("a\tb"), "a\\\\u0009b");
});
