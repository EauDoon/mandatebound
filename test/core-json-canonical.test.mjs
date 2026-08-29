import assert from "node:assert/strict";
import test from "node:test";
import {
  CanonicalizationError,
  canonicalBytes,
  canonicalize,
  contentId,
  digestBytes,
  equalDigest,
  isSha256Digest,
  sha256Bytes,
  sha256Digest,
} from "../dist/canonical.js";
import { parseStrictJson, parseStrictJsonObject, StrictJsonError } from "../dist/strict-json.js";

test("strict JSON rejects duplicate and prototype-sensitive keys", () => {
  assert.throws(() => parseStrictJson('{"a":1,"a":2}'), (error) => error instanceof StrictJsonError && error.code === "ALB_JSON_DUPLICATE_KEY");
  assert.throws(() => parseStrictJson('{"__proto__":1}'), (error) => error instanceof StrictJsonError && error.code === "ALB_JSON_UNSAFE_KEY");
});

test("strict JSON enforces the safe-integer I-JSON subset and bounds", () => {
  assert.throws(() => parseStrictJson('{"n":1.5}'), (error) => error instanceof StrictJsonError && error.code === "ALB_JSON_UNSAFE_NUMBER");
  assert.throws(() => parseStrictJson('{"n":9007199254740992}'), (error) => error instanceof StrictJsonError && error.code === "ALB_JSON_UNSAFE_NUMBER");
  assert.throws(() => parseStrictJson('[[[0]]]', { maxDepth: 2 }), (error) => error instanceof StrictJsonError && error.code === "ALB_JSON_LIMIT");
  assert.throws(() => parseStrictJson('"\\ud800"'), (error) => error instanceof StrictJsonError && error.code === "ALB_JSON_UNPAIRED_SURROGATE");
  const parsed = parseStrictJson('{"ok":[true,null,-7]}');
  assert.deepEqual({ ...parsed }, { ok: [true, null, -7] });
});

test("strict JSON handles escapes and rejects malformed grammar without body reflection", () => {
  assert.equal(parseStrictJson('"a\\n\\t\\u263a\\ud83d\\ude00"'), "a\n\t☺😀");
  for (const malformed of ["\ufeff{}", "[1,]", '{"a" 1}', '{"a":1,}', "tru", '"\\x"', '"unterminated']) {
    assert.throws(() => parseStrictJson(malformed), StrictJsonError);
  }
  assert.throws(() => parseStrictJsonObject("[]"), StrictJsonError);
  assert.throws(() => parseStrictJson("[1,2]", { maxArrayLength: 1 }), (error) => error.code === "ALB_JSON_LIMIT");
  assert.throws(() => parseStrictJson('{"a":1,"b":2}', { maxObjectKeys: 1 }), (error) => error.code === "ALB_JSON_LIMIT");
  assert.throws(() => parseStrictJson('"long"', { maxStringBytes: 2 }), (error) => error.code === "ALB_JSON_LIMIT");
  assert.throws(() => parseStrictJson("null", { maxBytes: 2 }), (error) => error.code === "ALB_JSON_LIMIT");
  assert.throws(() => parseStrictJson("[1,2]", { maxNodes: 2 }), (error) => error.code === "ALB_JSON_LIMIT");
  assert.throws(() => parseStrictJson("null", { maxDepth: 0 }), TypeError);
  for (const malformed of [
    "{} trailing",
    '{"a":1 "b":2}',
    "[1 2]",
    '"bad\\uZZZZ"',
    "-",
    `"raw${String.fromCharCode(1)}control"`,
    `"${String.fromCharCode(0xd800)}"`,
    `"${String.fromCharCode(0xdc00)}"`,
  ]) {
    assert.throws(() => parseStrictJson(malformed), StrictJsonError);
  }
  assert.throws(() => parseStrictJson(42), TypeError);
});

test("canonical JSON uses deterministic RFC 8785 key ordering", () => {
  assert.equal(canonicalize({ z: 1, a: "x", nested: { b: 2, a: 1 } }), '{"a":"x","nested":{"a":1,"b":2},"z":1}');
  assert.equal(canonicalize({ n: -0 }), '{"n":0}');
  assert.throws(() => canonicalize({ n: 1.1 }), CanonicalizationError);
  assert.throws(() => canonicalize({ value: undefined }), CanonicalizationError);
  assert.throws(() => canonicalize(new Date()), CanonicalizationError);
});

test("canonicalization rejects hidden, executable, sparse, and invalid Unicode values", () => {
  const sparse = [];
  sparse.length = 1;
  assert.throws(() => canonicalize(sparse), CanonicalizationError);
  let arrayAccessorCalls = 0;
  const accessorArray = [1];
  Object.defineProperty(accessorArray, "0", { enumerable: true, get: () => ++arrayAccessorCalls });
  assert.throws(() => canonicalize(accessorArray), CanonicalizationError);
  assert.equal(arrayAccessorCalls, 0);
  const decoratedArray = [1];
  decoratedArray.extra = true;
  assert.throws(() => canonicalize(decoratedArray), CanonicalizationError);
  let proxyTrapCalls = 0;
  const proxiedArray = new Proxy([1], {
    getPrototypeOf: (target) => { proxyTrapCalls += 1; return Reflect.getPrototypeOf(target); },
    ownKeys: (target) => { proxyTrapCalls += 1; return Reflect.ownKeys(target); },
  });
  assert.throws(() => canonicalize(proxiedArray), CanonicalizationError);
  assert.equal(proxyTrapCalls, 0);
  assert.throws(() => canonicalize("\ud800"), CanonicalizationError);
  assert.throws(() => canonicalize(() => true), CanonicalizationError);
  const accessor = {};
  Object.defineProperty(accessor, "x", { enumerable: true, get: () => 1 });
  assert.throws(() => canonicalize(accessor), CanonicalizationError);
  const hidden = {};
  Object.defineProperty(hidden, "x", { enumerable: false, value: 1 });
  assert.throws(() => canonicalize(hidden), CanonicalizationError);
  const unsafe = Object.create(null);
  unsafe.__proto__ = 1;
  assert.throws(() => canonicalize(unsafe), CanonicalizationError);
  assert.throws(() => canonicalize({ a: { b: 1 } }, { maxDepth: 1 }), CanonicalizationError);
  assert.throws(() => canonicalize([1, 2], { maxNodes: 2 }), CanonicalizationError);
  assert.throws(() => canonicalize("abc", { maxBytes: 2 }), CanonicalizationError);
  assert.throws(() => canonicalize("\udc00"), CanonicalizationError);
  const symbolKeyed = { visible: true };
  symbolKeyed[Symbol("hidden-channel")] = true;
  assert.throws(() => canonicalize(symbolKeyed), CanonicalizationError);
  assert.throws(() => canonicalize({}, { maxDepth: 0 }), TypeError);
});

test("content identifiers are stable and timing-safe comparable", () => {
  const left = contentId({ b: 2, a: 1 });
  const right = sha256Digest({ a: 1, b: 2 });
  assert.match(left, /^sha256:[a-f0-9]{64}$/);
  assert.equal(left, right);
  assert.equal(equalDigest(left, right), true);
  assert.equal(equalDigest(left, sha256Digest({ a: 2 })), false);
  assert.equal(isSha256Digest(left), true);
  assert.equal(isSha256Digest("sha256:nope"), false);
  assert.equal(digestBytes(left).length, 32);
  assert.throws(() => digestBytes("sha256:nope"), TypeError);
  assert.equal(sha256Bytes(canonicalBytes({ a: 1 })), sha256Digest({ a: 1 }));
  assert.notEqual(sha256Digest("raw"), sha256Digest({ value: "raw" }));
});
