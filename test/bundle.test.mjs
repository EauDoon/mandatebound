import assert from "node:assert/strict";
import test from "node:test";
import {
  computeMerkleRoot,
  createEvidenceBundle,
  evaluationCaseFromBundle,
  isSafeBundlePath,
  verifyEvidenceBundle,
} from "../dist/bundle.js";
import { canonicalBytes, sha256Bytes, sha256Digest } from "../dist/canonical.js";
import { evaluateBundle, evaluateCase } from "../dist/engine.js";
import { buildScenario } from "../dist/simulator.js";

function withoutEmbeddedBundle(input) {
  const { evidenceBundle: _ignored, ...clean } = input;
  return clean;
}

function reseal(candidate) {
  candidate.manifest.entries = candidate.objects
    .map((object) => {
      const existing = candidate.manifest.entries.find((entry) => entry.path === object.path);
      const bytes = canonicalBytes(object.content);
      return {
        path: object.path,
        mediaType: existing?.mediaType ?? "application/agent-liability+json",
        ...(existing?.schemaId === undefined ? {} : { schemaId: existing.schemaId }),
        size: bytes.byteLength,
        classification: existing?.classification ?? "internal",
        digest: sha256Bytes(bytes),
      };
    })
    .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  candidate.objects.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  candidate.manifest.merkleRoot = computeMerkleRoot(candidate.manifest.entries);
  candidate.manifest.manifestDigest = sha256Digest({
    format: candidate.manifest.format,
    evidenceCutoff: candidate.manifest.evidenceCutoff,
    pins: candidate.manifest.pins,
    entries: candidate.manifest.entries,
    merkleRoot: candidate.manifest.merkleRoot,
  });
  candidate.rootDigest = sha256Digest({
    schemaVersion: "1.0.0",
    manifestDigest: candidate.manifest.manifestDigest,
    merkleRoot: candidate.manifest.merkleRoot,
  });
  const hex = candidate.rootDigest.slice("sha256:".length);
  candidate.artifactId = `bundle-${hex.slice(0, 24)}`;
  candidate.bundleId = `urn:agent-liability:bundle:${hex}`;
  return candidate;
}

test("creates a deterministic, schema-closed, portable bundle", () => {
  const input = withoutEmbeddedBundle(buildScenario("principal").input);
  const first = createEvidenceBundle(input);
  const second = createEvidenceBundle(input);
  assert.deepEqual(second, first);
  const report = verifyEvidenceBundle(first);
  assert.equal(report.valid, true);
  assert.equal(report.verifiedEntries, report.totalEntries);
  assert.ok(first.manifest.entries.every((entry, index, entries) =>
    index === 0 || entries[index - 1].path < entry.path));
});

test("one-byte-equivalent content and root mutations fail verification", () => {
  const bundle = createEvidenceBundle(withoutEmbeddedBundle(buildScenario("principal").input));
  const contentTamper = structuredClone(bundle);
  contentTamper.objects[0].content.caseId = "case-synthetix";
  assert.equal(verifyEvidenceBundle(contentTamper).valid, false);

  const rootTamper = structuredClone(bundle);
  rootTamper.rootDigest = `${rootTamper.rootDigest.slice(0, -1)}${rootTamper.rootDigest.endsWith("0") ? "1" : "0"}`;
  assert.equal(verifyEvidenceBundle(rootTamper).valid, false);
});

test("historical replay is byte-identical under external anchors", () => {
  const input = withoutEmbeddedBundle(buildScenario("principal").input);
  const bundle = createEvidenceBundle(input);
  const anchors = {
    pins: input.pins,
    trustRootJwk: input.trustRootJwk,
    expectedBundleRootDigest: bundle.rootDigest,
  };
  const replayInput = evaluationCaseFromBundle(bundle, anchors);
  assert.deepEqual(createEvidenceBundle(replayInput), bundle);
  assert.deepEqual(evaluateBundle(bundle, anchors), evaluateCase(replayInput));
});

test("bundle evaluation without external anchors never allocates", () => {
  const input = withoutEmbeddedBundle(buildScenario("principal").input);
  const bundle = createEvidenceBundle(input);
  const unanchored = evaluateBundle(bundle);
  assert.equal(unanchored.outcome, "unresolved");
  assert.equal(unanchored.disposition, "invalid");
  assert.equal(unanchored.externalAuthenticity, "unestablished");
  assert.equal(unanchored.reasonCodes[0], "ALB_TRUST_ANCHOR_REQUIRED");

  const mismatched = evaluateBundle(bundle, {
    pins: { ...input.pins, engineVersion: "9.9.9" },
    expectedBundleRootDigest: bundle.rootDigest,
  });
  assert.equal(mismatched.outcome, "unresolved");
  assert.equal(mismatched.disposition, "invalid");

  const flattened = evaluateBundle(bundle, {
    ...input.pins,
    trustRootJwk: input.trustRootJwk,
    expectedBundleRootDigest: bundle.rootDigest,
  });
  assert.equal(flattened.outcome, "unresolved");
  assert.equal(flattened.disposition, "invalid");
  assert.equal(flattened.externalAuthenticity, "unestablished");
});

test("a bundled decision remains semantically closed and valid", () => {
  const input = withoutEmbeddedBundle(buildScenario("principal").input);
  const decision = evaluateCase(input);
  const bundle = createEvidenceBundle(input, decision);
  assert.equal(verifyEvidenceBundle(bundle).valid, true);
  assert.ok(bundle.objects.some((object) => object.path === "decision/liability-decision.json"));
});

test("rejects self-consistent unreferenced, omitted, duplicate, and non-contiguous paths", () => {
  const base = createEvidenceBundle(withoutEmbeddedBundle(buildScenario("principal").input));

  const extra = structuredClone(base);
  extra.objects.push({ path: "extra/unreferenced.json", encoding: "jcs-json", content: { extra: true } });
  assert.equal(verifyEvidenceBundle(reseal(extra)).valid, false);

  const omitted = structuredClone(base);
  omitted.objects = omitted.objects.filter((object) => object.path !== "case/index.json");
  assert.equal(verifyEvidenceBundle(reseal(omitted)).valid, false);

  const duplicate = structuredClone(base);
  const index = duplicate.objects.find((object) => object.path === "case/index.json").content;
  index.runtimeEventPaths = [index.runtimeEventPaths[0], index.runtimeEventPaths[0]];
  assert.equal(verifyEvidenceBundle(reseal(duplicate)).valid, false);

  const nonContiguous = structuredClone(base);
  const nonContiguousIndex = nonContiguous.objects.find((object) => object.path === "case/index.json").content;
  const oldPath = nonContiguousIndex.runtimeEventPaths[1];
  const newPath = "evidence/runtime-events/000099.json";
  nonContiguousIndex.runtimeEventPaths[1] = newPath;
  nonContiguous.objects.find((object) => object.path === oldPath).path = newPath;
  nonContiguous.manifest.entries.find((entry) => entry.path === oldPath).path = newPath;
  assert.equal(verifyEvidenceBundle(reseal(nonContiguous)).valid, false);
});

test("rejects cross-type aliases, index-time drift, and schema-invalid metadata", () => {
  const base = createEvidenceBundle(withoutEmbeddedBundle(buildScenario("principal").input));

  const crossType = structuredClone(base);
  const mandate = crossType.objects.find((object) => object.path === "evidence/mandate.json");
  const policy = crossType.objects.find((object) => object.path === "policy/liability-policy.json");
  [mandate.content, policy.content] = [policy.content, mandate.content];
  assert.equal(verifyEvidenceBundle(reseal(crossType)).valid, false);

  const timeDrift = structuredClone(base);
  timeDrift.objects.find((object) => object.path === "case/index.json").content.asOf = "2026-07-22T00:00:00.000Z";
  assert.equal(verifyEvidenceBundle(reseal(timeDrift)).valid, false);

  const badMetadata = structuredClone(base);
  badMetadata.manifest.pins.engineVersion = "not-semver";
  assert.equal(verifyEvidenceBundle(reseal(badMetadata)).valid, false);
});

test("safe path profile is lowercase, relative, bounded, and traversal-free", () => {
  assert.equal(isSafeBundlePath("evidence/runtime-events/000001.json"), true);
  for (const path of ["../escape", "/absolute", "Upper/File.json", "a\\b", "a//b", "a/./b", "a/../b", "x".repeat(241)]) {
    assert.equal(isSafeBundlePath(path), false);
  }
});

test("malformed bundle graphs return a bounded invalid report", () => {
  for (const value of [null, {}, { manifest: null }, { manifest: { entries: [] } }]) {
    const report = verifyEvidenceBundle(value);
    assert.equal(report.valid, false);
    assert.ok(report.issues.length > 0);
  }
});

test("verifier exercises bounded diagnostics for every manifest and entry layer", () => {
  const base = createEvidenceBundle(withoutEmbeddedBundle(buildScenario("principal").input));
  const mutations = [
    (value) => { value.extra = true; },
    (value) => { value.manifest.extra = true; },
    (value) => { value.manifest.pins.extra = true; },
    (value) => { value.manifest.entries = "entries"; },
    (value) => { value.objects = "objects"; },
    (value) => { value.manifest.entries = []; value.objects = []; },
    (value) => { value.objects.pop(); },
    (value) => { value.manifest.entries[0] = null; },
    (value) => { value.manifest.entries[0].extra = true; },
    (value) => { value.manifest.entries[0].path = "../unsafe"; },
    (value) => {
      value.manifest.entries[1].path = value.manifest.entries[0].path;
      value.objects[1].path = value.objects[0].path;
    },
    (value) => { value.manifest.entries.reverse(); value.objects.reverse(); },
    (value) => { value.objects[0] = null; },
    (value) => { value.objects[0].extra = true; },
    (value) => { value.objects[0].path = "different/path.json"; },
    (value) => { value.objects[0].encoding = "base64url"; },
    (value) => { value.manifest.entries[0].size = -1; },
    (value) => { value.manifest.entries[0].digest = `sha256:${"0".repeat(64)}`; },
    (value) => { value.objects[0].content = 1n; },
    (value) => { value.manifest.pins.schemaDigests = "pins"; },
    (value) => { value.manifest.pins.schemaDigests.reverse(); },
    (value) => { value.manifest.evidenceCutoff = "2026-07-22T00:00:00.000Z"; },
    (value) => { value.manifest.merkleRoot = `sha256:${"1".repeat(64)}`; },
    (value) => { value.manifest.manifestDigest = `sha256:${"2".repeat(64)}`; },
    (value) => { value.rootDigest = `sha256:${"3".repeat(64)}`; },
    (value) => { value.bundleId = `urn:agent-liability:bundle:${"4".repeat(64)}`; },
    (value) => { value.proofs = [{ protected: "a", signature: "b" }]; },
  ];
  for (const mutate of mutations) {
    const candidate = structuredClone(base);
    mutate(candidate);
    const report = verifyEvidenceBundle(candidate);
    assert.equal(report.valid, false);
    assert.ok(report.issues.length > 0);
  }
});

test("semantic closure rejects invalid identifiers, timestamps, proof schemas, and pins", () => {
  const base = createEvidenceBundle(withoutEmbeddedBundle(buildScenario("principal").input));
  const mutations = [
    (value) => { value.objects.find((object) => object.path === "case/index.json").content.caseId = "#invalid"; },
    (value) => { value.objects.find((object) => object.path === "case/index.json").content.asOf = "not-a-time"; },
    (value) => {
      const entry = value.manifest.entries.find((candidate) => candidate.path === "evidence/mandate.json");
      entry.schemaId = "https://github.com/Oonyl/mandatebound/schemas/v1/runtime-event.schema.json";
    },
    (value) => {
      const artifact = value.objects.find((object) => object.path === "evidence/mandate.json").content;
      artifact.proofs = [];
    },
    (value) => { value.manifest.pins.policyDigest = `sha256:${"5".repeat(64)}`; },
  ];
  for (const mutate of mutations) {
    const candidate = structuredClone(base);
    mutate(candidate);
    assert.equal(verifyEvidenceBundle(reseal(candidate)).valid, false);
  }
});

test("rejects duplicate artifact ids, duplicate sequences, extra index keys, and non-protocol media types", () => {
  const base = createEvidenceBundle(withoutEmbeddedBundle(buildScenario("principal").input));

  const duplicateId = structuredClone(base);
  const events = duplicateId.objects.filter((object) => object.path.startsWith("evidence/runtime-events/"));
  assert.ok(events.length >= 2);
  events[1].content = structuredClone(events[0].content);
  const duplicateIdReport = verifyEvidenceBundle(reseal(duplicateId));
  assert.equal(duplicateIdReport.valid, false);
  assert.ok(duplicateIdReport.issues.some((entry) =>
    entry.message === "Bundle artifact identifiers must be unique"
    || entry.message === "Runtime event sequences must be unique"));

  const extraIndexKey = structuredClone(base);
  extraIndexKey.objects.find((object) => object.path === "case/index.json").content.note = "sidecar";
  assert.equal(verifyEvidenceBundle(reseal(extraIndexKey)).valid, false);

  const decoratedPaths = structuredClone(base);
  const decoratedIndex = decoratedPaths.objects.find((object) => object.path === "case/index.json").content;
  decoratedIndex.runtimeEventPaths.extra = true;
  const decoratedReport = verifyEvidenceBundle(decoratedPaths);
  assert.equal(decoratedReport.valid, false);
  assert.ok(decoratedReport.issues.some((entry) =>
    entry.message === "Bundle case index is missing or invalid"));

  const oversized = structuredClone(base);
  const oversizedIndex = oversized.objects.find((object) => object.path === "case/index.json").content;
  oversizedIndex.runtimeEventPaths = Array.from(
    { length: 10_001 },
    (_unused, index) => `evidence/runtime-events/${String(index).padStart(6, "0")}.json`,
  );
  const oversizedReport = verifyEvidenceBundle(oversized);
  assert.equal(oversizedReport.valid, false);
  assert.ok(oversizedReport.issues.some((entry) =>
    entry.message === "Bundle case index is missing or invalid"));

  const wrongType = structuredClone(base);
  wrongType.objects.find((object) => object.path === "case/index.json").content.runtimeEventPaths = {
    0: "evidence/runtime-events/000000.json",
  };
  assert.equal(verifyEvidenceBundle(reseal(wrongType)).valid, false);

  const mediaType = structuredClone(base);
  mediaType.manifest.entries[0].mediaType = "text/plain";
  const mediaTypeReport = verifyEvidenceBundle(reseal(mediaType));
  assert.equal(mediaTypeReport.valid, false);
  assert.ok(mediaTypeReport.issues.some((entry) =>
    entry.path.endsWith(".mediaType") && entry.message.includes("media type")));

  const classification = structuredClone(base);
  classification.manifest.entries[0].classification = "secret";
  const classificationReport = verifyEvidenceBundle(reseal(classification));
  assert.equal(classificationReport.valid, false);
  assert.ok(classificationReport.issues.some((entry) =>
    entry.path.endsWith(".classification") || entry.code === "ALB_SCHEMA_INVALID"));
});
