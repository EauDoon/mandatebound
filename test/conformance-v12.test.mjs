import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";
import { compareCasePackStatus } from "../dist/casepack-tools.js";
import { getConformanceStatement } from "../dist/conformance.js";
import { RELEASE_VERSION } from "../dist/version.js";

// The release under test comes from package.json, and its declaration lives in
// the conformance directory for that major.minor; nothing here names a release.
const MANIFEST_VERSION = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
const [RELEASE_MAJOR, RELEASE_MINOR] = MANIFEST_VERSION.split(".");
const DECLARATION_URL = new URL(
  `../conformance/v${RELEASE_MAJOR}.${RELEASE_MINOR}/capabilities.json`,
  import.meta.url,
);

test("conformance statement names the exact evidence-import profile and its limits", () => {
  const statement = getConformanceStatement();
  assert.equal(statement.release, MANIFEST_VERSION);
  assert.equal(statement.evidenceProfile.ucpVersion, "2026-04-08");
  assert.equal(statement.evidenceProfile.ucpTransport, "REST");
  assert.equal(statement.evidenceProfile.ap2Version, "0.2.0");
  assert.equal(statement.claim, "bounded-evidence-profile");
  assert.equal(statement.legalEffect, "not-determined");

  const byId = new Map(statement.capabilities.map((entry) => [entry.id, entry]));
  assert.equal(byId.get("ucp_2026_04_08_rest_evidence_import").status, "supported");
  assert.equal(byId.get("ap2_0_2_0_mandates_evidence_import").status, "supported");
  assert.equal(byId.get("ap2_0_2_0_dispute_evidence_resolution").status, "supported");
  assert.equal(byId.get("ap2_0_2_0_evidence_pack").status, "supported");
  assert.match(
    byId.get("ap2_0_2_0_dispute_evidence_resolution").boundary,
    /never a claim outcome/u,
  );
  assert.equal(byId.get("external_evidence_review_v1").status, "supported");
  assert.match(
    byId.get("external_evidence_review_v1").boundary,
    /never re-verified here/u,
  );
  assert.equal(byId.get("ucp_mcp_transport").status, "deferred");
  assert.equal(byId.get("ucp_a2a_transport").status, "deferred");
  assert.equal(byId.get("external_trust_auto_promotion").status, "unsupported");
  assert.equal(byId.get("legal_adjudication").status, "unsupported");
  assert.equal(new Set(statement.capabilities.map((entry) => entry.id)).size, statement.capabilities.length);
});

test("conformance statement is immutable to callers", () => {
  const statement = getConformanceStatement();
  assert.equal(Object.isFrozen(statement), true);
  assert.equal(Object.isFrozen(statement.capabilities), true);
  assert.equal(Object.isFrozen(statement.capabilities[0]), true);
  assert.throws(() => {
    statement.capabilities.push({ id: "extra" });
  }, TypeError);
});

test("published capability declaration for this release matches the runtime statement", () => {
  const published = JSON.parse(readFileSync(
    DECLARATION_URL,
    "utf8",
  ));
  const runtime = getConformanceStatement();
  assert.equal(published.release, runtime.release);
  assert.deepEqual(published.evidenceProfile, runtime.evidenceProfile);
  assert.equal(
    published.disputeProfile.id,
    "ap2-v0.2.0+b4587ac1d055888a73b4b21750973cffba961793",
  );
  assert.equal(published.disputeProfile.legalEffect, "not-determined");
  assert.equal(
    published.disputeProfile.mandateProfileId,
    "ap2-v0.2.0-mandate-chain+b4587ac1d055888a73b4b21750973cffba961793",
  );
  assert.deepEqual(published.disputeProfile.operations, ["resolve", "pack", "verify", "render"]);
  // Every runtime capability, in order, with the status the runtime declares.
  assert.deepEqual(
    published.capabilities,
    runtime.capabilities.map(({ id, status }) => ({ id, status })),
  );
});

test("published fixture list is exactly what npm run conformance executes", () => {
  const published = JSON.parse(readFileSync(
    DECLARATION_URL,
    "utf8",
  ));
  const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  const script = manifest.scripts.conformance;
  const prefix = "npm run build && node --test ";
  assert.ok(script.startsWith(prefix), "conformance script shape changed");
  const executed = script.slice(prefix.length).split(/\s+/u);
  assert.deepEqual(published.fixtureTests, executed);
  assert.equal(new Set(executed).size, executed.length);
  for (const file of executed) {
    assert.match(file, /^test\/[a-z0-9.-]+\.test\.mjs$/u);
    assert.ok(existsSync(new URL(`../${file}`, import.meta.url)), `${file} is missing`);
  }
  // The supported external review capability is backed by its fixture file.
  assert.ok(executed.includes("test/review-external.test.mjs"));
});

test("CasePack assurance status ordering is stable", () => {
  assert.equal(compareCasePackStatus("satisfied", "satisfied"), 0);
  assert.ok(compareCasePackStatus("satisfied", "missing") < 0);
  assert.ok(compareCasePackStatus("conflicting", "unknown") > 0);
  assert.throws(() => compareCasePackStatus("other", "unknown"), TypeError);
});

test("CasePack status ordering matches the verifier's worst-status aggregation", () => {
  // casepack/verify.ts collapses per-requirement statuses with STATUS_PRIORITY,
  // so an exported comparator that disagrees with it would rank two cases
  // differently from the report the verifier actually produced.
  const ordered = [
    "not_applicable",
    "satisfied",
    "unknown",
    "missing",
    "unsupported",
    "conflicting",
  ];
  assert.deepEqual([...ordered].sort(compareCasePackStatus), ordered);
  for (let index = 0; index < ordered.length; index += 1) {
    for (let other = 0; other < ordered.length; other += 1) {
      const expected = Math.sign(index - other);
      assert.equal(
        Math.sign(compareCasePackStatus(ordered[index], ordered[other])),
        expected,
        `${ordered[index]} vs ${ordered[other]}`,
      );
    }
  }
});

test("release version cannot drift from the manifest, the changelog, or the published statement", () => {
  const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  const changelog = readFileSync(new URL("../CHANGELOG.md", import.meta.url), "utf8");
  const published = JSON.parse(readFileSync(
    DECLARATION_URL,
    "utf8",
  ));

  assert.equal(manifest.version, RELEASE_VERSION);
  assert.equal(published.release, RELEASE_VERSION);
  assert.equal(getConformanceStatement().release, RELEASE_VERSION);

  // Keep a Changelog: an `## [Unreleased]` section sits on top, and the newest
  // dated `## [X.Y.Z] - YYYY-MM-DD` section is the release these pins describe.
  const releasedMatches = [
    ...changelog.matchAll(/^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})$/gmu),
  ];
  const released = releasedMatches.map((match) => match[1]);
  assert.ok(released.length > 0, "CHANGELOG.md has no released version section");
  assert.equal(released[0], RELEASE_VERSION);
  const unreleased = changelog.search(/^## \[Unreleased\]$/mu);
  assert.ok(unreleased >= 0, "CHANGELOG.md has no [Unreleased] section");
  assert.ok(
    unreleased < (releasedMatches[0]?.index ?? -1),
    "[Unreleased] must precede the newest released section",
  );
});
