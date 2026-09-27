import assert from "node:assert/strict";
import test from "node:test";
import { sha256Bytes } from "../dist/canonical.js";
import {
  UCP_AP2_EVIDENCE_PROFILE,
  parseContentDigest,
  verifyRawBodyContentDigest,
  verifyUcpProfileSnapshot,
} from "../dist/ucp-ap2.js";
import {
  contentDigest,
  evaluationTime,
  issueCodes,
  makeUcpProfile,
  profileSnapshot,
  sourceDigest,
} from "./ucp-ap2-helpers.mjs";

test("exact UCP 2026-04-08 REST plus AP2 v0.2.0 profile is pinned offline", () => {
  const snapshot = profileSnapshot(makeUcpProfile());
  const report = verifyUcpProfileSnapshot(snapshot, {
    expectedProfileDigest: snapshot.profileDigest,
    asOf: evaluationTime,
  });
  assert.equal(report.upstreamValid, true, JSON.stringify(report.issues));
  assert.equal(report.evidenceEligible, true);
  assert.equal(report.value.profileId, UCP_AP2_EVIDENCE_PROFILE.id);
  assert.equal(report.value.authorizesNativeRole, false);

  const wrongVersion = profileSnapshot(makeUcpProfile("2026-01-23"));
  const wrongVersionReport = verifyUcpProfileSnapshot(wrongVersion, {
    expectedProfileDigest: wrongVersion.profileDigest,
    asOf: evaluationTime,
  });
  assert.equal(wrongVersionReport.upstreamValid, false);
  assert.equal(
    wrongVersionReport.issues.some((issue) => issue.code === "UCP_VERSION_UNSUPPORTED"),
    true,
  );

  const wrongAp2 = profileSnapshot(makeUcpProfile(), { ap2Version: "0.1.0" });
  assert.equal(verifyUcpProfileSnapshot(wrongAp2, {
    expectedProfileDigest: wrongAp2.profileDigest,
    asOf: evaluationTime,
  }).upstreamValid, false);
});

test("UCP profile importer distinguishes malformed, stale, unpinned, and incompatible snapshots", () => {
  const valid = profileSnapshot(makeUcpProfile());
  const stale = verifyUcpProfileSnapshot({
    ...valid,
    validUntil: "2026-05-01T00:00:00.000Z",
  }, {
    expectedProfileDigest: valid.profileDigest,
    asOf: evaluationTime,
  });
  assert.equal(stale.upstreamValid, true);
  assert.equal(stale.evidenceEligible, false);
  assert.equal(issueCodes(stale).has("UCP_PROFILE_SNAPSHOT_STALE"), true);

  const invalidWindow = verifyUcpProfileSnapshot({
    ...valid,
    capturedAt: "2027-05-01T00:00:00.000Z",
  }, {
    expectedProfileDigest: valid.profileDigest,
    asOf: evaluationTime,
  });
  assert.equal(invalidWindow.upstreamValid, false);
  assert.equal(issueCodes(invalidWindow).has("UCP_PROFILE_WINDOW_INVALID"), true);

  for (const profileUrl of [
    "not a url",
    "http://merchant.example/.well-known/ucp",
    "https://user:secret@merchant.example/.well-known/ucp",
    "https://merchant.example/.well-known/ucp#fragment",
  ]) {
    const report = verifyUcpProfileSnapshot({ ...valid, profileUrl }, {
      expectedProfileDigest: valid.profileDigest,
      asOf: evaluationTime,
    });
    assert.equal(report.upstreamValid, false, profileUrl);
    assert.equal(issueCodes(report).has("UCP_PROFILE_INVALID"), true);
  }

  const invalidUtf8 = Buffer.from([0xff]);
  const invalidUtf8Report = verifyUcpProfileSnapshot({
    ...valid,
    profileBytes: invalidUtf8,
    profileDigest: sha256Bytes(invalidUtf8),
  }, {
    expectedProfileDigest: sha256Bytes(invalidUtf8),
    asOf: evaluationTime,
  });
  assert.equal(invalidUtf8Report.upstreamValid, false);
  assert.equal(issueCodes(invalidUtf8Report).has("UCP_PROFILE_INVALID"), true);

  const unpinned = verifyUcpProfileSnapshot({
    ...valid,
    profileDigest: sourceDigest,
  }, {
    expectedProfileDigest: sourceDigest,
    asOf: evaluationTime,
  });
  assert.equal(unpinned.upstreamValid, false);
  assert.equal(unpinned.evidenceEligible, false);
  assert.equal(issueCodes(unpinned).has("UCP_PROFILE_DIGEST_MISMATCH"), true);
  assert.equal(issueCodes(unpinned).has("UCP_PROFILE_PIN_MISMATCH"), true);

  const wrongService = makeUcpProfile();
  wrongService.ucp.services["dev.ucp.shopping"] = [
    null,
    { version: "2026-01-23", transport: "mcp" },
  ];
  const wrongServiceSnapshot = profileSnapshot(wrongService);
  const wrongServiceReport = verifyUcpProfileSnapshot(wrongServiceSnapshot, {
    expectedProfileDigest: wrongServiceSnapshot.profileDigest,
    asOf: evaluationTime,
  });
  assert.equal(wrongServiceReport.upstreamValid, false);
  assert.equal(issueCodes(wrongServiceReport).has("UCP_REST_PROFILE_MISSING"), true);

  const wrongCapabilities = makeUcpProfile();
  wrongCapabilities.ucp.capabilities["dev.ucp.shopping.checkout"][0].version = "2026-01-23";
  wrongCapabilities.ucp.capabilities["dev.ucp.shopping.ap2_mandate"][0].version = "2026-01-23";
  const wrongCapabilitiesSnapshot = profileSnapshot(wrongCapabilities);
  const wrongCapabilitiesReport = verifyUcpProfileSnapshot(wrongCapabilitiesSnapshot, {
    expectedProfileDigest: wrongCapabilitiesSnapshot.profileDigest,
    asOf: evaluationTime,
  });
  assert.equal(wrongCapabilitiesReport.upstreamValid, false);
  assert.equal(issueCodes(wrongCapabilitiesReport).has("UCP_CHECKOUT_VERSION_UNSUPPORTED"), true);
  assert.equal(
    issueCodes(wrongCapabilitiesReport).has("UCP_AP2_EXTENSION_VERSION_UNSUPPORTED"),
    true,
  );

  for (const malformedProfile of [
    {},
    { ucp: { version: "2026-04-08", services: {} } },
    {
      ucp: {
        version: "2026-04-08",
        services: { "dev.ucp.shopping": {} },
        capabilities: {},
      },
    },
    {
      ...makeUcpProfile(),
      ucp: {
        ...makeUcpProfile().ucp,
        capabilities: {
          ...makeUcpProfile().ucp.capabilities,
          "dev.ucp.shopping.checkout": [false],
        },
      },
    },
  ]) {
    const snapshot = profileSnapshot(malformedProfile);
    const report = verifyUcpProfileSnapshot(snapshot, {
      expectedProfileDigest: snapshot.profileDigest,
      asOf: evaluationTime,
    });
    assert.equal(report.upstreamValid, false);
    assert.equal(issueCodes(report).has("UCP_PROFILE_SHAPE_INVALID"), true);
  }
});

test("RFC 9530 Content-Digest binds exact raw bytes and rejects alternate syntax", () => {
  const body = Buffer.from('{"checkout":{"id":"chk-1"}}', "utf8");
  const header = contentDigest(body);
  const parsed = parseContentDigest(header);
  assert.equal(parsed.algorithm, "sha-256");
  assert.equal(parsed.digest.byteLength, 32);
  assert.equal(verifyRawBodyContentDigest(body, header).upstreamValid, true);

  const oneByteMutation = Buffer.from(body);
  oneByteMutation[oneByteMutation.length - 2] ^= 1;
  assert.equal(verifyRawBodyContentDigest(oneByteMutation, header).upstreamValid, false);
  assert.throws(() => parseContentDigest(`sha-512=:${Buffer.alloc(64).toString("base64")}:`));
  assert.throws(() => parseContentDigest(`${header}, sha-512=:AAAA:`));
});

test("Content-Digest parser rejects noncanonical, malformed, and wrong-length values safely", () => {
  assert.throws(() => parseContentDigest(null));
  assert.throws(() => parseContentDigest("sha-256=::"));
  assert.throws(() => parseContentDigest("sha-256=:AB==:"));
  assert.throws(() => parseContentDigest(`sha-256=:${Buffer.alloc(31).toString("base64")}:`));
  const report = verifyRawBodyContentDigest(Buffer.alloc(0), "not-a-digest");
  assert.equal(report.upstreamValid, false);
  assert.equal(issueCodes(report).has("UCP_CONTENT_DIGEST_INVALID"), true);
});

test("UCP capability arrays must be present, non-empty, and object valued", () => {
  const verify = (profile) => {
    const snapshot = profileSnapshot(profile);
    return verifyUcpProfileSnapshot(snapshot, {
      expectedProfileDigest: snapshot.profileDigest,
      asOf: evaluationTime,
    });
  };

  // A capability that is missing, not an array, or empty is refused, and the
  // refusal is distinguished from a version mismatch.
  const capabilityCases = [
    ["dev.ucp.shopping.checkout", "absent", undefined],
    ["dev.ucp.shopping.checkout", "not-an-array", "checkout"],
    ["dev.ucp.shopping.checkout", "empty", []],
    ["dev.ucp.shopping.ap2_mandate", "empty", []],
  ];
  for (const [name, label, value] of capabilityCases) {
    const profile = makeUcpProfile();
    if (value === undefined) {
      delete profile.ucp.capabilities[name];
    } else {
      profile.ucp.capabilities[name] = value;
    }
    const report = verify(profile);
    assert.equal(report.upstreamValid, false, `${name} ${label} must be refused`);
    const message = report.issues.map((issue) => issue.message).join(" | ");
    assert.match(message, /Missing capability at/, `${name} ${label}: ${message}`);
  }

  // A capability array whose entries are not objects is refused too.
  const notObjects = makeUcpProfile();
  notObjects.ucp.capabilities["dev.ucp.shopping.checkout"] = ["checkout-string"];
  const report = verify(notObjects);
  assert.equal(report.upstreamValid, false);
  assert.match(
    report.issues.map((issue) => issue.message).join(" | "),
    /Expected JSON object at/,
  );

  // A services entry that is not an array is refused by the sibling helper
  // that resolves the service, and says so rather than reporting a capability.
  for (const bad of ["rest", [], [{ version: UCP_AP2_EVIDENCE_PROFILE.ucpVersion }]]) {
    const badService = makeUcpProfile();
    badService.ucp.services["dev.ucp.shopping"] = bad;
    const serviceReport = verify(badService);
    assert.equal(serviceReport.upstreamValid, false, JSON.stringify(bad));
    assert.match(
      serviceReport.issues.map((issue) => issue.message).join(" | "),
      /shopping service/,
      JSON.stringify(bad),
    );
  }

  // The unmodified reference profile still verifies, so the rules above are
  // specific rather than blanket.
  assert.equal(verify(makeUcpProfile()).upstreamValid, true);
});
