import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { computeMerkleRoot } from "../dist/bundle.js";
import { deriveLiabilityDecisionId } from "../dist/validation.js";
import {
  ENGINE_VERSION,
  LEGAL_EFFECT,
  PROTOCOL_VERSION,
} from "../dist/version.js";

const V1_SCHEMA_BYTES = Object.freeze({
  "appeal-event.schema.json": "c9729d6c8054af2f505a96a01cc31fd94a5cff12c872bd4cacff88feb8da3c14",
  "causation-attestation.schema.json": "7dfab6e50a5fcbdc19f4a12711da609224c0f24ee78175c1253200b2d47b3b1e",
  "common.schema.json": "3aaefe0c41d621c812179e6a540399b3d0ba43b33b250c3dda673ea707b7d82b",
  "evidence-bundle.schema.json": "3caf21edeed2cc603e5cedbb9906db4d5bce6e6758427957375b525ff0ceeaee",
  "execution-receipt.schema.json": "330fe27bb4a466b08ad65e4c88bb231d82f8046abfb34a2ad0796b29b385c81c",
  "incident-report.schema.json": "ec370d01ce20e4579bcaa58d6a895398b1050eb11817a061b2f07ee8c82ad4ce",
  "liability-decision.schema.json": "9556a73c02cf4aedac749c3c9f436c0bd26211fa992c0e66eff34604d59045c7",
  "liability-policy.schema.json": "54ac898c2ce5f356644f379597744da74b9966513f7bc69acb5648b2687c7614",
  "mandate-envelope.schema.json": "6e4cd83272c5555cd70b4399552de8a0c7696213707f1b57e18d74331758c2e2",
  "rulebook.schema.json": "fd0dfee6e5da770f6f37f6b6f4f3b94c5049ab6da7737a65cfa8ed7053b66f7c",
  "runtime-event.schema.json": "a6b549a84bb6f2c170c7fbcee42a7f5058f026bedf82dc229b85e637f33eccee",
  "signed-artifact.schema.json": "24e6644555961b22c3b9ddba65d993789a1f06d28b49cf2cac573d4afacf8b16",
  "trust-snapshot.schema.json": "5440a1eb2ab9e30e3b2360be04e526529859d807e1943b1e86fe20b648c6f49e",
});

test("v1 normative schema bytes remain frozen", () => {
  for (const [filename, expected] of Object.entries(V1_SCHEMA_BYTES)) {
    const bytes = readFileSync(new URL(`../schemas/v1/${filename}`, import.meta.url));
    const actual = createHash("sha256").update(bytes).digest("hex");
    assert.equal(actual, expected, filename);
  }
});

test("v1 protocol, engine, decision identifiers, and Merkle roots remain byte compatible", () => {
  assert.equal(PROTOCOL_VERSION, "1.0.0");
  assert.equal(ENGINE_VERSION, "1.0.0");
  assert.equal(LEGAL_EFFECT, "not-determined");

  const digest = `sha256:${"a".repeat(64)}`;
  const decisionMaterial = {
    schemaVersion: "1.0.0",
    caseId: "compat-case",
    evaluatedAt: "2026-01-01T00:00:00.000Z",
    evidenceBundleId: "compat-bundle",
    evidenceBundleDigest: digest,
    policyRef: { artifactType: "liability_policy", artifactId: "policy-1", digest },
    rulebookRef: { artifactType: "rulebook", artifactId: "rules-1", digest },
    trustSnapshotRef: { artifactType: "trust_snapshot", artifactId: "trust-1", digest },
    engineVersion: "1.0.0",
    outcome: "unresolved",
    disposition: "indeterminate",
    policyOutcome: "unresolved",
    appealPolicy: { reviewerIds: ["reviewer-1"], maxAppealEvents: 8 },
    reasonCodes: ["compatibility_fixture"],
    trace: [],
    missingEvidence: ["mandate"],
    conflictingEvidence: [],
    cryptographicFacts: [],
    verifiedFacts: [],
    attributedAttestations: [],
    policyConclusions: [{
      reasonCode: "compatibility_fixture",
      outcome: "unresolved",
      disposition: "indeterminate",
    }],
    rejectedEvidence: [],
    deterministicTrace: [],
    pins: {
      asOf: "2026-01-01T00:00:00.000Z",
      policyDigest: digest,
      trustSnapshotDigest: digest,
      rulebookDigest: digest,
      schemaDigests: [digest],
      engineVersion: "1.0.0",
      bundleRootDigest: digest,
    },
    externalAuthenticity: "unestablished",
    legalEffect: "not-determined",
  };
  assert.equal(
    deriveLiabilityDecisionId(decisionMaterial),
    "decision-7113d9e6610711dc82eda956c7260fae7fe3ea0e69694268c76d700483d66b1d",
  );

  const merkleRoot = computeMerkleRoot([
    {
      path: "a.json",
      mediaType: "application/agent-liability+json",
      size: 1,
      classification: "internal",
      digest: `sha256:${"1".repeat(64)}`,
    },
    {
      path: "b.json",
      mediaType: "application/agent-liability+json",
      size: 2,
      classification: "internal",
      digest: `sha256:${"2".repeat(64)}`,
    },
  ]);
  assert.equal(merkleRoot, "sha256:ada8e6ac0d225d0bc2c19ab1fced96bfba27721605874658f3a86816218f7466");
});
