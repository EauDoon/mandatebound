import { Buffer } from "node:buffer";
import assert from "node:assert/strict";
import { createEvidenceBundle } from "../../dist/bundle.js";
import { createMandateBoundCasePack, sealDelegationContext, sealDeterministicMappingTrace, sealEvidenceCoverageContract, sealProtocolEvidenceEnvelope } from "../../dist/casepack.js";
import { sha256Bytes, sha256Digest } from "../../dist/canonical.js";
import { buildScenario } from "../../dist/simulator.js";
const AS_OF = "2026-07-23T00:00:00.000Z";
const RAW_ALPHA = Buffer.from('{"action":"authorize","amount":"10"}', "utf8");
const RAW_BETA = Buffer.from('{"result":"accepted","sequence":1}', "utf8");

function withoutEmbeddedBundle(input) {
  const { evidenceBundle: _ignored, ...clean } = input;
  return clean;
}

function rawDescriptor(referenceId, bytes) {
  const digest = sha256Bytes(bytes);
  return {
    digest,
    byteLength: bytes.byteLength,
    reference: {
      referenceId,
      kind: "content_addressed",
      value: `urn:sha256:${digest.slice("sha256:".length)}`,
    },
  };
}

function protocolEnvelope({
  bundle,
  envelopeId,
  sourceId,
  eventClass,
  referenceId,
  bytes,
  checkpointInclusion,
}) {
  const output = bundle.manifest.entries.find((entry) => entry.path === "evidence/mandate.json")
    ?? bundle.manifest.entries[0];
  assert.ok(output);
  const rawEvidence = rawDescriptor(referenceId, bytes);
  const mapping = sealDeterministicMappingTrace({
    mapperId: "mandatebound.test-mapper",
    mapperVersion: "1.1.0",
    mappingPolicyDigest: sha256Digest({ mapper: "test-v1.1" }),
    inputDigest: rawEvidence.digest,
    outputArtifacts: [{ path: output.path, digest: output.digest }],
    steps: [{
      index: 0,
      ruleId: "map.raw-to-native",
      inputPointer: "/raw",
      outputPointer: "/bundle",
      status: "satisfied",
    }],
  });
  return sealProtocolEvidenceEnvelope({
    format: "MandateBoundProtocolEvidenceEnvelope/v1",
    envelopeId,
    sourceId,
    eventClass,
    capturedAt: "2026-07-22T12:00:00.000Z",
    mediaType: "application/json",
    rawEvidence,
    upstreamValid: true,
    mapping,
    ...(checkpointInclusion === undefined ? {} : { checkpointInclusion }),
  });
}

function coverageRequirement(requirementId, sourceId, eventClass) {
  return {
    requirementId,
    sourceId,
    eventClass,
    mediaTypes: ["application/json"],
    windowStart: "2026-07-22T00:00:00.000Z",
    windowEnd: "2026-07-22T23:59:59.999Z",
    minEnvelopes: 1,
    checkpointRequirement: "not_applicable",
  };
}

export function operatorFixture() {
  const bundle = createEvidenceBundle(withoutEmbeddedBundle(buildScenario("principal").input));
  const alpha = protocolEnvelope({
    bundle,
    envelopeId: "envelope.alpha",
    sourceId: "source.alpha",
    eventClass: "authorization",
    referenceId: "raw.alpha",
    bytes: RAW_ALPHA,
  });
  const beta = protocolEnvelope({
    bundle,
    envelopeId: "envelope.beta",
    sourceId: "source.beta",
    eventClass: "execution",
    referenceId: "raw.beta",
    bytes: RAW_BETA,
  });
  const policyDigest = sha256Digest({ coveragePolicy: "casepack-v1.1" });
  const coverageContract = sealEvidenceCoverageContract({
    format: "MandateBoundEvidenceCoverageContract/v1",
    contractId: "coverage.case-001",
    issuedAt: "2026-07-22T00:00:00.000Z",
    validFrom: "2026-07-22T00:00:00.000Z",
    validUntil: "2027-07-22T00:00:00.000Z",
    coverageScope: "declared_sources_and_windows_only",
    policyDigest,
    nativeBundleRootDigest: bundle.rootDigest,
    requirements: [
      coverageRequirement("requirement.alpha", "source.alpha", "authorization"),
      coverageRequirement("requirement.beta", "source.beta", "execution"),
    ],
  });
  const delegationContext = sealDelegationContext({
    format: "MandateBoundDelegationContext/v1",
    delegationId: "delegation.case-001",
    principalId: "principal.case-001",
    delegateId: "agent.case-001",
    mandateDigest: sha256Digest({ mandate: bundle.rootDigest }),
    scopeDigest: sha256Digest({ scope: "bounded-test" }),
    validFrom: "2026-07-22T00:00:00.000Z",
    validUntil: "2027-07-22T00:00:00.000Z",
    evidenceReferences: [],
    legalEffect: "not-determined",
  });
  const pack = createMandateBoundCasePack({
    format: "MandateBoundCasePack/v1",
    casePackId: "casepack.case-001",
    createdAt: AS_OF,
    nativeEvidenceBundle: bundle,
    protocolEvidence: [alpha, beta],
    delegationContext,
    coverageContract,
    sourceCheckpoints: [],
  });
  const anchors = {
    asOf: AS_OF,
    coveragePolicyDigest: policyDigest,
    coverageContractDigest: coverageContract.contractDigest,
    rawEvidence: [
      { referenceId: "raw.alpha", bytes: RAW_ALPHA },
      { referenceId: "raw.beta", bytes: RAW_BETA },
    ],
  };
  return { bundle, alpha, beta, coverageContract, delegationContext, pack, anchors };
}
