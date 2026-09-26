// Synthetic integration example. Uses only installed, public package exports.
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  buildScenario, canonicalBytes, evaluateBundle, parseStrictJsonObject, sha256Bytes, sha256Digest,
} from "@oonyl/mandatebound";
import {
  createMandateBoundCasePack, sealDelegationContext, sealDeterministicMappingTrace,
  sealEvidenceCoverageContract, sealProtocolEvidenceEnvelope, verifyMandateBoundCasePack,
} from "@oonyl/mandatebound/casepack";
import {
  UCP_AP2_EVIDENCE_PROFILE, verifyDetachedMerchantAuthorization, verifyUcpProfileSnapshot,
} from "@oonyl/mandatebound/ucp-ap2";

const limits = { maxBytes: 16_777_216, maxDepth: 48, maxNodes: 250_000 };
const capturedAt = "2026-07-22T00:00:00.000Z";
const validUntil = "2027-07-23T00:00:00.000Z";
const encode = (value) => `${JSON.stringify(value, null, 2)}\n`;
const readJson = async (path) => parseStrictJsonObject(await readFile(path, "utf8"), limits);
const safeIssues = (items) => items.map(({ code, path }) => ({ code, path }));

function rawBytes(invocation, referenceId) {
  const values = invocation.anchors.rawEvidence.filter((item) => item.referenceId === referenceId);
  if (values.length === 0) return undefined;
  if (values.length !== 1) throw new Error("EXAMPLE_DUPLICATE_RAW_REFERENCE");
  const value = values[0].bytesBase64;
  if (typeof value !== "string") throw new Error("EXAMPLE_RAW_ENCODING_INVALID");
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) throw new Error("EXAMPLE_RAW_ENCODING_INVALID");
  return bytes;
}

function verifySource(invocation, trusted) {
  const profileBytes = rawBytes(invocation, "raw.profile");
  const checkoutBytes = rawBytes(invocation, "raw.checkout");
  const missing = [
    ...(profileBytes === undefined ? [{ code: "EXAMPLE_PROFILE_MISSING", path: "raw.profile" }] : []),
    ...(checkoutBytes === undefined ? [{ code: "EXAMPLE_CHECKOUT_MISSING", path: "raw.checkout" }] : []),
  ];
  if (missing.length > 0) return { upstreamValid: false, evidenceEligible: false, issues: missing };
  const profile = verifyUcpProfileSnapshot({ ...trusted.profile, profileBytes }, {
    asOf: trusted.coverage.asOf, expectedProfileDigest: trusted.profile.profileDigest,
  });
  const checkout = parseStrictJsonObject(checkoutBytes.toString("utf8"));
  const merchant = verifyDetachedMerchantAuthorization(
    checkout, checkout.ap2?.merchant_authorization, trusted.merchant,
  );
  // Recheck signatures on replay; an envelope's recorded upstreamValid is not a verifier.
  return {
    upstreamValid: profile.upstreamValid && merchant.upstreamValid,
    evidenceEligible: profile.evidenceEligible && merchant.evidenceEligible,
    issues: [...safeIssues(profile.issues), ...safeIssues(merchant.issues)],
  };
}

function assess(invocation, trusted) {
  const source = verifySource(invocation, trusted);
  // Trust comes from the separately retained anchors, never the received pack.
  const anchors = { ...trusted.coverage, rawEvidence: invocation.anchors.rawEvidence.map((item) => ({
    referenceId: item.referenceId, bytes: rawBytes(invocation, item.referenceId),
  })) };
  const readiness = verifyMandateBoundCasePack(invocation.casePack, anchors);
  const packMatches = invocation.casePack.casePackDigest === trusted.casePackDigest;
  const ready = packMatches && readiness.valid && source.evidenceEligible;
  // The native engine does not assess outer source coverage. This integration gates it explicitly.
  const decision = ready ? evaluateBundle(invocation.casePack.nativeEvidenceBundle, trusted.native) : null;
  return {
    synthetic: true,
    profile: UCP_AP2_EVIDENCE_PROFILE.id,
    scope: "signed merchant checkout and declared source coverage; not a full AP2 mandate chain",
    casePackDigest: invocation.casePack.casePackDigest,
    ready,
    source,
    readiness: {
      valid: readiness.valid, integrity: readiness.integrityStatus, coverage: readiness.coverageStatus,
      requirements: readiness.requirements, findings: safeIssues(readiness.issues),
    },
    findings: packMatches ? [] : [{ code: "EXAMPLE_CASEPACK_PIN_MISMATCH", path: "casePackDigest" }],
    outcome: decision?.outcome ?? "unresolved",
    decision,
    legalEffect: "not-determined",
    globalCompleteness: readiness.globalCompleteness,
  };
}

async function create(directory) {
  const { input, bundle } = buildScenario("principal");
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const kid = "synthetic-merchant-key";
  const jwk = { ...pair.publicKey.export({ format: "jwk" }), kid, alg: "ES256", use: "sig", key_ops: ["verify"] };
  const version = UCP_AP2_EVIDENCE_PROFILE.ucpVersion;
  const capability = (name) => ({
    version, spec: `https://ucp.dev/${version}/specification/${name}`,
    schema: `https://ucp.dev/${version}/schemas/shopping/${name === "ap2-mandates" ? "ap2_mandate" : name}.json`,
  });
  const profileBytes = Buffer.from(encode({
    ucp: {
      version,
      services: { "dev.ucp.shopping": [{
        version, transport: "rest", spec: `https://ucp.dev/${version}/specification/overview`,
        schema: `https://ucp.dev/${version}/services/shopping/rest.openapi.json`,
      }] },
      capabilities: {
        "dev.ucp.shopping.checkout": [capability("checkout")],
        "dev.ucp.shopping.ap2_mandate": [{ ...capability("ap2-mandates"), extends: "dev.ucp.shopping.checkout" }],
      },
    },
    signing_keys: [jwk],
  }));
  const sourceDigest = sha256Bytes(profileBytes);
  const checkout = {
    id: "checkout-synthetic", status: "ready_for_complete", currency: "USD",
    line_items: [{ id: "line-1", item: { id: "sku-1", title: "Synthetic item", price: 2500 }, quantity: 1,
      totals: [{ type: "subtotal", amount: 2500 }, { type: "total", amount: 2500 }] }],
    totals: [{ type: "subtotal", amount: 2500 }, { type: "total", amount: 2500 }], links: [],
  };
  const header = Buffer.from(JSON.stringify({ alg: "ES256", kid })).toString("base64url");
  const signingInput = `${header}.${canonicalBytes(checkout).toString("base64url")}`;
  const signature = sign("sha256", Buffer.from(signingInput, "ascii"), {
    key: pair.privateKey, dsaEncoding: "ieee-p1363",
  }).toString("base64url");
  // UCP merchant authorization signs the JCS checkout with the entire ap2 object excluded.
  const checkoutBytes = Buffer.from(encode({ ...checkout, ap2: { merchant_authorization: `${header}..${signature}` } }));
  const rawEvidence = [
    { referenceId: "raw.checkout", bytesBase64: checkoutBytes.toString("base64") },
    { referenceId: "raw.profile", bytesBase64: profileBytes.toString("base64") },
  ];
  const trusted = {
    profile: {
      profileDigest: sourceDigest, profileUrl: "https://merchant.synthetic/.well-known/ucp",
      capturedAt, validUntil, ap2Version: UCP_AP2_EVIDENCE_PROFILE.ap2Version,
    },
    merchant: {
      keySnapshot: { kid, jwk, sourceDigest, capturedAt, validUntil },
      expectedKeySourceDigest: sourceDigest, asOf: input.asOf, allowedAlgorithms: ["ES256"],
    },
    native: { pins: input.pins, trustRootJwk: input.trustRootJwk, expectedBundleRootDigest: bundle.rootDigest },
    coverage: { asOf: input.asOf },
  };
  const source = verifySource({ anchors: { rawEvidence } }, trusted);
  if (!source.evidenceEligible) throw new Error("EXAMPLE_SOURCE_IMPORT_FAILED");
  const rawDigest = sha256Bytes(checkoutBytes);
  const receipt = bundle.manifest.entries.find((entry) => entry.path === "evidence/execution-receipt.json");
  if (!receipt) throw new Error("EXAMPLE_NATIVE_RECEIPT_MISSING");
  const envelope = sealProtocolEvidenceEnvelope({
    format: "MandateBoundProtocolEvidenceEnvelope/v1", envelopeId: "envelope.checkout",
    sourceId: "merchant.synthetic", eventClass: "checkout", capturedAt, mediaType: "application/json",
    rawEvidence: { digest: rawDigest, byteLength: checkoutBytes.length,
      reference: { referenceId: "raw.checkout", kind: "content_addressed", value: `urn:sha256:${rawDigest.slice(7)}` } },
    upstreamValid: source.upstreamValid,
    // Synthetic association only: the native signed receipt is supplied independently by the simulator.
    // Never promote a merchant key into native trust or infer a receipt from checkout authorization.
    mapping: sealDeterministicMappingTrace({
      mapperId: "synthetic.checkout-association", mapperVersion: "1.0.0",
      mappingPolicyDigest: sha256Digest({ rule: "synthetic-checkout-associated-with-independent-native-receipt" }),
      inputDigest: rawDigest, outputArtifacts: [{ path: receipt.path, digest: receipt.digest }],
      steps: [{ index: 0, ruleId: "synthetic.association", inputPointer: "", outputPointer: "", status: "satisfied" }],
    }),
  });
  const coverageContract = sealEvidenceCoverageContract({
    format: "MandateBoundEvidenceCoverageContract/v1", contractId: "coverage.synthetic",
    issuedAt: capturedAt, validFrom: capturedAt, validUntil, coverageScope: "declared_sources_and_windows_only",
    policyDigest: sha256Digest({ policy: "synthetic-one-signed-checkout" }), nativeBundleRootDigest: bundle.rootDigest,
    requirements: [{ requirementId: "checkout.required", sourceId: "merchant.synthetic", eventClass: "checkout",
      mediaTypes: ["application/json"], windowStart: capturedAt, windowEnd: input.asOf,
      minEnvelopes: 1, checkpointRequirement: "not_applicable" }],
  });
  const casePack = createMandateBoundCasePack({
    format: "MandateBoundCasePack/v1", casePackId: "casepack.synthetic", createdAt: input.asOf,
    nativeEvidenceBundle: bundle, protocolEvidence: [envelope], coverageContract, sourceCheckpoints: [],
    delegationContext: sealDelegationContext({
      format: "MandateBoundDelegationContext/v1", delegationId: "delegation.synthetic",
      principalId: "principal.synthetic", delegateId: "agent.synthetic",
      mandateDigest: input.mandate.payloadDigest, scopeDigest: sha256Digest(input.mandate.payload.scope),
      validFrom: capturedAt, validUntil, evidenceReferences: [], legalEffect: "not-determined",
    }),
  });
  trusted.casePackDigest = casePack.casePackDigest;
  trusted.coverage.coveragePolicyDigest = coverageContract.policyDigest;
  trusted.coverage.coverageContractDigest = coverageContract.contractDigest;
  const invocation = { casePack, anchors: { ...trusted.coverage, rawEvidence } };
  const result = assess(invocation, trusted);
  if (!result.ready || result.outcome !== "principal") throw new Error("EXAMPLE_ACCEPTANCE_FAILED");
  // Refuse to overwrite an existing directory. Only public keys and synthetic evidence are exported.
  await mkdir(directory);
  await writeFile(join(directory, "invocation.json"), encode(invocation), { flag: "wx" });
  await writeFile(join(directory, "anchors.json"), encode(trusted), { flag: "wx" });
  return result;
}

try {
  const [command, input, anchors, ...extra] = process.argv.slice(2);
  if (extra.length || !input || (command === "create" ? anchors !== undefined : command !== "replay" || !anchors)) {
    throw new Error("EXAMPLE_USAGE: create NEW_DIRECTORY | replay INVOCATION_JSON TRUSTED_ANCHORS_JSON");
  }
  const result = command === "create" ? await create(input) : assess(await readJson(input), await readJson(anchors));
  process.stdout.write(encode(result));
  if (!result.ready || result.outcome === "unresolved") process.exitCode = 2;
} catch (error) {
  const code = error instanceof Error && /^EXAMPLE_[A-Z_]+(?::.*)?$/.test(error.message)
    ? error.message : "EXAMPLE_INPUT_OR_IO_INVALID";
  process.stderr.write(`${code}\n`);
  process.exitCode = 2;
}
