import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { connect } from "node:net";
import test from "node:test";
import { appealEventDigest } from "../dist/appeals.js";
import { createApiServer, DEFAULT_API_LIMITS, isLoopbackAddress, validateLocalRequest } from "../dist/api.js";
import { DEFAULT_STRICT_JSON_LIMITS } from "../dist/strict-json.js";
import { verifyEvidenceBundle } from "../dist/bundle.js";
import { deriveLiabilityDecisionId } from "../dist/validation.js";

const DIGEST = `sha256:${"a".repeat(64)}`;

function decision(overrides = {}) {
  const { artifactId: _artifactId, ...fields } = overrides;
  const pins = fields.pins ?? {
    asOf: "2026-07-23T00:00:00.000Z",
    policyDigest: DIGEST,
    trustSnapshotDigest: DIGEST,
    rulebookDigest: DIGEST,
    schemaDigests: [DIGEST],
    engineVersion: "1.0.0",
    bundleRootDigest: DIGEST,
  };
  const material = {
    schemaVersion: "1.0.0",
    caseId: "case-api-1",
    evaluatedAt: pins.asOf,
    evidenceBundleId: "bundle-api-1",
    evidenceBundleDigest: pins.bundleRootDigest,
    policyRef: { artifactType: "liability_policy", artifactId: "policy-1", digest: pins.policyDigest },
    rulebookRef: { artifactType: "rulebook", artifactId: "rulebook-1", digest: pins.rulebookDigest },
    trustSnapshotRef: { artifactType: "trust_snapshot", artifactId: "trust-1", digest: pins.trustSnapshotDigest },
    engineVersion: pins.engineVersion,
    outcome: "unresolved",
    disposition: "indeterminate",
    policyOutcome: "unresolved",
    appealPolicy: { reviewerIds: ["reviewer-synthetic"], maxAppealEvents: 8 },
    reasonCodes: ["missing_required_evidence"],
    trace: [],
    missingEvidence: ["mandate"],
    conflictingEvidence: [],
    cryptographicFacts: [],
    verifiedFacts: [],
    attributedAttestations: [],
    policyConclusions: [{
      reasonCode: "missing_required_evidence",
      outcome: "unresolved",
      disposition: "indeterminate",
    }],
    rejectedEvidence: [],
    deterministicTrace: [],
    pins,
    externalAuthenticity: "established_by_caller_pins",
    legalEffect: "not-determined",
    ...fields,
  };
  return { artifactId: deriveLiabilityDecisionId(material), ...material };
}

function engine(overrides = {}) {
  return {
    verifyEvidenceBundle: () => ({
      valid: true,
      verifiedEntries: 1,
      totalEntries: 1,
      trustChecked: false,
      issues: [],
    }),
    evaluateCase: () => decision(),
    explainDecision: () => "Synthetic explanation.",
    ...overrides,
  };
}

function evaluationRequest(overrides = {}) {
  return {
    caseId: "case-api-1",
    asOf: "2026-07-23T00:00:00.000Z",
    pins: {
      asOf: "2026-07-23T00:00:00.000Z",
      policyDigest: DIGEST,
      trustSnapshotDigest: DIGEST,
      rulebookDigest: DIGEST,
      schemaDigests: [DIGEST],
      engineVersion: "1.0.0",
    },
    runtimeEvents: [],
    priorReceipts: [],
    causationAttestations: [],
    policy: {},
    rulebook: {},
    trustSnapshot: {},
    ...overrides,
  };
}

async function json(response) {
  return JSON.parse(await response.text());
}

async function rawHttpUntil(port, request, predicate, timeoutMs = 1_000) {
  return await new Promise((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port });
    let received = "";
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("Timed out waiting for raw HTTP response."));
    }, timeoutMs);
    const finish = () => {
      clearTimeout(timer);
      socket.destroy();
      resolve(received);
    };
    socket.on("connect", () => socket.write(request));
    socket.on("data", (chunk) => {
      received += chunk.toString("utf8");
      if (predicate(received)) finish();
    });
    socket.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

test("API binds to loopback by default, exposes probes and no CORS", async () => {
  const api = createApiServer({ engine: engine() });
  const address = await api.listen();
  try {
    assert.equal(address.host, "127.0.0.1");
    const health = await fetch(`${address.url}/healthz`);
    assert.equal(health.status, 200);
    assert.equal(health.headers.has("access-control-allow-origin"), false);
    assert.deepEqual(await json(health), { status: "ok" });

    const ready = await fetch(`${address.url}/readyz`);
    assert.equal(ready.status, 200);
    assert.deepEqual(await json(ready), { status: "ready" });

    const openapi = await fetch(`${address.url}/openapi.json`);
    assert.equal(openapi.status, 200);
    assert.equal((await json(openapi)).info.title, "MandateBound API");
  } finally {
    await api.close();
  }
});

test("published OpenAPI contract includes every route, Problem Details, and the complete decision surface", async () => {
  const api = createApiServer({ engine: engine() });
  const address = await api.listen();
  try {
    const response = await fetch(`${address.url}/openapi.json`);
    const document = await json(response);
    assert.equal(document.openapi, "3.1.0");
    assert.equal(document.info.title, "MandateBound API");
    assert.deepEqual(Object.keys(document.paths).sort(), [
      "/healthz",
      "/openapi.json",
      "/readyz",
      "/v1/appeals",
      "/v1/appeals/{id}",
      "/v1/appeals/{id}/events",
      "/v1/decisions/{id}",
      "/v1/evaluations",
      "/v1/simulations",
      "/v1/verify",
    ]);
    assert.deepEqual(document.components.schemas.ProblemDetails.required, [
      "type", "title", "status", "detail", "code", "requestId",
    ]);
    const required = new Set(document.components.schemas.LiabilityDecision.required);
    for (const field of [
      "disposition", "policyOutcome", "appealPolicy", "cryptographicFacts", "verifiedFacts", "attributedAttestations",
      "policyConclusions", "rejectedEvidence", "deterministicTrace", "pins", "externalAuthenticity",
    ]) {
      assert(required.has(field), `OpenAPI decision is missing ${field}`);
    }
    assert.match(document.components.schemas.EvidenceBundle.description, /Closed MandateBound evidence bundle/);
    assert.equal(document.components.schemas.EvidenceBundle.description.includes("Closed agent-liability"), false);
    assert.equal(
      document.paths["/v1/simulations"].post.responses["200"].content["application/json"].schema.oneOf.length,
      2,
    );
    for (const path of ["/v1/verify", "/v1/evaluations", "/v1/appeals", "/v1/appeals/{id}/events", "/v1/simulations"]) {
      const responses = document.paths[path].post.responses;
      for (const status of ["408", "413", "415", "503"]) {
        assert(status in responses, `${path} does not document ${status}`);
      }
    }
  } finally {
    await api.close();
  }
});

test("API binding is loopback-only and remote opt-in is not accepted", () => {
  assert.throws(() => createApiServer({ host: "0.0.0.0", engine: engine() }), /loopback/);
  assert.throws(() => createApiServer({ host: "192.0.2.10", allowRemote: true, engine: engine() }), /loopback/);
  assert.throws(() => createApiServer({ port: -1, engine: engine() }), /port/);
  assert.throws(() => createApiServer({ limits: { maxBodyBytes: 0 }, engine: engine() }), /limit/);
  assert.throws(
    () => createApiServer({ limits: { headersTimeoutMs: 20, requestTimeoutMs: 10 }, engine: engine() }),
    /Header timeout/,
  );
});

test("local request boundary rejects remote peers, rebinding Hosts, and foreign Origins", () => {
  const request = (remoteAddress, host, origin, rawHeaders = ["host", host]) => ({
    socket: { remoteAddress },
    headers: { host, ...(origin === undefined ? {} : { origin }) },
    rawHeaders,
  });
  const expectedHost = "127.0.0.1:4321";
  const expectedOrigin = "http://127.0.0.1:4321";
  assert.equal(validateLocalRequest(request("127.0.0.1", expectedHost), expectedHost, expectedOrigin), undefined);
  assert.equal(validateLocalRequest(request("::ffff:127.0.0.1", expectedHost), expectedHost, expectedOrigin), undefined);
  assert.equal(validateLocalRequest(request("fe80::1%lo0", expectedHost), expectedHost, expectedOrigin)?.code, "ALB_PEER_FORBIDDEN");
  assert.equal(validateLocalRequest(request("203.0.113.7", expectedHost), expectedHost, expectedOrigin)?.code, "ALB_PEER_FORBIDDEN");
  assert.equal(validateLocalRequest(request("127.0.0.1", "127.0.0.1:4321.evil.example"), expectedHost, expectedOrigin)?.code, "ALB_HOST_FORBIDDEN");
  assert.equal(validateLocalRequest(request("127.0.0.1", expectedHost, "http://evil.example:4321"), expectedHost, expectedOrigin)?.code, "ALB_ORIGIN_FORBIDDEN");
  assert.equal(validateLocalRequest(request("127.0.0.1", expectedHost, expectedOrigin), expectedHost, expectedOrigin), undefined);
  assert.equal(validateLocalRequest(request("127.0.0.1", expectedHost, undefined, ["host", expectedHost, "host", expectedHost]), expectedHost, expectedOrigin)?.code, "ALB_HOST_FORBIDDEN");
});

test("loopback recognition covers IPv4, IPv6, and mapped IPv6 without admitting public addresses", () => {
  assert.equal(isLoopbackAddress("127.0.0.1"), true);
  assert.equal(isLoopbackAddress("127.42.7.9"), true);
  assert.equal(isLoopbackAddress("::1"), true);
  assert.equal(isLoopbackAddress("0:0:0:0:0:0:0:1"), true);
  assert.equal(isLoopbackAddress("::1%lo0"), false);
  assert.equal(isLoopbackAddress("::ffff:127.0.0.1"), true);
  assert.equal(isLoopbackAddress("::ffff:7f00:1"), true);
  assert.equal(isLoopbackAddress("localhost"), false);
  assert.equal(isLoopbackAddress("0.0.0.0"), false);
  assert.equal(isLoopbackAddress("::"), false);
  assert.equal(isLoopbackAddress("::ffff:192.0.2.1"), false);
});

test("API applies Host and Origin boundaries before routing", async () => {
  const api = createApiServer({ engine: engine() });
  const address = await api.listen();
  try {
    const rebinding = await rawHttpUntil(
      address.port,
      [
        "GET /healthz HTTP/1.1",
        `Host: 127.0.0.1.evil.example:${address.port}`,
        "Connection: close",
        "",
        "",
      ].join("\r\n"),
      (text) => text.includes("ALB_HOST_FORBIDDEN"),
    );
    assert.match(rebinding, /^HTTP\/1\.1 403 /);

    const foreignOrigin = await rawHttpUntil(
      address.port,
      [
        "GET /healthz HTTP/1.1",
        `Host: 127.0.0.1:${address.port}`,
        `Origin: http://evil.example:${address.port}`,
        "Connection: close",
        "",
        "",
      ].join("\r\n"),
      (text) => text.includes("ALB_ORIGIN_FORBIDDEN"),
    );
    assert.match(foreignOrigin, /^HTTP\/1\.1 403 /);

    const sameOrigin = await fetch(`${address.url}/healthz`, {
      headers: { origin: address.url },
    });
    assert.equal(sameOrigin.status, 200);
  } finally {
    await api.close();
  }
});

test("listen is idempotent and readiness fails closed when store verification fails", async () => {
  const store = {
    putDecision: async (value) => value,
    getDecision: async () => undefined,
    appendAppeal: async () => { throw new Error("unused"); },
    getAppeal: async () => undefined,
    verifyChain: async () => ({
      valid: false,
      records: 1,
      completeness: "unproven",
      issues: [{ code: "ALB_STORE_HASH", message: "invalid" }],
    }),
    close: async () => {},
  };
  const api = createApiServer({ engine: engine(), store });
  const first = await api.listen();
  try {
    assert.deepEqual(await api.listen(), first);
    assert.deepEqual(api.address(), first);
    const ready = await fetch(`${first.url}/readyz`);
    assert.equal(ready.status, 503);
    assert.deepEqual(await json(ready), { status: "not_ready" });
  } finally {
    await api.close();
  }
});

test("API accepts unresolved as a stored 201 decision", async () => {
  const api = createApiServer({ engine: engine() });
  const address = await api.listen();
  try {
    const created = await fetch(`${address.url}/v1/evaluations`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(evaluationRequest()),
    });
    assert.equal(created.status, 201);
    const result = await json(created);
    assert.equal(result.outcome, "unresolved");
    assert.equal(result.legalEffect, "not-determined");

    const fetched = await fetch(`${address.url}/v1/decisions/${result.artifactId}`);
    assert.equal(fetched.status, 200);
    assert.equal((await json(fetched)).artifactId, result.artifactId);
  } finally {
    await api.close();
  }
});

test("API appeal endpoints preserve ordered history", async () => {
  const api = createApiServer({ engine: engine() });
  const address = await api.listen();
  try {
    const evaluation = await fetch(`${address.url}/v1/evaluations`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(evaluationRequest()),
    });
    const evaluated = await json(evaluation);
    const filed = {
      schemaVersion: "1.0.0",
      artifactId: "event-api-1",
      appealId: "appeal-api-1",
      decisionId: evaluated.artifactId,
      sequence: 1,
      eventType: "filed",
      actor: { id: "principal-synthetic", role: "principal" },
      occurredAt: "2026-07-23T00:00:00.000Z",
      reasonCodes: ["review_requested"],
    };
    const created = await fetch(`${address.url}/v1/appeals`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(filed),
    });
    assert.equal(created.status, 201);
    assert.equal((await json(created)).completeness.state, "unproven");

    const review = {
      ...filed,
      artifactId: "event-api-2",
      sequence: 2,
      previousEventDigest: appealEventDigest(filed),
      eventType: "review_started",
      actor: { id: "reviewer-synthetic", role: "reviewer" },
    };
    const appended = await fetch(`${address.url}/v1/appeals/appeal-api-1/events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(review),
    });
    assert.equal(appended.status, 201);
    assert.equal((await json(appended)).events.length, 2);

    const fetched = await fetch(`${address.url}/v1/appeals/appeal-api-1`);
    assert.equal(fetched.status, 200);
    assert.equal((await json(fetched)).status, "open");
  } finally {
    await api.close();
  }
});

test("API enforces the decision-bound reviewer allowlist and appeal event cap", async () => {
  const constrainedDecision = decision({
    appealPolicy: { reviewerIds: ["reviewer-api-allowed"], maxAppealEvents: 2 },
  });
  const api = createApiServer({ engine: engine({ evaluateCase: () => constrainedDecision }) });
  const address = await api.listen();
  try {
    await fetch(`${address.url}/v1/evaluations`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(evaluationRequest()),
    });
    const filed = {
      schemaVersion: "1.0.0",
      artifactId: "event-api-policy-1",
      appealId: "appeal-api-policy-1",
      decisionId: constrainedDecision.artifactId,
      sequence: 1,
      eventType: "filed",
      actor: { id: "principal-synthetic", role: "principal" },
      occurredAt: "2026-07-23T00:00:00.000Z",
      reasonCodes: ["review_requested"],
    };
    assert.equal((await fetch(`${address.url}/v1/appeals`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(filed),
    })).status, 201);

    const review = {
      ...filed,
      artifactId: "event-api-policy-2",
      sequence: 2,
      previousEventDigest: appealEventDigest(filed),
      eventType: "review_started",
      actor: { id: "reviewer-api-denied", role: "reviewer" },
    };
    const unauthorized = await fetch(`${address.url}/v1/appeals/${filed.appealId}/events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(review),
    });
    assert.equal(unauthorized.status, 422);
    assert.equal((await json(unauthorized)).code, "ALB_APPEAL_REVIEWER_UNAUTHORIZED");

    const authorized = { ...review, actor: { id: "reviewer-api-allowed", role: "reviewer" } };
    assert.equal((await fetch(`${address.url}/v1/appeals/${filed.appealId}/events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(authorized),
    })).status, 201);

    const capped = {
      ...authorized,
      artifactId: "event-api-policy-3",
      sequence: 3,
      previousEventDigest: appealEventDigest(authorized),
      eventType: "upheld",
    };
    const cap = await fetch(`${address.url}/v1/appeals/${filed.appealId}/events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(capped),
    });
    assert.equal(cap.status, 409);
    assert.equal((await json(cap)).code, "ALB_APPEAL_EVENT_CAP");
  } finally {
    await api.close();
  }
});

test("API rejects missing anchors, malformed JSON, duplicate keys, media types, and oversized bodies", async () => {
  const api = createApiServer({ engine: engine(), limits: { maxBodyBytes: 128 } });
  const address = await api.listen();
  try {
    const missingPins = await fetch(`${address.url}/v1/evaluations`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(missingPins.status, 422);
    assert.equal((await json(missingPins)).code, "ALB_EXTERNAL_PINS_REQUIRED");

    const malformed = await fetch(`${address.url}/v1/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: '{"bundle":',
    });
    assert.equal(malformed.status, 400);
    const malformedProblem = await json(malformed);
    assert.equal(malformedProblem.code, "ALB_JSON_INVALID");
    assert.equal(malformedProblem.offset, 10);
    assert.match(malformedProblem.detail, /offset 10/);

    const empty = await fetch(`${address.url}/v1/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "",
    });
    assert.equal(empty.status, 400);
    assert.equal((await json(empty)).code, "ALB_JSON_INVALID");

    const duplicate = await fetch(`${address.url}/v1/simulations`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: '{"scenario":"principal","scenario":"operator"}',
    });
    assert.equal(duplicate.status, 400);
    assert.equal((await json(duplicate)).code, "ALB_JSON_DUPLICATE_KEY");

    const media = await fetch(`${address.url}/v1/verify`, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "{}",
    });
    assert.equal(media.status, 415);

    const compressed = await fetch(`${address.url}/v1/verify`, {
      method: "POST",
      headers: { "content-type": "application/json", "content-encoding": "gzip" },
      body: "{}",
    });
    assert.equal(compressed.status, 415);
    assert.equal((await json(compressed)).code, "ALB_CONTENT_ENCODING");

    const oversized = await fetch(`${address.url}/v1/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ value: "x".repeat(256) }),
    });
    assert.equal(oversized.status, 413);
  } finally {
    await api.close();
  }
});

test("API JSON string limits follow the configured body cap", async () => {
  assert.equal(DEFAULT_API_LIMITS.maxBodyBytes, DEFAULT_STRICT_JSON_LIMITS.maxBytes);
  assert.equal(DEFAULT_API_LIMITS.maxJsonStringBytes, DEFAULT_STRICT_JSON_LIMITS.maxBytes);
  assert.equal(DEFAULT_API_LIMITS.maxJsonArrayLength, DEFAULT_STRICT_JSON_LIMITS.maxArrayLength);

  const token = "a".repeat(300_000);
  const api = createApiServer({ engine: engine(), limits: { maxBodyBytes: 400_000 } });
  const address = await api.listen();
  try {
    const accepted = await fetch(`${address.url}/v1/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    });
    assert.equal(accepted.status, 200);
  } finally {
    await api.close();
  }

  const tight = createApiServer({
    engine: engine(),
    limits: { maxBodyBytes: 400_000, maxJsonStringBytes: 16 },
  });
  const tightAddress = await tight.listen();
  try {
    const rejected = await fetch(`${tightAddress.url}/v1/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    });
    assert.equal(rejected.status, 413);
    assert.equal((await json(rejected)).code, "ALB_JSON_LIMIT");
  } finally {
    await tight.close();
  }
});

test("API enforces streaming body limits for chunked requests", async () => {
  const api = createApiServer({ engine: engine(), limits: { maxBodyBytes: 8 } });
  const address = await api.listen();
  try {
    const response = await rawHttpUntil(
      address.port,
      [
        "POST /v1/verify HTTP/1.1",
        `Host: 127.0.0.1:${address.port}`,
        "Content-Type: application/json",
        "Transfer-Encoding: chunked",
        "Connection: close",
        "",
        "10",
        "0123456789abcdef",
        "0",
        "",
        "",
      ].join("\r\n"),
      (text) => text.includes("ALB_BODY_LIMIT"),
    );
    assert.match(response, /^HTTP\/1\.1 413 /);
  } finally {
    await api.close();
  }
});

test("API applies its concurrency limit before routing a second request", async () => {
  let release;
  const released = new Promise((resolve) => { release = resolve; });
  let entered;
  const started = new Promise((resolve) => { entered = resolve; });
  const api = createApiServer({
    limits: { maxConcurrentRequests: 1 },
    engine: engine({
      verifyEvidenceBundle: async () => {
        entered();
        await released;
        return { valid: true, verifiedEntries: 1, totalEntries: 1, trustChecked: false, issues: [] };
      },
    }),
  });
  const address = await api.listen();
  try {
    const first = fetch(`${address.url}/v1/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    await started;
    const limited = await fetch(`${address.url}/healthz`);
    assert.equal(limited.status, 503);
    assert.equal((await json(limited)).code, "ALB_CONCURRENCY_LIMIT");
    release();
    assert.equal((await first).status, 200);
  } finally {
    release?.();
    await api.close();
  }
});

test("API rejects invalid UTF-8, query strings, malformed path identifiers, and malformed appeals", async () => {
  const api = createApiServer({ engine: engine() });
  const address = await api.listen();
  try {
    const invalidUtf8 = await fetch(`${address.url}/v1/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d]),
    });
    assert.equal(invalidUtf8.status, 400);
    assert.equal((await json(invalidUtf8)).code, "ALB_JSON_INVALID");

    const query = await fetch(`${address.url}/healthz?secret=must-not-be-reflected`);
    assert.equal(query.status, 400);
    const queryProblem = await json(query);
    assert.equal(queryProblem.code, "ALB_QUERY_UNSUPPORTED");
    assert.equal(JSON.stringify(queryProblem).includes("must-not-be-reflected"), false);

    const path = await fetch(`${address.url}/v1/decisions/%2F`);
    assert.equal(path.status, 400);
    assert.equal((await json(path)).code, "ALB_PATH_INVALID");

    const malformedAppeal = await fetch(`${address.url}/v1/appeals`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ schemaVersion: "1.0.0", sequence: 0 }),
    });
    assert.equal(malformedAppeal.status, 422);
    assert.equal((await json(malformedAppeal)).code, "ALB_SCHEMA_INVALID");
  } finally {
    await api.close();
  }
});

test("API body timeout rejects stalled uploads without waiting for the general request timeout", async () => {
  const api = createApiServer({
    engine: engine(),
    limits: { bodyTimeoutMs: 25, headersTimeoutMs: 250, requestTimeoutMs: 500 },
  });
  const address = await api.listen();
  try {
    const response = await rawHttpUntil(
      address.port,
      [
        "POST /v1/verify HTTP/1.1",
        `Host: 127.0.0.1:${address.port}`,
        "Content-Type: application/json",
        "Content-Length: 20",
        "Connection: close",
        "",
        "{",
      ].join("\r\n"),
      (text) => text.includes("ALB_BODY_TIMEOUT"),
    );
    assert.match(response, /^HTTP\/1\.1 408 /);
    assert.equal(response.includes("ALB_BODY_TIMEOUT"), true);
  } finally {
    await api.close();
  }
});

test("malformed nested evaluation input is a 422 and malformed bundles get a bounded report", async () => {
  const api = createApiServer({ engine: engine({ verifyEvidenceBundle }) });
  const address = await api.listen();
  try {
    const nested = await fetch(`${address.url}/v1/evaluations`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(evaluationRequest({ policy: null })),
    });
    assert.equal(nested.status, 422);
    assert.equal((await json(nested)).code, "ALB_EXTERNAL_PINS_REQUIRED");

    const malformedBundle = await fetch(`${address.url}/v1/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(malformedBundle.status, 200);
    const report = await json(malformedBundle);
    assert.equal(report.valid, false);
    assert.ok(report.issues.length > 0);
  } finally {
    await api.close();
  }
});

test("method and route failures use Problem Details", async () => {
  const api = createApiServer({ engine: engine() });
  const address = await api.listen();
  try {
    const method = await fetch(`${address.url}/v1/verify`);
    assert.equal(method.status, 405);
    assert.match(method.headers.get("content-type"), /^application\/problem\+json/);
    assert.equal((await json(method)).code, "ALB_METHOD_NOT_ALLOWED");

    const missing = await fetch(`${address.url}/not-a-route`);
    assert.equal(missing.status, 404);
    assert.equal((await json(missing)).code, "ALB_ROUTE_NOT_FOUND");
    assert.match((await fetch(`${address.url}/not-a-route`).then(json)).type, /^urn:mandatebound:problem:/);
  } finally {
    await api.close();
  }
});

test("API maps validation and store failures without exposing exception text", async () => {
  const api = createApiServer({
    engine: engine({ evaluateCase: () => { throw new TypeError("PRIVATE_VALIDATION_DETAIL"); } }),
  });
  const address = await api.listen();
  try {
    const invalid = await fetch(`${address.url}/v1/evaluations`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(evaluationRequest()),
    });
    assert.equal(invalid.status, 422);
    const invalidText = await invalid.text();
    assert.equal(invalidText.includes("PRIVATE_VALIDATION_DETAIL"), false);
    assert.equal(JSON.parse(invalidText).code, "ALB_ARTIFACT_INVALID");

    const missingDecisionAppeal = {
      schemaVersion: "1.0.0",
      artifactId: "event-api-missing",
      appealId: "appeal-api-missing",
      decisionId: "decision-api-missing",
      sequence: 1,
      eventType: "filed",
      actor: { id: "principal-synthetic", role: "principal" },
      occurredAt: "2026-07-23T00:00:00.000Z",
      reasonCodes: ["review_requested"],
    };
    const missing = await fetch(`${address.url}/v1/appeals`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(missingDecisionAppeal),
    });
    assert.equal(missing.status, 404);
    assert.equal((await json(missing)).code, "ALB_STORE_DECISION_NOT_FOUND");
  } finally {
    await api.close();
  }
});

test("simulation requests reject unknown fields and preserve bounded protocol error codes", async () => {
  const api = createApiServer({ engine: engine() });
  const address = await api.listen();
  try {
    const extra = await fetch(`${address.url}/v1/simulations`, {
      method: "POST",
      headers: { "content-type": "application/merge-patch+json" },
      body: JSON.stringify({ scenario: "principal", extra: true }),
    });
    assert.equal(extra.status, 422);
    assert.equal((await json(extra)).code, "ALB_SCENARIO_INVALID");

    const unknown = await fetch(`${address.url}/v1/simulations`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ scenario: "not-a-scenario" }),
    });
    assert.equal(unknown.status, 422);
    assert.equal((await json(unknown)).code, "ALB_SCENARIO_UNKNOWN");
  } finally {
    await api.close();
  }
});

test("Problem Details never reflects engine secrets or local paths", async () => {
  const canary = "PRIVATE_TOKEN_SHOULD_NOT_APPEAR";
  const logEvents = [];
  const api = createApiServer({
    engine: engine({ evaluateCase: () => { throw new Error(`${canary} C:\\private\\owner\\file.json`); } }),
    logger: (event) => logEvents.push(event),
  });
  const address = await api.listen();
  try {
    const response = await fetch(`${address.url}/v1/evaluations`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(evaluationRequest()),
    });
    assert.equal(response.status, 500);
    assert.match(response.headers.get("content-type"), /^application\/problem\+json/);
    const text = await response.text();
    assert.equal(text.includes(canary), false);
    assert.equal(text.includes("private\\owner"), false);
    assert.equal(JSON.parse(text).detail, "The request could not be completed.");
    assert.equal(JSON.stringify(logEvents).includes(canary), false);
    assert.equal(JSON.stringify(logEvents).includes("private\\owner"), false);
    assert.equal(logEvents.at(-1)?.detail, "The request could not be completed.");
  } finally {
    await api.close();
  }
});

test("API logger and Problem Details include JSON parse offset", async () => {
  const logEvents = [];
  const api = createApiServer({
    engine: engine(),
    logger: (event) => logEvents.push(event),
  });
  const address = await api.listen();
  try {
    const response = await fetch(`${address.url}/v1/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: '{"bundle":',
    });
    assert.equal(response.status, 400);
    const problem = await json(response);
    assert.equal(problem.code, "ALB_JSON_INVALID");
    assert.equal(problem.offset, 10);
    const event = logEvents.at(-1);
    assert.equal(event.code, "ALB_JSON_INVALID");
    assert.equal(event.status, 400);
    assert.equal(event.offset, 10);
    assert.match(event.detail, /offset 10/);
  } finally {
    await api.close();
  }
});
