import { Buffer } from "node:buffer";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { isIP, type AddressInfo } from "node:net";
import { TextDecoder } from "node:util";
import type {
  AppealEvent,
  BundleVerificationReport,
  EvidenceBundle,
  EvaluationInput,
  LiabilityDecision,
} from "./domain.js";
import { parseStrictJson, StrictJsonError } from "./strict-json.js";
import type { DecisionAppealStore } from "./store.js";
import { MemoryStore, StoreError } from "./store.js";
import { validateArtifact } from "./validation.js";

type MaybePromise<T> = T | Promise<T>;

export interface PlatformEngine {
  readonly verifyEvidenceBundle: (bundle: EvidenceBundle) => MaybePromise<BundleVerificationReport>;
  readonly evaluateCase: (input: EvaluationInput) => MaybePromise<LiabilityDecision>;
  readonly explainDecision: (decision: LiabilityDecision) => MaybePromise<unknown>;
}

async function resolveExport<T extends (...args: never[]) => unknown>(
  modules: readonly Record<string, unknown>[],
  names: readonly string[],
): Promise<T> {
  for (const module of modules) {
    for (const name of names) {
      const value = Reflect.get(module, name) as unknown;
      if (typeof value === "function") return value as T;
    }
  }
  throw new PlatformError("ALB_ENGINE_UNAVAILABLE", 503, "Evaluation engine is unavailable.");
}

export function createDefaultPlatformEngine(): PlatformEngine {
  return {
    async verifyEvidenceBundle(bundle) {
      const modules = [await import("./bundle.js"), await import("./engine.js")];
      const fn = await resolveExport<(value: EvidenceBundle) => MaybePromise<BundleVerificationReport>>(
        modules,
        ["verifyEvidenceBundle", "verifyBundle"],
      );
      return fn(bundle);
    },
    async evaluateCase(input) {
      const modules = [await import("./engine.js")];
      const fn = await resolveExport<(value: EvaluationInput) => MaybePromise<LiabilityDecision>>(
        modules,
        ["evaluateCase", "evaluateLiability", "evaluate"],
      );
      return fn(input);
    },
    async explainDecision(decision) {
      const modules = [await import("./engine.js")];
      const fn = await resolveExport<(value: LiabilityDecision) => MaybePromise<unknown>>(
        modules,
        ["explainDecision", "explain"],
      );
      return fn(decision);
    },
  };
}

export interface ApiLimits {
  readonly maxBodyBytes: number;
  readonly maxConcurrentRequests: number;
  readonly maxJsonDepth: number;
  readonly maxJsonNodes: number;
  readonly maxJsonObjectKeys: number;
  readonly bodyTimeoutMs: number;
  readonly requestTimeoutMs: number;
  readonly headersTimeoutMs: number;
  readonly keepAliveTimeoutMs: number;
}

const DEFAULT_LIMITS: ApiLimits = Object.freeze({
  maxBodyBytes: 1_048_576,
  maxConcurrentRequests: 16,
  maxJsonDepth: 32,
  maxJsonNodes: 100_000,
  maxJsonObjectKeys: 10_000,
  bodyTimeoutMs: 5_000,
  requestTimeoutMs: 10_000,
  headersTimeoutMs: 5_000,
  keepAliveTimeoutMs: 5_000,
});

export interface ApiLoggerEvent {
  readonly level: "info" | "warn" | "error";
  readonly code: string;
  readonly requestId: string;
  readonly status: number;
}

export interface CreateApiServerOptions {
  readonly store?: DecisionAppealStore;
  readonly engine?: PlatformEngine;
  readonly host?: string;
  readonly port?: number;
  readonly limits?: Partial<ApiLimits>;
  readonly logger?: (event: ApiLoggerEvent) => void;
}

export interface ApiAddress {
  readonly host: string;
  readonly port: number;
  readonly url: string;
}

export interface ApiServer {
  readonly server: Server;
  readonly store: DecisionAppealStore;
  listen(): Promise<ApiAddress>;
  address(): ApiAddress | undefined;
  close(): Promise<void>;
}

export interface ProblemDetails {
  readonly type: string;
  readonly title: string;
  readonly status: number;
  readonly detail: string;
  readonly code: string;
  readonly requestId: string;
}

class PlatformError extends Error {
  public readonly code: string;
  public readonly status: number;

  public constructor(code: string, status: number, message: string) {
    super(message);
    this.name = "PlatformError";
    this.code = code;
    this.status = status;
  }
}

function resolveLimits(overrides: Partial<ApiLimits> | undefined): ApiLimits {
  const limits = { ...DEFAULT_LIMITS, ...overrides };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new TypeError(`Invalid API limit: ${name}`);
    }
  }
  if (limits.headersTimeoutMs > limits.requestTimeoutMs) {
    throw new TypeError("Header timeout cannot exceed request timeout.");
  }
  return limits;
}

function isIpv4Loopback(host: string): boolean {
  const octets = host.split(".");
  return octets.length === 4 && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)
    && Number(octets[0]) === 127;
}

function mappedIpv4(host: string): string | undefined {
  const dotted = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(host);
  if (dotted !== null) return dotted[1];
  const groups = host.includes("::")
    ? (() => {
      const [left, right] = host.split("::");
      const leftGroups = left === "" ? [] : (left ?? "").split(":");
      const rightGroups = right === "" ? [] : (right ?? "").split(":");
      return [...leftGroups, ...Array.from({ length: 8 - leftGroups.length - rightGroups.length }, () => "0"), ...rightGroups];
    })()
    : host.split(":");
  if (groups.length !== 8 || groups[5]?.toLowerCase() !== "ffff") return undefined;
  const high = Number.parseInt(groups[6] ?? "", 16);
  const low = Number.parseInt(groups[7] ?? "", 16);
  if (!Number.isInteger(high) || !Number.isInteger(low) || high < 0 || low < 0) return undefined;
  return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
}

export function isLoopbackAddress(host: string): boolean {
  const normalized = host.trim().toLowerCase();
  if (isIP(normalized) === 4) return isIpv4Loopback(normalized);
  if (isIP(normalized) !== 6) return false;
  if (normalized === "::1") return true;
  const mapped = mappedIpv4(normalized);
  return mapped !== undefined && isIpv4Loopback(mapped);
}

function hostHeaderFor(host: string, port: number): string {
  const displayHost = isIP(host) === 6 ? `[${host.toLowerCase()}]` : host.toLowerCase();
  return `${displayHost}:${port}`;
}

export interface LocalRequestBoundaryFailure {
  readonly code: "ALB_PEER_FORBIDDEN" | "ALB_HOST_FORBIDDEN" | "ALB_ORIGIN_FORBIDDEN";
  readonly status: 403;
  readonly detail: string;
}

export function validateLocalRequest(
  request: Pick<IncomingMessage, "headers" | "rawHeaders" | "socket">,
  expectedHostHeader: string,
  expectedOrigin: string,
): LocalRequestBoundaryFailure | undefined {
  const peer = request.socket.remoteAddress;
  if (typeof peer !== "string" || !isLoopbackAddress(peer)) {
    return { code: "ALB_PEER_FORBIDDEN", status: 403, detail: "Requests must originate from a loopback peer." };
  }
  const hostHeaderCount = request.rawHeaders === undefined
    ? undefined
    : request.rawHeaders.filter((value, index) => index % 2 === 0 && value.toLowerCase() === "host").length;
  const host = request.headers.host;
  if (hostHeaderCount !== undefined && hostHeaderCount !== 1) {
    return { code: "ALB_HOST_FORBIDDEN", status: 403, detail: "The Host header must identify this loopback service exactly." };
  }
  if (typeof host !== "string" || host.toLowerCase() !== expectedHostHeader.toLowerCase()) {
    return { code: "ALB_HOST_FORBIDDEN", status: 403, detail: "The Host header must identify this loopback service exactly." };
  }
  const origin = request.headers.origin;
  if (origin !== undefined && (typeof origin !== "string" || origin !== expectedOrigin)) {
    return { code: "ALB_ORIGIN_FORBIDDEN", status: 403, detail: "The Origin header is not allowed for this loopback service." };
  }
  return undefined;
}

function setCommonHeaders(response: ServerResponse): void {
  response.setHeader("cache-control", "no-store");
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("content-security-policy", "default-src 'none'; frame-ancestors 'none'");
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  setCommonHeaders(response);
  const body = JSON.stringify(value);
  response.statusCode = status;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("content-length", Buffer.byteLength(body));
  response.end(body);
}

function titleFor(status: number): string {
  switch (status) {
    case 400: return "Invalid request";
    case 404: return "Resource not found";
    case 405: return "Method not allowed";
    case 408: return "Request timeout";
    case 409: return "State conflict";
    case 413: return "Request body too large";
    case 415: return "Unsupported media type";
    case 422: return "Unprocessable content";
    case 429: return "Too many requests";
    case 403: return "Forbidden";
    case 503: return "Service unavailable";
    default: return "Internal server error";
  }
}

function safeCode(value: string): string {
  return /^[A-Z0-9_]{3,80}$/.test(value) ? value : "ALB_INTERNAL";
}

function sendProblem(
  response: ServerResponse,
  status: number,
  codeValue: string,
  detail: string,
  requestId: string,
): void {
  setCommonHeaders(response);
  const code = safeCode(codeValue);
  const problem: ProblemDetails = {
    type: `urn:mandatebound:problem:${code.toLowerCase()}`,
    title: titleFor(status),
    status,
    detail,
    code,
    requestId,
  };
  const body = JSON.stringify(problem);
  response.statusCode = status;
  response.setHeader("content-type", "application/problem+json; charset=utf-8");
  response.setHeader("content-length", Buffer.byteLength(body));
  response.end(body);
}

function contentTypeIsJson(value: string | undefined): boolean {
  if (value === undefined) return false;
  const mediaType = value.split(";", 1)[0]?.trim().toLowerCase();
  return mediaType === "application/json" || mediaType?.endsWith("+json") === true;
}

async function readJsonBody(
  request: IncomingMessage,
  limits: ApiLimits,
): Promise<unknown> {
  if (!contentTypeIsJson(request.headers["content-type"])) {
    request.resume();
    throw new PlatformError("ALB_MEDIA_TYPE", 415, "A JSON request body is required.");
  }
  const encoding = request.headers["content-encoding"];
  if (encoding !== undefined && encoding.toLowerCase() !== "identity") {
    request.resume();
    throw new PlatformError("ALB_CONTENT_ENCODING", 415, "Compressed request bodies are not accepted.");
  }
  const lengthHeader = request.headers["content-length"];
  if (lengthHeader !== undefined) {
    if (!/^[0-9]+$/.test(lengthHeader)) {
      request.resume();
      throw new PlatformError("ALB_CONTENT_LENGTH", 400, "Content length is invalid.");
    }
    if (Number(lengthHeader) > limits.maxBodyBytes) {
      request.resume();
      throw new PlatformError("ALB_BODY_LIMIT", 413, "Request body exceeds the configured limit.");
    }
  }

  const body = await new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const cleanup = (): void => {
      clearTimeout(timeout);
      request.off("data", onData);
      request.off("end", onEnd);
      request.off("error", onError);
      request.off("aborted", onAborted);
    };
    const fail = (error: PlatformError): void => {
      if (settled) return;
      settled = true;
      cleanup();
      request.resume();
      reject(error);
    };
    const onData = (chunkValue: Buffer | Uint8Array | string): void => {
      const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue);
      total += chunk.length;
      if (total > limits.maxBodyBytes) {
        fail(new PlatformError("ALB_BODY_LIMIT", 413, "Request body exceeds the configured limit."));
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(Buffer.concat(chunks, total));
    };
    const onError = (): void => fail(new PlatformError("ALB_BODY_READ", 400, "Request body could not be read."));
    const onAborted = (): void => fail(new PlatformError("ALB_BODY_ABORTED", 400, "Request body was aborted."));
    const timeout = setTimeout(
      () => fail(new PlatformError("ALB_BODY_TIMEOUT", 408, "Request body timed out.")),
      limits.bodyTimeoutMs,
    );
    timeout.unref();
    request.on("data", onData);
    request.once("end", onEnd);
    request.once("error", onError);
    request.once("aborted", onAborted);
  });
  const total = body.length;
  if (total === 0) throw new PlatformError("ALB_JSON_INVALID", 400, "Request body is empty.");
  let raw: string;
  try {
    raw = new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw new PlatformError("ALB_JSON_INVALID", 400, "JSON body is invalid.");
  }
  try {
    return parseStrictJson(raw, {
      maxBytes: limits.maxBodyBytes,
      maxDepth: limits.maxJsonDepth,
      maxNodes: limits.maxJsonNodes,
      maxObjectKeys: limits.maxJsonObjectKeys,
    });
  } catch (error) {
    if (error instanceof StrictJsonError) {
      throw new PlatformError(error.code, error.code === "ALB_JSON_LIMIT" ? 413 : 400, "JSON body is invalid.");
    }
    throw error;
  }
}

function objectValue(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new PlatformError("ALB_BODY_SHAPE", 422, "Request body has an invalid shape.");
  }
  return value as Record<string, unknown>;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function evaluationInput(value: Record<string, unknown>): EvaluationInput {
  const allowed = new Set([
    "caseId",
    "asOf",
    "pins",
    "trustRootJwk",
    "mandate",
    "runtimeEvents",
    "executionReceipt",
    "priorReceipts",
    "incidentReport",
    "causationAttestations",
    "policy",
    "rulebook",
    "trustSnapshot",
    "evidenceBundle",
    "priorDecision",
    "appealId",
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new PlatformError("ALB_EVALUATION_SHAPE", 422, "Evaluation input has an invalid shape.");
  }
  const pins = value["pins"];
  if (
    typeof value["caseId"] !== "string"
    || typeof value["asOf"] !== "string"
    || !isObject(pins)
    || typeof pins["asOf"] !== "string"
    || typeof pins["policyDigest"] !== "string"
    || typeof pins["trustSnapshotDigest"] !== "string"
    || typeof pins["rulebookDigest"] !== "string"
    || !Array.isArray(pins["schemaDigests"])
    || typeof pins["engineVersion"] !== "string"
    || !Array.isArray(value["runtimeEvents"])
    || !Array.isArray(value["priorReceipts"])
    || !Array.isArray(value["causationAttestations"])
    || !isObject(value["policy"])
    || !isObject(value["rulebook"])
    || !isObject(value["trustSnapshot"])
  ) {
    throw new PlatformError("ALB_EXTERNAL_PINS_REQUIRED", 422, "A complete evaluation case with external pins is required.");
  }
  for (const optionalArtifact of [
    "trustRootJwk",
    "mandate",
    "executionReceipt",
    "incidentReport",
    "evidenceBundle",
    "priorDecision",
  ] as const) {
    const candidate = value[optionalArtifact];
    if (candidate !== undefined && !isObject(candidate)) {
      throw new PlatformError("ALB_EVALUATION_SHAPE", 422, "Evaluation input has an invalid shape.");
    }
  }
  return value as unknown as EvaluationInput;
}

function appealEvent(value: unknown): AppealEvent {
  const result = validateArtifact<AppealEvent>("appeal_event", value);
  if (!result.ok) {
    throw new PlatformError("ALB_SCHEMA_INVALID", 422, "Appeal event is invalid.");
  }
  return result.value;
}

function safePathIdentifier(encoded: string): string {
  let value: string;
  try {
    value = decodeURIComponent(encoded);
  } catch {
    throw new PlatformError("ALB_PATH_INVALID", 400, "Request path is invalid.");
  }
  if (!/^[A-Za-z0-9._:@+-]{1,160}$/.test(value)) {
    throw new PlatformError("ALB_PATH_INVALID", 400, "Request path is invalid.");
  }
  return value;
}

function errorMapping(error: unknown): PlatformError {
  if (error instanceof PlatformError) return error;
  if (error instanceof StoreError) {
    if (error.code.endsWith("NOT_FOUND")) return new PlatformError(error.code, 404, "Requested resource was not found.");
    if (/CONFLICT|FORK|DUPLICATE|SEQUENCE|TERMINAL|SUPERSESSION|EVENT_CAP/.test(error.code)) {
      return new PlatformError(error.code, 409, "Requested state transition conflicts with current state.");
    }
    if (/LIMIT/.test(error.code)) return new PlatformError(error.code, 413, "Configured storage limit was exceeded.");
    if (/LOCKED|CLOSED|WRITE|OPEN/.test(error.code)) return new PlatformError(error.code, 503, "Storage service is unavailable.");
    return new PlatformError(error.code, 422, "Stored artifact is invalid.");
  }
  const hasCode = typeof error === "object" && error !== null && "code" in error;
  const code = hasCode ? String(Reflect.get(error, "code")) : "ALB_INTERNAL";
  if (hasCode && /^ALB_[A-Z0-9_]{1,76}$/.test(code)) {
    return new PlatformError(code, 422, "Artifact validation failed.");
  }
  if (error instanceof TypeError || error instanceof RangeError) {
    return new PlatformError("ALB_ARTIFACT_INVALID", 422, "Protocol artifact is invalid.");
  }
  return new PlatformError("ALB_INTERNAL", 500, "The request could not be completed.");
}

let cachedOpenApi: unknown;

async function loadOpenApi(): Promise<unknown> {
  if (cachedOpenApi !== undefined) return cachedOpenApi;
  const url = new URL("../openapi/openapi.json", import.meta.url);
  try {
    cachedOpenApi = JSON.parse(await readFile(url, "utf8")) as unknown;
    return cachedOpenApi;
  } catch {
    throw new PlatformError("ALB_OPENAPI_UNAVAILABLE", 503, "OpenAPI document is unavailable.");
  }
}

export function createApiServer(options: CreateApiServerOptions = {}): ApiServer {
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 0;
  if (!isLoopbackAddress(host)) {
    throw new TypeError("API server must bind to a loopback address.");
  }
  if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) {
    throw new TypeError("Invalid API port.");
  }
  const limits = resolveLimits(options.limits);
  const store = options.store ?? new MemoryStore();
  const engine = options.engine ?? createDefaultPlatformEngine();
  let activeRequests = 0;
  let expectedHostHeader: string | undefined;
  let expectedOrigin: string | undefined;

  const server = createServer(async (request, response) => {
    const requestId = randomUUID();
    if (expectedHostHeader === undefined || expectedOrigin === undefined) {
      sendProblem(response, 503, "ALB_BOUNDARY_UNAVAILABLE", "The loopback request boundary is unavailable.", requestId);
      options.logger?.({ level: "error", code: "ALB_BOUNDARY_UNAVAILABLE", requestId, status: 503 });
      return;
    }
    const boundaryFailure = validateLocalRequest(request, expectedHostHeader, expectedOrigin);
    if (boundaryFailure !== undefined) {
      sendProblem(response, boundaryFailure.status, boundaryFailure.code, boundaryFailure.detail, requestId);
      options.logger?.({ level: "warn", code: boundaryFailure.code, requestId, status: boundaryFailure.status });
      return;
    }
    if (activeRequests >= limits.maxConcurrentRequests) {
      sendProblem(response, 503, "ALB_CONCURRENCY_LIMIT", "Service concurrency limit was reached.", requestId);
      options.logger?.({ level: "warn", code: "ALB_CONCURRENCY_LIMIT", requestId, status: 503 });
      return;
    }
    activeRequests += 1;
    try {
      const method = request.method ?? "";
      const parsedUrl = new URL(request.url ?? "/", "http://localhost");
      if (parsedUrl.search !== "") throw new PlatformError("ALB_QUERY_UNSUPPORTED", 400, "Query parameters are not supported.");
      const path = parsedUrl.pathname;

      if (method === "GET" && path === "/healthz") {
        sendJson(response, 200, { status: "ok" });
        return;
      }
      if (method === "GET" && path === "/readyz") {
        const verification = await store.verifyChain();
        if (!verification.valid) {
          sendJson(response, 503, { status: "not_ready" });
          return;
        }
        sendJson(response, 200, { status: "ready" });
        return;
      }
      if (method === "GET" && path === "/openapi.json") {
        sendJson(response, 200, await loadOpenApi());
        return;
      }
      if (method === "POST" && path === "/v1/verify") {
        const bundle = await readJsonBody(request, limits) as EvidenceBundle;
        const report = await engine.verifyEvidenceBundle(bundle);
        sendJson(response, 200, report);
        return;
      }
      if (method === "POST" && path === "/v1/evaluations") {
        const rawInput = objectValue(await readJsonBody(request, limits));
        const input = evaluationInput(rawInput);
        const decision = await engine.evaluateCase(input);
        await store.putDecision(decision);
        sendJson(response, 201, decision);
        return;
      }
      const decisionMatch = /^\/v1\/decisions\/([^/]+)$/.exec(path);
      if (method === "GET" && decisionMatch !== null) {
        const id = safePathIdentifier(decisionMatch[1] ?? "");
        const decision = await store.getDecision(id);
        if (decision === undefined) throw new PlatformError("ALB_DECISION_NOT_FOUND", 404, "Requested resource was not found.");
        sendJson(response, 200, decision);
        return;
      }
      if (method === "POST" && path === "/v1/appeals") {
        const event = appealEvent(await readJsonBody(request, limits));
        const appeal = await store.appendAppeal(event);
        sendJson(response, 201, appeal);
        return;
      }
      const appealEventsMatch = /^\/v1\/appeals\/([^/]+)\/events$/.exec(path);
      if (method === "POST" && appealEventsMatch !== null) {
        const id = safePathIdentifier(appealEventsMatch[1] ?? "");
        const event = appealEvent(await readJsonBody(request, limits));
        if (event.appealId !== id) throw new PlatformError("ALB_APPEAL_BINDING", 422, "Appeal event binding is invalid.");
        const appeal = await store.appendAppeal(event);
        sendJson(response, 201, appeal);
        return;
      }
      const appealMatch = /^\/v1\/appeals\/([^/]+)$/.exec(path);
      if (method === "GET" && appealMatch !== null) {
        const id = safePathIdentifier(appealMatch[1] ?? "");
        const appeal = await store.getAppeal(id);
        if (appeal === undefined) throw new PlatformError("ALB_APPEAL_NOT_FOUND", 404, "Requested resource was not found.");
        sendJson(response, 200, appeal);
        return;
      }
      if (method === "POST" && path === "/v1/simulations") {
        const body = objectValue(await readJsonBody(request, limits));
        if (Object.keys(body).some((key) => key !== "scenario")) {
          throw new PlatformError("ALB_SCENARIO_INVALID", 422, "Simulation request is invalid.");
        }
        const scenario = body["scenario"];
        if (typeof scenario !== "string") throw new PlatformError("ALB_SCENARIO_INVALID", 422, "Simulation scenario is invalid.");
        const { simulateScenario } = await import("./simulator.js");
        sendJson(response, 200, await simulateScenario(scenario));
        return;
      }

      const knownPath = path === "/v1/verify"
        || path === "/v1/evaluations"
        || path === "/v1/appeals"
        || path === "/v1/simulations"
        || path === "/healthz"
        || path === "/readyz"
        || path === "/openapi.json"
        || decisionMatch !== null
        || appealEventsMatch !== null
        || appealMatch !== null;
      if (knownPath) {
        response.setHeader("allow", "GET, POST");
        throw new PlatformError("ALB_METHOD_NOT_ALLOWED", 405, "HTTP method is not allowed.");
      }
      throw new PlatformError("ALB_ROUTE_NOT_FOUND", 404, "Requested resource was not found.");
    } catch (error) {
      const mapped = errorMapping(error);
      if (!response.headersSent) sendProblem(response, mapped.status, mapped.code, mapped.message, requestId);
      options.logger?.({
        level: mapped.status >= 500 ? "error" : "warn",
        code: mapped.code,
        requestId,
        status: mapped.status,
      });
    } finally {
      activeRequests -= 1;
    }
  });

  server.maxHeadersCount = 64;
  server.requestTimeout = limits.requestTimeoutMs;
  server.headersTimeout = limits.headersTimeoutMs;
  server.keepAliveTimeout = limits.keepAliveTimeoutMs;

  function currentAddress(): ApiAddress | undefined {
    const value = server.address();
    if (value === null || typeof value === "string") return undefined;
    const address = value as AddressInfo;
    const isIpv6 = address.family === "IPv6" || (address.family as unknown) === 6;
    const displayHost = isIpv6 ? `[${address.address}]` : address.address;
    return { host: address.address, port: address.port, url: `http://${displayHost}:${address.port}` };
  }

  function setBoundary(address: ApiAddress): void {
    expectedHostHeader = hostHeaderFor(address.host, address.port);
    expectedOrigin = `http://${expectedHostHeader}`;
  }

  return {
    server,
    store,
    async listen() {
      if (server.listening) {
        const existing = currentAddress();
        if (existing === undefined) throw new Error("API server address is unavailable.");
        setBoundary(existing);
        return existing;
      }
      await new Promise<void>((resolve, reject) => {
        const onError = (error: Error): void => reject(error);
        server.once("error", onError);
        server.listen(port, host, () => {
          server.off("error", onError);
          resolve();
        });
      });
      const address = currentAddress();
      if (address === undefined) throw new Error("API server address is unavailable.");
      setBoundary(address);
      return address;
    },
    address: currentAddress,
    async close() {
      if (server.listening) {
        await new Promise<void>((resolve, reject) => {
          server.close((error) => error === undefined ? resolve() : reject(error));
        });
      }
      await store.close();
    },
  };
}
