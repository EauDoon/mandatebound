#!/usr/bin/env node

import { Buffer } from "node:buffer";
import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { TextDecoder } from "node:util";
import type { Readable, Writable } from "node:stream";
import type { AppealCheckpoint } from "./appeals.js";
import { replayAppealEvents } from "./appeals.js";
import {
  createApiServer,
  createDefaultPlatformEngine,
  type ApiServer,
  type PlatformEngine,
} from "./api.js";
import {
  createMandateBoundCasePack,
  verifyMandateBoundCasePack,
  type CasePackVerificationAnchors,
  type MandateBoundCasePack,
} from "./casepack.js";
import {
  diffMandateBoundCasePacks,
  unpackMandateBoundCasePack,
} from "./casepack-tools.js";
import {
  assembleAp2DisputeEvidence,
  createAp2EvidenceTimeline,
  packAp2DisputeEvidence,
  renderAp2EvidenceTimelineHtml,
  verifyAp2DisputeEvidencePack,
  type AssembleAp2DisputeEvidenceInput,
  type PackAp2DisputeEvidenceInput,
} from "./ap2-dispute.js";
import { isSha256Digest } from "./canonical.js";
import { getConformanceStatement } from "./conformance.js";
import type {
  AppealEvent,
  EvidenceBundle,
  EvaluationInput,
  LiabilityDecision,
  Sha256Digest,
} from "./domain.js";
import {
  diffRulebooks,
  testPolicyPack,
  validatePolicyPack,
} from "./policy-tools.js";
import { createCaseReport, renderCaseReportHtml } from "./report.js";
import { simulateScenario } from "./simulator.js";
import { parseStrictJson, StrictJsonError } from "./strict-json.js";
import type { DecisionAppealStore } from "./store.js";
import { JsonlStore, MemoryStore, StoreError } from "./store.js";
import { ENGINE_VERSION, PROTOCOL_VERSION, RELEASE_VERSION } from "./version.js";
import { validateArtifact } from "./validation.js";

export const CLI_EXIT = Object.freeze({
  SUCCESS: 0,
  USAGE: 2,
  INVALID: 3,
  NOT_FOUND: 4,
  CONFLICT: 5,
  UNAVAILABLE: 6,
  INTERNAL: 70,
} as const);

export interface CliIo {
  readonly stdin?: Readable;
  readonly stdout?: Pick<Writable, "write">;
  readonly stderr?: Pick<Writable, "write">;
  readonly engine?: PlatformEngine;
  readonly store?: DecisionAppealStore;
  readonly signal?: AbortSignal;
  readonly onServer?: (server: ApiServer) => void;
}

interface ParsedArgs {
  readonly command?: string;
  readonly positionals: readonly string[];
  readonly options: Readonly<Record<string, string | boolean>>;
}

class CliError extends Error {
  public readonly code: string;
  public readonly exitCode: number;
  public readonly offset?: number;
  public readonly line?: number;

  public constructor(
    code: string,
    exitCode: number,
    message: string,
    options: { cause?: unknown; offset?: number; line?: number } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "CliError";
    this.code = code;
    this.exitCode = exitCode;
    if (options.offset !== undefined) this.offset = options.offset;
    if (options.line !== undefined) this.line = options.line;
  }
}

function diagnosticFields(error: { readonly offset?: number; readonly line?: number }): {
  readonly offset?: number;
  readonly line?: number;
} {
  return {
    ...(error.offset === undefined ? {} : { offset: error.offset }),
    ...(error.line === undefined ? {} : { line: error.line }),
  };
}

function locationFrom(error: unknown): { readonly offset?: number; readonly line?: number } {
  if (typeof error !== "object" || error === null) return {};
  const candidate = error as { readonly offset?: unknown; readonly line?: unknown };
  const offset = candidate.offset;
  const line = candidate.line;
  return {
    ...(typeof offset === "number" && Number.isSafeInteger(offset) && offset >= 0 ? { offset } : {}),
    ...(typeof line === "number" && Number.isSafeInteger(line) && line >= 1 ? { line } : {}),
  };
}

const VALUE_OPTIONS = new Set([
  "--store",
  "--host",
  "--port",
  "--scenario",
  "--input",
  "--format",
  "--expected-pack-digest",
]);
const FLAG_OPTIONS = new Set(["--help", "--version"]);
const MAX_CLI_INPUT_BYTES = 4 * 1024 * 1024;
const MAX_AP2_CLI_INPUT_BYTES = 17 * 1024 * 1024;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const CLI_COMMANDS = Object.freeze([
  { name: "verify", summary: "Verify a native evidence bundle" },
  { name: "decide", summary: "Evaluate a case and persist the policy result" },
  { name: "explain", summary: "Explain a stored decision without legal effect" },
  { name: "appeal", summary: "Append an appeal event" },
  { name: "replay", summary: "Replay an appeal event history" },
  { name: "simulate", summary: "Run a named synthetic scenario" },
  { name: "serve", summary: "Listen on loopback with the reference API" },
  { name: "casepack", summary: "Build, verify, unpack, or diff a CasePack" },
  { name: "policy", summary: "Validate, test, or diff a policy pack" },
  { name: "case-report", summary: "Render a CasePack report as JSON or HTML" },
  { name: "ap2-dispute", summary: "Resolve, pack, verify, or render AP2 dispute evidence" },
  { name: "conformance", summary: "Print the bounded capability statement" },
] as const);
const CLI_COMMAND_NAMES = CLI_COMMANDS.map((command) => command.name);
const CLI_USAGE =
  "mandatebound <verify|decide|explain|appeal|replay|simulate|serve|casepack|policy|case-report|ap2-dispute|conformance> [--input PATH] [--format json|html]";
const CLI_INPUT_HELP =
  "JSON commands read one document from --input PATH, a positional path, or stdin (-). Empty documents are rejected. Interactive terminals require an explicit path instead of implicit stdin.";

function decodeUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new CliError("ALB_JSON_INVALID", CLI_EXIT.INVALID, "Input JSON is invalid.");
  }
}

function parseArgs(argv: readonly string[]): ParsedArgs {
  const first = argv[0];
  const command = first === "--help" ? "help" : first === "--version" ? "version" : first;
  const positionals: string[] = [];
  const options: Record<string, string | boolean> = Object.create(null) as Record<string, string | boolean>;
  for (let index = 1; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === undefined) continue;
    if (VALUE_OPTIONS.has(argument)) {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("--")) {
        throw new CliError("ALB_CLI_USAGE", CLI_EXIT.USAGE, "A command option is missing its value.");
      }
      const name = argument.slice(2);
      if (options[name] !== undefined) {
        throw new CliError("ALB_CLI_USAGE", CLI_EXIT.USAGE, "Command option was provided more than once.");
      }
      options[name] = value;
      index += 1;
      continue;
    }
    if (FLAG_OPTIONS.has(argument)) {
      const name = argument.slice(2);
      if (options[name] !== undefined) {
        throw new CliError("ALB_CLI_USAGE", CLI_EXIT.USAGE, "Command option was provided more than once.");
      }
      options[name] = true;
      continue;
    }
    if (argument.startsWith("--")) {
      throw new CliError("ALB_CLI_USAGE", CLI_EXIT.USAGE, "Command option is not supported.");
    }
    positionals.push(argument);
  }
  return { ...(command === undefined ? {} : { command }), positionals, options };
}

function writeJson(stream: Pick<Writable, "write">, value: unknown): void {
  stream.write(`${JSON.stringify(value)}\n`);
}

async function readStdin(stream: Readable, maxBytes: number): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunkValue of stream) {
    const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue as Uint8Array);
    size += chunk.length;
    if (size > maxBytes) {
      throw new CliError("ALB_CLI_INPUT_LIMIT", CLI_EXIT.INVALID, "Input exceeds the configured limit.");
    }
    chunks.push(chunk);
  }
  return decodeUtf8(Buffer.concat(chunks, size));
}

function isInteractiveStdin(stream: Readable): boolean {
  return "isTTY" in stream && (stream as { readonly isTTY?: boolean }).isTTY === true;
}

async function readInput(
  pathValue: string | undefined,
  stdin: Readable,
  maxBytes = MAX_CLI_INPUT_BYTES,
): Promise<unknown> {
  if (pathValue === undefined && isInteractiveStdin(stdin)) {
    throw new CliError(
      "ALB_CLI_USAGE",
      CLI_EXIT.USAGE,
      "Command requires a JSON input path. Pass --input PATH, a positional path, or pipe JSON on stdin.",
    );
  }
  const path = pathValue ?? "-";
  let text: string;
  if (path === "-") {
    text = await readStdin(stdin, maxBytes);
  } else {
    try {
      const metadata = await lstat(path);
      if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > maxBytes) {
        throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "Input file is not accepted.");
      }
      text = decodeUtf8(await readFile(path));
    } catch (error) {
      if (error instanceof CliError) throw error;
      throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "Input file could not be read.", { cause: error });
    }
  }
  if (text.trim().length === 0) {
    throw new CliError(
      "ALB_CLI_INPUT",
      CLI_EXIT.INVALID,
      "Input is empty. Provide a JSON document via --input PATH or stdin.",
    );
  }
  try {
    return parseStrictJson(text, { maxBytes, maxStringBytes: maxBytes });
  } catch (error) {
    if (error instanceof StrictJsonError) {
      throw new CliError(error.code, CLI_EXIT.INVALID, error.message, {
        cause: error,
        offset: error.offset,
      });
    }
    throw error;
  }
}

function asObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "Input has an invalid shape.");
  }
  return value as Record<string, unknown>;
}

function hasExactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key))
    && Object.keys(value).every((key) => allowed.has(key));
}

async function storeFor(
  args: ParsedArgs,
  injected: DecisionAppealStore | undefined,
): Promise<{ store: DecisionAppealStore; owned: boolean }> {
  if (injected !== undefined) return { store: injected, owned: false };
  const path = args.options["store"];
  if (typeof path === "string") return { store: await JsonlStore.open(path), owned: true };
  return { store: new MemoryStore(), owned: true };
}

function mappedCliError(error: unknown): CliError {
  const location = locationFrom(error);
  if (error instanceof CliError) return error;
  if (error instanceof StoreError) {
    const options = { cause: error, ...location };
    if (error.code.endsWith("NOT_FOUND")) {
      return new CliError(error.code, CLI_EXIT.NOT_FOUND, "Requested resource was not found.", options);
    }
    if (/CONFLICT|FORK|DUPLICATE|SEQUENCE|TERMINAL|SUPERSESSION|EVENT_CAP|LOCKED/.test(error.code)) {
      return new CliError(error.code, CLI_EXIT.CONFLICT, "Requested state transition conflicts with current state.", options);
    }
    if (/OPEN|WRITE|CLOSED/.test(error.code)) {
      return new CliError(error.code, CLI_EXIT.UNAVAILABLE, "Storage is unavailable.", options);
    }
    return new CliError(error.code, CLI_EXIT.INVALID, "Stored artifact is invalid.", options);
  }
  const hasCode = typeof error === "object" && error !== null && "code" in error;
  const code = hasCode ? String(Reflect.get(error, "code")) : "ALB_INTERNAL";
  if (hasCode && /^ALB_[A-Z0-9_]+$/.test(code)) {
    return new CliError(code, CLI_EXIT.INVALID, "Artifact validation failed.", { cause: error, ...location });
  }
  if (error instanceof TypeError || error instanceof RangeError) {
    return new CliError("ALB_ARTIFACT_INVALID", CLI_EXIT.INVALID, "Protocol artifact is invalid.", {
      cause: error,
      ...location,
    });
  }
  return new CliError("ALB_INTERNAL", CLI_EXIT.INTERNAL, "Command could not be completed.", { cause: error });
}

function requireSingleInput(args: ParsedArgs): string | undefined {
  const option = args.options["input"];
  if (args.positionals.length > 1 || (args.positionals.length === 1 && option !== undefined)) {
    throw new CliError("ALB_CLI_USAGE", CLI_EXIT.USAGE, "Command accepts at most one input path.");
  }
  return typeof option === "string" ? option : args.positionals[0];
}

function assertOutputFormat(args: ParsedArgs, allowed: readonly string[]): string {
  const format = args.options["format"];
  const resolved = typeof format === "string" ? format : allowed[0];
  if (resolved === undefined || !allowed.includes(resolved)) {
    throw new CliError("ALB_CLI_USAGE", CLI_EXIT.USAGE, "Requested output format is not supported.");
  }
  return resolved;
}

function assertAllowedOptions(args: ParsedArgs, allowed: readonly string[]): void {
  const allowlist = new Set([...allowed, "format"]);
  if (Object.keys(args.options).some((name) => !allowlist.has(name))) {
    throw new CliError("ALB_CLI_USAGE", CLI_EXIT.USAGE, "Command option is not valid for this command.");
  }
}

function requireExpectedPackDigest(args: ParsedArgs): Sha256Digest {
  const value = args.options["expected-pack-digest"];
  if (typeof value !== "string" || !isSha256Digest(value)) {
    throw new CliError(
      "ALB_CLI_USAGE",
      CLI_EXIT.USAGE,
      "AP2 Pack verification requires --expected-pack-digest with a valid sha256 digest.",
    );
  }
  return value;
}

function parsePort(value: string | boolean | undefined): number {
  if (value === undefined) return 0;
  if (typeof value !== "string" || !/^[0-9]+$/.test(value)) {
    throw new CliError("ALB_CLI_USAGE", CLI_EXIT.USAGE, "Port is invalid.");
  }
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) {
    throw new CliError("ALB_CLI_USAGE", CLI_EXIT.USAGE, "Port is invalid.");
  }
  return port;
}

function requireSubcommandInput(
  args: ParsedArgs,
  actions: readonly string[],
): { readonly action: string; readonly path?: string } {
  const action = args.positionals[0];
  const expected = actions.join(", ");
  if (action === undefined) {
    throw new CliError(
      "ALB_CLI_USAGE",
      CLI_EXIT.USAGE,
      `Command action is missing. Expected one of: ${expected}.`,
    );
  }
  if (!actions.includes(action) || args.positionals.length > 2) {
    throw new CliError(
      "ALB_CLI_USAGE",
      CLI_EXIT.USAGE,
      `Command action is unsupported. Expected one of: ${expected}.`,
    );
  }
  const positionalPath = args.positionals[1];
  const optionPath = args.options["input"];
  if (positionalPath !== undefined && optionPath !== undefined) {
    throw new CliError("ALB_CLI_USAGE", CLI_EXIT.USAGE, "Command accepts at most one input path.");
  }
  const path = typeof optionPath === "string" ? optionPath : positionalPath;
  return { action, ...(path === undefined ? {} : { path }) };
}

function decodeBase64(value: unknown): Uint8Array {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > MAX_CLI_INPUT_BYTES * 2
    || !BASE64_PATTERN.test(value)
  ) {
    throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "Encoded evidence bytes are invalid.");
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) {
    throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "Encoded evidence bytes are invalid.");
  }
  return bytes;
}

function decodeCasePackAnchors(value: unknown): CasePackVerificationAnchors {
  const record = asObject(value);
  if (
    !hasExactKeys(
      record,
      ["asOf", "coveragePolicyDigest", "coverageContractDigest"],
      ["externalTrustSnapshotDigest", "rawEvidence"],
    )
    || typeof record["asOf"] !== "string"
    || typeof record["coveragePolicyDigest"] !== "string"
    || typeof record["coverageContractDigest"] !== "string"
    || (
      record["externalTrustSnapshotDigest"] !== undefined
      && typeof record["externalTrustSnapshotDigest"] !== "string"
    )
  ) {
    throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "CasePack anchors are invalid.");
  }
  let rawEvidence: { readonly referenceId: string; readonly bytes: Uint8Array }[] | undefined;
  if (record["rawEvidence"] !== undefined) {
    if (!Array.isArray(record["rawEvidence"]) || record["rawEvidence"].length > 1_024) {
      throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "CasePack raw evidence is invalid.");
    }
    rawEvidence = record["rawEvidence"].map((item) => {
      const entry = asObject(item);
      if (
        !hasExactKeys(entry, ["referenceId", "bytesBase64"])
        || typeof entry["referenceId"] !== "string"
      ) {
        throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "CasePack raw evidence is invalid.");
      }
      return {
        referenceId: entry["referenceId"],
        bytes: decodeBase64(entry["bytesBase64"]),
      };
    });
  }
  return {
    asOf: record["asOf"],
    coveragePolicyDigest: record["coveragePolicyDigest"] as CasePackVerificationAnchors["coveragePolicyDigest"],
    coverageContractDigest: record["coverageContractDigest"] as CasePackVerificationAnchors["coverageContractDigest"],
    ...(typeof record["externalTrustSnapshotDigest"] === "string"
      ? {
          externalTrustSnapshotDigest:
            record["externalTrustSnapshotDigest"] as NonNullable<
              CasePackVerificationAnchors["externalTrustSnapshotDigest"]
            >,
        }
      : {}),
    ...(rawEvidence === undefined ? {} : { rawEvidence }),
  };
}

function decodeCasePackInvocation(value: unknown): {
  readonly casePack: unknown;
  readonly anchors: CasePackVerificationAnchors;
} {
  const record = asObject(value);
  if (!hasExactKeys(record, ["casePack", "anchors"])) {
    throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "CasePack command input is invalid.");
  }
  return {
    casePack: record["casePack"],
    anchors: decodeCasePackAnchors(record["anchors"]),
  };
}

function buildCasePack(value: unknown): MandateBoundCasePack {
  const record = asObject(value);
  const material = Object.hasOwn(record, "casePack")
    ? (() => {
        if (!hasExactKeys(record, ["casePack"])) {
          throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "CasePack build input is invalid.");
        }
        return asObject(record["casePack"]);
      })()
    : record;
  if (Object.hasOwn(material, "casePackDigest")) {
    throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "CasePack build input is already sealed.");
  }
  const candidate = createMandateBoundCasePack(
    material as unknown as Omit<MandateBoundCasePack, "casePackDigest">,
  );
  const contract = asObject(candidate.coverageContract);
  const snapshot = candidate.externalTrustSnapshot;
  const verification = verifyMandateBoundCasePack(candidate, {
    asOf: candidate.createdAt,
    coveragePolicyDigest:
      contract["policyDigest"] as CasePackVerificationAnchors["coveragePolicyDigest"],
    coverageContractDigest:
      contract["contractDigest"] as CasePackVerificationAnchors["coverageContractDigest"],
    ...(snapshot === undefined
      ? {}
      : { externalTrustSnapshotDigest: snapshot.snapshotDigest }),
  });
  if (verification.integrityStatus === "conflicting") {
    throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "CasePack build input is invalid.");
  }
  return candidate;
}

export async function runCli(
  argv: readonly string[],
  io: CliIo = {},
): Promise<number> {
  const stdin = io.stdin ?? process.stdin;
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const engine = io.engine ?? createDefaultPlatformEngine();
  let ownedStore: DecisionAppealStore | undefined;
  try {
    const args = parseArgs(argv);
    if (args.command === "help" || args.options["help"] === true) {
      assertOutputFormat(args, ["json"]);
      writeJson(stdout, {
        ok: true,
        result: {
          name: "MandateBound",
          version: PROTOCOL_VERSION,
          releaseVersion: RELEASE_VERSION,
          engineVersion: ENGINE_VERSION,
          usage: CLI_USAGE,
          commands: CLI_COMMANDS,
          input: CLI_INPUT_HELP,
        },
      });
      return CLI_EXIT.SUCCESS;
    }
    if (args.command === "version" || args.options["version"] === true) {
      assertOutputFormat(args, ["json"]);
      writeJson(stdout, {
        ok: true,
        result: {
          name: "MandateBound",
          version: PROTOCOL_VERSION,
          releaseVersion: RELEASE_VERSION,
          engineVersion: ENGINE_VERSION,
        },
      });
      return CLI_EXIT.SUCCESS;
    }
    switch (args.command) {
      case "verify": {
        assertOutputFormat(args, ["json"]);
        assertAllowedOptions(args, ["input"]);
        const bundle = await readInput(requireSingleInput(args), stdin) as EvidenceBundle;
        const report = await engine.verifyEvidenceBundle(bundle);
        writeJson(stdout, { ok: report.valid, result: report });
        return report.valid ? CLI_EXIT.SUCCESS : CLI_EXIT.INVALID;
      }
      case "decide": {
        assertOutputFormat(args, ["json"]);
        assertAllowedOptions(args, ["input", "store"]);
        const input = await readInput(requireSingleInput(args), stdin) as EvaluationInput;
        const decision = await engine.evaluateCase(input);
        const resolved = await storeFor(args, io.store);
        if (resolved.owned) ownedStore = resolved.store;
        await resolved.store.putDecision(decision);
        writeJson(stdout, { ok: true, result: decision });
        return CLI_EXIT.SUCCESS;
      }
      case "explain": {
        assertOutputFormat(args, ["json"]);
        assertAllowedOptions(args, ["input"]);
        const decision = await readInput(requireSingleInput(args), stdin) as LiabilityDecision;
        const explanation = await engine.explainDecision(decision);
        writeJson(stdout, { ok: true, result: { explanation, legalEffect: "not-determined" } });
        return CLI_EXIT.SUCCESS;
      }
      case "appeal": {
        assertOutputFormat(args, ["json"]);
        assertAllowedOptions(args, ["input", "store"]);
        const input = await readInput(requireSingleInput(args), stdin);
        const record = asObject(input);
        const event = (record["event"] ?? input) as AppealEvent;
        const seedDecision = record["event"] === undefined ? undefined : record["decision"] as LiabilityDecision | undefined;
        const resolved = await storeFor(args, io.store);
        if (resolved.owned) ownedStore = resolved.store;
        if (seedDecision !== undefined) await resolved.store.putDecision(seedDecision);
        const appeal = await resolved.store.appendAppeal(event);
        writeJson(stdout, { ok: true, result: appeal });
        return CLI_EXIT.SUCCESS;
      }
      case "replay": {
        assertOutputFormat(args, ["json"]);
        assertAllowedOptions(args, ["input"]);
        const input = await readInput(requireSingleInput(args), stdin);
        const record = Array.isArray(input) ? { events: input } : asObject(input);
        const events = record["events"];
        if (!Array.isArray(events)) throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "Replay input is invalid.");
        const validatedEvents = events.map((event) => {
          const validation = validateArtifact<AppealEvent>("appeal_event", event);
          if (!validation.ok) {
            throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "Replay event is invalid.");
          }
          return validation.value;
        });
        const checkpoint = record["checkpoint"] as AppealCheckpoint | undefined;
        const replay = replayAppealEvents(validatedEvents, checkpoint);
        writeJson(stdout, { ok: replay.issues.length === 0, result: replay });
        return replay.issues.length === 0 ? CLI_EXIT.SUCCESS : CLI_EXIT.CONFLICT;
      }
      case "simulate": {
        assertOutputFormat(args, ["json"]);
        assertAllowedOptions(args, ["scenario"]);
        if (args.positionals.length > 1) {
          throw new CliError("ALB_CLI_USAGE", CLI_EXIT.USAGE, "Simulate accepts one scenario.");
        }
        const optionScenario = args.options["scenario"];
        const scenario = typeof optionScenario === "string" ? optionScenario : (args.positionals[0] ?? "all");
        const result = await simulateScenario(scenario);
        writeJson(stdout, { ok: true, result });
        return CLI_EXIT.SUCCESS;
      }
      case "serve": {
        assertOutputFormat(args, ["json"]);
        assertAllowedOptions(args, ["store", "host", "port"]);
        if (args.positionals.length !== 0) {
          throw new CliError("ALB_CLI_USAGE", CLI_EXIT.USAGE, "Serve does not accept an input path.");
        }
        const resolvedStore = await storeFor(args, io.store);
        let server: ApiServer | undefined;
        try {
          server = createApiServer({
            store: resolvedStore.store,
            engine,
            host: typeof args.options["host"] === "string" ? args.options["host"] : "127.0.0.1",
            port: parsePort(args.options["port"]),
          });
          io.onServer?.(server);
          if (io.signal !== undefined) {
            io.signal.addEventListener("abort", () => { void server?.close(); }, { once: true });
          }
          const address = await server.listen();
          writeJson(stdout, { ok: true, result: { status: "listening", host: address.host, port: address.port } });
          return CLI_EXIT.SUCCESS;
        } catch (error) {
          if (server !== undefined) await server.close().catch(() => undefined);
          else if (resolvedStore.owned) await resolvedStore.store.close().catch(() => undefined);
          throw error;
        }
      }
      case "casepack": {
        assertOutputFormat(args, ["json"]);
        assertAllowedOptions(args, ["input"]);
        const invocation = requireSubcommandInput(args, ["build", "verify", "unpack", "diff"]);
        const input = await readInput(invocation.path, stdin);
        if (invocation.action === "build") {
          writeJson(stdout, { ok: true, result: buildCasePack(input) });
          return CLI_EXIT.SUCCESS;
        }
        if (invocation.action === "verify") {
          const decoded = decodeCasePackInvocation(input);
          const report = verifyMandateBoundCasePack(decoded.casePack, decoded.anchors);
          writeJson(stdout, { ok: report.valid, result: report });
          return report.valid ? CLI_EXIT.SUCCESS : CLI_EXIT.INVALID;
        }
        if (invocation.action === "unpack") {
          const decoded = decodeCasePackInvocation(input);
          const report = unpackMandateBoundCasePack(decoded.casePack, decoded.anchors);
          writeJson(stdout, { ok: report.unpacked, result: report });
          return report.unpacked ? CLI_EXIT.SUCCESS : CLI_EXIT.INVALID;
        }
        const record = asObject(input);
        if (!hasExactKeys(record, ["before", "after"])) {
          throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "CasePack diff input is invalid.");
        }
        const before = decodeCasePackInvocation(record["before"]);
        const after = decodeCasePackInvocation(record["after"]);
        const report = diffMandateBoundCasePacks(
          before.casePack,
          before.anchors,
          after.casePack,
          after.anchors,
        );
        writeJson(stdout, { ok: report.comparable, result: report });
        return report.comparable ? CLI_EXIT.SUCCESS : CLI_EXIT.INVALID;
      }
      case "policy": {
        assertOutputFormat(args, ["json"]);
        assertAllowedOptions(args, ["input"]);
        const invocation = requireSubcommandInput(args, ["validate", "test", "diff"]);
        const input = await readInput(invocation.path, stdin);
        if (invocation.action === "validate") {
          const report = validatePolicyPack(input);
          writeJson(stdout, { ok: report.valid, result: report });
          return report.valid ? CLI_EXIT.SUCCESS : CLI_EXIT.INVALID;
        }
        if (invocation.action === "test") {
          const report = testPolicyPack(input);
          writeJson(stdout, { ok: report.valid && report.passed, result: report });
          if (!report.valid) return CLI_EXIT.INVALID;
          return report.passed ? CLI_EXIT.SUCCESS : CLI_EXIT.CONFLICT;
        }
        const report = diffRulebooks(input);
        writeJson(stdout, { ok: report.valid, result: report });
        return report.valid ? CLI_EXIT.SUCCESS : CLI_EXIT.INVALID;
      }
      case "case-report": {
        assertAllowedOptions(args, ["input"]);
        const format = assertOutputFormat(args, ["json", "html"]);
        const input = await readInput(requireSingleInput(args), stdin);
        const decoded = decodeCasePackInvocation(input);
        const report = createCaseReport(decoded.casePack, decoded.anchors);
        if (format === "html") stdout.write(renderCaseReportHtml(report));
        else writeJson(stdout, { ok: report.valid, result: report });
        return report.valid ? CLI_EXIT.SUCCESS : CLI_EXIT.INVALID;
      }
      case "ap2-dispute": {
        const invocation = requireSubcommandInput(args, ["resolve", "pack", "verify", "render"]);
        const needsPackAnchor = invocation.action === "verify" || invocation.action === "render";
        assertAllowedOptions(
          args,
          needsPackAnchor ? ["input", "expected-pack-digest"] : ["input"],
        );
        const verificationOptions = needsPackAnchor
          ? { expectedPackDigest: requireExpectedPackDigest(args) }
          : null;
        const format = assertOutputFormat(
          args,
          invocation.action === "render" ? ["json", "html"] : ["json"],
        );
        const input = asObject(await readInput(invocation.path, stdin, MAX_AP2_CLI_INPUT_BYTES));
        if (invocation.action === "resolve") {
          if (
            !hasExactKeys(input, ["transactionId", "asOf", "verificationPlan", "sources"])
            || typeof input["transactionId"] !== "string"
            || typeof input["asOf"] !== "string"
            || typeof input["verificationPlan"] !== "object"
            || input["verificationPlan"] === null
            || !Array.isArray(input["sources"])
          ) {
            throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "AP2 dispute input is invalid.");
          }
          const result = assembleAp2DisputeEvidence(
            input as unknown as AssembleAp2DisputeEvidenceInput,
          );
          writeJson(stdout, { ok: result.status === "evidence_verified", result });
          return result.status === "evidence_verified" ? CLI_EXIT.SUCCESS : CLI_EXIT.CONFLICT;
        }
        if (invocation.action === "pack") {
          if (
            !hasExactKeys(input, [
              "transactionId",
              "asOf",
              "createdAt",
              "verificationPlan",
              "sources",
              "checkoutVersions",
              "revocations",
            ])
          ) {
            throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "AP2 Evidence Pack input is invalid.");
          }
          const pack = packAp2DisputeEvidence(input as unknown as PackAp2DisputeEvidenceInput);
          writeJson(stdout, { ok: true, result: pack });
          return CLI_EXIT.SUCCESS;
        }
        if (verificationOptions === null) {
          throw new CliError("ALB_INTERNAL", CLI_EXIT.INTERNAL, "Command could not be completed.");
        }
        const packInput = hasExactKeys(input, ["ok", "result"]) && input["ok"] === true
          ? input["result"]
          : input;
        const verification = verifyAp2DisputeEvidencePack(packInput, verificationOptions);
        if (invocation.action === "verify") {
          writeJson(stdout, { ok: verification.status === "verified", result: verification });
          if (verification.packDigest === null) return CLI_EXIT.INVALID;
          return verification.status === "verified" ? CLI_EXIT.SUCCESS : CLI_EXIT.CONFLICT;
        }
        if (format === "html") {
          if (verification.packDigest === null) {
            throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "AP2 Evidence Pack input is invalid.");
          }
          stdout.write(renderAp2EvidenceTimelineHtml(
            packInput as Parameters<typeof renderAp2EvidenceTimelineHtml>[0],
            verificationOptions,
          ));
        } else {
          if (verification.packDigest === null) {
            writeJson(stdout, { ok: false, result: verification });
            return CLI_EXIT.INVALID;
          }
          writeJson(stdout, {
            ok: verification.status === "verified",
            result: {
              verification,
              timeline: createAp2EvidenceTimeline(
                packInput as Parameters<typeof createAp2EvidenceTimeline>[0],
                verificationOptions,
              ),
            },
          });
        }
        return verification.status === "verified" ? CLI_EXIT.SUCCESS : CLI_EXIT.CONFLICT;
      }
      case "conformance": {
        assertOutputFormat(args, ["json"]);
        assertAllowedOptions(args, []);
        if (args.positionals.length !== 0) {
          throw new CliError("ALB_CLI_USAGE", CLI_EXIT.USAGE, "Conformance does not accept input.");
        }
        writeJson(stdout, { ok: true, result: getConformanceStatement() });
        return CLI_EXIT.SUCCESS;
      }
      default:
        throw new CliError(
          "ALB_CLI_USAGE",
          CLI_EXIT.USAGE,
          args.command === undefined
            ? `Command is required. Expected one of: ${CLI_COMMAND_NAMES.join(", ")}. Run mandatebound --help.`
            : `Command is not supported. Expected one of: ${CLI_COMMAND_NAMES.join(", ")}. Run mandatebound --help.`,
        );
    }
  } catch (error) {
    const mapped = mappedCliError(error);
    const diagnostic = { code: mapped.code, message: mapped.message, ...diagnosticFields(mapped) };
    writeJson(stdout, { ok: false, error: diagnostic });
    writeJson(stderr, { level: "error", ...diagnostic });
    return mapped.exitCode;
  } finally {
    await ownedStore?.close().catch(() => undefined);
  }
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(resolve(entry)).href) {
  runCli(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  }).catch(() => {
    process.exitCode = CLI_EXIT.INTERNAL;
  });
}
