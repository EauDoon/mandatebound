#!/usr/bin/env node

import { Buffer } from "node:buffer";
import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { Readable, Writable } from "node:stream";
import type { AppealCheckpoint } from "./appeals.js";
import { replayAppealEvents } from "./appeals.js";
import {
  createApiServer,
  createDefaultPlatformEngine,
  type ApiServer,
  type PlatformEngine,
} from "./api.js";
import type {
  AppealEvent,
  EvidenceBundle,
  EvaluationInput,
  LiabilityDecision,
} from "./domain.js";
import { simulateScenario } from "./simulator.js";
import { parseStrictJson, StrictJsonError } from "./strict-json.js";
import type { DecisionAppealStore } from "./store.js";
import { JsonlStore, MemoryStore, StoreError } from "./store.js";
import { PROTOCOL_VERSION } from "./version.js";

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

  public constructor(code: string, exitCode: number, message: string) {
    super(message);
    this.name = "CliError";
    this.code = code;
    this.exitCode = exitCode;
  }
}

const VALUE_OPTIONS = new Set(["--store", "--host", "--port", "--scenario", "--input", "--format"]);
const FLAG_OPTIONS = new Set(["--allow-remote", "--help", "--version"]);
const MAX_CLI_INPUT_BYTES = 4 * 1024 * 1024;

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

async function readStdin(stream: Readable): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunkValue of stream) {
    const chunk = Buffer.isBuffer(chunkValue) ? chunkValue : Buffer.from(chunkValue as Uint8Array);
    size += chunk.length;
    if (size > MAX_CLI_INPUT_BYTES) {
      throw new CliError("ALB_CLI_INPUT_LIMIT", CLI_EXIT.INVALID, "Input exceeds the configured limit.");
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size).toString("utf8");
}

async function readInput(pathValue: string | undefined, stdin: Readable): Promise<unknown> {
  const path = pathValue ?? "-";
  let text: string;
  if (path === "-") {
    text = await readStdin(stdin);
  } else {
    try {
      const metadata = await lstat(path);
      if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_CLI_INPUT_BYTES) {
        throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "Input file is not accepted.");
      }
      text = await readFile(path, "utf8");
    } catch (error) {
      if (error instanceof CliError) throw error;
      throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "Input file could not be read.");
    }
  }
  try {
    return parseStrictJson(text, { maxBytes: MAX_CLI_INPUT_BYTES });
  } catch (error) {
    if (error instanceof StrictJsonError) {
      throw new CliError(error.code, CLI_EXIT.INVALID, "Input JSON is invalid.");
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
  if (error instanceof CliError) return error;
  if (error instanceof StoreError) {
    if (error.code.endsWith("NOT_FOUND")) return new CliError(error.code, CLI_EXIT.NOT_FOUND, "Requested resource was not found.");
    if (/CONFLICT|FORK|DUPLICATE|SEQUENCE|TERMINAL|SUPERSESSION|EVENT_CAP|LOCKED/.test(error.code)) {
      return new CliError(error.code, CLI_EXIT.CONFLICT, "Requested state transition conflicts with current state.");
    }
    if (/OPEN|WRITE|CLOSED/.test(error.code)) return new CliError(error.code, CLI_EXIT.UNAVAILABLE, "Storage is unavailable.");
    return new CliError(error.code, CLI_EXIT.INVALID, "Stored artifact is invalid.");
  }
  const hasCode = typeof error === "object" && error !== null && "code" in error;
  const code = hasCode ? String(Reflect.get(error, "code")) : "ALB_INTERNAL";
  if (hasCode && /^ALB_[A-Z0-9_]+$/.test(code)) return new CliError(code, CLI_EXIT.INVALID, "Artifact validation failed.");
  if (error instanceof TypeError || error instanceof RangeError) {
    return new CliError("ALB_ARTIFACT_INVALID", CLI_EXIT.INVALID, "Protocol artifact is invalid.");
  }
  return new CliError("ALB_INTERNAL", CLI_EXIT.INTERNAL, "Command could not be completed.");
}

function requireSingleInput(args: ParsedArgs): string | undefined {
  const option = args.options["input"];
  if (args.positionals.length > 1 || (args.positionals.length === 1 && option !== undefined)) {
    throw new CliError("ALB_CLI_USAGE", CLI_EXIT.USAGE, "Command accepts at most one input path.");
  }
  return typeof option === "string" ? option : args.positionals[0];
}

function assertJsonFormat(args: ParsedArgs): void {
  const format = args.options["format"];
  if (format !== undefined && format !== "json") {
    throw new CliError("ALB_CLI_USAGE", CLI_EXIT.USAGE, "Only JSON output is supported.");
  }
}

function assertAllowedOptions(args: ParsedArgs, allowed: readonly string[]): void {
  const allowlist = new Set([...allowed, "format"]);
  if (Object.keys(args.options).some((name) => !allowlist.has(name))) {
    throw new CliError("ALB_CLI_USAGE", CLI_EXIT.USAGE, "Command option is not valid for this command.");
  }
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
    assertJsonFormat(args);
    if (args.command === "help" || args.options["help"] === true) {
      writeJson(stdout, {
        ok: true,
        result: {
          name: "MandateBound",
          version: PROTOCOL_VERSION,
          usage: "mandatebound <verify|decide|explain|appeal|replay|simulate|serve> [--input PATH] [--format json]",
        },
      });
      return CLI_EXIT.SUCCESS;
    }
    if (args.command === "version" || args.options["version"] === true) {
      writeJson(stdout, { ok: true, result: { name: "MandateBound", version: PROTOCOL_VERSION } });
      return CLI_EXIT.SUCCESS;
    }
    switch (args.command) {
      case "verify": {
        assertAllowedOptions(args, ["input"]);
        const bundle = await readInput(requireSingleInput(args), stdin) as EvidenceBundle;
        const report = await engine.verifyEvidenceBundle(bundle);
        writeJson(stdout, { ok: report.valid, result: report });
        return report.valid ? CLI_EXIT.SUCCESS : CLI_EXIT.INVALID;
      }
      case "decide": {
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
        assertAllowedOptions(args, ["input"]);
        const decision = await readInput(requireSingleInput(args), stdin) as LiabilityDecision;
        const explanation = await engine.explainDecision(decision);
        writeJson(stdout, { ok: true, result: { explanation, legalEffect: "not-determined" } });
        return CLI_EXIT.SUCCESS;
      }
      case "appeal": {
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
        assertAllowedOptions(args, ["input"]);
        const input = await readInput(requireSingleInput(args), stdin);
        const record = Array.isArray(input) ? { events: input } : asObject(input);
        const events = record["events"];
        if (!Array.isArray(events)) throw new CliError("ALB_CLI_INPUT", CLI_EXIT.INVALID, "Replay input is invalid.");
        const checkpoint = record["checkpoint"] as AppealCheckpoint | undefined;
        const replay = replayAppealEvents(events as unknown as AppealEvent[], checkpoint);
        writeJson(stdout, { ok: replay.issues.length === 0, result: replay });
        return replay.issues.length === 0 ? CLI_EXIT.SUCCESS : CLI_EXIT.CONFLICT;
      }
      case "simulate": {
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
        assertAllowedOptions(args, ["store", "host", "port", "allow-remote"]);
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
            allowRemote: args.options["allow-remote"] === true,
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
      default:
        throw new CliError(
          "ALB_CLI_USAGE",
          CLI_EXIT.USAGE,
          "Command must be one of verify, decide, explain, appeal, replay, simulate, or serve.",
        );
    }
  } catch (error) {
    const mapped = mappedCliError(error);
    writeJson(stdout, { ok: false, error: { code: mapped.code, message: mapped.message } });
    writeJson(stderr, { level: "error", code: mapped.code, message: mapped.message });
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
