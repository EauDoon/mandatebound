import { open, readFile, stat, unlink, type FileHandle } from "node:fs/promises";
import { Buffer } from "node:buffer";
import { TextDecoder } from "node:util";
import type { AppealEvent, LiabilityDecision, Sha256Digest } from "./domain.js";
import { canonicalize, sha256Digest } from "./canonical.js";
import { DEFAULT_STRICT_JSON_LIMITS, parseStrictJson } from "./strict-json.js";
import { validateArtifact } from "./validation.js";
import {
  AppealError,
  type AppealCheckpoint,
  type AppealHistory,
  assertAppealAppendable,
  replayAppealEvents,
} from "./appeals.js";

export type StoreRecordType = "decision" | "appeal_event";

export interface StoreRecord {
  readonly format: "agent-liability-store-record/v1";
  readonly sequence: number;
  readonly previousHash?: Sha256Digest;
  readonly recordType: StoreRecordType;
  readonly recordId: string;
  readonly entityId: string;
  readonly payload: LiabilityDecision | AppealEvent;
  readonly recordHash: Sha256Digest;
}

export interface StoreCheckpoint {
  readonly sequence: number;
  readonly headHash: Sha256Digest;
}

export interface StoreVerification {
  readonly valid: boolean;
  readonly records: number;
  readonly headHash?: Sha256Digest;
  readonly completeness: "unproven" | "verified" | "mismatch";
  readonly issues: readonly { readonly code: string; readonly message: string }[];
}

export interface DecisionAppealStore {
  putDecision(decision: LiabilityDecision): Promise<LiabilityDecision>;
  getDecision(decisionId: string): Promise<LiabilityDecision | undefined>;
  appendAppeal(event: AppealEvent): Promise<AppealHistory>;
  getAppeal(appealId: string, checkpoint?: AppealCheckpoint): Promise<AppealHistory | undefined>;
  verifyChain(checkpoint?: StoreCheckpoint): Promise<StoreVerification>;
  close(): Promise<void>;
}

export class StoreError extends Error {
  public readonly code: string;
  public readonly line?: number;

  public constructor(code: string, message: string, options: { cause?: unknown; line?: number } = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "StoreError";
    this.code = code;
    if (options.line !== undefined) this.line = options.line;
  }
}

interface RecordBody {
  readonly format: "agent-liability-store-record/v1";
  readonly sequence: number;
  readonly previousHash?: Sha256Digest;
  readonly recordType: StoreRecordType;
  readonly recordId: string;
  readonly entityId: string;
  readonly payload: LiabilityDecision | AppealEvent;
}

function recordBody(record: StoreRecord): RecordBody {
  return {
    format: record.format,
    sequence: record.sequence,
    ...(record.previousHash === undefined ? {} : { previousHash: record.previousHash }),
    recordType: record.recordType,
    recordId: record.recordId,
    entityId: record.entityId,
    payload: record.payload,
  };
}

export function storeRecordHash(body: RecordBody): Sha256Digest {
  return sha256Digest(canonicalize(body));
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function isRecord(value: unknown): value is StoreRecord {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<StoreRecord>;
  const keys = Object.keys(value);
  return candidate.format === "agent-liability-store-record/v1"
    && Number.isSafeInteger(candidate.sequence)
    && (candidate.sequence ?? 0) >= 1
    && typeof candidate.recordType === "string"
    && (candidate.recordType === "decision" || candidate.recordType === "appeal_event")
    && typeof candidate.recordId === "string" && candidate.recordId.length > 0 && candidate.recordId.length <= 512
    && typeof candidate.entityId === "string" && candidate.entityId.length > 0 && candidate.entityId.length <= 512
    && (candidate.previousHash === undefined || /^sha256:[a-f0-9]{64}$/.test(candidate.previousHash))
    && typeof candidate.recordHash === "string" && /^sha256:[a-f0-9]{64}$/.test(candidate.recordHash)
    && typeof candidate.payload === "object"
    && candidate.payload !== null
    && keys.every((key) => [
      "format", "sequence", "previousHash", "recordType", "recordId", "entityId", "payload", "recordHash",
    ].includes(key));
}

function payloadIsValid(recordType: StoreRecordType, payload: unknown): boolean {
  return recordType === "decision"
    ? validateArtifact<LiabilityDecision>("liability_decision", payload).ok
    : validateArtifact<AppealEvent>("appeal_event", payload).ok;
}

function assertPayloadValid(recordType: StoreRecordType, payload: unknown): void {
  if (!payloadIsValid(recordType, payload)) {
    throw new StoreError("ALB_STORE_ARTIFACT_INVALID", "Stored artifact is invalid.");
  }
}

function appealBindsDecision(
  appeals: ReadonlyMap<string, readonly AppealEvent[]>,
  appealId: string | undefined,
  decisionId: string,
): boolean {
  return appealId !== undefined && appeals.get(appealId)?.[0]?.decisionId === decisionId;
}

const REVIEWER_EVENTS = new Set<AppealEvent["eventType"]>(["review_started", "upheld", "reversed"]);

function assertAppealPolicyAllows(
  decision: LiabilityDecision,
  existingEvents: readonly AppealEvent[],
  event: AppealEvent,
): void {
  if (existingEvents.length >= decision.appealPolicy.maxAppealEvents) {
    throw new StoreError("ALB_APPEAL_EVENT_CAP", "Appeal event cap has been reached.");
  }
  if (
    REVIEWER_EVENTS.has(event.eventType)
    && (
      event.actor.role !== "reviewer"
      || !decision.appealPolicy.reviewerIds.includes(event.actor.id)
    )
  ) {
    throw new StoreError("ALB_APPEAL_REVIEWER_UNAUTHORIZED", "Appeal reviewer assertion is not allowed by policy.");
  }
}

export function verifyStoreRecords(
  records: readonly unknown[],
  checkpoint?: StoreCheckpoint,
): StoreVerification {
  const issues: { code: string; message: string }[] = [];
  const ids = new Map<string, Sha256Digest>();
  const children = new Map<string, number>();
  const decisions = new Map<string, LiabilityDecision>();
  const appeals = new Map<string, AppealEvent[]>();
  let previousHash: Sha256Digest | undefined;

  for (let index = 0; index < records.length; index += 1) {
    const candidate = records[index];
    if (!isRecord(candidate)) {
      issues.push({ code: "ALB_STORE_RECORD", message: "Store record has an invalid shape." });
      previousHash = undefined;
      continue;
    }
    const record = candidate;
    const payloadValid = payloadIsValid(record.recordType, record.payload);
    if (!payloadValid) {
      issues.push({ code: "ALB_STORE_ARTIFACT", message: "Store record contains an invalid artifact." });
    }
    if (record.sequence !== index + 1) {
      issues.push({ code: "ALB_STORE_SEQUENCE", message: "Store sequence is not contiguous." });
    }
    if (record.previousHash !== previousHash) {
      issues.push({ code: "ALB_STORE_CHAIN", message: "Store hash chain is invalid." });
    }
    let computed: Sha256Digest | undefined;
    try {
      computed = storeRecordHash(recordBody(record));
    } catch {
      issues.push({ code: "ALB_STORE_RECORD", message: "Store record cannot be canonicalized." });
    }
    if (computed !== undefined && computed !== record.recordHash) {
      issues.push({ code: "ALB_STORE_HASH", message: "Store record digest does not match." });
    }
    const prior = ids.get(record.recordId);
    if (prior !== undefined && prior !== record.recordHash) {
      issues.push({ code: "ALB_STORE_EQUIVOCATION", message: "Store record identifier was reused." });
    } else if (prior !== undefined) {
      issues.push({ code: "ALB_STORE_DUPLICATE", message: "Store record was duplicated." });
    }
    ids.set(record.recordId, record.recordHash);
    if (record.previousHash !== undefined) {
      children.set(record.previousHash, (children.get(record.previousHash) ?? 0) + 1);
    }
    if (payloadValid) {
      if (record.recordType === "decision") {
        const decision = record.payload as LiabilityDecision;
        let transitionValid = true;
        if (record.entityId !== decision.artifactId || decisions.has(decision.artifactId)) {
          issues.push({ code: "ALB_STORE_DECISION_BINDING", message: "Stored decision binding is invalid." });
          transitionValid = false;
        }
        if (decision.supersedesDecisionId !== undefined) {
          const original = decisions.get(decision.supersedesDecisionId);
          if (
            original === undefined
            || !appealBindsDecision(appeals, decision.appealId, decision.supersedesDecisionId)
            || original.caseId !== decision.caseId
          ) {
            issues.push({ code: "ALB_STORE_SUPERSESSION", message: "Stored decision supersession is invalid." });
            transitionValid = false;
          }
        }
        if (transitionValid) decisions.set(decision.artifactId, decision);
      } else {
        const event = record.payload as AppealEvent;
        const decision = decisions.get(event.decisionId);
        const existing = appeals.get(event.appealId) ?? [];
        let transitionValid = true;
        if (decision === undefined) {
          issues.push({ code: "ALB_STORE_DECISION_NOT_FOUND", message: "Stored appeal decision is missing." });
          transitionValid = false;
        } else {
          try {
            assertAppealPolicyAllows(decision, existing, event);
            assertAppealAppendable(existing, event);
          } catch (error) {
            const code = error instanceof StoreError || error instanceof AppealError
              ? error.code
              : "ALB_STORE_TRANSITION";
            issues.push({ code, message: "Stored appeal transition is invalid." });
            transitionValid = false;
          }
          if (transitionValid && event.eventType === "reversed") {
            const superseding = event.supersedingDecisionId === undefined
              ? undefined
              : decisions.get(event.supersedingDecisionId);
            if (
              superseding === undefined
              || superseding.supersedesDecisionId !== event.decisionId
              || superseding.appealId !== event.appealId
            ) {
              issues.push({ code: "ALB_STORE_SUPERSESSION", message: "Stored appeal reversal is invalid." });
              transitionValid = false;
            }
          }
        }
        if (transitionValid) {
          existing.push(event);
          appeals.set(event.appealId, existing);
        }
      }
    }
    previousHash = record.recordHash;
  }

  if ([...children.values()].some((count) => count > 1)) {
    issues.push({ code: "ALB_STORE_FORK", message: "Store history contains a fork." });
  }

  let completeness: StoreVerification["completeness"] = "unproven";
  if (checkpoint !== undefined) {
    completeness = checkpoint.sequence === records.length && checkpoint.headHash === previousHash
      ? "verified"
      : "mismatch";
    if (completeness === "mismatch") {
      issues.push({ code: "ALB_STORE_CHECKPOINT", message: "Store checkpoint does not match the history." });
    }
  }

  return {
    valid: issues.length === 0,
    records: records.length,
    ...(previousHash === undefined ? {} : { headHash: previousHash }),
    completeness,
    issues,
  };
}

export interface MemoryStoreOptions {
  readonly records?: readonly StoreRecord[];
}

export class MemoryStore implements DecisionAppealStore {
  protected readonly records: StoreRecord[] = [];
  private readonly decisions = new Map<string, LiabilityDecision>();
  private readonly appeals = new Map<string, AppealEvent[]>();
  private writer: Promise<void> = Promise.resolve();
  private closed = false;

  public constructor(options: MemoryStoreOptions = {}) {
    if (options.records !== undefined) {
      const verification = verifyStoreRecords(options.records);
      if (!verification.valid) {
        throw new StoreError("ALB_STORE_CORRUPT", "Store history is invalid.");
      }
      for (const record of options.records) this.indexRecord(clone(record));
    }
  }

  private indexRecord(record: StoreRecord): void {
    this.records.push(record);
    if (record.recordType === "decision") {
      this.decisions.set(record.entityId, clone(record.payload as LiabilityDecision));
      return;
    }
    const event = clone(record.payload as AppealEvent);
    const existing = this.appeals.get(event.appealId) ?? [];
    existing.push(event);
    this.appeals.set(event.appealId, existing);
  }

  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.writer.then(operation, operation);
    this.writer = result.then(() => undefined, () => undefined);
    return result;
  }

  protected async persist(records: readonly StoreRecord[]): Promise<void> {
    void records;
  }

  protected ensureOpen(): void {
    if (this.closed) throw new StoreError("ALB_STORE_CLOSED", "Store is closed.");
  }

  private nextRecord(
    recordType: StoreRecordType,
    recordId: string,
    entityId: string,
    payload: LiabilityDecision | AppealEvent,
    offset = 0,
  ): StoreRecord {
    const previous = offset === 0
      ? this.records.at(-1)?.recordHash
      : undefined;
    const sequence = this.records.length + offset + 1;
    const body: RecordBody = {
      format: "agent-liability-store-record/v1",
      sequence,
      ...(previous === undefined ? {} : { previousHash: previous }),
      recordType,
      recordId,
      entityId,
      payload: clone(payload),
    };
    return { ...body, recordHash: storeRecordHash(body) };
  }

  public async putDecision(decision: LiabilityDecision): Promise<LiabilityDecision> {
    return this.enqueue(async () => {
      this.ensureOpen();
      assertPayloadValid("decision", decision);
      const existing = this.decisions.get(decision.artifactId);
      if (existing !== undefined) {
        if (canonicalize(existing) === canonicalize(decision)) return clone(existing);
        throw new StoreError("ALB_STORE_CONFLICT", "Decision identifier already exists.");
      }
      if (decision.supersedesDecisionId !== undefined) {
        const original = this.decisions.get(decision.supersedesDecisionId);
        if (original === undefined) {
          throw new StoreError("ALB_STORE_SUPERSESSION", "Superseded decision does not exist.");
        }
        if (!appealBindsDecision(this.appeals, decision.appealId, decision.supersedesDecisionId)) {
          throw new StoreError("ALB_STORE_SUPERSESSION", "Superseding decision is not bound to the superseded decision's appeal.");
        }
        if (original.caseId !== decision.caseId) {
          throw new StoreError("ALB_STORE_SUPERSESSION", "Superseding decision case does not match.");
        }
      }
      const record = this.nextRecord("decision", `decision:${decision.artifactId}`, decision.artifactId, decision);
      await this.persist([record]);
      this.indexRecord(record);
      return clone(decision);
    });
  }

  public async getDecision(decisionId: string): Promise<LiabilityDecision | undefined> {
    this.ensureOpen();
    const decision = this.decisions.get(decisionId);
    return decision === undefined ? undefined : clone(decision);
  }

  public async appendAppeal(event: AppealEvent): Promise<AppealHistory> {
    return this.enqueue(async () => {
      this.ensureOpen();
      assertPayloadValid("appeal_event", event);
      const decision = this.decisions.get(event.decisionId);
      if (decision === undefined) {
        throw new StoreError("ALB_STORE_DECISION_NOT_FOUND", "Appealed decision does not exist.");
      }
      const existing = this.appeals.get(event.appealId) ?? [];
      const priorById = this.records.find((record) => record.recordId === `appeal:${event.artifactId}`);
      if (priorById !== undefined) {
        if (canonicalize(priorById.payload) === canonicalize(event)) return replayAppealEvents(existing);
        throw new StoreError("ALB_STORE_CONFLICT", "Appeal event identifier already exists.");
      }
      assertAppealPolicyAllows(decision, existing, event);
      try {
        assertAppealAppendable(existing, event);
      } catch (error) {
        if (error instanceof AppealError) throw new StoreError(error.code, error.message);
        throw error;
      }
      if (event.eventType === "reversed") {
        const superseding = event.supersedingDecisionId === undefined
          ? undefined
          : this.decisions.get(event.supersedingDecisionId);
        if (
          superseding === undefined
          || superseding.supersedesDecisionId !== event.decisionId
          || superseding.appealId !== event.appealId
        ) {
          throw new StoreError("ALB_STORE_SUPERSESSION", "Reversal does not reference a valid superseding decision.");
        }
      }
      const record = this.nextRecord("appeal_event", `appeal:${event.artifactId}`, event.appealId, event);
      await this.persist([record]);
      this.indexRecord(record);
      return replayAppealEvents(this.appeals.get(event.appealId) ?? []);
    });
  }

  public async getAppeal(
    appealId: string,
    checkpoint?: AppealCheckpoint,
  ): Promise<AppealHistory | undefined> {
    this.ensureOpen();
    const events = this.appeals.get(appealId);
    return events === undefined ? undefined : replayAppealEvents(events, checkpoint);
  }

  public async verifyChain(checkpoint?: StoreCheckpoint): Promise<StoreVerification> {
    this.ensureOpen();
    return verifyStoreRecords(this.records, checkpoint);
  }

  public async close(): Promise<void> {
    await this.writer;
    this.closed = true;
  }
}

export interface JsonlStoreLimits {
  readonly maxFileBytes: number;
  readonly maxRecords: number;
  readonly maxRecordBytes: number;
}

export const DEFAULT_JSONL_STORE_LIMITS: JsonlStoreLimits = Object.freeze({
  maxFileBytes: 32 * 1024 * 1024,
  maxRecords: 100_000,
  maxRecordBytes: DEFAULT_STRICT_JSON_LIMITS.maxBytes,
});

export interface JsonlStoreOptions {
  readonly maxFileBytes?: number;
  readonly maxRecords?: number;
  readonly maxRecordBytes?: number;
}

export class JsonlStore extends MemoryStore {
  private readonly dataHandle: FileHandle;
  private readonly lockHandle: FileHandle;
  private readonly lockPath: string;
  private readonly maxFileBytes: number;
  private readonly maxRecords: number;
  private readonly maxRecordBytes: number;
  private needsSeparator: boolean;
  private appendStateUncertain = false;
  private jsonlClosed = false;

  private constructor(
    dataHandle: FileHandle,
    lockHandle: FileHandle,
    lockPath: string,
    records: readonly StoreRecord[],
    needsSeparator: boolean,
    maxFileBytes: number,
    maxRecords: number,
    maxRecordBytes: number,
  ) {
    super({ records });
    this.dataHandle = dataHandle;
    this.lockHandle = lockHandle;
    this.lockPath = lockPath;
    this.needsSeparator = needsSeparator;
    this.maxFileBytes = maxFileBytes;
    this.maxRecords = maxRecords;
    this.maxRecordBytes = maxRecordBytes;
  }

  protected override ensureOpen(): void {
    super.ensureOpen();
    if (this.appendStateUncertain) {
      throw new StoreError("ALB_STORE_WRITE", "Store append state is uncertain.");
    }
  }

  public static async open(filePath: string, options: JsonlStoreOptions = {}): Promise<JsonlStore> {
    const maxFileBytes = options.maxFileBytes ?? DEFAULT_JSONL_STORE_LIMITS.maxFileBytes;
    const maxRecords = options.maxRecords ?? DEFAULT_JSONL_STORE_LIMITS.maxRecords;
    const requestedRecordBytes = options.maxRecordBytes ?? DEFAULT_JSONL_STORE_LIMITS.maxRecordBytes;
    if (![maxFileBytes, maxRecords, requestedRecordBytes].every((value) => Number.isSafeInteger(value) && value >= 1)) {
      throw new TypeError("Store limits must be positive safe integers.");
    }
    const maxRecordBytes = Math.min(requestedRecordBytes, maxFileBytes);
    const lockPath = `${filePath}.lock`;
    let lockHandle: FileHandle | undefined;
    let dataHandle: FileHandle | undefined;
    try {
      lockHandle = await open(lockPath, "wx", 0o600);
      dataHandle = await open(filePath, "a+", 0o600);
      const metadata = await stat(filePath);
      if (!metadata.isFile() || metadata.size > maxFileBytes) {
        throw new StoreError("ALB_STORE_LIMIT", "Store file exceeds configured limits.");
      }
      const bytes = metadata.size === 0 ? undefined : await readFile(filePath);
      let text = "";
      try {
        if (bytes !== undefined) text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
      } catch (error) {
        throw new StoreError("ALB_STORE_CORRUPT", "Store contains invalid UTF-8.", { cause: error });
      }
      const needsSeparator = text.length > 0 && !text.endsWith("\n");
      const lines = text.length === 0 ? [] : text.split("\n");
      if (lines.at(-1) === "") lines.pop();
      if (lines.length > maxRecords) {
        throw new StoreError("ALB_STORE_LIMIT", "Store record count exceeds configured limits.");
      }
      const records: StoreRecord[] = [];
      for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index];
        if (line === undefined) continue;
        let parsed: unknown;
        try {
          parsed = parseStrictJson(line, { maxBytes: maxRecordBytes, maxStringBytes: maxRecordBytes });
        } catch (error) {
          throw new StoreError(
            "ALB_STORE_CORRUPT",
            `Store contains an invalid record at line ${String(index + 1)}.`,
            { cause: error, line: index + 1 },
          );
        }
        if (!isRecord(parsed)) {
          throw new StoreError(
            "ALB_STORE_CORRUPT",
            `Store contains an invalid record at line ${String(index + 1)}.`,
            { line: index + 1 },
          );
        }
        records.push(parsed);
      }
      return new JsonlStore(
        dataHandle,
        lockHandle,
        lockPath,
        records,
        needsSeparator,
        maxFileBytes,
        maxRecords,
        maxRecordBytes,
      );
    } catch (error) {
      await dataHandle?.close().catch(() => undefined);
      await lockHandle?.close().catch(() => undefined);
      if (lockHandle !== undefined) await unlink(lockPath).catch(() => undefined);
      if (error instanceof StoreError) throw error;
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "EEXIST") throw new StoreError("ALB_STORE_LOCKED", "Store already has a writer.", { cause: error });
      throw new StoreError("ALB_STORE_OPEN", "Store could not be opened.", { cause: error });
    }
  }

  protected override async persist(records: readonly StoreRecord[]): Promise<void> {
    const lines = records.map((record) => canonicalize(record));
    if (lines.some((line) => Buffer.byteLength(line) > this.maxRecordBytes)) {
      throw new StoreError("ALB_STORE_LIMIT", "Store append exceeds configured limits.");
    }
    const text = `${this.needsSeparator ? "\n" : ""}${lines.join("\n")}\n`;
    let appendStarted = false;
    try {
      const metadata = await this.dataHandle.stat();
      if (
        this.records.length + records.length > this.maxRecords
        || metadata.size + Buffer.byteLength(text) > this.maxFileBytes
      ) {
        throw new StoreError("ALB_STORE_LIMIT", "Store append exceeds configured limits.");
      }
      appendStarted = true;
      await this.dataHandle.appendFile(text, "utf8");
      this.needsSeparator = false;
      await this.dataHandle.sync();
    } catch (error) {
      if (appendStarted) this.appendStateUncertain = true;
      if (error instanceof StoreError) throw error;
      throw new StoreError("ALB_STORE_WRITE", "Store append failed.", { cause: error });
    }
  }

  public override async close(): Promise<void> {
    if (this.jsonlClosed) return;
    await super.close();
    this.jsonlClosed = true;
    await this.dataHandle.close();
    await this.lockHandle.close();
    await unlink(this.lockPath).catch(() => undefined);
  }
}
