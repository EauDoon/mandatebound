import { open } from "node:fs/promises";
import { constants } from "node:fs";
import { isSha256Digest } from "./canonical.js";
import { parseStrictJson } from "./strict-json.js";
import { DEFAULT_JSONL_STORE_LIMITS, StoreError, verifyStoreRecords,
  type JsonlStoreOptions, type StoreCheckpoint } from "./store.js";

/** Reads an existing snapshot without creating files, taking writer locks, or repairing bytes. */
export async function auditJsonlStore(path: string, checkpoint?: StoreCheckpoint, options: JsonlStoreOptions = {}) {
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_JSONL_STORE_LIMITS.maxFileBytes;
  const maxRecords = options.maxRecords ?? DEFAULT_JSONL_STORE_LIMITS.maxRecords;
  const maxRecordBytes = options.maxRecordBytes ?? DEFAULT_JSONL_STORE_LIMITS.maxRecordBytes;
  if (![maxFileBytes, maxRecords, maxRecordBytes].every((n) => Number.isSafeInteger(n) && n >= 1)
    || maxFileBytes > DEFAULT_JSONL_STORE_LIMITS.maxFileBytes) {
    throw new StoreError("ALB_STORE_LIMIT", "Audit limits must be positive integers, at most 32 MiB per file.");
  }
  if (checkpoint !== undefined && (checkpoint === null || typeof checkpoint !== "object"
    || !Number.isSafeInteger(checkpoint.sequence) || checkpoint.sequence < 1
    || !isSha256Digest(checkpoint.headHash)
    || Object.keys(checkpoint).length !== 2)) {
    throw new StoreError("ALB_STORE_CHECKPOINT", "Audit checkpoint is invalid.");
  }
  // A FIFO must not block before the descriptor can be rejected as non-regular.
  const handle = await open(path, constants.O_RDONLY | constants.O_NONBLOCK).catch((error: unknown) => {
    throw new StoreError("ALB_STORE_OPEN", "Store snapshot could not be opened.", { cause: error });
  });
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size > maxFileBytes) {
      throw new StoreError("ALB_STORE_LIMIT", "Store snapshot exceeds the file limit.");
    }
    const buffer = Buffer.alloc(Math.min(before.size + 1, maxFileBytes + 1));
    let length = 0;
    while (length < buffer.length) {
      const read = await handle.read(buffer, length, buffer.length - length, length);
      if (read.bytesRead === 0) break;
      length += read.bytesRead;
    }
    const after = await handle.stat();
    if (length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs) {
      throw new StoreError("ALB_STORE_CHANGED", "Store changed during audit. Retry on a stable snapshot.");
    }
    let text: string;
    try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buffer.subarray(0, length)); }
    catch { throw new StoreError("ALB_STORE_CORRUPT", "Store contains invalid UTF-8."); }
    let recordCount = text.length === 0 || text.endsWith("\n") ? 0 : 1;
    for (let index = 0; index < text.length; index += 1) {
      if (text[index] === "\n") recordCount += 1;
      if (recordCount > maxRecords) throw new StoreError("ALB_STORE_LIMIT", "Store exceeds the record limit.");
    }
    const lines = text === "" ? [] : text.split("\n");
    if (lines.at(-1) === "") lines.pop();
    const records = lines.map((line, index) => {
      try { return parseStrictJson(line, { maxBytes: maxRecordBytes, maxStringBytes: maxRecordBytes }); }
      catch { throw new StoreError("ALB_STORE_CORRUPT", "Store contains an invalid JSON record.", { line: index + 1 }); }
    });
    return { format: "MandateBoundStoreAudit/v1" as const, ...verifyStoreRecords(records, checkpoint),
      bytes: length, legalEffect: "not-determined" as const };
  } finally { await handle.close(); }
}
