import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { auditJsonlStore } from "../dist/store-audit.js";
import { JsonlStore } from "../dist/store.js";
import { simulateScenario } from "../dist/simulator.js";

test("audit reads persisted decisions without locks or mutations and detects truncation", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mandatebound-audit-"));
  try {
    const path = join(dir, "snapshot.jsonl");
    const store = await JsonlStore.open(path);
    await store.putDecision((await simulateScenario("principal")).decision);
    const bytes = await readFile(path);
    const first = await auditJsonlStore(path);
    assert.equal(first.valid, true);
    assert.equal(first.completeness, "unproven");
    const checkpoint = { sequence: first.records, headHash: first.headHash };
    assert.equal((await auditJsonlStore(path, checkpoint)).completeness, "verified");
    assert.deepEqual(await readFile(path), bytes);
    await store.close();
    assert.deepEqual(await readdir(dir), ["snapshot.jsonl"]);
    await writeFile(path, "");
    assert.equal((await auditJsonlStore(path, checkpoint)).valid, false);
    await writeFile(path, bytes.toString().replace('"principal"', '"operator"'));
    assert.equal((await auditJsonlStore(path)).valid, false);
    await assert.rejects(auditJsonlStore(path, undefined, { maxFileBytes: 1 }), /limit/);
    await assert.rejects(auditJsonlStore(path, { sequence: 0, headHash: first.headHash }), /checkpoint/);
    await assert.rejects(auditJsonlStore(path, undefined, { maxFileBytes: -1 }), /limits/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("audit rejects malformed bytes and never creates missing stores", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mandatebound-audit-"));
  try {
    const path = join(dir, "snapshot.jsonl");
    await assert.rejects(auditJsonlStore(path), /opened/);
    assert.deepEqual(await readdir(dir), []);
    for (const bytes of [Buffer.from([0xff]), Buffer.from('{"a":1,"a":2}\n'), Buffer.from("\n")]) {
      await writeFile(path, bytes);
      await assert.rejects(auditJsonlStore(path), /invalid/);
      assert.deepEqual(await readFile(path), bytes);
    }
    await writeFile(path, "{}\n{}\n");
    await assert.rejects(auditJsonlStore(path, undefined, { maxRecords: 1 }), /record limit/);
    await assert.rejects(auditJsonlStore(path, undefined, { maxRecordBytes: 1 }), /invalid/);
    assert.equal((await auditJsonlStore(path)).valid, false);
    await writeFile(path, "\n".repeat(100_001));
    await assert.rejects(auditJsonlStore(path), /record limit/);
    await writeFile(path, "{}");
    assert.equal((await auditJsonlStore(path, undefined, { maxRecords: 1 })).records, 1);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
