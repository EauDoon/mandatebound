// Run after npm run build. All inputs, evidence, keys, and decisions are synthetic.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { auditJsonlStore, JsonlStore, simulateScenario } from "../dist/index.js";

const directory = await mkdtemp(join(tmpdir(), "mandatebound-operator-demo-"));
let store;
try {
  const path = join(directory, "synthetic.jsonl");
  store = await JsonlStore.open(path);
  const simulation = await simulateScenario("unresolved");
  await store.putDecision(simulation.decision);
  await store.close();
  store = undefined;
  const unanchored = await auditJsonlStore(path);
  // Demonstration only: in actual use retain the checkpoint in an independent trusted record.
  const checkpoint = { sequence: unanchored.records, headHash: unanchored.headHash };
  const anchored = await auditJsonlStore(path, checkpoint);
  process.stdout.write(`${JSON.stringify({
    scenario: simulation.scenario,
    policyOutcome: simulation.decision.outcome,
    unanchoredCompleteness: unanchored.completeness,
    anchoredCompleteness: anchored.completeness,
    valid: anchored.valid,
    legalEffect: "not-determined",
  }, null, 2)}\n`);
} finally {
  await store?.close();
  await rm(directory, { recursive: true, force: true });
}
