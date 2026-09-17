import type { JsonObject } from "../domain.js";
import { UcpAp2ParseError } from "./parse-error.js";
import { requireJsonObject } from "./primitives.js";

/**
 * Small UCP profile-shape helpers used by verifyUcpProfileSnapshot. Kept in
 * their own file so the profile verifier focuses on the protocol decision
 * tree, not capability-array parsing.
 */

export function extractCapabilityEntries(
  capabilities: JsonObject,
  name: string,
  path: string,
): readonly JsonObject[] {
  const value = capabilities[name];
  if (!Array.isArray(value) || value.length === 0) {
    throw new UcpAp2ParseError(`Missing capability at ${path}`);
  }
  return value.map((entry, index) => requireJsonObject(entry, `${path}[${String(index)}]`));
}

export function hasVersionEntry(entries: readonly JsonObject[], version: string): boolean {
  return entries.some((entry) => entry.version === version);
}
