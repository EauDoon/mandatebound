import fc from "fast-check";

/**
 * Shared deterministic seed for the fast-check property suites.
 *
 * fast-check picks a random seed per run by default. That makes the suite
 * non-reproducible in two ways that both matter for a reference engine:
 *
 * 1. Coverage is not stable. Different random inputs reach different
 *    branches, so the coverage gate measures a different set of code paths
 *    on every run, and a green run does not mean the previous run exercised
 *    the same thing.
 * 2. A failure is not replayable. Without a recorded seed, a property
 *    failure seen once in CI usually cannot be reproduced locally.
 *
 * Pinning the seed makes every run identical and any failure trivially
 * replayable. Set FAST_CHECK_SEED to a specific integer to replay or explore
 * a different stream, for example:
 *
 *   FAST_CHECK_SEED=12345 npm test
 */
const DEFAULT_SEED = 20260923;

function resolveSeed() {
  const raw = process.env.FAST_CHECK_SEED;
  if (raw === undefined || raw === "") return DEFAULT_SEED;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`FAST_CHECK_SEED must be a non-negative integer, received: ${raw}`);
  }
  return parsed;
}

export const FAST_CHECK_SEED = resolveSeed();

fc.configureGlobal({ seed: FAST_CHECK_SEED });
