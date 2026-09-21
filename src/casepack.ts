/**
 * Thin barrel re-export that preserves the original `./casepack.js` import
 * path. The real implementation lives under `./casepack/` as a directory of
 * focused modules; this file just re-exports the public surface from
 * `./casepack/index.js`. The exported surface is byte-for-byte identical to
 * the original `src/casepack.ts`.
 */

export * from "./casepack/index.js";
