/**
 * Thin barrel re-export that preserves the original `./ucp-ap2.js` import
 * path. The real implementation lives under `./ucp-ap2/` as a directory of
 * focused modules; this file just re-exports the public surface from
 * `./ucp-ap2/index.js`. The exported surface is byte-for-byte identical to
 * the original `src/ucp-ap2.ts`.
 */

export * from "./ucp-ap2/index.js";
