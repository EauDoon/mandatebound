/**
 * Thin placeholder. The original `test/ucp-ap2.test.mjs` scenarios have been
 * split across focused files alongside this one. They share helpers from
 * `test/ucp-ap2-helpers.mjs` and are discovered by `node --test`:
 *
 *   test/ucp-ap2.profile.test.mjs     - UCP profile + RFC 9530 Content-Digest
 *   test/ucp-ap2.merchant.test.mjs    - merchant detached JWS + authorization
 *   test/ucp-ap2.signature.test.mjs   - RFC 9421 parser, signature base, request evidence
 *   test/ucp-ap2.ap2-token.test.mjs   - compact AP2 parser, SD-JWT disclosures, token verification
 *   test/ucp-ap2.ap2-mandate.test.mjs - AP2 verifier boundaries, mandate variants, constraints
 *   test/ucp-ap2.lifecycle.test.mjs   - transaction lifecycle correlation
 *
 * This file intentionally contains no tests so node:test discovery treats it
 * as an empty suite rather than duplicating coverage.
 */
