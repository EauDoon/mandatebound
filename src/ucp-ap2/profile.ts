/**
 * Evidence-profile pin constants for the UCP/AP2 adapter and the strict AP2
 * v0.2.0 Mandate chain profile. These constants freeze the wire surface the
 * adapter accepts and the vct/kind enums downstream code switches on.
 */

/**
 * This module is an additive evidence adapter. It deliberately does not extend
 * or reinterpret MandateBound's v1 wire schemas.
 */
export const UCP_AP2_EVIDENCE_PROFILE = Object.freeze({
  id: "ucp-2026-04-08-rest+ap2-mandates-0.2.0",
  ucpVersion: "2026-04-08",
  ucpTransport: "rest",
  ucpService: "dev.ucp.shopping",
  checkoutCapability: "dev.ucp.shopping.checkout",
  ap2Extension: "dev.ucp.shopping.ap2_mandate",
  ap2Version: "0.2.0",
} as const);

/**
 * Strict AP2 v0.2.0 Mandate profile used by the dispute resolver. Unlike the
 * older additive adapter above, this profile accepts directly signed closed
 * SD-JWTs and canonical Delegate SD-JWT chains, never a trailing plain KB-JWT.
 */
export const AP2_V020_MANDATE_CHAIN_PROFILE = Object.freeze({
  id: "ap2-v0.2.0-mandate-chain+b4587ac1d055888a73b4b21750973cffba961793",
  ap2Version: "0.2.0",
  ap2ReleaseCommit: "b4587ac1d055888a73b4b21750973cffba961793",
  serialization: "delegate-sd-jwt-chain",
  chainSeparator: "~~",
  receiptReference: "sha256-terminal-compact-jws",
} as const);

export const AP2_MANDATE_VCTS = Object.freeze([
  "mandate.checkout.1",
  "mandate.checkout.open.1",
  "mandate.payment.1",
  "mandate.payment.open.1",
] as const);

export const AP2_RECEIPT_KINDS = Object.freeze([
  "checkout_receipt",
  "payment_receipt",
] as const);
