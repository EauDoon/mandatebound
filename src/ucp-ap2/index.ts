/**
 * Barrel re-export for the UCP/AP2 evidence adapter. The exported surface
 * here is identical to the original src/ucp-ap2.ts so downstream consumers
 * (`from "./ucp-ap2.js"`, `from "@oonyl/mandatebound/ucp-ap2"`) see no change.
 */

export type {
  Ap2MandateVct,
  Ap2ReceiptKind,
  Ap2ReceiptStatus,
  EcPublicJwk,
  DetachedMerchantAuthorization,
  EvidenceCoverageItem,
  EvidenceCoverageState,
  ExpectedMerchant,
  InteropIssue,
  InteropIssueImpact,
  InteropVerification,
  JoseEcAlgorithm,
  ParsedCompactAp2Token,
  ParsedContentDigest,
  ParsedJwt,
  ParsedSdJwtDisclosure,
  ParsedUcpSignatureInput,
  PinnedEcKeySnapshot,
  RawBodyDigestVerification,
  TransactionLifecycleCorrelation,
  TransactionLifecycleEvidence,
  TransactionLifecycleKind,
  UcpHttpAlgorithm,
  UcpIdempotencyRecord,
  UcpProfileSnapshot,
  UcpRequestEvidenceInput,
  VerifiedAp2CheckoutJwt,
  VerifiedAp2Mandate,
  VerifiedAp2MandateChain,
  VerifiedAp2Receipt,
  VerifiedUcpProfile,
  VerifiedUcpRequestEvidence,
  VerifyAp2CheckoutJwtOptions,
  VerifyAp2MandateOptions,
  VerifyAp2ReceiptOptions,
  VerifyDetachedMerchantAuthorizationOptions,
  VerifyUcpProfileOptions,
} from "./types.js";

export {
  AP2_MANDATE_VCTS,
  AP2_RECEIPT_KINDS,
  AP2_V020_MANDATE_CHAIN_PROFILE,
  UCP_AP2_EVIDENCE_PROFILE,
} from "./profile.js";

export { UcpAp2ParseError } from "./parse-error.js";

export {
  TRANSACTION_LIFECYCLE_KINDS,
} from "./transaction-lifecycle.js";

export {
  parseContentDigest,
  verifyRawBodyContentDigest,
} from "./content-digest.js";

export {
  verifyDetachedMerchantAuthorization,
} from "./merchant-auth.js";

export {
  parseCompactAp2Token,
} from "./jwt-parse.js";

export {
  verifyAp2Mandate,
} from "./mandate-verify.js";

export {
  verifyAp2MandateChain,
} from "./mandate-chain.js";

export {
  verifyAp2CheckoutJwt,
} from "./checkout-jwt.js";

export {
  verifyAp2Receipt,
  computeAp2MandateReference,
  computeAp2OpenMandateHash,
} from "./receipt.js";

export {
  verifyUcpProfileSnapshot,
} from "./ucp-profile.js";

export {
  parseUcpSignatureInput,
  buildUcpRequestSignatureBase,
  verifyUcpRequestEvidence,
} from "./ucp-request.js";

export {
  correlateTransactionLifecycle,
} from "./transaction-lifecycle.js";
