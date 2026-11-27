import { Buffer } from "node:buffer";
import { sha256Digest } from "./canonical.js";
import type { JsonObject, JsonValue, Sha256Digest } from "./domain.js";
import type {
  EcPublicJwk,
  InteropIssue,
  ParsedJwt,
  ParsedSdJwtDisclosure,
  PinnedEcKeySnapshot,
} from "./ucp-ap2/types.js";
import { UcpAp2ParseError } from "./ucp-ap2/parse-error.js";
import { parseStrictJsonObject } from "./strict-json.js";
import {
  base64UrlSha256,
  decodeBase64Url,
  eligibilityIssue,
  isObject,
  parseEpoch,
  requireSafeInteger,
  strictUtf8,
  upstreamIssue,
} from "./ucp-ap2/primitives.js";
import { checkKeySnapshot, validateEcJwk, verifyParsedJwtSignature } from "./ucp-ap2/jwk.js";
import { parseCompactAp2Token, parseJwtCompact } from "./ucp-ap2/jwt-parse.js";

/**
 * Verifiable Intent (VI) v0.1 chain verification for dispute evidence.
 *
 * VI is the layered SD-JWT credential format maintained by Mastercard in
 * agent-intent/verifiable-intent: an issuer credential (L1) binds the user's
 * key, a user mandate (L2) carries final values (Immediate mode) or constraints plus an agent key
 * (Autonomous mode), and in Autonomous mode the agent signs a payment
 * fulfillment (L3a) and a checkout fulfillment (L3b).
 *
 * This verifier replays one preserved chain at a caller-supplied instant. It
 * is deliberately stricter than the reference SDK: signatures are checked over
 * the exact received segments (never a re-encoding), merchants and payees
 * match by `id` only, an allowlist that could match an undisclosed entry is
 * not reported as satisfied, and network-enforced constraints are reported as
 * not evaluable. It never echoes tokens, holder data, or payment instrument
 * identifiers, and it never determines a dispute outcome or legal effect.
 */

const PIN = "356c29635f1c44df7de02edb58699ca9f29bece6";

export const VERIFIABLE_INTENT_PROFILE = Object.freeze({
  id: `verifiable-intent-v0.1+${PIN}`,
  specVersion: "0.1",
  repository: "agent-intent/verifiable-intent",
  commit: PIN,
  issuerCredentialType: "https://credentials.mastercard.com/card",
  algorithm: "ES256",
  disclosureDigest: "sha-256",
  clockSkewSeconds: 60,
  maxL3LifetimeSeconds: 3600,
  mandatePairs: 1,
  builtInNetworkAccess: false,
  legalEffect: "not-determined",
} as const);

const CONSTRAINT_CHECKOUT_MERCHANTS = "mandate.checkout.allowed_merchants";
const CONSTRAINT_LINE_ITEMS = "mandate.checkout.line_items";
const CONSTRAINT_PAYEES = "mandate.payment.allowed_payees";
const CONSTRAINT_AMOUNT = "mandate.payment.amount_range";
const CONSTRAINT_REFERENCE = "mandate.payment.reference";
const NETWORK_ENFORCED_CONSTRAINTS: ReadonlySet<string> = new Set([
  "mandate.payment.agent_recurrence",
  "mandate.payment.budget",
  "mandate.payment.recurrence",
]);

/** Constraint types this profile evaluates, and the ones it reports as network enforced. */
export const VERIFIABLE_INTENT_CONSTRAINT_SUPPORT = Object.freeze({
  evaluated: Object.freeze([
    CONSTRAINT_CHECKOUT_MERCHANTS,
    CONSTRAINT_LINE_ITEMS,
    CONSTRAINT_PAYEES,
    CONSTRAINT_AMOUNT,
    CONSTRAINT_REFERENCE,
  ]),
  networkEnforced: Object.freeze([...NETWORK_ENFORCED_CONSTRAINTS].sort()),
});

const VCT_CHECKOUT_OPEN = "mandate.checkout.open.1";
const VCT_PAYMENT_OPEN = "mandate.payment.open.1";
const VCT_CHECKOUT_FINAL = "mandate.checkout.1";
const VCT_PAYMENT_FINAL = "mandate.payment.1";
const TYP_L1 = "sd+jwt";
const TYP_L2_IMMEDIATE = "kb-sd-jwt";
const TYP_L2_AUTONOMOUS = "kb-sd-jwt+kb";
const TYP_L3 = "kb-sd-jwt";
const MAX_PRESENTATION_BYTES = 1_048_576;
const ES256_ONLY: ReadonlySet<"ES256"> = new Set(["ES256"]);

export interface VerifiableIntentExpectations {
  readonly l2Audience?: string;
  readonly l2Nonce?: string;
  readonly l3PaymentAudience?: string;
  readonly l3PaymentNonce?: string;
  readonly l3CheckoutAudience?: string;
  readonly l3CheckoutNonce?: string;
}

export interface VerifyVerifiableIntentChainInput {
  /** Exact L1 issuer presentation, `<jwt>~<disclosure>~...~`. */
  readonly l1: string;
  /** Exact L2 user mandate presentation, full or selective. */
  readonly l2: string;
  /** Exact L2 presentation L3a binds with sd_hash; defaults to `l2`. */
  readonly l2PaymentPresentation?: string;
  /** Exact L2 presentation L3b binds with sd_hash; defaults to `l2`. */
  readonly l2CheckoutPresentation?: string;
  readonly l3Payment?: string;
  readonly l3Checkout?: string;
  readonly issuerKeySnapshot: PinnedEcKeySnapshot;
  readonly expectedIssuerKeySourceDigest: Sha256Digest;
  /** Optional pinned merchant key for the checkout_jwt signature. */
  readonly merchantKeySnapshot?: PinnedEcKeySnapshot;
  readonly expectedMerchantKeySourceDigest?: Sha256Digest;
  /** The instant the chain was presented, not the review date. */
  readonly asOf: string | number;
  readonly expected?: VerifiableIntentExpectations;
}

export type VerifiableIntentGate = "passed" | "failed" | "not_presented" | "not_applicable" | "not_checked";
export type VerifiableIntentConstraintStatus = "satisfied" | "violated" | "not_evaluable";

export interface VerifiableIntentConstraintResult {
  readonly mandate: "checkout" | "payment";
  readonly type: string;
  readonly status: VerifiableIntentConstraintStatus;
  /** A fixed reason code; it never contains a disclosed value. */
  readonly reason: string;
}

export interface VerifiableIntentChainReport {
  readonly schemaId: "MandateBoundVerifiableIntentChainReport/v1";
  readonly profileId: typeof VERIFIABLE_INTENT_PROFILE.id;
  readonly asOf: number | null;
  readonly mode: "immediate" | "autonomous" | null;
  readonly chainStatus: "verified" | "ineligible" | "invalid";
  readonly upstreamValid: boolean;
  readonly evidenceEligible: boolean;
  readonly gates: {
    readonly issuerCredential: VerifiableIntentGate;
    readonly userMandate: VerifiableIntentGate;
    readonly agentPayment: VerifiableIntentGate;
    readonly agentCheckout: VerifiableIntentGate;
    readonly crossReference: VerifiableIntentGate;
    readonly checkoutJwtSignature: VerifiableIntentGate;
    readonly audienceAndNonce: VerifiableIntentGate;
  };
  readonly disclosed: {
    readonly checkoutMandate: boolean;
    readonly paymentMandate: boolean;
  };
  readonly transaction: {
    readonly checkoutHash: string | null;
    readonly transactionId: string | null;
    readonly paymentAmount: { readonly currency: string; readonly amount: number } | null;
    readonly payeeId: string | null;
  };
  readonly constraints: readonly VerifiableIntentConstraintResult[];
  readonly constraintsResult: "satisfied" | "violated" | "incomplete" | "not_applicable" | "not_evaluated";
  readonly presentationDigests: {
    readonly l1: Sha256Digest | null;
    readonly l2: Sha256Digest | null;
    readonly l2PaymentPresentation: Sha256Digest | null;
    readonly l2CheckoutPresentation: Sha256Digest | null;
    readonly l3Payment: Sha256Digest | null;
    readonly l3Checkout: Sha256Digest | null;
  };
  readonly issues: readonly InteropIssue[];
  readonly disputeOutcome: "not-determined";
  readonly legalEffect: "not-determined";
  readonly reportDigest: Sha256Digest;
}

interface ViPresentation {
  readonly exact: string;
  readonly jwt: ParsedJwt;
  readonly disclosures: readonly ParsedSdJwtDisclosure[];
}

interface ResolvedMandate {
  readonly value: JsonObject;
  readonly disclosure: ParsedSdJwtDisclosure;
}

class ChainFailure extends Error {}

function fail(message: string): never {
  throw new UcpAp2ParseError(message);
}

function messageOf(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function presentationDigest(value: unknown): Sha256Digest | null {
  return typeof value === "string" && value.length > 0 ? sha256Digest(value) : null;
}

/**
 * Parse one exact VI presentation: an SD-JWT without a key-binding JWT, so it
 * ends with `~`. Every disclosure must be unique and referenced by the signed
 * payload, either from `_sd` or from a `delegate_payload` reference (the
 * reference SDK's L3 credentials carry no `_sd`).
 */
function parsePresentation(value: unknown, label: string): ViPresentation {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    Buffer.byteLength(value, "utf8") > MAX_PRESENTATION_BYTES
  ) {
    fail(`${label} presentation is empty, not a string, or exceeds the byte limit`);
  }
  if (!/^[\x21-\x7e]+$/u.test(value)) fail(`${label} presentation is not printable ASCII`);
  if (!value.endsWith("~")) fail(`${label} presentation must end with the disclosure separator`);
  const parsed = parseCompactAp2Token(value);
  if (parsed.keyBindingJwt !== null) fail(`${label} presentation must not carry a key-binding JWT`);
  const seen = new Set<string>();
  for (const disclosure of parsed.disclosures) {
    if (seen.has(disclosure.digest)) fail(`${label} presentation repeats a disclosure`);
    seen.add(disclosure.digest);
  }
  const sd = parsed.issuerJwt.claims._sd;
  if (sd !== undefined && (!Array.isArray(sd) || sd.some((entry) => typeof entry !== "string"))) {
    fail(`${label} _sd must be an array of digests`);
  }
  const referenced = new Set((sd ?? []) as string[]);
  const delegates = parsed.issuerJwt.claims.delegate_payload;
  if (Array.isArray(delegates)) {
    for (const entry of delegates) {
      if (isObject(entry) && typeof entry["..."] === "string") referenced.add(entry["..."]);
    }
  }
  if (parsed.disclosures.some((entry) => !referenced.has(entry.digest))) {
    fail(`${label} presentation contains a disclosure its signed payload does not reference`);
  }
  return Object.freeze({ exact: value, jwt: parsed.issuerJwt, disclosures: parsed.disclosures });
}

function requireTyp(jwt: ParsedJwt, expected: string, label: string): void {
  if (jwt.protectedHeader.typ !== expected) fail(`${label} header typ is not ${expected}`);
}

function checkTimes(
  claims: JsonObject,
  asOf: number,
  label: string,
  options: { readonly requireExp: boolean },
): { readonly iat: number; readonly exp: number | null } {
  const skew = VERIFIABLE_INTENT_PROFILE.clockSkewSeconds;
  const iat = requireSafeInteger(claims.iat, `${label}.iat`);
  if (iat > asOf + skew) fail(`${label} iat is after the evaluation time`);
  let exp: number | null = null;
  if (claims.exp !== undefined || options.requireExp) {
    exp = requireSafeInteger(claims.exp, `${label}.exp`);
    if (exp <= iat) fail(`${label} exp is not after iat`);
    if (asOf > exp + skew) fail(`${label} is expired at the evaluation time`);
  }
  return { iat, exp };
}

/** Resolve `{"...": digest}` delegate references against the known disclosures. */
function delegateReferences(claims: JsonObject, label: string): readonly string[] {
  const payload = claims.delegate_payload;
  if (!Array.isArray(payload) || payload.length === 0) fail(`${label} delegate_payload must be a non-empty array`);
  const refs: string[] = [];
  for (const entry of payload) {
    if (!isObject(entry) || Object.keys(entry).length !== 1 || typeof entry["..."] !== "string") {
      fail(`${label} delegate_payload entries must be disclosure references`);
    }
    refs.push(entry["..."]);
  }
  if (new Set(refs).size !== refs.length) fail(`${label} delegate_payload repeats a disclosure reference`);
  return refs;
}

function arrayElementValue(disclosure: ParsedSdJwtDisclosure): JsonValue | undefined {
  const decoded = disclosure.decoded as readonly JsonValue[];
  return decoded.length === 2 ? decoded[1] : undefined;
}

function cnfJwk(mandate: JsonObject, label: string): EcPublicJwk {
  const cnf = mandate.cnf;
  if (!isObject(cnf) || !isObject(cnf.jwk)) fail(`${label} is missing cnf.jwk`);
  return validateEcJwk(cnf.jwk, "ES256").jwk;
}

function validateClosedPayment(mandate: JsonObject, label: string): void {
  if (!nonEmptyString(mandate.transaction_id)) fail(`${label} is missing transaction_id`);
  const payee = mandate.payee;
  if (!isObject(payee) || !nonEmptyString(payee.name) || !nonEmptyString(payee.website)) {
    fail(`${label} payee must carry name and website`);
  }
  const amount = mandate.payment_amount;
  if (!isObject(amount) || !nonEmptyString(amount.currency)) fail(`${label} payment_amount is missing currency`);
  requireSafeInteger(amount.amount, `${label}.payment_amount.amount`);
  const instrument = mandate.payment_instrument;
  if (!isObject(instrument) || !nonEmptyString(instrument.id) || !nonEmptyString(instrument.type)) {
    fail(`${label} payment_instrument must carry id and type`);
  }
}

function validateClosedCheckout(mandate: JsonObject, label: string): string {
  if (!nonEmptyString(mandate.checkout_jwt) || !nonEmptyString(mandate.checkout_hash)) {
    fail(`${label} must carry checkout_jwt and checkout_hash`);
  }
  if (!/^[\x21-\x7e]+$/u.test(mandate.checkout_jwt)) fail(`${label} checkout_jwt is not ASCII`);
  if (base64UrlSha256(Buffer.from(mandate.checkout_jwt, "ascii")) !== mandate.checkout_hash) {
    fail(`${label} checkout_hash is not the SHA-256 of checkout_jwt`);
  }
  return mandate.checkout_hash;
}

function constraintList(mandate: JsonObject, label: string): readonly JsonObject[] {
  const constraints = mandate.constraints;
  if (constraints === undefined) return [];
  if (!Array.isArray(constraints) || constraints.some((entry) => !isObject(entry) || !nonEmptyString(entry.type))) {
    fail(`${label} constraints must be typed objects`);
  }
  return constraints as JsonObject[];
}

function sameInstrument(left: JsonValue | undefined, right: JsonValue | undefined): boolean {
  return isObject(left) && isObject(right) && left.id === right.id && left.type === right.type;
}

interface AllowlistOutcome {
  readonly status: VerifiableIntentConstraintStatus;
  readonly reason: string;
}

/**
 * Evaluate a merchant or payee allowlist by `id` only. An entry that stays an
 * undisclosed reference, or a disclosed entry without an `id`, could still be
 * the selected party, so a miss against the rest is not evaluable rather than
 * a violation.
 */
function evaluateAllowlist(
  allowed: JsonValue | undefined,
  selectedId: string | null,
  disclosures: ReadonlyMap<string, ParsedSdJwtDisclosure>,
): AllowlistOutcome {
  if (!Array.isArray(allowed) || allowed.length === 0) return { status: "violated", reason: "allowlist_empty_or_malformed" };
  const ids: string[] = [];
  let opaque = 0;
  for (const entry of allowed) {
    if (!isObject(entry)) return { status: "violated", reason: "allowlist_empty_or_malformed" };
    let resolved: JsonValue | undefined = entry;
    if (Object.hasOwn(entry, "...")) {
      const disclosure = typeof entry["..."] === "string" ? disclosures.get(entry["..."]) : undefined;
      resolved = disclosure === undefined ? undefined : arrayElementValue(disclosure);
    }
    if (isObject(resolved) && nonEmptyString(resolved.id)) ids.push(resolved.id);
    else opaque += 1;
  }
  if (selectedId === null) return { status: "not_evaluable", reason: "selected_party_id_missing" };
  if (ids.includes(selectedId)) return { status: "satisfied", reason: "id_in_disclosed_allowlist" };
  if (opaque > 0) return { status: "not_evaluable", reason: "may_match_undisclosed_or_unidentified_entry" };
  return { status: "violated", reason: "id_not_in_allowlist" };
}

function evaluateAmount(constraint: JsonObject, final: JsonObject | null): AllowlistOutcome {
  if (final === null) return { status: "not_evaluable", reason: "agent_payment_not_presented" };
  const amount = final.payment_amount as JsonObject;
  const value = amount.amount as number;
  if (!nonEmptyString(constraint.currency)) return { status: "violated", reason: "constraint_malformed" };
  for (const bound of [constraint.min, constraint.max]) {
    if (bound !== undefined && (typeof bound !== "number" || !Number.isSafeInteger(bound))) {
      return { status: "violated", reason: "constraint_malformed" };
    }
  }
  if (amount.currency !== constraint.currency) return { status: "violated", reason: "currency_mismatch" };
  if (typeof constraint.min === "number" && value < constraint.min) return { status: "violated", reason: "below_minimum" };
  if (typeof constraint.max === "number" && value > constraint.max) return { status: "violated", reason: "above_maximum" };
  return { status: "satisfied", reason: "within_range" };
}

/**
 * Evaluate `mandate.checkout.line_items` against the L3b checkout mandate's
 * `line_items`, the fulfillment source the VI constraint spec names. The
 * checkout_jwt cart schema is implementation-defined in v0.1, so it is never
 * read as a substitute.
 */
function evaluateLineItems(
  constraint: JsonObject,
  final: JsonObject | null,
  disclosures: ReadonlyMap<string, ParsedSdJwtDisclosure>,
): AllowlistOutcome {
  const malformed = { status: "violated", reason: "constraint_malformed" } as const;
  const entries = constraint.items;
  if (!Array.isArray(entries) || entries.length === 0) return malformed;
  const matchMode = constraint.match_mode ?? "minimum";
  if (matchMode !== "minimum" && matchMode !== "exact") return malformed;
  interface Requirement { readonly ids: ReadonlySet<string>; readonly opaque: number; readonly wildcard: boolean }
  const requirements: Requirement[] = [];
  let totalCap = 0;
  const perIdCap = new Map<string, number>();
  for (const entry of entries) {
    if (!isObject(entry) || !nonEmptyString(entry.id) || !Array.isArray(entry.acceptable_items)) return malformed;
    const quantity = entry.quantity;
    if (typeof quantity !== "number" || !Number.isSafeInteger(quantity) || quantity <= 0) return malformed;
    totalCap += quantity;
    const ids = new Set<string>();
    let opaque = 0;
    for (const item of entry.acceptable_items) {
      if (!isObject(item)) return malformed;
      let resolved: JsonValue | undefined = item;
      if (Object.hasOwn(item, "...")) {
        const disclosure = typeof item["..."] === "string" ? disclosures.get(item["..."]) : undefined;
        resolved = disclosure === undefined ? undefined : arrayElementValue(disclosure);
      }
      if (isObject(resolved) && nonEmptyString(resolved.id)) ids.add(resolved.id);
      else opaque += 1;
    }
    for (const id of ids) perIdCap.set(id, (perIdCap.get(id) ?? 0) + quantity);
    requirements.push({ ids, opaque, wildcard: entry.acceptable_items.length === 0 });
  }
  if (final === null) return { status: "not_evaluable", reason: "agent_checkout_not_presented" };
  const lineItems = final.line_items;
  if (lineItems === undefined) return { status: "not_evaluable", reason: "fulfillment_line_items_missing" };
  if (!Array.isArray(lineItems) || lineItems.length === 0) return { status: "violated", reason: "fulfillment_line_items_empty_or_malformed" };
  const quantities = new Map<string, number>();
  let total = 0;
  for (const line of lineItems) {
    if (!isObject(line)) return { status: "violated", reason: "fulfillment_line_items_empty_or_malformed" };
    const id = nonEmptyString(line.id) ? line.id : nonEmptyString(line.sku) ? line.sku : null;
    const quantity = line.quantity;
    if (id === null || typeof quantity !== "number" || !Number.isSafeInteger(quantity) || quantity < 0) {
      return { status: "violated", reason: "fulfillment_line_items_empty_or_malformed" };
    }
    total += quantity;
    quantities.set(id, (quantities.get(id) ?? 0) + quantity);
  }
  if (total > totalCap) return { status: "violated", reason: "total_quantity_exceeds_limit" };
  const anyWildcard = requirements.some((entry) => entry.wildcard);
  const anyOpaque = requirements.some((entry) => entry.opaque > 0);
  let undetermined = false;
  for (const [id, quantity] of quantities) {
    const cap = perIdCap.get(id);
    if (cap !== undefined && quantity > cap) return { status: "violated", reason: "item_quantity_exceeds_limit" };
    if (cap === undefined && !anyWildcard) {
      if (anyOpaque) undetermined = true;
      else return { status: "violated", reason: "item_not_acceptable" };
    }
  }
  if (matchMode === "exact") {
    for (const requirement of requirements) {
      if (requirement.wildcard) continue;
      const covered = [...requirement.ids].some((id) => (quantities.get(id) ?? 0) > 0);
      if (covered) continue;
      if (requirement.opaque > 0) undetermined = true;
      else return { status: "violated", reason: "exact_match_requirement_missing" };
    }
  }
  return undetermined
    ? { status: "not_evaluable", reason: "may_match_undisclosed_item" }
    : { status: "satisfied", reason: "line_items_within_constraint" };
}

/**
 * The checkout_jwt payload schema is implementation-defined in VI v0.1, and
 * the reference SDK writes decimal prices, which strict JSON rejects. The
 * signature check therefore reads only the protected header and verifies the
 * exact segments; the payload is parsed only to look for `merchant.id`.
 */
function checkoutJwtForSignature(compact: string): ParsedJwt {
  const parts = compact.split(".");
  const [protectedSegment, payloadSegment, signatureSegment] = parts;
  if (
    parts.length !== 3 ||
    protectedSegment === undefined || protectedSegment.length === 0 ||
    payloadSegment === undefined || payloadSegment.length === 0 ||
    signatureSegment === undefined || signatureSegment.length === 0
  ) {
    fail("checkout_jwt is not a three-segment compact JWT");
  }
  const protectedHeader = parseStrictJsonObject(strictUtf8(decodeBase64Url(protectedSegment, "checkout_jwt.protected")));
  decodeBase64Url(payloadSegment, "checkout_jwt.payload");
  return Object.freeze({ exactCompact: compact, protectedSegment, payloadSegment, signatureSegment, protectedHeader, claims: {} });
}

function checkoutMerchantId(checkoutJwt: string): string | null {
  const claims = parseJwtCompact(checkoutJwt, "checkout_jwt").claims;
  const merchant = claims.merchant;
  return isObject(merchant) && nonEmptyString(merchant.id) ? merchant.id : null;
}

function finishReport(material: Omit<VerifiableIntentChainReport, "reportDigest">): VerifiableIntentChainReport {
  return Object.freeze({ ...material, reportDigest: sha256Digest(material) });
}

/**
 * Verify one preserved Verifiable Intent chain at `asOf`, the instant it was
 * presented. The report carries gates, a constraint evaluation for Autonomous
 * mode, and presentation digests; it never carries the presentations.
 */
export function verifyVerifiableIntentChain(input: VerifyVerifiableIntentChainInput): VerifiableIntentChainReport {
  const issues: InteropIssue[] = [];
  const gates = {
    issuerCredential: "not_checked" as VerifiableIntentGate,
    userMandate: "not_checked" as VerifiableIntentGate,
    agentPayment: "not_presented" as VerifiableIntentGate,
    agentCheckout: "not_presented" as VerifiableIntentGate,
    crossReference: "not_applicable" as VerifiableIntentGate,
    checkoutJwtSignature: "not_checked" as VerifiableIntentGate,
    audienceAndNonce: "not_checked" as VerifiableIntentGate,
  };
  const source: Partial<VerifyVerifiableIntentChainInput> = isObject(input) ? input : {};
  const digests = Object.freeze({
    l1: presentationDigest(source.l1),
    l2: presentationDigest(source.l2),
    l2PaymentPresentation: presentationDigest(source.l2PaymentPresentation),
    l2CheckoutPresentation: presentationDigest(source.l2CheckoutPresentation),
    l3Payment: presentationDigest(source.l3Payment),
    l3Checkout: presentationDigest(source.l3Checkout),
  });
  let asOf: number | null = null;
  let mode: VerifiableIntentChainReport["mode"] = null;
  let disclosedCheckout = false;
  let disclosedPayment = false;
  let checkoutHash: string | null = null;
  let transactionId: string | null = null;
  let paymentAmount: VerifiableIntentChainReport["transaction"]["paymentAmount"] = null;
  let payeeId: string | null = null;
  const constraints: VerifiableIntentConstraintResult[] = [];
  let constraintsResult: VerifiableIntentChainReport["constraintsResult"] = "not_evaluated";
  let signedCheckoutJwt: string | null = null;

  const stop = (code: string, path: string, error: unknown, fallback: string): never => {
    issues.push(upstreamIssue(code, path, messageOf(error, fallback)));
    throw new ChainFailure();
  };
  const expected = isObject(source.expected) ? source.expected : {};
  const anchors: string[] = [];
  const checkAnchor = (claims: JsonObject, claim: "aud" | "nonce", value: unknown, path: string, label: string) => {
    if (value === undefined) {
      anchors.push(path);
      return;
    }
    if (typeof value !== "string" || claims[claim] !== value) {
      issues.push(upstreamIssue("VI_ANCHOR_MISMATCH", path, `${label} ${claim} does not match the expected value`));
      gates.audienceAndNonce = "failed";
    }
  };

  try {
    try {
      asOf = parseEpoch(source.asOf as string | number, "asOf");
    } catch (error) {
      stop("VI_AS_OF_INVALID", "asOf", error, "asOf is invalid");
    }
    const at = asOf as number;

    // L1: issuer credential, pinned issuer key, exact segments.
    let l1: ViPresentation;
    let userJwk: EcPublicJwk;
    let l1CardId: string | null = null;
    try {
      l1 = parsePresentation(source.l1, "L1");
      requireTyp(l1.jwt, TYP_L1, "L1");
      if (l1.jwt.claims.vct !== VERIFIABLE_INTENT_PROFILE.issuerCredentialType) fail("L1 vct is not the pinned card credential type");
      checkTimes(l1.jwt.claims, at, "L1", { requireExp: true });
      const cnf = l1.jwt.claims.cnf;
      if (!isObject(cnf) || !isObject(cnf.jwk)) fail("L1 is missing cnf.jwk");
      userJwk = validateEcJwk(cnf.jwk, "ES256").jwk;
      if (l1.jwt.claims.card_id !== undefined) {
        if (!nonEmptyString(l1.jwt.claims.card_id)) fail("L1 card_id must be a non-empty string");
        l1CardId = l1.jwt.claims.card_id;
      }
    } catch (error) {
      gates.issuerCredential = "failed";
      stop("VI_L1_INVALID", "l1", error, "L1 is invalid");
    }
    const snapshotUsable = checkKeySnapshot(
      source.issuerKeySnapshot,
      source.expectedIssuerKeySourceDigest as Sha256Digest,
      at,
      issues,
      "issuerKeySnapshot",
    );
    if (!snapshotUsable) {
      gates.issuerCredential = "failed";
      throw new ChainFailure();
    }
    const issuerSnapshot = source.issuerKeySnapshot as PinnedEcKeySnapshot;
    try {
      verifyParsedJwtSignature(l1!.jwt, issuerSnapshot.jwk, ES256_ONLY, issuerSnapshot.kid, "issuer");
    } catch (error) {
      gates.issuerCredential = "failed";
      stop("VI_L1_SIGNATURE_INVALID", "l1", error, "L1 signature is invalid");
    }
    gates.issuerCredential = "passed";

    // L2: user mandate, signed by the L1 cnf key, bound to the exact L1.
    let l2: ViPresentation;
    const known = new Map<string, ParsedSdJwtDisclosure>();
    let refs: readonly string[];
    try {
      l2 = parsePresentation(source.l2, "L2");
      const userKid = typeof userJwk!.kid === "string" ? userJwk!.kid : null;
      verifyParsedJwtSignature(l2.jwt, userJwk!, ES256_ONLY, userKid, "issuer");
      if (l2.jwt.claims.sd_hash !== base64UrlSha256(Buffer.from(l1!.exact, "ascii"))) {
        fail("L2 sd_hash does not bind the exact L1 presentation");
      }
      checkTimes(l2.jwt.claims, at, "L2", { requireExp: false });
      refs = delegateReferences(l2.jwt.claims, "L2");
      for (const disclosure of l2.disclosures) known.set(disclosure.digest, disclosure);
    } catch (error) {
      gates.userMandate = "failed";
      stop("VI_L2_INVALID", "l2", error, "L2 is invalid");
    }

    // Each L3 binds a selective L2 presentation. It must be the same signed L2
    // base JWT with disclosures that L2's own _sd references.
    const bound = (value: unknown, path: string): ViPresentation => {
      if (value === undefined) return l2!;
      try {
        const presentation = parsePresentation(value, path);
        if (presentation.jwt.exactCompact !== l2!.jwt.exactCompact) fail(`${path} is not built on the same L2 JWT`);
        for (const disclosure of presentation.disclosures) known.set(disclosure.digest, disclosure);
        return presentation;
      } catch (error) {
        gates.userMandate = "failed";
        return stop("VI_L2_PRESENTATION_INVALID", path, error, "L2 presentation is invalid");
      }
    };
    const paymentPresentation = source.l3Payment === undefined ? null : bound(source.l2PaymentPresentation, "l2PaymentPresentation");
    const checkoutPresentation = source.l3Checkout === undefined ? null : bound(source.l2CheckoutPresentation, "l2CheckoutPresentation");

    let checkoutMandate: ResolvedMandate | null = null;
    let paymentMandate: ResolvedMandate | null = null;
    try {
      if (refs!.length > 2) fail("L2 carries more than one mandate pair, which this profile does not verify");
      for (const ref of refs!) {
        const disclosure = known.get(ref);
        if (disclosure === undefined) continue;
        const value = arrayElementValue(disclosure);
        if (!isObject(value) || !nonEmptyString(value.vct)) fail("L2 delegate reference does not resolve to a typed mandate");
        if (value.vct === VCT_CHECKOUT_OPEN || value.vct === VCT_CHECKOUT_FINAL) {
          if (checkoutMandate !== null) fail("L2 discloses more than one checkout mandate");
          checkoutMandate = { value, disclosure };
        } else if (value.vct === VCT_PAYMENT_OPEN || value.vct === VCT_PAYMENT_FINAL) {
          if (paymentMandate !== null) fail("L2 discloses more than one payment mandate");
          paymentMandate = { value, disclosure };
        } else {
          fail("L2 delegate reference resolves to an unknown mandate type");
        }
      }
      const resolved = [checkoutMandate, paymentMandate].filter((entry): entry is ResolvedMandate => entry !== null);
      if (resolved.length === 0) fail("L2 discloses no mandate");
      const open = resolved.filter((entry) => entry.value.vct === VCT_CHECKOUT_OPEN || entry.value.vct === VCT_PAYMENT_OPEN);
      if (open.length > 0 && open.length !== resolved.length) fail("L2 mixes open and final mandates");
      mode = open.length > 0 ? "autonomous" : "immediate";
      requireTyp(l2!.jwt, mode === "autonomous" ? TYP_L2_AUTONOMOUS : TYP_L2_IMMEDIATE, "L2");
      disclosedCheckout = checkoutMandate !== null;
      disclosedPayment = paymentMandate !== null;
      const payment = paymentMandate as ResolvedMandate | null;
      if (l1CardId !== null && payment !== null) {
        const instrument = payment.value.payment_instrument;
        if (!isObject(instrument) || instrument.id !== l1CardId) fail("L2 payment_instrument.id does not match L1 card_id");
      }
    } catch (error) {
      gates.userMandate = "failed";
      stop("VI_L2_MANDATES_INVALID", "l2.delegate_payload", error, "L2 mandates are invalid");
    }
    const checkout = checkoutMandate as ResolvedMandate | null;
    const payment = paymentMandate as ResolvedMandate | null;
    checkAnchor(l2!.jwt.claims, "aud", expected.l2Audience, "expected.l2Audience", "L2");
    checkAnchor(l2!.jwt.claims, "nonce", expected.l2Nonce, "expected.l2Nonce", "L2");

    if (mode === "immediate") {
      try {
        if (checkout === null || payment === null) fail("Immediate mode needs both checkout and payment mandates disclosed");
        for (const mandate of [checkout.value, payment.value]) {
          if (Object.hasOwn(mandate, "cnf")) fail("Immediate mode mandates must not carry cnf");
        }
        checkoutHash = validateClosedCheckout(checkout.value, "L2 checkout mandate");
        validateClosedPayment(payment.value, "L2 payment mandate");
        if (payment.value.transaction_id !== checkoutHash) fail("L2 transaction_id does not equal checkout_hash");
        if (source.l3Payment !== undefined || source.l3Checkout !== undefined) {
          fail("Immediate mode chains have no agent layer");
        }
      } catch (error) {
        gates.userMandate = "failed";
        stop("VI_L2_IMMEDIATE_INVALID", "l2", error, "Immediate mandates are invalid");
      }
      gates.userMandate = "passed";
      gates.agentPayment = "not_applicable";
      gates.agentCheckout = "not_applicable";
      signedCheckoutJwt = checkout!.value.checkout_jwt as string;
      const paymentValue = payment!.value;
      transactionId = paymentValue.transaction_id as string;
      const amount = paymentValue.payment_amount as JsonObject;
      paymentAmount = { currency: amount.currency as string, amount: amount.amount as number };
      const payee = paymentValue.payee as JsonObject;
      payeeId = nonEmptyString(payee.id) ? payee.id : null;
      constraintsResult = "not_applicable";
    } else {
      // Autonomous: open mandates delegate to one agent key with a kid.
      let agentJwk: EcPublicJwk;
      let agentKid: string;
      try {
        const keys: EcPublicJwk[] = [];
        if (checkout !== null) {
          if (!constraintList(checkout.value, "L2 checkout mandate").some((entry) => entry.type === CONSTRAINT_LINE_ITEMS)) {
            fail("Open checkout mandate must carry a line_items constraint");
          }
          keys.push(cnfJwk(checkout.value, "L2 checkout mandate"));
        }
        if (payment !== null) {
          const list = constraintList(payment.value, "L2 payment mandate");
          if (!list.some((entry) => entry.type === CONSTRAINT_REFERENCE)) {
            fail("Open payment mandate must carry a reference constraint");
          }
          const instrument = payment.value.payment_instrument;
          if (!isObject(instrument) || !nonEmptyString(instrument.id) || !nonEmptyString(instrument.type)) {
            fail("Open payment mandate payment_instrument must carry id and type");
          }
          keys.push(cnfJwk(payment.value, "L2 payment mandate"));
        }
        const first = keys[0] as EcPublicJwk;
        if (!nonEmptyString(first.kid)) fail("Agent cnf.jwk must carry a kid");
        for (const key of keys) {
          if (key.x !== first.x || key.y !== first.y || key.kid !== first.kid) fail("Open mandates delegate to different agent keys");
        }
        agentJwk = first;
        agentKid = first.kid;
        if (checkout !== null && payment !== null) {
          const reference = constraintList(payment.value, "L2 payment mandate")
            .find((entry) => entry.type === CONSTRAINT_REFERENCE) as JsonObject;
          if (reference.conditional_transaction_id !== checkout.disclosure.digest) {
            fail("Payment reference does not bind the disclosed checkout mandate");
          }
        }
      } catch (error) {
        gates.userMandate = "failed";
        stop("VI_L2_AUTONOMOUS_INVALID", "l2", error, "Autonomous mandates are invalid");
      }
      gates.userMandate = "passed";

      const verifyL3 = (
        value: string,
        presentation: ViPresentation,
        label: "L3a" | "L3b",
        requiredVct: string,
        mandate: ResolvedMandate | null,
      ): JsonObject => {
        const l3 = parsePresentation(value, label);
        requireTyp(l3.jwt, TYP_L3, label);
        if (Object.hasOwn(l3.jwt.claims, "cnf")) fail(`${label} must not carry cnf`);
        verifyParsedJwtSignature(l3.jwt, agentJwk!, ES256_ONLY, agentKid!, "issuer");
        if (l3.jwt.claims.sd_hash !== base64UrlSha256(Buffer.from(presentation.exact, "ascii"))) {
          fail(`${label} sd_hash does not bind its L2 presentation`);
        }
        if (mandate === null || !presentation.disclosures.some((entry) => entry.digest === mandate.disclosure.digest)) {
          fail(`${label} L2 presentation does not include its L2 mandate`);
        }
        const times = checkTimes(l3.jwt.claims, at, label, { requireExp: true });
        if ((times.exp as number) - times.iat > VERIFIABLE_INTENT_PROFILE.maxL3LifetimeSeconds) {
          fail(`${label} lifetime exceeds one hour`);
        }
        const l3Known = new Map(l3.disclosures.map((entry) => [entry.digest, entry]));
        let final: JsonObject | null = null;
        for (const ref of delegateReferences(l3.jwt.claims, label)) {
          const disclosure = l3Known.get(ref);
          if (disclosure === undefined) fail(`${label} delegate reference is not disclosed`);
          const resolved = arrayElementValue(disclosure);
          if (!isObject(resolved)) fail(`${label} delegate reference does not resolve to an object`);
          if (resolved.vct === undefined) continue;
          if (resolved.vct !== requiredVct || final !== null) fail(`${label} carries an unexpected mandate`);
          final = resolved;
        }
        if (final === null) fail(`${label} carries no ${requiredVct} mandate`);
        const anchorPrefix = label === "L3a" ? "l3Payment" : "l3Checkout";
        checkAnchor(l3.jwt.claims, "aud", expected[`${anchorPrefix}Audience`], `expected.${anchorPrefix}Audience`, label);
        checkAnchor(l3.jwt.claims, "nonce", expected[`${anchorPrefix}Nonce`], `expected.${anchorPrefix}Nonce`, label);
        return final;
      };

      let finalPayment: JsonObject | null = null;
      let finalCheckout: JsonObject | null = null;
      if (source.l3Payment !== undefined) {
        try {
          finalPayment = verifyL3(source.l3Payment, paymentPresentation!, "L3a", VCT_PAYMENT_FINAL, payment);
          validateClosedPayment(finalPayment, "L3a payment mandate");
          if (!sameInstrument(finalPayment.payment_instrument, payment!.value.payment_instrument)) {
            fail("L3a payment_instrument does not match the L2 authorized instrument");
          }
          gates.agentPayment = "passed";
        } catch (error) {
          gates.agentPayment = "failed";
          stop("VI_L3_PAYMENT_INVALID", "l3Payment", error, "L3a is invalid");
        }
      }
      if (source.l3Checkout !== undefined) {
        try {
          finalCheckout = verifyL3(source.l3Checkout, checkoutPresentation!, "L3b", VCT_CHECKOUT_FINAL, checkout);
          checkoutHash = validateClosedCheckout(finalCheckout, "L3b checkout mandate");
          gates.agentCheckout = "passed";
        } catch (error) {
          gates.agentCheckout = "failed";
          stop("VI_L3_CHECKOUT_INVALID", "l3Checkout", error, "L3b is invalid");
        }
      }
      if (finalPayment !== null) {
        transactionId = finalPayment.transaction_id as string;
        const amount = finalPayment.payment_amount as JsonObject;
        paymentAmount = { currency: amount.currency as string, amount: amount.amount as number };
        const payee = finalPayment.payee as JsonObject;
        payeeId = nonEmptyString(payee.id) ? payee.id : null;
      }
      if (finalPayment !== null && finalCheckout !== null) {
        if (transactionId !== checkoutHash) {
          gates.crossReference = "failed";
          issues.push(upstreamIssue(
            "VI_CROSS_REFERENCE_MISMATCH",
            "l3Payment.transaction_id",
            "L3a transaction_id does not equal L3b checkout_hash",
          ));
        } else {
          gates.crossReference = "passed";
        }
      } else {
        gates.crossReference = "not_checked";
      }

      // Constraints: each disclosed open mandate's constraints against its L3.
      const checkoutJwt = finalCheckout === null ? null : finalCheckout.checkout_jwt as string;
      signedCheckoutJwt = checkoutJwt;
      let merchantId: string | null = null;
      let merchantIdReadable = true;
      if (checkoutJwt !== null) {
        try {
          merchantId = checkoutMerchantId(checkoutJwt);
        } catch {
          merchantIdReadable = false;
        }
      }
      const add = (mandateName: "checkout" | "payment", type: string, outcome: AllowlistOutcome) => {
        constraints.push(Object.freeze({ mandate: mandateName, type, status: outcome.status, reason: outcome.reason }));
      };
      if (checkout !== null) {
        for (const constraint of constraintList(checkout.value, "L2 checkout mandate")) {
          const type = constraint.type as string;
          if (type === CONSTRAINT_CHECKOUT_MERCHANTS) {
            if (finalCheckout === null) add("checkout", type, { status: "not_evaluable", reason: "agent_checkout_not_presented" });
            else if (!merchantIdReadable) add("checkout", type, { status: "not_evaluable", reason: "checkout_jwt_unreadable" });
            else if (merchantId === null) add("checkout", type, { status: "not_evaluable", reason: "checkout_jwt_merchant_id_missing" });
            else add("checkout", type, evaluateAllowlist(constraint.allowed, merchantId, known));
          } else if (type === CONSTRAINT_LINE_ITEMS) {
            add("checkout", type, evaluateLineItems(constraint, finalCheckout, known));
          } else {
            add("checkout", type, { status: "violated", reason: "unknown_type_in_open_mandate" });
          }
        }
      }
      if (payment !== null) {
        for (const constraint of constraintList(payment.value, "L2 payment mandate")) {
          const type = constraint.type as string;
          if (type === CONSTRAINT_AMOUNT) {
            add("payment", type, evaluateAmount(constraint, finalPayment));
          } else if (type === CONSTRAINT_PAYEES) {
            add("payment", type, finalPayment === null
              ? { status: "not_evaluable", reason: "agent_payment_not_presented" }
              : evaluateAllowlist(constraint.allowed, payeeId, known));
          } else if (type === CONSTRAINT_REFERENCE) {
            add("payment", type, checkout === null
              ? { status: "not_evaluable", reason: "checkout_mandate_not_disclosed" }
              : { status: "satisfied", reason: "binds_disclosed_checkout_mandate" });
          } else if (NETWORK_ENFORCED_CONSTRAINTS.has(type)) {
            add("payment", type, { status: "not_evaluable", reason: "network_enforced" });
          } else {
            add("payment", type, { status: "violated", reason: "unknown_type_in_open_mandate" });
          }
        }
      }
      constraintsResult = constraints.some((entry) => entry.status === "violated")
        ? "violated"
        : constraints.some((entry) => entry.status === "not_evaluable") ? "incomplete" : "satisfied";
    }

    // Optional merchant signature over the checkout_jwt, with a pinned key.
    if (source.merchantKeySnapshot !== undefined) {
      if (signedCheckoutJwt === null) {
        gates.checkoutJwtSignature = "not_presented";
      } else if (checkKeySnapshot(
        source.merchantKeySnapshot,
        source.expectedMerchantKeySourceDigest as Sha256Digest,
        at,
        issues,
        "merchantKeySnapshot",
      )) {
        try {
          const merchant = source.merchantKeySnapshot;
          verifyParsedJwtSignature(checkoutJwtForSignature(signedCheckoutJwt), merchant.jwk, ES256_ONLY, merchant.kid, "issuer");
          gates.checkoutJwtSignature = "passed";
        } catch (error) {
          gates.checkoutJwtSignature = "failed";
          issues.push(upstreamIssue("VI_CHECKOUT_JWT_SIGNATURE_INVALID", "checkout_jwt", messageOf(error, "checkout_jwt signature is invalid")));
        }
      } else {
        gates.checkoutJwtSignature = "failed";
      }
    }
  } catch (error) {
    if (!(error instanceof ChainFailure)) throw error;
  }

  if (anchors.length > 0 && gates.audienceAndNonce !== "failed") {
    for (const path of anchors) {
      issues.push(eligibilityIssue("VI_ANCHOR_UNCHECKED", path, "No expected value was supplied, so this claim was not checked"));
    }
    gates.audienceAndNonce = "not_checked";
  } else if (gates.audienceAndNonce !== "failed" && gates.userMandate === "passed") {
    gates.audienceAndNonce = "passed";
  }

  const upstreamValid = !issues.some((entry) => entry.impact === "upstream_validity");
  const evidenceEligible = upstreamValid && !issues.some((entry) => entry.impact === "evidence_eligibility");
  return finishReport({
    schemaId: "MandateBoundVerifiableIntentChainReport/v1",
    profileId: VERIFIABLE_INTENT_PROFILE.id,
    asOf,
    mode: upstreamValid ? mode : null,
    chainStatus: !upstreamValid ? "invalid" : evidenceEligible ? "verified" : "ineligible",
    upstreamValid,
    evidenceEligible,
    gates: Object.freeze({ ...gates }),
    disclosed: Object.freeze({ checkoutMandate: disclosedCheckout, paymentMandate: disclosedPayment }),
    transaction: Object.freeze(upstreamValid
      ? {
          checkoutHash,
          transactionId,
          paymentAmount: paymentAmount === null ? null : Object.freeze(paymentAmount),
          payeeId,
        }
      : { checkoutHash: null, transactionId: null, paymentAmount: null, payeeId: null }),
    constraints: Object.freeze(upstreamValid ? constraints : []),
    constraintsResult: upstreamValid ? constraintsResult : "not_evaluated",
    presentationDigests: digests,
    issues: Object.freeze([...issues]),
    disputeOutcome: "not-determined",
    legalEffect: "not-determined",
  });
}
