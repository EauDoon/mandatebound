import { Buffer } from "node:buffer";
import type { JsonObject } from "../domain.js";
import type {
  InteropIssue,
  InteropVerification,
  JoseEcAlgorithm,
  ParsedJwt,
  VerifyAp2CheckoutJwtOptions,
  VerifiedAp2CheckoutJwt,
} from "./types.js";
import { UCP_AP2_EVIDENCE_PROFILE } from "./profile.js";
import { UcpAp2ParseError } from "./parse-error.js";
import {
  finish,
  parseEpoch,
  requireJsonObject,
  requireSafeInteger,
  requireString,
  upstreamIssue,
  validateAllowedAlgorithms,
} from "./primitives.js";
import {
  checkKeySnapshot,
  verifyParsedJwtSignature,
} from "./jwk.js";
import { parseJwtCompact } from "./jwt-parse.js";

/**
 * AP2/UCP merchant-signed Checkout JWT verification. The adapter pins the
 * bounded UCP Checkout schema (line items, totals, status, links, merchant)
 * and verifies the signature under the merchant key snapshot.
 */

const AP2_CHECKOUT_STATUSES = new Set([
  "incomplete",
  "requires_escalation",
  "ready_for_complete",
  "complete_in_progress",
  "completed",
  "canceled",
]);

function validateCheckoutTotals(value: unknown, path: string): void {
  if (!Array.isArray(value) || value.length > 128) {
    throw new UcpAp2ParseError(`Checkout totals are invalid at ${path}`);
  }
  for (let index = 0; index < value.length; index += 1) {
    const total = requireJsonObject(value[index], `${path}[${String(index)}]`);
    requireString(total.type, `${path}[${String(index)}].type`);
    requireSafeInteger(total.amount, `${path}[${String(index)}].amount`);
  }
}

function validateAp2CheckoutClaims(claims: JsonObject): void {
  requireString(claims.id, "checkoutJwt.claims.id");
  if (!Array.isArray(claims.line_items) || claims.line_items.length > 128) {
    throw new UcpAp2ParseError("Checkout line_items are missing or exceed the item limit");
  }
  for (let index = 0; index < claims.line_items.length; index += 1) {
    const lineItem = requireJsonObject(
      claims.line_items[index],
      `checkoutJwt.claims.line_items[${String(index)}]`,
    );
    requireString(lineItem.id, `checkoutJwt.claims.line_items[${String(index)}].id`);
    const item = requireJsonObject(
      lineItem.item,
      `checkoutJwt.claims.line_items[${String(index)}].item`,
    );
    requireString(item.id, `checkoutJwt.claims.line_items[${String(index)}].item.id`);
    requireString(item.title, `checkoutJwt.claims.line_items[${String(index)}].item.title`);
    const quantity = requireSafeInteger(
      lineItem.quantity,
      `checkoutJwt.claims.line_items[${String(index)}].quantity`,
    );
    if (quantity < 1) throw new UcpAp2ParseError("Checkout line-item quantity must be positive");
    validateCheckoutTotals(
      lineItem.totals,
      `checkoutJwt.claims.line_items[${String(index)}].totals`,
    );
  }
  if (typeof claims.status !== "string" || !AP2_CHECKOUT_STATUSES.has(claims.status)) {
    throw new UcpAp2ParseError("Checkout status is not in the pinned UCP enum");
  }
  requireString(claims.currency, "checkoutJwt.claims.currency");
  validateCheckoutTotals(claims.totals, "checkoutJwt.claims.totals");
  if (!Array.isArray(claims.links) || claims.links.length > 128) {
    throw new UcpAp2ParseError("Checkout links are missing or exceed the item limit");
  }
  for (let index = 0; index < claims.links.length; index += 1) {
    const link = requireJsonObject(claims.links[index], `checkoutJwt.claims.links[${String(index)}]`);
    requireString(link.type, `checkoutJwt.claims.links[${String(index)}].type`);
    const url = requireString(link.url, `checkoutJwt.claims.links[${String(index)}].url`);
    try {
      new URL(url);
    } catch {
      throw new UcpAp2ParseError("Checkout link URL is not an absolute URI");
    }
  }
  if (claims.merchant !== undefined) {
    const merchant = requireJsonObject(claims.merchant, "checkoutJwt.claims.merchant");
    requireString(merchant.id, "checkoutJwt.claims.merchant.id");
    requireString(merchant.name, "checkoutJwt.claims.merchant.name");
  }
}

export function verifyAp2CheckoutJwt(
  options: VerifyAp2CheckoutJwtOptions,
): InteropVerification<VerifiedAp2CheckoutJwt> {
  const issues: InteropIssue[] = [];
  let parsed: ParsedJwt;
  let allowed: ReadonlySet<JoseEcAlgorithm>;
  let asOf: number;
  try {
    if (
      typeof options.token !== "string" ||
      options.token.length === 0 ||
      Buffer.byteLength(options.token, "utf8") > 1_048_576
    ) {
      throw new UcpAp2ParseError("Checkout JWT is empty or exceeds the byte limit");
    }
    parsed = parseJwtCompact(options.token, "checkoutJwt");
    allowed = validateAllowedAlgorithms(options.allowedAlgorithms, ["ES256"]);
    asOf = parseEpoch(options.asOf, "asOf");
  } catch (error) {
    issues.push(upstreamIssue(
      "AP2_CHECKOUT_JWT_INVALID",
      "checkoutJwt",
      error instanceof Error ? error.message : "Invalid merchant-signed Checkout JWT",
    ));
    return finish<VerifiedAp2CheckoutJwt>(null, issues);
  }

  if (!checkKeySnapshot(
    options.merchantKeySnapshot,
    options.expectedMerchantKeySourceDigest,
    options.asOf,
    issues,
    "checkoutMerchantKeySnapshot",
  )) {
    return finish<VerifiedAp2CheckoutJwt>(null, issues);
  }
  let header: { readonly algorithm: JoseEcAlgorithm; readonly kid: string | null } | null = null;
  try {
    header = verifyParsedJwtSignature(
      parsed,
      options.merchantKeySnapshot.jwk,
      allowed,
      options.merchantKeySnapshot.kid,
      "issuer",
    );
  } catch (error) {
    issues.push(upstreamIssue(
      "AP2_CHECKOUT_JWT_SIGNATURE_INVALID",
      "checkoutJwt",
      error instanceof Error ? error.message : "Checkout JWT signature is invalid",
    ));
  }
  if (
    options.expectedIssuer !== undefined &&
    parsed.claims.iss !== options.expectedIssuer
  ) {
    issues.push(upstreamIssue(
      "AP2_CHECKOUT_JWT_ISSUER_MISMATCH",
      "checkoutJwt.claims.iss",
      "Checkout JWT issuer does not match the expected merchant",
    ));
  }
  try {
    if (
      parsed.claims.iat !== undefined &&
      requireSafeInteger(parsed.claims.iat, "checkoutJwt.claims.iat") > asOf + 60
    ) {
      throw new UcpAp2ParseError("Checkout JWT issuance time is in the future");
    }
    if (
      parsed.claims.nbf !== undefined &&
      asOf < requireSafeInteger(parsed.claims.nbf, "checkoutJwt.claims.nbf")
    ) {
      throw new UcpAp2ParseError("Checkout JWT is not yet valid");
    }
    if (
      parsed.claims.exp !== undefined &&
      asOf >= requireSafeInteger(parsed.claims.exp, "checkoutJwt.claims.exp")
    ) {
      throw new UcpAp2ParseError("Checkout JWT is expired");
    }
  } catch (error) {
    issues.push(upstreamIssue(
      "AP2_CHECKOUT_JWT_TIME_INVALID",
      "checkoutJwt.claims",
      error instanceof Error ? error.message : "Checkout JWT time claims are invalid",
    ));
  }
  try {
    validateAp2CheckoutClaims(parsed.claims);
  } catch {
    issues.push(upstreamIssue(
      "AP2_CHECKOUT_SCHEMA_INVALID",
      "checkoutJwt.claims",
      "Checkout JWT does not match the bounded pinned AP2 v0.2.0 UCP Checkout schema",
    ));
  }
  return finish(Object.freeze({
    profileId: UCP_AP2_EVIDENCE_PROFILE.id,
    ap2Version: UCP_AP2_EVIDENCE_PROFILE.ap2Version,
    exactToken: options.token,
    claims: parsed.claims,
    issuer: typeof parsed.claims.iss === "string" ? parsed.claims.iss : null,
    merchantKid: header?.kid ?? options.merchantKeySnapshot.kid,
    merchantAlgorithm: header?.algorithm ?? "ES256",
    authorizesNativeRole: false,
  }), issues);
}
