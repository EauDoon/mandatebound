import { Buffer } from "node:buffer";
import type { JsonObject, JsonValue } from "../domain.js";
import type {
  Ap2MandateVct,
  EcPublicJwk,
  ExpectedMerchant,
  InteropIssue,
  InteropVerification,
  JoseEcAlgorithm,
  ParsedCompactAp2Token,
  ParsedSdJwtDisclosure,
  VerifyAp2MandateOptions,
  VerifiedAp2Mandate,
} from "./types.js";
import { AP2_MANDATE_VCTS, UCP_AP2_EVIDENCE_PROFILE } from "./profile.js";
import { UcpAp2ParseError } from "./parse-error.js";
import {
  base64UrlSha256,
  eligibilityIssue,
  finish,
  hasOwn,
  isObject,
  parseEpoch,
  publicJwkIdentity,
  requireJsonObject,
  requireSafeInteger,
  upstreamIssue,
  validateAllowedAlgorithms,
} from "./primitives.js";
import {
  checkKeySnapshot,
  validateEcJwk,
  validateJoseProtectedHeader,
  verifyParsedJwtSignature,
} from "./jwk.js";
import { parseCompactAp2Token, parseJwtCompact } from "./jwt-parse.js";

/**
 * Direct-signed AP2 Mandate verification, constraint verification (allowed
 * merchants, line items, payment reference), the bounded max-flow helper
 * used by line-item constraints, and shared JWT-claim helpers (audience,
 * expiry, parsed-JWT signature verification). The AP2 v0.2.0 delegate
 * SD-JWT chain verifier lives in ./mandate-chain.ts.
 */

const AP2_TERMINAL_TYPES = new Set(["kb+sd-jwt", "kb-sd-jwt"]);
const AP2_INTERMEDIATE_TYPES = new Set(["kb+sd-jwt+kb", "kb-sd-jwt+kb"]);
const AP2_ROOT_TYPES = new Set(["dc+sd-jwt", "example+sd-jwt"]);
const AP2_INHERITANCE_EXCLUSIONS = new Set([
  "vct",
  "constraints",
  "cnf",
  "iat",
  "exp",
  "nbf",
  "iss",
]);

export { AP2_TERMINAL_TYPES, AP2_INTERMEDIATE_TYPES, AP2_ROOT_TYPES, AP2_INHERITANCE_EXCLUSIONS };

export function materializeTopLevelDisclosures(
  parsed: ParsedCompactAp2Token,
  issues: InteropIssue[],
): JsonObject {
  const claims: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
  for (const [name, value] of Object.entries(parsed.issuerJwt.claims)) {
    claims[name] = value;
  }
  const digestList = claims._sd;
  const accepted = new Set<string>();
  if (digestList !== undefined) {
    if (!Array.isArray(digestList) || digestList.some((entry) => typeof entry !== "string")) {
      issues.push(upstreamIssue(
        "AP2_SD_DIGESTS_INVALID",
        "token.issuerJwt.claims._sd",
        "SD-JWT _sd must be an array of digest strings",
      ));
      return claims;
    }
    for (const entry of digestList) accepted.add(entry as string);
  }

  for (let index = 0; index < parsed.disclosures.length; index += 1) {
    const disclosure = parsed.disclosures[index] as ParsedSdJwtDisclosure;
    if (!accepted.has(disclosure.digest)) {
      issues.push(upstreamIssue(
        "AP2_DISCLOSURE_UNBOUND",
        `token.disclosures[${String(index)}]`,
        "Disclosure digest is not committed by the issuer JWT",
      ));
      continue;
    }
    const decoded = disclosure.decoded;
    if (!Array.isArray(decoded) || decoded.length !== 3 || typeof decoded[1] !== "string") {
      issues.push(upstreamIssue(
        "AP2_DISCLOSURE_SHAPE_UNSUPPORTED",
        `token.disclosures[${String(index)}]`,
        "Only top-level object-property disclosures are supported by this adapter",
      ));
      continue;
    }
    const name = decoded[1];
    if (hasOwn(claims, name)) {
      issues.push(upstreamIssue(
        "AP2_DISCLOSURE_CONFLICT",
        `token.disclosures[${String(index)}]`,
        "Disclosure conflicts with an existing claim",
      ));
      continue;
    }
    claims[name] = decoded[2] as JsonValue;
  }
  return claims;
}

export function verifyAudience(value: unknown, expected: string): boolean {
  if (typeof value === "string") return value === expected;
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) return false;
  return value.includes(expected);
}

export function verifyExpiryClaims(
  claims: JsonObject,
  asOf: number,
  issues: InteropIssue[],
  path: string,
): void {
  if (claims.exp === undefined) {
    issues.push(eligibilityIssue(
      "AP2_EXPIRY_MISSING",
      `${path}.exp`,
      "Mandate has no explicit expiration and is not eligible for durable authority evidence",
    ));
  } else {
    try {
      const exp = requireSafeInteger(claims.exp, `${path}.exp`);
      if (asOf >= exp) {
        issues.push(upstreamIssue("AP2_TOKEN_EXPIRED", `${path}.exp`, "Mandate is expired"));
      }
    } catch (error) {
      issues.push(upstreamIssue(
        "AP2_EXPIRY_INVALID",
        `${path}.exp`,
        error instanceof Error ? error.message : "Invalid expiration claim",
      ));
    }
  }
  if (claims.nbf !== undefined) {
    try {
      if (asOf < requireSafeInteger(claims.nbf, `${path}.nbf`)) {
        issues.push(upstreamIssue("AP2_TOKEN_NOT_YET_VALID", `${path}.nbf`, "Mandate is not yet valid"));
      }
    } catch (error) {
      issues.push(upstreamIssue(
        "AP2_NBF_INVALID",
        `${path}.nbf`,
        error instanceof Error ? error.message : "Invalid nbf claim",
      ));
    }
  }
  if (claims.iat !== undefined) {
    try {
      if (requireSafeInteger(claims.iat, `${path}.iat`) > asOf + 60) {
        issues.push(upstreamIssue(
          "AP2_IAT_IN_FUTURE",
          `${path}.iat`,
          "Mandate issuance time is in the future",
        ));
      }
    } catch (error) {
      issues.push(upstreamIssue(
        "AP2_IAT_INVALID",
        `${path}.iat`,
        error instanceof Error ? error.message : "Invalid iat claim",
      ));
    }
  }
}

export function verifyAllowedMerchantConstraint(
  constraint: JsonObject,
  expectedMerchant: ExpectedMerchant | undefined,
  checkoutJwt: unknown,
  requireBoundCheckoutMerchant: boolean,
): boolean {
  let merchant = expectedMerchant;
  if (requireBoundCheckoutMerchant) {
    if (typeof checkoutJwt !== "string") return false;
    try {
      const claims = parseJwtCompact(checkoutJwt, "checkoutJwt").claims;
      if (!isObject(claims.merchant) || typeof claims.merchant.id !== "string") return false;
      const boundMerchant: ExpectedMerchant = Object.freeze({
        id: claims.merchant.id,
        ...(typeof claims.merchant.website === "string"
          ? { website: claims.merchant.website }
          : {}),
      });
      if (
        expectedMerchant !== undefined && (
          expectedMerchant.id !== boundMerchant.id ||
          (
            expectedMerchant.website !== undefined &&
            expectedMerchant.website !== boundMerchant.website
          )
        )
      ) {
        return false;
      }
      merchant = boundMerchant;
    } catch {
      return false;
    }
  }
  if (merchant === undefined || !Array.isArray(constraint.allowed)) return false;
  return constraint.allowed.some((candidate) => {
    if (!isObject(candidate) || candidate.id !== merchant.id) return false;
    return requireBoundCheckoutMerchant ||
      merchant.website === undefined ||
      candidate.website === merchant.website;
  });
}

interface FlowEdge {
  readonly to: number;
  readonly reverse: number;
  capacity: number;
}

function addFlowEdge(graph: FlowEdge[][], from: number, to: number, capacity: number): void {
  const forward: FlowEdge = { to, reverse: graph[to]?.length ?? 0, capacity };
  const reverse: FlowEdge = { to: from, reverse: graph[from]?.length ?? 0, capacity: 0 };
  graph[from]?.push(forward);
  graph[to]?.push(reverse);
}

function boundedMaxFlow(graph: FlowEdge[][], source: number, sink: number): number {
  let total = 0;
  while (true) {
    const parentNode = new Array<number>(graph.length).fill(-1);
    const parentEdge = new Array<number>(graph.length).fill(-1);
    const queue: number[] = [source];
    parentNode[source] = source;
    for (let cursor = 0; cursor < queue.length && parentNode[sink] === -1; cursor += 1) {
      const node = queue[cursor] as number;
      const edges = graph[node] ?? [];
      for (let index = 0; index < edges.length; index += 1) {
        const edge = edges[index] as FlowEdge;
        if (edge.capacity <= 0 || parentNode[edge.to] !== -1) continue;
        parentNode[edge.to] = node;
        parentEdge[edge.to] = index;
        queue.push(edge.to);
        if (edge.to === sink) break;
      }
    }
    if (parentNode[sink] === -1) return total;
    let pushed = Number.MAX_SAFE_INTEGER;
    for (let node = sink; node !== source; node = parentNode[node] as number) {
      const previous = parentNode[node] as number;
      const edge = graph[previous]?.[parentEdge[node] as number];
      if (edge === undefined) throw new UcpAp2ParseError("Invalid AP2 line-item flow state");
      pushed = Math.min(pushed, edge.capacity);
    }
    for (let node = sink; node !== source; node = parentNode[node] as number) {
      const previous = parentNode[node] as number;
      const edge = graph[previous]?.[parentEdge[node] as number];
      if (edge === undefined) throw new UcpAp2ParseError("Invalid AP2 line-item flow state");
      edge.capacity -= pushed;
      const reverse = graph[node]?.[edge.reverse];
      if (reverse === undefined) throw new UcpAp2ParseError("Invalid AP2 line-item flow state");
      reverse.capacity += pushed;
    }
    total += pushed;
  }
}

function verifyLineItemsConstraint(constraint: JsonObject, checkoutJwt: unknown): boolean {
  if (typeof checkoutJwt !== "string") return false;
  let checkoutClaims: JsonObject;
  try {
    checkoutClaims = parseJwtCompact(checkoutJwt, "checkoutJwt").claims;
  } catch {
    return false;
  }
  if (
    !Array.isArray(constraint.items) ||
    constraint.items.length === 0 ||
    constraint.items.length > 128 ||
    !Array.isArray(checkoutClaims.line_items) ||
    checkoutClaims.line_items.length === 0 ||
    checkoutClaims.line_items.length > 128
  ) {
    return false;
  }

  const requirements: { readonly acceptable: ReadonlySet<string>; readonly quantity: number }[] = [];
  for (const requirement of constraint.items) {
    if (
      !isObject(requirement) ||
      typeof requirement.id !== "string" ||
      requirement.id.length === 0 ||
      !Array.isArray(requirement.acceptable_items) ||
      !Number.isSafeInteger(requirement.quantity) ||
      (requirement.quantity as number) <= 0
    ) {
      return false;
    }
    const acceptable = new Set<string>();
    for (const item of requirement.acceptable_items) {
      if (
        !isObject(item) ||
        typeof item.id !== "string" ||
        item.id.length === 0 ||
        typeof item.title !== "string" ||
        item.title.length === 0
      ) {
        return false;
      }
      acceptable.add(item.id);
    }
    requirements.push({ acceptable, quantity: requirement.quantity as number });
  }

  const cart = new Map<string, number>();
  for (const lineItem of checkoutClaims.line_items) {
    if (
      !isObject(lineItem) ||
      !isObject(lineItem.item) ||
      typeof lineItem.item.id !== "string" ||
      lineItem.item.id.length === 0 ||
      typeof lineItem.item.title !== "string" ||
      lineItem.item.title.length === 0 ||
      !Number.isSafeInteger(lineItem.quantity) ||
      (lineItem.quantity as number) <= 0
    ) {
      return false;
    }
    const next = (cart.get(lineItem.item.id) ?? 0) + (lineItem.quantity as number);
    if (!Number.isSafeInteger(next)) return false;
    cart.set(lineItem.item.id, next);
  }

  const skus = [...cart.keys()].sort();
  const source = 0;
  const skuOffset = 1;
  const requirementOffset = skuOffset + skus.length;
  const sink = requirementOffset + requirements.length;
  const graph: FlowEdge[][] = Array.from({ length: sink + 1 }, () => []);
  let totalQuantity = 0;
  let requiredQuantity = 0;
  for (let skuIndex = 0; skuIndex < skus.length; skuIndex += 1) {
    const sku = skus[skuIndex] as string;
    const quantity = cart.get(sku) as number;
    totalQuantity += quantity;
    if (!Number.isSafeInteger(totalQuantity)) return false;
    addFlowEdge(graph, source, skuOffset + skuIndex, quantity);
    for (let requirementIndex = 0; requirementIndex < requirements.length; requirementIndex += 1) {
      const requirement = requirements[requirementIndex] as {
        readonly acceptable: ReadonlySet<string>;
        readonly quantity: number;
      };
      if (requirement.acceptable.size === 0 || requirement.acceptable.has(sku)) {
        addFlowEdge(
          graph,
          skuOffset + skuIndex,
          requirementOffset + requirementIndex,
          quantity,
        );
      }
    }
  }
  for (let index = 0; index < requirements.length; index += 1) {
    const quantity = (requirements[index] as { quantity: number }).quantity;
    requiredQuantity += quantity;
    if (!Number.isSafeInteger(requiredQuantity)) return false;
    addFlowEdge(graph, requirementOffset + index, sink, quantity);
  }
  return totalQuantity === requiredQuantity
    && boundedMaxFlow(graph, source, sink) === requiredQuantity;
}

export function verifyConstraints(
  claims: JsonObject,
  options: VerifyAp2MandateOptions,
  issues: InteropIssue[],
  closedClaims?: JsonObject,
  requirePinnedSchema = false,
): void {
  if (claims.constraints === undefined) {
    if (requirePinnedSchema) {
      issues.push(upstreamIssue(
        "AP2_CONSTRAINTS_REQUIRED",
        "token.claims.constraints",
        "Pinned AP2 open Mandate schema requires constraints",
      ));
    }
    return;
  }
  if (!Array.isArray(claims.constraints)) {
    issues.push(upstreamIssue(
      "AP2_CONSTRAINTS_INVALID",
      "token.claims.constraints",
      "Mandate constraints must be an array",
    ));
    return;
  }
  let hasRequiredConstraint = false;
  for (let index = 0; index < claims.constraints.length; index += 1) {
    const candidate = claims.constraints[index];
    if (!isObject(candidate) || typeof candidate.type !== "string") {
      issues.push(upstreamIssue(
        "AP2_CONSTRAINT_INVALID",
        `token.claims.constraints[${String(index)}]`,
        "Constraint is missing a string type",
      ));
      continue;
    }
    if (candidate.type === "checkout.allowed_merchants") {
      if (requirePinnedSchema && options.expectedVct !== "mandate.checkout.1") {
        issues.push(upstreamIssue(
          "AP2_CONSTRAINT_UNSUPPORTED",
          `token.claims.constraints[${String(index)}]`,
          "Checkout constraint is not valid for this Mandate type",
        ));
        continue;
      }
      if (!verifyAllowedMerchantConstraint(
        candidate as JsonObject,
        options.expectedMerchant,
        closedClaims?.checkout_jwt,
        requirePinnedSchema,
      )) {
        issues.push(upstreamIssue(
          "AP2_CONSTRAINT_FAILED",
          `token.claims.constraints[${String(index)}]`,
          "Allowed-merchant constraint could not be satisfied",
        ));
      }
      continue;
    }
    if (candidate.type === "checkout.line_items") {
      hasRequiredConstraint = true;
      if (
        options.expectedVct !== "mandate.checkout.1" ||
        !verifyLineItemsConstraint(candidate as JsonObject, closedClaims?.checkout_jwt)
      ) {
        issues.push(upstreamIssue(
          "AP2_CONSTRAINT_FAILED",
          `token.claims.constraints[${String(index)}]`,
          "Line-item constraint could not be satisfied by the bound Checkout JWT",
        ));
      }
      continue;
    }
    if (candidate.type === "payment.reference") {
      hasRequiredConstraint = true;
      if (
        options.expectedVct !== "mandate.payment.1" ||
        typeof candidate.conditional_transaction_id !== "string" ||
        candidate.conditional_transaction_id.length === 0 ||
        options.expectedOpenCheckoutHash === undefined ||
        candidate.conditional_transaction_id !== options.expectedOpenCheckoutHash
      ) {
        issues.push(upstreamIssue(
          "AP2_CONSTRAINT_FAILED",
          `token.claims.constraints[${String(index)}]`,
          "Payment-reference constraint is missing or does not match the associated open Checkout Mandate",
        ));
      }
      continue;
    }
    issues.push(upstreamIssue(
      "AP2_CONSTRAINT_UNSUPPORTED",
      `token.claims.constraints[${String(index)}]`,
      "Unknown or unsupported constraint types fail closed",
    ));
  }
  if (requirePinnedSchema && !hasRequiredConstraint) {
    issues.push(upstreamIssue(
      "AP2_REQUIRED_CONSTRAINT_MISSING",
      "token.claims.constraints",
      options.expectedVct === "mandate.checkout.1"
        ? "Pinned Open Checkout Mandate requires checkout.line_items"
        : "Pinned Open Payment Mandate requires payment.reference",
    ));
  }
}

export function verifyAp2Mandate(
  options: VerifyAp2MandateOptions,
): InteropVerification<VerifiedAp2Mandate> {
  const issues: InteropIssue[] = [];
  let parsed: ParsedCompactAp2Token;
  let allowed: ReadonlySet<JoseEcAlgorithm>;
  let asOf: number;
  try {
    parsed = parseCompactAp2Token(options.token);
    allowed = validateAllowedAlgorithms(options.allowedAlgorithms, ["ES256"]);
    asOf = parseEpoch(options.asOf, "asOf");
  } catch (error) {
    issues.push(upstreamIssue(
      "AP2_TOKEN_INVALID",
      "token",
      error instanceof Error ? error.message : "Invalid AP2 token",
    ));
    return finish<VerifiedAp2Mandate>(null, issues);
  }

  if (!checkKeySnapshot(
    options.issuerKeySnapshot,
    options.expectedIssuerKeySourceDigest,
    options.asOf,
    issues,
    "issuerKeySnapshot",
  )) return finish<VerifiedAp2Mandate>(null, issues);

  let issuerHeader: { readonly algorithm: JoseEcAlgorithm; readonly kid: string | null } | null = null;
  try {
    issuerHeader = verifyParsedJwtSignature(
      parsed.issuerJwt,
      options.issuerKeySnapshot.jwk,
      allowed,
      options.issuerKeySnapshot.kid,
      "issuer",
    );
  } catch (error) {
    issues.push(upstreamIssue(
      "AP2_ISSUER_SIGNATURE_INVALID",
      "token.issuerJwt",
      error instanceof Error ? error.message : "Issuer signature is invalid",
    ));
  }

  const claims = materializeTopLevelDisclosures(parsed, issues);
  const vct = claims.vct;
  if (!AP2_MANDATE_VCTS.includes(vct as Ap2MandateVct) || vct !== options.expectedVct) {
    issues.push(upstreamIssue(
      "AP2_VCT_MISMATCH",
      "token.claims.vct",
      "Mandate vct does not exactly match the expected versioned type",
    ));
  }
  if (claims.iss !== options.expectedIssuer) {
    issues.push(upstreamIssue(
      "AP2_ISSUER_MISMATCH",
      "token.claims.iss",
      "Mandate issuer does not match the expected issuer",
    ));
  }
  verifyExpiryClaims(claims, asOf, issues, "token.claims");

  const requireKeyBinding = options.requireKeyBinding ?? true;
  let keyBound = false;
  if (parsed.keyBindingJwt === null) {
    if (requireKeyBinding) {
      issues.push(upstreamIssue(
        "AP2_KEY_BINDING_MISSING",
        "token.keyBindingJwt",
        "A Key Binding JWT is required by this evidence profile",
      ));
    }
  } else {
    try {
      const cnf = requireJsonObject(claims.cnf, "token.claims.cnf");
      const embeddedJwk = requireJsonObject(cnf.jwk, "token.claims.cnf.jwk") as unknown as EcPublicJwk;
      const kbHeader = validateJoseProtectedHeader(
        parsed.keyBindingJwt.protectedHeader,
        allowed,
        "key-binding",
      );
      validateEcJwk(embeddedJwk, kbHeader.algorithm);
      if (
        options.expectedAgentJwk !== undefined &&
        publicJwkIdentity(embeddedJwk) !== publicJwkIdentity(options.expectedAgentJwk)
      ) {
        throw new UcpAp2ParseError("cnf key does not match the expected agent key");
      }
      verifyParsedJwtSignature(
        parsed.keyBindingJwt,
        embeddedJwk,
        allowed,
        null,
        "key-binding",
      );
      const kbClaims = parsed.keyBindingJwt.claims;
      if (!verifyAudience(kbClaims.aud, options.expectedAudience)) {
        throw new UcpAp2ParseError("Key Binding audience does not match");
      }
      if (kbClaims.nonce !== options.expectedNonce) {
        throw new UcpAp2ParseError("Key Binding nonce does not match");
      }
      const expectedSdHash = base64UrlSha256(parsed.sdJwtWithoutKeyBinding);
      if (kbClaims.sd_hash !== expectedSdHash) {
        throw new UcpAp2ParseError("Key Binding sd_hash does not match the exact SD-JWT presentation");
      }
      verifyExpiryClaims(kbClaims, asOf, issues, "token.keyBindingJwt.claims");
      keyBound = true;
    } catch (error) {
      issues.push(upstreamIssue(
        "AP2_KEY_BINDING_INVALID",
        "token.keyBindingJwt",
        error instanceof Error ? error.message : "Invalid AP2 Key Binding JWT",
      ));
    }
  }

  let checkoutHash: string | undefined;
  if (vct === "mandate.checkout.1") {
    if (typeof claims.checkout_jwt !== "string" || typeof claims.checkout_hash !== "string") {
      issues.push(upstreamIssue(
        "AP2_CHECKOUT_BINDING_MISSING",
        "token.claims",
        "Closed Checkout Mandate is missing checkout_jwt or checkout_hash",
      ));
    } else {
      checkoutHash = base64UrlSha256(claims.checkout_jwt);
      if (claims.checkout_hash !== checkoutHash) {
        issues.push(upstreamIssue(
          "AP2_CHECKOUT_HASH_MISMATCH",
          "token.claims.checkout_hash",
          "checkout_hash does not match the exact checkout_jwt field value",
        ));
      }
      if (
        options.expectedCheckoutJwt !== undefined &&
        claims.checkout_jwt !== options.expectedCheckoutJwt
      ) {
        issues.push(upstreamIssue(
          "AP2_CHECKOUT_JWT_MISMATCH",
          "token.claims.checkout_jwt",
          "Mandate is bound to a different Checkout JWT",
        ));
      }
      if (
        options.expectedCheckoutHash !== undefined &&
        claims.checkout_hash !== options.expectedCheckoutHash
      ) {
        issues.push(upstreamIssue(
          "AP2_EXPECTED_CHECKOUT_HASH_MISMATCH",
          "token.claims.checkout_hash",
          "Mandate checkout hash does not match the caller-owned expected value",
        ));
      }
    }
  } else if (vct === "mandate.payment.1" && options.expectedCheckoutHash !== undefined) {
    if (claims.transaction_id !== options.expectedCheckoutHash) {
      issues.push(upstreamIssue(
        "AP2_PAYMENT_CHECKOUT_BINDING_MISMATCH",
        "token.claims.transaction_id",
        "Payment Mandate transaction_id is not the expected checkout hash",
      ));
    } else {
      checkoutHash = options.expectedCheckoutHash;
    }
  }

  verifyConstraints(claims, options, issues);

  const result: VerifiedAp2Mandate = {
    profileId: UCP_AP2_EVIDENCE_PROFILE.id,
    ap2Version: UCP_AP2_EVIDENCE_PROFILE.ap2Version,
    exactToken: options.token,
    vct: AP2_MANDATE_VCTS.includes(vct as Ap2MandateVct)
      ? vct as Ap2MandateVct
      : options.expectedVct,
    issuer: typeof claims.iss === "string" ? claims.iss : options.expectedIssuer,
    claims,
    issuerKid: issuerHeader?.kid ?? options.issuerKeySnapshot.kid,
    issuerAlgorithm: issuerHeader?.algorithm ?? "ES256",
    keyBound,
    authorizesNativeRole: false,
    ...(checkoutHash === undefined ? {} : { checkoutHash }),
  };
  return finish(Object.freeze(result), issues);
}
