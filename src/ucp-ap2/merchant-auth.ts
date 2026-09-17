import { Buffer } from "node:buffer";
import { canonicalBytes, sha256Bytes } from "../canonical.js";
import type { JsonObject, JsonValue } from "../domain.js";
import { parseStrictJsonObject } from "../strict-json.js";
import type {
  DetachedMerchantAuthorization,
  InteropIssue,
  InteropVerification,
  JoseEcAlgorithm,
  VerifyDetachedMerchantAuthorizationOptions,
} from "./types.js";
import { UcpAp2ParseError } from "./parse-error.js";
import {
  decodeBase64Url,
  finish,
  requireJsonObject,
  strictUtf8,
  upstreamIssue,
  validateAllowedAlgorithms,
} from "./primitives.js";
import {
  checkKeySnapshot,
  validateJoseProtectedHeader,
  verifyRawEcdsa,
} from "./jwk.js";

/**
 * UCP/AP2 detached merchant-authorization verification. The merchant signs
 * the canonicalized UCP checkout payload with the kid-pinned key, and the
 * adapter verifies the signature over the exact compact JWS form.
 */

export function verifyDetachedMerchantAuthorization(
  checkout: unknown,
  detachedJws: string,
  options: VerifyDetachedMerchantAuthorizationOptions,
): InteropVerification<DetachedMerchantAuthorization> {
  const issues: InteropIssue[] = [];
  if (!checkKeySnapshot(
    options.keySnapshot,
    options.expectedKeySourceDigest,
    options.asOf,
    issues,
    "merchantKeySnapshot",
  )) {
    return finish<DetachedMerchantAuthorization>(null, issues);
  }
  let protectedHeader: JsonObject;
  let kid = options.keySnapshot.kid;
  let algorithm: JoseEcAlgorithm = "ES256";
  let canonicalPayloadDigest = sha256Bytes(new Uint8Array());
  try {
    if (
      typeof detachedJws !== "string" ||
      detachedJws.length === 0 ||
      Buffer.byteLength(detachedJws, "utf8") > 65_536
    ) {
      throw new UcpAp2ParseError("Detached merchant JWS is empty or exceeds the byte limit");
    }
    const segments = detachedJws.split(".");
    if (
      segments.length !== 3 ||
      segments[0] === undefined ||
      segments[1] !== "" ||
      segments[2] === undefined ||
      segments[0].length === 0 ||
      segments[2].length === 0
    ) {
      throw new UcpAp2ParseError("Merchant authorization must use detached compact JWS form");
    }
    protectedHeader = parseStrictJsonObject(
      strictUtf8(decodeBase64Url(segments[0], "merchantAuthorization.protected")),
    );
    const allowed = validateAllowedAlgorithms(
      options.allowedAlgorithms,
      ["ES256", "ES384", "ES512"],
    );
    const parsedHeader = validateJoseProtectedHeader(protectedHeader, allowed, "merchant");
    algorithm = parsedHeader.algorithm;
    kid = parsedHeader.kid as string;
    if (kid !== options.keySnapshot.kid) {
      issues.push(upstreamIssue(
        "UCP_AP2_MERCHANT_KEY_MISMATCH",
        "merchantAuthorization.protected.kid",
        "Merchant authorization kid does not match the pinned key snapshot",
      ));
    }

    const checkoutObject = requireJsonObject(checkout, "checkout");
    const ap2 = requireJsonObject(checkoutObject.ap2, "checkout.ap2");
    if (ap2.merchant_authorization !== detachedJws) {
      issues.push(upstreamIssue(
        "UCP_AP2_MERCHANT_AUTHORIZATION_UNBOUND",
        "checkout.ap2.merchant_authorization",
        "Detached JWS is not the exact merchant_authorization embedded in the checkout",
      ));
    }
    const payload: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
    for (const [name, value] of Object.entries(checkoutObject)) {
      if (name !== "ap2") payload[name] = value;
    }
    const bytes = canonicalBytes(payload);
    canonicalPayloadDigest = sha256Bytes(bytes);
    const signingInput = Buffer.from(
      `${segments[0]}.${Buffer.from(bytes).toString("base64url")}`,
      "ascii",
    );
    const signature = decodeBase64Url(
      segments[2],
      "merchantAuthorization.signature",
    );
    if (!verifyRawEcdsa(
      algorithm,
      signingInput,
      signature,
      options.keySnapshot.jwk,
      options.keySnapshot.kid,
    )) {
      issues.push(upstreamIssue(
        "UCP_AP2_MERCHANT_SIGNATURE_INVALID",
        "merchantAuthorization.signature",
        "Detached merchant authorization signature verification failed",
      ));
    }
  } catch (error) {
    issues.push(upstreamIssue(
      "UCP_AP2_MERCHANT_AUTHORIZATION_INVALID",
      "merchantAuthorization",
      error instanceof Error ? error.message : "Invalid merchant authorization",
    ));
    return finish<DetachedMerchantAuthorization>(null, issues);
  }

  return finish(Object.freeze({
    exactCompact: detachedJws,
    protectedHeader,
    canonicalPayloadDigest,
    kid,
    algorithm,
  }), issues);
}
