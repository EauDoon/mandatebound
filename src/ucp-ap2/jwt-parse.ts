import { Buffer } from "node:buffer";
import { parseStrictJson, parseStrictJsonObject } from "../strict-json.js";
import type {
  ParsedCompactAp2Token,
  ParsedJwt,
  ParsedSdJwtDisclosure,
} from "./types.js";
import { UcpAp2ParseError } from "./parse-error.js";
import {
  base64UrlSha256,
  decodeBase64Url,
  requireString,
  strictUtf8,
} from "./primitives.js";

/**
 * Compact JWT and SD-JWT parsing for both AP2 closed Mandates and UCP/AP2
 * merchant-signed tokens. The parsers return the exact bytes that downstream
 * signature verification must operate over.
 */

export function parseJwtCompact(compact: string, path: string): ParsedJwt {
  const parts = compact.split(".");
  if (
    parts.length !== 3 ||
    parts[0] === undefined ||
    parts[1] === undefined ||
    parts[2] === undefined ||
    parts.some((entry) => entry.length === 0)
  ) {
    throw new UcpAp2ParseError(`Expected a three-segment compact JWT at ${path}`);
  }
  const protectedHeader = parseStrictJsonObject(
    strictUtf8(decodeBase64Url(parts[0], `${path}.protected`)),
  );
  const claims = parseStrictJsonObject(
    strictUtf8(decodeBase64Url(parts[1], `${path}.payload`)),
  );
  decodeBase64Url(parts[2], `${path}.signature`);
  return Object.freeze({
    exactCompact: compact,
    protectedSegment: parts[0],
    payloadSegment: parts[1],
    signatureSegment: parts[2],
    protectedHeader,
    claims,
  });
}

export function parseCompactAp2Token(token: string): ParsedCompactAp2Token {
  if (typeof token !== "string" || token.length === 0 || Buffer.byteLength(token) > 1_048_576) {
    throw new UcpAp2ParseError("AP2 compact token is empty or exceeds the byte limit");
  }
  const parts = token.split("~");
  const issuerCompact = parts.shift();
  if (issuerCompact === undefined || issuerCompact.length === 0) {
    throw new UcpAp2ParseError("AP2 compact token is missing its issuer JWT");
  }
  const issuerJwt = parseJwtCompact(issuerCompact, "token.issuerJwt");

  let keyBindingJwt: ParsedJwt | null = null;
  if (parts.length > 0) {
    const final = parts[parts.length - 1];
    if (final !== undefined && final.length > 0 && final.split(".").length === 3) {
      keyBindingJwt = parseJwtCompact(final, "token.keyBindingJwt");
      parts.pop();
    } else if (final === "") {
      parts.pop();
    }
  }
  if (parts.some((entry) => entry.length === 0 || entry.includes("."))) {
    throw new UcpAp2ParseError("AP2 token contains an invalid disclosure segment");
  }

  const algorithm = issuerJwt.claims._sd_alg === undefined
    ? "sha-256"
    : requireString(issuerJwt.claims._sd_alg, "token.issuerJwt.claims._sd_alg");
  if (algorithm !== "sha-256") {
    throw new UcpAp2ParseError("Only sha-256 SD-JWT disclosures are supported");
  }
  const disclosures = parts.map((encoded, index): ParsedSdJwtDisclosure => {
    const decodedBytes = decodeBase64Url(encoded, `token.disclosures[${String(index)}]`);
    const decoded = parseStrictJson(strictUtf8(decodedBytes));
    if (!Array.isArray(decoded) || (decoded.length !== 2 && decoded.length !== 3)) {
      throw new UcpAp2ParseError("SD-JWT disclosure must be a two- or three-element array");
    }
    if (typeof decoded[0] !== "string" || decoded[0].length < 8) {
      throw new UcpAp2ParseError("SD-JWT disclosure salt is missing or too short");
    }
    return Object.freeze({
      exact: encoded,
      digest: base64UrlSha256(encoded),
      decoded,
    });
  });

  const prefixSegments = [issuerCompact, ...parts];
  const sdJwtWithoutKeyBinding = keyBindingJwt === null
    ? token
    : `${prefixSegments.join("~")}~`;
  return Object.freeze({
    exact: token,
    issuerJwt,
    disclosures: Object.freeze(disclosures),
    keyBindingJwt,
    sdJwtWithoutKeyBinding,
  });
}
