import { Buffer } from "node:buffer";
import { sha256Bytes } from "../canonical.js";
import type {
  InteropIssue,
  InteropVerification,
  ParsedUcpSignatureInput,
  UcpRequestEvidenceInput,
  UcpHttpAlgorithm,
  VerifiedUcpRequestEvidence,
} from "./types.js";
import type { Sha256Digest } from "../domain.js";
import { UCP_AP2_EVIDENCE_PROFILE } from "./profile.js";
import { UcpAp2ParseError } from "./parse-error.js";
import {
  decodeBase64,
  finish,
  parseEpoch,
  parseHttpsUrl,
  STATE_CHANGING_METHODS,
  upstreamIssue,
  eligibilityIssue,
} from "./primitives.js";
import {
  checkKeySnapshot,
  verifyRawEcdsa,
} from "./jwk.js";
import { verifyRawBodyContentDigest } from "./content-digest.js";

/**
 * UCP HTTP request evidence verification. Implements the bounded RFC 9421
 * subset the UCP profile accepts, including idempotency-key handling and
 * content-digest verification.
 */

function parseQuoted(
  input: string,
  start: number,
): { readonly value: string; readonly next: number } {
  if (input[start] !== "\"") throw new UcpAp2ParseError("Expected quoted string");
  let cursor = start + 1;
  let output = "";
  while (cursor < input.length) {
    const character = input[cursor];
    if (character === "\"") return { value: output, next: cursor + 1 };
    if (character === "\\" || character === "\r" || character === "\n" || character === undefined) {
      throw new UcpAp2ParseError("Escapes and line breaks are not accepted in signature parameters");
    }
    output += character;
    cursor += 1;
  }
  throw new UcpAp2ParseError("Unterminated quoted string");
}

/**
 * Parse the single-signature RFC 9421 subset used by UCP. The exact serialized
 * inner-list and parameters are retained for signature-base reconstruction.
 */
export function parseUcpSignatureInput(value: string): ParsedUcpSignatureInput {
  if (typeof value !== "string" || value.length > 16_384) {
    throw new UcpAp2ParseError("Signature-Input is empty or exceeds the byte limit");
  }
  const equals = value.indexOf("=");
  if (equals <= 0) throw new UcpAp2ParseError("Signature-Input is missing a label");
  const label = value.slice(0, equals);
  if (!/^[a-z][a-z0-9_-]*$/.test(label)) {
    throw new UcpAp2ParseError("Signature-Input label is invalid");
  }
  const serializedParameters = value.slice(equals + 1);
  if (!serializedParameters.startsWith("(")) {
    throw new UcpAp2ParseError("Signature-Input must contain an inner list");
  }
  let cursor = 1;
  const components: string[] = [];
  while (cursor < serializedParameters.length) {
    if (serializedParameters[cursor] === ")") {
      cursor += 1;
      break;
    }
    if (components.length > 0) {
      if (serializedParameters[cursor] !== " ") {
        throw new UcpAp2ParseError("Signature components must be separated by one space");
      }
      cursor += 1;
    }
    const parsed = parseQuoted(serializedParameters, cursor);
    if (!/^@?[a-z0-9][a-z0-9_-]*$/.test(parsed.value)) {
      throw new UcpAp2ParseError("Signature component identifier is invalid");
    }
    if (components.includes(parsed.value)) {
      throw new UcpAp2ParseError("Signature component identifiers must be unique");
    }
    components.push(parsed.value);
    cursor = parsed.next;
  }
  if (components.length === 0 || serializedParameters[cursor - 1] !== ")") {
    throw new UcpAp2ParseError("Signature-Input inner list is empty or unterminated");
  }

  const parameters = new Map<string, string | number | true>();
  while (cursor < serializedParameters.length) {
    if (serializedParameters[cursor] !== ";") {
      throw new UcpAp2ParseError("Invalid Signature-Input parameter separator");
    }
    cursor += 1;
    const nameMatch = /^[a-z][a-z0-9_-]*/.exec(serializedParameters.slice(cursor));
    if (nameMatch === null) throw new UcpAp2ParseError("Invalid Signature-Input parameter name");
    const name = nameMatch[0];
    cursor += name.length;
    if (parameters.has(name)) {
      throw new UcpAp2ParseError("Duplicate Signature-Input parameter");
    }
    if (serializedParameters[cursor] !== "=") {
      parameters.set(name, true);
      continue;
    }
    cursor += 1;
    if (serializedParameters[cursor] === "\"") {
      const parsed = parseQuoted(serializedParameters, cursor);
      parameters.set(name, parsed.value);
      cursor = parsed.next;
    } else {
      const integerMatch = /^(?:0|[1-9][0-9]*)/.exec(serializedParameters.slice(cursor));
      if (integerMatch === null) {
        throw new UcpAp2ParseError("Unsupported Signature-Input parameter value");
      }
      const parsed = Number(integerMatch[0]);
      if (!Number.isSafeInteger(parsed)) {
        throw new UcpAp2ParseError("Signature-Input integer parameter is unsafe");
      }
      parameters.set(name, parsed);
      cursor += integerMatch[0].length;
    }
  }
  if (parameters.has("alg")) {
    throw new UcpAp2ParseError("UCP derives the algorithm from the JWK; alg is not accepted here");
  }
  for (const name of parameters.keys()) {
    if (!new Set(["keyid", "created", "expires", "nonce", "tag"]).has(name)) {
      throw new UcpAp2ParseError("Unsupported Signature-Input parameter");
    }
  }
  const keyId = parameters.get("keyid");
  if (typeof keyId !== "string" || keyId.length === 0) {
    throw new UcpAp2ParseError("Signature-Input is missing keyid");
  }
  const created = parameters.get("created");
  const expires = parameters.get("expires");
  if (created !== undefined && typeof created !== "number") {
    throw new UcpAp2ParseError("Signature-Input created must be an integer");
  }
  if (expires !== undefined && typeof expires !== "number") {
    throw new UcpAp2ParseError("Signature-Input expires must be an integer");
  }
  return Object.freeze({
    label,
    components: Object.freeze(components),
    keyId,
    created: created ?? null,
    expires: expires ?? null,
    serializedParameters,
  });
}

function normalizeHeaders(headers: Readonly<Record<string, string>>): ReadonlyMap<string, string> {
  const result = new Map<string, string>();
  for (const [name, value] of Object.entries(headers)) {
    const normalizedName = name.toLowerCase();
    if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(normalizedName)) {
      throw new UcpAp2ParseError("HTTP field name is invalid");
    }
    if (result.has(normalizedName)) {
      throw new UcpAp2ParseError("HTTP fields collide after case normalization");
    }
    if (typeof value !== "string" || /[\r\n]/.test(value)) {
      throw new UcpAp2ParseError("HTTP field value contains an invalid line break");
    }
    result.set(normalizedName, value.trim().replace(/[ \t]+/g, " "));
  }
  return result;
}

function requestComponentValue(
  component: string,
  input: UcpRequestEvidenceInput,
  headers: ReadonlyMap<string, string>,
): string {
  switch (component) {
    case "@method":
      return input.method.toUpperCase();
    case "@authority":
      return input.authority;
    case "@path":
      return input.path;
    case "@query":
      if (input.query === undefined) {
        throw new UcpAp2ParseError("Signed @query has no request query value");
      }
      return input.query.startsWith("?") ? input.query : `?${input.query}`;
    default: {
      if (component.startsWith("@")) {
        throw new UcpAp2ParseError("Unsupported derived HTTP signature component");
      }
      const value = headers.get(component);
      if (value === undefined) {
        throw new UcpAp2ParseError("Signed HTTP field is absent from request metadata");
      }
      return value;
    }
  }
}

export function buildUcpRequestSignatureBase(
  input: UcpRequestEvidenceInput,
  parsed = parseUcpSignatureInput(input.signatureInput),
): Uint8Array {
  const headers = normalizeHeaders(input.headers);
  const lines = parsed.components.map((component) =>
    `"${component}": ${requestComponentValue(component, input, headers)}`);
  lines.push(`"@signature-params": ${parsed.serializedParameters}`);
  return Buffer.from(lines.join("\n"), "utf8");
}

function parseUcpSignatureValue(
  value: string,
  expectedLabel: string,
): Uint8Array {
  const match = /^([a-z][a-z0-9_-]*)=:([A-Za-z0-9+/]*={0,2}):$/.exec(value);
  if (match === null || match[1] !== expectedLabel || match[2] === undefined) {
    throw new UcpAp2ParseError("Signature field label or byte sequence is invalid");
  }
  return decodeBase64(match[2], "Signature");
}

function requiredUcpRequestComponents(
  input: UcpRequestEvidenceInput,
  headers: ReadonlyMap<string, string>,
): readonly string[] {
  const required = ["@method", "@authority", "@path"];
  if (input.query !== undefined && input.query.length > 0) required.push("@query");
  if (headers.has("ucp-agent")) required.push("ucp-agent");
  if (STATE_CHANGING_METHODS.has(input.method.toUpperCase())) required.push("idempotency-key");
  if (input.rawBody !== undefined) required.push("content-digest", "content-type");
  return required;
}

function validateUcpAgentHeader(value: string): void {
  const match = /^profile="([^"\\]+)"$/.exec(value);
  if (match === null || match[1] === undefined) {
    throw new UcpAp2ParseError("UCP-Agent must contain exactly one quoted profile URL");
  }
  parseHttpsUrl(match[1], "ucp-agent.profile");
}

function validIdempotencyKey(value: string): boolean {
  return (
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value) ||
    /^[A-Za-z0-9_-]{22,}$/.test(value)
  );
}

export function verifyUcpRequestEvidence(
  input: UcpRequestEvidenceInput,
): InteropVerification<VerifiedUcpRequestEvidence> {
  const issues: InteropIssue[] = [];
  let parsed: ParsedUcpSignatureInput;
  let headers: ReadonlyMap<string, string>;
  let algorithm: UcpHttpAlgorithm = "ES256";
  let rawBodyDigest: Sha256Digest = sha256Bytes(input.rawBody ?? new Uint8Array());
  let operation = "";
  let replayStatus: "new" | "cached" | "unresolved" = "new";

  try {
    parsed = parseUcpSignatureInput(input.signatureInput);
    headers = normalizeHeaders(input.headers);
    if (!/^[A-Z]+$/.test(input.method.toUpperCase())) {
      throw new UcpAp2ParseError("HTTP method is invalid");
    }
    if (
      input.authority.length === 0 ||
      /[\r\n/]/.test(input.authority) ||
      !input.path.startsWith("/") ||
      /[\r\n]/.test(input.path)
    ) {
      throw new UcpAp2ParseError("HTTP authority or path is invalid");
    }
    operation = `${input.method.toUpperCase()} ${input.path}${
      input.query === undefined || input.query.length === 0
        ? ""
        : input.query.startsWith("?") ? input.query : `?${input.query}`
    }`;

    if (parsed.keyId !== input.keySnapshot.kid) {
      issues.push(upstreamIssue(
        "UCP_SIGNATURE_KEY_MISMATCH",
        "signature-input.keyid",
        "Signature keyid does not match the pinned key snapshot",
      ));
    }
    algorithm = input.keySnapshot.jwk.crv === "P-384" ? "ES384" : "ES256";
    if (input.keySnapshot.jwk.crv === "P-521") {
      issues.push(upstreamIssue(
        "UCP_ALGORITHM_UNSUPPORTED",
        "keySnapshot.jwk.crv",
        "UCP REST permits ES256 and optionally ES384, not ES512",
      ));
    }

    const required = requiredUcpRequestComponents(input, headers);
    for (const component of required) {
      if (!parsed.components.includes(component)) {
        issues.push(upstreamIssue(
          "UCP_SIGNED_COMPONENT_MISSING",
          "signature-input.components",
          `Required signed component ${component} is missing`,
        ));
      }
    }

    const ucpAgent = headers.get("ucp-agent");
    if (ucpAgent !== undefined) validateUcpAgentHeader(ucpAgent);

    if (input.rawBody !== undefined) {
      rawBodyDigest = sha256Bytes(input.rawBody);
      const contentDigest = headers.get("content-digest");
      if (contentDigest === undefined) {
        issues.push(upstreamIssue(
          "UCP_CONTENT_DIGEST_MISSING",
          "headers.content-digest",
          "Content-Digest is required when a request has a body",
        ));
      } else {
        const bodyReport = verifyRawBodyContentDigest(input.rawBody, contentDigest);
        issues.push(...bodyReport.issues);
      }
      if (headers.get("content-type") === undefined) {
        issues.push(upstreamIssue(
          "UCP_CONTENT_TYPE_MISSING",
          "headers.content-type",
          "Content-Type is required when a request has a body",
        ));
      }
    }

    if (STATE_CHANGING_METHODS.has(input.method.toUpperCase())) {
      const idempotencyKey = headers.get("idempotency-key");
      if (idempotencyKey === undefined || !validIdempotencyKey(idempotencyKey)) {
        issues.push(upstreamIssue(
          "UCP_IDEMPOTENCY_KEY_INVALID",
          "headers.idempotency-key",
          "State-changing request lacks a high-entropy idempotency key",
        ));
      } else {
        const previous = input.idempotencyLedger?.get(idempotencyKey);
        if (previous !== undefined) {
          if (previous.operation !== operation || previous.rawBodyDigest !== rawBodyDigest) {
            issues.push(upstreamIssue(
              "UCP_IDEMPOTENCY_CONFLICT",
              "headers.idempotency-key",
              "Idempotency key was previously used for different request bytes or operation",
            ));
          } else if (input.replayDisposition === "cached") {
            replayStatus = "cached";
          } else {
            replayStatus = "unresolved";
            issues.push(eligibilityIssue(
              "UCP_REPLAY_DISPOSITION_UNPROVEN",
              "replayDisposition",
              "Duplicate request is not evidenced as a cached, side-effect-free replay",
            ));
          }
        } else if (input.replayDisposition === "cached") {
          issues.push(upstreamIssue(
            "UCP_REPLAY_RECORD_MISSING",
            "replayDisposition",
            "Cached replay was asserted without a matching prior idempotency record",
          ));
        }
      }
    }

    const asOf = parseEpoch(input.asOf, "asOf");
    if (parsed.created !== null && parsed.created > asOf + 60) {
      issues.push(upstreamIssue(
        "UCP_SIGNATURE_CREATED_IN_FUTURE",
        "signature-input.created",
        "Signature creation time is in the future",
      ));
    }
    if (parsed.expires !== null && asOf >= parsed.expires) {
      issues.push(upstreamIssue(
        "UCP_SIGNATURE_EXPIRED",
        "signature-input.expires",
        "HTTP message signature is expired",
      ));
    }

    const signature = parseUcpSignatureValue(input.signature, parsed.label);
    const signatureBase = buildUcpRequestSignatureBase(input, parsed);
    if (!verifyRawEcdsa(
      algorithm,
      signatureBase,
      signature,
      input.keySnapshot.jwk,
      input.keySnapshot.kid,
    )) {
      issues.push(upstreamIssue(
        "UCP_SIGNATURE_INVALID",
        "signature",
        "RFC 9421 signature verification failed",
      ));
    }
  } catch (error) {
    issues.push(upstreamIssue(
      "UCP_REQUEST_EVIDENCE_INVALID",
      "request",
      error instanceof Error ? error.message : "Invalid UCP request evidence",
    ));
    return finish<VerifiedUcpRequestEvidence>(null, issues);
  }

  checkKeySnapshot(
    input.keySnapshot,
    input.expectedKeySourceDigest,
    input.asOf,
    issues,
    "keySnapshot",
  );

  const value: VerifiedUcpRequestEvidence = Object.freeze({
    profileId: UCP_AP2_EVIDENCE_PROFILE.id,
    operation,
    keyId: parsed.keyId,
    algorithm,
    signedComponents: parsed.components,
    rawBodyDigest,
    replayStatus,
    upstreamValid: true,
  });
  return finish(value, issues);
}
