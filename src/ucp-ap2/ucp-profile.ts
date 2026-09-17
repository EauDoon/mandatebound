import type { JsonObject } from "../domain.js";
import { isSha256Digest, sha256Bytes } from "../canonical.js";
import { parseStrictJsonObject } from "../strict-json.js";
import type {
  InteropIssue,
  InteropVerification,
  UcpProfileSnapshot,
  VerifiedUcpProfile,
  VerifyUcpProfileOptions,
} from "./types.js";
import { UCP_AP2_EVIDENCE_PROFILE } from "./profile.js";
import { UcpAp2ParseError } from "./parse-error.js";
import {
  extractCapabilityEntries,
  hasVersionEntry,
} from "./ucp-profile-helpers.js";
import {
  eligibilityIssue,
  finish,
  isObject,
  parseHttpsUrl,
  parseTimestampMillis,
  requireJsonObject,
  strictUtf8,
  upstreamIssue,
} from "./primitives.js";

/**
 * UCP profile snapshot verification. The adapter pins the exact UCP REST
 * shopping service declaration, the pinned checkout capability version, and
 * the AP2 Mandates extension version.
 */

export function verifyUcpProfileSnapshot(
  snapshot: UcpProfileSnapshot,
  options: VerifyUcpProfileOptions,
): InteropVerification<VerifiedUcpProfile> {
  const issues: InteropIssue[] = [];
  let profile: JsonObject;
  try {
    parseHttpsUrl(snapshot.profileUrl, "profileUrl");
    const capturedAt = parseTimestampMillis(snapshot.capturedAt, "capturedAt");
    const validUntil = parseTimestampMillis(snapshot.validUntil, "validUntil");
    const asOf = parseTimestampMillis(options.asOf, "asOf");
    if (capturedAt > validUntil) {
      issues.push(upstreamIssue(
        "UCP_PROFILE_WINDOW_INVALID",
        "profile",
        "Profile capture time is after its validity limit",
      ));
    }
    if (asOf > validUntil) {
      issues.push(eligibilityIssue(
        "UCP_PROFILE_SNAPSHOT_STALE",
        "profile",
        "Pinned UCP profile snapshot is stale",
      ));
    }
    profile = parseStrictJsonObject(strictUtf8(snapshot.profileBytes));
  } catch (error) {
    issues.push(upstreamIssue(
      "UCP_PROFILE_INVALID",
      "profile",
      error instanceof Error ? error.message : "Invalid UCP profile snapshot",
    ));
    return finish<VerifiedUcpProfile>(null, issues);
  }

  const actualDigest = sha256Bytes(snapshot.profileBytes);
  if (!isSha256Digest(snapshot.profileDigest) || snapshot.profileDigest !== actualDigest) {
    issues.push(upstreamIssue(
      "UCP_PROFILE_DIGEST_MISMATCH",
      "profileDigest",
      "Declared UCP profile digest does not match the exact captured bytes",
    ));
  }
  if (!isSha256Digest(options.expectedProfileDigest) || actualDigest !== options.expectedProfileDigest) {
    issues.push(eligibilityIssue(
      "UCP_PROFILE_PIN_MISMATCH",
      "profileDigest",
      "Captured UCP profile does not match the caller-owned digest pin",
    ));
  }
  if (snapshot.ap2Version !== UCP_AP2_EVIDENCE_PROFILE.ap2Version) {
    issues.push(upstreamIssue(
      "AP2_VERSION_UNSUPPORTED",
      "ap2Version",
      "Only the AP2 v0.2.0 evidence profile is supported",
    ));
  }

  try {
    const ucp = requireJsonObject(profile.ucp, "profile.ucp");
    if (ucp.version !== UCP_AP2_EVIDENCE_PROFILE.ucpVersion) {
      issues.push(upstreamIssue(
        "UCP_VERSION_UNSUPPORTED",
        "profile.ucp.version",
        "UCP profile version is not the pinned 2026-04-08 version",
      ));
    }
    const services = requireJsonObject(ucp.services, "profile.ucp.services");
    const shopping = services[UCP_AP2_EVIDENCE_PROFILE.ucpService];
    if (!Array.isArray(shopping)) {
      throw new UcpAp2ParseError("Missing UCP shopping service");
    }
    const restService = shopping.some((entry) => {
      if (!isObject(entry)) return false;
      return (
        entry.transport === UCP_AP2_EVIDENCE_PROFILE.ucpTransport &&
        entry.version === UCP_AP2_EVIDENCE_PROFILE.ucpVersion
      );
    });
    if (!restService) {
      issues.push(upstreamIssue(
        "UCP_REST_PROFILE_MISSING",
        "profile.ucp.services",
        "Pinned UCP REST shopping service declaration is missing",
      ));
    }

    const capabilities = requireJsonObject(ucp.capabilities, "profile.ucp.capabilities");
    const checkoutEntries = extractCapabilityEntries(
      capabilities,
      UCP_AP2_EVIDENCE_PROFILE.checkoutCapability,
      `profile.ucp.capabilities.${UCP_AP2_EVIDENCE_PROFILE.checkoutCapability}`,
    );
    if (!hasVersionEntry(checkoutEntries, UCP_AP2_EVIDENCE_PROFILE.ucpVersion)) {
      issues.push(upstreamIssue(
        "UCP_CHECKOUT_VERSION_UNSUPPORTED",
        "profile.ucp.capabilities",
        "Checkout capability is not pinned to UCP 2026-04-08",
      ));
    }
    const ap2Entries = extractCapabilityEntries(
      capabilities,
      UCP_AP2_EVIDENCE_PROFILE.ap2Extension,
      `profile.ucp.capabilities.${UCP_AP2_EVIDENCE_PROFILE.ap2Extension}`,
    );
    if (!hasVersionEntry(ap2Entries, UCP_AP2_EVIDENCE_PROFILE.ucpVersion)) {
      issues.push(upstreamIssue(
        "UCP_AP2_EXTENSION_VERSION_UNSUPPORTED",
        "profile.ucp.capabilities",
        "AP2 Mandates extension is not pinned to UCP 2026-04-08",
      ));
    }
  } catch (error) {
    issues.push(upstreamIssue(
      "UCP_PROFILE_SHAPE_INVALID",
      "profile",
      error instanceof Error ? error.message : "Invalid UCP profile structure",
    ));
  }

  const value: VerifiedUcpProfile = Object.freeze({
    profileId: UCP_AP2_EVIDENCE_PROFILE.id,
    profileDigest: actualDigest,
    profileUrl: snapshot.profileUrl,
    ucpVersion: UCP_AP2_EVIDENCE_PROFILE.ucpVersion,
    transport: UCP_AP2_EVIDENCE_PROFILE.ucpTransport,
    ap2Version: UCP_AP2_EVIDENCE_PROFILE.ap2Version,
    profile,
    authorizesNativeRole: false,
  });
  return finish(value, issues);
}
