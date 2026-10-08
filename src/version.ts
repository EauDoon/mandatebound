export const PROTOCOL_VERSION = "1.0.0" as const;
export const ENGINE_VERSION = "1.0.0" as const;
export const RELEASE_VERSION = "1.2.0" as const;
/**
 * The release whose schemas/v1.2 define the AP2 dispute resolution, Evidence
 * Pack and Pack verification formats. Those artifacts carry this value as
 * their `releaseVersion`, and verification requires it, so it is a format
 * identifier frozen at "1.2.0". It never follows the package release: moving it
 * would invalidate every retained Pack and violate the published schemas.
 */
export const AP2_DISPUTE_FORMAT_RELEASE = "1.2.0" as const;
export const LEGAL_EFFECT = "not-determined" as const;
