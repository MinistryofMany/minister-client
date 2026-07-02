import {
  createMinisterVerifier,
  type KeyInput,
  type VerifiedBadge as VerifiedBadgeSdk,
} from "@ministryofmany/client";
import type { VerifiedBadge } from "@ministryofmany/policy";

export interface VerifiedIdentity {
  sub: string;
  badges: VerifiedBadge[];
}

/**
 * Safe summary of badges dropped during verification. NEVER carries the raw VC
 * JWT (which may hold token material or PII) - only the per-entry error message
 * and a count. Handed to an optional `onRejectedBadges` callback so the host
 * app can log/alert with its own logger; the package itself logs nothing.
 */
export interface RejectedBadgesReport {
  sub: string;
  rejectedCount: number;
  rejectedReasons: string[];
}

export interface VerifierDeps {
  issuer: string;
  /** Mapped to the SDK's `clientId` so the id_token `aud` is enforced. */
  audience: string;
  /**
   * Inject a verification key to keep tests offline (e.g. a
   * `createLocalJWKSet(...)` resolver). Omit in production: the SDK then
   * fetches Minister's JWKS via the issuer (OIDC discovery + did:web). The
   * SDK derives the expected badge VC issuer DID from `issuer`, so there is
   * no separate `vcIssuer`.
   */
  jwks?: KeyInput;
  /**
   * Optional observability hook for badges that failed verification (forged,
   * expired, wrong-issuer, or unknown-type). Invoked with a SAFE summary only;
   * the verified badges are unchanged (fail-closed gating is preserved). Keep
   * the host app's logger/env out of this package by passing a callback here.
   */
  onRejectedBadges?: (report: RejectedBadgesReport) => void;
}

/**
 * Recover the VC `iat` (seconds) from an already-verified VC JWT to fill the
 * policy engine's `issuedAt` slot. No signature work happens here: the SDK
 * already verified `raw`, so we only base64url-decode the payload segment and
 * read `iat`. Returns 0 when the claim is absent or the payload is
 * unparseable.
 *
 * KNOWN REGRESSION (documented, accepted): post-MIN-1 this is NOT the badge's
 * issuance time. Minister re-mints every disclosed badge at disclosure time
 * (pairwise sub/jti, and `iat`/`nbf`/`exp` re-stamped to the disclosure
 * instant), so the recovered `iat` is "seconds ago" for every live token.
 * Any `maxAgeDays` policy leaf evaluated against this value passes
 * unconditionally — the RP-side freshness check is vacuous. The composed
 * system is still safe because Minister enforces `maxAgeDays` consent-side
 * against the badge's true database issuance time before disclosing, but do
 * not rely on this field as defense-in-depth. A verifiable, coarse
 * issuance-age claim for RPs is a tracked design follow-up.
 */
function iatFromRawVc(rawVcJwt: string): number {
  const seg = rawVcJwt.split(".")[1];
  if (!seg) return 0;
  try {
    const json = Buffer.from(seg, "base64url").toString("utf8");
    const iat = (JSON.parse(json) as { iat?: unknown }).iat;
    return typeof iat === "number" ? iat : 0;
  } catch {
    return 0;
  }
}

/**
 * Factory so callers can inject a local JWKS + mock issuer config. Wraps the
 * `@ministryofmany/client` verifier and reproduces the `VerifiedIdentity` contract
 * relying-party services consume.
 *
 * Bad-badge handling: the SDK never throws on an individual malformed,
 * expired, wrong-issuer, or unknown-type badge - it drops it into `rejected`
 * and returns the verified ones in `badges`. We surface only the verified
 * `badges`, so a forged or expired badge simply does not count toward a
 * policy (fails closed). The id_token wrapper itself still throws on a bad
 * signature / issuer / audience / expiry.
 */
export function makeVerifier(deps: VerifierDeps) {
  // Fail-closed audience. `@ministryofmany/client` only enforces the id_token `aud`
  // when its `clientId` is truthy - it builds the underlying `jose` verify
  // options as `...clientId ? { audience: clientId } : {}`, so an
  // empty/undefined audience would SILENTLY SKIP the `aud` check and accept a
  // token minted for any other RP. Guard here so this reusable factory can
  // never be constructed without an expected audience regardless of caller.
  if (!deps.audience) {
    throw new Error("makeVerifier: a non-empty `audience` (client id) is required");
  }
  const verifier = createMinisterVerifier({
    issuer: deps.issuer,
    clientId: deps.audience,
    jwks: deps.jwks,
  });
  return async function verifyMinisterIdToken(idToken: string): Promise<VerifiedIdentity> {
    // Throws MinisterTokenError on a bad id_token signature / iss / aud / exp / iat.
    const claims = await verifier.verifyIdToken(idToken);
    // Passing the raw id_token re-verifies the wrapper (issuer/audience/key)
    // before reading its badges; individual bad badges land in `rejected`.
    const { badges, rejected } = await verifier.verifyBadges(idToken);
    if (rejected.length > 0 && deps.onRejectedBadges) {
      // Observability for misconfiguration (e.g. an issuer-host vs VC-issuer
      // DID mismatch silently rejecting every badge) and forged-badge probing.
      // The verified `badges` returned below are unchanged: this is a
      // non-throwing side effect that preserves fail-closed gating. Surface only
      // a SAFE summary - the per-entry `error.message` - and NEVER the raw VC
      // JWT (`rejected[].raw`), which may carry token material or PII. The
      // badge slug/type is not cheaply available without decoding `raw`, so it
      // is intentionally omitted.
      deps.onRejectedBadges({
        sub: claims.sub,
        rejectedCount: rejected.length,
        rejectedReasons: rejected.map((r) => r.error.message),
      });
    }
    return {
      sub: claims.sub,
      badges: badges.map((b: VerifiedBadgeSdk) => ({
        type: b.type,
        attributes: b.claims as VerifiedBadge["attributes"],
        // Disclosure time, not issuance time — see iatFromRawVc: RP-side
        // maxAgeDays evaluated on this is vacuous (Minister enforces
        // freshness consent-side).
        issuedAt: iatFromRawVc(b.raw),
      })),
    };
  };
}
