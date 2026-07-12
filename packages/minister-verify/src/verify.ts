import {
  createMinisterVerifier,
  type KeyInput,
  type VerifiedBadge as VerifiedBadgeSdk,
} from "@ministryofmany/client";
import type { VerifiedBadge } from "@ministryofmany/policy";

export interface VerifiedIdentity {
  sub: string;
  badges: VerifiedBadge[];
  // The verified anti-sybil bucket (0-4), present ONLY when the RP requested the
  // `sybil-score` scope, the user consented, and Minister disclosed it. The SDK
  // range-validates it (integer 0-4) before it reaches here; undefined otherwise.
  // Consumed as-is by the RP; NEVER recomputed (the score config is server-only).
  sybil_bucket?: number;
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
 * Fill the policy engine's `issuedAt` slot from the badge's COARSE issuance
 * bucket: Minister discloses `credentialSubject.issuanceMonth` ("YYYY-MM",
 * the UTC calendar month of the badge's TRUE issuance), which the SDK
 * surfaces — already strictly format-checked — as `VerifiedBadge.issuanceMonth`.
 *
 * The mapping is the bucket START (first UTC second of the month), so the
 * computed age is always ≥ the true age: a stale badge can NEVER pass a
 * `maxAgeDays` leaf via bucketing (fail-closed), at the price of sub-month
 * precision (a badge issued late in a month reads as old as its month start;
 * `maxAgeDays` gates are month-granular by contract — Minister evaluates the
 * SAME coarse clock consent-side, so both ends agree).
 *
 * Never derive age from the VC `iat`: MIN-1 re-stamps it (and `nbf`/`exp`)
 * to the DISCLOSURE instant precisely because fine-grained issuance
 * timestamps were a cross-RP correlator — an iat-derived `issuedAt` reads
 * "seconds old" for every live token and admits any stale badge.
 *
 * Returns 0 when the claim is absent (a legacy, pre-claim Minister) or —
 * defensively — unparseable: age ≈ `now`, so every `maxAgeDays` leaf fails
 * (no freshness evidence ⇒ no freshness pass) while age-less leaves are
 * unaffected.
 */
function issuedAtFromIssuanceMonth(issuanceMonth: string | undefined): number {
  if (issuanceMonth === undefined) return 0;
  const match = /^(\d{4})-(0[1-9]|1[0-2])$/.exec(issuanceMonth);
  if (!match) return 0;
  return Date.UTC(Number(match[1]), Number(match[2]) - 1, 1) / 1000;
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
      // Passthrough of the already-range-validated bucket from the id_token
      // claims (undefined when the scope was not granted / not disclosed).
      sybil_bucket: claims.sybil_bucket,
      badges: badges.map((b: VerifiedBadgeSdk) => ({
        type: b.type,
        attributes: b.claims as VerifiedBadge["attributes"],
        // The issuance-month bucket START (coarse, fail-closed) — never the
        // disclosure-time iat. See issuedAtFromIssuanceMonth.
        issuedAt: issuedAtFromIssuanceMonth(b.issuanceMonth),
        // NOTE: `b.nullifier` (the per-RP `mnv1:` gating tag) is intentionally
        // DROPPED here — this mapping is not wired for nullifier-based gating
        // yet (the Discreetly gating follow-up is optional per the crypto-core
        // ADR). It does NOT propagate to policy evaluation via `attributes`
        // either: `b.claims` has the nullifier stripped SDK-side. When room
        // gating on the nullifier lands, thread it through as an optional field
        // here; until then, do NOT assume it reaches the policy layer.
      })),
    };
  };
}
