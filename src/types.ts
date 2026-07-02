import type { JWK, JWTVerifyGetKey, KeyLike } from "jose";
import type { VcVerificationError } from "./errors";

// Configuration for a Minister relying-party client.
export interface MinisterClientConfig {
  // Minister's origin, e.g. "https://ministry.id". This is the OIDC
  // `issuer` and the base for discovery (`/.well-known/...`). A trailing
  // slash is tolerated and normalized away.
  issuer: string;
  clientId: string;
  // Required for confidential clients. Omit for public/PKCE-only clients.
  clientSecret?: string;
  redirectUri: string;
}

// PKCE pair (RFC 7636, S256). The `verifier` stays server-side and is
// replayed at token exchange; the `challenge` goes in the auth URL.
export interface PkcePair {
  verifier: string;
  challenge: string;
}

// The per-request state an RP must persist between the authorization
// redirect and the callback. The SDK stores NOTHING — the app owns
// persistence and MUST consume this atomically by `state` (delete-on-read)
// so a `state`/`nonce` pair can be used at most once.
export interface OidcFlowState {
  // CSRF token echoed back as the `state` query param. Use it as the
  // lookup key for the persisted flow state.
  state: string;
  // Replay-binding nonce; must equal the verified id_token's `nonce`.
  nonce: string;
  // PKCE verifier replayed at token exchange.
  codeVerifier: string;
  // Epoch milliseconds after which this flow should be considered stale
  // and rejected. The SDK does not enforce it; the app should.
  expiresAt: number;
}

// Identity claims from a verified id_token.
export interface MinisterClaims {
  // Pairwise pseudonymous subject - stable per (issuer, clientId).
  sub: string;
  name?: string;
  picture?: string;
  // The original id_token JWT, for forwarding/storage.
  raw: string;
}

/**
 * A signature-verified, schema-validated badge.
 *
 * TEMPORAL CLAIMS ARE DISCLOSURE-SHAPED, NOT ISSUANCE-SHAPED (MIN-1).
 * Minister re-mints every disclosed badge at disclosure time: the VC's
 * `iat`/`nbf` are the disclosure instant and `exp` is disclosure time plus a
 * short presentation TTL (clamped so it never exceeds the badge's real
 * expiry). An issuance-derived timestamp would be a stable cross-RP
 * correlator, so none survives disclosure. Consequences for relying parties:
 *
 * - Any RP-side freshness check derived from the VC `iat` is VACUOUS. In
 *   particular, `@ministryofmany/policy`'s `maxAgeDays` — fed by
 *   `@ministryofmany/minister-verify`, which derives `issuedAt` from the VC
 *   `iat` — sees every disclosed badge as seconds old and therefore passes
 *   unconditionally. It is NOT an effective defense-in-depth today.
 * - Freshness is still enforced, but on Minister's side: a `minister_policy`
 *   `maxAgeDays` leaf is evaluated at consent against the badge's true
 *   database issuance time, before anything is disclosed. The composed system
 *   remains safe; only the redundant RP-side check is inert.
 * - Giving RPs a verifiable issuance-age signal without re-opening the
 *   timestamp-correlation channel (e.g. a coarse bucketed age claim) is a
 *   tracked design follow-up — do not repurpose `iat`/`exp` for it.
 */
export interface VerifiedBadge {
  // The Minister badge slug, e.g. "age-over-18".
  type: string;
  // The credentialSubject claims, validated against the badge's schema
  // (the `id` field is surfaced as `subject`).
  claims: Record<string, unknown>;
  // The holder's per-RP PAIRWISE Minister DID: `did:web:<domain>:u:<sub>`,
  // taken from the VC and asserted equal to the VC's own JWT `sub`. Minister
  // re-mints each badge at DISCLOSURE time under the same pairwise pseudonym it
  // stamps as the id_token `sub`, so this subject is opaque, carries no raw
  // internal user id, and DIFFERS across relying parties (two colluding RPs
  // cannot correlate the same user via their badges).
  //
  // The DID's trailing `<sub>` component equals the id_token `sub`. The wrapper
  // (`verifyMinisterBadges` / `exchangeCode` / `ministerBadgesFromProfile`)
  // binds each badge to the login automatically by requiring
  // `subject === did:web:<host>:u:<id_token sub>`; a borrowed badge (another
  // user's, presented alongside your login) lands in `rejected`. Standalone
  // `verifyMinisterBadge` does NOT bind (it has no id_token) — it only checks
  // the VC-internal `credentialSubject.id === sub` self-consistency.
  subject: string;
  // The original VC JWT, for storage or forwarding.
  raw: string;
}

// A badge that failed verification (bad signature, wrong issuer, expired,
// subject mismatch, unknown type, or invalid claims).
export interface RejectedBadge {
  raw: string;
  error: VcVerificationError;
}

// The outcome of verifying the badges in a token: the usable badges and
// the ones that failed (with reasons). verifyBadges never throws on an
// individual bad badge.
export interface BadgesResult {
  badges: VerifiedBadge[];
  rejected: RejectedBadge[];
}

// Result of a successful code exchange: identity plus disclosed badges.
export interface ExchangeResult {
  claims: MinisterClaims;
  // Signature-verified, schema-validated badges that were disclosed.
  badges: VerifiedBadge[];
  // Badges that were disclosed but failed verification (bad signature,
  // wrong issuer, expired, unknown type, invalid claims). Login still
  // succeeds; these are surfaced so the app can log or alert.
  rejected: RejectedBadge[];
}

// A key source for JWT verification. Either a single resolved key — a
// `KeyLike`, a raw `JWK`, or a symmetric `Uint8Array` — or a jose key resolver
// (e.g. a remote JWKS). A bare `JWK` is accepted so an RP (or a test) can hand
// over Minister's public key without importing it first; the SDK imports it
// internally (pinned to EdDSA). Injectable so tests verify without network
// access; the default is a remote JWKS fetched from Minister.
export type KeyInput = KeyLike | JWK | Uint8Array | JWTVerifyGetKey;
