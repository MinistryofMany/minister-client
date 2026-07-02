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
 * TEMPORAL JWT CLAIMS ARE DISCLOSURE-SHAPED, NOT ISSUANCE-SHAPED (MIN-1).
 * Minister re-mints every disclosed badge at disclosure time: the VC's
 * `iat`/`nbf` are the disclosure instant and `exp` is disclosure time plus a
 * short presentation TTL (clamped so it never exceeds the badge's real
 * expiry). A fine-grained issuance-derived timestamp would be a stable
 * cross-RP correlator, so none survives disclosure — never derive badge age
 * from `iat`/`exp`.
 *
 * The ONE issuance-derived signal is the deliberately COARSE
 * `issuanceMonth` field below ("YYYY-MM", the UTC calendar month of the
 * badge's true issuance, a reserved `credentialSubject` key stamped by
 * Minister at re-mint). Freshness checks derive from IT: map the month to
 * its bucket START so the computed age is always ≥ the true age (a stale
 * badge can never pass — fail-closed), and accept that sub-month precision
 * is intentionally lost (a `maxAgeDays` of N months works; sub-month gates
 * are out of contract). `@ministryofmany/minister-verify` feeds
 * `@ministryofmany/policy`'s `maxAgeDays` exactly this way, and Minister
 * additionally enforces the same coarse check consent-side before
 * disclosing. Month granularity keeps the field shared-by-many (≤ ~13
 * buckets across a badge population with the default 1-year lifetime,
 * ≈ 3.7 bits), so it is a cohort marker, not a re-identifier.
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
  // The UTC calendar month ("YYYY-MM") containing the badge's TRUE issuance
  // instant — Minister's reserved coarse-issuance metadata (see the interface
  // doc above). IDENTICAL for the same badge at every RP by design (a
  // shared-by-many cohort bucket, not a pairwise field) and strictly
  // format-checked (a present-but-malformed value rejects the badge).
  // Undefined when the disclosing Minister predates the claim; freshness
  // checks then fail closed (no evidence ⇒ no maxAgeDays pass).
  issuanceMonth?: string;
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
