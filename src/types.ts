import type { JWK, JWTVerifyGetKey, KeyLike } from "jose";
import type { VcVerificationError } from "./errors";
import type { BadgeStatusRef } from "./status-list";

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
  // Minister's opt-in coarse Sybil-resistance bucket (integer 0-4),
  // snapshotted at consent and disclosed only when the RP requested the
  // `sybil-score` scope. Verified upstream (signed id_token) and
  // range-validated on the way out; present ONLY when it is an integer in
  // [0,4] (0 is a real value), otherwise undefined. Never recompute it — the
  // score config is server-only; consume this value as-is.
  sybil_bucket?: number;
  // The anon-identity epoch for this RP, snapshotted at consent. Bumps when the
  // user re-keys (loses their root); the app re-keys its identity only when this
  // strictly advances past the epoch it last keyed at (see decideAnonAction in
  // @ministryofmany/identity/link). Verified upstream (signed id_token) and
  // range-validated on the way out; present ONLY when it is an integer >= 1,
  // otherwise undefined. Never recompute it - Ministry owns the epoch.
  minister_anon_epoch?: number;
  // The original id_token JWT, for forwarding/storage.
  raw: string;
}

/**
 * Minister's per-relying-party Sybil-dedup nullifier (`mnv1:...`), the value
 * Minister stamps in a disclosed badge's `credentialSubject.nullifier` (M5).
 *
 * BRANDED so it can NEVER be interchanged with the OTHER, unrelated nullifier
 * primitive in this ecosystem — `@ministryofmany/nullifier`'s Poseidon/BN254
 * field string (`poseidon2(toField(sub), contextId)`), which is account-anchored
 * and SNARK-provable. These two are permanently distinct (M3):
 *
 *   | | `@ministryofmany/nullifier` | this `MinisterGatingNullifier` |
 *   |---|---|---|
 *   | math | Poseidon / BN254 | RFC 9497 VOPRF + HMAC-SHA256 |
 *   | anchor | the per-RP `sub` (account) | the credential (email, github id) |
 *   | circuit-usable | YES | NO (gating-only, plaintext compare) |
 *   | catches | same-account-across-contexts | same-credential-across-accounts |
 *
 * There is no conversion between them. A future circuit-usable credential
 * nullifier must be a NEW Poseidon construction, never a bridge from this value.
 *
 * HONESTY: this proves ONE CREDENTIAL, not one person. It is per-site
 * (different, unlinkable at other RPs), stable for the same credential (the same
 * value if any account re-proves it here, surviving account delete/re-create),
 * and only as strong as the credential behind it (see each badge type's
 * `sybilResistance`). Gate on it; do not treat it as a unique-human oracle.
 */
export type MinisterGatingNullifier = string & {
  readonly __brand: "MinisterGatingNullifier";
};

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
  // Minister's per-RP Sybil-dedup nullifier (`mnv1:...`), when present — a
  // reserved `credentialSubject.nullifier` key Minister stamps under its
  // signature at disclosure (M5). Bound to THIS badge's subject/jti/type/exp,
  // so it cannot be lifted onto another credential or replayed as another user.
  //
  // Use it to gate on "one credential" (Sybil dedup, ban persistence): the SAME
  // value appears if any account re-proves the same credential to YOUR site, and
  // it PERSISTS across account delete/re-create; a DIFFERENT, unlinkable value
  // appears at other sites. It is NOT a unique-human oracle — read
  // `MinisterGatingNullifier` for the full honesty + non-interchangeability note.
  //
  // Undefined for badges with no wired nullifier (invite-code, age/residency,
  // and any pre-M5 disclosure). Present-but-malformed (`!^mnv1:[A-Za-z0-9_-]+$`)
  // fails the badge closed, like `issuanceMonth`.
  nullifier?: MinisterGatingNullifier;
  // Revocation handle (W3C BitstringStatusListEntry, §5.8), when the badge is
  // revocable. `{ uri, index }` points at Minister's per-RP status list. Persist
  // it next to any DURABLE entitlement you grant from this badge and sweep it
  // with `createMinisterStatusChecker(...).check(status)`; on "revoked" drop the
  // entitlement. Undefined for a non-revocable badge (or a pre-revocation issuer).
  // Present-but-malformed fails the badge closed, like `nullifier`.
  status?: BadgeStatusRef;
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
