import type { JWTVerifyGetKey, KeyLike } from "jose";
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

// A signature-verified, schema-validated badge.
export interface VerifiedBadge {
  // The Minister badge slug, e.g. "age-over-18".
  type: string;
  // The credentialSubject claims, validated against the badge's schema
  // (the `id` field is surfaced as `subject`).
  claims: Record<string, unknown>;
  // The credential subject DID (holder), equal to the id_token `sub`.
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
  badges: VerifiedBadge[];
}

// A key source for JWT verification. Either a single resolved key (e.g.
// a public key in a test) or a jose key resolver (e.g. a remote JWKS).
// Injectable so tests verify without network access; the default is a
// remote JWKS fetched from Minister.
export type KeyInput = KeyLike | Uint8Array | JWTVerifyGetKey;
