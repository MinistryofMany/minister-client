import type { JWTVerifyGetKey, KeyLike } from "jose";

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
  // Pairwise pseudonymous subject — stable per (issuer, clientId).
  sub: string;
  name?: string;
  picture?: string;
}

// A signature-verified, structurally-validated badge.
export interface VerifiedBadge {
  // The VC `type` array, e.g. ["VerifiableCredential", "MinisterEmailDomainCredential"].
  type: string[];
  // The `credentialSubject` claims (the `id` field is surfaced as `sub`).
  claims: Record<string, unknown>;
  // The credential subject DID (the holder), taken from the JWT `sub`.
  // Asserted to equal `credentialSubject.id`.
  sub: string;
  // The original VC JWT, for storage or forwarding.
  raw: string;
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
