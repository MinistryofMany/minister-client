import { verifyMinisterIdToken } from "./verify-id-token";
import { verifyMinisterBadges } from "./verify-badges";
import { verifyMinisterBadge } from "./verify-badge";
import type { JWTPayload } from "jose";
import type { KeyInput, MinisterClaims, VerifiedBadge, BadgesResult } from "./types";

export interface MinisterVerifierConfig {
  // Minister origin, e.g. "https://ministry.id".
  issuer: string;
  // REQUIRED (fail-closed audience): id_token `aud` is checked against it. A
  // verifier without a clientId would silently accept a token minted for
  // another RP, so this is mandatory — not merely recommended.
  clientId: string;
  // Inject the verification key. When omitted, each verifier fetches
  // Minister's remote JWKS on demand. Accepts a single public JWK too;
  // pass a public JWK in tests so verification stays offline.
  jwks?: KeyInput;
}

export interface MinisterVerifier {
  verifyIdToken(idToken: string, opts?: { nonce?: string }): Promise<MinisterClaims>;
  verifyBadges(tokenOrPayload: string | JWTPayload): Promise<BadgesResult>;
  verifyBadge(vcJwt: string): Promise<VerifiedBadge>;
}

// Configure-once, reuse: binds issuer/clientId/key so the three operations
// share one configuration. When `jwks` is injected, all three use that exact
// key. When omitted, each underlying verifier keeps its OWN per-issuer
// remote-JWKS cache (the id_token and badge verifiers cache independently -
// they do NOT share a JWKSet), so expect at most one fetch per verifier per
// issuer, not a single shared fetch.
export function createMinisterVerifier(config: MinisterVerifierConfig): MinisterVerifier {
  const { issuer, clientId, jwks } = config;
  return {
    verifyIdToken: (idToken, opts) =>
      verifyMinisterIdToken(idToken, { issuer, clientId, key: jwks, nonce: opts?.nonce }),
    verifyBadges: (tokenOrPayload) =>
      verifyMinisterBadges(tokenOrPayload, { issuer, clientId, key: jwks }),
    verifyBadge: (vcJwt) => verifyMinisterBadge(vcJwt, { issuer, key: jwks }),
  };
}
