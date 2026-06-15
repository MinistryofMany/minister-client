import { createRemoteJWKSet } from "jose";

import { OidcError } from "./errors";
import { verifyIdTokenPayload } from "./verify-id-token";
import { verifyMinisterBadges } from "./verify-badges";
import type {
  ExchangeResult,
  KeyInput,
  MinisterClaims,
  MinisterClientConfig,
} from "./types";

// The fields of the OIDC discovery document this SDK relies on.
interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

// Cache the discovery doc + id_token JWKS per issuer for the process
// lifetime. The JWKS set fetches lazily and rotates keys on its own.
const discoveryCache = new Map<string, Promise<Discovery>>();
const idTokenJwksCache = new Map<
  string,
  ReturnType<typeof createRemoteJWKSet>
>();

async function discover(issuer: string): Promise<Discovery> {
  const cached = discoveryCache.get(issuer);
  if (cached) return cached;
  const p = fetch(`${issuer}/.well-known/openid-configuration`)
      .then(async (res) => {
        if (!res.ok) {
          throw new OidcError(`OIDC discovery failed: HTTP ${res.status}`);
        }
        return (await res.json()) as Discovery;
      })
      .catch((cause) => {
        // Don't poison the cache with a rejected promise.
        discoveryCache.delete(issuer);
        throw cause instanceof OidcError
          ? cause
          : new OidcError(
              `OIDC discovery failed: ${cause instanceof Error ? cause.message : String(cause)}`,
            );
      });
  discoveryCache.set(issuer, p);
  return p;
}

function idTokenJwks(
  issuer: string,
  jwksUri: string,
): ReturnType<typeof createRemoteJWKSet> {
  let set = idTokenJwksCache.get(issuer);
  if (!set) {
    set = createRemoteJWKSet(new URL(jwksUri));
    idTokenJwksCache.set(issuer, set);
  }
  return set;
}

export interface GetAuthorizationUrlArgs {
  // Requested scopes, e.g. ["openid", "profile", "badge:age-over-21"].
  // `openid` is required by OIDC; this SDK does not inject it for you.
  scopes: string[];
  state: string;
  nonce: string;
  // PKCE S256 code challenge (from `generatePkce().challenge`).
  codeChallenge: string;
}

export interface ExchangeCodeArgs {
  // The `code` query param from the callback.
  code: string;
  // The PKCE verifier persisted from flow start.
  codeVerifier: string;
  // The `nonce` persisted from flow start; the verified id_token's
  // `nonce` must equal this.
  expectedNonce: string;
  // Inject the id_token verification key source (defaults to the remote
  // JWKS at the discovery `jwks_uri`). Tests pass a public key so
  // verification never touches the network.
  idTokenKey?: KeyInput;
  // Inject the badge verification key source (defaults to the remote
  // JWKS at `${issuer}/.well-known/jwks.json`).
  badgeKey?: KeyInput;
}

// Internal: the OIDC operations bound to a normalized config.
export class OidcCore {
  private readonly issuer: string;
  private readonly clientId: string;
  private readonly clientSecret?: string;
  private readonly redirectUri: string;

  constructor(config: MinisterClientConfig) {
    if (!config.issuer) throw new OidcError("issuer is required");
    if (!config.clientId) throw new OidcError("clientId is required");
    if (!config.redirectUri) throw new OidcError("redirectUri is required");
    this.issuer = config.issuer.replace(/\/$/, "");
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.redirectUri = config.redirectUri;
  }

  // Discover the authorization endpoint and build the redirect URL with
  // caller-supplied scopes and PKCE S256.
  async getAuthorizationUrl(args: GetAuthorizationUrlArgs): Promise<string> {
    if (args.scopes.length === 0) {
      throw new OidcError("at least one scope is required");
    }
    const d = await discover(this.issuer);
    const u = new URL(d.authorization_endpoint);
    u.searchParams.set("response_type", "code");
    u.searchParams.set("client_id", this.clientId);
    u.searchParams.set("redirect_uri", this.redirectUri);
    u.searchParams.set("scope", args.scopes.join(" "));
    u.searchParams.set("state", args.state);
    u.searchParams.set("nonce", args.nonce);
    u.searchParams.set("code_challenge", args.codeChallenge);
    u.searchParams.set("code_challenge_method", "S256");
    return u.toString();
  }

  // Exchange the authorization code for tokens, verify the id_token
  // (signature via JWKS, iss/aud/nonce), then extract and verify each
  // disclosed badge. Throws on any failure — the caller maps that to a
  // 401.
  async exchangeCode(args: ExchangeCodeArgs): Promise<ExchangeResult> {
    const d = await discover(this.issuer);

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: args.code,
      redirect_uri: this.redirectUri,
      client_id: this.clientId,
      code_verifier: args.codeVerifier,
    });
    if (this.clientSecret) body.set("client_secret", this.clientSecret);

    const res = await fetch(d.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw new OidcError(`token exchange failed: HTTP ${res.status} ${detail}`);
    }
    const tokens = (await res.json()) as { id_token?: unknown };
    if (typeof tokens.id_token !== "string") {
      throw new OidcError("token response missing id_token");
    }

    const idKey = args.idTokenKey ?? idTokenJwks(this.issuer, d.jwks_uri);
    const payload = await verifyIdTokenPayload(tokens.id_token, {
      issuer: d.issuer,
      clientId: this.clientId,
      nonce: args.expectedNonce,
      key: idKey,
    });
    const claims: MinisterClaims = {
      sub: payload.sub as string,
      name: typeof payload["name"] === "string" ? (payload["name"] as string) : undefined,
      picture: typeof payload["picture"] === "string" ? (payload["picture"] as string) : undefined,
      raw: tokens.id_token,
    };
    const { badges } = await verifyMinisterBadges(payload, {
      issuer: this.issuer,
      key: args.badgeKey,
    });
    return { claims, badges };
  }
}

// Test seam: clear the discovery + id_token JWKS caches.
export function _resetOidcCaches(issuer?: string): void {
  if (issuer) {
    const normalized = issuer.replace(/\/$/, "");
    discoveryCache.delete(normalized);
    idTokenJwksCache.delete(normalized);
  } else {
    discoveryCache.clear();
    idTokenJwksCache.clear();
  }
}
