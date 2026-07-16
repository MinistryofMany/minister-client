import {
  MinisterTokenError,
  OidcError,
  VcVerificationError,
  assertionResolverFor,
  bitIsSet,
  buildDid,
  buildPairwiseSubjectDid,
  claimsFromPayload,
  didFromIssuer,
  parseCredentialStatus,
  verifyIdTokenPayload,
  verifyMinisterBadge,
  verifyMinisterBadges,
  verifyMinisterIdToken,
  verifyStatusListCredential
} from "./chunk-7FPUBS2O.js";
import "./chunk-R4XGCZVA.js";
import {
  ACCOUNT_AGE_MONTHS,
  AGE_THRESHOLDS,
  AccountAgeClaims,
  AgeOverClaimsFor,
  BADGE_TYPES,
  EmailDomainClaims,
  EmailExactClaims,
  FOLLOWERS_BUCKETS,
  GROUP_ROLES,
  GroupMembershipClaims,
  InviteCodeClaims,
  OAUTH_PROVIDERS,
  OAuthAccountClaims,
  ResidencyCityClaims,
  ResidencyCountryClaims,
  ResidencyStateClaims,
  SocialFollowingClaims,
  TlsnAttestationClaims,
  badgeScope,
  badgeScopes,
  badgeTypeOf,
  getBadgeClaimSchema,
  knownBadgeTypes,
  slugForCredentialType
} from "./chunk-LS6OOLHT.js";

// src/oidc.ts
import { createRemoteJWKSet } from "jose";
var discoveryCache = /* @__PURE__ */ new Map();
var idTokenJwksCache = /* @__PURE__ */ new Map();
async function discover(issuer) {
  const cached = discoveryCache.get(issuer);
  if (cached) return cached;
  const p = fetch(`${issuer}/.well-known/openid-configuration`).then(async (res) => {
    if (!res.ok) {
      throw new OidcError(`OIDC discovery failed: HTTP ${res.status}`);
    }
    const doc = await res.json();
    if (doc.issuer?.replace(/\/$/, "") !== issuer.replace(/\/$/, "")) {
      throw new OidcError(
        `OIDC discovery issuer mismatch: configured ${issuer}, document ${doc.issuer}`
      );
    }
    return doc;
  }).catch((cause) => {
    discoveryCache.delete(issuer);
    throw cause instanceof OidcError ? cause : new OidcError(
      `OIDC discovery failed: ${cause instanceof Error ? cause.message : String(cause)}`
    );
  });
  discoveryCache.set(issuer, p);
  return p;
}
function idTokenJwks(issuer, jwksUri) {
  let set = idTokenJwksCache.get(issuer);
  if (!set) {
    set = createRemoteJWKSet(new URL(jwksUri));
    idTokenJwksCache.set(issuer, set);
  }
  return set;
}
var OidcCore = class {
  issuer;
  clientId;
  clientSecret;
  redirectUri;
  constructor(config) {
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
  async getAuthorizationUrl(args) {
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
    for (const [key, value] of Object.entries(args.extraParams ?? {})) {
      if (u.searchParams.has(key)) continue;
      u.searchParams.set(key, value);
    }
    return u.toString();
  }
  // Exchange the authorization code for tokens, verify the id_token
  // (signature via JWKS, iss/aud/nonce), then extract and verify each
  // disclosed badge. Throws on any failure — the caller maps that to a
  // 401.
  async exchangeCode(args) {
    const d = await discover(this.issuer);
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: args.code,
      redirect_uri: this.redirectUri,
      client_id: this.clientId,
      code_verifier: args.codeVerifier
    });
    if (this.clientSecret) body.set("client_secret", this.clientSecret);
    const res = await fetch(d.token_endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw new OidcError(`token exchange failed: HTTP ${res.status} ${detail}`);
    }
    const tokens = await res.json();
    if (typeof tokens.id_token !== "string") {
      throw new OidcError("token response missing id_token");
    }
    const idKey = args.idTokenKey ?? idTokenJwks(this.issuer, d.jwks_uri);
    const payload = await verifyIdTokenPayload(tokens.id_token, {
      issuer: d.issuer,
      clientId: this.clientId,
      nonce: args.expectedNonce,
      key: idKey
    });
    const claims = claimsFromPayload(payload, tokens.id_token);
    const { badges, rejected } = await verifyMinisterBadges(payload, {
      issuer: this.issuer,
      key: args.badgeKey
    });
    return { claims, badges, rejected };
  }
};

// src/client.ts
function createMinisterClient(config) {
  const core = new OidcCore(config);
  const issuer = config.issuer.replace(/\/$/, "");
  return {
    getAuthorizationUrl: (args) => core.getAuthorizationUrl(args),
    exchangeCode: (args) => core.exchangeCode(args),
    verifyMinisterBadge: (vcJwt, options) => verifyMinisterBadge(vcJwt, { issuer, key: options?.key })
  };
}

// src/pkce.ts
function b64url(bytes) {
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}
function randomBytes(length) {
  const buf = new Uint8Array(length);
  crypto.getRandomValues(buf);
  return buf;
}
async function sha256(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}
async function generatePkce() {
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(await sha256(verifier));
  return { verifier, challenge };
}
function randomUrlToken(bytes = 16) {
  return b64url(randomBytes(bytes));
}

// src/verifier.ts
function createMinisterVerifier(config) {
  const { issuer, clientId, jwks } = config;
  return {
    verifyIdToken: (idToken, opts) => verifyMinisterIdToken(idToken, { issuer, clientId, key: jwks, nonce: opts?.nonce }),
    verifyBadges: (tokenOrPayload) => verifyMinisterBadges(tokenOrPayload, { issuer, clientId, key: jwks }),
    verifyBadge: (vcJwt) => verifyMinisterBadge(vcJwt, { issuer, key: jwks })
  };
}

// src/status-checker.ts
var DEFAULT_POLL_INTERVAL_MS = 6e4;
var DEFAULT_LIST_VALIDITY_WINDOW_MS = 15 * 6e4;
var DEFAULT_MAX_STALE_MS = 4 * DEFAULT_LIST_VALIDITY_WINDOW_MS;
function latchKey(ref) {
  return `${ref.uri.replace(/\/$/, "")}#${ref.index}`;
}
function createMinisterStatusChecker(config) {
  const issuer = config.issuer.replace(/\/$/, "");
  const pollIntervalMs = config.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const maxStaleMs = config.maxStaleMs ?? DEFAULT_MAX_STALE_MS;
  const staleFailMode = config.staleFailMode ?? "open";
  const key = config.key ?? assertionResolverFor(issuer);
  const fetchImpl = config.fetchImpl ?? fetch;
  const now = config.nowFn ?? Date.now;
  const cache = /* @__PURE__ */ new Map();
  const inflight = /* @__PURE__ */ new Map();
  const memHighWater = /* @__PURE__ */ new Map();
  const latch = /* @__PURE__ */ new Set();
  const verifyFailures = /* @__PURE__ */ new Map();
  const lastVerifyFailed = /* @__PURE__ */ new Map();
  async function getHighWater(uri) {
    if (config.persistHighWater) {
      const v = await config.persistHighWater.get(uri);
      if (typeof v === "number") return v;
    }
    return memHighWater.get(uri) ?? -1;
  }
  async function setHighWater(uri, version) {
    memHighWater.set(uri, version);
    if (config.persistHighWater) await config.persistHighWater.set(uri, version);
  }
  function clearVerifyFailure(uri) {
    verifyFailures.delete(uri);
    lastVerifyFailed.delete(uri);
  }
  async function refetch(uri) {
    const existing = cache.get(uri);
    let res;
    try {
      const headers = {};
      if (existing?.etag) headers["If-None-Match"] = existing.etag;
      res = await fetchImpl(uri, { headers });
    } catch {
      return;
    }
    if (res.status === 304 && existing) {
      cache.set(uri, { ...existing, fetchedAtMs: now() });
      clearVerifyFailure(uri);
      return;
    }
    if (res.status !== 200) {
      return;
    }
    let snapshot;
    try {
      const jwt = (await res.text()).trim();
      snapshot = await verifyStatusListCredential(jwt, {
        fetchedUrl: uri,
        issuer,
        key,
        nowMs: now()
      });
    } catch (verr) {
      const count = (verifyFailures.get(uri) ?? 0) + 1;
      verifyFailures.set(uri, count);
      lastVerifyFailed.set(uri, true);
      config.onVerifyError?.({
        uri,
        error: verr instanceof Error ? verr : new Error(String(verr)),
        consecutiveFailures: count
      });
      return;
    }
    const hw = await getHighWater(uri);
    if (snapshot.version < hw) {
      clearVerifyFailure(uri);
      return;
    }
    await setHighWater(uri, snapshot.version);
    const etag = res.headers.get("etag") ?? void 0;
    cache.set(uri, { snapshot, fetchedAtMs: now(), etag });
    clearVerifyFailure(uri);
  }
  async function ensureSnapshot(uri) {
    const cached = cache.get(uri);
    const due = !cached || now() - cached.fetchedAtMs >= pollIntervalMs || now() >= cached.snapshot.expiresAtMs;
    if (due) {
      let pending = inflight.get(uri);
      if (!pending) {
        pending = refetch(uri).finally(() => inflight.delete(uri));
        inflight.set(uri, pending);
      }
      await pending;
    }
    return cache.get(uri);
  }
  async function check(ref) {
    const lk = latchKey(ref);
    if (latch.has(lk)) return "revoked";
    const entry = await ensureSnapshot(ref.uri);
    if (!entry) {
      return "stale";
    }
    const bitLength = entry.snapshot.bits.length * 8;
    if (ref.index < 0 || ref.index >= bitLength) {
      config.onVerifyError?.({
        uri: ref.uri,
        error: new Error(
          `status index ${ref.index} is out of range for a ${bitLength}-bit list`
        ),
        consecutiveFailures: verifyFailures.get(ref.uri) ?? 0
      });
      return "revoked";
    }
    const revoked = bitIsSet(entry.snapshot.bits, ref.index);
    if (revoked) {
      latch.add(lk);
      return "revoked";
    }
    const fresh = now() < entry.snapshot.expiresAtMs;
    if (fresh) return "valid";
    if (staleFailMode === "closed") return "stale";
    if (lastVerifyFailed.get(ref.uri)) return "stale";
    const stalenessMs = now() - entry.snapshot.expiresAtMs;
    return stalenessMs <= maxStaleMs ? "valid" : "stale";
  }
  return {
    check,
    isLatched: (ref) => latch.has(latchKey(ref))
  };
}
export {
  ACCOUNT_AGE_MONTHS,
  AGE_THRESHOLDS,
  AccountAgeClaims,
  AgeOverClaimsFor,
  BADGE_TYPES,
  EmailDomainClaims,
  EmailExactClaims,
  FOLLOWERS_BUCKETS,
  GROUP_ROLES,
  GroupMembershipClaims,
  InviteCodeClaims,
  MinisterTokenError,
  OAUTH_PROVIDERS,
  OAuthAccountClaims,
  OidcError,
  ResidencyCityClaims,
  ResidencyCountryClaims,
  ResidencyStateClaims,
  SocialFollowingClaims,
  TlsnAttestationClaims,
  VcVerificationError,
  badgeScope,
  badgeScopes,
  badgeTypeOf,
  buildDid,
  buildPairwiseSubjectDid,
  createMinisterClient,
  createMinisterStatusChecker,
  createMinisterVerifier,
  didFromIssuer,
  generatePkce,
  getBadgeClaimSchema,
  knownBadgeTypes,
  parseCredentialStatus,
  randomUrlToken,
  slugForCredentialType,
  verifyMinisterBadge,
  verifyMinisterBadges,
  verifyMinisterIdToken,
  verifyStatusListCredential
};
//# sourceMappingURL=index.js.map