import {
  badgeTypeOf,
  getBadgeClaimSchema
} from "./chunk-U2JFQKFV.js";

// src/did.ts
function buildDid(domain) {
  return `did:web:${domain}`;
}
function didFromIssuer(issuer) {
  const url = new URL(issuer);
  const host = url.port ? `${url.hostname}%3A${url.port}` : url.hostname;
  return buildDid(host);
}

// src/errors.ts
var VcVerificationError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "VcVerificationError";
  }
};
var OidcError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "OidcError";
  }
};
var MinisterTokenError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "MinisterTokenError";
  }
};

// src/verify-badge.ts
import { createRemoteJWKSet } from "jose";

// src/jwt.ts
import {
  jwtVerify
} from "jose";
function verifyJwt(jwt, key, options) {
  if (typeof key === "function") {
    return jwtVerify(jwt, key, options);
  }
  return jwtVerify(jwt, key, options);
}

// src/verify-badge.ts
var jwksCache = /* @__PURE__ */ new Map();
function remoteJwksFor(issuer) {
  let set = jwksCache.get(issuer);
  if (!set) {
    set = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
    jwksCache.set(issuer, set);
  }
  return set;
}
async function verifyMinisterBadge(vcJwt, options) {
  const issuer = options.issuer.replace(/\/$/, "");
  const expectedIss = didFromIssuer(issuer);
  const key = options.key ?? remoteJwksFor(issuer);
  let payload;
  try {
    const result = await verifyJwt(vcJwt, key, {
      issuer: expectedIss,
      algorithms: ["EdDSA"],
      typ: "vc+jwt",
      requiredClaims: ["exp"]
    });
    payload = result.payload;
  } catch (cause) {
    throw new VcVerificationError(
      cause instanceof Error ? cause.message : String(cause)
    );
  }
  if (typeof payload.sub !== "string" || payload.sub.length === 0) {
    throw new VcVerificationError("VC payload missing string `sub`");
  }
  const vc = payload.vc;
  if (!vc || typeof vc !== "object") {
    throw new VcVerificationError("VC payload missing `vc` envelope");
  }
  if (!Array.isArray(vc.type) || !vc.type.every((t) => typeof t === "string")) {
    throw new VcVerificationError("VC `type` must be a string array");
  }
  if (!vc.credentialSubject || typeof vc.credentialSubject !== "object" || Array.isArray(vc.credentialSubject)) {
    throw new VcVerificationError("VC missing `credentialSubject` object");
  }
  const credentialSubject = vc.credentialSubject;
  const subjectId = credentialSubject["id"];
  if (typeof subjectId !== "string" || subjectId.length === 0) {
    throw new VcVerificationError("VC `credentialSubject.id` missing");
  }
  if (subjectId !== payload.sub) {
    throw new VcVerificationError(
      "VC `credentialSubject.id` does not match `sub`"
    );
  }
  const slug = badgeTypeOf(vc.type);
  if (!slug) {
    throw new VcVerificationError(
      `Unknown Minister badge type: ${vc.type.join(",")}`
    );
  }
  const { id: _id, ...rawClaims } = credentialSubject;
  const schema = getBadgeClaimSchema(slug);
  let claims;
  try {
    claims = schema ? schema.parse(rawClaims) : rawClaims;
  } catch (cause) {
    throw new VcVerificationError(
      `Badge ${slug} claims failed validation: ${cause instanceof Error ? cause.message : String(cause)}`
    );
  }
  return { type: slug, claims, subject: payload.sub, raw: vcJwt };
}

// src/verify-id-token.ts
import { createRemoteJWKSet as createRemoteJWKSet2 } from "jose";
var jwksCache2 = /* @__PURE__ */ new Map();
function remoteJwksFor2(issuer) {
  let set = jwksCache2.get(issuer);
  if (!set) {
    set = createRemoteJWKSet2(new URL(`${issuer}/.well-known/jwks.json`));
    jwksCache2.set(issuer, set);
  }
  return set;
}
async function verifyIdTokenPayload(idToken, options) {
  const issuer = options.issuer.replace(/\/$/, "");
  const key = options.key ?? remoteJwksFor2(issuer);
  let payload;
  try {
    const result = await verifyJwt(idToken, key, {
      issuer,
      algorithms: ["EdDSA"],
      requiredClaims: ["exp", "iat"],
      clockTolerance: "30s",
      ...options.clientId ? { audience: options.clientId } : {}
    });
    payload = result.payload;
  } catch (cause) {
    throw new MinisterTokenError(cause instanceof Error ? cause.message : String(cause));
  }
  if (options.nonce !== void 0 && payload["nonce"] !== options.nonce) {
    throw new MinisterTokenError("id_token `nonce` mismatch");
  }
  if (typeof payload.sub !== "string" || payload.sub.length === 0) {
    throw new MinisterTokenError("id_token missing string `sub`");
  }
  return payload;
}
function claimsFromPayload(payload, raw) {
  return {
    sub: payload.sub,
    name: typeof payload["name"] === "string" ? payload["name"] : void 0,
    picture: typeof payload["picture"] === "string" ? payload["picture"] : void 0,
    raw
  };
}
async function verifyMinisterIdToken(idToken, options) {
  const payload = await verifyIdTokenPayload(idToken, options);
  return claimsFromPayload(payload, idToken);
}

// src/verify-badges.ts
async function verifyMinisterBadges(tokenOrPayload, options) {
  const payload = typeof tokenOrPayload === "string" ? await verifyIdTokenPayload(tokenOrPayload, options) : tokenOrPayload;
  const raw = payload["minister_badges"];
  if (raw === void 0 || raw === null) return { badges: [], rejected: [] };
  if (!Array.isArray(raw)) {
    return { badges: [], rejected: [{ raw: String(raw), error: new VcVerificationError("minister_badges is not an array") }] };
  }
  const result = { badges: [], rejected: [] };
  for (const entry of raw) {
    if (typeof entry !== "string") {
      result.rejected.push({ raw: String(entry), error: new VcVerificationError("badge entry is not a JWT string") });
      continue;
    }
    try {
      result.badges.push(await verifyMinisterBadge(entry, { issuer: options.issuer, key: options.key }));
    } catch (cause) {
      result.rejected.push({
        raw: entry,
        error: cause instanceof VcVerificationError ? cause : new VcVerificationError(String(cause))
      });
    }
  }
  return result;
}

export {
  buildDid,
  didFromIssuer,
  VcVerificationError,
  OidcError,
  MinisterTokenError,
  verifyMinisterBadge,
  verifyIdTokenPayload,
  claimsFromPayload,
  verifyMinisterIdToken,
  verifyMinisterBadges
};
//# sourceMappingURL=chunk-CSD6YO64.js.map