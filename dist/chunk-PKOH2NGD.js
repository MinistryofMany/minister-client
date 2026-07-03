import {
  badgeTypeOf,
  getBadgeClaimSchema
} from "./chunk-4E5KJT4H.js";

// src/did.ts
function buildDid(domain) {
  return `did:web:${domain}`;
}
function didFromIssuer(issuer) {
  const url = new URL(issuer);
  if (url.pathname !== "" && url.pathname !== "/") {
    throw new Error(
      `Minister issuer must be an origin with no path (got path "${url.pathname}" in "${issuer}")`
    );
  }
  if (url.search !== "" || url.hash !== "") {
    throw new Error(`Minister issuer must be an origin with no query or fragment: "${issuer}"`);
  }
  const host = url.port ? `${url.hostname}%3A${url.port}` : url.hostname;
  return buildDid(host);
}
function buildPairwiseSubjectDid(issuer, sub) {
  return `${didFromIssuer(issuer)}:u:${sub}`;
}
function parsePairwiseSubjectDid(subject) {
  const marker = ":u:";
  const idx = subject.lastIndexOf(marker);
  if (idx <= 0) return null;
  const issuerDid = subject.slice(0, idx);
  const sub = subject.slice(idx + marker.length);
  if (!issuerDid.startsWith("did:web:") || sub.length === 0 || sub.includes(":")) return null;
  return { issuerDid, sub };
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
  importJWK,
  jwtVerify
} from "jose";
function isJwk(key) {
  return typeof key === "object" && key !== null && !(key instanceof Uint8Array) && typeof key.kty === "string";
}
async function verifyJwt(jwt, key, options) {
  if (typeof key === "function") {
    return jwtVerify(jwt, key, options);
  }
  const resolved = isJwk(key) ? await importJWK(key, "EdDSA") : key;
  return jwtVerify(jwt, resolved, options);
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
  const {
    id: _id,
    issuanceMonth: rawIssuanceMonth,
    ...rawClaims
  } = credentialSubject;
  let issuanceMonth;
  if (rawIssuanceMonth !== void 0) {
    if (typeof rawIssuanceMonth !== "string" || !/^\d{4}-(0[1-9]|1[0-2])$/.test(rawIssuanceMonth)) {
      throw new VcVerificationError(
        "VC `credentialSubject.issuanceMonth` is not a YYYY-MM UTC month"
      );
    }
    issuanceMonth = rawIssuanceMonth;
  }
  const schema = getBadgeClaimSchema(slug);
  let claims;
  try {
    claims = schema ? schema.parse(rawClaims) : rawClaims;
  } catch (cause) {
    throw new VcVerificationError(
      `Badge ${slug} claims failed validation: ${cause instanceof Error ? cause.message : String(cause)}`
    );
  }
  return {
    type: slug,
    claims,
    subject: payload.sub,
    ...issuanceMonth !== void 0 ? { issuanceMonth } : {},
    raw: vcJwt
  };
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
  if (!options.clientId) {
    throw new MinisterTokenError("clientId (expected audience) is required to verify an id_token");
  }
  const key = options.key ?? remoteJwksFor2(issuer);
  let payload;
  try {
    const result = await verifyJwt(idToken, key, {
      issuer,
      algorithms: ["EdDSA"],
      requiredClaims: ["exp", "iat"],
      clockTolerance: "30s",
      audience: options.clientId
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
  let payload;
  if (typeof tokenOrPayload === "string") {
    if (!options.clientId) {
      throw new MinisterTokenError("clientId is required to verify a raw id_token string");
    }
    payload = await verifyIdTokenPayload(tokenOrPayload, {
      issuer: options.issuer,
      clientId: options.clientId,
      key: options.key
    });
  } else {
    payload = tokenOrPayload;
  }
  const raw = payload["minister_badges"];
  if (raw === void 0 || raw === null) return { badges: [], rejected: [] };
  if (!Array.isArray(raw)) {
    return { badges: [], rejected: [{ raw: String(raw), error: new VcVerificationError("minister_badges is not an array") }] };
  }
  const idTokenSub = payload["sub"];
  const canBind = typeof idTokenSub === "string" && idTokenSub.length > 0;
  const expectedSubject = canBind ? buildPairwiseSubjectDid(options.issuer, idTokenSub) : void 0;
  const result = { badges: [], rejected: [] };
  for (const entry of raw) {
    if (typeof entry !== "string") {
      result.rejected.push({ raw: String(entry), error: new VcVerificationError("badge entry is not a JWT string") });
      continue;
    }
    try {
      const badge = await verifyMinisterBadge(entry, { issuer: options.issuer, key: options.key });
      if (!expectedSubject) {
        throw new VcVerificationError(
          "cannot bind badge: id_token has no usable `sub`"
        );
      }
      if (badge.subject !== expectedSubject) {
        throw new VcVerificationError(
          "badge subject is not bound to the id_token sub (borrowed or mismatched credential)"
        );
      }
      result.badges.push(badge);
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
  buildPairwiseSubjectDid,
  parsePairwiseSubjectDid,
  VcVerificationError,
  OidcError,
  MinisterTokenError,
  verifyMinisterBadge,
  verifyIdTokenPayload,
  claimsFromPayload,
  verifyMinisterIdToken,
  verifyMinisterBadges
};
//# sourceMappingURL=chunk-PKOH2NGD.js.map