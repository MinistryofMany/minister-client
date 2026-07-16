import {
  badgeTypeOf,
  getBadgeClaimSchema
} from "./chunk-LS6OOLHT.js";

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

// src/status-list.ts
var MAX_STATUS_INDEX = 1 << 20;
function parseCredentialStatus(rawStatus, expectedIssuerOrigin) {
  if (rawStatus === void 0 || rawStatus === null) return void 0;
  if (typeof rawStatus !== "object" || Array.isArray(rawStatus)) {
    throw new VcVerificationError("VC `credentialStatus` is not an object");
  }
  const s = rawStatus;
  if (s.type !== "BitstringStatusListEntry") {
    throw new VcVerificationError(
      `VC credentialStatus.type must be BitstringStatusListEntry (got ${String(s.type)})`
    );
  }
  if (s.statusPurpose !== "revocation") {
    throw new VcVerificationError(
      `VC credentialStatus.statusPurpose must be "revocation" (got ${String(s.statusPurpose)})`
    );
  }
  const uri = s.statusListCredential;
  if (typeof uri !== "string" || uri.length === 0) {
    throw new VcVerificationError("VC credentialStatus.statusListCredential missing");
  }
  let listUrl;
  try {
    listUrl = new URL(uri);
  } catch {
    throw new VcVerificationError("VC credentialStatus.statusListCredential is not a URL");
  }
  const expected = new URL(expectedIssuerOrigin.replace(/\/$/, ""));
  if (listUrl.protocol !== "https:" && listUrl.hostname !== "localhost") {
    throw new VcVerificationError("VC credentialStatus list URL must be https");
  }
  if (listUrl.origin !== expected.origin) {
    throw new VcVerificationError(
      `VC credentialStatus list URL origin ${listUrl.origin} is not the configured issuer ${expected.origin}`
    );
  }
  const rawIndex = s.statusListIndex;
  const index = typeof rawIndex === "string" ? Number(rawIndex) : rawIndex;
  if (typeof index !== "number" || !Number.isInteger(index) || index < 0 || index >= MAX_STATUS_INDEX) {
    throw new VcVerificationError(
      `VC credentialStatus.statusListIndex out of range: ${String(rawIndex)}`
    );
  }
  return { uri, index };
}
function bitIsSet(bytes, index) {
  const byte = bytes[index >> 3] ?? 0;
  return (byte & 128 >> (index & 7)) !== 0;
}
function base64urlToBytes(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - b64.length % 4) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function gunzip(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}
async function decodeEncodedList(encodedList) {
  if (typeof encodedList !== "string" || encodedList.length < 1 || encodedList[0] !== "u") {
    throw new VcVerificationError("status list encodedList is not multibase base64url ('u')");
  }
  return gunzip(base64urlToBytes(encodedList.slice(1)));
}
var DEFAULT_CLOCK_TOLERANCE_SEC = 30;
async function verifyStatusListCredential(jwt, opts) {
  const expectedIss = didFromIssuer(opts.issuer);
  const fetchedUrl = opts.fetchedUrl.replace(/\/$/, "");
  let payload;
  try {
    const result = await verifyJwt(jwt, opts.key, {
      issuer: expectedIss,
      algorithms: ["EdDSA"],
      typ: "vc+jwt",
      requiredClaims: ["exp", "sub"],
      clockTolerance: opts.clockToleranceSec ?? DEFAULT_CLOCK_TOLERANCE_SEC,
      // Enforce max-age against the signed exp ourselves below too, but jose
      // already rejects an expired token here (defense 2). Thread the injected
      // clock into jose's exp/nbf evaluation so a clock-injected test (and the
      // checker's own `nowFn`) governs the signed-freshness check for real — not
      // just our post-hoc `expiresAtMs` comparison. Absent => jose uses wall time.
      ...opts.nowMs !== void 0 ? { currentDate: new Date(opts.nowMs) } : {}
    });
    payload = result.payload;
  } catch (cause) {
    throw new VcVerificationError(
      `status list verification failed: ${cause instanceof Error ? cause.message : String(cause)}`
    );
  }
  if (typeof payload.sub !== "string" || payload.sub.replace(/\/$/, "") !== fetchedUrl) {
    throw new VcVerificationError(
      `status list sub (${String(payload.sub)}) does not match fetched URL ${fetchedUrl}`
    );
  }
  const version = payload.statusListVersion;
  if (typeof version !== "number" || !Number.isInteger(version)) {
    throw new VcVerificationError("status list has no integer statusListVersion");
  }
  const vc = payload.vc;
  if (!vc || typeof vc !== "object") {
    throw new VcVerificationError("status list payload missing `vc` envelope");
  }
  if (!Array.isArray(vc.type) || !vc.type.includes("BitstringStatusListCredential")) {
    throw new VcVerificationError("status list vc.type must include BitstringStatusListCredential");
  }
  const cs = vc.credentialSubject;
  if (!cs || typeof cs !== "object") {
    throw new VcVerificationError("status list missing credentialSubject");
  }
  if (cs.statusPurpose !== "revocation") {
    throw new VcVerificationError("status list statusPurpose must be revocation");
  }
  if (typeof cs.encodedList !== "string") {
    throw new VcVerificationError("status list missing encodedList");
  }
  const bits = await decodeEncodedList(cs.encodedList);
  const expiresAtMs = typeof payload.exp === "number" ? payload.exp * 1e3 : 0;
  return { bits, version, expiresAtMs };
}

// src/did-assertion.ts
import { importJWK as importJWK2 } from "jose";
var didResolverCache = /* @__PURE__ */ new Map();
function assertionResolverFor(issuer) {
  let resolver = didResolverCache.get(issuer);
  if (!resolver) {
    resolver = createDidAssertionResolver(issuer);
    didResolverCache.set(issuer, resolver);
  }
  return resolver;
}
async function loadAssertionKeys(issuer) {
  const url = `${issuer}/.well-known/did.json`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`DID document fetch failed (${res.status}) for ${url}`);
  }
  const doc = await res.json();
  const vms = Array.isArray(doc.verificationMethod) ? doc.verificationMethod : [];
  const byId = /* @__PURE__ */ new Map();
  for (const vm of vms) {
    if (vm && typeof vm === "object" && typeof vm.id === "string") {
      byId.set(vm.id, vm);
    }
  }
  const assertion = Array.isArray(doc.assertionMethod) ? doc.assertionMethod : [];
  if (assertion.length === 0) {
    throw new Error("DID document has no `assertionMethod` entries");
  }
  const map = /* @__PURE__ */ new Map();
  for (const entry of assertion) {
    let vm;
    if (typeof entry === "string") {
      vm = byId.get(entry);
    } else if (entry && typeof entry === "object") {
      vm = entry;
    }
    const kid = vm && typeof vm.id === "string" ? vm.id : void 0;
    const jwk = vm?.publicKeyJwk;
    if (!kid || !jwk || typeof jwk !== "object") {
      throw new Error(
        `assertionMethod entry has no resolvable publicKeyJwk: ${String(
          typeof entry === "string" ? entry : vm?.id ?? "<embedded>"
        )}`
      );
    }
    map.set(kid, await importJWK2(jwk, "EdDSA"));
  }
  return map;
}
function createDidAssertionResolver(issuer) {
  let keysPromise;
  const load = () => {
    if (!keysPromise) {
      keysPromise = loadAssertionKeys(issuer).catch((err) => {
        keysPromise = void 0;
        throw err;
      });
    }
    return keysPromise;
  };
  return async (protectedHeader) => {
    const keys = await load();
    const kid = protectedHeader.kid;
    if (typeof kid !== "string" || kid.length === 0) {
      throw new Error("JWT has no `kid`; cannot pin to DID assertionMethod");
    }
    const key = keys.get(kid);
    if (!key) {
      throw new Error(`kid (${kid}) is not in the issuer DID document assertionMethod`);
    }
    return key;
  };
}

// src/verify-badge.ts
var NULLIFIER_RE = /^mnv1:[A-Za-z0-9_-]{20,64}$/;
async function verifyMinisterBadge(vcJwt, options) {
  const issuer = options.issuer.replace(/\/$/, "");
  const expectedIss = didFromIssuer(issuer);
  const key = options.key ?? assertionResolverFor(issuer);
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
    nullifier: rawNullifier,
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
  let nullifier;
  if (rawNullifier !== void 0) {
    if (typeof rawNullifier !== "string" || !NULLIFIER_RE.test(rawNullifier)) {
      throw new VcVerificationError(
        "VC `credentialSubject.nullifier` is not a well-formed mnv1 nullifier"
      );
    }
    nullifier = rawNullifier;
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
  let status;
  try {
    status = parseCredentialStatus(vc.credentialStatus, issuer);
  } catch (cause) {
    throw new VcVerificationError(
      cause instanceof Error ? cause.message : String(cause)
    );
  }
  return {
    type: slug,
    claims,
    subject: payload.sub,
    ...issuanceMonth !== void 0 ? { issuanceMonth } : {},
    ...nullifier !== void 0 ? { nullifier } : {},
    ...status !== void 0 ? { status } : {},
    raw: vcJwt
  };
}

// src/verify-id-token.ts
import { createRemoteJWKSet } from "jose";
var jwksCache = /* @__PURE__ */ new Map();
function remoteJwksFor(issuer) {
  let set = jwksCache.get(issuer);
  if (!set) {
    set = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
    jwksCache.set(issuer, set);
  }
  return set;
}
async function verifyIdTokenPayload(idToken, options) {
  const issuer = options.issuer.replace(/\/$/, "");
  if (!options.clientId) {
    throw new MinisterTokenError("clientId (expected audience) is required to verify an id_token");
  }
  const key = options.key ?? remoteJwksFor(issuer);
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
  const rawBucket = payload["sybil_bucket"];
  const sybil_bucket = typeof rawBucket === "number" && Number.isInteger(rawBucket) && rawBucket >= 0 && rawBucket <= 4 ? rawBucket : void 0;
  const rawEpoch = payload["minister_anon_epoch"];
  const minister_anon_epoch = typeof rawEpoch === "number" && Number.isInteger(rawEpoch) && rawEpoch >= 1 ? rawEpoch : void 0;
  return {
    sub: payload.sub,
    name: typeof payload["name"] === "string" ? payload["name"] : void 0,
    picture: typeof payload["picture"] === "string" ? payload["picture"] : void 0,
    sybil_bucket,
    minister_anon_epoch,
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
  assertionResolverFor,
  VcVerificationError,
  OidcError,
  MinisterTokenError,
  parseCredentialStatus,
  bitIsSet,
  verifyStatusListCredential,
  verifyMinisterBadge,
  verifyIdTokenPayload,
  claimsFromPayload,
  verifyMinisterIdToken,
  verifyMinisterBadges
};
//# sourceMappingURL=chunk-7FPUBS2O.js.map