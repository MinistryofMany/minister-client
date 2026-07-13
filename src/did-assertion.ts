import { importJWK, type JWK, type JWTVerifyGetKey, type KeyLike } from "jose";

// Resolve Minister badge/status-list verification keys from the issuer's DID
// document `assertionMethod` — NOT the raw JWKS. Minister's JWKS serves BOTH the
// badge key (#key-2) AND the in-process token key (#key-3); selecting by `kid`
// against the full JWKS would accept a VC carrying `kid ...#key-3` (forged with a
// stolen token key), defeating the KMS split (docs/kms-signing.md). The DID
// document's `assertionMethod` lists ONLY #key-2, so both badge VCs AND status
// lists (also #key-2-signed) pin here and reject any kid not listed.

interface DidVerificationMethod {
  id?: unknown;
  publicKeyJwk?: unknown;
}
interface DidDocumentShape {
  verificationMethod?: unknown;
  assertionMethod?: unknown;
}

// One resolver per issuer, cached for the process lifetime. Cache key is the
// trusted RP-config issuer (not request input), so this stays bounded. Each
// resolver memoizes its fetched key map and clears it on failure so a transient
// did.json outage self-heals on the next call.
const didResolverCache = new Map<string, JWTVerifyGetKey>();

export function assertionResolverFor(issuer: string): JWTVerifyGetKey {
  let resolver = didResolverCache.get(issuer);
  if (!resolver) {
    resolver = createDidAssertionResolver(issuer);
    didResolverCache.set(issuer, resolver);
  }
  return resolver;
}

async function loadAssertionKeys(issuer: string): Promise<Map<string, KeyLike | Uint8Array>> {
  const url = `${issuer}/.well-known/did.json`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`DID document fetch failed (${res.status}) for ${url}`);
  }
  const doc = (await res.json()) as DidDocumentShape;

  const vms = Array.isArray(doc.verificationMethod) ? doc.verificationMethod : [];
  const byId = new Map<string, DidVerificationMethod>();
  for (const vm of vms) {
    if (vm && typeof vm === "object" && typeof (vm as DidVerificationMethod).id === "string") {
      byId.set((vm as DidVerificationMethod).id as string, vm as DidVerificationMethod);
    }
  }

  const assertion = Array.isArray(doc.assertionMethod) ? doc.assertionMethod : [];
  if (assertion.length === 0) {
    throw new Error("DID document has no `assertionMethod` entries");
  }

  const map = new Map<string, KeyLike | Uint8Array>();
  for (const entry of assertion) {
    // Per W3C, an assertionMethod entry is either a string reference to a
    // verificationMethod `id` or an embedded verification method object.
    let vm: DidVerificationMethod | undefined;
    if (typeof entry === "string") {
      vm = byId.get(entry);
    } else if (entry && typeof entry === "object") {
      vm = entry as DidVerificationMethod;
    }
    const kid = vm && typeof vm.id === "string" ? vm.id : undefined;
    const jwk = vm?.publicKeyJwk;
    if (!kid || !jwk || typeof jwk !== "object") {
      throw new Error(
        `assertionMethod entry has no resolvable publicKeyJwk: ${String(
          typeof entry === "string" ? entry : (vm?.id ?? "<embedded>"),
        )}`,
      );
    }
    map.set(kid, await importJWK(jwk as JWK, "EdDSA"));
  }
  return map;
}

function createDidAssertionResolver(issuer: string): JWTVerifyGetKey {
  let keysPromise: Promise<Map<string, KeyLike | Uint8Array>> | undefined;
  const load = () => {
    if (!keysPromise) {
      // Don't cache a REJECTED fetch: a transient did.json outage would otherwise
      // wedge verification for the process lifetime.
      keysPromise = loadAssertionKeys(issuer).catch((err) => {
        keysPromise = undefined;
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

// Test seam: drop the cached DID assertionMethod key resolver for an issuer (or
// all issuers).
export function _resetAssertionCache(issuer?: string): void {
  if (issuer) didResolverCache.delete(issuer.replace(/\/$/, ""));
  else didResolverCache.clear();
}
