import { importJWK, type JWK, type JWTVerifyGetKey, type KeyLike } from "jose";

import { badgeTypeOf, getBadgeClaimSchema } from "./badges/helpers";
import { didFromIssuer } from "./did";
import { verifyJwt } from "./jwt";
import { VcVerificationError } from "./errors";
import type { KeyInput, VerifiedBadge } from "./types";

// Verify a Minister-issued verifiable credential against Minister's PUBLIC badge
// key. Unlike `@ministryofmany/vc`'s `verifyVc` (which threads a full Issuer
// carrying the private key), an RP only ever holds public material.
//
// Badge keys are pinned to the issuer's DID document `assertionMethod` — NOT the
// raw JWKS. Minister's JWKS at /.well-known/jwks.json serves BOTH the badge
// signing key (#key-2) AND the in-process token key (#key-3); jose selects a key
// by the JWT `kid`, so verifying a badge against the full JWKS would accept a VC
// carrying `kid ...#key-3` — i.e. one forged with a stolen token key — defeating
// the KMS split. The DID document's `assertionMethod` lists ONLY #key-2, so we
// resolve badge keys from it and REJECT any `kid` not listed there. That keeps
// the token key from ever attesting a badge.

// did:web DID document, restricted to the fields we consume.
interface DidVerificationMethod {
  id?: unknown;
  publicKeyJwk?: unknown;
}
interface DidDocumentShape {
  verificationMethod?: unknown;
  assertionMethod?: unknown;
}

// Cache one assertionMethod key resolver per issuer for the process lifetime.
// Cache key is the trusted RP-config issuer (not request input), so this stays
// bounded. Each resolver memoizes the fetched-and-imported key map internally and
// clears it on failure, so a transient did.json fetch error self-heals on the
// next call rather than permanently wedging badge verification.
const didResolverCache = new Map<string, JWTVerifyGetKey>();

function assertionResolverFor(issuer: string): JWTVerifyGetKey {
  let resolver = didResolverCache.get(issuer);
  if (!resolver) {
    resolver = createDidAssertionResolver(issuer);
    didResolverCache.set(issuer, resolver);
  }
  return resolver;
}

// Fetch <issuer>/.well-known/did.json and build a `kid -> public key` map from
// its `assertionMethod` — the ONLY keys allowed to verify a badge VC.
async function loadAssertionKeys(
  issuer: string,
): Promise<Map<string, KeyLike | Uint8Array>> {
  const url = `${issuer}/.well-known/did.json`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`DID document fetch failed (${res.status}) for ${url}`);
  }
  const doc = (await res.json()) as DidDocumentShape;

  const vms = Array.isArray(doc.verificationMethod) ? doc.verificationMethod : [];
  const byId = new Map<string, DidVerificationMethod>();
  for (const vm of vms) {
    if (
      vm &&
      typeof vm === "object" &&
      typeof (vm as DidVerificationMethod).id === "string"
    ) {
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
      // Don't cache a REJECTED fetch: a transient did.json outage would
      // otherwise wedge badge verification for the process lifetime.
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
      throw new Error("badge JWT has no `kid`; cannot pin to DID assertionMethod");
    }
    const key = keys.get(kid);
    if (!key) {
      throw new Error(
        `badge kid (${kid}) is not in the issuer DID document assertionMethod`,
      );
    }
    return key;
  };
}

export interface VerifyBadgeOptions {
  // Minister origin, e.g. "https://ministry.id".
  issuer: string;
  // Inject the verification key. Defaults to the issuer's DID assertionMethod
  // key set (kid-pinned to #key-2). Pass a public JWK in tests so verification
  // never touches the network.
  key?: KeyInput;
}

// Verify a received VC JWT (standalone).
//
// Beyond `@ministryofmany/vc`'s structural checks, this asserts the VC-INTERNAL
// invariant `credentialSubject.id === payload.sub` — that the claims are bound
// to the subject the issuer signed them for. It does NOT (and cannot) bind the
// badge to any LOGIN: there is no id_token here, so nothing ties this VC to the
// user in front of you. A valid Minister badge belonging to some OTHER user
// (e.g. one received via a share link) verifies successfully. Treating a
// standalone `verifyMinisterBadge` success as "the current user holds this
// badge" is an authorization bug.
//
// The holder-to-login binding lives in the wrapper (`verifyMinisterBadges`),
// which requires `subject === did:web:<host>:u:<id_token sub>`. Use the wrapper
// for any access decision; use this only to certify issuance of an out-of-band
// VC.
export async function verifyMinisterBadge(
  vcJwt: string,
  options: VerifyBadgeOptions,
): Promise<VerifiedBadge> {
  const issuer = options.issuer.replace(/\/$/, "");
  const expectedIss = didFromIssuer(issuer);
  const key = options.key ?? assertionResolverFor(issuer);

  let payload;
  try {
    const result = await verifyJwt(vcJwt, key, {
      issuer: expectedIss,
      algorithms: ["EdDSA"],
      typ: "vc+jwt",
      requiredClaims: ["exp"],
    });
    payload = result.payload;
  } catch (cause) {
    throw new VcVerificationError(
      cause instanceof Error ? cause.message : String(cause),
    );
  }

  if (typeof payload.sub !== "string" || payload.sub.length === 0) {
    throw new VcVerificationError("VC payload missing string `sub`");
  }

  const vc = payload.vc as
    | { type?: unknown; credentialSubject?: unknown }
    | undefined;
  if (!vc || typeof vc !== "object") {
    throw new VcVerificationError("VC payload missing `vc` envelope");
  }
  if (!Array.isArray(vc.type) || !vc.type.every((t) => typeof t === "string")) {
    throw new VcVerificationError("VC `type` must be a string array");
  }
  if (
    !vc.credentialSubject ||
    typeof vc.credentialSubject !== "object" ||
    Array.isArray(vc.credentialSubject)
  ) {
    throw new VcVerificationError("VC missing `credentialSubject` object");
  }

  const credentialSubject = vc.credentialSubject as Record<string, unknown>;
  const subjectId = credentialSubject["id"];
  if (typeof subjectId !== "string" || subjectId.length === 0) {
    throw new VcVerificationError("VC `credentialSubject.id` missing");
  }

  // Holder-binding invariant: the JWT subject must equal the credential
  // subject the issuer signed. (Additional check beyond @ministryofmany/vc.)
  if (subjectId !== payload.sub) {
    throw new VcVerificationError(
      "VC `credentialSubject.id` does not match `sub`",
    );
  }

  // Map the VC type to a known Minister badge slug.
  const slug = badgeTypeOf(vc.type as string[]);
  if (!slug) {
    throw new VcVerificationError(
      `Unknown Minister badge type: ${(vc.type as string[]).join(",")}`,
    );
  }

  // Validate the claims against that badge type's schema. Two RESERVED keys
  // are stripped first: `id` (redundant with `sub`) and `issuanceMonth`
  // (Minister's coarse-issuance metadata, stamped at disclosure re-mint —
  // cross-cutting VC metadata, never a per-type claim; stripping it keeps
  // strict per-type schemas like tlsn-attestation passing).
  const {
    id: _id,
    issuanceMonth: rawIssuanceMonth,
    ...rawClaims
  } = credentialSubject;

  // Strictly format-check the coarse issuance bucket when present. A
  // malformed value means issuer drift or a claim-shaped smuggle upstream of
  // the signature — fail closed rather than hand policy code a garbage
  // timestamp. Absent is fine (legacy Minister); downstream freshness checks
  // then fail closed on maxAgeDays.
  let issuanceMonth: string | undefined;
  if (rawIssuanceMonth !== undefined) {
    if (
      typeof rawIssuanceMonth !== "string" ||
      !/^\d{4}-(0[1-9]|1[0-2])$/.test(rawIssuanceMonth)
    ) {
      throw new VcVerificationError(
        "VC `credentialSubject.issuanceMonth` is not a YYYY-MM UTC month",
      );
    }
    issuanceMonth = rawIssuanceMonth;
  }

  const schema = getBadgeClaimSchema(slug);
  let claims: Record<string, unknown>;
  try {
    claims = schema
      ? (schema.parse(rawClaims) as Record<string, unknown>)
      : rawClaims;
  } catch (cause) {
    throw new VcVerificationError(
      `Badge ${slug} claims failed validation: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    );
  }

  return {
    type: slug,
    claims,
    subject: payload.sub,
    ...(issuanceMonth !== undefined ? { issuanceMonth } : {}),
    raw: vcJwt,
  };
}

// Test seam: drop the cached DID assertionMethod key resolver for an issuer (or
// all issuers).
export function _resetBadgeKeyCache(issuer?: string): void {
  if (issuer) didResolverCache.delete(issuer.replace(/\/$/, ""));
  else didResolverCache.clear();
}
