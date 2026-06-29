import { exportJWK, generateKeyPair, SignJWT, type JWK, type KeyLike } from "jose";

// Shared test fixtures. NOT part of the published API (excluded from the
// tsup entry); imported only by `*.test.ts`. Lets tests sign real
// Ed25519 JWTs and inject the matching public key so verification runs
// fully offline.

export interface TestKeys {
  privateKey: KeyLike;
  publicKey: KeyLike;
  publicJwk: JWK;
}

export async function makeKeys(): Promise<TestKeys> {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA", {
    extractable: true,
  });
  const publicJwk = await exportJWK(publicKey);
  return { privateKey, publicKey, publicJwk };
}

// Build a local key resolver mimicking createRemoteJWKSet, so id_token
// tests can exercise the resolver-function code path (not just a bare
// KeyLike) without a network fetch.
export function localJwks(publicKey: KeyLike) {
  return () => Promise.resolve(publicKey);
}

export interface SignVcArgs {
  privateKey: KeyLike;
  issuerDid: string; // e.g. "did:web:ministry.id"
  subject: string; // credentialSubject.id and JWT sub
  type?: string[];
  claims?: Record<string, unknown>;
  // Override the JWT sub independently of credentialSubject.id, to test
  // the holder-binding mismatch rejection.
  subOverride?: string;
  typ?: string;
}

// Sign a Minister-shaped VC JWT, mirroring @ministryofmany/vc's issueVc.
export async function signVc(args: SignVcArgs): Promise<string> {
  const type = args.type ?? ["VerifiableCredential", "MinisterEmailDomainCredential"];
  const claims = args.claims ?? { domain: "example.com" };
  const vc = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    type,
    credentialSubject: { id: args.subject, ...claims },
  };
  return new SignJWT({ vc })
    .setProtectedHeader({ alg: "EdDSA", typ: args.typ ?? "vc+jwt" })
    .setIssuer(args.issuerDid)
    .setSubject(args.subOverride ?? args.subject)
    .setIssuedAt()
    .setExpirationTime("1y")
    .sign(args.privateKey);
}

export interface SignIdTokenArgs {
  privateKey: KeyLike;
  issuer: string; // OIDC issuer, e.g. "https://ministry.id"
  audience: string; // client_id
  sub?: string;
  nonce?: string;
  name?: string;
  picture?: string;
  ministerBadges?: string[];
  extra?: Record<string, unknown>;
}

// Sign a Minister-shaped id_token.
export async function signIdToken(args: SignIdTokenArgs): Promise<string> {
  const payload: Record<string, unknown> = {
    sub: args.sub ?? "pairwise-subject-123",
    ...(args.nonce !== undefined ? { nonce: args.nonce } : {}),
    ...(args.name !== undefined ? { name: args.name } : {}),
    ...(args.picture !== undefined ? { picture: args.picture } : {}),
    ...(args.ministerBadges !== undefined
      ? { minister_badges: args.ministerBadges }
      : {}),
    ...(args.extra ?? {}),
  };
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "EdDSA" })
    .setIssuer(args.issuer)
    .setAudience(args.audience)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(args.privateKey);
}
