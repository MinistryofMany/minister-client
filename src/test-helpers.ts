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
  // A `vc.credentialStatus` entry (revocation) — placed at the vc level, sibling
  // of credentialSubject, exactly as Minister's reMintVc stamps it.
  credentialStatus?: Record<string, unknown>;
}

// Sign a Minister-shaped VC JWT, mirroring @ministryofmany/vc's issueVc.
export async function signVc(args: SignVcArgs): Promise<string> {
  const type = args.type ?? ["VerifiableCredential", "MinisterEmailDomainCredential"];
  const claims = args.claims ?? { domain: "example.com" };
  const vc: Record<string, unknown> = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    type,
    credentialSubject: { id: args.subject, ...claims },
    ...(args.credentialStatus !== undefined ? { credentialStatus: args.credentialStatus } : {}),
  };
  return new SignJWT({ vc })
    .setProtectedHeader({ alg: "EdDSA", typ: args.typ ?? "vc+jwt" })
    .setIssuer(args.issuerDid)
    .setSubject(args.subOverride ?? args.subject)
    .setIssuedAt()
    .setExpirationTime("1y")
    .sign(args.privateKey);
}

// ---------------------------------------------------------------------------
// Status-list fixtures (revocation). Platform-neutral (Web CompressionStream)
// so they build the SAME `u<base64url(gzip(bits))>` shape the SDK decodes.
// ---------------------------------------------------------------------------

// One shard = 8,192 bits = 1 KiB (mirrors Minister's SHARD_SIZE_BYTES).
export const STATUS_SHARD_BYTES = 1024;

export function newStatusBits(): Uint8Array {
  return new Uint8Array(STATUS_SHARD_BYTES);
}

// Set a bit W3C-style (index i = the (i mod 8)-th bit from the LEFT of byte i>>3).
export function setStatusBit(bits: Uint8Array, index: number): void {
  bits[index >> 3] = (bits[index >> 3] ?? 0) | (0x80 >> (index & 7));
}

async function gzipToEncodedList(bits: Uint8Array): Promise<string> {
  const stream = new Blob([bits as BlobPart]).stream().pipeThrough(new CompressionStream("gzip"));
  const buf = await new Response(stream).arrayBuffer();
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const b64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `u${b64}`;
}

export interface SignStatusListArgs {
  privateKey: KeyLike;
  issuerDid: string; // e.g. "did:web:ministry.id"
  listUrl: string; // the credential `sub` and credentialStatus.statusListCredential
  version: number;
  bits: Uint8Array;
  // Seconds-from-now for exp; default +900 (15 min). Pass a negative value to
  // forge an already-expired list.
  expDeltaSec?: number;
  subOverride?: string; // to test the sub-binding rejection
  typ?: string;
}

// Sign a Minister-shaped BitstringStatusListCredential, mirroring the publisher.
export async function signStatusList(args: SignStatusListArgs): Promise<string> {
  const encodedList = await gzipToEncodedList(args.bits);
  const nowSec = Math.floor(Date.now() / 1000);
  return new SignJWT({
    statusListVersion: args.version,
    vc: {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiableCredential", "BitstringStatusListCredential"],
      credentialSubject: {
        id: `${args.listUrl}#list`,
        type: "BitstringStatusList",
        statusPurpose: "revocation",
        encodedList,
      },
      ttl: 60000,
    },
  })
    .setProtectedHeader({ alg: "EdDSA", typ: args.typ ?? "vc+jwt", kid: `${args.issuerDid}#key-2` })
    .setIssuer(args.issuerDid)
    .setSubject(args.subOverride ?? args.listUrl)
    .setIssuedAt(nowSec)
    .setExpirationTime(nowSec + (args.expDeltaSec ?? 900))
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
