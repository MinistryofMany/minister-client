import { didFromIssuer } from "./did";
import { verifyJwt } from "./jwt";
import { VcVerificationError } from "./errors";
import type { KeyInput } from "./types";

// Client-side badge revocation via per-RP W3C Bitstring Status Lists
// (Minister docs/groups-revocation-design.md §5.6/§5.8). An RP that grants a
// durable entitlement from a badge carrying `credentialStatus` persists its
// (uri, index) and sweeps them against Minister's published, #key-2-signed list.
//
// This is the SDK side of the freshness/rollback defense. Four stacked, MANDATORY
// checks (§5.6): (1) signature + `sub == fetched URL` binding; (2) hard max-age on
// the signed `exp`; (3) a monotonic `statusListVersion` high-water mark; (4) a
// revocation LATCH — because `statusPurpose: "revocation"` is irreversible by
// spec, once any validly-signed list showed an index revoked, that handle stays
// revoked forever in local state, no matter what later lists say. Together these
// turn every rollback variant into at worst a bounded DELAY, never an
// un-revocation.

// A parsed, validated credentialStatus pointer (surfaced on VerifiedBadge.status).
export interface BadgeStatusRef {
  // The list URL (credentialStatus.statusListCredential).
  uri: string;
  // The bit index within that list.
  index: number;
}

export type StatusCheck = "valid" | "revoked" | "stale";

// Upper bound on a plausible index — one shard is 8,192 bits, but an ecosystem
// could grow it; 2^20 is a generous ceiling that still rejects absurd values
// (Minister's §5.8 shape check).
const MAX_STATUS_INDEX = 1 << 20;

// Parse + strictly validate a `vc.credentialStatus`. Malformed => throw (the
// caller fails the badge closed, matching the nullifier posture). `undefined`
// return means "no credentialStatus present" (a non-revocable badge).
export function parseCredentialStatus(
  rawStatus: unknown,
  expectedIssuerOrigin: string,
): BadgeStatusRef | undefined {
  if (rawStatus === undefined || rawStatus === null) return undefined;
  if (typeof rawStatus !== "object" || Array.isArray(rawStatus)) {
    throw new VcVerificationError("VC `credentialStatus` is not an object");
  }
  const s = rawStatus as Record<string, unknown>;

  if (s.type !== "BitstringStatusListEntry") {
    throw new VcVerificationError(
      `VC credentialStatus.type must be BitstringStatusListEntry (got ${String(s.type)})`,
    );
  }
  if (s.statusPurpose !== "revocation") {
    throw new VcVerificationError(
      `VC credentialStatus.statusPurpose must be "revocation" (got ${String(s.statusPurpose)})`,
    );
  }

  const uri = s.statusListCredential;
  if (typeof uri !== "string" || uri.length === 0) {
    throw new VcVerificationError("VC credentialStatus.statusListCredential missing");
  }
  // Pin the list URL to the configured Minister origin: a badge must never point
  // at a status list on some other host (an attacker-controlled always-valid
  // list). https-only, exact origin match.
  let listUrl: URL;
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
      `VC credentialStatus list URL origin ${listUrl.origin} is not the configured issuer ${expected.origin}`,
    );
  }

  const rawIndex = s.statusListIndex;
  const index = typeof rawIndex === "string" ? Number(rawIndex) : rawIndex;
  if (typeof index !== "number" || !Number.isInteger(index) || index < 0 || index >= MAX_STATUS_INDEX) {
    throw new VcVerificationError(
      `VC credentialStatus.statusListIndex out of range: ${String(rawIndex)}`,
    );
  }

  return { uri, index };
}

// W3C bit read: index i is the (i mod 8)-th bit FROM THE LEFT of byte i>>3.
// MUST match Minister's encode (status-list/bitstring.ts).
function bitIsSet(bytes: Uint8Array, index: number): boolean {
  const byte = bytes[index >> 3] ?? 0;
  return (byte & (0x80 >> (index & 7))) !== 0;
}

// base64url -> bytes, platform-neutral (no node Buffer): the SDK builds against
// the DOM lib and must run in browsers as well as Node/RP servers. `atob` needs
// standard base64 with padding.
function base64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// GZIP-decompress via the Web DecompressionStream (Node 18+ and browsers) — keeps
// the SDK free of node builtins.
async function gunzip(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([bytes as BlobPart]).stream().pipeThrough(new DecompressionStream("gzip"));
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}

// Decode `u<base64url(gzip(bits))>` (multibase base64url) into raw bytes.
async function decodeEncodedList(encodedList: string): Promise<Uint8Array> {
  if (typeof encodedList !== "string" || encodedList.length < 1 || encodedList[0] !== "u") {
    throw new VcVerificationError("status list encodedList is not multibase base64url ('u')");
  }
  return gunzip(base64urlToBytes(encodedList.slice(1)));
}

// A verified, freshness-checked status list snapshot.
export interface StatusListSnapshot {
  bits: Uint8Array;
  version: number;
  // Epoch ms after which the signed list is stale (from `exp`).
  expiresAtMs: number;
  etag?: string;
}

export interface VerifyStatusListOptions {
  // The URL the SDK fetched (for the sub-binding check).
  fetchedUrl: string;
  // The configured Minister issuer origin, e.g. "https://ministry.id".
  issuer: string;
  // Verification key: defaults to the issuer DID assertionMethod resolver
  // (#key-2 pinned). Injectable for offline tests.
  key: KeyInput;
  // Clock tolerance for exp (seconds). Matches the id_token verifier's 30s.
  clockToleranceSec?: number;
  nowMs?: number;
}

const DEFAULT_CLOCK_TOLERANCE_SEC = 30;

// Verify a fetched status-list JWT and extract the bitstring (§5.6 defenses 1-2).
// Throws VcVerificationError on any failure; the checker translates a throw into
// "stale" (then the configured fail mode decides).
export async function verifyStatusListCredential(
  jwt: string,
  opts: VerifyStatusListOptions,
): Promise<StatusListSnapshot> {
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
      // already rejects an expired token here (defense 2).
    });
    payload = result.payload;
  } catch (cause) {
    throw new VcVerificationError(
      `status list verification failed: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }

  // Defense 1: sub binds the credential to the URL the SDK fetched. Replay of one
  // list's credential under another list's URL is impossible.
  if (typeof payload.sub !== "string" || payload.sub.replace(/\/$/, "") !== fetchedUrl) {
    throw new VcVerificationError(
      `status list sub (${String(payload.sub)}) does not match fetched URL ${fetchedUrl}`,
    );
  }

  const version = payload.statusListVersion;
  if (typeof version !== "number" || !Number.isInteger(version)) {
    throw new VcVerificationError("status list has no integer statusListVersion");
  }

  const vc = payload.vc as { type?: unknown; credentialSubject?: unknown } | undefined;
  if (!vc || typeof vc !== "object") {
    throw new VcVerificationError("status list payload missing `vc` envelope");
  }
  if (!Array.isArray(vc.type) || !vc.type.includes("BitstringStatusListCredential")) {
    throw new VcVerificationError("status list vc.type must include BitstringStatusListCredential");
  }
  const cs = vc.credentialSubject as Record<string, unknown> | undefined;
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
  const expiresAtMs = typeof payload.exp === "number" ? payload.exp * 1000 : 0;

  return { bits, version, expiresAtMs };
}

export { bitIsSet };
