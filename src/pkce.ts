import type { PkcePair } from "./types";

// PKCE + random-token helpers built on the Web Crypto API
// (`globalThis.crypto`), so the SDK runs unchanged on Node 20+, Deno,
// and edge runtimes (Vercel Edge, Cloudflare Workers) — the same
// environments jose targets. No `node:crypto` import.

function b64url(bytes: Uint8Array): string {
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  crypto.getRandomValues(buf);
  return buf;
}

async function sha256(input: string): Promise<Uint8Array> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}

// Generate a PKCE verifier/challenge pair (RFC 7636, S256). The verifier
// is 32 random bytes base64url-encoded; the challenge is its SHA-256.
export async function generatePkce(): Promise<PkcePair> {
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(await sha256(verifier));
  return { verifier, challenge };
}

// A URL-safe random token, used for `state` and `nonce`. 16 bytes
// (128 bits) of entropy by default.
export function randomUrlToken(bytes = 16): string {
  return b64url(randomBytes(bytes));
}
