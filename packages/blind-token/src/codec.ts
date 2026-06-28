// base64url codecs, browser- and Node-safe. Lifted from FreedInk's per-file
// re-implementations (vote-token.ts:217-228) and unified here so neither the
// client nor the server re-derives them. These use only `btoa`/`atob`, which
// exist in both modern Node (globals) and browsers, so the root entry stays
// isomorphic.

// Encode bytes as unpadded base64url.
export function bytesToB64url(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Decode unpadded (or padded) base64url back to bytes.
export function b64urlToBytes(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
