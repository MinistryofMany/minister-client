/**
 * Ministry -> RP anonymous-identity handoff: the ZERO-DEPENDENCY entry point.
 *
 * This module has no `@semaphore-protocol/identity` import (nothing here pulls
 * in the commitment math), so an app can statically import the fragment
 * capture+scrub at module scope - before analytics or any third-party JS runs -
 * without waiting for a lazy import. That is the whole reason it is its own
 * `./link` subpath: the scrub is security-critical and cannot be deferred.
 *
 * Ministry delivers a 32-byte per-app secret (the app's branch of the identity
 * tree) to the RP's OIDC callback landing page as a URL fragment
 * (`#minister_anon=v1.<43 base64url chars>`). The RP:
 *
 *   1. `extractMinisterAppSecret()` - read + validate + SCRUB the fragment,
 *   2. after the token exchange, `decideAnonAction()` with the branch, the
 *      id_token's `minister_anon_epoch`, and the epoch the app last keyed at,
 *   3. feed the branch to `deriveIdentity(branch, context)` (from the package
 *      root) -> per-context Semaphore identity.
 *
 * Nothing here talks to any server. The per-app secret and everything derived
 * from it are browser-local; sending any of them to the RP server (or anywhere
 * else) is an integration bug.
 */

/** Fragment parameter name carrying the per-app secret on the OIDC callback. */
export const MINISTER_ANON_PARAM = "minister_anon";

/** Length, in bytes, of the Ministry-delivered per-app secret (HKDF L=32). */
export const APP_SECRET_BYTES = 32;

/**
 * Fragment value grammar: `v1.` + exactly 43 base64url chars (= 32 bytes).
 * Unknown versions are ignored - return null, never garbage.
 */
const FRAGMENT_VALUE = /^v1\.([A-Za-z0-9_-]{43})$/;

/**
 * Structural subset of DOM `Location` this module reads. A real
 * `window.location` satisfies it; tests and non-DOM builds can inject one.
 */
export interface MinisterLinkLocation {
  readonly pathname: string;
  readonly search: string;
  readonly hash: string;
}

/** Structural subset of DOM `History` used for the scrub. */
export interface MinisterLinkHistory {
  /** Current router/history state, preserved across the scrub replaceState. */
  readonly state?: unknown;
  replaceState(data: unknown, unused: string, url?: string | null): void;
}

function base64urlDecode(s: string): Uint8Array | null {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (b64.length % 4)) % 4);
  let bin: string;
  try {
    bin = atob(b64 + pad);
  } catch {
    return null;
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Read and scrub the Ministry anon fragment on the RP's OIDC callback landing
 * page. Returns the 32-byte per-app secret, or `null` if the fragment is
 * absent, malformed, or an unknown version (fail-closed: login succeeded but no
 * anonymous identity arrives - show the RP's "connect your anonymous identity"
 * state, never invent a secret).
 *
 * INTEGRATION REQUIREMENTS - the fragment only survives server-side HTTP 3xx
 * redirects, and it is a secret sitting in the URL until scrubbed:
 *
 *   - Call this on the landing page BEFORE any other script touches the URL:
 *     before analytics, before error reporters, before any third-party JS.
 *   - NO client-side redirect may run anywhere in the callback chain before
 *     extraction: a `location.assign`/`replace`, meta refresh, or
 *     framework-router navigation silently destroys the fragment. Every hop
 *     from the OIDC callback to this page must be a server-side 3xx whose
 *     `Location` carries no fragment of its own.
 *   - The scrub (default on) removes ONLY the `minister_anon` param from the
 *     fragment via `history.replaceState`, so the secret does not persist in
 *     the tab's history entry or leak through later `location.href` reads. A
 *     malformed value is scrubbed too. If scrubbing is requested but
 *     `history.replaceState` is unavailable this THROWS rather than silently
 *     leaving the secret in the URL.
 *   - Residual: a crash between navigation and scrub can leave the fragment in
 *     a restored-session URL. Accepted; blast radius is this one app's secret,
 *     which is exactly why the per-app secret - never the root - crosses
 *     origins.
 */
export function extractMinisterAppSecret(opts?: {
  /** Defaults to `globalThis.location`. Absent (SSR) -> null, fail-closed. */
  location?: MinisterLinkLocation;
  /** Default true. Only pass false if the caller scrubs by other means. */
  scrub?: boolean;
  /** Defaults to `globalThis.history`. Injectable for tests. */
  history?: MinisterLinkHistory;
}): Uint8Array | null {
  const loc = opts?.location ?? (globalThis as { location?: MinisterLinkLocation }).location;
  if (!loc || typeof loc.hash !== "string") return null;
  const hash = loc.hash;
  if (hash === "" || hash === "#") return null;

  const params = new URLSearchParams(hash.startsWith("#") ? hash.slice(1) : hash);
  const raw = params.get(MINISTER_ANON_PARAM);
  if (raw === null) return null;

  // Scrub BEFORE validating: even a malformed or unknown-version value is
  // secret-shaped material that must not linger in the URL or history entry.
  if (opts?.scrub !== false) {
    params.delete(MINISTER_ANON_PARAM);
    const rest = params.toString();
    const url = loc.pathname + loc.search + (rest ? `#${rest}` : "");
    const hist = opts?.history ?? (globalThis as { history?: MinisterLinkHistory }).history;
    if (!hist || typeof hist.replaceState !== "function") {
      throw new Error(
        "extractMinisterAppSecret: cannot scrub the minister_anon fragment - " +
          "history.replaceState is unavailable. Pass opts.history, or opts.scrub: " +
          "false only if the caller removes the fragment by other means.",
      );
    }
    // Preserve any existing router/history state: passing null would clobber
    // a framework router's state entry. Only the URL is being rewritten here.
    hist.replaceState(hist.state ?? null, "", url);
  }

  const match = FRAGMENT_VALUE.exec(raw);
  const encoded = match?.[1];
  if (encoded === undefined) return null;
  const bytes = base64urlDecode(encoded);
  if (bytes === null || bytes.byteLength !== APP_SECRET_BYTES) return null;
  return bytes;
}

/**
 * What the app should do with a freshly-captured branch, given the epoch the
 * id_token carries and the epoch the app last keyed at. A discriminated union
 * (not a boolean) so `none` is unignorable at the type level - the four-branch
 * decision below is the point, not `shouldRekey -> boolean`.
 */
export type AnonAction =
  | { action: "none" }
  | { action: "adopt"; branch: Uint8Array; epoch: number }
  | { action: "rekey"; branch: Uint8Array; epoch: number };

/**
 * Decide whether to adopt a first identity, re-key to a new one, or do nothing,
 * keyed on `(branch, tokenEpoch, storedEpoch)`. The signed id_token epoch is the
 * authority; a bare commitment mismatch is NOT a re-key trigger.
 *
 *   - branch === null              -> "none": nothing arrived this login, keep
 *     whatever is stored.
 *   - tokenEpoch === undefined     -> "none": no authenticated epoch to key on,
 *     fail closed rather than adopt an un-versioned branch.
 *   - storedEpoch === undefined    -> "adopt": first identity for this app.
 *   - tokenEpoch > storedEpoch     -> "rekey": the epoch strictly advanced.
 *   - otherwise                    -> "none": already keyed at this epoch, or a
 *     stale/replayed token (tokenEpoch <= storedEpoch) that must never clobber
 *     the current commitment or loop replacements to defeat RLN.
 */
export function decideAnonAction(input: {
  branch: Uint8Array | null;
  tokenEpoch: number | undefined;
  storedEpoch: number | undefined;
}): AnonAction {
  const { branch, tokenEpoch, storedEpoch } = input;
  if (branch === null) return { action: "none" };
  if (tokenEpoch === undefined) return { action: "none" };
  if (storedEpoch === undefined) return { action: "adopt", branch, epoch: tokenEpoch };
  if (tokenEpoch > storedEpoch) return { action: "rekey", branch, epoch: tokenEpoch };
  return { action: "none" };
}
