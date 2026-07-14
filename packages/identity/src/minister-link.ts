import { DEVICE_SEED_BYTES } from "./derive.js";

/**
 * Ministry -> RP anonymous-identity handoff (anon-identity master spec 8.4 + 9).
 *
 * Ministry delivers a 32-byte per-app secret to the RP's OIDC callback landing
 * page as a URL fragment (`#minister_anon=v1.<43 base64url chars>`). The RP:
 *
 *   1. `extractMinisterAppSecret()`  - read + validate + SCRUB the fragment,
 *   2. `deriveDeviceSeedFromMinister(appSecret, rpMixSecret)` - HKDF in the
 *      RP's own secret, producing the 32-byte device seed,
 *   3. feed that seed to the EXISTING chain unchanged:
 *      `deriveIdentity(deviceSeed, contextId)` -> per-context Semaphore identity.
 *
 * Nothing here talks to any server. The per-app secret, the mixed device seed,
 * and everything derived from them are browser-local; sending any of them to
 * the RP server (or anywhere else) is an integration bug (spec 9.3).
 */

/** Fragment parameter name carrying the per-app secret on the OIDC callback. */
export const MINISTER_ANON_PARAM = "minister_anon";

/** Length, in bytes, of the Ministry-delivered per-app secret (spec 8.1: L=32). */
export const APP_SECRET_BYTES = 32;

/** Minimum length, in bytes, of the RP mix secret (spec 9.2: >= 32 CSPRNG bytes). */
export const RP_MIX_SECRET_MIN_BYTES = 32;

/**
 * HKDF `info` for the RP mix derivation (spec 9.2). Versioned and frozen:
 * changing it re-derives every device seed and forks every identity.
 */
const RP_MIX_INFO = new TextEncoder().encode("minister/anon/rp-mix/v1");

/**
 * Fragment value grammar (spec 8.2): `v1.` + exactly 43 base64url chars
 * (= 32 bytes). Unknown versions are ignored - return null, never garbage.
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
 * absent, malformed, or an unknown version (fail-closed, spec 8.3: login
 * succeeded but no anonymous identity arrives - show the RP's "connect your
 * anonymous identity" state, never invent a secret).
 *
 * INTEGRATION REQUIREMENTS (spec 8.4 / 9.3, findings S3/S4) - the fragment
 * only survives server-side HTTP 3xx redirects, and it is a secret sitting in
 * the URL until scrubbed:
 *
 *   - Call this on the landing page BEFORE any other script touches the URL:
 *     before analytics, before error reporters, before any third-party JS.
 *   - NO client-side redirect may run anywhere in the callback chain before
 *     extraction (finding S3): a `location.assign`/`replace`, meta refresh, or
 *     framework-router navigation silently destroys the fragment. Every hop
 *     from the OIDC callback to this page must be a server-side 3xx whose
 *     `Location` carries no fragment of its own.
 *   - The scrub (default on) removes ONLY the `minister_anon` param from the
 *     fragment via `history.replaceState`, so the secret does not persist in
 *     the tab's history entry or leak through later `location.href` reads
 *     (finding S4). A malformed value is scrubbed too. If scrubbing is
 *     requested but `history.replaceState` is unavailable this THROWS rather
 *     than silently leaving the secret in the URL.
 *   - Residual (spec 8.4): a crash between navigation and scrub can leave the
 *     fragment in a restored-session URL. Accepted; blast radius is this one
 *     app's secret, which is exactly why the per-app secret - never the root
 *     seed - crosses origins.
 *
 * Cache at most the mixed device seed (`deriveDeviceSeedFromMinister` output),
 * never this raw per-app secret (spec 9.3).
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
    hist.replaceState(null, "", url);
  }

  const match = FRAGMENT_VALUE.exec(raw);
  const encoded = match?.[1];
  if (encoded === undefined) return null;
  const bytes = base64urlDecode(encoded);
  if (bytes === null || bytes.byteLength !== APP_SECRET_BYTES) return null;
  return bytes;
}

/**
 * Mix the RP's own secret into the Ministry-delivered per-app secret to produce
 * the 32-byte device seed (spec 9.2):
 *
 *   device_seed = HKDF-SHA-256(ikm = per_app_secret,
 *                              salt = rp_mix_secret,
 *                              info = "minister/anon/rp-mix/v1", L = 32)
 *
 * The output is `DEVICE_SEED_BYTES` long and feeds the existing per-context
 * chain unchanged: `deriveIdentity(deviceSeed, contextId)`. The mix means a
 * compromise that exfiltrates seeds from the ministry.id origin still cannot
 * reproduce this RP's identities without also taking the RP's secret
 * (2026-07-09 decision).
 *
 * ============================================================================
 * FORK-AVOIDANCE INVARIANT (spec I9): `rpMixSecret` IS IDENTITY-DETERMINING.
 * ============================================================================
 * It is the HKDF salt, so losing or regenerating it silently forks EVERY
 * user's identity in this app: every commitment, membership, and nullifier
 * orphans, every prior post becomes unownable, and NO ERROR FIRES ANYWHERE.
 * There is no legitimate rotation - only the fork. Treat it with seed-level
 * durability discipline, RP-side:
 *
 *   - Provision ONCE at launch: >= 32 CSPRNG bytes (env var, suggested name
 *     `ANON_RP_MIX_SECRET`), delivered to the signed-in page by the RP's own
 *     server (page props / load function), never baked into a public bundle.
 *   - Back it up IMMEDIATELY in the RP's secret store with the same
 *     durability as the RP's database.
 *   - IMMUTABLE post-launch. Any "rotate secrets" runbook must explicitly
 *     exclude this value.
 *   - A written per-RP recovery story (where the backup lives, who can
 *     restore it) is required before the integration ships (spec 9.2).
 *
 * Ministry never holds this value; the obligation sits entirely with the RP.
 *
 * Throws on wrong-size inputs (programmer/provisioning error - loud, not
 * fail-closed). Never sends anything anywhere: pure client-side WebCrypto.
 */
export async function deriveDeviceSeedFromMinister(
  appSecret: Uint8Array,
  rpMixSecret: Uint8Array,
): Promise<Uint8Array> {
  if (!(appSecret instanceof Uint8Array) || appSecret.byteLength !== APP_SECRET_BYTES) {
    throw new Error(`appSecret must be ${APP_SECRET_BYTES} bytes (from extractMinisterAppSecret).`);
  }
  if (!(rpMixSecret instanceof Uint8Array) || rpMixSecret.byteLength < RP_MIX_SECRET_MIN_BYTES) {
    throw new Error(
      `rpMixSecret must be at least ${RP_MIX_SECRET_MIN_BYTES} bytes of the RP's own high-entropy secret.`,
    );
  }
  const c = globalThis.crypto;
  if (!c?.subtle) {
    throw new Error("WebCrypto (globalThis.crypto.subtle) is not available in this environment.");
  }
  const baseKey = await c.subtle.importKey(
    "raw",
    appSecret as unknown as BufferSource,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const bits = await c.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: rpMixSecret as unknown as BufferSource,
      info: RP_MIX_INFO as unknown as BufferSource,
    },
    baseKey,
    DEVICE_SEED_BYTES * 8,
  );
  return new Uint8Array(bits);
}
