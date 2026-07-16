import { Identity } from "@semaphore-protocol/identity";
import type { AnonContext, DerivedIdentity } from "./types.js";

/**
 * Per-app-secret -> per-context Semaphore v4 identity derivation (L2 of the
 * two-level anon-identity tree).
 *
 * The user has ONE 16-byte root on their own devices. Ministry derives an L1
 * `per_app_secret` (32 bytes) per relying party and hands it to the app in the
 * OIDC callback fragment (see `./link`). This module takes that per-app secret
 * and derives a DISTINCT Semaphore v4 identity per `AnonContext`, so:
 *   - same (per_app_secret, context)  -> same commitment (multi-device: every
 *     device holding the same root/branch derives the same identity),
 *   - different context               -> different, unlinkable commitment,
 * which is exactly one identity per user per context, the shape RLN needs.
 *
 * Derivation (L2, HKDF-SHA-256, WebCrypto via globalThis.crypto):
 *
 *   prk        = HKDF-importKey(per_app_secret)                       // IKM
 *   ctxKey     = HKDF-Expand(prk, salt=DERIVE_SALT,
 *                            info="ministry/v1/ctx/" + ctxId,         // domain separation
 *                            L=32)
 *   identity   = new Identity(ctxKey)                                 // pure Semaphore v4
 *   commitment = poseidon2([publicKey.x, publicKey.y])               // v4, byte-for-byte
 *
 * The per-context `info` string is the domain separator that makes distinct
 * contexts cryptographically independent. The 32-byte output is handed straight
 * to the v4 `Identity` constructor (EdDSAPoseidon: Blake-512 -> BabyJubJub
 * scalar -> public key -> poseidon2 commitment). We choose only the private-key
 * bytes; we do NOT touch the commitment math.
 */

/** Length, in bytes, of the Ministry-delivered L1 per-app secret (HKDF L=32). */
export const PER_APP_SECRET_BYTES = 32;

/** Length, in bytes, of each derived per-context key fed to `new Identity`. */
export const CONTEXT_KEY_BYTES = 32;

/**
 * HKDF salt, shared by both derivation levels. A fixed, app-wide constant (HKDF
 * security does not require a secret salt; a constant salt with a distinct
 * `info` per node is the standard "expand one IKM into many subkeys" usage).
 * Changing this string re-namespaces every derived commitment, so it is
 * versioned and frozen. Frozen golden vectors depend on this exact value.
 */
const DERIVE_SALT = new TextEncoder().encode("ministry/anon/v1");

/** L2 domain-separation prefix for the HKDF `info` field. */
const L2_INFO_PREFIX = "ministry/v1/ctx/";

function subtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) {
    throw new Error("WebCrypto (globalThis.crypto.subtle) is not available in this environment.");
  }
  return c.subtle;
}

function assertPerAppSecret(perAppSecret: Uint8Array): void {
  if (!(perAppSecret instanceof Uint8Array)) {
    throw new Error("perAppSecret must be a Uint8Array.");
  }
  if (perAppSecret.byteLength !== PER_APP_SECRET_BYTES) {
    throw new Error(
      `perAppSecret must be ${PER_APP_SECRET_BYTES} bytes, got ${perAppSecret.byteLength}.`,
    );
  }
}

/**
 * Serialize an `AnonContext` into the L2 `info` context id. Each segment is
 * validated to be a non-empty string with no `/`: because the segments are
 * joined with `/`, a slash inside a segment would make the resulting string
 * ambiguous (e.g. `{kind:"room", id:"a", sub:"b"}` and `{kind:"room",
 * id:"a/b"}` would collide onto the same secret). Rejecting the slash makes the
 * decomposition unique, so distinct contexts can never derive the same key.
 */
function contextInfoId(context: AnonContext): string {
  const segments =
    context.sub === undefined
      ? [context.kind, context.id]
      : [context.kind, context.id, context.sub];
  for (const s of segments) {
    if (typeof s !== "string" || s.length === 0) {
      throw new Error("AnonContext kind/id/sub must be non-empty strings.");
    }
    if (s.includes("/")) {
      throw new Error(
        `AnonContext segment ${JSON.stringify(s)} must not contain "/": a slash ` +
          "makes the derived context id ambiguous and could collide two distinct " +
          "contexts onto the same identity secret.",
      );
    }
  }
  return segments.join("/");
}

/**
 * Derive the raw per-context key bytes from a per-app secret via
 * HKDF-Expand(SHA-256). Exposed so callers/tests can inspect the deterministic
 * key material; `deriveIdentity` wraps this into a Semaphore v4 `Identity`.
 *
 * For Discreetly's Semaphore v3 (flat trapdoor/nullifier), the two 32-byte
 * outputs are taken directly here with `sub: "trapdoor"` / `sub: "nullifier"`
 * contexts, not through a nested room-secret level.
 */
export async function deriveContextKeyBytes(
  perAppSecret: Uint8Array,
  context: AnonContext,
): Promise<Uint8Array> {
  assertPerAppSecret(perAppSecret);
  const s = subtle();
  const baseKey = await s.importKey(
    "raw",
    perAppSecret as unknown as BufferSource,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const info = new TextEncoder().encode(L2_INFO_PREFIX + contextInfoId(context));
  const bits = await s.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: DERIVE_SALT as unknown as BufferSource,
      info: info as unknown as BufferSource,
    },
    baseKey,
    CONTEXT_KEY_BYTES * 8,
  );
  return new Uint8Array(bits);
}

/**
 * Derive the per-context Semaphore v4 identity from a per-app secret. The
 * returned `DerivedIdentity` satisfies the `SemaphoreIdentityLike` contract the
 * membership layer consumes (`commitment` decimal string + opaque `native`
 * handle) and also exposes the concrete v4 `Identity` for in-world callers.
 *
 * Determinism: same (perAppSecret, context) -> identical key -> identical
 * commitment. Distinct context -> distinct, unlinkable commitment.
 */
export async function deriveIdentity(
  perAppSecret: Uint8Array,
  context: AnonContext,
): Promise<DerivedIdentity> {
  const contextKey = await deriveContextKeyBytes(perAppSecret, context);
  const identity = new Identity(contextKey);
  const commitment = identity.commitment.toString();
  return {
    context,
    identity,
    native: identity,
    commitment,
  };
}

/**
 * Derive the identities for many contexts from one per-app secret, in parallel.
 * Order matches the input `contexts` order.
 */
export async function deriveIdentities(
  perAppSecret: Uint8Array,
  contexts: readonly AnonContext[],
): Promise<DerivedIdentity[]> {
  return Promise.all(contexts.map((c) => deriveIdentity(perAppSecret, c)));
}
