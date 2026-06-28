import { Identity } from "@semaphore-protocol/identity";
import type { ContextId, DerivedIdentity } from "./types.js";

/**
 * Device-seed -> per-context Semaphore v4 identity derivation.
 *
 * deforum-spec.md section 2: "One device seed to back up, distinct commitment per
 * sub-forum." From a single, backed-up 32-byte device seed we deterministically
 * derive a DISTINCT Semaphore v4 `Identity` per `contextId`, so:
 *   - same (seed, context)      -> same commitment (the device proves the same membership),
 *   - different context          -> different, unlinkable commitment (no cross-context linkage),
 * which is exactly the improvement over Discreetly, where one commitment was
 * reused across rooms and leaked cross-room membership at rest.
 *
 * Derivation (HKDF-SHA-256, WebCrypto, framework-agnostic via globalThis.crypto):
 *
 *   prk_seed   = HKDF-importKey(deviceSeed)                          // IKM
 *   privKey    = HKDF-Expand(prk_seed, salt=DERIVE_SALT,
 *                            info="minister/identity/v1:"+contextId, // domain separation
 *                            L=32)
 *   identity   = new Identity(privKey)                               // pure Semaphore v4
 *   commitment = poseidon2([publicKey.x, publicKey.y])               // v4, byte-for-byte
 *
 * HKDF is the standard primitive for expanding one secret into many independent
 * subkeys; the per-context `info` string is the domain separator that makes
 * distinct contexts cryptographically independent. The 32-byte output is handed
 * straight to the v4 `Identity` constructor, which runs it through EdDSAPoseidon
 * (Blake-512 -> BabyJubJub scalar -> public key -> poseidon2 commitment). We do
 * NOT touch any of the commitment math; we only choose the private-key bytes.
 */

/** Length, in bytes, of a device seed. 32 bytes (256 bits) -> a 24-word BIP-39 backup. */
export const DEVICE_SEED_BYTES = 32;

/** Length, in bytes, of each derived per-context private key fed to `new Identity`. */
export const DERIVED_KEY_BYTES = 32;

/**
 * HKDF salt. A fixed, app-wide constant (HKDF security does not require a secret
 * salt; a constant salt with distinct `info` per context is the standard "expand
 * one IKM into many subkeys" usage). Changing this string re-namespaces every
 * derived commitment, so it is versioned and frozen.
 */
const DERIVE_SALT = new TextEncoder().encode("minister/identity/hkdf/v1");

/** Per-context domain-separation prefix for the HKDF `info` field. */
const INFO_PREFIX = "minister/identity/v1:";

function subtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) {
    throw new Error("WebCrypto (globalThis.crypto.subtle) is not available in this environment.");
  }
  return c.subtle;
}

function assertSeed(deviceSeed: Uint8Array): void {
  if (!(deviceSeed instanceof Uint8Array)) {
    throw new Error("deviceSeed must be a Uint8Array.");
  }
  if (deviceSeed.byteLength !== DEVICE_SEED_BYTES) {
    throw new Error(
      `deviceSeed must be ${DEVICE_SEED_BYTES} bytes, got ${deviceSeed.byteLength}.`,
    );
  }
}

/**
 * Generate a fresh, cryptographically-random 32-byte device seed. This is the ONE
 * value the user backs up (via `seedToMnemonic`); every per-context identity is
 * derived from it. Never persisted in plaintext - encrypt it with the vault.
 */
export function generateDeviceSeed(): Uint8Array {
  const c = globalThis.crypto;
  if (!c?.getRandomValues) {
    throw new Error("WebCrypto (globalThis.crypto.getRandomValues) is not available.");
  }
  return c.getRandomValues(new Uint8Array(DEVICE_SEED_BYTES));
}

/**
 * Derive the raw per-context private-key bytes from a device seed via
 * HKDF-Expand(SHA-256). Exposed so callers/tests can inspect the deterministic
 * key material; `deriveIdentity` wraps this into a Semaphore v4 `Identity`.
 */
export async function derivePrivateKeyBytes(
  deviceSeed: Uint8Array,
  context: ContextId,
): Promise<Uint8Array> {
  assertSeed(deviceSeed);
  const s = subtle();
  const baseKey = await s.importKey(
    "raw",
    deviceSeed as unknown as BufferSource,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const info = new TextEncoder().encode(INFO_PREFIX + context);
  const bits = await s.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: DERIVE_SALT as unknown as BufferSource,
      info: info as unknown as BufferSource,
    },
    baseKey,
    DERIVED_KEY_BYTES * 8,
  );
  return new Uint8Array(bits);
}

/**
 * Derive the per-context Semaphore v4 identity from a device seed. The returned
 * `DerivedIdentity` satisfies the `SemaphoreIdentityLike` contract the membership
 * layer consumes (`commitment` decimal string + opaque `native` handle) and also
 * exposes the concrete v4 `Identity` for in-world callers.
 *
 * Determinism: same (deviceSeed, context) -> identical private key -> identical
 * commitment. Distinct context -> distinct, unlinkable commitment.
 */
export async function deriveIdentity(
  deviceSeed: Uint8Array,
  context: ContextId,
): Promise<DerivedIdentity> {
  const privateKey = await derivePrivateKeyBytes(deviceSeed, context);
  const identity = new Identity(privateKey);
  const commitment = identity.commitment.toString();
  return {
    context,
    identity,
    native: identity,
    commitment,
  };
}

/**
 * Derive the identities for many contexts from one device seed, in parallel.
 * Order matches the input `contexts` order.
 */
export async function deriveIdentities(
  deviceSeed: Uint8Array,
  contexts: readonly ContextId[],
): Promise<DerivedIdentity[]> {
  return Promise.all(contexts.map((c) => deriveIdentity(deviceSeed, c)));
}
