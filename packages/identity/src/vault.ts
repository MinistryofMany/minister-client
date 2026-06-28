import { DEVICE_SEED_BYTES } from "./derive.js";

/**
 * Framework-agnostic encrypted device-seed vault.
 *
 * Ported from the two proven donor implementations - FreedInk
 * `src/lib/client/vault.ts` and Discreetly `apps/web/src/lib/identity.ts` - with
 * their app couplings removed: NO `$app/environment`, NO `localStorage`, NO
 * SvelteKit/Next imports. Storage is the app's job; this module only turns a
 * device seed + password into a portable encrypted envelope and back.
 *
 * KDF:  PBKDF2-HMAC-SHA-256 (WebCrypto, via globalThis.crypto).
 * AEAD: AES-GCM-256 (the auth tag detects a wrong password / tamper -> throws).
 *
 * What is encrypted is the 32-byte DEVICE SEED (not a single identity): every
 * per-context Semaphore identity is re-derived from it (see `deriveIdentity`), so
 * one vault unlock restores the user's whole context set. The plaintext seed and
 * the derived key are NEVER persisted and NEVER leave the device.
 */

/** PBKDF2 iteration count. 600k matches FreedInk's vault and clears the OWASP
 *  PBKDF2-SHA256 floor; both donor apps use >= 210k. */
export const PBKDF2_ITERATIONS = 600_000;
const PBKDF2_HASH = "SHA-256" as const;
const SALT_BYTES = 16;
const IV_BYTES = 12; // AES-GCM nonce
const AES_KEY_BITS = 256;

/** Encrypted-at-rest envelope. base64 fields are portable as JSON (export/backup). */
export interface SeedVault {
  readonly v: 1;
  readonly kdf: "PBKDF2";
  readonly hash: "SHA-256";
  readonly iterations: number;
  /** base64 PBKDF2 salt. */
  readonly salt: string;
  /** base64 AES-GCM nonce (iv). */
  readonly iv: string;
  /** base64 AES-GCM ciphertext, including the 16-byte auth tag. */
  readonly ciphertext: string;
}

export class VaultError extends Error {}
export class WrongPasswordError extends VaultError {
  constructor() {
    super("Incorrect password or corrupted vault data.");
    this.name = "WrongPasswordError";
  }
}

function subtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) {
    throw new VaultError("WebCrypto (globalThis.crypto.subtle) is not available in this environment.");
  }
  return c.subtle;
}

function randomBytes(n: number): Uint8Array {
  const c = globalThis.crypto;
  if (!c?.getRandomValues) {
    throw new VaultError("WebCrypto (globalThis.crypto.getRandomValues) is not available.");
  }
  return c.getRandomValues(new Uint8Array(n));
}

// --- base64 helpers (no Buffer dependency; identical encoding to both donors) ---

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

async function deriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  const s = subtle();
  const baseKey = await s.importKey(
    "raw",
    new TextEncoder().encode(password) as unknown as BufferSource,
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return s.deriveKey(
    { name: "PBKDF2", salt: salt as unknown as BufferSource, iterations, hash: PBKDF2_HASH },
    baseKey,
    { name: "AES-GCM", length: AES_KEY_BITS },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Encrypt a 32-byte device seed under `password`. Returns a portable envelope. */
export async function encryptSeed(deviceSeed: Uint8Array, password: string): Promise<SeedVault> {
  if (!(deviceSeed instanceof Uint8Array) || deviceSeed.byteLength !== DEVICE_SEED_BYTES) {
    throw new VaultError(`deviceSeed must be a ${DEVICE_SEED_BYTES}-byte Uint8Array.`);
  }
  if (password.length === 0) throw new VaultError("Password must not be empty.");
  const s = subtle();
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const key = await deriveKey(password, salt, PBKDF2_ITERATIONS);
  const ct = await s.encrypt(
    { name: "AES-GCM", iv: iv as unknown as BufferSource },
    key,
    deviceSeed as unknown as BufferSource,
  );
  return {
    v: 1,
    kdf: "PBKDF2",
    hash: PBKDF2_HASH,
    iterations: PBKDF2_ITERATIONS,
    salt: toBase64(salt),
    iv: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(ct)),
  };
}

/**
 * Decrypt a vault envelope back to the device seed. Throws `WrongPasswordError`
 * on a bad password or tampered ciphertext (AES-GCM auth-tag failure), exactly
 * like the donor `decryptIdentity`.
 */
export async function decryptSeed(vault: SeedVault, password: string): Promise<Uint8Array> {
  if (vault.v !== 1) throw new VaultError(`Unsupported vault version: ${String(vault.v)}`);
  const s = subtle();
  const salt = fromBase64(vault.salt);
  const iv = fromBase64(vault.iv);
  const ciphertext = fromBase64(vault.ciphertext);
  const key = await deriveKey(password, salt, vault.iterations);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await s.decrypt(
      { name: "AES-GCM", iv: iv as unknown as BufferSource },
      key,
      ciphertext as unknown as BufferSource,
    );
  } catch {
    // AES-GCM auth-tag failure -> wrong password or corrupted data.
    throw new WrongPasswordError();
  }
  const seed = new Uint8Array(plaintext);
  if (seed.byteLength !== DEVICE_SEED_BYTES) {
    throw new VaultError(`Decrypted seed has wrong size: ${seed.byteLength} bytes.`);
  }
  return seed;
}

/** Serialize a vault envelope to a JSON string (for download / persistence). */
export function vaultToJson(vault: SeedVault): string {
  return JSON.stringify(vault);
}

/** Parse a vault envelope from a JSON string. Throws `VaultError` on bad JSON/shape. */
export function vaultFromJson(json: string): SeedVault {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new VaultError("Vault is not valid JSON.");
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    (parsed as { v?: unknown }).v !== 1 ||
    typeof (parsed as { ciphertext?: unknown }).ciphertext !== "string" ||
    typeof (parsed as { salt?: unknown }).salt !== "string" ||
    typeof (parsed as { iv?: unknown }).iv !== "string" ||
    typeof (parsed as { iterations?: unknown }).iterations !== "number"
  ) {
    throw new VaultError("Vault JSON is missing required fields or has the wrong shape.");
  }
  return parsed as SeedVault;
}
