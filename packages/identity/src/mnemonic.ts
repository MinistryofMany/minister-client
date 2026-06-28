import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { DEVICE_SEED_BYTES } from "./derive.js";

/**
 * BIP-39 mnemonic backup of the device seed.
 *
 * Ported from FreedInk `src/lib/client/vault.ts` (`exportMnemonic` /
 * `identityFromMnemonic`), but applied to the 32-byte DEVICE SEED rather than a
 * single Semaphore identity - because the device seed is the single value the
 * user backs up to recover ALL their per-context identities. A 32-byte (256-bit)
 * entropy maps to a 24-word English BIP-39 mnemonic with checksum.
 *
 * This is the recovery path that is independent of the password-encrypted vault:
 * if the user loses their device AND password, the 24 words regenerate the same
 * device seed, which re-derives every per-context identity (same commitments).
 */

/**
 * Encode a 32-byte device seed as a 24-word BIP-39 English mnemonic. Throws if the
 * seed is not exactly 32 bytes (BIP-39 entropy must be 128-256 bits in 32-bit
 * steps; we fix the seed at 256 bits).
 */
export function seedToMnemonic(deviceSeed: Uint8Array): string {
  if (!(deviceSeed instanceof Uint8Array) || deviceSeed.byteLength !== DEVICE_SEED_BYTES) {
    throw new Error(`deviceSeed must be a ${DEVICE_SEED_BYTES}-byte Uint8Array.`);
  }
  return entropyToMnemonic(deviceSeed, wordlist);
}

/**
 * Decode a 24-word BIP-39 mnemonic back to the 32-byte device seed. Validates the
 * words and checksum first (throws on a bad mnemonic). Whitespace-tolerant and
 * case-insensitive, matching the donor's normalization.
 */
export function mnemonicToSeed(mnemonic: string): Uint8Array {
  const normalized = mnemonic.trim().split(/\s+/).join(" ").toLowerCase();
  if (!validateMnemonic(normalized, wordlist)) {
    throw new Error("Invalid mnemonic: words or checksum do not match BIP-39.");
  }
  const entropy = mnemonicToEntropy(normalized, wordlist);
  if (entropy.byteLength !== DEVICE_SEED_BYTES) {
    throw new Error(
      `Mnemonic decodes to ${entropy.byteLength} bytes; expected a ${DEVICE_SEED_BYTES}-byte device seed.`,
    );
  }
  return entropy;
}

/** True iff `mnemonic` is a structurally valid BIP-39 English mnemonic (words + checksum). */
export function isValidMnemonic(mnemonic: string): boolean {
  const normalized = mnemonic.trim().split(/\s+/).join(" ").toLowerCase();
  return validateMnemonic(normalized, wordlist);
}
