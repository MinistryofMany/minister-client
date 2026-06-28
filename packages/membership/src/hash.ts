// Shared field-hashing helpers.

/**
 * BN254 scalar field prime, the field Semaphore signals must live in. Identical
 * to FreedInk's SEMAPHORE_FIELD and @minister/rln's SNARK_FIELD_SIZE; kept here
 * so the hash output is byte-for-byte FreedInk's.
 */
const SEMAPHORE_FIELD = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

/**
 * Hash an arbitrary string into a bigint that fits in the Semaphore field.
 * Reproduces FreedInk's `hashToField` EXACTLY (SHA-256 of the UTF-8 bytes,
 * interpreted big-endian as a bigint, reduced mod the field), so a proof's
 * scope/message fields match what a FreedInk verifier re-derives. Used by the
 * Semaphore engine for `scope` and `message`.
 */
export async function hashToField(message: string): Promise<bigint> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("WebCrypto (globalThis.crypto.subtle) is not available for hashToField.");
  }
  const data = new TextEncoder().encode(message);
  const buf = await subtle.digest("SHA-256", data as unknown as BufferSource);
  const hex = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return BigInt("0x" + hex) % SEMAPHORE_FIELD;
}
