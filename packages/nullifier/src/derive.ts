import { poseidon2 } from "poseidon-lite";

/**
 * The BN254 (alt_bn128) scalar field order. Every nullifier and field element
 * is reduced modulo this prime so it is a valid Poseidon/SNARK input.
 *
 * This value is load-bearing: it must stay byte-for-byte identical across the
 * ecosystem (Discreetly `gate/join-nullifier.ts`, the Deforum user-sub-forum
 * nullifier) or two implementations of "the same" nullifier would diverge and
 * silently break membership/ban anchoring. Covered by the golden-vector test.
 */
export const FIELD = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

/**
 * Reduce an arbitrary string (e.g. a Minister pairwise `sub`) to a field
 * element by accumulating its UTF-8 bytes big-endian, base 256, modulo FIELD.
 *
 * This is intentionally NOT a hash: it is the exact reduction Discreetly's
 * `toField` performs, preserved byte-for-byte so the derived nullifier matches
 * existing on-chain-style anchors. Do not "improve" it; a different reduction
 * is a different nullifier namespace.
 *
 * NOTE: this is a byte-reduction for ARBITRARY strings; it is not meant to
 * re-reduce a value that is ALREADY a field element (e.g. a decimal field-string
 * nullifier). For that, take the numeric value (`BigInt(n) % FIELD`) and use
 * `deriveContextNullifierFromField` - feeding the decimal STRING through
 * `toField` would re-hash its digits and is not the identity on field elements.
 */
export function toField(s: string): bigint {
  // Cross-primitive guard (M3). This Poseidon/BN254 nullifier is PERMANENTLY
  // DISTINCT from Minister's gating nullifier (`mnv1:...`, HMAC/VOPRF,
  // plaintext-compare, NOT circuit-usable). The two must never bridge. The
  // TypeScript brand blocks the assignment one direction, but a branded value
  // widens back to `string`, so `toField(badge.nullifier)` would type-check and
  // silently produce a valid-looking field element. Reject it at runtime: a
  // future circuit-usable credential nullifier must be a NEW construction, not a
  // reduction of the gating tag.
  if (/^mnv1:/.test(s)) {
    throw new Error(
      "toField refuses an `mnv1:` gating nullifier: it is not interchangeable with the " +
        "Poseidon/BN254 primitive (M3). Derive a new nullifier, never bridge from mnv1.",
    );
  }
  let acc = 0n;
  for (const byte of new TextEncoder().encode(s)) acc = (acc * 256n + BigInt(byte)) % FIELD;
  return acc;
}

/**
 * Context-agnostic, two-layer nullifier:
 *
 *   poseidon2(toField(sub), contextId % FIELD)
 *
 * Stable for a given (sub, contextId); unlinkable across contexts without the
 * `sub`. ZK-friendly (Poseidon over the BN254 field).
 *
 * - `sub` is the per-relying-party stable subject (Minister pairwise `sub`).
 * - `contextId` is the scope this nullifier is anchored to, as a field element.
 *   In Discreetly this is the room's RLN identifier; in Deforum it is the
 *   sub-forum id. It is reduced modulo FIELD so any bigint is accepted.
 *
 * This generalizes Discreetly's `joinNullifier(sub, rlnIdentifier)` and the
 * Deforum user-sub-forum nullifier `poseidon2(toField(sub), subforumId)`: all
 * three are the same function, so their outputs are identical for equal inputs
 * (asserted by the cross-impl test).
 */
export function deriveContextNullifier(sub: string, contextId: bigint): bigint {
  return poseidon2([toField(sub), contextId % FIELD]);
}

/**
 * Like `deriveContextNullifier`, but the first input is ALREADY a field element
 * (e.g. a membership proof's nullifier), not an arbitrary string. The value is
 * reduced modulo FIELD as a numeric VALUE rather than re-byte-reduced through
 * `toField` on its decimal string:
 *
 *   poseidon2(value % FIELD, contextId % FIELD)
 *
 * Use this for a secret that is itself a field-string nullifier, so that two
 * distinct field elements stay distinct (running them through `toField` would
 * re-hash their decimal digits and is not the identity on field elements).
 */
export function deriveContextNullifierFromField(value: bigint, contextId: bigint): bigint {
  return poseidon2([value % FIELD, contextId % FIELD]);
}
