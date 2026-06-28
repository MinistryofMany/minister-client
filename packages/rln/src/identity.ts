import { poseidon1, poseidon2 } from "poseidon-lite";

/**
 * The v3 identity layer that RLN needs, expressed on the bigint-only surface.
 *
 * Semaphore v3's `Identity` derives a single field-element `secret` from two
 * random secrets (`trapdoor`, `nullifier`) and a commitment from that secret:
 *
 *   secret     = poseidon2([nullifier, trapdoor])   // note: nullifier FIRST
 *   commitment = poseidon1([secret])
 *
 * (Verified byte-for-byte against @semaphore-protocol/identity@3.15.0:
 *  the constructor computes `_secret = poseidon2([_nullifier, _trapdoor])` and
 *  `_commitment = poseidon1([_secret])`.)
 *
 * This package exposes that derivation directly so RLN consumers never hold a
 * Semaphore `Identity` object: they keep the raw `secret` (the RLN
 * `identitySecret` circuit input) and the `commitment` (its poseidon1 image,
 * which Shamir collision-recovery maps back to).
 */

/** A v3 identity reduced to bigints. `secret` is the RLN identitySecret. */
export interface RlnIdentitySecrets {
  readonly trapdoor: bigint;
  readonly nullifier: bigint;
  readonly secret: bigint;
  readonly commitment: bigint;
}

/**
 * Derive the RLN identity secret from the v3 (trapdoor, nullifier) pair.
 * `secret = poseidon2([nullifier, trapdoor])` - the nullifier is hashed FIRST,
 * matching Semaphore v3 exactly. Getting this order wrong silently breaks every
 * commitment and the RLN circuit binding.
 */
export function deriveSecret(trapdoor: bigint, nullifier: bigint): bigint {
  return poseidon2([nullifier, trapdoor]);
}

/** Derive the identity commitment from the RLN identity secret: poseidon1([secret]). */
export function deriveCommitment(secret: bigint): bigint {
  return poseidon1([secret]);
}

/**
 * One field element of a v3 serialized identity. Semaphore v3's
 * `Identity.toString()` emits `["0x"+trapdoor.toString(16), "0x"+nullifier.toString(16)]`,
 * so the on-disk values are 0x-prefixed hex strings. The v3 constructor parses
 * each element through `BigNumber.from`, which also accepts decimal strings and
 * safe-integer numbers; `BigInt(...)` reproduces that for every value a real
 * serialized blob can contain.
 */
export type SerializedField = string | number | bigint;

function toField(value: SerializedField, label: string): bigint {
  try {
    return BigInt(value);
  } catch {
    throw new Error(`Invalid serialized identity ${label}: ${String(value)}`);
  }
}

/**
 * Deserialize a Semaphore v3 `Identity.toString()` blob - JSON `[trapdoor, nullifier]` -
 * to the raw bigint secrets. This is the migration path for existing Discreetly
 * localStorage identities: an existing `[trapdoor, nullifier]` blob round-trips
 * to the SAME poseidon1 commitment, so members keep working with no re-enrollment.
 *
 * Accepts either the JSON string form or the already-parsed two-element array.
 * Throws on any shape that is not a 2-element [trapdoor, nullifier] tuple.
 */
export function deserializeV3Identity(
  serialized: string | readonly [SerializedField, SerializedField],
): RlnIdentitySecrets {
  let tuple: unknown;
  if (typeof serialized === "string") {
    try {
      tuple = JSON.parse(serialized);
    } catch {
      throw new Error("Serialized v3 identity is not valid JSON.");
    }
  } else {
    tuple = serialized;
  }

  if (!Array.isArray(tuple) || tuple.length !== 2) {
    throw new Error("Serialized v3 identity must be a [trapdoor, nullifier] tuple.");
  }

  const trapdoor = toField(tuple[0] as SerializedField, "trapdoor");
  const nullifier = toField(tuple[1] as SerializedField, "nullifier");
  const secret = deriveSecret(trapdoor, nullifier);
  const commitment = deriveCommitment(secret);
  return { trapdoor, nullifier, secret, commitment };
}

/**
 * Re-serialize secrets back into the canonical Semaphore v3 `Identity.toString()`
 * form (`["0x"+trapdoor, "0x"+nullifier]` hex). Lets a consumer round-trip a
 * migrated identity to the exact byte form v3 would have written.
 */
export function serializeV3Identity(trapdoor: bigint, nullifier: bigint): string {
  return JSON.stringify([`0x${trapdoor.toString(16)}`, `0x${nullifier.toString(16)}`]);
}
