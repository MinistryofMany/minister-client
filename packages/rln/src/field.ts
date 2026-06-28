import { poseidon1, poseidon2 } from "poseidon-lite";

export function str2BigInt(str: string): bigint {
  if (str.length === 0) return BigInt(0);
  const bytes = new TextEncoder().encode(str);
  let hex = "0x";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, "0");
  }
  return BigInt(hex);
}

/** Deterministic id from a server id and a name (Poseidon). */
export function genId(
  serverID: string | bigint | number,
  roomName: string | bigint | number,
): bigint {
  if (typeof roomName === "string") {
    return poseidon2([BigInt(serverID), str2BigInt(roomName)]);
  }
  return poseidon2([BigInt(serverID), BigInt(roomName)]);
}

export function randomBigInt(bits = 253): bigint {
  const byteCount = Math.ceil(bits / 8);
  const bytes = new Uint8Array(byteCount);
  globalThis.crypto.getRandomValues(bytes);
  const excessBits = byteCount * 8 - bits;
  if (excessBits > 0) {
    bytes[0] = bytes[0]! & ((1 << (8 - excessBits)) - 1);
  }
  let hex = "0x";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, "0");
  }
  return BigInt(hex);
}

/** Merkle leaf for a non-admin member: poseidon2(identityCommitment, userMessageLimit). */
export function getRateCommitmentHash(
  identityCommitment: bigint,
  userMessageLimit: number | bigint,
): bigint {
  return poseidon2([identityCommitment, userMessageLimit]);
}

/** Internal message hash (Poseidon of the utf8 -> bigint message). Distinct from the RLN signal hash. */
export function getMessageHash(message: string): bigint {
  return poseidon1([str2BigInt(message)]);
}
