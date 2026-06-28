import { hexlify } from "@ethersproject/bytes";
import { toUtf8Bytes } from "@ethersproject/strings";
import { keccak256 } from "@ethersproject/keccak256";

/** RLN signal hash: keccak256 of the utf8 signal, shifted right 8 bits to fit the field. */
export function calculateSignalHash(signal: string): bigint {
  const converted = hexlify(toUtf8Bytes(signal));
  return BigInt(keccak256(converted)) >> BigInt(8);
}
