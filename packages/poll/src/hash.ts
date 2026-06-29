// Portable SHA-256 over the Web Crypto SubtleCrypto API (globalThis.crypto.subtle),
// available in browsers and Node 20+. Used for the commit-reveal binding hash and
// the raffle public-seed derivation. Framework-agnostic: no node:crypto import, so
// the same code runs in a server, a worker, or the browser.

const enc = new TextEncoder();

function toHex(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** SHA-256 of a UTF-8 string, lower-case hex. */
export async function sha256Hex(input: string): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error(
      "@ministryofmany/poll: globalThis.crypto.subtle is unavailable (need Node 20+ or a browser)",
    );
  }
  const digest = await globalThis.crypto.subtle.digest("SHA-256", enc.encode(input));
  return toHex(digest);
}

/**
 * ASCII unit separator (0x1f) - the field delimiter for domain-separated hashes.
 * Written via fromCharCode so the control byte is explicit in source rather than
 * an invisible literal.
 */
const US = String.fromCharCode(0x1f);

/**
 * Domain-separated commit hash for commit-reveal:
 *   H("minister-poll/commit" || US || choice || US || salt)
 * The unit-separator byte (0x1f) delimits the fields, so two different
 * (choice, salt) pairs cannot collide by concatenation ambiguity (e.g. ("ab","c")
 * vs ("a","bc") would otherwise hash the same plain concatenation). The domain tag
 * prevents this hash from being mistaken for any other hash in the system.
 */
export async function commitHash(choice: string, salt: string): Promise<string> {
  return sha256Hex(`minister-poll/commit${US}${choice}${US}${salt}`);
}

/**
 * Domain-separated commitment over a raffle seed preimage:
 *   H("minister-poll/seed-commit" || US || seedPreimage)
 * Published at poll create (as RaffleConfig.seedCommit) before entries open; the
 * preimage is revealed at resolve time and re-hashed here to check it matches.
 * The domain tag keeps this hash distinct from the commit-reveal vote hash and
 * the draw hash so the three cannot be cross-substituted.
 */
export async function seedCommitHash(seedPreimage: string): Promise<string> {
  return sha256Hex(`minister-poll/seed-commit${US}${seedPreimage}`);
}

/**
 * Derive a uniform integer in [0, n) from a public seed, by hashing
 * H("minister-poll/draw" || US || seed || US || counter) until a value below the
 * largest multiple of `n` is found (rejection sampling), eliminating modulo bias.
 * Deterministic for a given (seed, n): anyone with the public seed recomputes the
 * same index. `n` must be a positive safe integer.
 */
export async function uniformIndex(seed: string, n: number): Promise<number> {
  if (!Number.isInteger(n) || n <= 0 || n > Number.MAX_SAFE_INTEGER) {
    throw new Error(`uniformIndex: n must be a positive safe integer, got ${n}`);
  }
  // 53-bit space (matches JS safe-integer range). Reject the top partial bucket
  // so every residue class is equally likely.
  const space = 2 ** 53;
  const limit = space - (space % n);
  for (let counter = 0; counter < 1_000_000; counter++) {
    const h = await sha256Hex(`minister-poll/draw${US}${seed}${US}${counter}`);
    // Take the top 53 bits of the digest as an integer.
    const value = Number(BigInt("0x" + h.slice(0, 14)) & ((1n << 53n) - 1n));
    if (value < limit) return value % n;
  }
  // Unreachable in practice: P(reject) < 0.5 per round, so a million rounds is
  // astronomically safe. Fail closed rather than loop forever.
  throw new Error("uniformIndex: exhausted rejection sampling (unreachable)");
}
