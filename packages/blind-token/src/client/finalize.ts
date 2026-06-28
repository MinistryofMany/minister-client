// Chromium-safe finalize for partially-blind RSA (CLIENT side). Lifted
// BYTE-FOR-BYTE from FreedInk's src/lib/client/vote-token.ts:37-215 (the
// finalizeInBrowser machinery + mgf1 + emsaPssVerify + deriveMetadataExponent),
// generalized only at the surface (it works against an already-imported public
// CryptoKey + raw info bytes, exactly as FreedInk's internal helper did).
//
// WHY THIS EXISTS: @cloudflare/blindrsa-ts@0.4.6 PartiallyBlindRSA.finalize()
// performs its RFC 9474 signature self-check by importing the PER-METADATA
// DERIVED public key into WebCrypto (crypto.subtle.importKey('jwk', ...) then
// crypto.subtle.verify). The partially-blind scheme derives a public exponent
// e' that is modulus_bits/2 = 1024 bits long. Chromium's WebCrypto (BoringSSL)
// rejects importing an RSA public key whose exponent exceeds ~32 bits with an
// empty-message OperationError (chromium issue 340178598); Node's WebCrypto
// (OpenSSL) has no such bound, which is why the library's finalize passes under
// Node but throws in a real browser. The bug is present in upstream HEAD too, so
// a version bump does not fix it.
//
// WHAT WE DO INSTEAD: compute the unblinded signature with the exact same
// arithmetic the library uses (s = blind_sig * r^-1 mod n), then run the RFC 9474
// finalize self-check (EMSA-PSS-VERIFY against the derived public key) using the
// library's own bignum primitives - never importing the large-exponent key into
// WebCrypto. The produced signature bytes are BYTE-IDENTICAL to the library's
// finalize output (proven by the byte-diff unit test), so the wire scheme
// (RSAPBSSA.SHA384.PSS.Randomized, public metadata <infoPrefix>:<actionKey>) is
// unchanged: the server verifies with the unmodified library, and the Signet
// signing service stays interop-compatible. We do NOT touch what is signed or
// what is verified - only the client-side import mechanics of the self-check.
//
// The self-check is preserved (not skipped): a malformed/garbled blind signature
// from a buggy or hostile issuer is caught here, before the user spends their
// one-per-tuple token on a redemption the server would reject anyway.

// Deep imports into the library's INTERNAL primitives. @cloudflare/blindrsa-ts
// ships these as ESM with .d.ts and has NO `exports` map, so the subpath is
// resolvable + typed. It is pinned at EXACTLY 0.4.6 (peer dep); these paths are
// not a stable public API and are the highest-fragility coupling in the package.
// The Chromium-drift tripwire test (test/chromium-internals.test.ts) fails loudly
// if these paths or the finalize byte-output ever drift. sjcl is the library's
// bundled bignum; util holds the same RSAVP1 / i2osp / os2ip / int_to_bytes /
// joinAll the library uses everywhere, so reusing them keeps us bit-for-bit
// aligned with suite.finalize.
async function loadFinalizeDeps() {
  const [{ default: sjcl }, util] = await Promise.all([
    import("@cloudflare/blindrsa-ts/lib/src/sjcl/index.js"),
    import("@cloudflare/blindrsa-ts/lib/src/util.js"),
  ]);
  return { sjcl, ...util };
}

type FinalizeDeps = Awaited<ReturnType<typeof loadFinalizeDeps>>;

// SHA-384 PSS parameters of the suite (RSAPBSSA.SHA384.PSS.Randomized). These
// MUST match the suite the server uses; they are fixed by the scheme and never
// vary at runtime, so we hard-code them rather than reading suite.params (an
// internal field).
const HASH = "SHA-384";
const H_LEN = 48; // SHA-384 digest bytes
const SALT_LEN = 48; // PSS salt length for the SHA384 variant

// MGF1 (RFC 8017 B.2.1) over SHA-384, used by EMSA-PSS-VERIFY.
async function mgf1(
  sjcl: FinalizeDeps["sjcl"],
  i2osp: FinalizeDeps["i2osp"],
  joinAll: FinalizeDeps["joinAll"],
  seed: Uint8Array,
  maskLen: number,
): Promise<Uint8Array> {
  let t = new Uint8Array(0);
  let counter = 0;
  while (t.length < maskLen) {
    const c = i2osp(new sjcl.bn(counter), 4);
    const h = new Uint8Array(
      await crypto.subtle.digest(HASH, joinAll([seed, c]).slice().buffer),
    );
    t = joinAll([t, h]);
    counter++;
  }
  return t.slice(0, maskLen);
}

// EMSA-PSS-VERIFY (RFC 8017 9.1.2). Returns whether the encoded message EM is a
// valid PSS encoding of M for the given emBits. Constant-time on the final hash
// compare; the structural checks short-circuit but reveal nothing secret (EM is
// derived from the public signature). This is the same predicate the library's
// crypto.subtle.verify computes - we evaluate it arithmetically so no
// large-exponent key import is needed.
async function emsaPssVerify(
  deps: FinalizeDeps,
  m: Uint8Array,
  em: Uint8Array,
  emBits: number,
): Promise<boolean> {
  const { sjcl, i2osp, joinAll } = deps;
  const emLen = Math.ceil(emBits / 8);
  const mHash = new Uint8Array(await crypto.subtle.digest(HASH, m.slice().buffer));
  if (emLen < H_LEN + SALT_LEN + 2) return false;
  if (em[emLen - 1] !== 0xbc) return false;
  const maskedDB = em.slice(0, emLen - H_LEN - 1);
  const h = em.slice(emLen - H_LEN - 1, emLen - 1);
  const zeroBits = 8 * emLen - emBits;
  const topMask = zeroBits === 0 ? 0 : (0xff << (8 - zeroBits)) & 0xff;
  if ((maskedDB[0]! & topMask) !== 0) return false;
  const dbMask = await mgf1(sjcl, i2osp, joinAll, h, emLen - H_LEN - 1);
  const db = new Uint8Array(maskedDB.length);
  for (let i = 0; i < db.length; i++) db[i] = maskedDB[i]! ^ dbMask[i]!;
  db[0]! &= 0xff >> zeroBits;
  const psLen = emLen - H_LEN - SALT_LEN - 2;
  for (let i = 0; i < psLen; i++) if (db[i] !== 0x00) return false;
  if (db[psLen] !== 0x01) return false;
  const salt = db.slice(db.length - SALT_LEN);
  const hPrime = new Uint8Array(
    await crypto.subtle.digest(
      HASH,
      joinAll([new Uint8Array(8), mHash, salt]).slice().buffer,
    ),
  );
  if (h.length !== hPrime.length) return false;
  let diff = 0;
  for (let i = 0; i < h.length; i++) diff |= h[i]! ^ hPrime[i]!;
  return diff === 0;
}

// DerivePublicKey for public metadata (draft-amjad-cfrg-partially-blind-rsa,
// mirrored from PartiallyBlindRSA.derivePublicKey, partially_blindrsa.js:249-273).
// We inline it rather than call the library method because that method is declared
// `private` in the type surface. The output e' is byte-identical to the library's
// (asserted by the byte-diff test on the whole finalize), so this stays
// wire-compatible.
async function deriveMetadataExponent(
  deps: FinalizeDeps,
  n: ReturnType<FinalizeDeps["os2ip"]>,
  info: Uint8Array,
) {
  const { sjcl, i2osp, joinAll } = deps;
  const hkdfInput = joinAll([
    new TextEncoder().encode("key"),
    info,
    new Uint8Array([0x00]),
  ]);
  const hkdfSalt = i2osp(n, n.bitLength() >> 3);
  const lambdaLen = n.bitLength() >> 4; // modulus_len_bytes / 2
  const hkdfLen = lambdaLen + 16;
  const expanded = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: HASH,
        info: new TextEncoder().encode("PBRSA"),
        salt: hkdfSalt.slice().buffer,
      },
      await crypto.subtle.importKey("raw", hkdfInput, "HKDF", false, ["deriveBits"]),
      hkdfLen * 8,
    ),
  );
  expanded[0]! &= 0x3f; // clear two top bits
  expanded[lambdaLen - 1]! |= 0x01; // set bottom bit (force odd)
  return sjcl.bn.fromBits(
    sjcl.codec.bytes.toBits(Array.from(expanded.slice(0, lambdaLen))),
  );
}

// Chromium-safe replacement for suite.finalize(). Mirrors
// PartiallyBlindRSA.finalize (partially_blindrsa.js:138-185) byte-for-byte for
// the signature, swapping only its WebCrypto derived-key self-check for an
// arithmetic EMSA-PSS-VERIFY (see the WHY block above). `pub` is the issuer's
// public RSA-PSS CryptoKey (extractable, exported as JWK to recover the modulus);
// `info` is the buildInfo() bytes (<infoPrefix>:<actionKey>).
export async function finalizeInBrowser(
  pub: CryptoKey,
  prepared: Uint8Array,
  info: Uint8Array,
  blindSig: Uint8Array,
  inv: Uint8Array,
): Promise<Uint8Array> {
  const deps = await loadFinalizeDeps();
  const { sjcl, os2ip, i2osp, int_to_bytes, rsavp1, joinAll } = deps;

  const jwk = await crypto.subtle.exportKey("jwk", pub);
  if (!jwk.n) throw new Error("public key missing modulus");
  const n = sjcl.bn.fromBits(sjcl.codec.base64url.toBits(jwk.n));
  const kLen = Math.ceil((pub.algorithm as RsaHashedKeyAlgorithm).modulusLength / 8);

  // 0-2: sizes + recover z. (RFC 9474 finalize steps 0-2.)
  if (inv.length !== kLen) throw new Error("unexpected input size");
  if (blindSig.length !== kLen) throw new Error("unexpected input size");
  const rInv = os2ip(inv);
  const z = os2ip(blindSig);

  // 3-4: s = z * rInv mod n ; sig = i2osp(s, kLen). Identical to the library.
  const s = z.mulmod(rInv, n);
  const sig = i2osp(s, kLen);

  // 5: msg_prime = concat("msg", int_to_bytes(len(info),4), info, prepared).
  const msgPrime = joinAll([
    new TextEncoder().encode("msg"),
    int_to_bytes(info.length, 4),
    info,
    prepared,
  ]);

  // 6-8: derive e' for this metadata, then EMSA-PSS-VERIFY the unblinded sig
  // arithmetically (rsavp1 + EMSA-PSS-VERIFY) - no large-exponent key import.
  const ePrime = await deriveMetadataExponent(deps, n, info);
  const emBits = n.bitLength() - 1; // matches emsa_pss_encode(..., modulusLength-1) in blind()
  const recovered = i2osp(rsavp1({ e: ePrime, n }, os2ip(sig)), Math.ceil(emBits / 8));
  if (!(await emsaPssVerify(deps, msgPrime, recovered, emBits))) {
    throw new Error("invalid signature");
  }
  return sig;
}
