# @ministryofmany/nullifier

Poseidon/BN254 context nullifier — the **circuit-usable, account-anchored**
nullifier primitive for the Ministry ecosystem (Discreetly RLN/membership, the
Deforum user-sub-forum anchor). It derives a SNARK-friendly field element that is
stable per `(sub, contextId)` and unlinkable across contexts without the `sub`.

```ts
import { deriveContextNullifier } from "@ministryofmany/nullifier";

// poseidon2(toField(sub), contextId % FIELD)
const nul = deriveContextNullifier(pairwiseSub, roomRlnIdentifier);
```

`toField` reduces an arbitrary string to a BN254 field element by big-endian
base-256 accumulation mod `FIELD` (NOT a hash — it is the exact reduction
Discreetly's `toField` performs, preserved byte-for-byte). Use
`deriveContextNullifierFromField` when the first input is ALREADY a field element
(e.g. a membership proof's nullifier) rather than an arbitrary string.

## Two nullifier primitives — permanently distinct, never bridge

This ecosystem has **two** nullifiers. They are NOT interchangeable, there is no
conversion between them, and mixing them is a correctness bug:

| | `@ministryofmany/nullifier` (this package) | Minister gating nullifier (`MinisterGatingNullifier`, `mnv1:...`) |
|---|---|---|
| Math | Poseidon / BN254 (`poseidon2(toField(sub), contextId)`) | RFC 9497 VOPRF (stage 1) + HMAC-SHA256 (stage 2) |
| Anchor | the per-RP `sub` (account-anchored) | the credential (email, github id) |
| Circuit-usable | **YES** — SNARK-provable (RLN, membership) | **NO** — gating-only, plaintext compare |
| Catches | same-account-across-contexts linkage | same-credential-across-accounts Sybil |
| Wire form | decimal BN254 field string | `mnv1:` + base64url |

**Never bridge from `mnv1:`.** The gating nullifier is a plaintext gating tag; it
is not a field element and must never be fed into `toField`, `poseidon2`, or any
circuit input. Doing so would produce a valid-LOOKING field element that silently
conflates two unrelated anonymity namespaces. `toField` enforces this at runtime:
it **throws** on any input matching `^mnv1:`. A future circuit-usable *credential*
nullifier must be a NEW Poseidon construction over an appropriate anchor, not a
reduction of the gating tag.

The gating nullifier lives on `@minister/client`'s `VerifiedBadge.nullifier` and
is documented in `src/types.ts` (`MinisterGatingNullifier`). Gate on it for
"one credential" (Sybil dedup, ban persistence); do not treat it as a
unique-human oracle.
