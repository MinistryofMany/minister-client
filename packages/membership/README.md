# @ministryofmany/membership

Semaphore group-membership proofs - per-context Merkle group, snapshots,
client-side proof generation, server-side verify - that three structurally different apps
(FreedInk, Discreetly, Deforum) back with their own storage and tree model
WITHOUT changing their on-the-wire proof shape or their database.

It consumes:

- [`@ministryofmany/identity`](../identity) - pure Semaphore **v4**: per-context
  identity derivation + the structural `SemaphoreIdentityLike` contract. The
  `semaphoreEngine` runs over it.
- [`@ministryofmany/rln`](../rln) - the Semaphore **v3 + RLN** quarantine island
  (bigint-only surface). The `rlnEngine` runs over it; no v3 type leaks into this
  package's public surface. **Optional peer dependency, lazy-loaded:** the rln
  engine lives behind `engineFor("rln")` / `loadRlnEngine()` (a memoized dynamic
  import) and the static `@ministryofmany/membership/rln` subpath - it is NOT
  exported from the package root - so a semaphore-only consumer neither installs
  nor evaluates the rlnjs island. An RLN consumer installs `@ministryofmany/rln`
  alongside this package.

Replay / uniqueness is **not** here: `verify()` returns the nullifier and the app
records it (via [`@ministryofmany/nullifier`](../nullifier)).

## Layers

```
  app code          app ORM (Drizzle / Prisma)        app artifact loader
                    │ implements           │ implements      │ implements
  seams      MerkleGroupProvider     SnapshotStore        ArtifactSource
             (mandatory)             (optional)           (client only)
                    │                       │                 │
  package    MembershipSnapshot composition  +  ProofEngine: semaphoreEngine | rlnEngine
             createMembership(...) -> { current, refresh, verify }   (server)
             generateMembershipProof(...)                            (/client)
```

- **`MerkleGroupProvider`** (mandatory, per app) - the storage-agnostic source of
  the eligible, exclusion-filtered leaf set for a `(context, subTree)`. A
  discriminated union on `engine`: a `semaphore` provider may omit `engineParams`;
  an **`rln` provider must supply `engineParams`** (`rlnIdentifier` +
  `userMessageLimit`) or it does not typecheck.
- **`SnapshotStore`** (optional) - persists/looks-up frozen `{ root, leaves[] }`
  rows pinned to `(context, subTree, root)`. FreedInk/Deforum implement it;
  Discreetly passes the package's **`liveSnapshotStore(provider)`**, which never
  persists and recomputes the root live **exactly once per verify**.
- **`ProofEngine`** - fixes the proof payload, the `commitment -> leaf` mapping,
  the depth discipline, and prove/verify. Two ship in the box: **`semaphoreEngine`**
  (vanilla v4, dynamic LeanIMT, leaf = identity commitment; static export from the
  root) and **`rlnEngine`** (RLN, fixed depth-20, leaf =
  `rateCommitment = poseidon2(ic, userMessageLimit)`; imported statically from
  `@ministryofmany/membership/rln` or resolved lazily via `engineFor("rln")` /
  `loadRlnEngine()` - requires the optional peer `@ministryofmany/rln`).
- **`ArtifactSource`** (client) - injectable WASM/zkey loading;
  `hashPinnedArtifactSource` (FreedInk's SHA-256-pinned fetch, data-driven) and
  `staticArtifactSource` (pre-loaded bytes) ship.

## The five domain controls

1. **R1 authorization pin.** Every lookup is pinned to `(context, subTree, root)`,
   so a proof bound to one tree's root cannot pass a different tree/role check.
   This holds for the RLN engine too: `rlnEngine.verify` resolves the snapshot by
   `(context, subTree)` and forces that snapshot's root as `@ministryofmany/rln`
   `verifyRlnProof`'s `expectedRoot`, even though RLN also binds the root in
   `publicSignals`.
2. **Banned-exclusion.** `listEligible` omits banned/revoked commitments, so a
   `refresh()` after a ban yields a new root the just-banned member cannot prove
   against. `requireCurrentRoot` rejects any older root.
   **SAFE DEFAULT (fail-closed): `requireCurrentRoot` defaults to `true`.** A
   persisted-store consumer who forgets the flag still rejects a just-banned
   member's pre-ban snapshot. Pass an **explicit `requireCurrentRoot: false`** only
   for the deliberately-lenient historical-root mode (e.g. FreedInk comments
   tolerate stale snapshots). The Semaphore engine additionally guards that the
   store's returned snapshot root equals the proof root (defense-in-depth), so a
   wrong-root store row cannot weaken the R1 pin.
3. **Engine isolation.** The v4 leaf (`SemaphoreLeaf`) and the v3 RLN leaf
   (`RlnLeaf`) are nominally branded, so a v4 leaf cannot flow into the depth-20
   RLN tree (a silent wrong-but-valid root) - it is a compile error. The two
   engines also produce different roots for identical raw leaves (tested).
4. **OrderKeys determinism.** The comparator is byte-specified - numeric
   subtraction for `number` keys (ms timestamps), `localeCompare` for `string`
   keys (ids/commitments) - reproducing FreedInk's
   `(userCreatedAt, userId, deviceCreatedAt, idc)` sort exactly. A ported FreedInk
   root-determinism test is the tripwire.
5. **Live-store single recompute.** `liveSnapshotStore.getByRoot` recomputes the
   live root once and reuses it for the `requireCurrentRoot` check - never twice.

## How each app maps onto `MerkleGroupProvider`

### FreedInk - Semaphore, dynamic depth, persisted snapshot

```ts
const provider: SemaphoreGroupProvider = {
  shape: { kind: "dynamic" },
  engine: "semaphore",
  async listEligible({ context: blogId, subTree /* 'author' | 'comment' */ }) {
    // active blog_members holding the capability x active user_identities,
    // one EligibleLeaf per device, leaf === commitment === idc.
    return rows.map((r) => ({
      leaf: r.idc,
      commitment: r.idc,
      // FreedInk's exact deterministic sort (control 4):
      orderKeys: [r.userCreatedAtMs, r.userId, r.deviceCreatedAtMs, r.idc],
    }));
  },
  // engineParams omitted: Semaphore needs none.
};

const membership = createMembership({ provider, store: freedinkSnapshotStore });
// freedinkSnapshotStore: put -> blog_member_snapshots; getByRoot pinned to
// (blogId, capability, root) - this IS the R1 control. requireCurrentRoot
// recomputes the live root once and rejects a stale (post-revoke) root.
```

### Discreetly - RLN, fixed depth 20, live root, rate-commitment leaves

```ts
const provider: RlnGroupProvider = {
  shape: { kind: "fixed", depth: 20 },
  engine: "rln",
  async listEligible({ context: roomId, subTree: "room" }) {
    // membershipLeaf where revokedAt IS NULL (BANNED memberships have all leaves
    // pruned), mapped to the rate commitment. No orderKeys: insertion order.
    return rows.map((r) => ({ leaf: r.rateCommitment, commitment: r.identityCommitment }));
  },
  async engineParams(roomId) {
    return { engine: "rln", rlnIdentifier: room.rlnIdentifier, userMessageLimit: room.userMessageLimit };
  },
};

// No snapshot table: the live store recomputes the root per verify.
const membership = createMembership({ provider }); // store defaults to liveSnapshotStore(provider)
// verify passes rln: { currentEpoch, epochErrorRange, rlnIdentifier, verificationKey };
// the package forces the snapshot root as expectedRoot. Returns { nullifier, rln:{epoch,x,y} }
// so Discreetly's Shamir collision/ban path keeps working unchanged.
```

### Deforum - per-sub-forum + per-role trees, banned-excluded snapshots

```ts
// context = subforumId; subTree = roleSlug for pseudonymous role gates, or
// 'anon:<action>' (e.g. 'anon:post') for the fully-anonymous tier.
const provider: SemaphoreGroupProvider = {
  shape: { kind: "dynamic" },         // anon tier = FreedInk's machinery (v4)
  engine: "semaphore",
  async listEligible({ context: subforumId, subTree }) {
    // exclude any member whose user-sub-forum nullifier is in the sub-forum bans
    // table, AND any revoked device leaf -> the frozen snapshot omits banned
    // commitments (control 2). A passed ban writes the nullifier + revokes leaves,
    // then refresh() yields a new root the banned member cannot prove against.
    return eligible.map((m) => ({ leaf: m.idc, commitment: m.idc, orderKeys: [/* ... */] }));
  },
};
const membership = createMembership({ provider, store: deforumSnapshotStore });
// Anon post: client generateMembershipProof(per-sub-forum identity, frozen
// banned-excluded snapshot, scope = per-epoch/per-action, message = content hash);
// server verify({ requireCurrentRoot: true }) and record the nullifier under the
// per-epoch cap (@ministryofmany/nullifier).
//
// Optional RLN escalation (D4): a high-abuse anon-action tree flips to
// engine:'rln' + shape:{kind:'fixed',depth:20} + RLN engineParams, reusing
// Discreetly's path - a per-sub-forum config flag, not a code fork.
```

## Entry points

- `@ministryofmany/membership` (server): `createMembership`, `liveSnapshotStore`, the
  engines, the seams + types.
- `@ministryofmany/membership/client`: `generateMembershipProof` + the artifact
  helpers, kept separate so the prover WASM never lands in a server bundle.

## Build / test

```sh
pnpm --filter @ministryofmany/membership run build       # tsup -> dist (.js + .d.ts), two entries
pnpm --filter @ministryofmany/membership run typecheck   # tsc --noEmit
pnpm --filter @ministryofmany/membership run test         # vitest
```

The two end-to-end suites generate REAL proofs and inject the circuit artifacts
from a sibling checkout (FreedInk's vendored Semaphore artifacts; Discreetly's
depth-20 RLN circuit). They skip cleanly when those artifacts are absent; the
pure-logic controls (R1 pin, engine isolation, orderKeys determinism, the live
store) run unconditionally.
```
