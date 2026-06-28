# @minister/poll

A framework-agnostic polling / decision engine. **One engine, many surfaces**: a
`Poll` is fixed by three levers - the **question type**, the **audience gate**, and
the **result view** - so a standalone StrawPoll-style poll, a poll-as-post-type in
a forum, and a pinned poll in a chat room are all the same primitive. This is the
NET-NEW primitive in the `@minister/*` scope: no donor app shipped polling as a
reusable module (FreedInk's tally is bespoke to blog-review).

It consumes:

- [`@minister/policy`](../policy) - the audience gate is a badge requirement AST
  (`allOf` / `anyOf` / `atLeast` / badge-leaf). The engine does NOT evaluate
  badges; the caller verifies disclosed VCs and runs `evaluate(...)` BEFORE
  minting a verified voter handle. The gate rides on the poll so a result view can
  surface the pool definition.
- [`@minister/nullifier`](../nullifier) - `deriveContextNullifier` derives the
  per-`(poll, member)` nullifier that makes a poll unstuffable.
- [`@minister/membership`](../membership) - the `FieldString` type and, at the
  call site, the verified membership proof whose `nullifier` is the voter handle
  for anonymous / named-set polls.

Replay / uniqueness persistence is **not** here: the package defines the
`VoteStore` insert-or-reject contract and the app implements it (a
`UNIQUE(pollId, nullifier)` index).

## The Poll

```
Poll = { id, questionType, audienceGate, config, lifecycle }
lifecycle: draft --open--> open --close--> closed --resolve--> resolved
```

`closed` is also the **reveal window** for commit-reveal; every other type
resolves straight from `closed`.

## Question types (the lever)

| slug            | shape                                  | result view                |
| --------------- | -------------------------------------- | -------------------------- |
| `single-choice` | pick one of N options                  | percentage bar             |
| `yes-no`        | motion + OPTIONAL quorum/supermajority | quorum/threshold outcome   |
| `ranked`        | ranked-choice (IRV - see below)        | standings + round trace    |
| `schedule`      | multi-select / pick-time-slots         | per-slot heatmap + best    |
| `commit-reveal` | sealed vote, then reveal               | bar over revealed votes    |
| `raffle`        | draw a random winner                   | winner                     |
| `verdict`       | accept / reject                        | verdict outcome            |

A `QuestionType<Config, Vote, Tally>` is a pure unit: `validateVote`, `tally`,
`resultView`, `resolve`. It never touches persistence, auth, or nullifiers.

### yes-no threshold math

`threshold = ceil(eligible * numerator / denominator)`, numerator/denominator
configurable, **defaulting to 2/3** - byte-for-byte FreedInk `tally.ts`. `eligible`
is the FROZEN population the caller passes (FreedInk freezes it to close the
quorum-capture attack). An optional `quorum` adds a minimum-turnout floor.

### ranked = IRV

Instant-runoff voting (not Borda): eliminate the lowest-support candidate and
transfer ballots to each ballot's next still-standing preference until one holds a
majority of active ballots. Chosen for the **majority criterion** and an auditable
round-by-round trace. **Tie-break is deterministic**: the config option order is
the published tie rule (no `Math.random`, no wall-clock).

### raffle = verifiable draw

The winner is `entrant[uniformIndex(seed, n)]` over the entrants sorted ascending
by nullifier - a **pure function of two public inputs** (the seed + the entrant
set), rejection-sampled to remove modulo bias. There is **no unseeded
randomness** (`Math.random` is unverifiable and banned). The caller supplies the
public `seed` under one of two documented schemes:

- **commit-reveal seed**: at poll create, publish `H(preimage)` as
  `config.seedCommit` (a domain-separated SHA-256, `seedCommitHash`). After
  entries close, reveal the `preimage` and pass it to `resolve(pollId, { seed })`;
  the engine verifies it hashes to the committed `seedCommit` before drawing and
  rejects (`not-resolvable`) on a mismatch. Trust: the operator committed before
  knowing the entrant set, so they cannot grind the outcome.
- **external verifiable randomness** (drand / VRF / future block hash). Pass the
  beacon value as `config.seed` (fixed at create) or `resolve(pollId, { seed })`
  (revealed later). No `seedCommit` is set; trust is the beacon's.

The seed is resolved as `resolve` `opts.seed` if supplied, else `config.seed`; if
neither is present resolve fails closed. This makes the commit-reveal scheme
reachable: the revealed seed is supplied AFTER entries close rather than being
frozen in `config` at create. The package guarantees the draw is reproducible from
public inputs, so the chosen scheme's trust assumption is the only one in play.

A poisoned entrant (a stored nullifier that is not a canonical decimal field
string) makes the draw fail closed with a typed `not-resolvable` error rather than
throwing out of `resolve`.

## Unstuffability (the security property)

Every cast carries a **verified voter handle** plus a **per-`(poll, member)`
nullifier**:

- `{ kind: "membership", membershipNullifier }` - anonymous / named-set polls; the
  caller already verified a `@minister/membership` proof.
- `{ kind: "subject", subject }` - pseudonymous polls; the caller already
  authenticated a stable per-RP subject (e.g. a Minister pairwise `sub`).

The engine derives `deriveContextNullifier(handleSecret, toField(pollId))` and the
`VoteStore.castOnce` records it under `UNIQUE(pollId, nullifier)`:

1. **one vote per member** - a second cast (same per-poll nullifier) is rejected
   `already-voted`;
2. **no cross-poll replay** - the pollId is mixed into the derivation, so a
   member's nullifier differs per poll, and the UNIQUE key is `(pollId,
   nullifier)`, so a value lifted from poll A is meaningless in poll B.

`castOnce` MUST be atomic (an INSERT guarded by the UNIQUE index, catching the
violation as `replay`). A non-atomic check-then-insert is a stuffing hole.

## INTEGRATION REQUIREMENT (the engine does NOT gate)

This package is unstuffability + tally only. It performs **no** authentication,
VC verification, badge-policy evaluation, or membership-proof checking. Two things
the CALLER MUST do, or the gate is open:

1. **Gate before minting a `VoterHandle` and calling `cast()`.** Before each cast,
   the caller MUST verify the disclosed badge VCs and run `@minister/policy`
   `evaluate()` against the poll's `audienceGate`, AND verify any membership proof,
   and only then mint the verified `VoterHandle` (`{ kind: "subject" }` from an
   authenticated subject, or `{ kind: "membership", membershipNullifier }` from a
   verified proof). The engine TRUSTS the handle it is given and does not re-check
   the gate - an unverified handle casts an unauthorized vote.

2. **The yes-no `eligible` denominator is a caller-supplied frozen number with no
   issued-token floor.** `threshold = ceil(eligible * numerator / denominator)`
   uses exactly the number the caller passes; the engine does not derive it from a
   membership snapshot or count issued tokens. A caller that wants FreedInk-style
   `max(snapshot, issued)` quorum-capture protection MUST compute that value itself
   and pass it as `eligible`.

## commit-reveal binding

The commit phase stores only `commitHash(choice, salt)` (domain-separated SHA-256
with unit-separator field delimiters). A reveal is accepted only if it reproduces
the stored commit, so a voter can neither change their choice after committing nor
reveal a value other than what they sealed. `resolve` counts only
revealed-and-matching votes. The salt is the voter's secret and MUST be
high-entropy.

## Result views + credibility surface

Every view carries the credibility surface (polling.md): the **pool definition**
(the audience gate) + the **distinct-verified-voter count** (distinct recorded
nullifiers), so a viewer can judge that a number is unstuffable.

## Storage seams

`PollStore` (poll CRUD + lifecycle) and `VoteStore` (the one-vote guard + list +
count + reveal-update) are injectable interfaces. **No ORM lives in this package.**

## Usage

```ts
import { createPollEngine } from "@minister/poll";

const engine = createPollEngine({ pollStore, voteStore });

await engine.create({
  id: "town-hall-1",
  questionType: "yes-no",
  audienceGate: { open: false, policy: { badge: { type: "email-domain", where: { domain: "acme.test" } } } },
  config: { eligible: 42 }, // default 2/3 supermajority
});
await engine.transition("town-hall-1", "open");

// caller has verified the badge gate + minted a voter handle
await engine.cast("town-hall-1", { kind: "subject", subject: pairwiseSub }, { choice: "yes" });

await engine.transition("town-hall-1", "closed");
const { view } = (await engine.resolve("town-hall-1")) as { ok: true; view: any };
```

## Keeping in sync

The badge vocabulary used in an audience gate comes from `@minister/policy`; keep
poll gates expressed against the shared badge slugs (the same drift-check that
covers the rest of the ecosystem applies).
