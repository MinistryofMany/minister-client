import { assertionResolverFor } from "./did-assertion";
import {
  verifyStatusListCredential,
  bitIsSet,
  type BadgeStatusRef,
  type StatusCheck,
  type StatusListSnapshot,
} from "./status-list";
import type { KeyInput } from "./types";

// createMinisterStatusChecker — the RP-side revocation checker
// (Minister docs/groups-revocation-design.md §5.8). Sweeps persisted badge
// `status` handles against Minister's per-RP status lists and answers
// "valid" | "revoked" | "stale". Herd-private by construction: it only ever
// fetches WHOLE lists, never a per-index query.
//
// Freshness/rollback defenses (§5.6), all here:
//   1. signature + `sub == fetched URL` binding (in verifyStatusListCredential);
//   2. hard max-age: an expired signed list is not "fresh" (jose rejects it, and
//      we re-check exp), so it can mislead for at most one validity window;
//   3. monotonic statusListVersion high-water mark: a rolled-back (older-version)
//      list is rejected and the last-known snapshot is kept;
//   4. revocation LATCH: `statusPurpose: "revocation"` is irreversible by spec,
//      so once any validly-signed list showed an index revoked, that handle is
//      revoked FOREVER in this process — no later list can un-revoke it. Every
//      rollback variant collapses to at worst a bounded DELAY.
//
// Failure policy (list unfetchable or stale past exp): DEFAULT fail-open on
// last-known state (keep honoring the last confirmed bit) with a `maxStaleMs`
// hard cap and a `staleFailMode: "closed"` opt-out for rooms that warrant it. A
// revoked bit is ALWAYS authoritative even from a stale snapshot (monotonic), so
// fail-open never resurrects access — it only preserves a not-yet-revoked grant
// during a publisher/CDN outage (which fail-closed would turn into a mass
// eviction = re-proving, the exact UX the design forbids).

export type StaleFailMode = "open" | "closed";

// Surfaced when a fetched list body is a well-formed HTTP 200 whose VERIFICATION
// fails (bad signature, sub/URL mismatch, malformed, or an out-of-range status
// index) — categorically distinct from an unreachable list. A verification
// failure is a possible attack (a forged list served in place of the real one),
// so the checker fails the affected check CLOSED and reports it here with a
// running count of consecutive failures per list.
export interface StatusVerifyErrorInfo {
  uri: string;
  error: Error;
  consecutiveFailures: number;
}

// Optional cross-restart persistence for the version high-water mark (defense 3).
// In-memory by default: a restart resets it, leaving defense 2 (hard max-age) as
// the floor — a named, accepted limitation (§5.6, auditor #7).
export interface HighWaterStore {
  get(listUri: string): number | undefined | Promise<number | undefined>;
  set(listUri: string, version: number): void | Promise<void>;
}

export interface MinisterStatusCheckerConfig {
  // Minister origin, e.g. "https://ministry.id". Status list URLs must be on it.
  issuer: string;
  // Minimum interval between network refetches of one list (ETag-conditional).
  // Between refetches a still-fresh cached snapshot answers with zero I/O.
  // Default 60s (matches the publisher epoch).
  pollIntervalMs?: number;
  // Hard cap on how long past a list's signed `exp` the checker will keep serving
  // its last-known CLEAR bit under fail-open. Default DEFAULT_MAX_STALE_MS (4× the
  // 15-min list validity window = 1h): a few validity windows of grace for a
  // genuine publisher/CDN outage, after which a sustained RP<->Minister partition
  // fails CLOSED ("stale") rather than honoring an un-refreshed CLEAR bit forever.
  // A REVOKED bit stays authoritative via the latch regardless of this cap. Pass
  // Number.POSITIVE_INFINITY to opt back into unbounded fail-open.
  maxStaleMs?: number;
  // What to do when a list is unfetchable/stale and the last-known bit is CLEAR.
  // "open" (default) keeps honoring it (within maxStaleMs); "closed" returns
  // "stale" so the RP can drop access. A REVOKED bit is authoritative regardless.
  // NOTE: a VERIFICATION failure (not an outage) overrides "open" and fails the
  // check closed — a forged list never rides the silent keep-last-known path.
  staleFailMode?: StaleFailMode;
  // Optional telemetry for verification failures (see StatusVerifyErrorInfo).
  // Fired from the refetch path and from an out-of-range status index.
  onVerifyError?: (info: StatusVerifyErrorInfo) => void;
  // Verification key. Defaults to the issuer DID assertionMethod resolver
  // (#key-2 pinned). Inject a public JWK in tests to stay offline.
  key?: KeyInput;
  // Optional persistence for the version high-water mark.
  persistHighWater?: HighWaterStore;
  // Injectable fetch (tests). Defaults to the global fetch.
  fetchImpl?: typeof fetch;
  // Injectable clock (tests). Defaults to Date.now.
  nowFn?: () => number;
}

export interface MinisterStatusChecker {
  // Sweep one persisted handle. Returns:
  //   "valid"   — a usable snapshot shows the bit clear;
  //   "revoked" — latched, or a (possibly stale) snapshot shows the bit set;
  //   "stale"   — no usable snapshot and fail-open tolerance exhausted, or
  //               staleFailMode "closed". The RP applies its own policy.
  check(ref: BadgeStatusRef): Promise<StatusCheck>;
  // True if this handle has been latched revoked in-process (test/introspection).
  isLatched(ref: BadgeStatusRef): boolean;
}

interface CacheEntry {
  snapshot: StatusListSnapshot;
  fetchedAtMs: number;
  etag?: string;
}

const DEFAULT_POLL_INTERVAL_MS = 60_000;

// Minister's signed-list validity window (docs/groups-revocation-design.md
// §5.6.2). The SDK does not import Minister's constants, so this is transcribed;
// only the DEFAULT_MAX_STALE_MS multiple below depends on it.
const DEFAULT_LIST_VALIDITY_WINDOW_MS = 15 * 60_000;

// Finite default fail-open staleness cap: 4× the validity window (= 1h). Bounds
// how long a CLEAR bit is honored past a list's signed `exp` during an outage
// before the check fails CLOSED. Chosen so a real publisher/CDN blip is absorbed
// (a few validity windows) but a sustained partition cannot honor an
// un-refreshed CLEAR bit indefinitely. Overridable via `maxStaleMs`.
const DEFAULT_MAX_STALE_MS = 4 * DEFAULT_LIST_VALIDITY_WINDOW_MS;

function latchKey(ref: BadgeStatusRef): string {
  return `${ref.uri.replace(/\/$/, "")}#${ref.index}`;
}

export function createMinisterStatusChecker(
  config: MinisterStatusCheckerConfig,
): MinisterStatusChecker {
  const issuer = config.issuer.replace(/\/$/, "");
  const pollIntervalMs = config.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const maxStaleMs = config.maxStaleMs ?? DEFAULT_MAX_STALE_MS;
  const staleFailMode: StaleFailMode = config.staleFailMode ?? "open";
  const key: KeyInput = config.key ?? assertionResolverFor(issuer);
  const fetchImpl = config.fetchImpl ?? fetch;
  const now = config.nowFn ?? Date.now;

  const cache = new Map<string, CacheEntry>();
  const inflight = new Map<string, Promise<void>>();
  const memHighWater = new Map<string, number>();
  const latch = new Set<string>();
  // Consecutive count of 200-body-fails-verification results per list (reset on
  // any successful fetch/304). Surfaced via onVerifyError.
  const verifyFailures = new Map<string, number>();
  // Whether the MOST RECENT refetch that got a body ended in a verification
  // failure (a forged/corrupt list). Drives the fail-CLOSED override in check():
  // a verification failure must never ride the silent keep-last-known fail-open
  // path an unreachable list gets.
  const lastVerifyFailed = new Map<string, boolean>();

  async function getHighWater(uri: string): Promise<number> {
    if (config.persistHighWater) {
      const v = await config.persistHighWater.get(uri);
      if (typeof v === "number") return v;
    }
    return memHighWater.get(uri) ?? -1;
  }

  async function setHighWater(uri: string, version: number): Promise<void> {
    memHighWater.set(uri, version);
    if (config.persistHighWater) await config.persistHighWater.set(uri, version);
  }

  // Clear the verification-failure state for a list (a fresh good fetch or 304
  // confirms Minister is serving the real list again).
  function clearVerifyFailure(uri: string): void {
    verifyFailures.delete(uri);
    lastVerifyFailed.delete(uri);
  }

  // Refetch one list (ETag-conditional), verify, high-water-check, and update the
  // cache. Keeps the last-known snapshot on an UNREACHABLE list (network error,
  // non-200) — the fail-open substrate. A well-formed 200 whose VERIFICATION
  // fails is treated differently (defense against a forged list): it is counted,
  // reported via onVerifyError, and flags the list so `check` fails CLOSED rather
  // than silently honoring the last-known CLEAR bit.
  async function refetch(uri: string): Promise<void> {
    const existing = cache.get(uri);
    let res: Response;
    try {
      const headers: Record<string, string> = {};
      if (existing?.etag) headers["If-None-Match"] = existing.etag;
      res = await fetchImpl(uri, { headers });
    } catch {
      // Network error — UNREACHABLE. Keep last-known; not a verification failure.
      return;
    }

    if (res.status === 304 && existing) {
      // Unchanged: refresh the poll clock, keep the snapshot. A 304 is a fresh
      // confirmation the server serves the good list — clear any prior verify flag.
      cache.set(uri, { ...existing, fetchedAtMs: now() });
      clearVerifyFailure(uri);
      return;
    }
    if (res.status !== 200) {
      // 503 (not yet published), 404, 5xx — UNREACHABLE. Keep last-known.
      return;
    }

    let snapshot: StatusListSnapshot;
    try {
      const jwt = (await res.text()).trim();
      snapshot = await verifyStatusListCredential(jwt, {
        fetchedUrl: uri,
        issuer,
        key,
        nowMs: now(),
      });
    } catch (verr) {
      // A 200 body that FAILS verification (bad signature, sub mismatch, expired,
      // malformed) is NOT an outage — it is a forged/corrupt list served in place
      // of the real one. Count it, surface it, and mark the list so check() fails
      // CLOSED for it instead of riding fail-open on the last-known CLEAR bit.
      const count = (verifyFailures.get(uri) ?? 0) + 1;
      verifyFailures.set(uri, count);
      lastVerifyFailed.set(uri, true);
      config.onVerifyError?.({
        uri,
        error: verr instanceof Error ? verr : new Error(String(verr)),
        consecutiveFailures: count,
      });
      return;
    }

    // Signature verified. Defense 3: reject a version regression (rollback). This
    // is a validly-signed older list (not a forgery), so we keep last-known and
    // clear the forged-body flag — the latch already blocks any un-revocation.
    const hw = await getHighWater(uri);
    if (snapshot.version < hw) {
      clearVerifyFailure(uri);
      return;
    }
    await setHighWater(uri, snapshot.version);

    const etag = res.headers.get("etag") ?? undefined;
    cache.set(uri, { snapshot, fetchedAtMs: now(), etag });
    clearVerifyFailure(uri);
  }

  // Ensure the freshest snapshot we can get, deduping concurrent refetches.
  async function ensureSnapshot(uri: string): Promise<CacheEntry | undefined> {
    const cached = cache.get(uri);
    const due =
      !cached ||
      now() - cached.fetchedAtMs >= pollIntervalMs ||
      now() >= cached.snapshot.expiresAtMs;

    if (due) {
      let pending = inflight.get(uri);
      if (!pending) {
        pending = refetch(uri).finally(() => inflight.delete(uri));
        inflight.set(uri, pending);
      }
      await pending;
    }
    return cache.get(uri);
  }

  async function check(ref: BadgeStatusRef): Promise<StatusCheck> {
    const lk = latchKey(ref);
    // Defense 4: latched handles are revoked forever, no matter what any list says.
    if (latch.has(lk)) return "revoked";

    const entry = await ensureSnapshot(ref.uri);
    if (!entry) {
      // No usable snapshot ever obtained (e.g. a brand-new list still 503-ing, or
      // a list only ever served as a forged body). Nothing to fail-open ON — the
      // RP applies its own policy. A verification failure was already surfaced via
      // onVerifyError from refetch.
      return "stale";
    }

    // A `credentialStatus` index outside the decoded list is MALFORMED — the
    // badge points past this shard's length (lists are always published at full
    // shard size, so an in-range index never falls off the end). Fail CLOSED
    // (deny) and surface it; never silently read an out-of-range bit as clear.
    const bitLength = entry.snapshot.bits.length * 8;
    if (ref.index < 0 || ref.index >= bitLength) {
      config.onVerifyError?.({
        uri: ref.uri,
        error: new Error(
          `status index ${ref.index} is out of range for a ${bitLength}-bit list`,
        ),
        consecutiveFailures: verifyFailures.get(ref.uri) ?? 0,
      });
      return "revoked";
    }

    const revoked = bitIsSet(entry.snapshot.bits, ref.index);
    if (revoked) {
      // Authoritative even from a stale snapshot: a revoked bit never un-sets
      // (monotonic), so trusting it can only ENFORCE a revocation, never fabricate
      // one. Latch it so we never re-fetch our way back to "valid".
      latch.add(lk);
      return "revoked";
    }

    // Bit clear. Fresh snapshot => valid.
    const fresh = now() < entry.snapshot.expiresAtMs;
    if (fresh) return "valid";

    // Stale-and-clear: apply the failure policy.
    if (staleFailMode === "closed") return "stale";
    // C1: a VERIFICATION failure on the freshest refetch (a forged list is being
    // served) must NOT ride fail-open on the last good CLEAR bit — fail CLOSED
    // immediately, regardless of the fail-open grace, so an attacker serving a
    // bad body cannot buy a full maxStaleMs window of retained access.
    if (lastVerifyFailed.get(ref.uri)) return "stale";
    const stalenessMs = now() - entry.snapshot.expiresAtMs;
    return stalenessMs <= maxStaleMs ? "valid" : "stale";
  }

  return {
    check,
    isLatched: (ref) => latch.has(latchKey(ref)),
  };
}
