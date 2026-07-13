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
  // its last-known CLEAR bit under fail-open. Default Infinity (fail-open on
  // last-known indefinitely — the design default). Set a finite cap for
  // fail-closed-after-cap.
  maxStaleMs?: number;
  // What to do when a list is unfetchable/stale and the last-known bit is CLEAR.
  // "open" (default) keeps honoring it (within maxStaleMs); "closed" returns
  // "stale" so the RP can drop access. A REVOKED bit is authoritative regardless.
  staleFailMode?: StaleFailMode;
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

function latchKey(ref: BadgeStatusRef): string {
  return `${ref.uri.replace(/\/$/, "")}#${ref.index}`;
}

export function createMinisterStatusChecker(
  config: MinisterStatusCheckerConfig,
): MinisterStatusChecker {
  const issuer = config.issuer.replace(/\/$/, "");
  const pollIntervalMs = config.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const maxStaleMs = config.maxStaleMs ?? Number.POSITIVE_INFINITY;
  const staleFailMode: StaleFailMode = config.staleFailMode ?? "open";
  const key: KeyInput = config.key ?? assertionResolverFor(issuer);
  const fetchImpl = config.fetchImpl ?? fetch;
  const now = config.nowFn ?? Date.now;

  const cache = new Map<string, CacheEntry>();
  const inflight = new Map<string, Promise<void>>();
  const memHighWater = new Map<string, number>();
  const latch = new Set<string>();

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

  // Refetch one list (ETag-conditional), verify, high-water-check, and update the
  // cache. Silently keeps the last-known snapshot on any failure (fail-open
  // substrate); a caller inspects freshness afterward.
  async function refetch(uri: string): Promise<void> {
    const existing = cache.get(uri);
    try {
      const headers: Record<string, string> = {};
      if (existing?.etag) headers["If-None-Match"] = existing.etag;
      const res = await fetchImpl(uri, { headers });

      if (res.status === 304 && existing) {
        // Unchanged: refresh the poll clock, keep the snapshot.
        cache.set(uri, { ...existing, fetchedAtMs: now() });
        return;
      }
      if (res.status !== 200) {
        // 503 (not yet published), 404, 5xx — keep last-known.
        return;
      }

      const jwt = (await res.text()).trim();
      const snapshot = await verifyStatusListCredential(jwt, {
        fetchedUrl: uri,
        issuer,
        key,
        nowMs: now(),
      });

      // Defense 3: reject a version regression (rollback). Keep last-known.
      const hw = await getHighWater(uri);
      if (snapshot.version < hw) {
        return;
      }
      await setHighWater(uri, snapshot.version);

      const etag = res.headers.get("etag") ?? undefined;
      cache.set(uri, { snapshot, fetchedAtMs: now(), etag });
    } catch {
      // Network error, verification failure, expired signature — keep last-known.
    }
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
      // No usable snapshot ever obtained (e.g. a brand-new list still 503-ing).
      // Nothing to fail-open ON — the RP applies its own policy.
      return "stale";
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
    const stalenessMs = now() - entry.snapshot.expiresAtMs;
    return stalenessMs <= maxStaleMs ? "valid" : "stale";
  }

  return {
    check,
    isLatched: (ref) => latch.has(latchKey(ref)),
  };
}
