// RemoteSigner - calls the external Signet service over mTLS. Holds NO private
// key. Lifts FreedInk's SignetVoteSigner (src/lib/server/vote-signer.ts:112-196)
// + the signet.ts transport/endpoint wrappers (src/lib/server/signet.ts)
// wholesale: the node:https Agent mTLS transport, the base64 wire format, the
// in-process READY-pubkey memo, and the enqueue-once-per-group dedup are preserved
// EXACTLY. The /sign + /key wire scheme is byte-identical to today's FreedInk
// deployment, so the Signet interop proof keeps passing.
//
// The anonymity invariant lives here and one layer up: this transport forwards the
// already-blinded message bytes and never sees the raw nonce. It NEVER logs
// request/response bodies (no blinded messages, no signatures).
//
// THE SIGNET PREFIX COUPLING (verified, Signet/src/crypto.rs:47): the deployed
// Signet hard-codes `freedink-vote:` and signs over `freedink-vote:<version_id>`.
// It takes only `version_id` on the wire, not full metadata. So this RemoteSigner
// sends version_id = info.actionKey, and Signet reconstructs
// `<its compiled prefix>:<actionKey>`. For the bytes to match what the client
// blinded under (info.infoPrefix:actionKey) and what verifyToken checks, the
// client info.infoPrefix, this RemoteSigner's cfg.infoPrefix, and the deployed
// Signet's compiled prefix MUST be byte-equal. We assert info.infoPrefix ===
// cfg.infoPrefix on every sign() to surface the silent-misconfiguration trap
// (otherwise every signature fails closed at redemption: no token counts).

import { Agent, request as httpsRequest } from "node:https";
import type { Signer, SignArgs } from "./signer.js";
import type { TokenLogger } from "./store.js";
import { noopLogger } from "./store.js";
import type {
  PublicKeyOutcome,
  RotateOutcome,
  SignOutcome,
} from "../types.js";

export interface RemoteSignerConfig {
  baseUrl: string; // https://signet:8443 (no trailing slash)
  clientCert: string; // PEM
  clientKey: string; // PEM
  caCert: string; // PEM
  // The wire prefix the deployed Signet was BUILT for (see the coupling note
  // above). Default 'freedink-vote' for back-compat; a Deforum Signet deployment
  // sets its own, and the deployed Signet binary must agree on these bytes.
  infoPrefix?: string;
  requestTimeoutMs?: number; // default 15000 (matches signet.ts)
  // How long a READY public key stays cached in-process before it is re-fetched.
  // Bounds staleness after an OUT-OF-BAND key rotation (an admin rotating a
  // group's key via a separate client): without a TTL this instance would blind
  // preflights under the retired key until process restart, and every signature
  // would then fail closed at redemption. Default 5 minutes; set 0 to disable
  // caching entirely.
  pubKeyCacheTtlMs?: number;
  logger?: TokenLogger;
}

const DEFAULT_INFO_PREFIX = "freedink-vote";
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_PUBKEY_CACHE_TTL_MS = 300_000; // 5 minutes

interface ResolvedConfig {
  baseUrl: string;
  clientCert: string;
  clientKey: string;
  caCert: string;
  infoPrefix: string;
  requestTimeoutMs: number;
  pubKeyCacheTtlMs: number;
  logger: TokenLogger;
}

interface SignetResponse {
  status: number;
  json: unknown; // parsed JSON, or null for an empty/non-JSON body
  text: string; // raw text (for error surfacing); never logged on success
}

function b64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

class RemoteSigner implements Signer {
  readonly backend = "remote" as const;
  private readonly cfg: ResolvedConfig;
  private agent: Agent | null = null;

  // Small in-process cache of READY public keys (SPKI). The Signet public key is
  // stable per group, so within a bounded TTL we don't re-fetch it on every
  // preflight or redemption. Pending keys are never cached. Each entry carries
  // the fetch time so an OUT-OF-BAND rotation (admin rotates via a separate
  // client) can only pin a stale key for at most `pubKeyCacheTtlMs`, not until
  // process restart. NOT a persistence layer; a restart rebuilds it from GET
  // /key. (Lifts pubKeyCache, with the L2 staleness bound added.)
  private readonly pubKeyCache = new Map<string, { spki: Uint8Array; fetchedAt: number }>();

  // Groups for which we have already issued a POST /key from a read/sign path in
  // this process. Signet dedups concurrent generations per group, but RE-issuing
  // POST /key on every pending poll thrashes the worker pool, so we enqueue at
  // most ONCE per group per process here. (Lifts the `enqueued` set.)
  private readonly enqueued = new Set<string>();

  constructor(cfg: RemoteSignerConfig) {
    this.cfg = {
      baseUrl: cfg.baseUrl.replace(/\/$/, ""),
      clientCert: cfg.clientCert,
      clientKey: cfg.clientKey,
      caCert: cfg.caCert,
      infoPrefix: cfg.infoPrefix ?? DEFAULT_INFO_PREFIX,
      requestTimeoutMs: cfg.requestTimeoutMs ?? DEFAULT_TIMEOUT_MS,
      pubKeyCacheTtlMs: cfg.pubKeyCacheTtlMs ?? DEFAULT_PUBKEY_CACHE_TTL_MS,
      logger: cfg.logger ?? noopLogger,
    };
  }

  // One Agent per signer (keep-alive pooled). The Agent holds the client identity
  // for mTLS; Signet pins our cert CN, so the same cert is presented every call.
  // Lifts agentFor(): rejectUnauthorized stays true so a future edit can't
  // silently disable cert verification.
  private getAgent(): Agent {
    if (this.agent) return this.agent;
    this.agent = new Agent({
      cert: this.cfg.clientCert,
      key: this.cfg.clientKey,
      ca: this.cfg.caCert,
      keepAlive: true,
      rejectUnauthorized: true,
    });
    return this.agent;
  }

  // Low-level request. `path` includes any query string. `body`, when present, is
  // JSON-encoded. Returns status + parsed body without throwing on non-2xx - the
  // caller maps status codes (200 / 202 pending / 429) to behavior. Lifts
  // signetRequest. Never logs bodies.
  private request(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
  ): Promise<SignetResponse> {
    const url = new URL(this.cfg.baseUrl + path);
    const payload =
      body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");

    return new Promise<SignetResponse>((resolve, reject) => {
      const req = httpsRequest(
        {
          method,
          hostname: url.hostname,
          port: url.port,
          path: url.pathname + url.search,
          agent: this.getAgent(),
          headers: {
            accept: "application/json",
            ...(payload
              ? {
                  "content-type": "application/json",
                  "content-length": String(payload.length),
                }
              : {}),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            let parsed: unknown = null;
            if (text.length > 0) {
              try {
                parsed = JSON.parse(text);
              } catch {
                // Non-JSON body (e.g. /healthz "ok" or a plain error). Leave json
                // null; callers that need JSON treat that as a failure.
                parsed = null;
              }
            }
            resolve({ status: res.statusCode ?? 0, json: parsed, text });
          });
        },
      );
      req.on("error", reject);
      // A hung signer must not wedge a request thread forever.
      req.setTimeout(this.cfg.requestTimeoutMs, () => {
        req.destroy(new Error("Signet request timed out"));
      });
      if (payload) req.write(payload);
      req.end();
    });
  }

  // GET /key?group_id=… → 200 ready (public_key SPKI base64) | 202 pending.
  // A 429 on /key* (Signet rate-limits key reads) maps to `pending`, not an error:
  // it means "the key budget is busy, retry shortly" - same user-facing behavior
  // as a key still generating. Lifts signetGetKey + getPublicKey memo/enqueue.
  async getPublicKey(group: string): Promise<PublicKeyOutcome> {
    const cached = this.pubKeyCache.get(group);
    if (cached && Date.now() - cached.fetchedAt < this.cfg.pubKeyCacheTtlMs) {
      return { status: "ready", publicKeySpki: cached.spki };
    }
    const res = await this.request(
      "GET",
      `/key?group_id=${encodeURIComponent(group)}`,
    );
    if (res.status === 200) {
      const j = res.json as { public_key?: string };
      if (!j || typeof j.public_key !== "string") {
        throw new Error("Signet /key returned 200 without a public_key");
      }
      const spki = b64ToBytes(j.public_key);
      this.pubKeyCache.set(group, { spki, fetchedAt: Date.now() });
      return { status: "ready", publicKeySpki: spki };
    }
    if (res.status === 202 || res.status === 429) {
      // Ensure the key was enqueued at least once. Enqueue ONCE per process to
      // avoid thrashing Signet's keygen worker on repeated polls.
      this.enqueueOnce(group);
      return { status: "pending" };
    }
    throw new Error(`Signet /key failed (${res.status}): ${res.text.slice(0, 200)}`);
  }

  // Fire POST /key at most once per group per process. Best-effort. Lifts
  // enqueueOnce.
  private enqueueOnce(group: string): void {
    if (this.enqueued.has(group)) return;
    this.enqueued.add(group);
    void this.ensureKey(group);
  }

  // POST /sign { group_id, participant_id, version_id, blinded_message(base64) }
  // → 200 { blind_signature(base64) } | 202 pending | 429 rate-limited.
  //
  // blindedMessage is the ALREADY-BLINDED bytes. The raw nonce is never in scope.
  // We send base64 (Signet's wire format) and never log the message or signature.
  // version_id = info.actionKey (Signet prepends its compiled prefix). Lifts
  // signetSign + SignetVoteSigner.sign.
  async sign(args: SignArgs): Promise<SignOutcome> {
    // Surface the silent-misconfiguration trap: the client blinded under
    // info.infoPrefix:actionKey and Signet will sign under cfg.infoPrefix:actionKey
    // (its compiled prefix, mirrored in cfg.infoPrefix). If they differ, every
    // signature fails closed at redemption. Fail LOUD here instead, at sign time.
    if (args.info.infoPrefix !== this.cfg.infoPrefix) {
      throw new Error(
        `info prefix mismatch: client uses "${args.info.infoPrefix}" but this ` +
          `RemoteSigner is configured for "${this.cfg.infoPrefix}" (must match the ` +
          `deployed Signet's compiled prefix, or every signature fails to verify)`,
      );
    }
    const res = await this.request("POST", "/sign", {
      group_id: args.group,
      participant_id: args.participant,
      version_id: args.info.actionKey,
      blinded_message: Buffer.from(args.blindedMessage).toString("base64"),
    });
    if (res.status === 200) {
      const j = res.json as { blind_signature?: string };
      if (!j || typeof j.blind_signature !== "string") {
        throw new Error("Signet /sign returned 200 without a blind_signature");
      }
      return { status: "ok", blindSignature: b64ToBytes(j.blind_signature) };
    }
    if (res.status === 202) {
      // Key still generating - make sure it's enqueued once, then tell the caller
      // to retry. Re-enqueueing on every retry would thrash the keygen worker.
      this.enqueueOnce(args.group);
      return { status: "pending" };
    }
    if (res.status === 429) return { status: "rate_limited" };
    if (res.status === 409) {
      // Signet's ledger already holds this (group, participant, version_id) tuple;
      // it enforces the one-per-tuple cap independently of this issuer's local
      // store. This arises after a lost /sign response, or a second issuer instance
      // with a separate local store. Signet never stored the blind signature, so it
      // CANNOT be reproduced (a re-sign hits the UNIQUE index and 409s again): the
      // post-commit window is NON-RECOVERABLE for that one token. Surface it as a
      // coherent TERMINAL outcome so the Issuer stops retrying, instead of an opaque
      // throw that loops in signer_error. Recovery is out-of-band (admin delete of
      // the Signet row, or a key rotation).
      return { status: "already_issued" };
    }
    // 400 (bad blinded message) and any other status are real errors to surface.
    throw new Error(`Signet /sign failed (${res.status}): ${res.text.slice(0, 200)}`);
  }

  // POST /key?group_id=… → enqueue keygen (idempotent + deduped). 200 ready
  // (already exists) or 202 pending - both success. A 429 (key-endpoint rate
  // limit) is also success-ish: the keygen is/was enqueued; the on-demand sign
  // path is the hard guarantee. Lifts signetCreateKey + SignetVoteSigner.ensureKey.
  async ensureKey(group: string): Promise<void> {
    this.enqueued.add(group);
    try {
      const res = await this.request(
        "POST",
        `/key?group_id=${encodeURIComponent(group)}`,
      );
      if (res.status === 200) {
        const j = res.json as { public_key?: string };
        if (j && typeof j.public_key === "string") {
          this.pubKeyCache.set(group, { spki: b64ToBytes(j.public_key), fetchedAt: Date.now() });
        }
        return;
      }
      if (res.status === 202 || res.status === 429) return;
      throw new Error(
        `Signet POST /key failed (${res.status}): ${res.text.slice(0, 200)}`,
      );
    } catch (err) {
      // Pre-gen is best-effort; a failed enqueue is logged, not fatal. Clear the
      // marker so a later poll can retry the enqueue rather than waiting forever.
      this.enqueued.delete(group);
      this.cfg.logger.warn({ err, group }, "signet ensureKey failed");
    }
  }

  // POST /key/rotate?group_id=… → ADMIN ONLY on Signet. 200 { public_key } ready
  // (rotation is synchronous on Signet) | 429 rate-limited (key budget busy ->
  // surface as pending: retry the rotate). Drops the cached pubkey so the next
  // read fetches the new one. Wired NOW so adding rotation later is not a breaking
  // change. The client cert presented must be an admin identity Signet recognizes,
  // or Signet returns 403 (a real error we surface).
  async rotateKey(group: string): Promise<RotateOutcome> {
    const res = await this.request(
      "POST",
      `/key/rotate?group_id=${encodeURIComponent(group)}`,
    );
    if (res.status === 200) {
      const j = res.json as { public_key?: string };
      if (!j || typeof j.public_key !== "string") {
        throw new Error("Signet /key/rotate returned 200 without a public_key");
      }
      const spki = b64ToBytes(j.public_key);
      this.pubKeyCache.set(group, { spki, fetchedAt: Date.now() });
      return { status: "rotated", publicKeySpki: spki };
    }
    if (res.status === 429) {
      // Key budget busy; the rotate did not happen. Drop any stale cache entry is
      // unnecessary (we never rotated), tell the caller to retry.
      return { status: "pending" };
    }
    throw new Error(
      `Signet /key/rotate failed (${res.status}): ${res.text.slice(0, 200)}`,
    );
  }
}

// RemoteSigner - calls Signet over mTLS. Holds no private key. The hardened tier.
// The PEM-resolution helper (inline value vs. filesystem path) stays in the
// consuming app's config layer; this takes resolved PEM strings.
export function createRemoteSigner(cfg: RemoteSignerConfig): Signer {
  return new RemoteSigner(cfg);
}
