import type {
  ContextId,
  DeviceCommitment,
  IdentityCommitment,
  RevocationRegistry,
} from "./types.js";

/**
 * An in-memory `RevocationRegistry` over the per-device commitment lifecycle.
 *
 * This is the reference implementation of the revocation contract from `types.ts`:
 * a usable default for tests and single-process deployments, and the shape an app
 * mirrors over its own ORM (FreedInk `user_identities.status`, Discreetly
 * `membershipLeaf.revokedAt`, Deforum device revocation - all the same contract).
 *
 * It enforces the lifecycle invariants:
 *  - register/upsert a device commitment as `active`,
 *  - `revoke` flips it to `revoked` idempotently,
 *  - `revokedCommitments` is what the membership layer subtracts before rebuilding
 *    a root, so a revoked device can no longer prove membership against the new root.
 *
 * Keyed on `(context, deviceId)`. Reusing the same `deviceId` in a context with a
 * different commitment (e.g. a key rotation) replaces the prior record's
 * commitment but keeps its status, so a rotated-but-revoked device stays excluded.
 */
export class InMemoryRevocationRegistry implements RevocationRegistry {
  // context -> deviceId -> record
  private readonly byContext = new Map<ContextId, Map<string, DeviceCommitment>>();

  private bucket(context: ContextId): Map<string, DeviceCommitment> {
    let m = this.byContext.get(context);
    if (m === undefined) {
      m = new Map<string, DeviceCommitment>();
      this.byContext.set(context, m);
    }
    return m;
  }

  /**
   * Register (or upsert) a device's commitment in a context. New devices start
   * `active`; re-registering an existing device updates its commitment but
   * preserves its status (a revoked device stays revoked across a rotation).
   * Returns the resulting record.
   */
  register(
    context: ContextId,
    deviceId: string,
    commitment: IdentityCommitment,
  ): DeviceCommitment {
    const m = this.bucket(context);
    const prior = m.get(deviceId);
    const record: DeviceCommitment = {
      deviceId,
      context,
      commitment,
      status: prior?.status ?? "active",
    };
    m.set(deviceId, record);
    return record;
  }

  async revoke(context: ContextId, deviceId: string): Promise<DeviceCommitment | null> {
    const m = this.byContext.get(context);
    const prior = m?.get(deviceId);
    if (m === undefined || prior === undefined) return null;
    if (prior.status === "revoked") return prior; // idempotent
    const revoked: DeviceCommitment = { ...prior, status: "revoked" };
    m.set(deviceId, revoked);
    return revoked;
  }

  async revokedCommitments(context: ContextId): Promise<ReadonlySet<IdentityCommitment>> {
    const m = this.byContext.get(context);
    const out = new Set<IdentityCommitment>();
    if (m === undefined) return out;
    for (const rec of m.values()) {
      if (rec.status === "revoked") out.add(rec.commitment);
    }
    return out;
  }

  async list(context: ContextId): Promise<DeviceCommitment[]> {
    const m = this.byContext.get(context);
    return m === undefined ? [] : [...m.values()];
  }
}
