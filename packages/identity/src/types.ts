import type { Identity } from "@semaphore-protocol/identity";

/**
 * A field-element-bearing decimal string (a bigint serialized via `toString()`).
 * Identity commitments cross the wire and land in app databases as decimal text in
 * every donor app (verified: FreedInk idc / Discreetly identityCommitment columns),
 * so this package's public surface speaks decimal strings, never raw bigints.
 */
export type FieldString = string;

/**
 * A Semaphore identity commitment as a decimal string. For Semaphore v4 this is
 * `poseidon2([publicKey.x, publicKey.y]).toString()` (verified against
 * @semaphore-protocol/identity@4.14.2: the constructor sets
 * `_commitment = poseidon2(this._publicKey)`).
 */
export type IdentityCommitment = FieldString;

/**
 * An opaque, app-defined membership context. One Semaphore identity is derived
 * per context from a single device seed, so each context gets a distinct,
 * unlinkable commitment.
 *  - Deforum: a sub-forum id.
 *  - Discreetly: a room id (this is the fix for its cross-room commitment reuse).
 *  - FreedInk: a blog id.
 * Free-form string: a new context never needs a schema/enum migration.
 */
export type ContextId = string;

/**
 * The structural shape `@minister/membership` consumes from a Semaphore identity
 * (the `SemaphoreIdentityLike` contract from membership-interface.md section 6).
 *
 * The contract deliberately does NOT name a concrete Semaphore major: it exposes
 * the decimal-string `commitment` every consumer needs plus an opaque `native`
 * handle that a proof engine narrows to its own Identity type. This keeps the
 * membership layer storage- and engine-agnostic and contains the v3/v4 blast
 * radius behind one boundary (semaphore-version-reconciliation.md option C/D).
 *
 * For THIS package the contract is satisfied with `native` being a v4
 * `@semaphore-protocol/identity` `Identity`; the membership v4 engine narrows it
 * back via `asV4Identity`.
 */
export interface SemaphoreIdentityLike {
  /** The public identity commitment, decimal string. */
  readonly commitment: IdentityCommitment;
  /** The native Semaphore identity handle. Opaque at this boundary by contract. */
  readonly native: unknown;
}

/**
 * The concrete identity this package produces: a `SemaphoreIdentityLike` whose
 * `native` is a pure Semaphore v4 `Identity`. Callers inside the v4 world can use
 * `identity` directly; callers behind the membership seam see only the structural
 * `SemaphoreIdentityLike`.
 */
export interface DerivedIdentity extends SemaphoreIdentityLike {
  /** The context this identity was derived for. */
  readonly context: ContextId;
  /** The native Semaphore v4 identity. */
  readonly identity: Identity;
  /** Same object as `identity`, typed per the structural contract. */
  readonly native: Identity;
}

/**
 * Lifecycle status of a single device's commitment within one context. Mirrors the
 * exclusion sources the membership layer already keys on (verified: FreedInk
 * `user_identities.status` active/revoked; Discreetly `membershipLeaf.revokedAt`).
 *  - `active`:  the leaf is included when the membership root is (re)built.
 *  - `revoked`: the leaf MUST be excluded so a rebuilt root no longer admits it.
 */
export type DeviceStatus = "active" | "revoked";

/**
 * A per-device commitment record within one context - the unit the membership
 * layer turns into (or drops from) a Merkle leaf. One human/user may run several
 * devices; each device derives its own identity from its own device seed, so each
 * has its own commitment and can be revoked independently (lost/stolen device)
 * without disturbing the others.
 */
export interface DeviceCommitment {
  /** Stable per-device id (app-assigned; e.g. a device row PK). */
  readonly deviceId: string;
  /** The context this commitment belongs to. */
  readonly context: ContextId;
  /** The device's identity commitment in this context, decimal string. */
  readonly commitment: IdentityCommitment;
  /** Lifecycle status. */
  readonly status: DeviceStatus;
}

/**
 * The revocation contract the membership layer uses to rebuild a root that
 * excludes revoked devices. This package owns the TYPES (the shared vocabulary);
 * each app owns the storage. It is the device-side analogue of the membership
 * doc's exclusion seam, expressed in commitment terms so the membership layer can
 * filter leaves without knowing the app's schema.
 */
export interface RevocationRegistry {
  /**
   * Mark a device's commitment revoked within a context. Idempotent: revoking an
   * already-revoked or unknown device is a no-op (so a double-tap from a moderator
   * never throws). Returns the resulting record, or `null` if the device is
   * unknown in this context.
   */
  revoke(context: ContextId, deviceId: string): Promise<DeviceCommitment | null>;

  /**
   * The set of currently-revoked commitments for a context, as decimal strings.
   * The membership layer subtracts these from the eligible leaf set before
   * computing the root (verified pattern: FreedInk/Discreetly exclude
   * revoked/banned leaves prior to root computation).
   */
  revokedCommitments(context: ContextId): Promise<ReadonlySet<IdentityCommitment>>;

  /** All device commitments for a context, both active and revoked. */
  list(context: ContextId): Promise<DeviceCommitment[]>;
}

/**
 * Filter an eligible commitment set down to the still-active ones by subtracting a
 * revoked set. Pure helper so the membership layer (and tests) get the exclusion
 * semantics from one place without re-implementing the subtraction.
 *
 * Order is preserved (it is load-bearing for FreedInk's deterministic root, where
 * the client must not re-sort - verified membership-interface.md section 2).
 */
export function excludeRevoked(
  commitments: readonly IdentityCommitment[],
  revoked: ReadonlySet<IdentityCommitment>,
): IdentityCommitment[] {
  return commitments.filter((c) => !revoked.has(c));
}
