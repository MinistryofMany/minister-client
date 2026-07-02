// @ministryofmany/membership - Semaphore group-membership proofs (Merkle group +
// snapshots + verify), with storage and the proof engine supplied by the consuming app.
//
// This (root) entry point is SERVER-SIDE: snapshot composition + proof
// verification. Client-side proof generation lives in @ministryofmany/membership/client
// so the prover WASM never lands in a server bundle.
//
// See README.md for how FreedInk, Discreetly, and Deforum each map onto
// MerkleGroupProvider.

// Core domain types + the leaf-brand boundary (engine isolation, control 3).
export type {
  FieldString,
  IdentityCommitment,
  ContextId,
  SubTree,
  TreeRef,
  EngineKind,
  TreeShape,
  Leaf,
  SemaphoreLeaf,
  RlnLeaf,
  MembershipSnapshot,
} from "./types.js";
export { asSemaphoreLeaf, asRlnLeaf } from "./types.js";

// The mandatory per-app seam.
export type {
  EligibleLeaf,
  EngineParams,
  MerkleGroupProvider,
  SemaphoreGroupProvider,
  RlnGroupProvider,
} from "./provider.js";
export { resolveEngineParams } from "./provider.js";

// The optional persistence seam + the package-shipped live store.
export type { SnapshotStore, GetByRootOptions, GetByRootResult } from "./store.js";
export { liveSnapshotStore } from "./store.js";

// The proof-engine seam + the shipped engines. The semaphore engine is static;
// the rln engine is NOT exported here - it lives behind the lazy
// engineFor("rln") / loadRlnEngine() (and the @ministryofmany/membership/rln
// subpath for static import), so a semaphore-only consumer's graph never touches
// the @ministryofmany/rln island (rlnjs + Semaphore v3).
export type {
  SemaphoreProof,
  RlnProof,
  MembershipProof,
  ProveContext,
  VerifyContext,
  VerifyResult,
  VerifyFailure,
  ProofEngine,
} from "./engine.js";
export { semaphoreEngine, engineFor, loadRlnEngine } from "./engines/index.js";

// Injectable artifact loading (also re-exported from /client).
export type { ArtifactSource, ArtifactPin } from "./artifacts.js";
export { hashPinnedArtifactSource, staticArtifactSource } from "./artifacts.js";

// Deterministic ordering (the FreedInk-root-reproducing comparator).
export { orderLeaves } from "./order.js";

// Field hashing (FreedInk-byte-for-byte hashToField).
export { hashToField } from "./hash.js";

// Live snapshot construction (current root + ordered leaves).
export { currentSnapshot } from "./snapshot.js";

// The composition entry point.
export type { MembershipConfig, Membership } from "./membership.js";
export { createMembership } from "./membership.js";
