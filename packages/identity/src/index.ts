// @ministryofmany/identity - pure Semaphore v4 identity layer.
//
// This package pins Semaphore v4 ONLY (@semaphore-protocol/identity ^4) and has
// NO Semaphore v3 / rlnjs anywhere in its dependency closure - v3 + RLN are
// quarantined in @ministryofmany/rln (see semaphore-version-reconciliation.md). It
// provides:
//   1. per-app-secret -> per-context Identity derivation (one Ministry-delivered
//      branch yields a distinct, unlinkable commitment per context),
//   2. the per-device commitment lifecycle + revocation contract the membership
//      layer uses to rebuild a root excluding revoked devices,
//   3. the structural SemaphoreIdentityLike contract membership consumes,
//   4. the Ministry anon handoff (./link): extract the per-app secret from the
//      OIDC callback fragment + decide adopt/rekey against the id_token epoch.
//      That entry point is zero-dependency and re-exported here for convenience.
export * from "./types.js";
export * from "./derive.js";
export * from "./revocation.js";
export * from "./link.js";
