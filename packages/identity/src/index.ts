// @ministryofmany/identity - pure Semaphore v4 identity layer.
//
// This package pins Semaphore v4 ONLY (@semaphore-protocol/identity ^4) and has
// NO Semaphore v3 / rlnjs anywhere in its dependency closure - v3 + RLN are
// quarantined in @ministryofmany/rln (see semaphore-version-reconciliation.md). It
// provides:
//   1. device-seed -> per-context Identity derivation (one backed-up seed yields a
//      distinct, unlinkable commitment per context),
//   2. a framework-agnostic PBKDF2-SHA256 + AES-GCM device-seed vault with a
//      BIP-39 mnemonic backup,
//   3. the per-device commitment lifecycle + revocation contract the membership
//      layer uses to rebuild a root excluding revoked devices,
//   4. the structural SemaphoreIdentityLike contract membership consumes,
//   5. the Ministry anon handoff (minister-link): extract the per-app secret
//      from the OIDC callback fragment + mix in the RP's own secret to produce
//      the device seed that feeds derivation (anon-identity master spec 8.4/9).
export * from "./types.js";
export * from "./derive.js";
export * from "./vault.js";
export * from "./mnemonic.js";
export * from "./revocation.js";
export * from "./minister-link.js";
