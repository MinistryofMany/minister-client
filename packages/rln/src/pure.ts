// @ministryofmany/rln/pure - the rlnjs-free, Semaphore-Group-free surface.
//
// Everything re-exported here is bigint / keccak / poseidon math whose import
// closure NEVER touches rlnjs or @semaphore-protocol/group. That makes it safe
// to import EAGERLY into a server / SSR module graph (e.g. Next renders client
// components on the server, evaluating their top-level imports under Node).
//
// The prover / verifier and the depth-20 Merkle helpers (which pull rlnjs, and
// rlnjs touches `Worker` at module top-level under some bundlers) live ONLY on
// the root "." entry. SSR-sensitive apps must import those lazily
// (`await import("@ministryofmany/rln")`) so they never enter the server graph.
export * from "./constants.js";
export * from "./field.js";
export * from "./shamir.js";
export * from "./signal-hash.js";
export * from "./identity.js";
