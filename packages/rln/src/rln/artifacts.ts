/**
 * Injectable circuit-artifact loading. The consumer supplies the depth-20 RLN
 * wasm + proving zkey (for proving) and the parsed Groth16 verification key (for
 * verifying). This package NEVER hard-codes a path to Discreetly's
 * packages/circuits or any one lockfile - the artifacts are provided by the app.
 */

/** Prover artifacts: a filesystem path (Node) or raw bytes (browser passthrough). */
export interface RlnProverArtifacts {
  /** RLN circuit wasm: a path string (Node) or Uint8Array (browser). */
  readonly wasm: string | Uint8Array;
  /** RLN proving key (.zkey): a path string (Node) or Uint8Array (browser). */
  readonly zkey: string | Uint8Array;
}

/** The parsed RLN Groth16 verification key JSON (verifier side). */
export type RlnVerificationKey = Record<string, unknown>;

/**
 * Source of the RLN circuit artifacts. One fixed depth-20 circuit, so there is
 * no depth parameter (unlike a per-depth Semaphore artifact source). Implement
 * this over the app's own artifact storage / integrity policy.
 */
export interface ArtifactSource {
  /** Resolve the prover artifacts (wasm + zkey). Called on each proof generation. */
  prover(): Promise<RlnProverArtifacts> | RlnProverArtifacts;
  /** Resolve the parsed Groth16 verification key. Called on each verification. */
  verificationKey(): Promise<RlnVerificationKey> | RlnVerificationKey;
}

/**
 * Build an ArtifactSource from already-resolved artifacts (the common case:
 * Node reads paths/bytes once at startup, the browser passes Uint8Arrays). Both
 * the prover bytes and the verification key are optional so a proving-only or
 * verifying-only consumer is not forced to supply the other half.
 */
export function staticArtifactSource(opts: {
  prover?: RlnProverArtifacts;
  verificationKey?: RlnVerificationKey;
}): ArtifactSource {
  return {
    prover() {
      if (!opts.prover) {
        throw new Error("ArtifactSource: no prover artifacts (wasm/zkey) were provided.");
      }
      return opts.prover;
    },
    verificationKey() {
      if (!opts.verificationKey) {
        throw new Error("ArtifactSource: no verification key was provided.");
      }
      return opts.verificationKey;
    },
  };
}
