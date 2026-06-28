// Public RLN surface. buildGroup / merkleProofForLeaf are intentionally NOT
// re-exported: they return a Semaphore Group / zk-kit MerkleProof and would leak
// a v3 type into the public d.ts. Only the bigint root, the plain proof struct,
// and the prove/verify entry points cross the boundary.
export { MERKLE_TREE_DEPTH, computeRoot, sanitizeLeaves } from "./merkle.js";
export type {
  ArtifactSource,
  RlnProverArtifacts,
  RlnVerificationKey,
} from "./artifacts.js";
export { staticArtifactSource } from "./artifacts.js";
export type {
  FieldString,
  Groth16Proof,
  RlnPublicSignals,
  RlnSnarkProof,
  RlnProof,
} from "./proof.js";
export type { GenerateRlnProofInputs } from "./prover.js";
export { generateRlnProof } from "./prover.js";
export type { VerifyRlnProofParams } from "./verifier.js";
export { verifyRlnProof } from "./verifier.js";
