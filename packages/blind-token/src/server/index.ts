// @minister/blind-token/server - Node side.
//
// The Signer interface + LocalSigner / RemoteSigner backends, createSigner
// selection, the record-first/rollback-on-failure Issuer, verifyToken,
// generateIssuerKey, and the injectable Store interfaces (no ORM in the package).
//
// THE ANONYMITY INVARIANT is structural here: no Signer or Issuer method accepts a
// raw or prepared nonce. sign()/issue() take only the already-blinded message; the
// raw nonce never reaches a signer (local or Signet).

// Crypto core (verify + keygen). The safe-prime generator is the Node default; a
// non-Node host can inject one.
export { generateIssuerKey, verifyToken, nodeSafePrime } from "./crypto.js";

// Signer interface + backends + selection.
export type { Signer, SignArgs } from "./signer.js";
export { createLocalSigner } from "./local-signer.js";
export type { LocalSignerOpts } from "./local-signer.js";
export { createRemoteSigner } from "./remote-signer.js";
export type { RemoteSignerConfig } from "./remote-signer.js";
export { createSigner } from "./create-signer.js";

// The issuance-guard orchestrator.
export { createIssuer } from "./issuer.js";
export type { Issuer, IssuerOpts, IssueResult } from "./issuer.js";

// Injectable storage seams + logger.
export type { IssuanceStore, KeyStore, TokenLogger } from "./store.js";
export { noopLogger } from "./store.js";

// Shared wire helpers / types re-exported for server convenience.
export { buildInfo } from "../info.js";
export { bytesToB64url, b64urlToBytes } from "../codec.js";
export { SUITE_NAME } from "../types.js";
export type {
  SuiteName,
  ActionInfo,
  RedeemableToken,
  PublicKeySpki,
  IssuerKeyPair,
  TokenScope,
  SignOutcome,
  PublicKeyOutcome,
  RotateOutcome,
} from "../types.js";
