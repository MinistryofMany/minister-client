// Ambient shims for third-party libraries whose package.json `exports` map omits
// a resolvable "types" condition under moduleResolution: Bundler. Mirrors the
// pattern documented in Discreetly's packages/shared/src/types/external-shims.d.ts
// and apps/web/src/types/external-shims.d.ts. These types stay PRIVATE to this
// package - none of them appear in the public d.ts (the public surface is
// bigint-only and never re-exports a Semaphore object).

declare module "ffjavascript" {
  /** Prime-field arithmetic over a SNARK scalar field (used for Shamir recovery). */
  export class ZqField {
    constructor(p: bigint);
    add(a: bigint, b: bigint): bigint;
    sub(a: bigint, b: bigint): bigint;
    mul(a: bigint, b: bigint): bigint;
    div(a: bigint, b: bigint): bigint;
    normalize(a: bigint): bigint;
  }
}

declare module "@semaphore-protocol/group" {
  import type { MerkleProof } from "@zk-kit/incremental-merkle-tree";
  type BigNumberish = string | number | bigint;
  export class Group {
    constructor(id: BigNumberish, treeDepth?: number, members?: BigNumberish[]);
    get id(): BigNumberish;
    get root(): BigNumberish;
    get depth(): number;
    get zeroValue(): BigNumberish;
    get members(): BigNumberish[];
    indexOf(member: BigNumberish): number;
    addMember(member: BigNumberish): void;
    addMembers(members: BigNumberish[]): void;
    updateMember(index: number, member: BigNumberish): void;
    removeMember(index: number): void;
    generateMerkleProof(index: number): MerkleProof;
  }
}

declare module "@zk-kit/incremental-merkle-tree" {
  export interface MerkleProof {
    root: unknown;
    leaf: unknown;
    siblings: unknown[];
    pathIndices: number[];
  }
}

declare module "rlnjs" {
  import type { MerkleProof } from "@zk-kit/incremental-merkle-tree";
  export type StrBigInt = string | bigint;
  export interface RLNPublicSignals {
    x: StrBigInt;
    externalNullifier: StrBigInt;
    y: StrBigInt;
    root: StrBigInt;
    nullifier: StrBigInt;
  }
  export interface Proof {
    pi_a: StrBigInt[];
    pi_b: StrBigInt[][];
    pi_c: StrBigInt[];
    protocol: string;
    curve: string;
  }
  export interface RLNSNARKProof {
    proof: Proof;
    publicSignals: RLNPublicSignals;
  }
  export interface RLNFullProof {
    snarkProof: RLNSNARKProof;
    epoch: bigint;
    rlnIdentifier: bigint;
  }
  export type VerificationKey = Record<string, unknown>;
  export class RLNProver {
    constructor(wasmFilePath: string | Uint8Array, finalZkeyPath: string | Uint8Array);
    generateProof(args: {
      rlnIdentifier: bigint;
      identitySecret: bigint;
      userMessageLimit: bigint;
      messageId: bigint;
      merkleProof: MerkleProof;
      x: bigint;
      epoch: bigint;
    }): Promise<RLNFullProof>;
  }
  export class RLNVerifier {
    constructor(verificationKey: VerificationKey);
    verifyProof(rlnIdentifier: bigint, rlnFullProof: RLNFullProof): Promise<boolean>;
  }
}
