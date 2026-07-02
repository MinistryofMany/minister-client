import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  getRateCommitmentHash,
  deriveSecret,
  deriveCommitment,
  randomBigInt,
} from "@ministryofmany/rln";
import { rlnEngine } from "./rln.js";
import { createMembership } from "../membership.js";
import { liveSnapshotStore } from "../store.js";
import type { ArtifactSource } from "../artifacts.js";
import type { EligibleLeaf, RlnGroupProvider } from "../provider.js";
import type { SemaphoreIdentityLike } from "@ministryofmany/identity";
import type { TreeRef } from "../types.js";

// Real RLN (Semaphore v3) proof, end-to-end. The RLN engine's verify MUST pass
// the SNAPSHOT ROOT as @ministryofmany/rln verifyRlnProof's expectedRoot (control 1,
// R1 for RLN): a proof's root is pinned to the resolved snapshot even though RLN
// also binds the root in publicSignals.
//
// The depth-20 RLN circuit artifacts are INJECTED. Resolve them from
// MOM_RLN_ARTIFACTS_DIR when set, else fall back to the sibling Discreetly
// circuits package (the lifted-from origin) five levels up from this file (../ =
// src, membership, packages, minister-client, then the MinistryOfMany workspace
// root). If absent we WARN and skip the proof tests loudly - never a silent skip.
const ENV_DIR = process.env.MOM_RLN_ARTIFACTS_DIR;
const ARTIFACT_BASE = ENV_DIR
  ? ENV_DIR.endsWith("/")
    ? ENV_DIR
    : `${ENV_DIR}/`
  : fileURLToPath(
      new URL("../../../../../Discreetly/packages/circuits/artifacts/rln/", import.meta.url),
    );
const wasmPath = `${ARTIFACT_BASE}circuit.wasm`;
const zkeyPath = `${ARTIFACT_BASE}final.zkey`;
const vkeyPath = `${ARTIFACT_BASE}verification_key.json`;
const haveArtifacts = existsSync(wasmPath) && existsSync(zkeyPath) && existsSync(vkeyPath);
if (!haveArtifacts) {
  console.warn(
    `SKIPPING e2e: RLN circuit artifacts not found at ${ARTIFACT_BASE} (set MOM_RLN_ARTIFACTS_DIR to override)`,
  );
}

function membershipArtifacts(): ArtifactSource {
  return {
    async load() {
      return { wasm: new Uint8Array(readFileSync(wasmPath)), zkey: new Uint8Array(readFileSync(zkeyPath)) };
    },
  };
}

function verificationKey(): Record<string, unknown> {
  return JSON.parse(readFileSync(vkeyPath, "utf8")) as Record<string, unknown>;
}

// The RLN identity uses Semaphore v3-style secrets: the circuit derives the
// commitment as poseidon1(identitySecret), so the leaf MUST be the rate
// commitment of THAT commitment, not a v4 commitment. We mint a v3-style RLN
// identity from @ministryofmany/rln's own derivation (random trapdoor/nullifier ->
// secret -> commitment), exactly the contract the depth-20 circuit expects.
interface RlnId {
  commitment: bigint;
  identitySecret: bigint;
}
function makeRlnId(): RlnId {
  const trapdoor = randomBigInt();
  const nullifier = randomBigInt();
  const identitySecret = deriveSecret(trapdoor, nullifier);
  const commitment = deriveCommitment(identitySecret);
  return { commitment, identitySecret };
}
function likeOf(commitment: bigint): SemaphoreIdentityLike {
  return { commitment: commitment.toString(), native: {} };
}

const RLN_IDENTIFIER = "12345";
const USER_MESSAGE_LIMIT = 10;

function rlnProviderFor(getCommitments: () => bigint[]): RlnGroupProvider {
  return {
    shape: { kind: "fixed", depth: 20 },
    engine: "rln",
    async listEligible(): Promise<EligibleLeaf[]> {
      return getCommitments().map((ic) => ({
        leaf: getRateCommitmentHash(ic, USER_MESSAGE_LIMIT).toString(),
        commitment: ic.toString(),
      }));
    },
    async engineParams() {
      return { engine: "rln", rlnIdentifier: RLN_IDENTIFIER, userMessageLimit: USER_MESSAGE_LIMIT };
    },
  };
}

describe.runIf(haveArtifacts)("rlnEngine end-to-end (real v3 RLN proof against the snapshot root)", () => {
  it("a real RLN proof verifies against the live snapshot root and exposes the nullifier + x/y", async () => {
    // A real v3-style RLN identity: the commitment (for the leaf) and the secret
    // (the RLN identitySecret circuit input) satisfy commitment = poseidon1(secret).
    const id = makeRlnId();
    const commitment = id.commitment;
    const identitySecret = id.identitySecret;

    const members = [commitment, 222n, 333n];
    const provider = rlnProviderFor(() => members);
    const store = liveSnapshotStore(provider, rlnEngine);
    const membership = createMembership({ provider, store });
    const ref: TreeRef = { context: "room1", subTree: "room" };

    const snapshot = await membership.current(ref);
    const epoch = 42n;

    const proof = await rlnEngine.prove({
      identity: likeOf(commitment),
      snapshot,
      scope: "room1",
      message: "hello world",
      artifacts: membershipArtifacts(),
      rln: {
        rlnIdentifier: RLN_IDENTIFIER,
        userMessageLimit: USER_MESSAGE_LIMIT,
        identitySecret: identitySecret.toString(),
        epoch,
        messageId: 0n,
      },
    });
    expect(proof.kind).toBe("rln");

    const res = await membership.verify({
      ref,
      proof,
      expectedScope: "room1",
      expectedMessage: "hello world",
      rln: {
        currentEpoch: epoch,
        rlnIdentifier: RLN_IDENTIFIER,
        verificationKey: verificationKey(),
      },
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(typeof res.nullifier).toBe("string");
      expect(BigInt(res.nullifier)).toBeGreaterThan(0n);
      expect(res.rln?.epoch).toBe(epoch);
      expect(typeof res.rln?.x).toBe("string");
      expect(typeof res.rln?.y).toBe("string");
    }
  }, 90_000);

  it("rejects when the proof's signal does not match the expected message (bad-signal)", async () => {
    const id = makeRlnId();
    const members = [id.commitment, 222n];
    const provider = rlnProviderFor(() => members);
    const membership = createMembership({ provider, store: liveSnapshotStore(provider, rlnEngine) });
    const ref: TreeRef = { context: "room1", subTree: "room" };
    const snapshot = await membership.current(ref);
    const epoch = 7n;

    const proof = await rlnEngine.prove({
      identity: likeOf(id.commitment),
      snapshot,
      scope: "room1",
      message: "original message",
      artifacts: membershipArtifacts(),
      rln: {
        rlnIdentifier: RLN_IDENTIFIER,
        userMessageLimit: USER_MESSAGE_LIMIT,
        identitySecret: id.identitySecret.toString(),
        epoch,
      },
    });

    const res = await membership.verify({
      ref,
      proof,
      expectedScope: "room1",
      expectedMessage: "TAMPERED message",
      rln: { currentEpoch: epoch, rlnIdentifier: RLN_IDENTIFIER, verificationKey: verificationKey() },
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("bad-signal");
  }, 90_000);

  it("rejects an out-of-window epoch (bad-epoch)", async () => {
    const id = makeRlnId();
    const members = [id.commitment, 222n];
    const provider = rlnProviderFor(() => members);
    const membership = createMembership({ provider, store: liveSnapshotStore(provider, rlnEngine) });
    const ref: TreeRef = { context: "room1", subTree: "room" };
    const snapshot = await membership.current(ref);
    const epoch = 7n;

    const proof = await rlnEngine.prove({
      identity: likeOf(id.commitment),
      snapshot,
      scope: "room1",
      message: "m",
      artifacts: membershipArtifacts(),
      rln: {
        rlnIdentifier: RLN_IDENTIFIER,
        userMessageLimit: USER_MESSAGE_LIMIT,
        identitySecret: id.identitySecret.toString(),
        epoch,
      },
    });

    const res = await membership.verify({
      ref,
      proof,
      expectedScope: "room1",
      expectedMessage: "m",
      rln: {
        currentEpoch: epoch + 100n, // far outside the +/-1 window
        rlnIdentifier: RLN_IDENTIFIER,
        verificationKey: verificationKey(),
      },
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("bad-epoch");
  }, 90_000);

  it("R1 pin holds for RLN: a proof whose root is unknown for the tree is rejected", async () => {
    // Prove against a snapshot, then attempt to verify against a DIFFERENT tree
    // whose live root differs. The store resolves by (context, subTree); the
    // proof's root is not the other tree's live root -> rejected.
    const id = makeRlnId();
    const roomA = [id.commitment, 222n];
    const roomB = [id.commitment, 222n, 333n, 444n]; // different set -> different root

    const provider: RlnGroupProvider = {
      shape: { kind: "fixed", depth: 20 },
      engine: "rln",
      async listEligible(ref) {
        const cs = ref.context === "roomA" ? roomA : roomB;
        return cs.map((ic) => ({
          leaf: getRateCommitmentHash(ic, USER_MESSAGE_LIMIT).toString(),
          commitment: ic.toString(),
        }));
      },
      async engineParams() {
        return { engine: "rln", rlnIdentifier: RLN_IDENTIFIER, userMessageLimit: USER_MESSAGE_LIMIT };
      },
    };
    const membership = createMembership({ provider, store: liveSnapshotStore(provider, rlnEngine) });
    const refA: TreeRef = { context: "roomA", subTree: "room" };
    const refB: TreeRef = { context: "roomB", subTree: "room" };
    const epoch = 9n;

    const snapA = await membership.current(refA);
    const proof = await rlnEngine.prove({
      identity: likeOf(id.commitment),
      snapshot: snapA,
      scope: "roomA",
      message: "m",
      artifacts: membershipArtifacts(),
      rln: {
        rlnIdentifier: RLN_IDENTIFIER,
        userMessageLimit: USER_MESSAGE_LIMIT,
        identitySecret: id.identitySecret.toString(),
        epoch,
      },
    });

    // Verify the roomA proof as roomB: the proof root is roomA's, not roomB's
    // live root, so it is rejected as stale (the live store has no history).
    const res = await membership.verify({
      ref: refB,
      proof,
      expectedScope: "roomA",
      expectedMessage: "m",
      rln: { currentEpoch: epoch, rlnIdentifier: RLN_IDENTIFIER, verificationKey: verificationKey() },
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("stale-root");
  }, 120_000);
});
