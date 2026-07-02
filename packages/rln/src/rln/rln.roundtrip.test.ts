import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Identity } from "@semaphore-protocol/identity";
import { getRateCommitmentHash } from "../field.js";
import { calculateSignalHash } from "../signal-hash.js";
import { computeRoot } from "./merkle.js";
import { staticArtifactSource } from "./artifacts.js";
import type { ArtifactSource, RlnVerificationKey } from "./artifacts.js";
import { generateRlnProof } from "./prover.js";
import { verifyRlnProof } from "./verifier.js";

// The depth-20 RLN circuit artifacts are INJECTED, not hard-coded. Resolve them
// from MOM_RLN_ARTIFACTS_DIR when set, else fall back to the sibling Discreetly
// circuits package (the lifted-from origin) five levels up from this file (../ =
// src, rln, packages, minister-client, then the MinistryOfMany workspace root).
// If they are genuinely absent we WARN and skip the proof tests loudly - never a
// silent skip. The pure-math golden vectors above still gate the island.
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

function artifactSource(): ArtifactSource {
  const verificationKey = JSON.parse(readFileSync(vkeyPath, "utf8")) as RlnVerificationKey;
  return staticArtifactSource({
    prover: { wasm: wasmPath, zkey: zkeyPath },
    verificationKey,
  });
}

describe.runIf(haveArtifacts)("RLN prove -> verify round-trip + nullifier", () => {
  it("accepts a valid proof, exposes the nullifier, and rejects tampering", async () => {
    const artifacts = artifactSource();
    const identity = new Identity();
    const rlnIdentifier = 12345n;
    const userMessageLimit = 10n;
    const messageId = 0n;
    const epoch = 42n;

    const rateCommitment = getRateCommitmentHash(identity.commitment, userMessageLimit);
    const leaves = [rateCommitment];
    const expectedRoot = computeRoot(rlnIdentifier, leaves);
    const x = calculateSignalHash("hello world");

    const proof = await generateRlnProof(
      {
        rlnIdentifier,
        identitySecret: identity.secret,
        userMessageLimit,
        messageId,
        leaves,
        leaf: rateCommitment,
        x,
        epoch,
      },
      artifacts,
    );

    // The proof carries the RLN nullifier (per epoch + rlnIdentifier) and binds x + root.
    expect(BigInt(proof.snarkProof.publicSignals.x)).toBe(x);
    expect(BigInt(proof.snarkProof.publicSignals.root)).toBe(expectedRoot);
    expect(typeof proof.snarkProof.publicSignals.nullifier).toBe("string");
    expect(BigInt(proof.snarkProof.publicSignals.nullifier)).toBeGreaterThan(0n);

    // Valid proof verifies.
    await expect(
      verifyRlnProof(
        { rlnIdentifier, proof, signalHash: x, epoch, currentEpoch: epoch, expectedRoot },
        artifacts,
      ),
    ).resolves.toBe(true);

    // Wrong signal hash -> reject.
    await expect(
      verifyRlnProof(
        { rlnIdentifier, proof, signalHash: x + 1n, epoch, currentEpoch: epoch, expectedRoot },
        artifacts,
      ),
    ).resolves.toBe(false);

    // Epoch outside the window -> reject.
    await expect(
      verifyRlnProof(
        { rlnIdentifier, proof, signalHash: x, epoch, currentEpoch: epoch + 5n, expectedRoot },
        artifacts,
      ),
    ).resolves.toBe(false);

    // Wrong expected root -> reject.
    await expect(
      verifyRlnProof(
        {
          rlnIdentifier,
          proof,
          signalHash: x,
          epoch,
          currentEpoch: epoch,
          expectedRoot: expectedRoot + 1n,
        },
        artifacts,
      ),
    ).resolves.toBe(false);
  }, 60_000);

  it("the RLN nullifier is identical for the same (identity, epoch, rlnIdentifier) and differs across epochs", async () => {
    const artifacts = artifactSource();
    const identity = new Identity();
    const rlnIdentifier = 999n;
    const userMessageLimit = 10n;
    const rateCommitment = getRateCommitmentHash(identity.commitment, userMessageLimit);
    const leaves = [rateCommitment];
    const x = calculateSignalHash("nullifier check");

    const mk = (epoch: bigint, messageId: bigint) =>
      generateRlnProof(
        {
          rlnIdentifier,
          identitySecret: identity.secret,
          userMessageLimit,
          messageId,
          leaves,
          leaf: rateCommitment,
          x,
          epoch,
        },
        artifacts,
      );

    const p1 = await mk(7n, 0n);
    const p2 = await mk(7n, 0n);
    const p3 = await mk(8n, 0n);

    // Same epoch + same identity -> same RLN nullifier (rate-limit anchor).
    expect(p1.snarkProof.publicSignals.nullifier).toBe(p2.snarkProof.publicSignals.nullifier);
    // Different epoch -> different nullifier.
    expect(p1.snarkProof.publicSignals.nullifier).not.toBe(
      p3.snarkProof.publicSignals.nullifier,
    );
  }, 90_000);
});
