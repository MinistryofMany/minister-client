import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  // The v3 quarantine deps are installed by the consumer and pinned exactly
  // (poseidon-lite 0.2.0, @semaphore-protocol/group 3.10.1, rlnjs 3.2.0,
  // ffjavascript 0.2.60), so the hash/proof math is controlled at install time;
  // never inline them into the bundle. They stay private to this package - the
  // public surface is bigint-only and never re-exports a Semaphore object.
  external: [
    "@ethersproject/bytes",
    "@ethersproject/keccak256",
    "@ethersproject/strings",
    "@semaphore-protocol/group",
    "ffjavascript",
    "poseidon-lite",
    "rlnjs",
  ],
  target: "es2022",
});
