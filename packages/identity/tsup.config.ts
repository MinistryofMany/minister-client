import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  // @scure/bip39 and @semaphore-protocol/identity are installed by the consumer
  // and pinned by the lockfile, so the hashing / commitment math is controlled
  // at install time; never inline them into the bundle. @semaphore-protocol/identity
  // is pure v4 - there is intentionally no v3 / rlnjs in this package's closure.
  external: ["@scure/bip39", "@semaphore-protocol/identity"],
  target: "es2022",
});
