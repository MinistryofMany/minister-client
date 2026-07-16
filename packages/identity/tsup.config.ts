import { defineConfig } from "tsup";

export default defineConfig({
  // Two entry points: the root (Semaphore v4 derivation) and the zero-dependency
  // ./link (fragment capture + scrub + epoch decision), which pulls in no
  // @semaphore-protocol/identity so apps can import it at module scope.
  entry: ["src/index.ts", "src/link.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  // @semaphore-protocol/identity is installed by the consumer and pinned by the
  // lockfile, so the commitment math is controlled at install time; never inline
  // it into the bundle. It is pure v4 - there is intentionally no v3 / rlnjs in
  // this package's closure.
  external: ["@semaphore-protocol/identity"],
  target: "es2022",
});
