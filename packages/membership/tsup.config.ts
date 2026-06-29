import { defineConfig } from "tsup";

export default defineConfig({
  // Two entry points: the server-side root (snapshot + verify + the verifier half
  // of both engines) and the client subpath (proof generation only), so the heavy
  // prover WASM never lands in a server bundle (matching FreedInk's lazy-import +
  // Discreetly's transpilePackages split).
  entry: ["src/index.ts", "src/client.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  // Workspace + Semaphore deps are installed by the consumer and pinned by the
  // lockfile, so the hashing / proof math is controlled at install time; never
  // inline them. @ministryofmany/rln is the v3 + RLN quarantine island; keeping it
  // external preserves that boundary.
  external: [
    "@ministryofmany/identity",
    "@ministryofmany/rln",
    "@semaphore-protocol/group",
    "@semaphore-protocol/proof",
    "@semaphore-protocol/identity",
  ],
  target: "es2022",
});
