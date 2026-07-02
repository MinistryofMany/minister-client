import { defineConfig } from "tsup";

export default defineConfig({
  // Three entry points: the server-side root (snapshot + verify + the semaphore
  // engine), the client subpath (proof generation only, so the heavy prover WASM
  // never lands in a server bundle - matching FreedInk's lazy-import +
  // Discreetly's transpilePackages split), and the rln subpath (the RLN engine,
  // kept off the root so semaphore-only consumers never touch the
  // @ministryofmany/rln island).
  entry: ["src/index.ts", "src/client.ts", "src/rln.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  // LOAD-BEARING: engines/index.ts reaches ./rln.js only via a dynamic import.
  // With splitting the rln module becomes its own chunk that the root entry never
  // statically imports; withOUT splitting esbuild would inline the dynamic import
  // and hoist `import "@ministryofmany/rln"` back into dist/index.js, re-eagering
  // the very island this packaging fix quarantines. (true is tsup's esm default;
  // pinned here so a config tweak can't silently regress it.)
  splitting: true,
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
