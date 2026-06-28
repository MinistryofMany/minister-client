import { defineConfig } from "tsup";

export default defineConfig({
  // Three entry points mirroring the FreedInk client/server split + the
  // @minister/client root-plus-subpaths convention:
  //   - root: shared isomorphic wire helpers (buildInfo, codecs, SUITE_NAME, types)
  //   - client: browser prepare/finalize (lazy-loads @cloudflare/blindrsa-ts)
  //   - server: Signer backends, Issuer, verify, keygen, store interfaces
  entry: ["src/index.ts", "src/client/index.ts", "src/server/index.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  // @cloudflare/blindrsa-ts is a PEER dep pinned to EXACTLY 0.4.6: the
  // Chromium-safe finalize reaches into its internal modules (lib/src/sjcl,
  // lib/src/util), which have no `exports` map and are not a stable public API.
  // Never inline it into the bundle - the consumer's pinned copy controls the
  // crypto math at install time, and the deep imports must resolve against that
  // exact installed version. node:crypto stays external too (Node builtin).
  external: ["@cloudflare/blindrsa-ts", /^node:/],
  target: "es2022",
});
