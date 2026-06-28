import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  // Workspace + zod deps are installed by the consumer and pinned by the
  // lockfile, so the nullifier / policy math is controlled at install time;
  // never inline them. Keeping @minister/* external preserves each primitive's
  // boundary (one audited copy of the field math, the policy AST, the nullifier
  // derivation) instead of forking a bundled copy per consumer.
  external: ["@minister/membership", "@minister/nullifier", "@minister/policy", "zod"],
  target: "es2022",
});
