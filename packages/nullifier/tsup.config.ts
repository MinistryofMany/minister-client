import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  // poseidon-lite is installed by the consumer and pinned (0.2.0) so the hash
  // math is controlled at install time; never inline it into the bundle.
  external: ["poseidon-lite"],
  target: "es2022",
});
