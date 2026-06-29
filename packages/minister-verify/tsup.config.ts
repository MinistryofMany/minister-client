import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  // Peers/workspace deps are installed by the consumer; never inline them.
  external: ["@ministryofmany/client", "@ministryofmany/policy", "jose"],
  target: "es2022",
});
