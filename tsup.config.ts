import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  // jose and zod are peer/runtime deps installed by the consumer; never
  // inline them into the published bundle.
  external: ["jose", "zod"],
  target: "es2022",
});
