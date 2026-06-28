import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  // zod is installed by the consumer; never inline it into the bundle.
  external: ["zod"],
  target: "es2022",
});
