import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/auth-js.ts", "src/badges/index.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  // jose, zod, and the optional @auth/core peer are installed by the
  // consumer; never inline them into the published bundle.
  external: ["jose", "zod", "@auth/core"],
  target: "es2022",
});
