import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Crypto/keygen tests are slow; give them room. The byte-identical and
    // interop tests run real 1024/2048-bit safe-prime keygen.
    testTimeout: 60_000,
    hookTimeout: 60_000,
    include: ["src/**/*.test.ts", "test/**/*.test.ts"],
  },
});
