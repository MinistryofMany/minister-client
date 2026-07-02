import { defineConfig, configDefaults } from "vitest/config";

// Root config for the whole workspace. `pnpm exec vitest run` from the repo root
// collects the SDK's own `src/**` suites plus every `packages/*` suite in one run.
//
// The exclude list is load-bearing: without `**/.claude/**` / `**/worktrees/**`,
// a git worktree left under `.claude/worktrees/` (a full duplicate package tree
// with stale imports) gets globbed into the run, doubling suites and failing on
// obsolete imports. Keep those excluded so a future worktree can't pollute a run.
export default defineConfig({
  test: {
    include: ["src/**/*.test.ts", "packages/*/src/**/*.test.ts", "packages/*/test/**/*.test.ts"],
    exclude: [
      ...configDefaults.exclude,
      "**/dist/**",
      "**/.claude/**",
      "**/worktrees/**",
    ],
    // Crypto/keygen and real ZK proof suites are slow; give them room.
    testTimeout: 60_000,
    hookTimeout: 60_000,
    // A run that matches no test files is a failure, not a pass: it usually means
    // a glob broke or a package's suites silently dropped out.
    passWithNoTests: false,
  },
});
