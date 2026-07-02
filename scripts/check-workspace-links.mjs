#!/usr/bin/env node
// Hard pretest: fail LOUDLY if any `@ministryofmany/*` workspace dependency is
// not linked into its consuming package.
//
// Why this exists: on a checkout where `pnpm install` has not run (or the link
// graph is stale), a package's `@ministryofmany/*` import fails to resolve. A
// suite that imports through such a dep then collects zero tests and the run
// still exits green - a phantom pass that silently drops safety-critical
// coverage (e.g. the poll one-vote / unstuffability suites). This check turns
// that into an up-front error before any test runs.

import { readFileSync, existsSync, statSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const packagesDir = join(root, "packages");

const DEP_FIELDS = ["dependencies", "devDependencies", "peerDependencies"];
const SCOPE = "@ministryofmany/";

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

/** A dep is "linked" if it resolves to a real dir with a package.json, either in
 *  the consumer's own node_modules (pnpm's per-package symlink) or hoisted at the
 *  workspace root node_modules. We check the linked TARGET, not its built dist,
 *  so an unbuilt-but-linked package still passes. */
function isLinked(consumerDir, depName) {
  const candidates = [
    join(consumerDir, "node_modules", depName),
    join(root, "node_modules", depName),
  ];
  for (const c of candidates) {
    if (!existsSync(c)) continue;
    try {
      const pkgJson = join(c, "package.json");
      if (statSync(c).isDirectory() && existsSync(pkgJson)) return true;
    } catch {
      // dangling symlink -> not linked; keep checking other candidates.
    }
  }
  return false;
}

const failures = [];
const checked = [];

const pkgDirs = readdirSync(packagesDir, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => join(packagesDir, d.name));

for (const consumerDir of pkgDirs) {
  const manifestPath = join(consumerDir, "package.json");
  if (!existsSync(manifestPath)) continue;
  const manifest = readJson(manifestPath);
  for (const field of DEP_FIELDS) {
    const deps = manifest[field] ?? {};
    for (const depName of Object.keys(deps)) {
      if (!depName.startsWith(SCOPE)) continue;
      checked.push(`${manifest.name} -> ${depName}`);
      if (!isLinked(consumerDir, depName)) {
        failures.push(
          `  ${manifest.name} (${field}) cannot resolve ${depName} - run \`pnpm install\``,
        );
      }
    }
  }
}

if (failures.length > 0) {
  console.error(
    `check-workspace-links: ${failures.length} unresolved @ministryofmany/* workspace link(s):`,
  );
  console.error(failures.join("\n"));
  process.exit(1);
}

console.log(
  `check-workspace-links: OK - all ${checked.length} @ministryofmany/* workspace links resolve.`,
);
