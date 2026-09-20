#!/usr/bin/env node
// Copies @mp4marketing/pg-plan-guard's source into
// supabase/functions/_shared/, so the Edge Function can import it as a
// plain relative file instead of via a `npm:@mp4marketing/pg-plan-guard`
// specifier.
//
// WHY THIS EXISTS: `supabase functions deploy`'s Deno-based bundler cannot
// reliably resolve a PRIVATE npm package (GitHub Packages, in our case)
// during deploy, even with a correctly-placed, correctly-populated .npmrc
// (confirmed live 2026-09-20 -- both known bugs, wrong .npmrc location and
// no ${VAR} substitution, were fixed and the failure was byte-for-byte
// identical anyway: "npm package '@mp4marketing/pg-plan-guard' does not
// exist"). This matches a real, currently-unfixed upstream bug
// (supabase/cli#4927, closed "not planned") -- `functions serve` resolves
// private npm: specifiers correctly, `functions deploy` does not, using the
// same CLI, same config. `postgres@3.4.4` (also an `npm:` import in
// index.ts) is unaffected because it's on the PUBLIC npm registry --
// Deno's bug is specific to registries that need auth.
//
// THE FIX: sidestep Deno's private-registry resolution entirely for this
// one dependency. `npm install` (real Node/npm, not Deno) already proven to
// authenticate against npm.pkg.github.com correctly via the standard
// GITHUB_TOKEN + .npmrc mechanism -- so install it as an ordinary
// devDependency, then copy its already-resolved source file in before
// `supabase functions deploy` runs. index.ts imports the copy via a
// relative path, never `npm:@mp4marketing/pg-plan-guard`.
//
// The version pinned in package.json's devDependencies is the ONE place
// this now needs to stay in sync with the Worker side's own package.json --
// run `npm run vendor:pg-plan-guard` (this script) after bumping it there,
// both locally and as a CI step immediately before every deploy, so the
// copy can never silently go stale between deploys.
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..");
const source = join(repoRoot, "node_modules", "@mp4marketing", "pg-plan-guard", "src", "index.js");
const destDir = join(repoRoot, "supabase", "functions", "_shared");
const dest = join(destDir, "pg-plan-guard.js");

mkdirSync(destDir, { recursive: true });
copyFileSync(source, dest);
console.log(`Vendored ${source} -> ${dest}`);
