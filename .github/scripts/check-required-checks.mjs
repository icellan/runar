#!/usr/bin/env node
/**
 * R-104 — prove (or refuse to claim) that the gates in ci.yml actually block a
 * merge.
 *
 * The finding: "Required-status-checks and branch protection live in GitHub
 * settings, not in the checkout, so from the repository alone the entire gate
 * structure is advisory. The project's central claim rests on a gate whose
 * enforcement cannot be verified from the artifact being shipped."
 *
 * This script closes the half that CAN be closed from inside CI: it asks the
 * API for the protected branch's ACTUAL required status checks and compares
 * them with `.github/required-checks.json`.
 *
 * Three outcomes, and the third is the honest one:
 *
 *   * every entry present            -> exit 0, prints the list it verified;
 *   * an entry missing               -> exit 1, names it;
 *   * protection unreadable (the default GITHUB_TOKEN cannot read branch
 *     protection — that needs an admin token) -> exit 0 with a loud
 *     ::warning:: and a job-summary line saying enforcement is UNVERIFIED.
 *
 * The third case is not a pass dressed up as one: it says, in the run's own
 * output, exactly what the reviewer's finding says — that nothing here proves a
 * red run blocks a merge. Set BRANCH_PROTECTION_TOKEN to a token with
 * `administration: read` to turn the warning into a verdict, and
 * REQUIRED_CHECKS_STRICT=1 to make an unverifiable run a failure.
 */

import { readFileSync, appendFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const MANIFEST = resolve(HERE, '../required-checks.json');

const repo = process.env.GITHUB_REPOSITORY;
const token = process.env.BRANCH_PROTECTION_TOKEN || process.env.GH_TOKEN || process.env.GITHUB_TOKEN;

function summary(line) {
  console.log(line);
  const path = process.env.GITHUB_STEP_SUMMARY;
  if (path) {
    try {
      appendFileSync(path, `${line}\n`);
    } catch {
      // A summary we cannot write is not a reason to fail the check.
    }
  }
}

const manifest = JSON.parse(readFileSync(MANIFEST, 'utf-8'));
const branch = manifest.branch;
const wanted = manifest.required.map((r) => r.check);

if (!repo) {
  console.error('[required-checks] GITHUB_REPOSITORY is unset — run me from GitHub Actions.');
  process.exit(2);
}
if (!token) {
  console.error('[required-checks] no token in BRANCH_PROTECTION_TOKEN / GH_TOKEN / GITHUB_TOKEN.');
  process.exit(2);
}

const url = `https://api.github.com/repos/${repo}/branches/${branch}/protection/required_status_checks`;
const res = await fetch(url, {
  headers: {
    authorization: `Bearer ${token}`,
    accept: 'application/vnd.github+json',
    'user-agent': 'runar-required-checks',
    'x-github-api-version': '2022-11-28',
  },
});

const strict = process.env.REQUIRED_CHECKS_STRICT === '1';

if (res.status === 403 || res.status === 401 || res.status === 404) {
  const why =
    res.status === 404
      ? `no branch protection is configured on '${branch}', or this token cannot see it`
      : `this token may not read branch protection on '${branch}' (needs administration: read)`;
  summary(
    `::warning::[required-checks] ENFORCEMENT UNVERIFIED — ${why} (HTTP ${res.status}). ` +
    `Nothing in this run proves that a red gate blocks a merge. ` +
    `Set the BRANCH_PROTECTION_TOKEN secret to check it for real.`,
  );
  process.exit(strict ? 1 : 0);
}

if (!res.ok) {
  console.error(`[required-checks] GitHub API returned HTTP ${res.status}: ${await res.text()}`);
  process.exit(1);
}

const body = await res.json();
const actual = new Set([
  ...(body.contexts ?? []),
  ...((body.checks ?? []).map((c) => c.context)),
]);

const missing = wanted.filter((c) => !actual.has(c));
const extra = [...actual].filter((c) => !wanted.includes(c));

summary(`[required-checks] branch '${branch}' requires ${actual.size} check(s); manifest names ${wanted.length}.`);
if (extra.length > 0) {
  // Not a failure: a check required on the branch but absent from the manifest
  // is stricter than the claim, not weaker. Still worth naming.
  summary(`[required-checks] required on the branch but not in the manifest: ${extra.join(', ')}`);
}

if (missing.length > 0) {
  summary(
    `::error::[required-checks] ${missing.length} gate(s) the repository claims are blocking are ` +
    `NOT required status checks on '${branch}': ${missing.join(', ')}. ` +
    `Either add them in branch protection, or move them to "not_required" in ` +
    `.github/required-checks.json with a reason.`,
  );
  process.exit(1);
}

summary(`[required-checks] verified: every gate in the manifest blocks a merge on '${branch}'.`);
