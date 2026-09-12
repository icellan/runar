#!/usr/bin/env node
/**
 * R-108 — the TypeScript/JS dependency-advisory gate.
 *
 * `.github/workflows/dependency-audit.yml` scans six tiers and said TypeScript
 * was "already covered by `pnpm audit` in the repo's main lifecycle". That
 * command appeared nowhere else in the repository, so the tier with the largest
 * third-party surface had no dependency scanning at all.
 *
 * Policy, matching the other six tiers in that workflow:
 *   HIGH / CRITICAL  -> fail, unless the advisory is listed in
 *                       `audits/ts-dependency-advisories.json`
 *   MEDIUM / LOW     -> reported, not enforced
 *
 * The baseline is not an amnesty. It exists because 21 HIGH/CRITICAL advisories
 * were already present when the gate was written, all of them in test, release
 * or compile-time tooling, and turning the gate on as a hard failure would have
 * blocked every merge on day one without making anything safer. What the gate
 * buys immediately is that advisory number 22 fails the build.
 *
 * A listed advisory that `pnpm audit` no longer reports is ALSO a failure: a
 * stale exemption is how a list like this stops describing reality.
 *
 * Usage:
 *   node scripts/check-ts-advisories.mjs                 # runs pnpm audit itself
 *   node scripts/check-ts-advisories.mjs --input a.json  # reads a saved report
 */
import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE = 'audits/ts-dependency-advisories.json';
const ENFORCED = new Set(['high', 'critical']);

function readReport() {
  const i = process.argv.indexOf('--input');
  if (i >= 0 && process.argv[i + 1]) {
    return JSON.parse(readFileSync(process.argv[i + 1], 'utf8'));
  }
  // `pnpm audit` exits non-zero whenever it finds anything, so the exit status
  // is not the signal — the parsed report is. Capture stdout either way.
  let out = '';
  try {
    out = execSync('pnpm audit --json', { cwd: REPO, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  } catch (err) {
    out = err.stdout ?? '';
  }
  if (out.trim() === '') {
    console.error('pnpm audit produced no output — treating as a harness failure, not a clean scan.');
    process.exit(2);
  }
  return JSON.parse(out);
}

function advisoryId(a, key) {
  return a.github_advisory_id ?? (Array.isArray(a.cves) && a.cves[0]) ?? key;
}

const baseline = JSON.parse(readFileSync(join(REPO, BASELINE), 'utf8'));
const allowed = new Map(baseline.advisories.map((e) => [`${e.module}::${e.advisory}`, e]));

const report = readReport();
const advisories = report.advisories ?? {};

const reported = new Map();
for (const [key, a] of Object.entries(advisories)) {
  if (!ENFORCED.has(a.severity)) continue;
  reported.set(`${a.module_name}::${advisoryId(a, key)}`, a);
}

const unlisted = [...reported.entries()].filter(([k]) => !allowed.has(k));
const stale = [...allowed.keys()].filter((k) => !reported.has(k));

const counts = report.metadata?.vulnerabilities ?? {};
console.log(
  `pnpm audit: critical=${counts.critical ?? 0} high=${counts.high ?? 0} ` +
    `moderate=${counts.moderate ?? 0} low=${counts.low ?? 0}`,
);
console.log(`enforced (high+critical) distinct advisories: ${reported.size}`);
console.log(`baseline entries: ${allowed.size}`);

if (unlisted.length > 0) {
  console.error(`\n${unlisted.length} HIGH/CRITICAL advisory(ies) NOT in ${BASELINE}:`);
  for (const [k, a] of unlisted) {
    console.error(`  - ${k}  ${a.severity}  ${(a.title ?? '').slice(0, 90)}`);
  }
  console.error(
    `\nUpgrade the direct dependent that pulls it in. Adding it to the baseline is the ` +
      `last resort, and every entry needs a surface classification and a reason.`,
  );
}
if (stale.length > 0) {
  console.error(`\n${stale.length} baseline entry(ies) no longer reported — remove them:`);
  for (const k of stale) console.error(`  - ${k}`);
}

process.exit(unlisted.length > 0 || stale.length > 0 ? 1 : 0);
