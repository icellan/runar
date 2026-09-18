import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * R-104 — "No file in the repository can prove any CI gate actually blocks a
 * merge."
 *
 * Branch protection lives in GitHub settings, so the repository can hold a
 * CLAIM (`.github/required-checks.json`) and a workflow that checks the claim
 * against the API. What the repository can enforce on its own — with no
 * network, on every run — is that the claim stays honest: that it names real
 * jobs, under the names GitHub actually matches, and accounts for every job in
 * ci.yml. That is this test.
 *
 * Without it the manifest is a document, and a document drifts: rename a job,
 * and the workflow starts checking for a status check that no longer exists.
 */

const REPO = resolve(__dirname, '..');
const MANIFEST_PATH = resolve(REPO, '.github/required-checks.json');
const CI_PATH = resolve(REPO, '.github/workflows/ci.yml');
const WORKFLOW_PATH = resolve(REPO, '.github/workflows/required-checks.yml');
const SCRIPT_PATH = resolve(REPO, '.github/scripts/check-required-checks.mjs');

interface Entry {
  job: string;
  check: string;
  reason?: string;
}
interface Manifest {
  branch: string;
  required: Entry[];
  not_required: Entry[];
}

/** Job ids and display names declared in ci.yml, in file order. */
function ciJobs(): Array<{ id: string; name: string }> {
  const lines = readFileSync(CI_PATH, 'utf-8').split('\n');
  const out: Array<{ id: string; name: string }> = [];
  let inJobs = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (/^jobs:\s*$/.test(line)) {
      inJobs = true;
      continue;
    }
    if (!inJobs) continue;
    const m = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
    if (!m) continue;
    const id = m[1]!;
    // GitHub shows a job's `name:` if it has one, else the job id — and it is
    // that string branch protection matches, not the id.
    let name = id;
    for (let j = i + 1; j < lines.length; j++) {
      if (/^ {2}[A-Za-z0-9_-]+:\s*$/.test(lines[j]!)) break;
      const n = /^ {4}name:\s*(.+?)\s*$/.exec(lines[j]!);
      if (n) {
        name = n[1]!.replace(/^['"]|['"]$/g, '');
        break;
      }
    }
    out.push({ id, name });
  }
  return out;
}

const manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf-8')) as Manifest;
const jobs = ciJobs();
const all = [...manifest.required, ...manifest.not_required];

describe('R-104 required-checks manifest', () => {
  it('parses a non-trivial set of jobs out of ci.yml', () => {
    // If the scraper breaks, every comparison below passes vacuously.
    expect(jobs.length).toBeGreaterThan(20);
    expect(jobs.map((j) => j.id)).toContain('conformance');
  });

  it('names the branch it is a claim about', () => {
    expect(manifest.branch).toBeTruthy();
  });

  it('every entry names a job that exists in ci.yml', () => {
    const ids = new Set(jobs.map((j) => j.id));
    const unknown = all.filter((e) => !ids.has(e.job)).map((e) => e.job);
    expect(unknown.join(', ')).toBe('');
  });

  it("every entry's check string is the name GitHub will report", () => {
    const byId = new Map(jobs.map((j) => [j.id, j.name]));
    const wrong = all
      .filter((e) => byId.get(e.job) !== e.check)
      .map((e) => `${e.job}: manifest says ${JSON.stringify(e.check)}, ci.yml says ${JSON.stringify(byId.get(e.job))}`);
    expect(wrong.join('\n  ')).toBe('');
  });

  it('every job in ci.yml is accounted for, in exactly one list', () => {
    const listed = new Map<string, number>();
    for (const e of all) listed.set(e.job, (listed.get(e.job) ?? 0) + 1);

    const unaccounted = jobs.filter((j) => !listed.has(j.id)).map((j) => j.id);
    expect(
      unaccounted.length === 0
        ? ''
        : `${unaccounted.length} ci.yml job(s) are in neither list — add them to "required", ` +
          `or to "not_required" with a reason: ${unaccounted.join(', ')}`,
    ).toBe('');

    const duplicated = [...listed.entries()].filter(([, n]) => n > 1).map(([id]) => id);
    expect(duplicated.join(', ')).toBe('');
  });

  it('every not_required entry carries a reason', () => {
    const unexplained = manifest.not_required.filter((e) => (e.reason ?? '').length < 40).map((e) => e.job);
    expect(unexplained.join(', ')).toBe('');
  });

  it('the conformance suite is claimed as blocking — the finding names it', () => {
    expect(manifest.required.map((e) => e.job)).toContain('conformance');
    expect(manifest.required.map((e) => e.job)).toContain('conformance-anf-parity');
  });

  it('the workflow and the checker it runs both exist and are wired together', () => {
    expect(existsSync(SCRIPT_PATH)).toBe(true);
    expect(existsSync(WORKFLOW_PATH)).toBe(true);
    const wf = readFileSync(WORKFLOW_PATH, 'utf-8');
    expect(wf).toContain('.github/scripts/check-required-checks.mjs');
    const script = readFileSync(SCRIPT_PATH, 'utf-8');
    expect(script).toContain('required_status_checks');
    expect(script).toContain('required-checks.json');
  });
});
