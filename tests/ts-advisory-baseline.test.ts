/**
 * R-108 — the TS/JS advisory baseline must stay reviewable.
 *
 * `audits/ts-dependency-advisories.json` is the list of HIGH/CRITICAL
 * advisories the dependency-audit gate tolerates. A list like that decays in
 * two directions: entries added without a reason, and entries that outlive the
 * advisory. The CI job catches the second (it fails on a baseline entry
 * `pnpm audit` no longer reports, which needs network). This test catches the
 * first, offline, on every run.
 *
 * The point of the classification field is that "why is this tolerated" has a
 * different answer for a vitest transitive than for a dependency of the
 * published compiler. An entry that cannot say which one it is has not been
 * reviewed.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

const REPO = resolve(__dirname, '..');
const BASELINE = 'audits/ts-dependency-advisories.json';

interface Entry {
  module: string;
  advisory: string;
  severity: string;
  title?: string;
  pulled_in_by?: string[];
  surface?: string;
  why_deferred?: string;
}

const doc = JSON.parse(readFileSync(join(REPO, BASELINE), 'utf8')) as {
  _surfaces: Record<string, string>;
  advisories: Entry[];
};

describe('R-108: the TS advisory baseline is reviewable', () => {
  it('the gate script exists and the baseline is non-empty', () => {
    expect(existsSync(join(REPO, 'scripts/check-ts-advisories.mjs'))).toBe(true);
    expect(doc.advisories.length).toBeGreaterThan(0);
  });

  it('the dependency-audit workflow actually runs the gate', () => {
    const yml = readFileSync(join(REPO, '.github/workflows/dependency-audit.yml'), 'utf8');
    expect(
      /node scripts\/check-ts-advisories\.mjs/.test(yml),
      'the TS tier is scanned by nothing again',
    ).toBe(true);
  });

  it('every entry names a real surface classification', () => {
    const known = new Set(Object.keys(doc._surfaces));
    const bad = doc.advisories
      .filter((e) => !e.surface || !known.has(e.surface))
      .map((e) => `${e.module}::${e.advisory} surface=${e.surface ?? '(none)'}`);
    expect(bad, `classifications must be one of: ${[...known].join(', ')}`).toEqual([]);
  });

  it('every entry says why it is deferred, and says something', () => {
    const bad = doc.advisories
      .filter((e) => !e.why_deferred || e.why_deferred.trim().length < 20 ||
                     /NEEDS CLASSIFICATION/i.test(e.why_deferred))
      .map((e) => `${e.module}::${e.advisory}`);
    expect(bad, `these entries carry no usable reason`).toEqual([]);
  });

  it('every entry names the dependent that pulls it in', () => {
    const bad = doc.advisories
      .filter((e) => !Array.isArray(e.pulled_in_by) || e.pulled_in_by.length === 0)
      .map((e) => `${e.module}::${e.advisory}`);
    expect(
      bad,
      `without the direct dependent, nobody can tell what to upgrade to remove the entry`,
    ).toEqual([]);
  });

  it('no duplicate module::advisory keys (a shadowed entry is the one a reviewer reads)', () => {
    const keys = doc.advisories.map((e) => `${e.module}::${e.advisory}`);
    expect(keys.length).toBe(new Set(keys).size);
  });

  it('only HIGH and CRITICAL are baselined (lower severities are not enforced anyway)', () => {
    const bad = doc.advisories
      .filter((e) => !['high', 'critical'].includes(e.severity))
      .map((e) => `${e.module}::${e.advisory} severity=${e.severity}`);
    expect(bad).toEqual([]);
  });
});
