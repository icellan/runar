/**
 * R-241 (CL-GAP-063): the dependency-audit workflow's header states a severity
 * policy none of its jobs implement.
 *
 * The header said:
 *
 *   * HIGH / CRITICAL severity advisories  -> fail the job (block merge).
 *   * MEDIUM / LOW severity advisories     -> annotate / warn, do not fail.
 *
 * No job filters by severity. Every one fails on any advisory its scanner
 * reports, and each job's own comment says so — cargo-audit "we accept the
 * default exit policy", pip-audit "exits non-zero on any finding by default",
 * bundler-audit "exits non-zero on any advisory". The rust job's comment is the
 * clearest admission of the gap the finding names.
 *
 * The jobs are not wrong. Fail-on-any is STRICTER than the stated policy, and
 * each ecosystem's reason is already written beside it: the advisory databases
 * these scanners read only carry advisories at warning level or above for this
 * dependency surface. The defect is the header — a reader learns a rule the
 * repository does not follow, and files a bug the first time a MEDIUM advisory
 * blocks their merge.
 *
 * This test holds the header to what the jobs do: it may not promise a
 * warn-don't-fail tier while every scanner job fails on any finding.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const WF = '.github/workflows/dependency-audit.yml';

const workflow = () => readFileSync(join(ROOT, WF), 'utf8');

/** Everything above the first job — the file's policy statement. */
function header(): string {
  const text = workflow();
  const firstJob = text.indexOf('\njobs:');
  expect(firstJob, 'the workflow has no jobs: block').toBeGreaterThan(-1);
  return text.slice(0, firstJob);
}

/** Job ids declared under `jobs:`. */
function jobIds(): string[] {
  return [...workflow().matchAll(/^ {2}([a-z0-9-]+-audit):$/gm)].map((m) => m[1]!);
}

describe('R-241: the audit workflow documents the policy it enforces', () => {
  it('the workflow is where the test thinks it is', () => {
    expect(existsSync(join(ROOT, WF)), `${WF} moved`).toBe(true);
    expect(jobIds().length, 'no *-audit jobs found').toBeGreaterThanOrEqual(7);
  });

  it('does not promise that MEDIUM/LOW advisories only warn', () => {
    const offenders = header()
      .split('\n')
      .filter((l) => /MEDIUM|LOW/.test(l) && /warn|annotate|do not fail/i.test(l))
      .filter((l) => !/used to say|R-241/.test(l));
    expect(
      offenders,
      'the header promises a warn-only tier, and no job implements one — every ' +
        'scanner here fails on any advisory it reports',
    ).toEqual([]);
  });

  it('states that the enforced behaviour is fail-on-any', () => {
    expect(header()).toMatch(/fail(s|ing)? on any (reported )?advisory/i);
  });

  it('every audit job is named in the header', () => {
    const h = header();
    const missing = jobIds().filter((id) => !h.includes(id.replace('-audit', '')));
    expect(missing, 'audit jobs the policy section does not account for').toEqual([]);
  });
});
