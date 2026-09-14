/**
 * R-216 (CL-GAP-061): the Teranode integration leg only runs on manual
 * `workflow_dispatch` with an explicit opt-in flag, so every on-chain claim
 * specific to Teranode is unverified continuously.
 *
 * Confirmed. `ci.yml`'s job carried
 *
 *     if: github.event_name == 'workflow_dispatch' && inputs.run_teranode
 *
 * and `ci.yml` has no `schedule` trigger at all, so the leg ran only when
 * someone remembered to tick a box. The SV Node regtest suite runs on every PR;
 * Teranode — the other production node implementation — ran on none.
 *
 * The per-PR opt-out is sound and is kept: the compose stack is 10+
 * microservices plus a ~10k-block pre-mine, too heavy for every pull request.
 * But "too heavy per PR" and "never runs unattended" are different decisions,
 * and only the first was intended. A nightly workflow now runs it.
 *
 * WHAT THIS TEST DOES NOT SHOW, stated plainly: it cannot run the Teranode
 * stack, so it does not demonstrate that the nightly run PASSES — only that the
 * leg is scheduled, well-formed, and actually invokes the suite. Whether
 * Teranode's own claims hold is what the nightly run itself will report.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIR = join(ROOT, '.github/workflows');

/**
 * Workflows as raw text.
 *
 * No YAML parser: the repo root has no `js-yaml` dependency, and adding one to
 * assert a scheduling fact would be a heavier change than the fact. The two
 * shapes below — a top-level `schedule:` under `on:`, and a `run:` naming the
 * script — are unambiguous in this file set, and the first case fails loudly if
 * the script is ever renamed.
 */
function workflows(): { file: string; text: string }[] {
  return readdirSync(DIR)
    .filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'))
    .sort()
    .map((file) => ({ file, text: readFileSync(join(DIR, file), 'utf-8') }));
}

function invokesTeranode(text: string): boolean {
  return codeOnly(text).includes('integration:teranode:run');
}

/** A top-level `schedule:` trigger, i.e. two-space indented under `on:`. */
function isScheduled(text: string): boolean {
  return /^\s{2}schedule:/m.test(codeOnly(text));
}

/**
 * The workflow with `#` comment lines removed.
 *
 * A guard about what a workflow DOES must not read what it SAYS. The first
 * version of the dispatch-gate case below matched raw text and failed on this
 * repo's own new workflow, whose header quotes the very `if:` expression it
 * exists to forbid — the fourth time in this remediation pass that explanatory
 * prose collided with a guard scanning for a literal (R-228, R-210, R-200).
 * Stripping comments fixes the class, not the instance.
 */
function codeOnly(text: string): string {
  return text
    .split('\n')
    .filter((l) => !/^\s*#/.test(l))
    .join('\n');
}

describe('R-216: Teranode is exercised without a human ticking a box', () => {
  it('some workflow still invokes the Teranode suite at all', () => {
    // Anti-vacuity: if the script were renamed, every assertion below would
    // pass by matching nothing.
    const runners = workflows().filter(({ text }) => invokesTeranode(text));
    expect(
      runners.map((r) => r.file),
      'no workflow runs `pnpm run integration:teranode:run` any more',
    ).not.toEqual([]);
  });

  it('and at least one of those runs on a schedule', () => {
    const scheduled = workflows()
      .filter(({ text }) => invokesTeranode(text))
      .filter(({ text }) => isScheduled(text));
    expect(
      scheduled.map((s) => s.file),
      'Teranode runs only when someone triggers it by hand, so its on-chain claims ' +
        'are unverified between manual runs',
    ).not.toEqual([]);
  });

  it('the scheduled leg is not itself gated behind a dispatch-only condition', () => {
    // The specific shape the finding names: a job that exists but whose `if`
    // can never be true on a schedule.
    for (const { file, text } of workflows().filter(({ text }) => invokesTeranode(text))) {
      if (!isScheduled(text)) continue;
      expect(
        codeOnly(text),
        `${file} schedules Teranode but gates it on workflow_dispatch, so the schedule is dead`,
      ).not.toMatch(/if:\s*github\.event_name\s*==\s*'workflow_dispatch'[^\n]*run_teranode/);
    }
  });

  it('and it stops the stack even when the suite fails', () => {
    // A 10+ microservice compose stack left running is a broken runner for the
    // next job, so the teardown must be `if: always()`.
    const scheduled = workflows()
      .filter(({ text }) => invokesTeranode(text))
      .filter(({ text }) => isScheduled(text));
    for (const { file, text } of scheduled) {
      const code = codeOnly(text);
      const stopIdx = code.indexOf('teranode.sh stop');
      expect(stopIdx, `${file} never stops the Teranode stack`).toBeGreaterThan(0);
      expect(
        code.slice(Math.max(0, stopIdx - 200), stopIdx),
        `${file} stops Teranode without \`if: always()\`, so a failed suite leaves it running`,
      ).toMatch(/if:\s*always\(\)/);
    }
  });
});
