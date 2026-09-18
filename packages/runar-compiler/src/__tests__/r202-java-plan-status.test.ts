import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * R-202 / CL-DOC-027 — `docs/java-tier-plan.md` read "Proposal / Phase 1
 * (skeleton only)" for several releases after the Java tier shipped complete.
 *
 * A stale status line at the top of a design doc is worse than no status line:
 * it tells a reader to discount everything under it, including the parts that
 * are still accurate. This one sat above a pipeline specification that the
 * shipped compiler follows exactly.
 *
 * The finding's second half — that the doc and the CHANGELOG specify Typecheck
 * BEFORE ExpandFixedArrays while `Cli.java` did the opposite (CL-BUG-024) — no
 * longer reproduces. Measured: `Cli.java` calls `Typecheck.run` at :169 and
 * `ExpandFixedArrays.run` at :178, which is the doc's order and the order
 * CLAUDE.md's pipeline lists. That was fixed by earlier work; the test below
 * pins it so the two cannot diverge again silently.
 */

const REPO = resolve(__dirname, '../../../..');
const PLAN = resolve(REPO, 'docs/java-tier-plan.md');
const CLI = resolve(REPO, 'compilers/java/src/main/java/runar/compiler/Cli.java');

describe('R-202 the Java tier plan describes a shipped tier', () => {
  it('the status line no longer says "skeleton only"', () => {
    const head = readFileSync(PLAN, 'utf8').split('\n').slice(0, 12).join('\n');
    expect(head, 'the Status line is back to Proposal / Phase 1').not.toMatch(
      /\*\*Status:\*\*\s*Proposal/,
    );
    expect(head).toMatch(/SHIPPED/);
  });

  it('the tier it describes is actually built', () => {
    // A status line claiming SHIPPED is its own kind of stale claim if the
    // thing is not there.
    expect(existsSync(CLI), 'compilers/java Cli.java is missing').toBe(true);
    expect(
      existsSync(resolve(REPO, 'packages/runar-java/build.gradle.kts'))
        || existsSync(resolve(REPO, 'packages/runar-java/build.gradle')),
      'packages/runar-java is missing',
    ).toBe(true);
  });

  it('Cli.java runs Typecheck BEFORE ExpandFixedArrays, as the plan specifies', () => {
    const cli = readFileSync(CLI, 'utf8');
    const typecheck = cli.indexOf('Typecheck.run(contract)');
    const expand = cli.indexOf('ExpandFixedArrays.run(contract)');
    expect(typecheck, 'Typecheck.run not found').toBeGreaterThan(-1);
    expect(expand, 'ExpandFixedArrays.run not found').toBeGreaterThan(-1);
    expect(
      typecheck,
      'the Java pass order contradicts its own design doc again (CL-BUG-024)',
    ).toBeLessThan(expand);
  });

  it('the plan still lists the pipeline in that order', () => {
    const plan = readFileSync(PLAN, 'utf8');
    const tc = plan.indexOf('3. Typecheck');
    const ex = plan.indexOf('4. Expand fixed arrays');
    expect(tc).toBeGreaterThan(-1);
    expect(ex).toBeGreaterThan(tc);
  });
});
