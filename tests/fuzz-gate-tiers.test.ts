/**
 * R-111 — the stateful contract-level fuzz gate must exercise all seven tiers.
 *
 * It ran on six. Zig was excluded from the stateful IR->hex gate on both the PR
 * and nightly paths, which left the one gate purpose-built for fund-safety
 * shapes — the `prop-write-in-arm` branch topology and the `addOutput`
 * multi-output intrinsic — never running against the tier this audit
 * independently found had a library entry point skipping a whole pass, two
 * peephole rules nobody else has, and two missing rules everybody else has.
 *
 * The exclusion was justified by a frontend defect that no longer exists (see
 * the R-111 commit for the measurement). What did still block it was a fuzzer
 * artifact, fixed in the generator: `readonly` was drawn by coin flip
 * independently of which properties the methods actually wrote, and a property
 * that is mutable BY DECLARATION but written by nothing is not expressible on
 * the `.runar.zig` surface, which INFERS readonly from use.
 *
 * This test pins the tier list in both places it is written down — the workflow
 * and the `fuzz:ir:gate:stateful` script — so a tier cannot be quietly dropped
 * again. A future exclusion is a deliberate, visible edit to this list.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const REPO = resolve(__dirname, '..');
const read = (rel: string) => readFileSync(join(REPO, rel), 'utf8');

const ALL_TIERS = ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'] as const;

/** Every `--compilers <list>` argument in a file, as a set of tier names. */
function compilerLists(text: string): string[][] {
  const out: string[][] = [];
  for (const m of text.matchAll(/--compilers[ \t\\\n]+([a-z,]+)/g)) {
    out.push(m[1]!.split(',').filter(Boolean));
  }
  return out;
}

describe('R-111: the stateful fuzz gate runs every tier', () => {
  it('the stateful PR-gate step lists all seven tiers', () => {
    const yml = read('.github/workflows/fuzzer-nightly.yml');
    // The stateful steps are the ones passing `--stateful`.
    const statefulBlocks = yml
      .split(/\n      - name: /)
      .filter((b) => b.includes('--stateful'));
    expect(statefulBlocks.length, 'no --stateful fuzz step found at all').toBeGreaterThan(0);

    const offenders: string[] = [];
    for (const block of statefulBlocks) {
      for (const list of compilerLists(block)) {
        const missing = ALL_TIERS.filter((t) => !list.includes(t));
        if (missing.length > 0) {
          offenders.push(
            `${block.split('\n')[0]!.trim()}: missing ${missing.join(', ')}`,
          );
        }
      }
    }
    expect(
      offenders,
      `the stateful fuzz gate is the one purpose-built for fund-safety shapes; ` +
        `a tier missing from it is a tier those shapes never reach`,
    ).toEqual([]);
  });

  it('the fuzz:ir:gate:stateful script lists all seven tiers', () => {
    const pkg = JSON.parse(read('conformance/package.json')) as { scripts: Record<string, string> };
    const script = pkg.scripts['fuzz:ir:gate:stateful'];
    expect(script, 'fuzz:ir:gate:stateful missing from conformance/package.json').toBeTruthy();
    const lists = compilerLists(script!);
    expect(lists.length, 'the script pins no --compilers list').toBeGreaterThan(0);
    for (const list of lists) {
      expect(ALL_TIERS.filter((t) => !list.includes(t))).toEqual([]);
    }
  });

  it('no IR-differential fuzz step excludes a tier', () => {
    // Scope: the `--ir` family, which is what this finding is about. The
    // CANONICAL fuzz family is deliberately split — its PR gate runs six tiers
    // because the Java shim forks a JVM per case, and Java is covered by a
    // separate one-JVM batch step immediately after. That split is documented
    // in the workflow and is a throughput decision, not a coverage hole.
    const yml = read('.github/workflows/fuzzer-nightly.yml');
    const irBlocks = yml
      .split(/\n      - name: /)
      .filter((b) => /--ir\b/.test(b) && /--compilers/.test(b));
    expect(irBlocks.length, 'no --ir fuzz step found at all').toBeGreaterThanOrEqual(2);

    const offenders: string[] = [];
    for (const block of irBlocks) {
      for (const list of compilerLists(block)) {
        const missing = ALL_TIERS.filter((t) => !list.includes(t));
        if (missing.length > 0) {
          offenders.push(`${block.split('\n')[0]!.trim()}: missing ${missing.join(', ')}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});
