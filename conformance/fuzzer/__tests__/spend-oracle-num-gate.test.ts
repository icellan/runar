/**
 * The spend-oracle `--num` in CI must cover every construct family.
 *
 * `generateShapes` draws `FAMILIES[i % FAMILIES.length]`, so a run with `--num`
 * below `REQUIRED_CASE_COUNT` never reaches the tail families — silently. The
 * workflow carries the count as a hand-copied literal (`--num 35`) with zero
 * margin, and nothing compared that literal to `FAMILIES.length`:
 * `__tests__/spend-oracle.test.ts` passes `REQUIRED_CASE_COUNT` to the driver
 * itself, so it cannot see the workflow drift away from it. The workflow's own
 * comment records this having already failed once — 32 was raised to 35 after
 * three loop-carried families stopped being drawn — and
 * `conformance/fuzzer/README.md` still documented 32 and called it
 * "== REQUIRED_CASE_COUNT".
 *
 * This is the `--num` analogue of `tests/fuzz-gate-tiers.test.ts` (R-111),
 * which parses `--compilers` out of the same YAML and pins it to all seven
 * tiers: the constant is checked where it is WRITTEN DOWN, not where it is
 * imported.
 *
 * Adding a family is therefore a deliberate, visible edit in two places rather
 * than a silent loss of coverage. The bound is `>=`, not `==`, so the gate is
 * allowed to run more cases than there are families — but never fewer.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { REQUIRED_CASE_COUNT } from '../spend-shapes.js';

const REPO = resolve(__dirname, '../../..');
const read = (rel: string) => readFileSync(resolve(REPO, rel), 'utf8');

/** Every literal `--num <n>` in a block. Shell-variable forms are skipped. */
function numLiterals(text: string): number[] {
  const out: number[] = [];
  for (const m of text.matchAll(/--num[ \t\\\n]+(\d+)\b/g)) out.push(Number(m[1]));
  return out;
}

describe('spend-oracle --num covers every construct family', () => {
  it('every --spend-oracle step in the nightly workflow runs at least one case per family', () => {
    const yml = read('.github/workflows/fuzzer-nightly.yml');
    const blocks = yml
      .split(/\n      - name: /)
      .filter((b) => b.includes('--spend-oracle'));

    // Anti-vacuity: a renamed or deleted step must not make this guard pass by
    // having nothing to check.
    expect(blocks.length, 'no --spend-oracle step found in the workflow at all').toBeGreaterThan(0);

    const offenders: string[] = [];
    let checked = 0;
    for (const block of blocks) {
      const nums = numLiterals(block);
      for (const n of nums) {
        checked++;
        if (n < REQUIRED_CASE_COUNT) {
          offenders.push(`${block.split('\n')[0]!.trim()}: --num ${n} < ${REQUIRED_CASE_COUNT}`);
        }
      }
    }
    expect(checked, 'no literal --num found in any --spend-oracle step').toBeGreaterThan(0);
    expect(
      offenders,
      `families are drawn round-robin (spend-shapes.ts generateShapes), so a --num below ` +
        `REQUIRED_CASE_COUNT (${REQUIRED_CASE_COUNT}) silently never reaches the tail families`,
    ).toEqual([]);
  });

  it('the README documents a --num that covers every family', () => {
    const md = read('conformance/fuzzer/README.md');
    const lines = md.split('\n').filter((l) => l.includes('--spend-oracle') && /--num\s+\d+/.test(l));
    expect(lines.length, 'no documented --spend-oracle command with a --num').toBeGreaterThan(0);

    const offenders = lines
      .flatMap((l) => numLiterals(l).map((n) => ({ l, n })))
      .filter(({ n }) => n < REQUIRED_CASE_COUNT)
      .map(({ l, n }) => `${l.trim()} (--num ${n} < ${REQUIRED_CASE_COUNT})`);
    expect(offenders).toEqual([]);
  });

  it('no prose claims a number IS REQUIRED_CASE_COUNT while naming a different one', () => {
    const md = read('conformance/fuzzer/README.md');
    const offenders: string[] = [];
    // No digits between the number and the claim, so a seed earlier on the
    // line cannot be mistaken for the count.
    for (const m of md.matchAll(/(\d+)[^\d\n]{0,20}\(==\s*`?REQUIRED_CASE_COUNT/g)) {
      if (Number(m[1]) !== REQUIRED_CASE_COUNT) {
        offenders.push(`"${m[0]}" but REQUIRED_CASE_COUNT is ${REQUIRED_CASE_COUNT}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});
