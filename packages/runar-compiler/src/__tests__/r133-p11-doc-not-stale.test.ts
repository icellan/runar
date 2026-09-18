import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * R-133 / CL-DOC-030 — a first-party design note asserted that a funds-locking
 * defect was OPEN, three weeks after it was fixed.
 *
 * `packages/runar-compiler/docs/multi-result-branch-node.md` said, in bold:
 * "**The shape §9 called 'P1-1' is real, and it is OPEN.**" — a declared-results
 * `if` nested in another `if`'s arm rotating the slots it inherited, so "the
 * else-path compiles to an unspendable script".
 *
 * It was fixed in `9cfd953f` ("restore inherited slot order after adopting
 * declared results"), and the pinned reduction —
 * `packages/runar-testing/src/__tests__/nested-declared-results-arm-layout-vm.test.ts`
 * — is live and green (6 cases), with its own header already corrected to say
 * FIXED. Only the design note still claimed otherwise.
 *
 * This is the mirror image of a stale "RESOLVED" claim and costs the same: in
 * this very review it produced a CRITICAL finding that had to be withdrawn.
 * A reader of either artifact would conclude a funds-locking defect is live at
 * HEAD.
 *
 * The guard pins the pair: the note must not assert the shape is open, and the
 * reduction that proves it closed must still be a live suite — no skipped or
 * `.todo`-marked case, asserted below against the whole vitest skip surface —
 * because a doc saying "fixed" backed by a skipped test is the same lie
 * wearing the other hat.
 */

const REPO = resolve(__dirname, '../../../..');
const NOTE = resolve(REPO, 'packages/runar-compiler/docs/multi-result-branch-node.md');
const PIN = resolve(
  REPO,
  'packages/runar-testing/src/__tests__/nested-declared-results-arm-layout-vm.test.ts',
);

describe('R-133 the P1-1 design note is not stale', () => {
  it('the note no longer asserts the shape is OPEN', () => {
    const text = readFileSync(NOTE, 'utf8');
    // Match the ASSERTION, not the word: the corrected section quotes the old
    // sentence in order to retract it.
    const claims = text
      .split('\n')
      .filter((l) => /P1-1/.test(l) && /\bis OPEN\b/.test(l))
      .filter((l) => !/was OPEN|used to|retract|no longer|superseded/i.test(l));
    expect(
      claims,
      `multi-result-branch-node.md still asserts P1-1 is open: ${claims.join(' / ')}`,
    ).toEqual([]);
  });

  it('the note names the commit that closed it', () => {
    expect(readFileSync(NOTE, 'utf8')).toMatch(/9cfd953f/);
  });

  it('the reduction that proves it closed is a LIVE suite, not a skipped one', () => {
    const text = readFileSync(PIN, 'utf8');
    expect(text).not.toMatch(/\b(it|describe|test)\.(skip|todo)\b/);
    expect((text.match(/\bit\(/g) ?? []).length).toBeGreaterThanOrEqual(3);
  });

  it('the pin still says FIXED, so the pair cannot drift apart again', () => {
    expect(readFileSync(PIN, 'utf8')).toMatch(/FIXED in 9cfd953f/);
  });
});
