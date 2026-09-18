/**
 * R-106 — every `examples/ts` contract must have a test beside it.
 *
 * Thirteen example contracts had zero tests in all nine formats. Three of them
 * — `branch-merged-locals`, `cond-write-multi-field`, `nested-if-multi-reassign`
 * — are the exact branch-lifting shapes behind the 2026-08 fund-safety
 * miscompiles, and `asm-raw-script` is the only example of the `asm()` escape
 * hatch. Several were checked in AS regression fixtures for named defects,
 * without the assertions that would make them regression tests.
 *
 * A note on what "zero coverage" meant, because the phrase overstates it:
 * eleven of the thirteen are conformance fixtures (byte parity across seven
 * tiers) and six carry a real-crypto witness with a hand-authored
 * `expectedState`. What none of them had was a test at the EXAMPLES layer,
 * which is the one that reads the source semantics through the interpreter
 * rather than the compiled bytes — the independent half of the oracle.
 *
 * This guard requires the file to exist. It cannot require the assertions to be
 * good; that is what review is for.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, statSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

const REPO = resolve(__dirname, '..');
const TS_EXAMPLES = join(REPO, 'examples/ts');

/**
 * Directories intentionally without a test, each with a reason.
 *
 * Every entry here is currently the SAME reason, and it is not laziness — it is
 * `examples/ts/example-spendability-policy.test.ts` refusing an interpreter-only
 * test on a stateful example. That policy is right: `TestContract` mocks ECDSA
 * and never runs the compiled script, so an interpreter-only stateful test
 * teaches contributors that a green suite means spendable, which is the
 * PALMER-1 lesson inverted.
 *
 * These five need real spendability coverage, and each is blocked on a specific
 * piece of harness work rather than on writing assertions:
 *
 *   all-readonly-cleanstack     the SDK's `prepareCall` does not classify it as
 *                               stateful (no mutable fields), so it asks for the
 *                               injected `txPreimage` as a user argument and the
 *                               real-crypto oracle cannot drive it
 *   conditional-data-output     no conformance fixture under this name, so there
 *                               is nothing for a real-crypto witness to attach to
 *   intent-output-p2pkh         needs `_serialisedOutputs` witness bytes, which
 *   intent-prev-output-script   and `_prevOutScript_<i>`; the SDK supports both
 *                               but neither oracle exposes a way to set them
 *   stateful-wots-gate          needs a real WOTS+ signature as a literal in the
 *                               witness JSON (~2 KB of hex) — possible, just bulky
 *
 * An entry here is a decision someone made and can be argued with; a silently
 * untested directory is not.
 */
const APPROVED_UNTESTED: Record<string, string> = {
  'all-readonly-cleanstack': 'stateful; SDK does not classify it stateful, oracle cannot drive it',
  'conditional-data-output': 'stateful; no conformance fixture to hang a real-crypto witness on',
  'intent-output-p2pkh': 'stateful; needs _serialisedOutputs witness bytes the oracles cannot set',
  'intent-prev-output-script': 'stateful; needs _prevOutScript_<i> witness bytes the oracles cannot set',
  'stateful-wots-gate': 'stateful; needs a real WOTS+ signature literal in the witness',
};

describe('R-106: examples/ts contracts are tested', () => {
  const dirs = readdirSync(TS_EXAMPLES)
    .filter((d) => statSync(join(TS_EXAMPLES, d)).isDirectory())
    .filter((d) => readdirSync(join(TS_EXAMPLES, d)).some((f) => f.endsWith('.runar.ts')))
    .sort();

  it('the example corpus is non-empty', () => {
    expect(existsSync(TS_EXAMPLES)).toBe(true);
    expect(dirs.length).toBeGreaterThanOrEqual(20);
  });

  it('every contract directory carries at least one test file', () => {
    const untested = dirs.filter((d) => {
      if (d in APPROVED_UNTESTED) return false;
      return !readdirSync(join(TS_EXAMPLES, d)).some((f) => f.endsWith('.test.ts'));
    });
    expect(
      untested,
      `these examples/ts contracts have no test beside them: ${untested.join(', ')}. ` +
        `Several of the thirteen this finding named were checked in as regression ` +
        `fixtures for named defects, which is the worst version of the gap: the file ` +
        `looks like coverage and asserts nothing.`,
    ).toEqual([]);
  });

  it('no approved-untested entry is stale', () => {
    const stale = Object.keys(APPROVED_UNTESTED).filter(
      (d) =>
        !dirs.includes(d) ||
        readdirSync(join(TS_EXAMPLES, d)).some((f) => f.endsWith('.test.ts')),
    );
    expect(stale, `these approvals no longer describe anything`).toEqual([]);
  });
});
