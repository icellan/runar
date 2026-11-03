import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * F-298 / CL-DOC-019 — `docs/testing-guide.md` was never touched by R-112
 * (CLAUDE.md and packages/runar-testing/README.md were) and still described
 * the interpreter's crypto as a blanket mock, in both prose and a table,
 * repeated four times:
 *
 *   :207-208  "`checkSig` / `checkMultiSig` / `checkPreimage` / `verifyRabinSig`
 *              always return `true`"
 *   :565      "`TestContract` uses mocked ECDSA cryptographic operations —
 *              `checkSig`, `checkMultiSig`, and `checkPreimage` always return
 *              `true`"
 *   :649      "`checkSig` returned `true` either way"
 *   :668-671  a table: `checkSig` / `checkMultiSig` / `checkPreimage` /
 *              `verifyRabinSig` all "**Mocked → always `true`**"
 *
 * Ground truth (packages/runar-testing/src/interpreter/interpreter.ts):
 *   checkSig        REAL ECDSA over the fixed TEST_MESSAGE (:1009-1037)
 *   verifyRabinSig   REAL Rabin verification (:1319+)
 *   checkPreimage    stubbed to `true` (:1316-1317) — this one claim IS correct
 *   checkMultiSig    REFUSES — throws rather than answer (:1039-1059)
 *
 * This matters beyond doc accuracy: the stale claim is precisely the belief
 * that makes a branch-blind `TestContract` test of `checkSig`/`checkMultiSig`
 * look unavoidable when it is not (CL-BUG-252).
 *
 * This test pins the corrected claims in docs/testing-guide.md. It does NOT
 * touch CLAUDE.md or packages/runar-testing/README.md — R-112 already fixed
 * those (verified separately; see r112-interpreter-crypto-honesty.test.ts) —
 * and it does NOT touch the unrelated native-tier "Mock crypto" table under
 * "Testing Rust Contracts" (~:1220), which is out of this item's scope.
 */

const REPO = resolve(__dirname, '../../../..');
const DOC_PATH = resolve(REPO, 'docs/testing-guide.md');

/** Builtins the interpreter does NOT mock, despite the doc's old claim. */
const WRONGLY_CLAIMED_MOCKED = ['checkSig', 'checkMultiSig', 'verifyRabinSig'];

const MOCK_CLAIM = '(?:Mocked\\s*(?:→|->)\\s*always|always\\s+returns?\\s+`?true`?)';

/**
 * A claim that `name` always returns true / is mocked, scoped to ONE markdown
 * table row (`line`) for that exact builtin — so a hit on `checkMultiSig`'s
 * row can never be the next row's (accurate) `checkPreimage` claim leaking in.
 */
function staleTableClaims(tableLines: string[], name: string): string[] {
  const re = new RegExp('^\\|\\s*`' + name + '`\\s*\\|.*?' + MOCK_CLAIM, 'i');
  return tableLines.filter((l) => re.test(l));
}

/**
 * The same claim in prose (not a table row). Table rows are stripped first
 * so a window can never cross from one row's cell into another's; the
 * remaining prose is then whitespace-flattened so a claim that wraps across
 * a markdown source line (like :207-208) is still caught.
 */
function staleProseClaims(proseText: string, name: string): string[] {
  const re = new RegExp('`?' + name + '`?[^\\n]{0,160}?' + MOCK_CLAIM, 'gi');
  return [...proseText.matchAll(re)].map((m) => m[0]);
}

describe("F-298 / CL-DOC-019: docs/testing-guide.md matches the interpreter's real crypto behavior (R-112)", () => {
  const lines = readFileSync(DOC_PATH, 'utf8').split('\n');
  const tableLines = lines.filter((l) => l.trim().startsWith('|'));
  const prose = lines
    .filter((l) => !l.trim().startsWith('|'))
    .join(' ')
    .replace(/\s+/g, ' ');

  for (const name of WRONGLY_CLAIMED_MOCKED) {
    it(`does not claim \`${name}\` is mocked / always returns true (table)`, () => {
      const hits = staleTableClaims(tableLines, name);
      expect(
        hits,
        `docs/testing-guide.md's table still claims \`${name}\` is mocked/always-true: ${JSON.stringify(hits)}`,
      ).toEqual([]);
    });

    it(`does not claim \`${name}\` is mocked / always returns true (prose)`, () => {
      const hits = staleProseClaims(prose, name);
      expect(
        hits,
        `docs/testing-guide.md's prose still claims \`${name}\` is mocked/always-true: ${JSON.stringify(hits)}`,
      ).toEqual([]);
    });
  }

  it('checkPreimage is still (correctly) documented as stubbed to true', () => {
    // The one claim in the old table that was actually right — make sure the
    // fix did not over-correct and remove it.
    expect(staleTableClaims(tableLines, 'checkPreimage').length).toBeGreaterThan(0);
  });

  it('documents checkMultiSig as refusing (throwing), not as mocked', () => {
    expect(prose + ' ' + tableLines.join(' ')).toMatch(/checkMultiSig[^\n]{0,200}?(refuses|throws)/i);
  });
});
