import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile } from '../index.js';

/**
 * F-288 / CL-DOC-013 — `docs/formats/typescript.md`'s operator table told
 * readers that `&&` / `||` evaluate both branches with "no short-circuit
 * script-level", which is exactly the eager semantics that NEW-014 fixed
 * (see `04-anf-lower.ts` `lowerBinaryExpr` and the fund-loss history in
 * `shortcircuit-consensus-vm.test.ts`). `docs/language-reference.md` already
 * says the opposite, correctly: "These short-circuit ... which become real
 * branches, so the skipped operand's opcodes never run."
 *
 * Measured directly against the compiler below, not trusted from either doc:
 * compiling the exact guard idiom both docs discuss —
 *
 *     assert(d === 0n || (100n / d) > 1n);
 *
 * — produces a script containing `OP_IF` and no `OP_BOOLOR` (the eager binary
 * opcode the old doc's claim implies). `&&` / `||` written at the TypeScript
 * surface always desugar to the ternary (`lowerBinaryExpr` in
 * `04-anf-lower.ts`) before Stack-IR lowering, so there is no source-level
 * path left to the eager opcode the doc described.
 *
 * This guard pins both halves: the measured compiler behavior, and the doc
 * text matching it. Restore the old wording and the second case fails by
 * name.
 */

const REPO = resolve(__dirname, '../../../..');
const TS_FORMAT_DOC = resolve(REPO, 'docs/formats/typescript.md');

const OR_DIV_GUARD = `import { SmartContract, assert } from 'runar-lang';

export class Sc extends SmartContract {
  readonly n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public m(d: bigint): void {
    assert(d === 0n || (100n / d) > 1n);
    assert(this.n > 0n);
  }
}
`;

describe('F-288 the TypeScript format guide no longer documents eager && / ||', () => {
  it('the reference compiler lowers the guard idiom to a real branch, not an eager bool opcode', () => {
    const r = compile(OR_DIV_GUARD, { fileName: 'Sc.runar.ts' });
    expect(r.diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
    expect(r.success).toBe(true);
    // Real control flow: the right operand's opcodes sit behind OP_IF/OP_ELSE.
    expect(r.scriptAsm).toMatch(/OP_IF/);
    // The eager binary form "||" used to lower to, and which the old doc's
    // "Both branches evaluated" claim implied, must not appear.
    expect(r.scriptAsm).not.toMatch(/OP_BOOLOR/);
    expect(r.scriptAsm).not.toMatch(/OP_BOOLAND/);
  });

  it('docs/formats/typescript.md no longer claims && / || are eager with no script-level short-circuit', () => {
    const text = readFileSync(TS_FORMAT_DOC, 'utf8');
    const row = text.split('\n').find((l) => /^\|\s*`&&`,\s*`\\?\|\\?\|`,\s*`!`\s*\|/.test(l));
    expect(row, 'the Boolean logic operator row is gone from the table').toBeDefined();
    expect(row, 'typescript.md still claims both branches are evaluated eagerly').not.toMatch(
      /[Bb]oth branches evaluated/,
    );
    expect(row, 'typescript.md still claims there is no script-level short-circuit').not.toMatch(
      /no short-circuit/i,
    );
    expect(row, 'the row should now say the operators short-circuit, matching language-reference.md').toMatch(
      /[Ss]hort-circuit/,
    );
  });
});
