/**
 * W5 / LoopYoink — extra declarators in a declaration list were dropped.
 *
 * `01-parse.ts` read `decls[0]` and discarded the rest. Two sites, two
 * different failures, both fail-OPEN:
 *
 *   `let a = 1n, b = 2n;`                 a WARNING, then `b` is dropped.
 *   `for (let i = 0n, k = <expr>; …)`     dropped with NO diagnostic at all.
 *
 * `compile()` stops only on `severity === 'error'`, so the warning did not stop
 * anything either. Anything effectful in a dropped declarator vanished.
 *
 * Measured before the fix. A private helper carrying the contract's guard,
 * called from the second declarator of a for-initializer, compiled to nothing:
 *
 *   guard in the second declarator   hex 008b519c77 (5 bytes)
 *                                    Spend.validate() ACCEPTS x = 5
 *   same guard as its own statement  hex 0078760164a069007b7c938b519c637c9c67…
 *                                    Spend.validate() REJECTS x = 5
 *
 * The guard says `x > 100n`. In the first form the developer wrote it, the
 * compiler said nothing, and it is absent from the locking script.
 *
 * The fix is to fail closed: `decls.length !== 1` is an ERROR at both sites.
 * Lowering every initializer properly is out of scope -- the language subset is
 * one declarator per statement, which is what `spec/grammar.md`'s
 * VariableDeclaration production already says.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { ScriptExecutionContract } from '../script-execution.js';

function contract(body: string): string {
  return `
import { SmartContract, assert } from 'runar-lang';

export class DropGuard extends SmartContract {
  readonly tag: bigint;

  constructor(tag: bigint) {
    super(tag);
    this.tag = tag;
  }

  private guard(x: bigint): bigint {
    assert(x > 100n);
    return x;
  }

  public verify(x: bigint): void {
${body}
  }
}
`;
}

/** The guard as its own statement: the shape that works, and must keep working. */
const SINGLE_DECLARATOR = `    let s: bigint = 0n;
    const k: bigint = this.guard(x);
    for (let i: bigint = 0n; i < 2n; i++) { s = s + i; }
    assert(s === 1n && k === x);`;

/** The same guard in a for-initializer's SECOND declarator. */
const FOR_INIT_SECOND_DECLARATOR = `    let s: bigint = 0n;
    for (let i: bigint = 0n, k: bigint = this.guard(x); i < 2n; i++) { s = s + i; }
    assert(s === 1n);`;

function compileOf(body: string) {
  return compile(contract(body), { fileName: 'DropGuard.runar.ts' });
}

function errorsOf(body: string): string[] {
  return compileOf(body)
    .diagnostics.filter((d) => d.severity === 'error')
    .map((d) => d.message);
}

describe('W5 — a declaration list must declare exactly one variable', () => {
  it('control: the guard as its own statement is emitted, and rejects x = 5', () => {
    const c = ScriptExecutionContract.fromSource(
      contract(SINGLE_DECLARATOR),
      { tag: 0n },
      'DropGuard.runar.ts',
    );
    // Acceptance oracle: @bsv/sdk Spend.validate(), via execute().
    expect(c.execute('verify', [5n]).success).toBe(false);
    expect(c.execute('verify', [200n]).success).toBe(true);
  });

  it('PoC: a guard in a for-init second declarator does not compile', () => {
    // Before the fix: success === true, ZERO diagnostics, and the guard was
    // absent from the locking script -- Spend.validate() accepted x = 5.
    const r = compileOf(FOR_INIT_SECOND_DECLARATOR);
    expect(r.success).toBe(false);
    expect(errorsOf(FOR_INIT_SECOND_DECLARATOR).join('\n')).toMatch(
      /declare one variable per statement/i,
    );
  });

  it('a for-initializer with extra declarators is an error, not silence', () => {
    const body = `    let s: bigint = 0n;
    for (let i: bigint = 0n, k: bigint = 9n; i < 2n; i++) { s = s + i; }
    assert(x === s);`;
    // The specific regression: this used to emit no diagnostic whatsoever.
    const r = compileOf(body);
    expect(r.diagnostics.length).toBeGreaterThan(0);
    expect(errorsOf(body).join('\n')).toMatch(/declare one variable per statement/i);
  });

  it('an ordinary multi-declarator statement is an ERROR, not a warning', () => {
    const body = `    let a: bigint = 1n, b: bigint = 2n;
    assert(x === a + b);`;
    const r = compileOf(body);
    // It used to be severity 'warning', and compile() only stops on 'error',
    // so `success` was true while `b` was gone.
    expect(r.success).toBe(false);
    expect(r.diagnostics.filter((d) => d.severity === 'warning')
      .map((d) => d.message)
      .join('\n')).not.toMatch(/Multiple variable declarations/i);
    expect(errorsOf(body).join('\n')).toMatch(/declare one variable per statement/i);
  });

  it('single-declarator statements and for-initializers still compile', () => {
    expect(errorsOf(SINGLE_DECLARATOR)).toEqual([]);
    expect(errorsOf(`    let s: bigint = 0n;
    for (let i: bigint = 0n; i < 2n; i++) { s = s + i; }
    assert(x === s);`)).toEqual([]);
  });
});
