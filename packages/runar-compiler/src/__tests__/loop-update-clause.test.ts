/**
 * R-065 — the for-loop `update` clause is parsed, carried through the whole
 * AST, and then never validated and never lowered.
 *
 * `04-anf-lower.ts`'s `extractLoopStep` only ever understood a UNIT step: it
 * returns `1` for `i++`, `-1` for `i--`, and otherwise falls back to the
 * *comparison direction* — so any other update clause is silently coerced to
 * `±1` and the clause itself is discarded. `02-validate.ts` never looked at
 * `stmt.update` at all, and `03-typecheck.ts`'s `for_statement` arm checked
 * `init`, `condition` and `body` but skipped `update` entirely.
 *
 * Three shapes of the same hole, all observable from ordinary source:
 *
 *   * `for (let i = 0n; i < 5n; undefinedFn())` compiled to byte-identical
 *     output. A nonexistent function name raised nothing — a hole in the rule
 *     that only Rúnar builtins and contract methods are callable (CLAUDE.md
 *     names `console.log` explicitly).
 *   * `for (let i = 0n; i < 5n; this.count++)` silently DROPPED the state
 *     write from the emitted script.
 *   * a non-unit step (`i += 2`, reached through the Zig / Solidity / Go
 *     frontends, which lower `i += 2` to `i = i + 2`) unrolled 10 times over
 *     i = 0..9 instead of 5 times over i = 0,2,4,6,8. Byte-identical to the
 *     `i++` loop, with no diagnostic.
 *
 * `spec/grammar.md` is authoritative and permits only the unit forms:
 *
 *     ForStatement
 *         = 'for' '(' 'let' Identifier ':' 'bigint' '=' Expression ';'
 *                     Identifier RelOp Expression ';'
 *                     Identifier ( '++' | '--' ) ')' Block
 *
 * and, under Statement Restrictions, "The loop variable MUST use simple
 * increment (`++`) or decrement (`--`)". So rejecting is the fix rather than
 * lowering: the ANF `loop` node can express exactly
 * `{ count, iterVar, start, step, body }` and synthesizes the iterator on
 * unrolled iteration k as `start + k*step`. There is no slot for an arbitrary
 * update statement, and appending the update's lowering to the loop body would
 * re-emit `i++` as a dead binding on every loop that already compiles
 * correctly — moving bytes across the whole corpus to express nothing.
 *
 * This is the TypeScript arm of the fix already shipped for the Rust tier
 * (`compilers/rust/tests/loop_update_clause_tests.rs`); the diagnostic text is
 * shared verbatim so the seven tiers do not drift.
 *
 * What these tests do NOT prove: nothing here says the update clause is
 * *lowered*. The contract is that a non-representable update is a compile
 * error instead of silent output. The controls pin the `bounded-loop` shape
 * only — they show the fix refuses nothing that compiled before, not that
 * every loop in the corpus is unaffected (the conformance goldens cover that).
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { compile } from '../index.js';

const REPO_ROOT = join(__dirname, '../../../..');

/** The one correct answer: `bounded-loop` compiles to these 42 bytes in every frontend. */
const BOUNDED_LOOP_HEX =
  '000052797b7c937c935152797b7c937c935252797b7c937c935352797b7c937c93547b7b7c937c93009c';

function example(rel: string): string {
  return readFileSync(join(REPO_ROOT, rel), 'utf-8');
}

function compileSource(source: string, fileName: string): { ok: boolean; hex: string; diags: string } {
  const result = compile(source, { fileName });
  return {
    ok: result.success,
    hex: result.artifact?.script ?? '',
    diags: (result.diagnostics ?? []).map((d) => d.message).join('\n'),
  };
}

/** A stateful contract parameterised on the for-loop update clause. */
function tsWithUpdate(update: string): string {
  return `import { StatefulSmartContract, assert } from 'runar-lang';

class UpdateProbe extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

  public unlock(expected: bigint): void {
    let acc: bigint = 0n;
    for (let i: bigint = 0n; i < 3n; ${update}) {
      acc = acc + i;
    }
    assert(acc === expected);
  }
}
`;
}

/**
 * The Zig frontend folds `while (c) : (continueExpr)` into a ForStatement
 * whose update is the ASSIGNMENT spelling `i = i + K` — the shape the
 * TypeScript surface parser refuses to build (`i += 2n` in a for-update is
 * "Unsupported binary operator"), and therefore the only way to reach a
 * non-unit step from TypeScript-parseable source.
 */
function zigWithStep(step: string): string {
  return example('examples/zig/bounded-loop/BoundedLoop.runar.zig').replace('i += 1', step);
}

describe('R-065: the for-loop update clause is validated, not silently discarded', () => {
  // -------------------------------------------------------------------------
  // The defect
  // -------------------------------------------------------------------------

  it('rejects a non-unit step instead of coercing it to i++', () => {
    const r = compileSource(zigWithStep('i += 2'), 'BoundedLoop.runar.zig');
    expect(
      r.ok,
      `\`i += 2\` must not compile: it silently unrolled with step 1 and produced ${r.hex.length} hex chars`,
    ).toBe(false);
    expect(r.diags).toMatch(/must advance the loop variable by one/);
  });

  it('rejects a negative non-unit step too', () => {
    const source = example('examples/zig/bounded-loop/BoundedLoop.runar.zig')
      .replace('var i: i64 = 0;', 'var i: i64 = 5;')
      .replace('while (i < 5) : (i += 1)', 'while (i > 0) : (i -= 2)');
    const r = compileSource(source, 'BoundedLoop.runar.zig');
    expect(r.ok, '`i -= 2` must not compile').toBe(false);
    expect(r.diags).toMatch(/must advance the loop variable by one/);
  });

  it('rejects a call to an undefined function in the update clause', () => {
    const r = compileSource(tsWithUpdate('undefinedFn()'), 'UpdateProbe.runar.ts');
    expect(
      r.ok,
      'a for-loop update clause calling an undefined function must not compile: ' +
        "the type checker's unknown-function rule has to reach inside the update",
    ).toBe(false);
    expect(r.diags.trim(), 'rejection must carry a diagnostic').not.toBe('');
  });

  it('rejects console.log in the update clause', () => {
    const r = compileSource(tsWithUpdate('console.log(i)'), 'UpdateProbe.runar.ts');
    expect(r.ok, '`console.log` must be rejected in the update clause too').toBe(false);
  });

  it('rejects a state mutation in the update clause rather than dropping it', () => {
    const r = compileSource(tsWithUpdate('this.count++'), 'UpdateProbe.runar.ts');
    expect(
      r.ok,
      'a state mutation in the update clause is not representable in the ANF loop node, ' +
        'so it must be a compile error — silently dropping it is what this test forbids',
    ).toBe(false);
    expect(r.diags).toMatch(/must advance the loop variable by one/);
  });

  it('rejects an update that advances a variable other than the iterator', () => {
    const source = `import { SmartContract, assert } from 'runar-lang';

class OtherVar extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) { super(expected); this.expected = expected; }

  public verify(start: bigint): void {
    let sum: bigint = 0n;
    let j: bigint = 0n;
    for (let i: bigint = 0n; i < 3n; j++) {
      sum = sum + start + i;
    }
    assert(sum === this.expected);
  }
}
`;
    const r = compileSource(source, 'OtherVar.runar.ts');
    expect(r.ok, '`j++` advances a variable the loop model never binds').toBe(false);
    expect(r.diags).toMatch(/must advance the loop variable by one/);
  });

  // -------------------------------------------------------------------------
  // Controls: every shape that compiles today must still compile, byte-identical
  // -------------------------------------------------------------------------

  it('control: the `i++` bounded loop is byte-unchanged', () => {
    const r = compileSource(
      example('examples/ts/bounded-loop/BoundedLoop.runar.ts'),
      'BoundedLoop.runar.ts',
    );
    expect(r.ok, r.diags).toBe(true);
    expect(r.hex, '`i++` lowering must not move bytes').toBe(BOUNDED_LOOP_HEX);
  });

  it('control: the Solidity `i++` bounded loop is byte-unchanged', () => {
    const r = compileSource(
      example('examples/sol/bounded-loop/BoundedLoop.runar.sol'),
      'BoundedLoop.runar.sol',
    );
    expect(r.ok, r.diags).toBe(true);
    expect(r.hex).toBe(BOUNDED_LOOP_HEX);
  });

  // The assignment spelling `i = i + 1` — the shape `i += 1` desugars to, and
  // the one the accepted set has to keep alongside `i++` — is covered by the
  // Zig and Java controls below. This tier's Solidity parser does not accept
  // `+=` in the for-update position at all ("Expected ')', got '+='"), which is
  // a separate parser gap, not R-065.

  it('control: the Zig `while (i < 5) : (i += 1)` fold is byte-unchanged', () => {
    const r = compileSource(
      example('examples/zig/bounded-loop/BoundedLoop.runar.zig'),
      'BoundedLoop.runar.zig',
    );
    expect(r.ok, r.diags).toBe(true);
    expect(r.hex).toBe(BOUNDED_LOOP_HEX);
  });

  it('control: the Move while-fold bounded loop is byte-unchanged', () => {
    const r = compileSource(
      example('examples/move/bounded-loop/BoundedLoop.runar.move'),
      'BoundedLoop.runar.move',
    );
    expect(r.ok, r.diags).toBe(true);
    expect(r.hex).toBe(BOUNDED_LOOP_HEX);
  });

  it('control: the Go `i++` bounded loop is byte-unchanged', () => {
    const r = compileSource(
      example('examples/go/bounded-loop/BoundedLoop.runar.go'),
      'BoundedLoop.runar.go',
    );
    expect(r.ok, r.diags).toBe(true);
    expect(r.hex).toBe(BOUNDED_LOOP_HEX);
  });

  it('control: the Java `i = i.plus(Bigint.ONE)` bounded loop is byte-unchanged', () => {
    const r = compileSource(
      example('examples/java/src/main/java/runar/examples/bounded-loop/BoundedLoop.runar.java'),
      'BoundedLoop.runar.java',
    );
    expect(r.ok, r.diags).toBe(true);
    expect(r.hex).toBe(BOUNDED_LOOP_HEX);
  });

  it('control: a countdown loop (`i--` with `>`) still compiles', () => {
    const source = `import { SmartContract, assert } from 'runar-lang';

class Countdown extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) { super(expected); this.expected = expected; }

  public verify(start: bigint): void {
    let sum: bigint = 0n;
    for (let i: bigint = 3n; i > 0n; i--) {
      sum = sum + start + i;
    }
    assert(sum === this.expected);
  }
}
`;
    const r = compileSource(source, 'Countdown.runar.ts');
    expect(r.ok, `a countdown loop must still compile: ${r.diags}`).toBe(true);
  });
});
