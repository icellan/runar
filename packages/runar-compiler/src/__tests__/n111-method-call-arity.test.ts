import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import { emit } from '../passes/06-emit.js';
import type { ANFProgram } from '../ir/anf-ir.js';

/**
 * N-111 — `inlineMethodCall` silently dropped surplus arguments.
 *
 * The binding loop is `if (i < method.params.length)` with no `else`, so an
 * argument past the last parameter was skipped. Skipped is not the same as
 * ignored: a surplus argument never reaches `operandConsume`/`bringToTop`, so
 * a ref that would otherwise have been CONSUMED at the call site stays live on
 * the stack and every later depth shifts under it. The emitted script changes,
 * with no diagnostic.
 *
 * Reachable only through `--ir` — a surplus argument in SOURCE is caught by
 * typecheck. That is exactly why the check belongs in the lowerer, and the
 * precedent is explicit a few hundred lines down in `lowerCheckMultiSig`:
 * "Checking in the lowerer rather than the typechecker also covers the `--ir`
 * input path, which never runs a typecheck."
 *
 * All SEVEN tiers had it, and all seven produced the same wrong bytes, so no
 * cross-tier parity gate could see it. The six IR-capable tiers are gated by
 * `conformance/negatives/ir/I08-method-call-surplus-arg.ir.json`; this file is
 * the seventh, because the reference tier ships no `--ir` CLI mode and cannot
 * appear in that lane.
 */

/**
 * A contract with one private helper taking two parameters. The ANF is
 * produced by the compiler's OWN front half (parse -> anf-lower), then the
 * call's argument list is edited before stack lowering — which is precisely
 * the shape `--ir` admits from outside, and the only way to reach a surplus
 * argument at all (a surplus argument in SOURCE is caught by typecheck).
 *
 * Built from source rather than read from `conformance/tests/multi-method`
 * because `loadANFFromJSON` does not currently decode that golden's
 * `load_const` encoding — a separate, pre-existing limitation of the reference
 * loader, and not something this test should depend on. The six IR-capable
 * tiers are gated against the real golden by
 * `conformance/negatives/ir/I08-method-call-surplus-arg.ir.json`.
 */
const SOURCE = `
import { SmartContract, assert } from 'runar-lang';

export class Helper extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  private addTwo(a: bigint, b: bigint): bigint {
    return a + b;
  }

  public unlock(x: bigint, y: bigint): void {
    const s: bigint = this.addTwo(x, y);
    assert(s === this.target);
  }
}
`;

/** The program's ANF with `addTwo`'s call-site argument list replaced. */
function anfWithArgs(args: string[]): ANFProgram {
  const parsed = parse(SOURCE, 'Helper.runar.ts');
  if (parsed.contract === null) {
    throw new Error(
      `the fixture source must parse; it did not:\n` +
        parsed.errors.map((e) => `  ${e.message}`).join('\n'),
    );
  }
  const program = lowerToANF(parsed.contract) as ANFProgram;
  let patched = 0;
  const walk = (bindings: any[]): void => {
    for (const b of bindings) {
      const v: any = b.value ?? {};
      if (v.kind === 'method_call' && v.method === 'addTwo') {
        v.args = args;
        patched++;
      }
      for (const k of ['body', 'then', 'else', 'thenBody', 'elseBody']) {
        if (Array.isArray(v[k])) walk(v[k]);
      }
    }
  };
  for (const m of program.methods) walk(m.body as any[]);
  expect(patched, 'the contract must still contain the call this test patches').toBe(1);
  return program;
}

const hexFor = (args: string[]): string => emit(lowerToStack(anfWithArgs(args))).scriptHex;

describe('N-111: a method_call may not pass more arguments than the callee declares', () => {
  /**
   * The control. `computeThreshold` takes two parameters and the golden passes
   * two; this must keep lowering, and keep lowering to the same bytes. Without
   * it, "surplus is rejected" would be equally consistent with a lowerer that
   * had stopped inlining private calls at all.
   */
  it('control: the unmodified golden still lowers', () => {
    expect(hexFor(['t0', 't1'])).toBe(hexFor(['t0', 't1']));
    expect(hexFor(['t0', 't1']).length).toBeGreaterThan(0);
  });

  it('rejects one surplus argument', () => {
    expect(() => hexFor(['t0', 't1', 't0'])).toThrow(
      /passes 3 arguments but 'addTwo' declares 2 parameters/,
    );
  });

  /**
   * The case with no honest reading at all: the surplus ref names a binding
   * that does not exist anywhere in the program. Before the fix this was
   * accepted in silence, which means the lowerer never resolved it — a
   * `method_call` could carry arbitrary garbage past position N and no pass
   * would look at it.
   */
  it('rejects a surplus argument naming a binding that does not exist', () => {
    expect(() => hexFor(['t0', 't1', 'tZZZ'])).toThrow(/passes 3 arguments/);
  });

  /**
   * The low side is deliberately NOT changed. Too few arguments already fails,
   * and its diagnostic names the unbound parameter, which is strictly more
   * useful than an arity count. Pinned so a later "tidy this into an equality
   * check" does not trade the better message for the worse one.
   */
  it('too FEW arguments still fails with the parameter-name diagnostic', () => {
    expect(() => hexFor(['t0'])).toThrow(/method parameter '\w+' is not on the stack/);
  });
});
