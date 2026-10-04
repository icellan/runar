/**
 * F-108 — DCE must treat a PRIVATE method's last binding as a liveness root.
 *
 * A private helper with no output side effect stays its own ANF method; the
 * call site stays a `method_call` and stack lowering inlines the helper,
 * taking its LAST binding as the call's result (05-stack-lower.ts,
 * "Method return value is the last binding result"). Nothing inside the helper
 * references that binding, so when DCE ran — which it does once any EC rewrite
 * fires anywhere in the program — a pure return expression such as `n + 1n`
 * was deleted along with everything feeding it. The helper was emptied and a
 * valid contract failed to compile ("Value 't2' not found on stack").
 *
 * What this proves: `eliminateDeadBindings` keeps a private method's final
 * binding and its transitive inputs, still drops genuinely dead bindings ahead
 * of it, and still drops an unreferenced pure final binding of a PUBLIC method
 * (whose last binding is never a return value); and the reported contract
 * compiles in both constant-folding modes with the helper's body intact.
 *
 * What it does not prove: that the script is spendable — that is executed on
 * all seven tiers by `conformance/dce/private-return.test.ts`.
 */
import { describe, it, expect } from 'vitest';
import { eliminateDeadBindings } from '../optimizer/dce.js';
import { compile } from '../index.js';
import type { ANFProgram, ANFBinding, ANFValue, ANFMethod } from '../ir/index.js';

function b(name: string, value: ANFValue): ANFBinding {
  return { name, value };
}

function method(name: string, isPublic: boolean, body: ANFBinding[]): ANFMethod {
  return { name, params: [{ name: 'n', type: 'bigint' }], body, isPublic };
}

function programOf(...methods: ANFMethod[]): ANFProgram {
  return { contractName: 'T', properties: [], methods };
}

/** `add1(n) { const dead = 7n; return n + 1n; }` */
function add1Body(): ANFBinding[] {
  return [
    b('dead', { kind: 'load_const', value: 7n }),
    b('t0', { kind: 'load_param', name: 'n' }),
    b('t1', { kind: 'load_const', value: 1n }),
    b('t2', { kind: 'bin_op', op: '+', left: 't0', right: 't1' }),
  ];
}

const names = (m: ANFMethod | undefined): string[] => (m?.body ?? []).map((x) => x.name);

describe('F-108: a private method\'s last binding is a DCE root', () => {
  it('keeps the return value of a private helper and its inputs', () => {
    const out = eliminateDeadBindings(programOf(method('add1', false, add1Body())));
    expect(
      names(out.methods[0]),
      'DCE emptied a private helper: its last binding is the value stack ' +
        'lowering returns to the caller, so it is live even though nothing ' +
        'inside the helper references it.',
    ).toEqual(['t0', 't1', 't2']);
  });

  it('still drops an unreferenced pure last binding of a public method', () => {
    const out = eliminateDeadBindings(programOf(method('pub', true, add1Body())));
    expect(names(out.methods[0])).toEqual([]);
  });

  const SOURCE = `
import { SmartContract, assert, ecMulGen, Point } from 'runar-lang';

class P108 extends SmartContract {
  readonly target: bigint = 6n;

  constructor() {
    super();
  }

  public go(n: bigint): void {
    const p: Point = ecMulGen(0n);
    assert(p === p);
    assert(this.add1(n) === this.target);
  }

  private add1(n: bigint): bigint {
    return n + 1n;
  }
}
`;

  for (const disableConstantFolding of [false, true]) {
    it(`compiles the reported contract (constant folding ${disableConstantFolding ? 'OFF' : 'ON'})`, () => {
      const opts = { fileName: 'P108.runar.ts', disableConstantFolding };
      const withEc = compile(SOURCE, opts);
      const errors = withEc.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
      expect(errors, 'valid contract failed to compile once EC-gated DCE ran').toEqual([]);
      expect(withEc.success).toBe(true);
      expect(names(withEc.anf?.methods.find((m) => m.name === 'add1'))).toEqual(['t0', 't1', 't2']);
    });
  }
});
