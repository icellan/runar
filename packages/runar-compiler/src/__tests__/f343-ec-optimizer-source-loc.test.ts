/**
 * F-343 — the TS EC optimizer keeps source locations on what it rewrites.
 *
 * `optimizeBodyOnce` rebuilt a rewritten binding as `{ name, value }` and the
 * helper bindings a rule mints (the fused scalar of Rules 9/10/11, the N-104
 * operand gate of Rules 1-4) had no `sourceLoc` at all, so stack lowering
 * (which maps ops through `binding.sourceLoc`) left every opcode of a
 * rewritten EC call, and of its gate, out of the source map.
 *
 * Convention: the rewritten binding keeps its own location, and every helper
 * minted while rewriting it takes that same location (it exists only because
 * of that source expression).
 *
 * What this proves: on hand-built located ANF, Rules 6 (ecMulGen(1)), 9
 * (scalar fusion helper) and 4 (operand gate helpers) leave the original
 * binding's location on the rewritten binding and on every minted helper;
 * a binding with no location stays without one; and end to end, a TS contract
 * whose `ecMul(p, 1n)` is rewritten has the gate's opcodes mapped to that
 * source line. Script bytes are checked by the conformance goldens, not here.
 *
 * What this does not prove: anything about the other six tiers (they keep the
 * rewritten binding's location but, today, not the helpers'), the exact column
 * the ANF lowerer assigns, or source-map behaviour of rules no test here hits
 * (1, 2, 3, 5, 7, 8, 8r, 10, 11 share the same code path in optimizeBodyOnce).
 */
import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { optimizeEC } from '../optimizer/anf-ec.js';
import type { ANFProgram, ANFBinding, ANFValue } from '../ir/index.js';

type Loc = { file: string; line: number; column: number };

function b(name: string, value: ANFValue, sourceLoc?: Loc): ANFBinding {
  return sourceLoc ? { name, value, sourceLoc } : { name, value };
}

function program(body: ANFBinding[]): ANFProgram {
  return {
    contractName: 'T',
    properties: [],
    methods: [{ name: 'm', params: [{ name: 'pt', type: 'Point' }], body, isPublic: true }],
  };
}

const LOC: Loc = { file: 'T.runar.ts', line: 7, column: 4 };

describe('F-343: EC optimizer preserves sourceLoc', () => {
  it('Rule 6 ecMulGen(1) -> G keeps the rewritten binding location', () => {
    const out = optimizeEC(program([
      b('one', { kind: 'load_const', value: 1n }),
      b('g', { kind: 'call', func: 'ecMulGen', args: ['one'] }, LOC),
      b('x', { kind: 'call', func: 'ecPointX', args: ['g'] }),
      b('a', { kind: 'assert', value: 'x' }),
    ]));
    const g = out.methods[0]!.body.find(x => x.name === 'g')!;
    expect(g.value.kind).toBe('load_const');
    expect(g.sourceLoc).toEqual(LOC);
  });

  it('Rule 9 fusion: rewritten binding and the fused-scalar helper carry the location', () => {
    const before = program([
      b('p', { kind: 'load_param', name: 'pt' }),
      b('k1', { kind: 'load_const', value: 3n }),
      b('k2', { kind: 'load_const', value: 5n }),
      b('inner', { kind: 'call', func: 'ecMul', args: ['p', 'k1'] }),
      b('outer', { kind: 'call', func: 'ecMul', args: ['inner', 'k2'] }, LOC),
      b('x', { kind: 'call', func: 'ecPointX', args: ['outer'] }),
      b('a', { kind: 'assert', value: 'x' }),
    ]);
    const body = optimizeEC(before).methods[0]!.body;
    const outer = body.find(x => x.name === 'outer')!;
    expect(outer.value).toMatchObject({ kind: 'call', func: 'ecMul', args: ['p', 'outer_k'] });
    expect(outer.sourceLoc).toEqual(LOC);
    const helper = body.find(x => x.name === 'outer_k')!;
    expect(helper.value).toMatchObject({ kind: 'load_const', value: 15n });
    expect(helper.sourceLoc).toEqual(LOC);
  });

  it('Rule 4 ecMul(p, 0): every operand-gate helper carries the location', () => {
    const body = optimizeEC(program([
      b('p', { kind: 'load_param', name: 'pt' }),
      b('zero', { kind: 'load_const', value: 0n }),
      b('t', { kind: 'call', func: 'ecMul', args: ['p', 'zero'] }, LOC),
      b('x', { kind: 'call', func: 'ecPointX', args: ['t'] }),
      b('a', { kind: 'assert', value: 'x' }),
    ])).methods[0]!.body;
    const minted = body.filter(x => x.name.startsWith('t_'));
    expect(minted.map(x => x.name)).toEqual(['t_inf', 't_isinf', 't_oncurve', 't_ok', 't_gate']);
    for (const m of minted) expect({ name: m.name, loc: m.sourceLoc }).toEqual({ name: m.name, loc: LOC });
    expect(body.find(x => x.name === 't')!.sourceLoc).toEqual(LOC);
  });

  it('an unlocated binding stays unlocated (no sourceLoc key invented)', () => {
    const body = optimizeEC(program([
      b('p', { kind: 'load_param', name: 'pt' }),
      b('zero', { kind: 'load_const', value: 0n }),
      b('t', { kind: 'call', func: 'ecMul', args: ['p', 'zero'] }),
      b('x', { kind: 'call', func: 'ecPointX', args: ['t'] }),
      b('a', { kind: 'assert', value: 'x' }),
    ])).methods[0]!.body;
    for (const x of body) expect('sourceLoc' in x).toBe(false);
  });

  it('end to end: a rewritten ecMul(p, 1n) and its gate map to the source line', () => {
    const source = [
      "import { SmartContract, assert, ecMul, ecPointX } from 'runar-lang';",
      "import type { Point } from 'runar-lang';",
      '',
      'class EcLoc extends SmartContract {',
      '  readonly x: bigint;',
      '  constructor(x: bigint) { super(x); this.x = x; }',
      '  public check(p: Point) {',
      '    const q = ecMul(p, 1n);',
      '    assert(ecPointX(q) === this.x);',
      '  }',
      '}',
      '',
    ].join('\n');
    const fileName = 'EcLoc.runar.ts';
    const result = compile(source, { fileName });
    expect(result.success).toBe(true);
    const mulLine = source.split('\n').findIndex(l => l.includes('ecMul(p, 1n)')) + 1;
    const onLine = result.artifact!.sourceMap!.mappings.filter(m => m.line === mulLine);
    // The ecMul operand gate (ecOnCurve + the infinity check) is dozens of
    // opcodes; before F-343 none of them was mapped.
    expect(onLine.length).toBeGreaterThan(10);
  });
});
