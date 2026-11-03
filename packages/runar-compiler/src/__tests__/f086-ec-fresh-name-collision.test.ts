/**
 * F-086 — a name minted by the EC optimizer must never collide with a name the
 * method already uses.
 *
 * The scalar-fusing rules (9, 10, 11) fold a new constant scalar and bind it
 * under a generated name placed just before the rewritten binding. This tier
 * mints `<binding>_k`. ANF is single-assignment, and stack lowering resolves a
 * name to the shallowest stack slot carrying it, so if `<binding>_k` is already
 * a body binding or a method param, the two values share one name: the
 * rewritten call and every later reference to the ORIGINAL name read whichever
 * slot is shallowest. Reachable from `--ir` / `compileFromANF`, where binding
 * and param names are attacker-chosen.
 *
 * Pre-fix, a body binding `s_k = 999` followed by
 * `s = ecAdd(ecMulGen(2), ecMulGen(3))` and `assert(k === s_k)` compiled to a
 * script that accepts k = 5 and rejects the honest k = 999 (verified with
 * @bsv/sdk Spend.validate, strict v1 — see the F-086 remediation log).
 *
 * What this proves: the minted name is fresh w.r.t. every binding name (at
 * any depth), every param and every property of the method; the collision
 * programs compile to exactly the script of the same program with the
 * colliding name renamed away; and the no-collision naming is unchanged.
 * What it does not prove: anything about names minted by stack lowering
 * (`_codePart`, `__param_*`, `__merge$*`), which is a separate namespace
 * question.
 */
import { describe, it, expect } from 'vitest';
import { optimizeEC } from '../optimizer/anf-ec.js';
import { compileFromANF } from '../index.js';
import type { ANFProgram, ANFBinding, ANFMethod, ANFValue } from '../ir/index.js';

function b(name: string, value: ANFValue): ANFBinding {
  return { name, value };
}

/** unlock(p: Point, <kName>: bigint) with an optional pre-existing body binding. */
function program(opts: { bodyName?: string; kParam?: string }): ANFProgram {
  const kParam = opts.kParam ?? 'k';
  const body: ANFBinding[] = [];
  if (opts.bodyName) body.push(b(opts.bodyName, { kind: 'load_const', value: 999n }));
  body.push(
    b('t1', { kind: 'load_const', value: 2n }),
    b('t2', { kind: 'call', func: 'ecMulGen', args: ['t1'] }),
    b('t3', { kind: 'load_const', value: 3n }),
    b('t4', { kind: 'call', func: 'ecMulGen', args: ['t3'] }),
    b('s', { kind: 'call', func: 'ecAdd', args: ['t2', 't4'] }),
    b('t5', { kind: 'load_param', name: 'p' }),
    b('t6', { kind: 'bin_op', op: '===', left: 's', right: 't5' }),
    b('t7', { kind: 'assert', value: 't6' }),
    b('t8', { kind: 'load_param', name: kParam }),
  );
  if (opts.bodyName) {
    body.push(b('t9', { kind: 'bin_op', op: '===', left: 't8', right: opts.bodyName }));
  } else {
    body.push(
      b('t9c', { kind: 'load_const', value: 999n }),
      b('t9', { kind: 'bin_op', op: '===', left: 't8', right: 't9c' }),
    );
  }
  body.push(b('t10', { kind: 'assert', value: 't9' }));
  const methods: ANFMethod[] = [
    { name: 'constructor', params: [], isPublic: false, body: [
      b('t0', { kind: 'call', func: 'super', args: [] }),
    ] },
    { name: 'unlock', isPublic: true, body, params: [
      { name: 'p', type: 'Point' }, { name: kParam, type: 'bigint' },
    ] },
  ];
  return { contractName: 'EcOptCollide', properties: [], methods };
}

function unlockOf(p: ANFProgram): ANFMethod {
  return p.methods.find(m => m.name === 'unlock')!;
}

/** The scalar the rewritten `s` actually consumes: the latest prior binding of its arg. */
function fusedScalar(m: ANFMethod): unknown {
  const i = m.body.findIndex(x => x.name === 's');
  const s = m.body[i]!.value;
  expect(s.kind).toBe('call');
  if (s.kind !== 'call') return undefined;
  expect(s.func).toBe('ecMulGen');
  const arg = s.args[0]!;
  expect(m.params.map(q => q.name)).not.toContain(arg);
  const prior = m.body.slice(0, i).filter(x => x.name === arg);
  expect(prior.length).toBe(1);
  const v = prior[0]!.value;
  return v.kind === 'load_const' ? v.value : undefined;
}

function expectSingleAssignment(m: ANFMethod): void {
  const names = m.body.map(x => x.name);
  expect(new Set(names).size).toBe(names.length);
  for (const q of m.params) expect(names).not.toContain(q.name);
}

describe('F-086: EC optimizer minted names are collision-free', () => {
  it('control: no collision keeps the historical `<binding>_k` name', () => {
    const m = unlockOf(optimizeEC(program({})));
    expect(m.body.some(x => x.name === 's_k')).toBe(true);
    expect(fusedScalar(m)).toBe(5n);
  });

  it('a pre-existing body binding `s_k` is not shadowed', () => {
    const m = unlockOf(optimizeEC(program({ bodyName: 's_k' })));
    expectSingleAssignment(m);
    expect(fusedScalar(m)).toBe(5n);
    const orig = m.body.find(x => x.name === 's_k')!;
    expect(orig.value).toEqual({ kind: 'load_const', value: 999n });
  });

  it('a method param named `s_k` is not shadowed', () => {
    const m = unlockOf(optimizeEC(program({ kParam: 's_k' })));
    expectSingleAssignment(m);
    expect(fusedScalar(m)).toBe(5n);
  });

  it('colliding programs compile to the same script as their renamed twins', () => {
    const ref = compileFromANF(program({ bodyName: 'zz_unused' })).scriptHex;
    expect(compileFromANF(program({ bodyName: 's_k' })).scriptHex).toBe(ref);
    const refParam = compileFromANF(program({ kParam: 'zz' })).scriptHex;
    expect(compileFromANF(program({ kParam: 's_k' })).scriptHex).toBe(refParam);
  });
});
