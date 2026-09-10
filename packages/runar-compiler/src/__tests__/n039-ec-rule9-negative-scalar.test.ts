/**
 * N-039 — rule 9 (`ecMul(ecMul(p, k1), k2)` → `ecMul(p, k1*k2)`) must reduce the
 * fused scalar into `[0, CURVE_N)`.
 *
 * JavaScript's `%` is truncated, not floored, so a negative constant scalar used
 * to produce a NEGATIVE fused scalar in the TypeScript tier while Go, Rust,
 * Python, Zig, Ruby and Java all normalised into `[0, n)` — a cross-tier hex
 * divergence in the fold-ON leg. Rules 10 and 11 in the same file already
 * normalise; rule 9 did not.
 */
import { describe, it, expect } from 'vitest';
import { optimizeEC } from '../optimizer/anf-ec.js';
import { compile } from '../index.js';
import type { ANFProgram, ANFBinding, ANFMethod, ANFValue } from '../ir/index.js';

const CURVE_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

function makeProgram(methods: ANFMethod[]): ANFProgram {
  return { contractName: 'Test', properties: [], methods };
}

function makeMethod(name: string, body: ANFBinding[]): ANFMethod {
  return { name, params: [], body, isPublic: true };
}

function b(name: string, value: ANFValue): ANFBinding {
  return { name, value };
}

/** Build `ecMul(ecMul(pt, k1), k2)` and return the fused scalar rule 9 produced. */
function fusedScalar(k1: bigint, k2: bigint): bigint {
  const program = makeProgram([
    makeMethod('m', [
      b('t0', { kind: 'load_param', name: 'pt' }),
      b('t1', { kind: 'load_const', value: k1 }),
      b('t2', { kind: 'call', func: 'ecMul', args: ['t0', 't1'] }),
      b('t3', { kind: 'load_const', value: k2 }),
      b('t4', { kind: 'call', func: 'ecMul', args: ['t2', 't3'] }),
      b('t5', { kind: 'assert', value: 't4' }),
    ]),
  ]);
  const result = optimizeEC(program);
  const body = result.methods[0]!.body;
  const t4 = body.find((x) => x.name === 't4');
  expect(t4, 'rule 9 must fire — if it declined, the probe shape is wrong').toBeDefined();
  expect(t4!.value.kind).toBe('call');
  if (t4!.value.kind !== 'call') throw new Error('unreachable');
  expect(t4!.value.func).toBe('ecMul');
  const scalarName = t4!.value.args[1]!;
  const scalarBinding = body.find((x) => x.name === scalarName);
  expect(scalarBinding, `fused scalar binding ${scalarName} must exist`).toBeDefined();
  expect(scalarBinding!.value.kind).toBe('load_const');
  if (scalarBinding!.value.kind !== 'load_const') throw new Error('unreachable');
  const v = scalarBinding!.value.value;
  expect(typeof v).toBe('bigint');
  return v as bigint;
}

describe('N-039: EC rule 9 scalar fusion normalises into [0, CURVE_N)', () => {
  it('folds a NEGATIVE constant scalar to a non-negative value', () => {
    const fused = fusedScalar(-3n, 5n);
    expect(fused).toBeGreaterThanOrEqual(0n);
    expect(fused).toBeLessThan(CURVE_N);
    expect(fused).toBe(CURVE_N - 15n);
  });

  it('folds a negative RIGHT scalar to a non-negative value', () => {
    const fused = fusedScalar(7n, -2n);
    expect(fused).toBeGreaterThanOrEqual(0n);
    expect(fused).toBe(CURVE_N - 14n);
  });

  it('control: positive scalars keep folding to the plain product', () => {
    expect(fusedScalar(3n, 5n)).toBe(15n);
    expect(fusedScalar(2n, 3n)).toBe(6n);
  });

  it('control: a product that wraps CURVE_N still reduces into range', () => {
    const fused = fusedScalar(CURVE_N - 1n, 2n);
    expect(fused).toBe(CURVE_N - 2n);
  });

  it('end-to-end (fold ON): the fused scalar reaching stack lowering is in [0, CURVE_N)', () => {
    // Fold ON is the only leg where a negative literal reaches rule 9 (see the
    // reachability test below). The six native tiers all normalise, so a
    // negative fused scalar here is a cross-tier hex divergence: the scalar is
    // pushed as a 1-byte negative script number instead of the 32-byte
    // canonical representative.
    const negSource = `
import { SmartContract, assert, ecOnCurve, ecMul, ecMulGen } from 'runar-lang';

export class EcNegProbe extends SmartContract {
  constructor() { super(); }

  public unlock(): void {
    assert(ecOnCurve(ecMul(ecMul(ecMulGen(9n), -3n), 5n)));
  }
}
`;
    const on = compile(negSource, { fileName: 'EcNegProbe.runar.ts' });
    expect(on.success, JSON.stringify(on.diagnostics)).toBe(true);
    expect(typeof on.scriptHex).toBe('string');
    expect(on.scriptHex!.length).toBeGreaterThan(0);

    const bindings = on.anf!.methods.flatMap((m) => m.body);
    // Rule 9 fired: the outer ecMul now takes a fused constant scalar.
    const fused = bindings.find((x) => x.name.endsWith('_k'));
    expect(fused, 'rule 9 must have produced a fused scalar binding').toBeDefined();
    expect(fused!.value.kind).toBe('load_const');
    if (fused!.value.kind !== 'load_const') throw new Error('unreachable');
    expect(fused!.value.value).toBe(CURVE_N - 15n);

    // Note: the superseded `ecMul(p, -3n)` binding survives DCE (calls are
    // conservatively treated as side-effecting) and still carries the author's
    // own negative literal. All seven tiers agree on that binding; only the
    // FUSED scalar rule 9 synthesises was tier-divergent.
  });

  it('reachability: with folding OFF the negative literal never reaches rule 9', () => {
    // `-3n` lowers to `unary_op '-'` over `load_const 3n`, so `getConstInt`
    // returns undefined and rule 9 declines outright. The fused-scalar bug is
    // therefore only observable in the fold-ON leg via the source pipeline.
    const negSource = `
import { SmartContract, assert, ecOnCurve, ecMul, ecMulGen } from 'runar-lang';

export class EcNegProbe extends SmartContract {
  constructor() { super(); }

  public unlock(): void {
    assert(ecOnCurve(ecMul(ecMul(ecMulGen(9n), -3n), 5n)));
  }
}
`;
    const off = compile(negSource, {
      fileName: 'EcNegProbe.runar.ts',
      disableConstantFolding: true,
    });
    expect(off.success, JSON.stringify(off.diagnostics)).toBe(true);
    const bindings = off.anf!.methods.flatMap((m) => m.body);
    // Rule 9 did not fire: both ecMul calls survive.
    const ecMuls = bindings.filter(
      (x) => x.value.kind === 'call' && x.value.func === 'ecMul',
    );
    expect(ecMuls.length).toBe(2);
    // And no negative constant is present anywhere in the fold-OFF ANF.
    for (const binding of bindings) {
      if (binding.value.kind === 'load_const' && typeof binding.value.value === 'bigint') {
        expect(binding.value.value).toBeGreaterThanOrEqual(0n);
      }
    }
  });
});
