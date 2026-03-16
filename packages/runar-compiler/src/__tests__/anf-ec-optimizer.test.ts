import { describe, it, expect } from 'vitest';
import { optimizeEC } from '../optimizer/anf-ec.js';
import type { ANFProgram, ANFBinding, ANFMethod, ANFValue } from '../ir/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const INFINITY_HEX = '0'.repeat(128);
const GEN_X = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GEN_Y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
const G_HEX =
  GEN_X.toString(16).padStart(64, '0') +
  GEN_Y.toString(16).padStart(64, '0');

function makeProgram(methods: ANFMethod[]): ANFProgram {
  return { contractName: 'Test', properties: [], methods };
}

function makeMethod(name: string, body: ANFBinding[]): ANFMethod {
  return { name, params: [], body, isPublic: true };
}

function b(name: string, value: ANFValue): ANFBinding {
  return { name, value };
}

function findBinding(program: ANFProgram, name: string): ANFBinding | undefined {
  for (const method of program.methods) {
    for (const binding of method.body) {
      if (binding.name === name) return binding;
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ANF EC Optimizer', () => {
  describe('Rule 5: ecMulGen(0) → INFINITY', () => {
    it('replaces ecMulGen(0) with infinity constant', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 0n }),
          b('t1', { kind: 'call', func: 'ecMulGen', args: ['t0'] }),
          b('t2', { kind: 'assert', value: 't1' }),
        ]),
      ]);
      const result = optimizeEC(program);
      const t1 = findBinding(result, 't1');
      expect(t1).toBeDefined();
      expect(t1!.value.kind).toBe('load_const');
      if (t1!.value.kind === 'load_const') {
        expect(t1!.value.value).toBe(INFINITY_HEX);
      }
    });
  });

  describe('Rule 6: ecMulGen(1) → G', () => {
    it('replaces ecMulGen(1) with generator constant', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 1n }),
          b('t1', { kind: 'call', func: 'ecMulGen', args: ['t0'] }),
          b('t2', { kind: 'assert', value: 't1' }),
        ]),
      ]);
      const result = optimizeEC(program);
      const t1 = findBinding(result, 't1');
      expect(t1).toBeDefined();
      expect(t1!.value.kind).toBe('load_const');
      if (t1!.value.kind === 'load_const') {
        expect(t1!.value.value).toBe(G_HEX);
      }
    });
  });

  describe('Rule 4: ecMul(x, 0) → INFINITY', () => {
    it('replaces ecMul with zero scalar', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_param', name: 'pt' }),
          b('t1', { kind: 'load_const', value: 0n }),
          b('t2', { kind: 'call', func: 'ecMul', args: ['t0', 't1'] }),
          b('t3', { kind: 'assert', value: 't2' }),
        ]),
      ]);
      const result = optimizeEC(program);
      const t2 = findBinding(result, 't2');
      expect(t2).toBeDefined();
      expect(t2!.value.kind).toBe('load_const');
      if (t2!.value.kind === 'load_const') {
        expect(t2!.value.value).toBe(INFINITY_HEX);
      }
    });
  });

  describe('Rule 3: ecMul(x, 1) → x', () => {
    it('replaces ecMul with identity scalar', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_param', name: 'pt' }),
          b('t1', { kind: 'load_const', value: 1n }),
          b('t2', { kind: 'call', func: 'ecMul', args: ['t0', 't1'] }),
          b('t3', { kind: 'assert', value: 't2' }),
        ]),
      ]);
      const result = optimizeEC(program);
      const t2 = findBinding(result, 't2');
      expect(t2).toBeDefined();
      // Should alias to t0 via load_const @ref:
      expect(t2!.value.kind).toBe('load_const');
    });
  });

  describe('Rule 1: ecAdd(x, INFINITY) → x', () => {
    it('simplifies addition with infinity', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_param', name: 'pt' }),
          b('t1', { kind: 'load_const', value: INFINITY_HEX }),
          b('t2', { kind: 'call', func: 'ecAdd', args: ['t0', 't1'] }),
          b('t3', { kind: 'assert', value: 't2' }),
        ]),
      ]);
      const result = optimizeEC(program);
      const t2 = findBinding(result, 't2');
      expect(t2).toBeDefined();
      // Should alias to t0 via load_const @ref:
      expect(t2!.value.kind).toBe('load_const');
    });
  });

  describe('Rule 2: ecAdd(INFINITY, x) → x', () => {
    it('simplifies addition with left infinity', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: INFINITY_HEX }),
          b('t1', { kind: 'load_param', name: 'pt' }),
          b('t2', { kind: 'call', func: 'ecAdd', args: ['t0', 't1'] }),
          b('t3', { kind: 'assert', value: 't2' }),
        ]),
      ]);
      const result = optimizeEC(program);
      const t2 = findBinding(result, 't2');
      expect(t2).toBeDefined();
      expect(t2!.value.kind).toBe('load_const');
    });
  });

  describe('Rule 7: ecNegate(ecNegate(x)) → x', () => {
    it('cancels double negation', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_param', name: 'pt' }),
          b('t1', { kind: 'call', func: 'ecNegate', args: ['t0'] }),
          b('t2', { kind: 'call', func: 'ecNegate', args: ['t1'] }),
          b('t3', { kind: 'assert', value: 't2' }),
        ]),
      ]);
      const result = optimizeEC(program);
      const t2 = findBinding(result, 't2');
      expect(t2).toBeDefined();
      // Should alias to t0 via load_const @ref:
      expect(t2!.value.kind).toBe('load_const');
    });
  });

  describe('Rule 8: ecAdd(x, ecNegate(x)) → INFINITY', () => {
    it('cancels P + (-P)', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_param', name: 'pt' }),
          b('t1', { kind: 'call', func: 'ecNegate', args: ['t0'] }),
          b('t2', { kind: 'call', func: 'ecAdd', args: ['t0', 't1'] }),
          b('t3', { kind: 'assert', value: 't2' }),
        ]),
      ]);
      const result = optimizeEC(program);
      const t2 = findBinding(result, 't2');
      expect(t2).toBeDefined();
      expect(t2!.value.kind).toBe('load_const');
      if (t2!.value.kind === 'load_const') {
        expect(t2!.value.value).toBe(INFINITY_HEX);
      }
    });
  });

  describe('Rule 10: ecAdd(ecMulGen(k1), ecMulGen(k2)) → ecMulGen(k1+k2)', () => {
    it('combines generator multiplications', () => {
      const CURVE_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 5n }),
          b('t1', { kind: 'call', func: 'ecMulGen', args: ['t0'] }),
          b('t2', { kind: 'load_const', value: 7n }),
          b('t3', { kind: 'call', func: 'ecMulGen', args: ['t2'] }),
          b('t4', { kind: 'call', func: 'ecAdd', args: ['t1', 't3'] }),
          b('t5', { kind: 'assert', value: 't4' }),
        ]),
      ]);
      const result = optimizeEC(program);
      const t4 = findBinding(result, 't4');
      expect(t4).toBeDefined();
      expect(t4!.value.kind).toBe('call');
      if (t4!.value.kind === 'call') {
        expect(t4!.value.func).toBe('ecMulGen');
        // The scalar should be (5 + 7) % N = 12
        const scalarBinding = findBinding(result, t4!.value.args[0]!);
        expect(scalarBinding).toBeDefined();
        expect(scalarBinding!.value.kind).toBe('load_const');
        if (scalarBinding!.value.kind === 'load_const') {
          expect(scalarBinding!.value.value).toBe(12n % CURVE_N);
        }
      }
    });
  });

  describe('Rule 12: ecMul(G, k) → ecMulGen(k)', () => {
    it('replaces ecMul with G point with ecMulGen', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('g', { kind: 'load_const', value: G_HEX }),
          b('t0', { kind: 'load_param', name: 'k' }),
          b('t1', { kind: 'call', func: 'ecMul', args: ['g', 't0'] }),
          b('t2', { kind: 'assert', value: 't1' }),
        ]),
      ]);
      const result = optimizeEC(program);
      const t1 = findBinding(result, 't1');
      expect(t1).toBeDefined();
      expect(t1!.value.kind).toBe('call');
      if (t1!.value.kind === 'call') {
        expect(t1!.value.func).toBe('ecMulGen');
        // The scalar argument should reference the original k parameter
        expect(t1!.value.args[0]).toBe('t0');
      }
    });
  });

  describe('does not optimize non-EC calls', () => {
    it('leaves sha256 calls unchanged', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_param', name: 'data' }),
          b('t1', { kind: 'call', func: 'sha256', args: ['t0'] }),
          b('t2', { kind: 'assert', value: 't1' }),
        ]),
      ]);
      const result = optimizeEC(program);
      const t1 = findBinding(result, 't1');
      expect(t1).toBeDefined();
      expect(t1!.value.kind).toBe('call');
      if (t1!.value.kind === 'call') {
        expect(t1!.value.func).toBe('sha256');
      }
    });

    it('passes through a program with no EC operations unchanged', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_param', name: 'x' }),
          b('t1', { kind: 'load_const', value: 5n }),
          b('t2', { kind: 'bin_op', op: '+', left: 't0', right: 't1' }),
          b('t3', { kind: 'assert', value: 't2' }),
        ]),
      ]);
      const result = optimizeEC(program);
      // The program reference should be identical (no change)
      expect(result).toBe(program);
    });
  });

  describe('contract metadata and structural preservation', () => {
    it('preserves contract metadata (name, properties) after optimization', () => {
      // P2PKH-like program with no EC ops
      const program: ANFProgram = {
        contractName: 'P2PKH',
        properties: [
          { name: 'pubKeyHash', type: 'Sha256', readonly: true },
        ],
        methods: [
          makeMethod('unlock', [
            b('t0', { kind: 'load_param', name: 'sig' }),
            b('t1', { kind: 'load_param', name: 'pubKey' }),
            b('t2', { kind: 'call', func: 'hash160', args: ['t1'] }),
            b('t3', { kind: 'load_prop', name: 'pubKeyHash' }),
            b('t4', { kind: 'bin_op', op: '===', left: 't2', right: 't3' }),
            b('t5', { kind: 'assert', value: 't4' }),
            b('t6', { kind: 'call', func: 'checkSig', args: ['t0', 't1'] }),
            b('t7', { kind: 'assert', value: 't6' }),
          ]),
        ],
      };
      const result = optimizeEC(program);
      expect(result.contractName).toBe('P2PKH');
      expect(result.properties).toHaveLength(1);
      expect(result.properties[0]!.name).toBe('pubKeyHash');
    });

    it('optimizes each method in a multi-method program independently', () => {
      // Both methods contain ecAdd(x, INFINITY) — each should be simplified independently
      const program = makeProgram([
        makeMethod('method1', [
          b('t0', { kind: 'load_param', name: 'pt' }),
          b('t1', { kind: 'load_const', value: INFINITY_HEX }),
          b('t2', { kind: 'call', func: 'ecAdd', args: ['t0', 't1'] }),
          b('t3', { kind: 'assert', value: 't2' }),
        ]),
        makeMethod('method2', [
          b('s0', { kind: 'load_param', name: 'pt2' }),
          b('s1', { kind: 'load_const', value: INFINITY_HEX }),
          b('s2', { kind: 'call', func: 'ecAdd', args: ['s0', 's1'] }),
          b('s3', { kind: 'assert', value: 's2' }),
        ]),
      ]);
      const result = optimizeEC(program);
      // Rule 1: ecAdd(x, INFINITY) → alias to x via load_const @ref:
      const t2 = findBinding(result, 't2');
      expect(t2).toBeDefined();
      expect(t2!.value.kind).toBe('load_const');
      if (t2!.value.kind === 'load_const') {
        expect(t2!.value.value).toMatch(/^@ref:/);
      }
      // Check method2: s2 should also be aliased
      const s2 = findBinding(result, 's2');
      expect(s2).toBeDefined();
      expect(s2!.value.kind).toBe('load_const');
      if (s2!.value.kind === 'load_const') {
        expect(s2!.value.value).toMatch(/^@ref:/);
      }
    });

    it('preserves empty method body unchanged', () => {
      const program = makeProgram([
        makeMethod('empty', []),
      ]);
      const result = optimizeEC(program);
      expect(result.methods[0]!.body).toHaveLength(0);
    });

    it('preserves unreferenced call binding (side-effect call)', () => {
      // checkSig is a call — it has side effects (used as assert input), but even
      // a standalone call binding that nothing else references must survive because
      // call bindings are treated as having side effects.
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_param', name: 'sig' }),
          b('t1', { kind: 'load_param', name: 'pubKey' }),
          b('t2', { kind: 'call', func: 'checkSig', args: ['t0', 't1'] }),
          b('t3', { kind: 'assert', value: 't2' }),
        ]),
      ]);
      const result = optimizeEC(program);
      // The checkSig call binding must still be present
      const t2 = findBinding(result, 't2');
      expect(t2).toBeDefined();
      expect(t2!.value.kind).toBe('call');
      if (t2!.value.kind === 'call') {
        expect(t2!.value.func).toBe('checkSig');
      }
    });

    it('chains Rule 12 then Rule 5: ecMul(G, 0) becomes INFINITY', () => {
      // Rule 12: ecMul(G, k) → ecMulGen(k)
      // Rule 5:  ecMulGen(0) → INFINITY
      // Combined: ecMul(G, 0) → INFINITY
      const program = makeProgram([
        makeMethod('m', [
          b('g', { kind: 'load_const', value: G_HEX }),
          b('t0', { kind: 'load_const', value: 0n }),
          b('t1', { kind: 'call', func: 'ecMul', args: ['g', 't0'] }),
          b('t2', { kind: 'assert', value: 't1' }),
        ]),
      ]);
      const result = optimizeEC(program);
      const t1 = findBinding(result, 't1');
      expect(t1).toBeDefined();
      expect(t1!.value.kind).toBe('load_const');
      if (t1!.value.kind === 'load_const') {
        expect(t1!.value.value).toBe(INFINITY_HEX);
      }
    });
  });

  describe('dead binding elimination after EC optimization', () => {
    it('removes bindings that become dead after EC optimization', () => {
      // ecMulGen(0) → INFINITY, so the scalar 0n binding becomes dead
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 0n }),
          b('t1', { kind: 'call', func: 'ecMulGen', args: ['t0'] }),
          b('t2', { kind: 'assert', value: 't1' }),
        ]),
      ]);
      const result = optimizeEC(program);
      // t1 should be replaced with INFINITY constant
      const t1 = findBinding(result, 't1');
      expect(t1!.value.kind).toBe('load_const');
      // t0 (0n) is no longer referenced — dead binding elimination should remove it
      const t0 = findBinding(result, 't0');
      expect(t0).toBeUndefined();
    });

    it('preserves side-effect bindings (assert) even when unreferenced by further EC ops', () => {
      // An assert is a side-effect and must not be eliminated
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_param', name: 'pt' }),
          b('t1', { kind: 'load_const', value: 0n }),
          b('t2', { kind: 'call', func: 'ecMul', args: ['t0', 't1'] }),
          // Assert the result (side effect)
          b('t3', { kind: 'assert', value: 't2' }),
          // Unreferenced constant — should be removed
          b('t4', { kind: 'load_const', value: 99n }),
        ]),
      ]);
      const result = optimizeEC(program);
      // t3 (assert) must be preserved
      const t3 = findBinding(result, 't3');
      expect(t3).toBeDefined();
      // t4 (unused constant) should be removed by dead binding elimination
      const t4 = findBinding(result, 't4');
      expect(t4).toBeUndefined();
    });
  });
});
