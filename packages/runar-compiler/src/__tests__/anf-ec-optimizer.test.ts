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
      // Should alias to t0
      expect(t2!.value.kind).toBe('load_param');
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
      // Should alias to t0
      expect(t2!.value.kind).toBe('load_param');
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
      expect(t2!.value.kind).toBe('load_param');
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
      // Should alias to t0
      expect(t2!.value.kind).toBe('load_param');
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
  });
});
