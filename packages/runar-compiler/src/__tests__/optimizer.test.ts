import { describe, it, expect } from 'vitest';
import { foldConstants, eliminateDeadBindings } from '../optimizer/constant-fold.js';
import { optimizeStackIR } from '../optimizer/peephole.js';
import type { ANFProgram, ANFBinding, ANFMethod, ANFValue, StackOp } from '../ir/index.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeProgram(methods: ANFMethod[]): ANFProgram {
  return {
    contractName: 'Test',
    properties: [],
    methods,
  };
}

function makeMethod(name: string, body: ANFBinding[]): ANFMethod {
  return {
    name,
    params: [],
    body,
    isPublic: true,
  };
}

function b(name: string, value: ANFValue): ANFBinding {
  return { name, value };
}

// ---------------------------------------------------------------------------
// Constant folding: binary operations
// ---------------------------------------------------------------------------

describe('Optimizer: Constant Folding', () => {
  describe('binary operations on bigints', () => {
    it('folds addition of two constants', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 10n }),
          b('t1', { kind: 'load_const', value: 20n }),
          b('t2', { kind: 'bin_op', op: '+', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      const t2 = folded.methods[0]!.body[2]!;
      expect(t2.value.kind).toBe('load_const');
      if (t2.value.kind === 'load_const') {
        expect(t2.value.value).toBe(30n);
      }
    });

    it('folds subtraction', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 50n }),
          b('t1', { kind: 'load_const', value: 20n }),
          b('t2', { kind: 'bin_op', op: '-', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value).toEqual({ kind: 'load_const', value: 30n });
    });

    it('folds multiplication', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 6n }),
          b('t1', { kind: 'load_const', value: 7n }),
          b('t2', { kind: 'bin_op', op: '*', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value).toEqual({ kind: 'load_const', value: 42n });
    });

    it('folds division', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 100n }),
          b('t1', { kind: 'load_const', value: 4n }),
          b('t2', { kind: 'bin_op', op: '/', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value).toEqual({ kind: 'load_const', value: 25n });
    });

    it('does not fold division by zero', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 100n }),
          b('t1', { kind: 'load_const', value: 0n }),
          b('t2', { kind: 'bin_op', op: '/', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value.kind).toBe('bin_op');
    });

    it('does not fold modulo by zero', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 100n }),
          b('t1', { kind: 'load_const', value: 0n }),
          b('t2', { kind: 'bin_op', op: '%', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value.kind).toBe('bin_op');
    });

    it('folds modulo', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 10n }),
          b('t1', { kind: 'load_const', value: 3n }),
          b('t2', { kind: 'bin_op', op: '%', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value).toEqual({ kind: 'load_const', value: 1n });
    });

    it('folds comparison operators', () => {
      const tests: [string, bigint, bigint, boolean][] = [
        ['===', 5n, 5n, true],
        ['===', 5n, 6n, false],
        ['!==', 5n, 6n, true],
        ['<', 3n, 5n, true],
        ['<', 5n, 3n, false],
        ['>', 5n, 3n, true],
        ['<=', 5n, 5n, true],
        ['>=', 5n, 5n, true],
      ];
      for (const [op, left, right, expected] of tests) {
        const program = makeProgram([
          makeMethod('m', [
            b('t0', { kind: 'load_const', value: left }),
            b('t1', { kind: 'load_const', value: right }),
            b('t2', { kind: 'bin_op', op, left: 't0', right: 't1' }),
          ]),
        ]);
        const folded = foldConstants(program);
        expect(folded.methods[0]!.body[2]!.value).toEqual(
          { kind: 'load_const', value: expected }
        );
      }
    });

    it('folds left shift', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 1n }),
          b('t1', { kind: 'load_const', value: 3n }),
          b('t2', { kind: 'bin_op', op: '<<', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value).toEqual({ kind: 'load_const', value: 8n });
    });

    it('folds right shift for non-negative operands', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 16n }),
          b('t1', { kind: 'load_const', value: 2n }),
          b('t2', { kind: 'bin_op', op: '>>', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value).toEqual({ kind: 'load_const', value: 4n });
    });

    it('does not fold right shift with negative left operand (Fix #17)', () => {
      // JavaScript >> is arithmetic (sign-extending) but Bitcoin Script's
      // OP_RSHIFT is logical. The constant folder must NOT fold this case
      // because JS (-8n >> 1n) == -4n but Bitcoin OP_RSHIFT gives a
      // different (logical shift) result.
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: -8n }),
          b('t1', { kind: 'load_const', value: 1n }),
          b('t2', { kind: 'bin_op', op: '>>', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      // Should NOT be folded — must remain a bin_op for runtime evaluation
      expect(folded.methods[0]!.body[2]!.value.kind).toBe('bin_op');
    });

    it('folds bitwise operators', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 0b1100n }),
          b('t1', { kind: 'load_const', value: 0b1010n }),
          b('t2', { kind: 'bin_op', op: '&', left: 't0', right: 't1' }),
          b('t3', { kind: 'bin_op', op: '|', left: 't0', right: 't1' }),
          b('t4', { kind: 'bin_op', op: '^', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value).toEqual({ kind: 'load_const', value: 0b1000n });
      expect(folded.methods[0]!.body[3]!.value).toEqual({ kind: 'load_const', value: 0b1110n });
      expect(folded.methods[0]!.body[4]!.value).toEqual({ kind: 'load_const', value: 0b0110n });
    });
  });

  // ---------------------------------------------------------------------------
  // Boolean operations
  // ---------------------------------------------------------------------------

  describe('boolean operations', () => {
    it('folds && and ||', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: true }),
          b('t1', { kind: 'load_const', value: false }),
          b('t2', { kind: 'bin_op', op: '&&', left: 't0', right: 't1' }),
          b('t3', { kind: 'bin_op', op: '||', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value).toEqual({ kind: 'load_const', value: false });
      expect(folded.methods[0]!.body[3]!.value).toEqual({ kind: 'load_const', value: true });
    });

    it('folds boolean equality', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: true }),
          b('t1', { kind: 'load_const', value: true }),
          b('t2', { kind: 'bin_op', op: '===', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value).toEqual({ kind: 'load_const', value: true });
    });
  });

  // ---------------------------------------------------------------------------
  // String (ByteString) operations
  // ---------------------------------------------------------------------------

  describe('string operations', () => {
    it('folds string concatenation', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 'ab' }),
          b('t1', { kind: 'load_const', value: 'cd' }),
          b('t2', { kind: 'bin_op', op: '+', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value).toEqual({ kind: 'load_const', value: 'abcd' });
    });

    it('does not fold concatenation with invalid hex characters', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 'aabb' }),
          b('t1', { kind: 'load_const', value: 'zzzz' }),
          b('t2', { kind: 'bin_op', op: '+', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      // Should NOT fold: 'zzzz' is not valid hex
      expect(folded.methods[0]!.body[2]!.value.kind).toBe('bin_op');
    });

    it('does not fold concatenation when left operand has invalid hex', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 'xyz1' }),
          b('t1', { kind: 'load_const', value: 'aabb' }),
          b('t2', { kind: 'bin_op', op: '+', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value.kind).toBe('bin_op');
    });

    it('folds concatenation of valid hex strings', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 'aabb' }),
          b('t1', { kind: 'load_const', value: 'ccdd' }),
          b('t2', { kind: 'bin_op', op: '+', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value).toEqual({ kind: 'load_const', value: 'aabbccdd' });
    });

    it('folds string equality', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 'abc' }),
          b('t1', { kind: 'load_const', value: 'abc' }),
          b('t2', { kind: 'bin_op', op: '===', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value).toEqual({ kind: 'load_const', value: true });
    });
  });

  // ---------------------------------------------------------------------------
  // Unary operations
  // ---------------------------------------------------------------------------

  describe('unary operations', () => {
    it('folds boolean negation', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: true }),
          b('t1', { kind: 'unary_op', op: '!', operand: 't0' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[1]!.value).toEqual({ kind: 'load_const', value: false });
    });

    it('folds bigint negation', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 42n }),
          b('t1', { kind: 'unary_op', op: '-', operand: 't0' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[1]!.value).toEqual({ kind: 'load_const', value: -42n });
    });

    it('folds bitwise complement', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 0n }),
          b('t1', { kind: 'unary_op', op: '~', operand: 't0' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[1]!.value).toEqual({ kind: 'load_const', value: -1n });
    });

    it('folds ! on bigint (zero -> true)', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 0n }),
          b('t1', { kind: 'unary_op', op: '!', operand: 't0' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[1]!.value).toEqual({ kind: 'load_const', value: true });
    });
  });

  // ---------------------------------------------------------------------------
  // Constant propagation
  // ---------------------------------------------------------------------------

  describe('constant propagation', () => {
    it('propagates constants through chains', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 10n }),
          b('t1', { kind: 'load_const', value: 20n }),
          b('t2', { kind: 'bin_op', op: '+', left: 't0', right: 't1' }),
          // t2 is now const 30n, so t3 = t2 + 12n = 42n
          b('t3', { kind: 'load_const', value: 12n }),
          b('t4', { kind: 'bin_op', op: '+', left: 't2', right: 't3' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[4]!.value).toEqual({ kind: 'load_const', value: 42n });
    });

    it('does not fold when operand is not constant (load_param)', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_param', name: 'x' }),
          b('t1', { kind: 'load_const', value: 5n }),
          b('t2', { kind: 'bin_op', op: '+', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value.kind).toBe('bin_op');
    });
  });

  // ---------------------------------------------------------------------------
  // If-branch folding
  // ---------------------------------------------------------------------------

  describe('if-branch folding', () => {
    it('folds away false branch when condition is known true', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: true }),
          b('t1', {
            kind: 'if',
            cond: 't0',
            then: [b('t2', { kind: 'load_const', value: 42n })],
            else: [b('t3', { kind: 'load_const', value: 99n })],
          }),
        ]),
      ]);
      const folded = foldConstants(program);
      const ifValue = folded.methods[0]!.body[1]!.value;
      expect(ifValue.kind).toBe('if');
      if (ifValue.kind === 'if') {
        expect(ifValue.then).toHaveLength(1);
        expect(ifValue.else).toHaveLength(0);
      }
    });

    it('folds away true branch when condition is known false', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: false }),
          b('t1', {
            kind: 'if',
            cond: 't0',
            then: [b('t2', { kind: 'load_const', value: 42n })],
            else: [b('t3', { kind: 'load_const', value: 99n })],
          }),
        ]),
      ]);
      const folded = foldConstants(program);
      const ifValue = folded.methods[0]!.body[1]!.value;
      if (ifValue.kind === 'if') {
        expect(ifValue.then).toHaveLength(0);
        expect(ifValue.else).toHaveLength(1);
      }
    });

    it('folds constants inside both branches when condition is unknown', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_param', name: 'flag' }),
          b('c1', { kind: 'load_const', value: 5n }),
          b('c2', { kind: 'load_const', value: 3n }),
          b('t1', {
            kind: 'if',
            cond: 't0',
            then: [b('t2', { kind: 'bin_op', op: '+', left: 'c1', right: 'c2' })],
            else: [b('t3', { kind: 'bin_op', op: '-', left: 'c1', right: 'c2' })],
          }),
        ]),
      ]);
      const folded = foldConstants(program);
      const ifValue = folded.methods[0]!.body[3]!.value;
      if (ifValue.kind === 'if') {
        expect(ifValue.then[0]!.value).toEqual({ kind: 'load_const', value: 8n });
        expect(ifValue.else[0]!.value).toEqual({ kind: 'load_const', value: 2n });
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Loop folding
  // ---------------------------------------------------------------------------

  describe('loop folding', () => {
    it('folds constants inside loop body', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('c1', { kind: 'load_const', value: 10n }),
          b('c2', { kind: 'load_const', value: 20n }),
          b('t0', {
            kind: 'loop',
            count: 5,
            iterVar: 'i',
            body: [b('t1', { kind: 'bin_op', op: '+', left: 'c1', right: 'c2' })],
          }),
        ]),
      ]);
      const folded = foldConstants(program);
      const loopValue = folded.methods[0]!.body[2]!.value;
      if (loopValue.kind === 'loop') {
        expect(loopValue.body[0]!.value).toEqual({ kind: 'load_const', value: 30n });
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Non-foldable values pass through unchanged
  // ---------------------------------------------------------------------------

  describe('non-foldable values', () => {
    it('leaves load_param unchanged', () => {
      const program = makeProgram([
        makeMethod('m', [b('t0', { kind: 'load_param', name: 'x' })]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[0]!.value).toEqual({ kind: 'load_param', name: 'x' });
    });

    it('leaves load_prop unchanged', () => {
      const program = makeProgram([
        makeMethod('m', [b('t0', { kind: 'load_prop', name: 'pk' })]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[0]!.value).toEqual({ kind: 'load_prop', name: 'pk' });
    });

    it('leaves call unchanged', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_param', name: 'x' }),
          b('t1', { kind: 'call', func: 'hash160', args: ['t0'] }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[1]!.value.kind).toBe('call');
    });

    it('leaves assert unchanged', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: true }),
          b('t1', { kind: 'assert', value: 't0' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[1]!.value.kind).toBe('assert');
    });

    it('leaves update_prop unchanged', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 0n }),
          b('t1', { kind: 'update_prop', name: 'count', value: 't0' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[1]!.value.kind).toBe('update_prop');
    });

    it('leaves check_preimage unchanged', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_param', name: 'preimage' }),
          b('t1', { kind: 'check_preimage', preimage: 't0' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[1]!.value.kind).toBe('check_preimage');
    });

    it('leaves add_output unchanged', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 1000n }),
          b('t1', { kind: 'load_param', name: 'count' }),
          b('pre', { kind: 'check_preimage', preimage: 'dummyPre' }),
          b('t2', { kind: 'add_output', satoshis: 't0', stateValues: ['t1'], preimage: 'pre' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[3]!.value.kind).toBe('add_output');
    });
  });
});

// ---------------------------------------------------------------------------
// Dead Binding Elimination
// ---------------------------------------------------------------------------

describe('Optimizer: Dead Binding Elimination', () => {
  it('removes unused bindings', () => {
    const program = makeProgram([
      makeMethod('m', [
        b('t0', { kind: 'load_const', value: 42n }),       // unused
        b('t1', { kind: 'load_const', value: true }),
        b('t2', { kind: 'assert', value: 't1' }),
      ]),
    ]);
    const cleaned = eliminateDeadBindings(program);
    const names = cleaned.methods[0]!.body.map(b => b.name);
    expect(names).not.toContain('t0');
    expect(names).toContain('t1');
    expect(names).toContain('t2');
  });

  it('keeps bindings with side effects even if unreferenced', () => {
    const program = makeProgram([
      makeMethod('m', [
        b('t0', { kind: 'load_const', value: true }),
        b('t1', { kind: 'assert', value: 't0' }),           // side effect
        b('t2', { kind: 'load_const', value: 99n }),         // unreferenced
      ]),
    ]);
    const cleaned = eliminateDeadBindings(program);
    const names = cleaned.methods[0]!.body.map(b => b.name);
    expect(names).toContain('t1'); // assert has side effects
    expect(names).not.toContain('t2'); // unused constant
  });

  it('removes transitively dead bindings', () => {
    const program = makeProgram([
      makeMethod('m', [
        b('t0', { kind: 'load_const', value: 10n }),         // only used by t1
        b('t1', { kind: 'load_const', value: 20n }),         // only used by t2
        b('t2', { kind: 'bin_op', op: '+', left: 't0', right: 't1' }), // unused
        b('t3', { kind: 'load_const', value: true }),
        b('t4', { kind: 'assert', value: 't3' }),
      ]),
    ]);
    const cleaned = eliminateDeadBindings(program);
    const names = cleaned.methods[0]!.body.map(b => b.name);
    expect(names).not.toContain('t0');
    expect(names).not.toContain('t1');
    expect(names).not.toContain('t2');
    expect(names).toContain('t3');
    expect(names).toContain('t4');
  });

  it('preserves all bindings when everything is used', () => {
    const program = makeProgram([
      makeMethod('m', [
        b('t0', { kind: 'load_param', name: 'x' }),
        b('t1', { kind: 'load_const', value: 5n }),
        b('t2', { kind: 'bin_op', op: '===', left: 't0', right: 't1' }),
        b('t3', { kind: 'assert', value: 't2' }),
      ]),
    ]);
    const cleaned = eliminateDeadBindings(program);
    expect(cleaned.methods[0]!.body).toHaveLength(4);
  });

  it('keeps update_prop as side effect', () => {
    const program = makeProgram([
      makeMethod('m', [
        b('t0', { kind: 'load_const', value: 0n }),
        b('t1', { kind: 'update_prop', name: 'count', value: 't0' }),
      ]),
    ]);
    const cleaned = eliminateDeadBindings(program);
    expect(cleaned.methods[0]!.body).toHaveLength(2);
  });

  it('keeps check_preimage as side effect', () => {
    const program = makeProgram([
      makeMethod('m', [
        b('t0', { kind: 'load_param', name: 'preimage' }),
        b('t1', { kind: 'check_preimage', preimage: 't0' }),
      ]),
    ]);
    const cleaned = eliminateDeadBindings(program);
    expect(cleaned.methods[0]!.body).toHaveLength(2);
  });

  it('keeps add_output as side effect', () => {
    const program = makeProgram([
      makeMethod('m', [
        b('t0', { kind: 'load_const', value: 1000n }),
        b('t1', { kind: 'load_param', name: 'val' }),
        b('pre', { kind: 'check_preimage', preimage: 'dummyPre' }),
        b('t2', { kind: 'add_output', satoshis: 't0', stateValues: ['t1'], preimage: 'pre' }),
      ]),
    ]);
    const cleaned = eliminateDeadBindings(program);
    expect(cleaned.methods[0]!.body).toHaveLength(4);
  });
});

// ---------------------------------------------------------------------------
// Peephole Optimizer (Stack IR)
// ---------------------------------------------------------------------------

describe('Optimizer: Peephole (Stack IR)', () => {
  describe('DUP/DROP elimination', () => {
    it('removes dup followed by drop (StackOp form)', () => {
      const ops: StackOp[] = [
        { op: 'dup' },
        { op: 'drop' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([]);
    });

    it('removes OP_DUP followed by OP_DROP (opcode form)', () => {
      const ops: StackOp[] = [
        { op: 'opcode', code: 'OP_DUP' },
        { op: 'opcode', code: 'OP_DROP' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([]);
    });
  });

  describe('double negation elimination', () => {
    it('removes OP_NOT OP_NOT', () => {
      const ops: StackOp[] = [
        { op: 'push', value: 1n },
        { op: 'opcode', code: 'OP_NOT' },
        { op: 'opcode', code: 'OP_NOT' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([{ op: 'push', value: 1n }]);
    });

    it('removes OP_NEGATE OP_NEGATE', () => {
      const ops: StackOp[] = [
        { op: 'push', value: 42n },
        { op: 'opcode', code: 'OP_NEGATE' },
        { op: 'opcode', code: 'OP_NEGATE' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([{ op: 'push', value: 42n }]);
    });
  });

  describe('swap elimination', () => {
    it('removes SWAP SWAP', () => {
      const ops: StackOp[] = [
        { op: 'push', value: 1n },
        { op: 'swap' },
        { op: 'swap' },
        { op: 'push', value: 2n },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([
        { op: 'push', value: 1n },
        { op: 'push', value: 2n },
      ]);
    });
  });

  describe('verify fusion', () => {
    it('fuses OP_EQUAL + OP_VERIFY into OP_EQUALVERIFY', () => {
      const ops: StackOp[] = [
        { op: 'opcode', code: 'OP_EQUAL' },
        { op: 'opcode', code: 'OP_VERIFY' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([{ op: 'opcode', code: 'OP_EQUALVERIFY' }]);
    });

    it('fuses OP_CHECKSIG + OP_VERIFY into OP_CHECKSIGVERIFY', () => {
      const ops: StackOp[] = [
        { op: 'opcode', code: 'OP_CHECKSIG' },
        { op: 'opcode', code: 'OP_VERIFY' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([{ op: 'opcode', code: 'OP_CHECKSIGVERIFY' }]);
    });

    it('fuses OP_NUMEQUAL + OP_VERIFY into OP_NUMEQUALVERIFY', () => {
      const ops: StackOp[] = [
        { op: 'opcode', code: 'OP_NUMEQUAL' },
        { op: 'opcode', code: 'OP_VERIFY' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([{ op: 'opcode', code: 'OP_NUMEQUALVERIFY' }]);
    });

    it('fuses OP_CHECKMULTISIG + OP_VERIFY into OP_CHECKMULTISIGVERIFY', () => {
      const ops: StackOp[] = [
        { op: 'opcode', code: 'OP_CHECKMULTISIG' },
        { op: 'opcode', code: 'OP_VERIFY' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([{ op: 'opcode', code: 'OP_CHECKMULTISIGVERIFY' }]);
    });

    it('fuses string-form OP_EQUAL + OP_VERIFY into EQUALVERIFY', () => {
      // Both ops are in OpcodeOp form (op: 'opcode', code: string).
      // This exercises the opcode-string path of the VERIFY fusion rule.
      const ops: StackOp[] = [
        { op: 'opcode', code: 'OP_EQUAL' },
        { op: 'opcode', code: 'OP_VERIFY' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([{ op: 'opcode', code: 'OP_EQUALVERIFY' }]);
    });
  });

  describe('arithmetic identity elimination', () => {
    it('removes PUSH 0 + OP_ADD (identity: x + 0 = x)', () => {
      const ops: StackOp[] = [
        { op: 'push', value: 42n },
        { op: 'push', value: 0n },
        { op: 'opcode', code: 'OP_ADD' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([{ op: 'push', value: 42n }]);
    });

    it('removes PUSH 0 + OP_SUB (identity: x - 0 = x)', () => {
      const ops: StackOp[] = [
        { op: 'push', value: 42n },
        { op: 'push', value: 0n },
        { op: 'opcode', code: 'OP_SUB' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([{ op: 'push', value: 42n }]);
    });

    it('replaces PUSH 1 + OP_ADD with OP_1ADD', () => {
      const ops: StackOp[] = [
        { op: 'push', value: 1n },
        { op: 'opcode', code: 'OP_ADD' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([{ op: 'opcode', code: 'OP_1ADD' }]);
    });

    it('replaces PUSH 1 + OP_SUB with OP_1SUB', () => {
      const ops: StackOp[] = [
        { op: 'push', value: 1n },
        { op: 'opcode', code: 'OP_SUB' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([{ op: 'opcode', code: 'OP_1SUB' }]);
    });
  });

  describe('dead value elimination', () => {
    it('removes PUSH x followed by DROP', () => {
      const ops: StackOp[] = [
        { op: 'push', value: 99n },
        { op: 'drop' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([]);
    });

    it('removes PUSH(bytes) followed by DROP', () => {
      const ops: StackOp[] = [
        { op: 'push', value: Uint8Array.from([0xde, 0xad, 0xbe, 0xef]) },
        { op: 'drop' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([]);
    });

    it('removes PUSH(-1) followed by DROP', () => {
      const ops: StackOp[] = [
        { op: 'push', value: -1n },
        { op: 'drop' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([]);
    });

    it('removes PUSH(false) followed by DROP', () => {
      const ops: StackOp[] = [
        { op: 'push', value: false },
        { op: 'drop' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([]);
    });
  });

  describe('stack fusion', () => {
    it('fuses OVER OVER into OP_2DUP', () => {
      const ops: StackOp[] = [
        { op: 'over' },
        { op: 'over' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([{ op: 'opcode', code: 'OP_2DUP' }]);
    });

    it('fuses DROP DROP into OP_2DROP', () => {
      const ops: StackOp[] = [
        { op: 'drop' },
        { op: 'drop' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([{ op: 'opcode', code: 'OP_2DROP' }]);
    });
  });

  describe('recursive if-block optimization', () => {
    it('optimizes ops inside if-then blocks', () => {
      const ops: StackOp[] = [
        {
          op: 'if',
          then: [
            { op: 'opcode', code: 'OP_NOT' },
            { op: 'opcode', code: 'OP_NOT' },
          ],
        },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([{ op: 'if', then: [] }]);
    });

    it('optimizes ops inside if-else blocks', () => {
      const ops: StackOp[] = [
        {
          op: 'if',
          then: [{ op: 'push', value: 1n }],
          else: [
            { op: 'swap' },
            { op: 'swap' },
          ],
        },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([
        {
          op: 'if',
          then: [{ op: 'push', value: 1n }],
          else: [],
        },
      ]);
    });

    it('removes SWAP SWAP in then-branch independently', () => {
      const ops: StackOp[] = [
        {
          op: 'if',
          then: [
            { op: 'swap' },
            { op: 'swap' },
          ],
          else: [{ op: 'push', value: 2n }],
        },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([
        {
          op: 'if',
          then: [],
          else: [{ op: 'push', value: 2n }],
        },
      ]);
    });

    it('optimizes both then-branch and else-branch independently', () => {
      // then-branch: SWAP SWAP → removed
      // else-branch: OP_NOT OP_NOT → removed
      const ops: StackOp[] = [
        {
          op: 'if',
          then: [
            { op: 'swap' },
            { op: 'swap' },
          ],
          else: [
            { op: 'opcode', code: 'OP_NOT' },
            { op: 'opcode', code: 'OP_NOT' },
          ],
        },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([
        {
          op: 'if',
          then: [],
          else: [],
        },
      ]);
    });
  });

  describe('iterative fixed-point', () => {
    it('cascading elimination across multiple passes', () => {
      // PUSH 99, DROP removes to nothing
      // Then DUP, DROP that were adjacent to a removed pair may cascade
      const ops: StackOp[] = [
        { op: 'dup' },
        { op: 'push', value: 99n },
        { op: 'drop' },
        { op: 'drop' },
      ];
      const result = optimizeStackIR(ops);
      // First pass: PUSH 99 + DROP -> removed, leaving DUP, DROP
      // Second pass: DUP + DROP -> removed
      expect(result).toEqual([]);
    });
  });

  describe('non-matchable ops pass through', () => {
    it('leaves unrelated ops unchanged', () => {
      const ops: StackOp[] = [
        { op: 'push', value: 10n },
        { op: 'opcode', code: 'OP_ADD' },
        { op: 'opcode', code: 'OP_HASH160' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual(ops);
    });
  });

  // -----------------------------------------------------------------------
  // Edge cases: empty and single-op inputs
  // -----------------------------------------------------------------------

  describe('edge cases', () => {
    it('returns empty array for empty input', () => {
      const result = optimizeStackIR([]);
      expect(result).toEqual([]);
    });

    it('leaves a single push op unchanged', () => {
      const ops: StackOp[] = [{ op: 'push', value: 42n }];
      const result = optimizeStackIR(ops);
      expect(result).toEqual(ops);
    });

    it('leaves a single opcode unchanged', () => {
      const ops: StackOp[] = [{ op: 'opcode', code: 'OP_HASH160' }];
      const result = optimizeStackIR(ops);
      expect(result).toEqual(ops);
    });

    it('leaves a single dup unchanged', () => {
      const ops: StackOp[] = [{ op: 'dup' }];
      const result = optimizeStackIR(ops);
      expect(result).toEqual(ops);
    });

    it('handles PUSH bool followed by DROP', () => {
      const ops: StackOp[] = [
        { op: 'push', value: true },
        { op: 'drop' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([]);
    });

    it('handles PUSH bytes followed by DROP', () => {
      const ops: StackOp[] = [
        { op: 'push', value: new Uint8Array([0xde, 0xad]) },
        { op: 'drop' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([]);
    });

    it('leaves an unrelated pair unchanged', () => {
      // OP_HASH160 followed by OP_ADD — no rule applies
      const ops: StackOp[] = [
        { op: 'opcode', code: 'OP_HASH160' },
        { op: 'opcode', code: 'OP_ADD' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual(ops);
    });
  });

  // -----------------------------------------------------------------------
  // New rules: Roll/Pick simplification
  // -----------------------------------------------------------------------

  describe('Roll/Pick simplification', () => {
    it('removes PUSH 0 + Roll(0) (no-op)', () => {
      const ops: StackOp[] = [{ op: 'push', value: 0n }, { op: 'roll', depth: 0 }];
      expect(optimizeStackIR(ops)).toEqual([]);
    });


    it('replaces PUSH 1 + Roll(1) with Swap', () => {
      const ops: StackOp[] = [{ op: 'push', value: 1n }, { op: 'roll', depth: 1 }];
      expect(optimizeStackIR(ops)).toEqual([{ op: 'swap' }]);
    });

    it('replaces PUSH 2 + Roll(2) with Rot', () => {
      const ops: StackOp[] = [{ op: 'push', value: 2n }, { op: 'roll', depth: 2 }];
      expect(optimizeStackIR(ops)).toEqual([{ op: 'rot' }]);
    });

    it('replaces PUSH 0 + Pick(0) with Dup', () => {
      const ops: StackOp[] = [{ op: 'push', value: 0n }, { op: 'pick', depth: 0 }];
      expect(optimizeStackIR(ops)).toEqual([{ op: 'dup' }]);
    });

    it('replaces PUSH 1 + Pick(1) with Over', () => {
      const ops: StackOp[] = [{ op: 'push', value: 1n }, { op: 'pick', depth: 1 }];
      expect(optimizeStackIR(ops)).toEqual([{ op: 'over' }]);
    });
  });

  // -----------------------------------------------------------------------
  // Opcode-string Roll/Pick forms
  // SLH-DSA codegen emits Opcode("OP_ROLL") string form instead of typed
  // Roll/Pick ops. The peephole optimizer currently does NOT reduce these
  // (it only reduces the typed roll/pick forms above).
  // -----------------------------------------------------------------------

  describe('opcode-string Roll/Pick forms', () => {
    it('does NOT optimize PUSH(0) + opcode OP_ROLL (string form, typed form is optimized)', () => {
      // Typed roll{0} is optimized away. Opcode-string OP_ROLL is not.
      // POTENTIAL BUG: OP_ROLL string form and OP_PICK string form are not
      // reduced by the same rules as typed Roll/Pick ops. Go/Rust/Python
      // compilers may handle this differently.
      const typedOps: StackOp[] = [{ op: 'push', value: 0n }, { op: 'roll', depth: 0 }];
      expect(optimizeStackIR(typedOps)).toEqual([]);

      const stringOps: StackOp[] = [{ op: 'push', value: 0n }, { op: 'opcode', code: 'OP_ROLL' }];
      // Currently passes through unchanged (not optimized)
      expect(optimizeStackIR(stringOps)).toEqual(stringOps);
    });

    it('does NOT optimize PUSH(0) + opcode OP_PICK (string form, typed form is optimized)', () => {
      // Typed pick{0} → dup. Opcode-string OP_PICK is not reduced.
      const typedOps: StackOp[] = [{ op: 'push', value: 0n }, { op: 'pick', depth: 0 }];
      expect(optimizeStackIR(typedOps)).toEqual([{ op: 'dup' }]);

      const stringOps: StackOp[] = [{ op: 'push', value: 0n }, { op: 'opcode', code: 'OP_PICK' }];
      // Currently passes through unchanged (not optimized)
      expect(optimizeStackIR(stringOps)).toEqual(stringOps);
    });
  });

  // -----------------------------------------------------------------------
  // New rules: SHA256+SHA256, 0+NUMEQUAL, 1+MUL
  // -----------------------------------------------------------------------

  describe('new 2-op rules', () => {
    it('fuses SHA256 SHA256 into HASH256', () => {
      const ops: StackOp[] = [
        { op: 'opcode', code: 'OP_SHA256' },
        { op: 'opcode', code: 'OP_SHA256' },
      ];
      expect(optimizeStackIR(ops)).toEqual([{ op: 'opcode', code: 'OP_HASH256' }]);
    });

    it('replaces PUSH 0 + NUMEQUAL with NOT', () => {
      const ops: StackOp[] = [
        { op: 'push', value: 0n },
        { op: 'opcode', code: 'OP_NUMEQUAL' },
      ];
      expect(optimizeStackIR(ops)).toEqual([{ op: 'opcode', code: 'OP_NOT' }]);
    });

  });

  // -----------------------------------------------------------------------
  // New rules: 3-op constant folding
  // -----------------------------------------------------------------------

  describe('3-op constant folding', () => {
    it('folds PUSH(a) PUSH(b) ADD to PUSH(a+b)', () => {
      const ops: StackOp[] = [
        { op: 'push', value: 3n },
        { op: 'push', value: 7n },
        { op: 'opcode', code: 'OP_ADD' },
      ];
      expect(optimizeStackIR(ops)).toEqual([{ op: 'push', value: 10n }]);
    });

    it('folds PUSH(a) PUSH(b) SUB to PUSH(a-b)', () => {
      const ops: StackOp[] = [
        { op: 'push', value: 10n },
        { op: 'push', value: 3n },
        { op: 'opcode', code: 'OP_SUB' },
      ];
      expect(optimizeStackIR(ops)).toEqual([{ op: 'push', value: 7n }]);
    });

    it('folds PUSH(a) PUSH(b) MUL to PUSH(a*b)', () => {
      const ops: StackOp[] = [
        { op: 'push', value: 6n },
        { op: 'push', value: 7n },
        { op: 'opcode', code: 'OP_MUL' },
      ];
      expect(optimizeStackIR(ops)).toEqual([{ op: 'push', value: 42n }]);
    });

    it('constant-folds SUB that produces a negative result', () => {
      // Stack semantics: PUSH(3), PUSH(10), SUB → 3 - 10 = -7
      const ops: StackOp[] = [
        { op: 'push', value: 3n },
        { op: 'push', value: 10n },
        { op: 'opcode', code: 'OP_SUB' },
      ];
      expect(optimizeStackIR(ops)).toEqual([{ op: 'push', value: -7n }]);
    });

    it('constant-folds ADD with large values (1000 + 999 = 1999)', () => {
      const ops: StackOp[] = [
        { op: 'push', value: 1000n },
        { op: 'push', value: 999n },
        { op: 'opcode', code: 'OP_ADD' },
      ];
      expect(optimizeStackIR(ops)).toEqual([{ op: 'push', value: 1999n }]);
    });
  });

  // -----------------------------------------------------------------------
  // New rules: 4-op chain folding
  // -----------------------------------------------------------------------

  describe('4-op chain folding', () => {
    it('folds PUSH(a) ADD PUSH(b) ADD to PUSH(a+b) ADD', () => {
      const ops: StackOp[] = [
        { op: 'push', value: 3n },
        { op: 'opcode', code: 'OP_ADD' },
        { op: 'push', value: 7n },
        { op: 'opcode', code: 'OP_ADD' },
      ];
      expect(optimizeStackIR(ops)).toEqual([
        { op: 'push', value: 10n },
        { op: 'opcode', code: 'OP_ADD' },
      ]);
    });

    it('folds PUSH(a) SUB PUSH(b) SUB to PUSH(a+b) SUB', () => {
      const ops: StackOp[] = [
        { op: 'push', value: 3n },
        { op: 'opcode', code: 'OP_SUB' },
        { op: 'push', value: 7n },
        { op: 'opcode', code: 'OP_SUB' },
      ];
      expect(optimizeStackIR(ops)).toEqual([
        { op: 'push', value: 10n },
        { op: 'opcode', code: 'OP_SUB' },
      ]);
    });
  });
});
