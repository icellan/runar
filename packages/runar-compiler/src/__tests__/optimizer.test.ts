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
          b('t2', { kind: 'add_output', satoshis: 't0', stateValues: ['t1'] }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value.kind).toBe('add_output');
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
        b('t2', { kind: 'add_output', satoshis: 't0', stateValues: ['t1'] }),
      ]),
    ]);
    const cleaned = eliminateDeadBindings(program);
    expect(cleaned.methods[0]!.body).toHaveLength(3);
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
        { op: 'push', value: 20n },
        { op: 'opcode', code: 'OP_ADD' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual(ops);
    });
  });
});
