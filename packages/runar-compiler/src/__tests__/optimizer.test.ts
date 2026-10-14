import { describe, it, expect } from 'vitest';
import { foldConstants, eliminateDeadBindings } from '../optimizer/constant-fold.js';
import { optimizeStackIR } from '../optimizer/peephole.js';
import { compile, compileFromANF, loadANFFromJSON } from '../index.js';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ANFProgram, ANFBinding, ANFMethod, ANFValue, StackOp } from '../ir/index.js';
import { emitMethod } from '../passes/06-emit.js';
// @ts-expect-error vitest resolves this via alias (runar-testing is not a tsc dep of runar-compiler)
import { ScriptVM, bytesToHex } from 'runar-testing';

/** N-065: the ANF the (now refused) N-064 collision probes lowered to. */
const N064_COLLISION_ANF = JSON.parse(
  readFileSync(join(__dirname, '../../../../conformance/negatives/n064-collision-anf.json'), 'utf8'),
) as { probes: Array<{ name: string; source: string; ir: unknown }> };

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

    it('does NOT fold shifts (OP_LSHIFT/OP_RSHIFT are byte-array ops)', () => {
      // Bitcoin Script's OP_LSHIFT/OP_RSHIFT operate on the operands' raw
      // script-number bytes, preserving byte length — 255 << 1 is 254 on-chain,
      // not 510. Folding with native bigint would bake a wrong constant into
      // the deployed script, so the folder must leave these as bin_ops for the
      // runtime opcode (and the interpreter models the same byte semantics).
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 255n }),
          b('t1', { kind: 'load_const', value: 1n }),
          b('t2', { kind: 'bin_op', op: '<<', left: 't0', right: 't1' }),
          b('t3', { kind: 'bin_op', op: '>>', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value.kind).toBe('bin_op');
      expect(folded.methods[0]!.body[3]!.value.kind).toBe('bin_op');
    });

    it('does not fold right shift with negative left operand (Fix #17)', () => {
      // Subsumed by the rule above, but kept as an explicit regression anchor.
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: -8n }),
          b('t1', { kind: 'load_const', value: 1n }),
          b('t2', { kind: 'bin_op', op: '>>', left: 't0', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value.kind).toBe('bin_op');
    });

    it('does NOT fold bitwise operators (OP_AND/OP_OR/OP_XOR are byte-array ops)', () => {
      // These require equal-length operand bytes and operate bytewise — the
      // numeric fold (e.g. 255 & 1 == 1) disagrees with the on-chain result
      // (255 & 1 ABORTS on a length mismatch). Never fold; emit the opcode.
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
      expect(folded.methods[0]!.body[2]!.value.kind).toBe('bin_op');
      expect(folded.methods[0]!.body[3]!.value.kind).toBe('bin_op');
      expect(folded.methods[0]!.body[4]!.value.kind).toBe('bin_op');
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

    it('does NOT fold bitwise complement (OP_INVERT is a byte-array op)', () => {
      // OP_INVERT flips the operand's script-number bytes, not native ~n
      // (~5 is -122 on-chain, not -6). Never fold; emit the opcode.
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: 5n }),
          b('t1', { kind: 'unary_op', op: '~', operand: 't0' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[1]!.value.kind).toBe('unary_op');
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

    // N-064: a name can be bound more than once (a reassignment, or a user
    // local that shares an earlier compiler temp's name). The env must track
    // the LATEST binding, so a rebinding to a non-constant drops the old
    // constant. Proves: after x = 1, rebinding x to a param or to an @ref
    // alias leaves `x + 1` unfolded. Does not prove anything about if/loop
    // arms (see the if-branch / loop tests) or the emitted script (the
    // end-to-end Spend proof is runar-testing's n064 test).
    it('drops a stale constant when the name is rebound to a load_param (N-064)', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('x', { kind: 'load_const', value: 1n }),
          b('x', { kind: 'load_param', name: 'p' }),
          b('t1', { kind: 'load_const', value: 1n }),
          b('t2', { kind: 'bin_op', op: '+', left: 'x', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[3]!.value.kind).toBe('bin_op');
    });

    it('drops a stale constant when the name is rebound to an @ref alias (N-064)', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('x', { kind: 'load_const', value: 1n }),
          b('p0', { kind: 'load_param', name: 'p' }),
          b('x', { kind: 'load_const', value: '@ref:p0' }),
          b('t1', { kind: 'load_const', value: 1n }),
          b('t2', { kind: 'bin_op', op: '+', left: 'x', right: 't1' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[4]!.value.kind).toBe('bin_op');
    });

    it('a user local named like an earlier temp does not fold with the temp\'s constant (N-064)', () => {
      // `assert(p > 0n); let t1: bigint = p; assert(t1 + 1n === 1n);` — the
      // `0n` lowers to temp t1, then the user local rebinds t1. Folded with
      // the stale t1 = 0 the guard became OP_TRUE and accepted any p > 0.
      //
      // N-065: that source is now refused (a local may not be spelled like an
      // ANF temp), so the collision ANF it lowered to is replayed directly
      // from the shared corpus. It is the exact binding list the source
      // produced; before N-064 folding it gave `7600a0695151515177777777`.
      const probe = N064_COLLISION_ANF.probes.find((p) => p.name === 'Rebind')!;
      expect(compile(probe.source, { fileName: 'Rebind.runar.ts' }).success).toBe(false);
      const load = () => loadANFFromJSON(JSON.stringify(probe.ir));
      const off = compileFromANF(load()).scriptHex;
      const on = compileFromANF(foldConstants(load())).scriptHex;
      expect(off).toBe('76007c78a0697c8b519c77');
      expect(on).toBe(off);
    });
  });

  // ---------------------------------------------------------------------------
  // If-branch folding
  // ---------------------------------------------------------------------------

  describe('if-branch folding', () => {
    // A statically-known condition must NOT blank the untaken arm.
    //
    // The folder used to return `else: []` (or `then: []`) while leaving the
    // `if` node itself in place. An arm is not a free-floating binding list —
    // it carries the stack-shape contract 04-anf-lower builds (the
    // `__merge$<i>` result block for K>=2 merged locals) and 05-stack-lower
    // consumes. Erasing one arm made `lowerIf` register ONE stackMap slot for
    // K physical results, which at K=2 silently miscompiled the guard (the
    // deployed script accepted spends the source rejects) and at K=1 rejected
    // source that compiles with folding disabled.
    it('keeps BOTH arms when the condition is known true', () => {
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
        expect(ifValue.else).toHaveLength(1);
      }
    });

    it('keeps BOTH arms when the condition is known false', () => {
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
      expect(ifValue.kind).toBe('if');
      if (ifValue.kind === 'if') {
        expect(ifValue.then).toHaveLength(1);
        expect(ifValue.else).toHaveLength(1);
      }
    });

    // A statically-known condition must not leak an arm's constants into the
    // enclosing environment either: the `if` survives the pass, so both arms
    // are still emitted and either can run.
    it('does not propagate a taken arm\'s constants past the if', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('t0', { kind: 'load_const', value: true }),
          b('t1', {
            kind: 'if',
            cond: 't0',
            then: [b('x', { kind: 'load_const', value: 42n })],
            else: [b('x', { kind: 'load_const', value: 99n })],
          }),
          b('t2', { kind: 'bin_op', op: '+', left: 'x', right: 't0' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[2]!.value.kind).toBe('bin_op');
    });

    // N-064: an arm that rebinds a name the enclosing env holds as a constant
    // changes that name's value after the if (it is how a branch reassigns a
    // local), so the pre-if constant must not survive the if. Proves: the
    // fold of `x + 1` after the if is not done with the stale x = 0.
    it('drops a constant the if rebinds in an arm (N-064)', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('x', { kind: 'load_const', value: 0n }),
          b('c', { kind: 'load_param', name: 'c' }),
          b('t1', {
            kind: 'if',
            cond: 'c',
            then: [
              b('t2', { kind: 'load_param', name: 'p' }),
              b('x', { kind: 'load_const', value: '@ref:t2' }),
            ],
            else: [],
          }),
          b('t3', { kind: 'load_const', value: 1n }),
          b('t4', { kind: 'bin_op', op: '+', left: 'x', right: 't3' }),
        ]),
      ]);
      const folded = foldConstants(program);
      expect(folded.methods[0]!.body[4]!.value.kind).toBe('bin_op');
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
            start: 0n,
            step: 1,
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

  describe('loop folding: names the body rebinds (N-064)', () => {
    // The body is emitted once per iteration, so a read before the body's own
    // rebinding sees the ENTRY value only in iteration 0. A name the body
    // rebinds is not a constant inside the body, nor after the loop. Proves:
    // neither the in-body nor the post-loop `x + 1` folds with x = 0.
    it('does not fold a body-rebound name inside the body or after the loop', () => {
      const program = makeProgram([
        makeMethod('m', [
          b('x', { kind: 'load_const', value: 0n }),
          b('t0', {
            kind: 'loop',
            count: 2,
            iterVar: 'i',
            start: 0n,
            step: 1,
            body: [
              b('t1', { kind: 'load_const', value: 1n }),
              b('t2', { kind: 'bin_op', op: '+', left: 'x', right: 't1' }),
              b('t3', { kind: 'load_param', name: 'p' }),
              b('x', { kind: 'load_const', value: '@ref:t3' }),
            ],
          }),
          b('t4', { kind: 'load_const', value: 1n }),
          b('t5', { kind: 'bin_op', op: '+', left: 'x', right: 't4' }),
        ]),
      ]);
      const folded = foldConstants(program);
      const loopValue = folded.methods[0]!.body[1]!.value;
      expect(loopValue.kind).toBe('loop');
      if (loopValue.kind === 'loop') {
        expect(loopValue.body[1]!.value.kind).toBe('bin_op');
      }
      expect(folded.methods[0]!.body[3]!.value.kind).toBe('bin_op');
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

    it('keeps OP_NEGATE OP_NEGATE (F-001: OP_NEGATE validates/normalises its operand)', () => {
      // Sound to drop only over a canonical producer like this constant; the
      // rule has no producer guard (see peephole.ts), so it never fires — the
      // ANF constant folder covers the constant case.
      const ops: StackOp[] = [
        { op: 'push', value: 42n },
        { op: 'opcode', code: 'OP_NEGATE' },
        { op: 'opcode', code: 'OP_NEGATE' },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual(ops);
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
      // OP_NUMEQUAL is a canonical-boolean producer, so the OP_NOT pair on top
      // of it is genuine double negation and collapses (C17: the pair is only
      // removable when the value beneath is provably 0/1).
      const ops: StackOp[] = [
        {
          op: 'if',
          then: [
            { op: 'opcode', code: 'OP_NUMEQUAL' },
            { op: 'opcode', code: 'OP_NOT' },
            { op: 'opcode', code: 'OP_NOT' },
          ],
        },
      ];
      const result = optimizeStackIR(ops);
      expect(result).toEqual([{ op: 'if', then: [{ op: 'opcode', code: 'OP_NUMEQUAL' }] }]);
    });

    it('leaves a bare OP_NOT pair at the head of a branch alone (C17)', () => {
      // The negated value arrives from outside the branch, so the window
      // cannot prove it is a canonical boolean — the pair must survive.
      const ops: StackOp[] = [
        {
          op: 'if',
          then: [
            { op: 'opcode', code: 'OP_NOT' },
            { op: 'opcode', code: 'OP_NOT' },
          ],
        },
      ];
      expect(optimizeStackIR(ops)).toEqual(ops);
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
      // else-branch: OP_EQUAL OP_NOT OP_NOT → OP_EQUAL
      const ops: StackOp[] = [
        {
          op: 'if',
          then: [
            { op: 'swap' },
            { op: 'swap' },
          ],
          else: [
            { op: 'opcode', code: 'OP_EQUAL' },
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
          else: [{ op: 'opcode', code: 'OP_EQUAL' }],
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
  //
  // F-353 (resolved 2026-10) established that opcode-string push+ROLL/PICK
  // at the depths the typed rules cover (0/1/2 for ROLL, 0/1 for PICK) does
  // not occur on any live TS codegen path, and is behaviourally identical to
  // the typed form when it is constructed synthetically (see
  // 'string-form Roll/Pick execution equivalence' below). F-353 left the
  // peephole rules typed-only on that basis ("generalizing would be
  // speculative code for zero benefit").
  //
  // F-392 revisits that call: the generalization is not speculative, it is
  // a real cross-tier inconsistency. `compilers/python/.../optimizer.py` and
  // `compilers/ruby/.../optimizer.rb` already match EITHER the typed node OR
  // the opcode-string form for all five rules (explicitly commented "typed
  // or string-form"); `compilers/go`, `compilers/rust`, and
  // `compilers/java` match only the typed form, the same gap this file had.
  // Since the pattern is proven byte-neutral (zero live occurrences in any
  // tier's codegen, confirmed empirically via the full conformance corpus in
  // both constant-folding modes, plus the whole `packages/runar-compiler`
  // unit-test corpus), there is no reason for TS/Go/Rust/Java to special-case
  // fewer representations of the same stack effect than Python/Ruby already
  // do -- so this file, and the Go/Rust/Java peepholes, now match both forms
  // too, using Python/Ruby's predicate.
  //
  // `compilers/zig` is excluded: its unified instruction stream cannot
  // distinguish a typed depth-1/depth-2 roll from an untyped post-if
  // reconciliation roll (`push d + roll(depth=d+1) + drop`), so folding
  // PUSH(1)/PUSH(2) + ROLL there risks a miscompile, not just a missed
  // optimization (see `compilers/zig/src/passes/peephole.zig` Rule 18/19
  // comment). That is a pre-existing, independently-documented divergence,
  // not something this item changes.
  // -----------------------------------------------------------------------

  describe('opcode-string Roll/Pick forms (F-392: now optimized, same as typed form)', () => {
    it('optimizes PUSH(0) + opcode OP_ROLL the same as typed roll{0}', () => {
      const typedOps: StackOp[] = [{ op: 'push', value: 0n }, { op: 'roll', depth: 0 }];
      expect(optimizeStackIR(typedOps)).toEqual([]);

      const stringOps: StackOp[] = [{ op: 'push', value: 0n }, { op: 'opcode', code: 'OP_ROLL' }];
      expect(optimizeStackIR(stringOps)).toEqual([]);
    });

    it('optimizes PUSH(1) + opcode OP_ROLL the same as typed roll{1} (-> swap)', () => {
      const typedOps: StackOp[] = [{ op: 'push', value: 1n }, { op: 'roll', depth: 1 }];
      expect(optimizeStackIR(typedOps)).toEqual([{ op: 'swap' }]);

      const stringOps: StackOp[] = [{ op: 'push', value: 1n }, { op: 'opcode', code: 'OP_ROLL' }];
      expect(optimizeStackIR(stringOps)).toEqual([{ op: 'swap' }]);
    });

    it('optimizes PUSH(2) + opcode OP_ROLL the same as typed roll{2} (-> rot)', () => {
      const typedOps: StackOp[] = [{ op: 'push', value: 2n }, { op: 'roll', depth: 2 }];
      expect(optimizeStackIR(typedOps)).toEqual([{ op: 'rot' }]);

      const stringOps: StackOp[] = [{ op: 'push', value: 2n }, { op: 'opcode', code: 'OP_ROLL' }];
      expect(optimizeStackIR(stringOps)).toEqual([{ op: 'rot' }]);
    });

    it('optimizes PUSH(0) + opcode OP_PICK the same as typed pick{0} (-> dup)', () => {
      const typedOps: StackOp[] = [{ op: 'push', value: 0n }, { op: 'pick', depth: 0 }];
      expect(optimizeStackIR(typedOps)).toEqual([{ op: 'dup' }]);

      const stringOps: StackOp[] = [{ op: 'push', value: 0n }, { op: 'opcode', code: 'OP_PICK' }];
      expect(optimizeStackIR(stringOps)).toEqual([{ op: 'dup' }]);
    });

    it('optimizes PUSH(1) + opcode OP_PICK the same as typed pick{1} (-> over)', () => {
      const typedOps: StackOp[] = [{ op: 'push', value: 1n }, { op: 'pick', depth: 1 }];
      expect(optimizeStackIR(typedOps)).toEqual([{ op: 'over' }]);

      const stringOps: StackOp[] = [{ op: 'push', value: 1n }, { op: 'opcode', code: 'OP_PICK' }];
      expect(optimizeStackIR(stringOps)).toEqual([{ op: 'over' }]);
    });

    // Depths the typed rules do NOT cover (2 for PICK, 3 for ROLL -- the
    // depths wots-codegen.ts and the pow() loop actually use) still pass
    // through unreduced in both forms: this item only teaches the rules
    // that already exist a second input representation, it does not add
    // new depths.
    it('does NOT optimize PUSH(2) + opcode OP_PICK (no typed rule at this depth either)', () => {
      const stringOps: StackOp[] = [{ op: 'push', value: 2n }, { op: 'opcode', code: 'OP_PICK' }];
      expect(optimizeStackIR(stringOps)).toEqual(stringOps);
    });

    it('does NOT optimize PUSH(3) + opcode OP_ROLL (no typed rule at this depth either)', () => {
      const stringOps: StackOp[] = [{ op: 'push', value: 3n }, { op: 'opcode', code: 'OP_ROLL' }];
      expect(optimizeStackIR(stringOps)).toEqual(stringOps);
    });
  });

  // -----------------------------------------------------------------------
  // F-353: string-form Roll/Pick execution equivalence
  //
  // The comment above (before this fix) flagged the un-reduced opcode-string
  // Roll/Pick sequences as a "POTENTIAL BUG". These tests settle the actual
  // question -- is the un-reduced form a MISCOMPILE (different runtime
  // behaviour) or merely a missed optimization (same behaviour, more bytes)?
  // -- by running both the un-reduced sequence and its typed-rule equivalent
  // through the real @bsv/sdk Spend engine (via ScriptVM, not the ANF
  // interpreter or TestContract, which share the compiler's own model) and
  // comparing the full final stack. They PASS at HEAD: that is the correct,
  // expected result, and is the proof that closes this item.
  //
  // What this proves: the three un-reduced sequences below execute
  // identically to their typed-rule replacements on the production script
  // interpreter -- OP_0 OP_ROLL is a true no-op, OP_0 OP_PICK behaves like
  // OP_DUP, and OP_2 OP_ROLL behaves like OP_ROT. There is no hidden runtime
  // divergence.
  //
  // What this does NOT prove: that every string-form Roll/Pick depth is
  // behaviourally safe (only the three depths tested are covered; the
  // general claim follows from Bitcoin Script's OP_ROLL/OP_PICK semantics,
  // not from exhaustive testing). The tests below feed the un-reduced ops
  // straight to `emitMethod`, bypassing `optimizeStackIR`, so they are
  // unaffected by F-392's peephole change (see the describe block above,
  // which now DOES reduce these forms) -- they remain a direct check that
  // the raw opcode-string bytes execute correctly regardless of whether the
  // optimizer ever sees them.
  // -----------------------------------------------------------------------

  describe('string-form Roll/Pick execution equivalence (F-353)', () => {
    function emitOps(ops: StackOp[]): string {
      return emitMethod({ name: 'f353', ops, maxStackDepth: 0 }).scriptHex;
    }
    function runEffect(ops: StackOp[]): { success: boolean; stack: string[] } {
      const r = new ScriptVM().executeHex(emitOps(ops));
      return { success: r.success, stack: r.stack.map(bytesToHex) };
    }

    it('PUSH(0) + opcode OP_ROLL executes identically to a true no-op (typed roll{0})', () => {
      const witness: StackOp[] = [{ op: 'push', value: 11n }, { op: 'push', value: 22n }];
      const unreduced = runEffect([...witness, { op: 'push', value: 0n }, { op: 'opcode', code: 'OP_ROLL' }]);
      const noop = runEffect(witness);
      expect(unreduced).toEqual(noop);
    });

    it('PUSH(0) + opcode OP_PICK executes identically to OP_DUP (typed pick{0})', () => {
      const witness: StackOp[] = [{ op: 'push', value: 11n }, { op: 'push', value: 22n }];
      const unreduced = runEffect([...witness, { op: 'push', value: 0n }, { op: 'opcode', code: 'OP_PICK' }]);
      const dup = runEffect([...witness, { op: 'dup' }]);
      expect(unreduced).toEqual(dup);
    });

    it('PUSH(2) + opcode OP_ROLL executes identically to OP_ROT (typed roll{2}) -- covers the dead emitCheckPreimageBindingLegacy shape, unreachable from compile() but still checked for safety', () => {
      const witness: StackOp[] = [
        { op: 'push', value: 11n },
        { op: 'push', value: 22n },
        { op: 'push', value: 33n },
      ];
      const unreduced = runEffect([...witness, { op: 'push', value: 2n }, { op: 'opcode', code: 'OP_ROLL' }]);
      const rotated = runEffect([...witness, { op: 'rot' }]);
      expect(unreduced).toEqual(rotated);
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
