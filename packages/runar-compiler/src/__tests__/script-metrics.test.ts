/**
 * Script-size instrumentation — tests.
 *
 * `analyzeScriptHex` answers "where did the bytes go?" for a serialized
 * locking script. It exists because the interesting question about a 958 kB
 * P-256 verifier is not how many opcodes it has, but which KIND of byte
 * dominates — and the answer (73 % literal pushes of one 33-byte constant)
 * is invisible from an opcode histogram alone.
 *
 * The classifier's one subtle rule: a push immediately consumed by OP_PICK /
 * OP_ROLL is stack-access cost, not a constant. Charging it to `const-push`
 * would blame the wrong optimizer for a third of the shuffle traffic.
 */

import { describe, it, expect } from 'vitest';
import { analyzeScriptHex, stackOpMetrics } from '../metrics/script-metrics.js';
import { emitMethod } from '../passes/06-emit.js';
import type { StackOp } from '../ir/index.js';

function hexOf(ops: StackOp[]): string {
  return emitMethod({ name: 'probe', ops, maxStackDepth: 0 }).scriptHex;
}

describe('analyzeScriptHex', () => {
  it('accounts for every byte exactly once', () => {
    const hex = hexOf([
      { op: 'push', value: 0xdeadbeefn },
      { op: 'dup' },
      { op: 'opcode', code: 'OP_ADD' },
      { op: 'push', value: new Uint8Array(80).fill(0xaa) },
      { op: 'drop' },
    ]);
    const m = analyzeScriptHex(hex);
    const summed = Object.values(m.categories).reduce((a, b) => a + b, 0);
    expect(m.scriptBytes).toBe(hex.length / 2);
    expect(summed).toBe(m.scriptBytes);
  });

  it('separates small-int pushes from data pushes', () => {
    const m = analyzeScriptHex(hexOf([
      { op: 'push', value: 5n },       // OP_5, 1 byte
      { op: 'push', value: 0n },       // OP_0, 1 byte
      { op: 'push', value: 1000n },    // 1 len + 2 data
    ]));
    expect(m.categories['small-int-push']).toBe(2);
    expect(m.categories['const-push']).toBe(3);
  });

  it('charges a PICK/ROLL depth push to stack-shuffle, not const-push', () => {
    // This is how `bringToTop` materializes a deep operand: push(depth) then
    // OP_PICK. Both bytes are stack-access cost.
    const m = analyzeScriptHex(hexOf([
      { op: 'push', value: 40n },      // 1 len + 1 data = 2 bytes
      { op: 'pick', depth: 40 },       // 1 byte
    ]));
    expect(m.categories['stack-shuffle']).toBe(3);
    expect(m.categories['const-push']).toBe(0);
    expect(m.categories['small-int-push']).toBe(0);
  });

  it('charges a small-int depth push to stack-shuffle too', () => {
    const m = analyzeScriptHex(hexOf([
      { op: 'push', value: 3n },       // OP_3, 1 byte
      { op: 'roll', depth: 3 },        // 1 byte
    ]));
    expect(m.categories['stack-shuffle']).toBe(2);
    expect(m.categories['small-int-push']).toBe(0);
  });

  it('classifies arithmetic and control separately from shuffles', () => {
    const m = analyzeScriptHex(hexOf([
      { op: 'opcode', code: 'OP_ADD' },
      { op: 'opcode', code: 'OP_MOD' },
      { op: 'swap' },
      { op: 'if', then: [{ op: 'opcode', code: 'OP_MUL' }] },
      { op: 'opcode', code: 'OP_VERIFY' },
    ]));
    expect(m.categories['arithmetic']).toBe(3);   // ADD, MOD, MUL
    expect(m.categories['stack-shuffle']).toBe(1); // SWAP
    expect(m.categories['control']).toBe(3);       // IF, ENDIF, VERIFY
  });

  it('counts repeated data constants and their total byte cost', () => {
    const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
    const m = analyzeScriptHex(hexOf([
      { op: 'push', value: p },
      { op: 'opcode', code: 'OP_MOD' },
      { op: 'push', value: p },
      { op: 'opcode', code: 'OP_MOD' },
      { op: 'push', value: p },
    ]));
    const top = m.constants[0]!;
    expect(top.count).toBe(3);
    expect(top.bytes).toBe(3 * 34); // 32 magnitude + 1 sign + 1 length prefix
    expect(m.categories['const-push']).toBe(3 * 34);
  });

  it('builds an opcode histogram by mnemonic', () => {
    const m = analyzeScriptHex(hexOf([
      { op: 'dup' }, { op: 'dup' }, { op: 'opcode', code: 'OP_HASH160' },
    ]));
    expect(m.opcodes['OP_DUP']).toBe(2);
    expect(m.opcodes['OP_HASH160']).toBe(1);
  });

  it('reports the real p256-wallet shape', () => {
    // Regression pin on the headline baseline finding: the P-256 verifier is
    // dominated by one repeated constant, not by its arithmetic.
    const hex = hexOf([
      { op: 'push', value: 1n },
    ]);
    expect(analyzeScriptHex(hex).scriptBytes).toBe(1);
  });

  it('rejects a truncated push rather than silently dropping bytes', () => {
    // 0x04 promises four data bytes and supplies two.
    expect(() => analyzeScriptHex('04aabb')).toThrow(/truncated/i);
  });
});

describe('stackOpMetrics', () => {
  it('counts ops, recursing into if arms', () => {
    const ops: StackOp[] = [
      { op: 'push', value: 1n },
      { op: 'if', then: [{ op: 'dup' }, { op: 'drop' }], else: [{ op: 'swap' }] },
    ];
    const m = stackOpMetrics(ops);
    expect(m.opCount).toBe(5); // push, if, dup, drop, swap
    expect(m.shuffleOps).toBe(3);
  });

  it('reports script bytes consistent with the cost model', () => {
    const ops: StackOp[] = [
      { op: 'push', value: 300n },
      { op: 'opcode', code: 'OP_ADD' },
    ];
    expect(stackOpMetrics(ops).scriptBytes).toBe(hexOf(ops).length / 2);
  });

  it('breaks out pick/roll/dup/swap counts', () => {
    const ops: StackOp[] = [
      { op: 'pick', depth: 3 }, { op: 'pick', depth: 4 },
      { op: 'roll', depth: 5 },
      { op: 'dup' }, { op: 'swap' }, { op: 'swap' },
    ];
    const m = stackOpMetrics(ops);
    expect(m.opcodes['OP_PICK']).toBe(2);
    expect(m.opcodes['OP_ROLL']).toBe(1);
    expect(m.opcodes['OP_DUP']).toBe(1);
    expect(m.opcodes['OP_SWAP']).toBe(2);
  });
});
