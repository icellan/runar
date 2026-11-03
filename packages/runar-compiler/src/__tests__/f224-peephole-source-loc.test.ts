/**
 * F-224 — peephole rewrites must keep a source location on the ops they emit.
 *
 * Before the fix every replacement op built by a peephole rule
 * (`OP_EQUAL OP_VERIFY` → `OP_EQUALVERIFY`, the roll/pick depth rules, the
 * constant folds, …) was a fresh literal with no `sourceLoc`, and
 * `optimizeNestedIf` rebuilt each `if` op without one. The emitter clears its
 * pending location after every op, so those opcodes got NO source-map entry:
 * in P2PKH the `OP_EQUALVERIFY` of `assert(hash160(pubKey) === …)` was the one
 * unmapped opcode of that statement.
 *
 * Convention (same as the Python and Rust tiers): a replacement op that has no
 * location of its own inherits the location of the FIRST op of the matched
 * window.
 *
 * What this proves: fused / rewritten ops (including both ops of a 2-op
 * replacement and a rebuilt `if`) carry the head op's location through
 * `optimizeStackIR`, and end to end the P2PKH `OP_EQUALVERIFY` is mapped to
 * the `assert` statement it came from. Ops without any location stay without
 * one (no `sourceLoc: undefined` key is introduced).
 *
 * What this does not prove: the head-vs-tail convention is pinned only by the
 * unit tests (in P2PKH both fused ops come from the same statement). It says
 * nothing about the Go/Zig/Ruby/Java peepholes, nor about the column accuracy
 * of the lowerer's own locations (that is the independent-oracle's job). The
 * end-to-end test equates asm token index with opcodeIndex, which only holds
 * for a script with no raw_bytes span (`<raw N bytes>` is several tokens) —
 * hence P2PKH.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile } from '../index.js';
import { optimizeStackIR } from '../optimizer/peephole.js';
import type { StackOp } from '../ir/index.js';

const A = { file: 'C.runar.ts', line: 10, column: 4 };
const B = { file: 'C.runar.ts', line: 20, column: 8 };

describe('F-224: peephole keeps sourceLoc on rewritten ops', () => {
  it('OP_CHECKSIG(A), OP_VERIFY(B) fuse into OP_CHECKSIGVERIFY carrying A', () => {
    const ops: StackOp[] = [
      { op: 'opcode', code: 'OP_CHECKSIG', sourceLoc: A },
      { op: 'opcode', code: 'OP_VERIFY', sourceLoc: B },
    ];
    expect(optimizeStackIR(ops)).toEqual([
      { op: 'opcode', code: 'OP_CHECKSIGVERIFY', sourceLoc: A },
    ]);
  });

  it('a 2-op replacement (chain fold) gives both ops the head location', () => {
    const ops: StackOp[] = [
      { op: 'push', value: 3n, sourceLoc: A },
      { op: 'opcode', code: 'OP_ADD', sourceLoc: A },
      { op: 'push', value: 4n, sourceLoc: B },
      { op: 'opcode', code: 'OP_ADD', sourceLoc: B },
    ];
    expect(optimizeStackIR(ops)).toEqual([
      { op: 'push', value: 7n, sourceLoc: A },
      { op: 'opcode', code: 'OP_ADD', sourceLoc: A },
    ]);
  });

  it('a rebuilt if op keeps its own location', () => {
    const ops: StackOp[] = [
      {
        op: 'if',
        then: [{ op: 'opcode', code: 'OP_EQUAL', sourceLoc: B }, { op: 'opcode', code: 'OP_VERIFY', sourceLoc: B }],
        sourceLoc: A,
      },
    ];
    const out = optimizeStackIR(ops);
    expect(out[0]!.sourceLoc).toEqual(A);
    expect(out[0]!.op === 'if' && out[0]!.then).toEqual([
      { op: 'opcode', code: 'OP_EQUALVERIFY', sourceLoc: B },
    ]);
  });

  it('ops without a location stay without one', () => {
    const out = optimizeStackIR([
      { op: 'opcode', code: 'OP_EQUAL' },
      { op: 'opcode', code: 'OP_VERIFY' },
    ]);
    expect(out).toHaveLength(1);
    expect('sourceLoc' in out[0]!).toBe(false);
  });

  it('P2PKH: the fused OP_EQUALVERIFY is mapped to its assert statement', () => {
    const fileName = 'examples/ts/p2pkh/P2PKH.runar.ts';
    const source = readFileSync(resolve(__dirname, '../../../../', fileName), 'utf8');
    const result = compile(source, { fileName });
    expect(result.success).toBe(true);
    const asm = result.artifact!.asm.split(' ');
    const idx = asm.indexOf('OP_EQUALVERIFY');
    expect(idx).toBeGreaterThanOrEqual(0);
    const mappings = result.artifact!.sourceMap!.mappings;
    const lineOfAssert = source.split('\n').findIndex(l => l.includes('assert(hash160(pubKey)')) + 1;
    expect(mappings.find(m => m.opcodeIndex === idx)).toMatchObject({
      line: lineOfAssert,
      column: 4,
    });
  });
});
