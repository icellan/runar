/**
 * F-259 — an unrolled loop body's opcodes map to the body statement's line,
 * not to the `for` line.
 *
 * Before the fix `lowerLoop` lowered every body binding with `lowerBinding`
 * directly, never updating `currentSourceLoc`, so every opcode the body
 * emitted inherited the enclosing loop binding's location: in BoundedLoop all
 * 39 loop ops (5 iterations of `sum = sum + start + i`) were mapped to
 * `for (let i ...)`. If-branch bindings already got per-binding locations
 * (through `lowerBindings`); loop-body bindings did not.
 *
 * Convention (same in all 7 tiers): each body binding's own location is used
 * while it lowers; a body binding without one keeps the loop's location. The
 * per-iteration iteration-variable push and its cleanup belong to the loop
 * itself and stay on the `for` line.
 *
 * What this proves: end to end, on examples/ts/bounded-loop, every body op of
 * every unrolled iteration is mapped to the body line and column, and only the
 * five iteration-variable pushes (OP_0..OP_4) are mapped to the `for` line.
 *
 * What this does not prove: anything about the other six tiers (each has its
 * own test), nested loops, or body bindings the ANF lowerer leaves without a
 * location. It equates asm token index with opcodeIndex, which holds only for
 * a script with no raw_bytes span — true for BoundedLoop.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile } from '../index.js';

describe('F-259: loop-body ops map to the body statement', () => {
  it('BoundedLoop: body ops -> body line, iteration-variable pushes -> for line', () => {
    const fileName = 'examples/ts/bounded-loop/BoundedLoop.runar.ts';
    const source = readFileSync(resolve(__dirname, '../../../../', fileName), 'utf8');
    const result = compile(source, { fileName, disableConstantFolding: true });
    expect(result.success).toBe(true);

    const lines = source.split('\n');
    const forLine = lines.findIndex(l => l.includes('for (let i')) + 1;
    const bodyLine = lines.findIndex(l => l.includes('sum = sum + start + i')) + 1;
    const forColumn = lines[forLine - 1]!.indexOf('for');
    const bodyColumn = lines[bodyLine - 1]!.indexOf('sum');

    const asm = result.artifact!.asm.split(' ');
    // Five unrolled iterations of 8 ops each, starting at opcode 1 (opcode 0
    // is `let sum = 0n`); each starts with the push of the iteration value.
    const iterPushes = [1, 9, 17, 25, 33];
    expect(iterPushes.map(i => asm[i])).toEqual(['OP_0', 'OP_1', 'OP_2', 'OP_3', 'OP_4']);

    const mappings = result.artifact!.sourceMap!.mappings;
    const loopOps = mappings.filter(m => m.opcodeIndex >= 1 && m.opcodeIndex <= 39);
    expect(loopOps).toHaveLength(39);
    for (const m of loopOps) {
      const expected = iterPushes.includes(m.opcodeIndex)
        ? { line: forLine, column: forColumn }
        : { line: bodyLine, column: bodyColumn };
      expect({ opcodeIndex: m.opcodeIndex, line: m.line, column: m.column }).toEqual({
        opcodeIndex: m.opcodeIndex,
        ...expected,
      });
    }
  });
});
