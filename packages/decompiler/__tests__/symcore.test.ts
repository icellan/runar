/**
 * S1 — symbolic stack VM foundation.
 *
 * symExec walks an op slice maintaining a stack of provenance-tracked
 * SymValues (no codegen, no byte output — analysis only). describe() renders a
 * value readably. Tested on the real FTK CompactSize-varint discriminant
 * (offset 538..549): read the first byte, compare it to 0xfd.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { hexToBytes } from 'runar-testing';
import { disassemble } from '../src/disasm.js';
import { symExec, describeSym, simplify } from '../src/symcore.js';

const ftkHex = readFileSync(
  new URL('./fixtures/ftk-demo.hex', import.meta.url),
  'utf8',
).trim();
const ops = disassemble(hexToBytes(ftkHex));

describe('symExec — varint discriminant slice', () => {
  const start = ops.findIndex((o) => o.offset === 538); // OP_1
  const end = ops.findIndex((o) => o.offset === 549); // OP_IF (exclusive)
  const slice = ops.slice(start, end);
  const state = symExec(slice, { initialStack: ['in0'] });

  it('models every opcode in the straight-line slice', () => {
    expect(state.modeled).toBe(true);
  });

  it('leaves [lo, hi, comparison] on the stack', () => {
    expect(state.stack.length).toBe(3);
    const top = state.stack[state.stack.length - 1]!;
    expect(top.t).toBe('binop');
  });

  it('the comparison traces the first byte of the input against 0xfd', () => {
    const top = describeSym(state.stack[state.stack.length - 1]!);
    expect(top).toContain('in0');
    expect(top.toLowerCase()).toContain('num(');
    expect(top).toContain('fd00');
  });
});

describe('symExec — control flow (IF/ELSE phi-merge)', () => {
  // 538..554 covers ...GREATERTHAN IF 4 ELSE 2 ENDIF — the CompactSize width select.
  const start = ops.findIndex((o) => o.offset === 538);
  const end = ops.findIndex((o) => o.offset === 554); // OP_SPLIT (exclusive)
  const state = symExec(ops.slice(start, end), { initialStack: ['in0'] });

  it('models the balanced IF/ELSE branch', () => {
    expect(state.modeled).toBe(true);
  });

  it('merges the two branches into a select() with constants 4 and 2', () => {
    const top = state.stack[state.stack.length - 1]!;
    expect(top.t).toBe('select');
    if (top.t === 'select') {
      expect(top.whenTrue).toEqual({ t: 'const', hex: '04' });
      expect(top.whenFalse).toEqual({ t: 'const', hex: '02' });
      expect(top.cond.t).toBe('binop');
    }
  });
});

describe('simplify — byte-reversal idiom (S2)', () => {
  // The sCrypt reverse: split a value into single bytes and cat them back in
  // descending offset order. simplify() must collapse that to reverse(v).
  // Reverse a 4-byte SHA256-tail stand-in built from a known-length base.
  const start = ops.findIndex((o) => o.offset === 26); // OP_DUP (start of the hash reverse)
  const end = ops.findIndex((o) => o.offset === 198); // OP_IF (exclusive)
  const state = symExec(ops.slice(start, end), { initialStack: ['preimage'] });

  it('models the whole reverse block', () => {
    expect(state.modeled).toBe(true);
  });

  it('collapses the split/cat shuffle of hash256(preimage) into reverse(...)', () => {
    const top = simplify(state.stack[state.stack.length - 1]!);
    const s = describeSym(top);
    expect(s).toContain('reverse(');
    expect(s).toContain('OP_HASH256(preimage)');
    // the raw nested-split form is gone
    expect(s).not.toContain('[0x10..][0x0f..]');
  });
});
