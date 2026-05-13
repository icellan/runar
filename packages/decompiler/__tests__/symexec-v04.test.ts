/**
 * Symbolic-stack lifter v0.4 — control flow + new opcode families.
 *
 * Each test exercises one new feature and (when it round-trips end-to-end)
 * asserts the full decompile pipeline picks the `symexec` recovery path
 * and the recovered source re-compiles to byte-identical hex. Cases that
 * the lifter explicitly defers to raw_script (OP_SPLIT, OP_CHECKMULTISIG
 * after surface-compiler stack juggling) are also covered to lock in the
 * "no crash" floor.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { hexToBytes } from 'runar-testing';
import { compile } from 'runar-compiler';
import {
  decompile,
  liftStraightLine,
  renderTsSource,
  resetUnhandledOpcodeCounts,
  getUnhandledOpcodeCounts,
  disassemble,
  verifyDecompilationAnf,
  verifyDecompilation,
} from '../src/index.js';

beforeEach(() => { resetUnhandledOpcodeCounts(); });

describe('symexec-lift v0.4 — OP_IF / OP_ELSE / OP_ENDIF', () => {
  it('simple if-then-else with literal branches lifts via symexec and round-trips byte-identically', () => {
    // OP_IF OP_TRUE OP_ELSE OP_FALSE OP_ENDIF
    // Logically: assert(cond ? true : false).
    const hex = '6351670068';
    const bytes = hexToBytes(hex);

    const out = liftStraightLine(disassemble(bytes));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    // One param, type refined to boolean by the OP_IF consumer.
    expect(out.paramTypes).toEqual(['boolean']);

    // The recovered source renders the if as a ternary expression.
    const source = renderTsSource(out);
    expect(source).toContain('_p0 ? true : false');

    // Full pipeline takes the symexec path and the source recompiles
    // byte-identically.
    const dec = decompile(bytes);
    expect(dec.recoveryPath).toBe('symexec');
    expect(dec.ok).toBe(true);
    const recompiled = compile(dec.source, { fileName: '_Recovered.runar.ts' });
    expect(recompiled.success).toBe(true);
    expect(recompiled.scriptHex).toBe(hex);
  });

  it('if-then-else with comparison branches over a shared param lifts and round-trips', () => {
    // Compiles from:
    //   if (a > 0n) { assert(b > 0n); } else { assert(b < 0n); }
    // → OP_SWAP OP_0 OP_GREATERTHAN OP_IF OP_0 OP_GREATERTHAN OP_ELSE OP_0 OP_LESSTHAN OP_ENDIF
    const hex = '7c00a06300a067009f68';
    const bytes = hexToBytes(hex);

    const out = liftStraightLine(disassemble(bytes));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.paramTypes).toEqual(['bigint', 'bigint']);

    const source = renderTsSource(out);
    // Sanity: source uses a ternary over two `>` / `<` comparisons.
    expect(source).toContain('> 0n');
    expect(source).toContain('< 0n');

    const dec = decompile(bytes);
    expect(dec.recoveryPath).toBe('symexec');
    expect(dec.ok).toBe(true);
    const recompiled = compile(dec.source, { fileName: '_Recovered.runar.ts' });
    expect(recompiled.success).toBe(true);
    expect(recompiled.scriptHex).toBe(hex);

    // Both verification paths agree.
    expect(verifyDecompilationAnf(bytes, out.program).ok).toBe(true);
    expect(verifyDecompilation(bytes, source).ok).toBe(true);
  });

  it('nested if-in-then lifts via symexec and round-trips byte-identically', () => {
    // Compiles from:
    //   public unlock(a: boolean, b: boolean) {
    //     assert(a ? (b ? true : false) : false);
    //   }
    // The Rúnar emitter produces OP_SWAP then the nested OP_IFs with an
    // OP_NIP in the outer-ELSE branch to balance the stack.
    const hex = '7c63635167006867007768';
    const bytes = hexToBytes(hex);

    const out = liftStraightLine(disassemble(bytes));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.paramTypes).toEqual(['boolean', 'boolean']);

    const dec = decompile(bytes);
    expect(dec.recoveryPath).toBe('symexec');
    expect(dec.ok).toBe(true);
    const recompiled = compile(dec.source, { fileName: '_Recovered.runar.ts' });
    expect(recompiled.success).toBe(true);
    expect(recompiled.scriptHex).toBe(hex);
  });

  it('OP_IF nesting deeper than MAX_IF_NESTING (16) aborts cleanly to raw_script', () => {
    // Build 17 levels of OP_IF / OP_ENDIF — one level over the bumped
    // MAX_IF_NESTING budget. The lifter must refuse, the pipeline must
    // not throw, and the recovery path must NOT be symexec.
    const N = 17;
    let nested = '63'.repeat(N) + '51'; // N OP_IFs then OP_TRUE in deepest body
    nested += '68'.repeat(N); // N OP_ENDIFs
    const bytes = hexToBytes(nested);
    expect(() => decompile(bytes)).not.toThrow();
    const dec = decompile(bytes);
    expect(dec.recoveryPath).not.toBe('symexec');
  });
});

describe('symexec-lift v0.4 — long pushes (OP_PUSHDATA1)', () => {
  it('80-byte ByteString push via OP_PUSHDATA1 followed by OP_EQUAL lifts and round-trips', () => {
    // 80-byte payload forces OP_PUSHDATA1 (76..255 → 0x4c length-prefixed).
    const payload = '11'.repeat(80);
    const hex = '4c50' + payload + '87'; // OP_PUSHDATA1 0x50 <80 bytes> OP_EQUAL
    const bytes = hexToBytes(hex);

    const out = liftStraightLine(disassemble(bytes));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.paramTypes).toEqual(['bytes']);

    const dec = decompile(bytes);
    expect(dec.recoveryPath).toBe('symexec');
    expect(dec.ok).toBe(true);
    const recompiled = compile(dec.source, { fileName: '_Recovered.runar.ts' });
    expect(recompiled.success).toBe(true);
    expect(recompiled.scriptHex).toBe(hex);
  });
});

describe('symexec-lift v0.4 — OP_CAT', () => {
  it('OP_CAT OP_HASH256 <32-byte> OP_EQUAL lifts to assert(hash256(cat(...)) === ...) and round-trips', () => {
    // Synthetic shape: two ByteString params, concatenate, hash256, compare
    // to a 32-byte literal.
    const literal = 'aa'.repeat(32);
    const hex = '7eaa20' + literal + '87';
    const bytes = hexToBytes(hex);

    const out = liftStraightLine(disassemble(bytes));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.paramTypes).toEqual(['bytes', 'bytes']);

    const source = renderTsSource(out);
    expect(source).toContain('cat(_p0, _p1)');
    expect(source).toContain('hash256(');

    const dec = decompile(bytes);
    expect(dec.recoveryPath).toBe('symexec');
    expect(dec.ok).toBe(true);
    const recompiled = compile(dec.source, { fileName: '_Recovered.runar.ts' });
    expect(recompiled.success).toBe(true);
    expect(recompiled.scriptHex).toBe(hex);
  });
});

describe('symexec-lift v0.4 — OP_CHECKMULTISIG (2-of-3 hand-rolled)', () => {
  it('lifter recognizes the canonical hand-rolled multisig shape but the surface compiler reorders the stack', () => {
    // Hand-rolled 2-of-3:
    //   stack at entry (phantom params, bottom→top): dummy, sig1, sig2
    //   script:  OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
    //
    // The lifter detects the OP_CHECKMULTISIG pattern and emits a clean
    // `checkMultiSig([sig1, sig2], [pk1, pk2, pk3])` ANF binding. The TS
    // source compiles, but the surface compiler emits this same logical
    // call as `<pk1> <pk2> <pk3> OP_ROT OP_ROT OP_ROT OP_0 OP_ROT OP_2 OP_3
    // OP_ROLL OP_3 OP_CHECKMULTISIG` because it routes everything through
    // its standard stack-juggling-for-args. Result: lift succeeds, source
    // verification diverges, pipeline falls through to raw_script — never
    // crashes, never produces wrong source.
    const pk = (b: string) => '02' + b.repeat(32);
    const hex = '52' + '21' + pk('aa') + '21' + pk('bb') + '21' + pk('cc') + '53' + 'ae';
    const bytes = hexToBytes(hex);

    // Lifter alone succeeds and produces a checkMultiSig call binding.
    const out = liftStraightLine(disassemble(bytes));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    const callBinding = out.program.methods[0]!.body.find(b => b.value.kind === 'call');
    expect(callBinding).toBeDefined();
    if (callBinding && callBinding.value.kind === 'call') {
      expect(callBinding.value.func).toBe('checkMultiSig');
      expect(callBinding.value.args).toHaveLength(2);
    }

    // Full pipeline: ANF round-trip diverges (surface compiler reorders),
    // so the recovery layer falls through to raw_script per spec. No
    // throw, no wrong output.
    expect(() => decompile(bytes)).not.toThrow();
    const dec = decompile(bytes);
    expect(dec.ok).toBe(true);
    expect(dec.recoveryPath).not.toBe('symexec');
  });
});

describe('symexec-lift v0.4 — OP_SPLIT clean fallback', () => {
  it('OP_SPLIT aborts to raw_script (multi-return not modeled)', () => {
    const hex = '7f'; // OP_SPLIT alone
    const bytes = hexToBytes(hex);
    const out = liftStraightLine(disassemble(bytes));
    expect(out.ok).toBe(false);
    if (out.ok) return;
    expect(out.unhandled).toBe('OP_SPLIT');
    expect(getUnhandledOpcodeCounts().get('OP_SPLIT')).toBe(1);
  });
});
