/**
 * Phase 4 analyzer-side tests for `rawScriptSpans` integration.
 *
 * The static analyzer walks compiled hex byte-by-byte. When `asm({...})`
 * produces opaque byte regions, the analyzer must NOT inspect their
 * contents — the bytes are not guaranteed to form a well-formed opcode
 * stream, and the peephole optimizer treats them as a hard barrier.
 * `analyzeScript(hex, { rawScriptSpans })` collapses each declared span
 * into one synthetic step whose stack effect is `(-inArity, +outArity)`.
 *
 * These tests pin down the contract between the analyzer and the artifact:
 *
 *   1. Same hex, different `rawScriptSpans` → different findings. Proves
 *      the integration is doing real work and isn't a no-op.
 *   2. Pathological bytes inside a span (a bare `OP_IF`, a bare
 *      `OP_CODESEPARATOR`, garbage push prefixes) don't produce false
 *      findings outside the span.
 *   3. Stack depth carries across the span using the declared arities.
 *   4. A `CHECKSIG` byte hidden inside a span does NOT count toward the
 *      path's `hasCheckSig` flag, so `NO_SIG_CHECK` still fires.
 */

import { describe, it, expect } from 'vitest';
import { analyzeScript, collapseRawScriptSpans, parseScript } from '../analyzer/index.js';
import type { RawScriptSpan } from '../analyzer/index.js';

describe('analyzer rawScriptSpans — collapse + stack-effect', () => {
  it('replaces an opaque region with a single synthetic RAW_SPAN step', () => {
    // Three real opcodes worth of bytes inside the span — the collapse must
    // drop them all and emit exactly one synthetic step.
    const hex = '63abac'; // OP_IF, OP_CODESEPARATOR, OP_CHECKSIG
    const opcodes = parseScript(hex);
    expect(opcodes.length).toBe(3);

    const spans: RawScriptSpan[] = [
      { offset: 0, length: 3, inArity: 1, outArity: 1 },
    ];
    const collapsed = collapseRawScriptSpans(opcodes, spans);
    expect(collapsed.length).toBe(1);
    expect(collapsed[0]!.name).toBe('RAW_SPAN');
    expect(collapsed[0]!.size).toBe(3);
    expect(collapsed[0]!.rawSpanArity).toEqual([1, 1]);
  });

  it('produces different findings with vs. without the span (regression guard)', () => {
    // A bare `OP_IF` (0x63) has no matching `OP_ENDIF` — without spans, the
    // analyzer must flag `UNBALANCED_IF_ENDIF`. With a span covering it,
    // the collapse hides the OP_IF and the structural check passes.
    const hex = '63';

    const withoutSpans = analyzeScript(hex);
    expect(withoutSpans.findings.some(f => f.code === 'UNBALANCED_IF_ENDIF')).toBe(true);

    const withSpans = analyzeScript(hex, {
      rawScriptSpans: [{ offset: 0, length: 1, inArity: 0, outArity: 1 }],
    });
    expect(withSpans.findings.some(f => f.code === 'UNBALANCED_IF_ENDIF')).toBe(false);
  });

  it('hides OP_CODESEPARATOR inside a span from the CODESEPARATOR_PRESENT check', () => {
    // OP_CODESEPARATOR (0xab) flags an `info`-severity finding when seen by
    // the opcode-concerns pass. Inside a raw_script span it must not fire.
    const hex = 'abac'; // OP_CODESEPARATOR followed by OP_CHECKSIG
    const withoutSpans = analyzeScript(hex);
    expect(withoutSpans.findings.some(f => f.code === 'CODESEPARATOR_PRESENT')).toBe(true);

    const withSpans = analyzeScript(hex, {
      rawScriptSpans: [{ offset: 0, length: 1, inArity: 0, outArity: 0 }],
    });
    expect(withSpans.findings.some(f => f.code === 'CODESEPARATOR_PRESENT')).toBe(false);
  });

  it('carries declared stack-effect across the span', () => {
    // Without spans: parsing `93` as OP_ADD gives a [2, 1] stack effect →
    //   from depth 0, end depth = -1 (negative because items come from
    //   unlocking script in the analyzer's model).
    // With a span covering it with inArity=3, outArity=2: collapsed step
    //   reduces depth by 1 (-3 + 2). End depth diverges by exactly that
    //   amount, providing a clean before/after assertion.
    const hex = '93'; // OP_ADD
    const withoutSpans = analyzeScript(hex);
    const withSpans = analyzeScript(hex, {
      rawScriptSpans: [{ offset: 0, length: 1, inArity: 3, outArity: 2 }],
    });

    // Both analyses produce a single linear path. The terminal depth values
    // come from `getStackEffect` and reflect the difference between
    // OP_ADD's stack effect and the declared span arity.
    expect(withoutSpans.summary.totalPaths).toBe(1);
    expect(withSpans.summary.totalPaths).toBe(1);

    const realAddDelta = -2 + 1; // pops 2, pushes 1
    const spanDelta = -3 + 2;    // pops 3, pushes 2
    expect(withoutSpans.paths[0]!.stackDepthAtEnd).toBe(realAddDelta);
    expect(withSpans.paths[0]!.stackDepthAtEnd).toBe(spanDelta);
  });

  it('does NOT credit a CHECKSIG inside a span toward hasCheckSig', () => {
    // OP_CHECKSIG (0xac) inside an opaque span must not count — the
    // user-declared raw_script body is opaque, so the analyzer cannot
    // claim signature verification is present without seeing real bytes.
    // (If the contract author wanted the analyzer to credit the check,
    // they should write it outside the asm block.)
    const hex = 'ac';

    const withoutSpans = analyzeScript(hex);
    expect(withoutSpans.paths[0]!.hasCheckSig).toBe(true);

    const withSpans = analyzeScript(hex, {
      rawScriptSpans: [{ offset: 0, length: 1, inArity: 2, outArity: 1 }],
    });
    expect(withSpans.paths[0]!.hasCheckSig).toBe(false);
    expect(withSpans.findings.some(f => f.code === 'NO_SIG_CHECK')).toBe(true);
  });

  it('handles multiple non-overlapping spans correctly', () => {
    // Real opcode, span, real opcode, span, real opcode.
    // Layout (byte offsets): 51 @ 0 (OP_1) | span 1 byte @ 1 | 51 @ 2 (OP_1) | span 2 bytes @ 3 | 51 @ 5
    const hex = '51' + '93' + '51' + 'abac' + '51';
    const opcodes = parseScript(hex);
    // Parser sees one ParsedOpcode per byte in the unrecognized regions —
    // 3 OP_1s + OP_ADD + OP_CODESEPARATOR + OP_CHECKSIG = 6 raw opcodes.
    expect(opcodes.length).toBe(6);

    const spans: RawScriptSpan[] = [
      { offset: 1, length: 1, inArity: 0, outArity: 0 },
      { offset: 3, length: 2, inArity: 0, outArity: 0 },
    ];
    const collapsed = collapseRawScriptSpans(opcodes, spans);
    // 3 real OP_1s + 2 synthetic RAW_SPANs = 5 logical steps.
    expect(collapsed.length).toBe(5);
    // The OP_1 (0x51) maps to the 'OP_1' name through the opN encoding,
    // not to 'PUSH_1'. Confirm the surrounding real opcodes survived.
    expect(collapsed[0]!.name).toBe('OP_1');
    expect(collapsed[4]!.name).toBe('OP_1');
  });

  it('preserves opcodes that sit between spans', () => {
    // Same layout as the previous test but assert the surviving real
    // opcodes by name and offset, not just count.
    const hex = '51' + '93' + '51' + 'abac' + '51';
    const opcodes = parseScript(hex);
    const collapsed = collapseRawScriptSpans(opcodes, [
      { offset: 1, length: 1, inArity: 0, outArity: 0 },
      { offset: 3, length: 2, inArity: 0, outArity: 0 },
    ]);

    expect(collapsed.map(o => ({ name: o.name, offset: o.offset }))).toEqual([
      { name: 'OP_1', offset: 0 },
      { name: 'RAW_SPAN', offset: 1 },
      { name: 'OP_1', offset: 2 },
      { name: 'RAW_SPAN', offset: 3 },
      { name: 'OP_1', offset: 5 },
    ]);
  });

  it('is a no-op when rawScriptSpans is empty or missing', () => {
    const hex = '5152'; // OP_1 OP_2
    const a = analyzeScript(hex);
    const b = analyzeScript(hex, {});
    const c = analyzeScript(hex, { rawScriptSpans: [] });

    // The summaries must agree across all three calls — empty/missing spans
    // never alter the analysis result.
    expect(b.summary).toEqual(a.summary);
    expect(c.summary).toEqual(a.summary);
  });
});
