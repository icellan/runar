/**
 * General (semantic) lifter — milestone 1.
 *
 * Invariant 1 (tiling): the segment list returned by `generalLift`, rendered
 * as a *shadow* ANFProgram where every segment is a `raw_script` island of its
 * ORIGINAL bytes, must recompile byte-identical to the input. This holds for
 * any byte stream — Rúnar-produced or foreign — and proves the decomposition
 * is sound independent of how much was structurally lifted.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { hexToBytes } from 'runar-testing';
import { disassemble } from '../src/disasm.js';
import { generalLift, buildShadowProgram, segmentByBoundaries } from '../src/general-lift.js';
import { verifyDecompilationAnf } from '../src/verify.js';

const ftkHex = readFileSync(
  new URL('./fixtures/ftk-demo.hex', import.meta.url),
  'utf8',
).trim();

describe('generalLift — tiling invariant (Invariant 1)', () => {
  it('FTK script: shadow ANF (all original-byte islands) recompiles byte-identical', () => {
    const bytes = hexToBytes(ftkHex);
    const result = generalLift(disassemble(bytes));
    const shadow = buildShadowProgram(bytes, result.segments);
    const verdict = verifyDecompilationAnf(bytes, shadow);
    expect(verdict.ok).toBe(true);
  });

  it('segments exactly tile the input — contiguous, no gap, no overlap', () => {
    const bytes = hexToBytes('76a914' + '00'.repeat(20) + '88ac');
    const result = generalLift(disassemble(bytes));
    let cursor = 0;
    for (const seg of result.segments) {
      expect(seg.span[0]).toBe(cursor);
      cursor = seg.span[1];
    }
    expect(cursor).toBe(bytes.length);
  });
});

describe('generalLift — idiom-driven segmentation (I3)', () => {
  it('labels recognized idiom spans, in order, and still tiles byte-identical', () => {
    const bytes = hexToBytes(ftkHex);
    const result = generalLift(disassemble(bytes));
    const labels = result.segments.map((s) => (s.kind === 'asm' ? s.idiom : undefined) ?? '(asm)');
    expect(labels).toContain('p2pkh_sig_gate');
    expect(labels).toContain('op_push_tx');
    expect(labels).toContain('op_return_state');
    expect(labels[0]).toBe('p2pkh_sig_gate');
    expect(labels[labels.length - 1]).toBe('op_return_state');
    expect(verifyDecompilationAnf(bytes, buildShadowProgram(bytes, result.segments)).ok).toBe(true);
  });

  it('recognizes the full milestone-1 idiom set and tiles byte-identical', () => {
    const bytes = hexToBytes(ftkHex);
    const result = generalLift(disassemble(bytes));
    const idioms = new Set(
      result.segments.flatMap((s) => (s.kind === 'asm' && s.idiom ? [s.idiom] : [])),
    );
    for (const expected of [
      'p2pkh_sig_gate',
      'op_push_tx',
      'preimage_extract',
      'build_p2pkh_output',
      'outputs_enforce',
      'op_return_state',
    ]) {
      expect(idioms.has(expected)).toBe(true);
    }
    // more than half of the spans are now recognized
    const recognized = result.segments.filter((s) => s.kind === 'asm' && s.idiom).length;
    expect(recognized).toBeGreaterThanOrEqual(13);
    // tiling still holds with the finer segmentation
    expect(verifyDecompilationAnf(bytes, buildShadowProgram(bytes, result.segments)).ok).toBe(true);
  });

  it('attaches symbolic analysis to the unrecognized varint region (538..1035)', () => {
    const bytes = hexToBytes(ftkHex);
    const segs = generalLift(disassemble(bytes)).segments;
    const mid = segs.find((s) => s.kind === 'asm' && !s.idiom && s.span[0] === 538);
    expect(mid).toBeDefined();
    expect(mid!.kind).toBe('asm');
    if (mid!.kind === 'asm') {
      expect(mid!.analysis).toBeDefined();
      expect(mid!.analysis!.toLowerCase()).toContain('varint');
    }
  });
});

describe('segmentByBoundaries — multi-island split (I2)', () => {
  it('FTK split at 3 op-boundaries still recompiles byte-identical', () => {
    const bytes = hexToBytes(ftkHex);
    const ops = disassemble(bytes);
    const segs = segmentByBoundaries(ops, [6, 200, 900]);
    expect(segs.length).toBe(4);
    // contiguous tiling
    let cursor = 0;
    for (const seg of segs) {
      expect(seg.span[0]).toBe(cursor);
      cursor = seg.span[1];
    }
    expect(cursor).toBe(bytes.length);
    // byte-identity preserved across the split
    expect(verifyDecompilationAnf(bytes, buildShadowProgram(bytes, segs)).ok).toBe(true);
  });

  it('honors paramCount as the first island in-arity (initial stack depth)', () => {
    const bytes = hexToBytes(ftkHex);
    const ops = disassemble(bytes);
    const segs = segmentByBoundaries(ops, [6], { paramCount: 3 });
    const first = segs[0]!;
    expect(first.kind).toBe('asm');
    if (first.kind === 'asm') expect(first.inArity).toBe(3);
  });
});
