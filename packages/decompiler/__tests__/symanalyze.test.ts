/**
 * S2 — symbolic region analyzer. Scans the previously-unrecognized 538..1035
 * region of the FTK script and recovers *meaning* (not code): little-endian
 * integer decodes and CompactSize varint reads, confirmed via symExec.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { hexToBytes } from 'runar-testing';
import { disassemble } from '../src/disasm.js';
import { analyzeRegion, detectRepeats, classifyFields } from '../src/symanalyze.js';

const ftkHex = readFileSync(
  new URL('./fixtures/ftk-demo.hex', import.meta.url),
  'utf8',
).trim();
const ops = disassemble(hexToBytes(ftkHex));

describe('analyzeRegion — the 538..1035 varint region', () => {
  const start = ops.findIndex((o) => o.offset === 538);
  const end = ops.findIndex((o) => o.offset === 1035);
  const a = analyzeRegion(ops, start, end);

  it('finds both little-endian decodes and CompactSize varint reads', () => {
    expect(a.findings.length).toBeGreaterThan(0);
    const kinds = new Set(a.findings.map((f) => f.kind));
    expect(kinds.has('le_int_decode')).toBe(true);
    expect(kinds.has('varint_read')).toBe(true);
  });

  it('summarizes what the region does', () => {
    expect(a.summary.toLowerCase()).toContain('varint');
    expect(a.summary.toLowerCase()).toContain('integer');
  });

  it('reports byte offsets within the region', () => {
    for (const f of a.findings) {
      expect(f.offset).toBeGreaterThanOrEqual(538);
      expect(f.offset).toBeLessThan(1035);
    }
  });
});

describe('detectRepeats — unrolled loops', () => {
  const start = ops.findIndex((o) => o.offset === 538);
  const end = ops.findIndex((o) => o.offset === 1035);
  const repeats = detectRepeats(ops, start, end);

  it('finds the 5x unrolled block (12-op body)', () => {
    const five = repeats.find((r) => r.repeats === 5);
    expect(five).toBeDefined();
    expect(five!.period).toBe(12);
  });

  it('every detected loop is a real tandem repeat', () => {
    for (const r of repeats) {
      expect(r.repeats).toBeGreaterThanOrEqual(2);
      expect(r.period).toBeGreaterThanOrEqual(4);
      expect(r.endOffset).toBeGreaterThan(r.startOffset);
    }
  });

  it('analyzeRegion summary mentions the unrolled loop(s)', () => {
    const an = analyzeRegion(ops, start, end);
    expect(an.summary.toLowerCase()).toContain('unrolled');
    expect(an.loops.length).toBeGreaterThan(0);
  });
});

describe('classifyFields — value roles by field width', () => {
  const start = ops.findIndex((o) => o.offset === 538);
  const end = ops.findIndex((o) => o.offset === 1035);

  it('finds 8-byte amount reads (OP_8 OP_SPLIT)', () => {
    const f = classifyFields(ops, start, end);
    expect(f.amount8).toBeGreaterThan(0);
  });

  it('summary names the recovered value roles', () => {
    const an = analyzeRegion(ops, start, end);
    expect(an.summary).toContain('8-byte amount');
    // existing structural facts remain in the summary
    expect(an.summary.toLowerCase()).toContain('varint');
    expect(an.summary.toLowerCase()).toContain('integer');
  });
});
