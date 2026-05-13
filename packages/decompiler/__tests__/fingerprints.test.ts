/**
 * Fingerprint DB regression guard.
 *
 * Loads the checked-in fingerprints.json and asserts:
 *   1. The DB has the expected shape.
 *   2. All 6 in-scope EC primitives are present (ecAdd, ecMul, ecMulGen,
 *      ecOnCurve, ecPointX, ecPointY).
 *   3. The fingerprints are "primitive-only" — they match even when the
 *      primitive is followed by an arbitrary unrelated Rúnar expression
 *      (NOT the ecOnCurve / `>= 0n` wrapper used by the build probes).
 *      This is the property that made the old wrapper-bundled fingerprints
 *      useless on real compiled contracts.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { hexToBytes } from 'runar-testing';
import { loadFingerprints } from '../src/fingerprints.js';
import { disassemble } from '../src/disasm.js';
import { matchFingerprints } from '../src/match.js';

const EXPECTED_NAMES = ['ecAdd', 'ecMul', 'ecMulGen', 'ecOnCurve', 'ecPointX', 'ecPointY'];

describe('fingerprint DB structure', () => {
  it('loads without throwing', () => {
    const db = loadFingerprints();
    expect(db).toBeDefined();
    expect(db.compilerVersion).toBeTypeOf('string');
    expect(Array.isArray(db.entries)).toBe(true);
  });

  it('every entry has the expected shape', () => {
    const db = loadFingerprints();
    for (const e of db.entries) {
      expect(e.name).toBeTypeOf('string');
      expect(e.arity).toBeTypeOf('number');
      expect(e.length).toBeGreaterThan(0);
      expect(typeof e.normalizedHex).toBe('string');
      expect(e.normalizedHex).toMatch(/^[0-9a-f]*$/);
      expect(typeof e.hash).toBe('string');
    }
  });

  it('all 6 in-scope EC primitives are present', () => {
    const db = loadFingerprints();
    const names = db.entries.map((e) => e.name).sort();
    expect(names).toEqual([...EXPECTED_NAMES].sort());
  });
});

describe('fingerprint match in non-wrapper context', () => {
  /**
   * Compile a contract that calls ecAdd followed by ecPointX (NOT the
   * ecOnCurve wrapper used by the build probes). The wrapper-bundled
   * fingerprints from the previous build would fail to match here. With
   * primitive-only fingerprints, both calls should be recognized.
   */
  it('recognizes ecAdd when followed by ecPointX (not ecOnCurve)', () => {
    const src = `
import { SmartContract, assert, ecAdd, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';
export class Probe extends SmartContract {
  constructor() { super(); }
  public probe(a: Point, b: Point): void {
    const sum = ecAdd(a, b);
    assert(ecPointX(sum) >= 0n);
  }
}
`;
    const r = compile(src, { fileName: 'Probe.runar.ts' });
    expect(r.success).toBe(true);
    expect(r.scriptHex).toBeTypeOf('string');

    const ops = disassemble(hexToBytes(r.scriptHex!));
    const db = loadFingerprints();
    const annotated = matchFingerprints(ops, { db });

    const matched = annotated.flatMap((a) => (a.kind === 'builtin_call' ? [a.name] : []));
    expect(matched).toContain('ecAdd');
    expect(matched).toContain('ecPointX');
  });

  /**
   * ecPointX / ecPointY fingerprints must NOT include the `>= 0n` comparison
   * used by the build probe. The proof: if those bytes were included, the
   * fingerprint would fail to match a contract that uses ecPointX in a
   * different arithmetic context.
   */
  it('recognizes ecPointX when followed by ecPointY (not `>= 0n`)', () => {
    const src = `
import { SmartContract, assert, ecPointX, ecPointY } from 'runar-lang';
import type { Point } from 'runar-lang';
export class Probe extends SmartContract {
  constructor() { super(); }
  public probe(p: Point): void {
    const x = ecPointX(p);
    const y = ecPointY(p);
    assert(x + y >= 0n);
  }
}
`;
    const r = compile(src, { fileName: 'Probe.runar.ts' });
    expect(r.success).toBe(true);

    const ops = disassemble(hexToBytes(r.scriptHex!));
    const db = loadFingerprints();
    const annotated = matchFingerprints(ops, { db });

    const matched = annotated.flatMap((a) => (a.kind === 'builtin_call' ? [a.name] : []));
    expect(matched).toContain('ecPointX');
    expect(matched).toContain('ecPointY');
  });
});
