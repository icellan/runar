/**
 * #180 / #213: the stack lowerer prefixes each public method with an entry
 * width gate (`<copy> OP_SIZE <w> OP_NUMEQUALVERIFY OP_DROP`) for every
 * fixed-width parameter. The lifter must strip it (it is compiler-emitted,
 * not author code), recover the declared type from the width, and the
 * recovered source must re-compile byte-identically (which puts the gates
 * back).
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { decompile, disassemble, liftStraightLine } from '../src/index.js';
import { hexToBytes } from 'runar-testing';

const SRC = `import { SmartContract, assert, sha256 } from 'runar-lang';
import type { Point, Sha256 } from 'runar-lang';

class Gated extends SmartContract {
  constructor() { super(); }
  public unlock(h: Sha256, p: Point) {
    assert(sha256(p) === h);
  }
}
`;

describe('#180/#213: entry width gates are stripped and restored', () => {
  const r = compile(SRC, { fileName: 'Gated.runar.ts' });
  if (!r.success || !r.scriptHex) throw new Error(JSON.stringify(r.diagnostics));
  const hex = r.scriptHex;

  it('the compiled script starts with the two gates (h at depth 1, p at depth 0)', () => {
    expect(hex.startsWith('788201209d75' + '768201409d75')).toBe(true);
  });

  it('the lifter strips them and recovers Sha256 / Point from the widths', () => {
    const out = liftStraightLine(disassemble(hexToBytes(hex)));
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.paramTypes).toEqual(['sha256', 'point']);
  });

  it('the recovered source recompiles byte-identically', () => {
    const dec = decompile(hexToBytes(hex));
    expect(dec.ok).toBe(true);
    const re = compile(dec.source, { fileName: '_Recovered.runar.ts' });
    expect(re.success).toBe(true);
    expect(re.scriptHex).toBe(hex);
  });
});
