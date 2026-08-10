/**
 * `opReturn(data | data[])` — shorthand that desugars at parse time to the asm
 * escape hatch `asm({ body: [OP_RETURN, push(f0), ...] })`, so it produces
 * byte-identical script. TS-first builtin (other tiers port pending).
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

function hex(src: string): string {
  const r = compile(src, { fileName: 'T.runar.ts', disableConstantFolding: false });
  if (!r.success || !r.scriptHex) {
    throw new Error(r.diagnostics.filter((d) => d.severity === 'error').map((e) => e.message).join('; '));
  }
  return r.scriptHex;
}

const head = "import { UnsafeSmartContract, asm, opReturn, OP_RETURN, push } from 'runar-lang';";
const wrap = (body: string) =>
  `${head}\nexport class T extends UnsafeSmartContract {\n  constructor() { super(); }\n  public m(x: bigint): void {\n    ${body}\n  }\n}`;

describe('opReturn shorthand', () => {
  it('array form is byte-identical to the asm array form', () => {
    const viaOpReturn = hex(wrap("opReturn(['00', '46544b', '64656d6f']);"));
    const viaAsm = hex(wrap("asm({ body: [OP_RETURN, push('00'), push('46544b'), push('64656d6f')], in_arity: 1, out_arity: 1 });"));
    expect(viaOpReturn).toBe(viaAsm);
    expect(viaOpReturn).toBe('6a01000346544b0464656d6f');
  });

  it('single-field form equals the one-element array form', () => {
    expect(hex(wrap("opReturn('48656c6c6f');"))).toBe(hex(wrap("opReturn(['48656c6c6f']);")));
  });

  it('encodes a large (PUSHDATA2) payload like asm', () => {
    const big = 'ab'.repeat(300); // 300 bytes -> OP_PUSHDATA2
    expect(hex(wrap(`opReturn(['${big}']);`))).toBe(
      hex(wrap(`asm({ body: [OP_RETURN, push('${big}')], in_arity: 1, out_arity: 1 });`)),
    );
  });

  it('rejects a non-string field', () => {
    const r = compile(wrap('opReturn([123]);'), { fileName: 'T.runar.ts' });
    expect(r.success).toBe(false);
    expect(r.diagnostics.some((d) => d.severity === 'error' && /opReturn\(\) fields must be hex string/.test(d.message))).toBe(true);
  });
});
