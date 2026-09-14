/**
 * R-286 (CL-GAP-076): every emitted `ecMul` / `ecMulGen` depends on
 * `OP_RSHIFTNUM` (0xb7), which pre-Chronicle decodes as `OP_NOP8`. A NOP does
 * not abort — it does nothing and execution continues — so a stale evaluator
 * runs the ladder to completion and hands back a silently wrong answer instead
 * of failing. "No test pins the pre-Chronicle behaviour."
 *
 * `docs/chronicle-opcode-policy.md` already explains that failure mode, and
 * names the property that keeps it from biting today:
 *
 *   "In today's codegen, every primitive that emits OP_LSHIFTNUM or
 *    OP_RSHIFTNUM also emits OP_2MUL or OP_2DIV nearby, so in practice a
 *    pre-Chronicle evaluator aborts before the silent-NOP case can bite. That
 *    is a property of the current code, not a guarantee, and it depends on
 *    which branch executes first. Do not build on it."
 *
 * A property of the current code, stated in prose, is a claim that quietly stops
 * being true. This is that sentence as a test: any script carrying a Chronicle
 * NOP-decoded opcode must also carry a Chronicle DISABLED one, so a stale
 * evaluator hits `ErrDisabledOpcode` and stops rather than computing garbage.
 *
 * It is a byte-level scan, and deliberately so — the alternative is an evaluator
 * configured without the Chronicle opcodes, and `@bsv/sdk` implements them, so
 * the repo has no engine that can demonstrate the silent-NOP path directly.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';

/** Pre-Chronicle: these decode as upgradable NOPs — they do NOT abort. */
const NOP_DECODED = { OP_LSHIFTNUM: 0xb6, OP_RSHIFTNUM: 0xb7 } as const;
/** Pre-Chronicle: these are DISABLED — they abort with ErrDisabledOpcode. */
const DISABLED = { OP_2MUL: 0x8d, OP_2DIV: 0x8e } as const;

/** Opcode bytes of a script, skipping push data so operands are not misread. */
function opcodesOf(hex: string): Set<number> {
  const bytes = Buffer.from(hex, 'hex');
  const ops = new Set<number>();
  for (let i = 0; i < bytes.length; ) {
    const op = bytes[i]!;
    ops.add(op);
    i += 1;
    if (op >= 0x01 && op <= 0x4b) i += op;
    else if (op === 0x4c) { i += 1 + (bytes[i] ?? 0); }
    else if (op === 0x4d) { i += 2 + ((bytes[i] ?? 0) | ((bytes[i + 1] ?? 0) << 8)); }
    else if (op === 0x4e) {
      i += 4 + (((bytes[i] ?? 0) | ((bytes[i + 1] ?? 0) << 8) | ((bytes[i + 2] ?? 0) << 16) | ((bytes[i + 3] ?? 0) << 24)) >>> 0);
    }
  }
  return ops;
}

function compileHex(src: string, fileName: string): string {
  const result = compile(src, { fileName });
  expect(result.success, result.diagnostics.map((d) => d.message).join('\n')).toBe(true);
  return result.scriptHex!;
}

const EC_MUL = `
import { SmartContract, assert, ecMul, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';

class MulProbe extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public unlock(p: Point, k: bigint) {
    assert(ecPointX(ecMul(p, k)) === this.expected);
  }
}
`;

const EC_MUL_GEN = `
import { SmartContract, assert, ecMulGen, ecPointX } from 'runar-lang';

class MulGenProbe extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public unlock(k: bigint) {
    assert(ecPointX(ecMulGen(k)) === this.expected);
  }
}
`;

const CASES = [
  { name: 'ecMul', src: EC_MUL, file: 'MulProbe.runar.ts' },
  { name: 'ecMulGen', src: EC_MUL_GEN, file: 'MulGenProbe.runar.ts' },
];

describe('R-286: a Chronicle NOP never travels without a Chronicle abort', () => {
  it('the opcode scan is not vacuous — ecMul really does emit OP_RSHIFTNUM', () => {
    const ops = opcodesOf(compileHex(EC_MUL, 'MulProbe.runar.ts'));
    expect(
      ops.has(NOP_DECODED.OP_RSHIFTNUM),
      'ecMul no longer emits 0xb7; this whole file is about a risk that is gone',
    ).toBe(true);
  });

  for (const { name, src, file } of CASES) {
    it(`${name}: any NOP-decoded opcode is accompanied by a disabled one`, () => {
      const ops = opcodesOf(compileHex(src, file));

      const nops = Object.entries(NOP_DECODED).filter(([, b]) => ops.has(b)).map(([n]) => n);
      if (nops.length === 0) return; // nothing to protect against

      const aborts = Object.entries(DISABLED).filter(([, b]) => ops.has(b)).map(([n]) => n);
      expect(
        aborts.length,
        `${name} emits ${nops.join(', ')} — which a pre-Chronicle evaluator treats as ` +
          `a no-op and CONTINUES past — with no OP_2MUL/OP_2DIV to make that evaluator ` +
          `abort instead. docs/chronicle-opcode-policy.md's "in practice a pre-Chronicle ` +
          `evaluator aborts before the silent-NOP case can bite" is no longer true.`,
      ).toBeGreaterThan(0);
    });
  }

  it('the policy document still states the property this test pins', () => {
    const { readFileSync } = require('node:fs') as typeof import('node:fs');
    const doc = readFileSync(
      new URL('../docs/chronicle-opcode-policy.md', import.meta.url),
      'utf8',
    );
    expect(doc).toMatch(/OP_RSHIFTNUM/);
    expect(doc).toMatch(/silently incorrect result|silent-NOP/);
  });
});
