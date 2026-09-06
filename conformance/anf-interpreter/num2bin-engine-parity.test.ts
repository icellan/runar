import { describe, it, expect } from 'vitest';
import { computeNewStateAndDataOutputs } from '../../packages/runar-sdk/src/index.js';
import { ScriptVM } from '../../packages/runar-testing/src/vm/script-vm.js';
import type { ANFProgram } from '../../packages/runar-ir-schema/src/index.js';

// ---------------------------------------------------------------------------
// NEW-013 — `num2bin` sign-bit placement, checked against the ENGINE.
//
// The SDK ANF interpreter models what the DEPLOYED SCRIPT computes. For
// `num2bin` that model was wrong for negative values: it set the sign bit on
// the last MAGNITUDE byte and then padded zeros AFTER it, so `num2bin(-1n, 2n)`
// came out `8100` where OP_NUM2BIN yields `0180`. The interpreter's answer
// feeds `computeNewState` / `computeNewStateAndDataOutputs`, i.e. the bytes the
// SDK puts in the call transaction — so a legal method built a continuation the
// script rejects.
//
// Every previous num2bin test in this repo was self-referential: either
// `bin2num(num2bin(x)) === x` (true for ANY self-consistent framing, including
// the wrong one) or tier-vs-tier (six tiers shared the bug, so they agreed).
// This file compares against the ONE authority that is not the SDK: BSV's
// OP_NUM2BIN, executed on the real `@bsv/sdk` Spend interpreter, live, in this
// process. No table of expected bytes is checked in here — a table could be
// edited to match a regression; the engine cannot.
//
// Engine algorithm (@bsv/sdk `Spend`, OP_NUM2BIN):
//   1. minimally encode the operand as a script number (LE sign-magnitude);
//   2. if it is longer than `size`, FAIL (impossible encoding);
//   3. if it is exactly `size`, push it unchanged;
//   4. otherwise strip the sign bit off the top magnitude byte, zero-extend to
//      `size`, and set the sign bit on byte `size - 1`.
// ---------------------------------------------------------------------------

const OP_NUM2BIN = 0x80;

/** Minimal BSV script-number encoding: LE magnitude with the sign in the MSB. */
function scriptNum(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array(0);
  const negative = n < 0n;
  let abs = negative ? -n : n;
  const bytes: number[] = [];
  while (abs > 0n) {
    bytes.push(Number(abs & 0xffn));
    abs >>= 8n;
  }
  if ((bytes[bytes.length - 1]! & 0x80) !== 0) bytes.push(negative ? 0x80 : 0x00);
  else if (negative) bytes[bytes.length - 1]! |= 0x80;
  return new Uint8Array(bytes);
}

/** Direct push of `bytes` (empty pushes as OP_0, matching a zero script-num). */
function pushData(bytes: Uint8Array): number[] {
  if (bytes.length === 0) return [0x00];
  if (bytes.length > 75) throw new Error('operand too large for a direct push');
  return [bytes.length, ...bytes];
}

interface EngineResult {
  hex?: string;
  error?: string;
}

/**
 * `<n> <byteLen> OP_NUM2BIN` on the real engine. Returns the resulting stack
 * top, or the engine's own rejection message.
 */
function engineNum2bin(n: bigint, byteLen: bigint): EngineResult {
  const script = new Uint8Array([
    ...pushData(scriptNum(n)),
    ...pushData(scriptNum(byteLen)),
    OP_NUM2BIN,
  ]);
  const vm = new ScriptVM();
  const result = vm.executeScript(script);
  if (result.error !== undefined && result.error !== '') return { error: result.error };
  const top = result.stack[result.stack.length - 1];
  if (top === undefined) return { error: 'engine left an empty stack' };
  return { hex: Buffer.from(top).toString('hex') };
}

/**
 * `num2bin(v, byteLen)` through the SDK ANF interpreter, surfaced as the script
 * of a data output so the raw bytes — not a re-decoded number — are observed.
 * Hand-built ANF keeps this test independent of the compiler; the shape is the
 * same one `04-anf-lower.ts` emits for `this.addDataOutput(0n, num2bin(v, N))`.
 */
function sdkNum2bin(n: bigint, byteLen: bigint): string {
  const anf: ANFProgram = {
    contractName: 'Num2BinProbe',
    properties: [{ name: 'count', type: 'bigint', readonly: false }],
    methods: [
      {
        name: 'probe',
        isPublic: true,
        params: [{ name: 'v', type: 'bigint' }],
        body: [
          { name: 't0', value: { kind: 'load_param', name: 'v' } },
          { name: 't1', value: { kind: 'load_const', value: byteLen } },
          { name: 't2', value: { kind: 'call', func: 'num2bin', args: ['t0', 't1'] } },
          { name: 't3', value: { kind: 'load_const', value: 0n } },
          { name: 't4', value: { kind: 'add_data_output', satoshis: 't3', scriptBytes: 't2' } },
        ],
      },
    ],
  } as unknown as ANFProgram;

  const result = computeNewStateAndDataOutputs(anf, 'probe', { count: 0n }, { v: n }, [0n]);
  expect(result.dataOutputs).toHaveLength(1);
  return result.dataOutputs[0]!.script;
}

// Values × widths that the engine ACCEPTS. Every entry is a case the deployed
// script can really reach, so a disagreement here is a real unspendable-output
// bug, not a curiosity.
//
//   negative padded ......... the NEW-013 corner: sign bit must land on the pad
//   negative exact-width .... magnitude exactly fills the field
//   negative carry .......... magnitude's top byte already uses bit 7, so the
//                             minimal encoding grows a byte before padding
//   positive ................ same widths, must be untouched by the fix
//   zero .................... all-zero field, no sign bit anywhere
const CASES: Array<[bigint, bigint]> = [
  // negative, padded
  [-1n, 2n], [-1n, 4n], [-1n, 8n],
  [-5n, 4n], [-7n, 8n],
  [-1000n, 4n], [-1000n, 8n],
  [-255n, 3n], [-256n, 3n],
  // negative, exact width (minimal encoding already fills the field)
  [-1n, 1n], [-127n, 1n], [-1000n, 2n], [-256n, 2n], [-128n, 2n], [-32768n, 3n],
  // negative, sign-bit carry (top magnitude byte has bit 7 set)
  [-128n, 3n], [-128n, 8n], [-32768n, 4n], [-32768n, 8n],
  // positive, same widths — must not move
  [1n, 1n], [1n, 2n], [1n, 4n], [1n, 8n],
  [5n, 4n], [7n, 8n], [1000n, 2n], [1000n, 4n], [1000n, 8n],
  [127n, 1n], [128n, 2n], [128n, 3n], [255n, 2n], [32768n, 3n],
  // zero
  [0n, 1n], [0n, 2n], [0n, 4n], [0n, 8n],
];

describe('num2bin vs OP_NUM2BIN (engine is the authority)', () => {
  // Non-vacuity sentinels. A filtered-empty matrix, or one that quietly lost
  // its negative half, would leave this whole file green while checking
  // nothing — which is exactly how the bug survived six tiers.
  it('drives a non-empty matrix covering both signs and zero', () => {
    expect(CASES.length).toBeGreaterThanOrEqual(30);
    expect(CASES.filter(([n]) => n < 0n).length).toBeGreaterThanOrEqual(15);
    expect(CASES.filter(([n]) => n > 0n).length).toBeGreaterThanOrEqual(10);
    expect(CASES.filter(([n]) => n === 0n).length).toBeGreaterThanOrEqual(1);
  });

  it('reaches the engine for every case (no silent rejections)', () => {
    for (const [n, len] of CASES) {
      const engine = engineNum2bin(n, len);
      expect(engine.error, `engine rejected num2bin(${n}, ${len}); it is not a valid oracle case`).toBeUndefined();
      expect(engine.hex).toHaveLength(Number(len) * 2);
    }
  });

  // The pre-fix implementation set the sign bit on the last MAGNITUDE byte and
  // padded after it. Pinning one such value proves the matrix above can go red:
  // if `num2bin(-1n, 2n)` ever answers `8100` again, the case list is still
  // able to see it.
  it('does not answer with the pre-fix encoding for the canonical case', () => {
    expect(sdkNum2bin(-1n, 2n)).not.toBe('8100');
    expect(engineNum2bin(-1n, 2n).hex).toBe('0180');
  });

  for (const [n, len] of CASES) {
    it(`num2bin(${n}, ${len}) matches OP_NUM2BIN`, () => {
      const engine = engineNum2bin(n, len);
      expect(engine.error).toBeUndefined();
      expect(sdkNum2bin(n, len)).toBe(engine.hex);
    });
  }
});
