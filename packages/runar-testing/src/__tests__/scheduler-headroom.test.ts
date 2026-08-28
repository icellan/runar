/**
 * Headroom probe for the stack scheduler.
 *
 * `conformance/tests/arithmetic` is the smallest fixture whose bytes are
 * produced ENTIRELY by the generic ANF -> Stack lowering: no crypto macro, no
 * sighash scaffolding, no state continuation. 16 of its 28 bytes (57 %) are
 * stack access. That makes it the honest measuring stick for "how much can a
 * better schedule win on ordinary contracts?".
 *
 * This test pins two things:
 *
 *  1. what the compiler emits today, and
 *  2. that a hand-written alternative schedule — operands held hot at the top,
 *     finished results parked on the alt stack — accepts and rejects exactly
 *     the same inputs while being materially smaller.
 *
 * (2) is not a claim about what the compiler does; it is the TARGET the
 * liveness scheduler is aimed at, executed on the real interpreter so the
 * headroom number in `docs/experiments/stack-scheduler-design.md` is measured
 * rather than estimated. If a future scheduler beats it, tighten this test.
 */

import { describe, it, expect } from 'vitest';
import { ScriptVM } from '../vm/script-vm.js';

/** Encode a bigint as a minimally-encoded Bitcoin script number push. */
function pushNum(n: bigint): string {
  if (n === 0n) return '00';
  if (n >= 1n && n <= 16n) return (0x50 + Number(n)).toString(16).padStart(2, '0');
  const neg = n < 0n;
  let v = neg ? -n : n;
  const bytes: number[] = [];
  while (v > 0n) { bytes.push(Number(v & 0xffn)); v >>= 8n; }
  if (bytes[bytes.length - 1]! & 0x80) bytes.push(neg ? 0x80 : 0x00);
  else if (neg) bytes[bytes.length - 1] = bytes[bytes.length - 1]! | 0x80;
  return bytes.length.toString(16).padStart(2, '0') + bytes.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * What the compiler emits today for `Arithmetic.verify`, with the constructor
 * placeholder (`00`) replaced by a real target push.
 *
 *   OP_2DUP OP_ADD                  sum
 *   OP_2 OP_PICK OP_2 OP_PICK OP_SUB   diff
 *   OP_3 OP_PICK OP_3 OP_PICK OP_MUL   prod
 *   OP_4 OP_ROLL OP_4 OP_ROLL OP_DIV   quot
 *   OP_3 OP_ROLL OP_3 OP_ROLL OP_ADD OP_ROT OP_ADD OP_SWAP OP_ADD
 *   <target> OP_NUMEQUAL
 */
function currentSchedule(target: bigint): string {
  return `6e9352795279945379537995547a547a96537a537a937b937c93${pushNum(target)}9c`;
}

/**
 * The same computation, scheduled so `a` and `b` never leave the top two
 * slots and each finished result is spilled to the alt stack:
 *
 *   OP_2DUP OP_ADD OP_TOALTSTACK    sum   -> alt
 *   OP_2DUP OP_SUB OP_TOALTSTACK    diff  -> alt
 *   OP_2DUP OP_MUL OP_TOALTSTACK    prod  -> alt
 *   OP_DIV                          quot  (consumes a, b)
 *   OP_FROMALTSTACK OP_ADD          + prod
 *   OP_FROMALTSTACK OP_ADD          + diff
 *   OP_FROMALTSTACK OP_ADD          + sum
 *   <target> OP_NUMEQUAL
 *
 * Addition is associative and commutative over script numbers here, so the
 * reversed accumulation order is value-identical.
 */
function altStackSchedule(target: bigint): string {
  return `6e936b6e946b6e956b966c936c936c93${pushNum(target)}9c`;
}

function run(scriptHex: string, a: bigint, b: bigint): boolean {
  const vm = new ScriptVM();
  const unlocking = `${pushNum(a)}${pushNum(b)}`;
  const r = vm.execute(
    Uint8Array.from(Buffer.from(unlocking, 'hex')),
    Uint8Array.from(Buffer.from(scriptHex, 'hex')),
  );
  return r.success;
}

/** a + b, a - b, a * b, a / b summed — the contract's `result`. */
function expected(a: bigint, b: bigint): bigint {
  // Script's OP_DIV truncates toward zero, which matches bigint division.
  return (a + b) + (a - b) + a * b + a / b;
}

const CASES: [bigint, bigint][] = [
  [7n, 3n], [3n, 7n], [1n, 1n], [100n, 7n], [-5n, 3n], [5n, -3n],
  [-5n, -3n], [0n, 1n], [16n, 16n], [17n, 2n], [255n, 4n], [-1n, -1n],
  [1000n, 3n], [2n, 1000n],
];

describe('stack scheduler headroom (conformance/tests/arithmetic)', () => {
  it('pins the byte cost of both schedules', () => {
    // 5 is the byte cost of the `target` push in these probes (4-byte push of
    // a value that needs a sign byte); both schedules carry the same one, so
    // the difference is entirely scheduling.
    const t = 1000n;
    const cur = currentSchedule(t).length / 2;
    const alt = altStackSchedule(t).length / 2;
    expect(cur).toBe(30);
    expect(alt).toBe(20);
    // 33 % fewer bytes, all of it stack traffic.
    expect(1 - alt / cur).toBeGreaterThan(0.3);
  });

  it('the emitted schedule matches the checked-in golden modulo the placeholder', () => {
    // Golden is the template: `00` where the constructor arg is spliced in.
    const template = '6e9352795279945379537995547a547a96537a537a937b937c93009c';
    expect(currentSchedule(0n)).toBe(template);
  });

  it.each(CASES)('both schedules accept exactly the right target for a=%s b=%s', (a, b) => {
    const want = expected(a, b);
    expect(run(currentSchedule(want), a, b)).toBe(true);
    expect(run(altStackSchedule(want), a, b)).toBe(true);
  });

  it.each(CASES)('both schedules reject a wrong target for a=%s b=%s', (a, b) => {
    const wrong = expected(a, b) + 1n;
    expect(run(currentSchedule(wrong), a, b)).toBe(false);
    expect(run(altStackSchedule(wrong), a, b)).toBe(false);
  });
});
