import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import {
  CONSENSUS_SPEND_CONTEXT,
  newConsensusSpend,
} from '../../packages/runar-testing/src/consensus-spend.js';
import * as rt from '../../packages/runar-lang/src/runtime/index.js';
import { computeNewState } from '../../packages/runar-sdk/src/anf-interpreter.js';
import { Tier, buildSourceTiers, compileHex, ALL_TIER_IDS } from './tier-harness.js';
import { isCiEnv } from '../env.js';

type ANFProgram = Parameters<typeof computeNewState>[0];

/**
 * N-103 — `log2(n)` must be exact floor(log2(n)) for EVERY positive n.
 *
 * Before this item every tier lowered log2 to a 64-iteration halving loop, so
 * the script saturated at 64 (log2(2^70) = 64, wrong from 2^65 up) and
 * returned 0 for n <= 0, while the docs claimed exact floor(log2(n)) and the
 * spec said "approximate". User decision R86: make the script exact in all
 * seven tiers with no cap, and make n <= 0 ABORT the script (assert-fail).
 *
 * The new lowering (one op sequence, every tier) reads the bit length off the
 * minimal Script-number encoding instead of looping:
 *
 *   OP_BIN2NUM                       normalise to the minimal encoding
 *   OP_DUP OP_0 OP_GREATERTHAN OP_VERIFY   n <= 0 aborts
 *   OP_SIZE OP_1SUB OP_TUCK OP_SPLIT OP_NIP OP_BIN2NUM
 *                                    -> (size-1) top, top = the last byte (0..127)
 *   OP_SWAP OP_8 OP_MUL OP_1SUB      -> top, 8*(size-1) - 1
 *   7x OP_OVER <c> OP_GREATERTHANOREQUAL OP_ADD   for c = 1,2,4,...,64
 *   OP_NIP                           -> 8*(size-1) - 1 + #{c : top >= c}
 *
 * A top byte of 0 is the sign-padding byte, and then n's bit length is exactly
 * 8*(size-1), which the formula gives with no comparison set.
 *
 * Oracle: `@bsv/sdk` Spend under consensus rules (`newConsensusSpend`), on the
 * hex each tier's own CLI emits — never the ANF interpreter or TestContract.
 *
 * What this proves, for every available tier, fold OFF and ON:
 *   - a probe `assert(log2(n) === e)` ACCEPTS at e = floor(log2 n) and REJECTS
 *     at e - 1 and e + 1, for n on every encoding boundary
 *     {1, 2, 3, 127, 128, 255, 256, 32767, 32768, 2^63-1, 2^63, 2^64, 2^65,
 *     2^70, 2^200+5} (2^65 and 2^70 were wrong before: the script said 64);
 *   - n = 0 and n = -1 ABORT: no e satisfies the probe, whether e is 0, -1 or 1;
 *   - a non-minimally encoded n (5 as `05 00 00`) never yields the size-derived
 *     wrong value (15) — the leading OP_BIN2NUM normalises it;
 *   - with a CONSTANT operand the folder agrees with the script: log2(2^70)
 *     and log2(2^200+5) accept at the exact value, and log2(0) / log2(-1)
 *     still abort (the folder must decline rather than fold them to 0);
 *   - the log2 window appears exactly once and every tier emits TS's bytes;
 *   - the TS native runtime and the TS SDK ANF interpreter return the same
 *     exact value, and throw for n <= 0.
 * What it does NOT prove: anything about operands wider than 2^200+5 beyond
 * the general argument above, the other tiers' runtimes/interpreters (each
 * replays packages/runar-zig/src/fixtures/f033-math-builtins-onchain.json in
 * its own n030 vector test), or the Lean model.
 */

const OP = {
  BIN2NUM: '81', DUP: '76', P0: '00', GREATERTHAN: 'a0', VERIFY: '69', SIZE: '82',
  SUB1: '8c', TUCK: '7d', SPLIT: '7f', NIP: '77', SWAP: '7c', P8: '58', MUL: '95',
  OVER: '78', GTE: 'a2', ADD: '93',
};
const CMP = (c: string) => [OP.OVER, c, OP.GTE, OP.ADD];
/** The whole log2 window, from the leading normalisation to the final OP_NIP. */
const LOG2_WINDOW = [
  OP.BIN2NUM, OP.DUP, OP.P0, OP.GREATERTHAN, OP.VERIFY,
  OP.SIZE, OP.SUB1, OP.TUCK, OP.SPLIT, OP.NIP, OP.BIN2NUM,
  OP.SWAP, OP.P8, OP.MUL, OP.SUB1,
  ...CMP('51'), ...CMP('52'), ...CMP('54'), ...CMP('58'), ...CMP('60'), ...CMP('0120'), ...CMP('0140'),
  OP.NIP,
];

/** Split a script into whole opcodes (opcode byte plus any push payload). */
function walk(hex: string): string[] {
  const b = Buffer.from(hex, 'hex');
  const ops: string[] = [];
  let i = 0;
  while (i < b.length) {
    const op = b[i]!;
    const start = i++;
    if (op >= 0x01 && op <= 0x4b) i += op;
    else if (op === 0x4c) i += 1 + b[i]!;
    else if (op === 0x4d) i += 2 + b.readUInt16LE(i);
    else if (op === 0x4e) i += 4 + b.readUInt32LE(i);
    if (i > b.length) throw new Error(`truncated push at byte ${start}`);
    ops.push(b.subarray(start, i).toString('hex'));
  }
  return ops;
}

function countWindow(ops: string[], win: string[]): number {
  let n = 0;
  for (let k = 0; k + win.length <= ops.length; k++) {
    if (win.every((w, j) => ops[k + j] === w)) n++;
  }
  return n;
}

/** Signed value as a minimal Script number (LE magnitude, sign in the top bit). */
function scriptNum(v: bigint): Buffer {
  const neg = v < 0n;
  let x = neg ? -v : v;
  const out: number[] = [];
  while (x > 0n) {
    out.push(Number(x & 0xffn));
    x >>= 8n;
  }
  if (out.length > 0) {
    if (out[out.length - 1]! & 0x80) out.push(neg ? 0x80 : 0);
    else if (neg) out[out.length - 1]! |= 0x80;
  }
  return Buffer.from(out);
}

/** Minimal push (consensus MINIMALDATA). */
function push(data: Buffer): string {
  if (data.length === 0) return '00';
  if (data.length === 1 && data[0]! >= 0x01 && data[0]! <= 0x10) return (0x50 + data[0]!).toString(16);
  if (data.length === 1 && data[0] === 0x81) return '4f';
  if (data.length <= 75) return data.length.toString(16).padStart(2, '0') + data.toString('hex');
  if (data.length <= 255) return '4c' + data.length.toString(16).padStart(2, '0') + data.toString('hex');
  throw new Error('push: operand > 255 bytes');
}

function accepts(lockingHex: string, unlockingHex: string): boolean {
  try {
    return newConsensusSpend({
      ...CONSENSUS_SPEND_CONTEXT,
      lockingScript: LockingScript.fromHex(lockingHex),
      unlockingScript: UnlockingScript.fromHex(unlockingHex),
      otherInputs: [],
      outputs: [],
    }).validate();
  } catch {
    return false; // a thrown validation error is a failed spend
  }
}

const PARAM_SRC = `import { SmartContract, assert, log2 } from 'runar-lang';
class N103Log2 extends SmartContract {
  constructor() { super(); }
  public check(n: bigint, expected: bigint) {
    assert(log2(n) === expected);
  }
}
`;

/** Constant operand: under fold ON the folder decides, under fold OFF the script. */
const constSrc = (c: bigint) => `import { SmartContract, assert, log2 } from 'runar-lang';
class N103Log2Const extends SmartContract {
  constructor() { super(); }
  public check(expected: bigint) {
    const k: bigint = log2(${c < 0n ? `-${-c}n` : `${c}n`});
    assert(k === expected);
  }
}
`;

const P = (k: bigint) => 1n << k;
/** n -> exact floor(log2 n), on every minimal-encoding boundary. */
const EXACT: [bigint, bigint][] = [
  [1n, 0n], [2n, 1n], [3n, 1n], [127n, 6n], [128n, 7n], [255n, 7n], [256n, 8n],
  [32767n, 14n], [32768n, 15n], [P(63n) - 1n, 62n], [P(63n), 63n], [P(64n), 64n],
  [P(65n), 65n], [P(70n), 70n], [P(200n) + 5n, 200n],
];
const ABORTS = [0n, -1n];
const CONST_EXACT: [bigint, bigint][] = [[P(70n), 70n], [P(200n) + 5n, 200n]];

const unlockParam = (n: bigint, e: bigint) => push(scriptNum(n)) + push(scriptNum(e));
const unlockConst = (e: bigint) => push(scriptNum(e));

const foldOff = (t: Tier): Tier => ({ ...t, argsFor: (s) => [...t.argsFor(s), '--disable-constant-folding'] });
const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TS_TIER = TIERS.find((t) => t.id === 'ts');
const MODES: { label: string; tier: (t: Tier) => Tier }[] = [
  { label: 'fold OFF', tier: foldOff },
  { label: 'fold ON', tier: (t) => t },
];

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n103-log2-'));
});
function write(name: string, src: string): string {
  const p = join(dir, name);
  writeFileSync(p, src);
  return p;
}

/** The TS SDK ANF interpreter, on a one-binding log2 program. */
function sdkLog2(n: bigint): unknown {
  const anf: ANFProgram = {
    contractName: 'Log2Probe',
    properties: [{ name: 'result', type: 'bigint', readonly: false }],
    methods: [
      {
        name: 'probe',
        params: [{ name: 'a', type: 'bigint' }],
        body: [
          { name: 't0', value: { kind: 'load_param', name: 'a' } },
          { name: 'r', value: { kind: 'call', func: 'log2', args: ['t0'] } },
          { name: 'u', value: { kind: 'update_prop', name: 'result', value: 'r' } },
        ],
        isPublic: true,
      },
    ],
  };
  return computeNewState(anf, 'probe', { result: 0n }, { a: n }).result;
}

describe('N-103 log2 is exact for every n > 0 and aborts for n <= 0 — seven tiers, executed on @bsv/sdk', () => {
  it('the TS reference and at least one other tier are available (all seven in CI)', () => {
    expect(TS_TIER).toBeDefined();
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(ALL_TIER_IDS.length);
  });

  it('preconditions: the expected values are floor(log2 n) by bit length', () => {
    for (const [n, e] of EXACT) expect(BigInt(n.toString(2).length - 1)).toBe(e);
  });

  it('TS runtime and TS SDK ANF interpreter: exact value, throw for n <= 0', () => {
    for (const [n, e] of EXACT) {
      expect(rt.log2(n), `runtime log2(${n})`).toBe(e);
      expect(sdkLog2(n), `sdk interpreter log2(${n})`).toBe(e);
    }
    for (const n of ABORTS) {
      expect(() => rt.log2(n), `runtime log2(${n})`).toThrow();
      expect(() => sdkLog2(n), `sdk interpreter log2(${n})`).toThrow();
    }
  });

  for (const mode of MODES) {
    describe(mode.label, () => {
      let tsParam = '';
      const tsConst = new Map<bigint, string>();
      const constOperands = [...CONST_EXACT.map(([c]) => c), ...ABORTS];
      beforeAll(() => {
        tsParam = compileHex(mode.tier(TS_TIER!), write('P.runar.ts', PARAM_SRC));
        for (const c of constOperands) {
          tsConst.set(c, compileHex(mode.tier(TS_TIER!), write(`C${c}.runar.ts`, constSrc(c))));
        }
      }, 240_000);

      for (const tier of TIERS) {
        it(`${tier.id}: exact on every boundary, n <= 0 aborts, folder agrees, TS bytes`, () => {
          const param = tier.id === 'ts' ? tsParam : compileHex(mode.tier(tier), write('P.runar.ts', PARAM_SRC));

          for (const [n, e] of EXACT) {
            expect(accepts(param, unlockParam(n, e)), `log2(${n}) = ${e} rejected`).toBe(true);
            expect(accepts(param, unlockParam(n, e + 1n)), `log2(${n}) = ${e + 1n} accepted`).toBe(false);
            expect(accepts(param, unlockParam(n, e - 1n)), `log2(${n}) = ${e - 1n} accepted`).toBe(false);
          }
          for (const n of ABORTS) {
            for (const e of [0n, -1n, 1n]) {
              expect(accepts(param, unlockParam(n, e)), `log2(${n}) = ${e} accepted (must abort)`).toBe(false);
            }
          }
          // Non-minimal 5 (`05 00 00`): never the size-derived 8*2 - 1 = 15.
          expect(accepts(param, '03050000' + push(scriptNum(15n))), 'non-minimal 5 gave 15').toBe(false);

          for (const c of constOperands) {
            const hex = tier.id === 'ts' ? tsConst.get(c)! : compileHex(mode.tier(tier), write(`C${c}.runar.ts`, constSrc(c)));
            const exact = CONST_EXACT.find(([k]) => k === c);
            if (exact) {
              expect(accepts(hex, unlockConst(exact[1])), `const log2(${c}) = ${exact[1]} rejected`).toBe(true);
              expect(accepts(hex, unlockConst(exact[1] + 1n)), `const log2(${c}) off by one accepted`).toBe(false);
            } else {
              for (const e of [0n, -1n, 1n]) {
                expect(accepts(hex, unlockConst(e)), `const log2(${c}) = ${e} accepted (must abort)`).toBe(false);
              }
            }
            expect(hex, `const log2(${c}) bytes`).toBe(tsConst.get(c));
          }

          expect(countWindow(walk(param), LOG2_WINDOW), 'log2 window').toBe(1);
          expect(param).toBe(tsParam);
        }, 240_000);
      }
    });
  }
});
