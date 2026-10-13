/**
 * N-251 — the negate-cancel rewrites must agree with the adder they replace on
 * an (x, 0) operand.
 *
 *     R8  ec-add-negate-cancel           ecAdd($x, ecNegate($x))  -> INFINITY
 *     R8r ec-add-negate-cancel-reversed  ecAdd(ecNegate($x), $x)  -> INFINITY
 *
 * N-110 made the unoptimized adder ABORT when it doubles a point with y = 0
 * (the tangent has no denominator). For x = (a, 0), ecNegate(x) is (a, 0)
 * again, so `ecAdd(x, ecNegate(x))` IS that doubling and aborts — unless the
 * optimizer has rewritten it to INFINITY, which returned O. Same program, two
 * meanings. User decision R96: keep the rewrite, gate it so it aborts too.
 *
 * The gate is N-110's predicate, not a bare `y != 0`: the adder exempts
 * px == 0 so that O + O stays O, and ecNegate(O) = O, so x = O must still
 * give O (row `O` below). x = (0, y != 0) is the chord path, not a doubling,
 * and gives O in both modes (row `zeroX`).
 *
 * The shape is unreachable from source (pass 04 gives each occurrence of a
 * variable its own binding — see r034-ec-negate-cancel-parity.test.ts), so the
 * probe is hand-written ANF fed to `compileFromANF`, as the `--ir` path would.
 *
 * Oracle: `@bsv/sdk` Spend under consensus rules (`newConsensusSpend`), with
 * minimal pushes so MINIMALDATA does not abort a row for the wrong reason.
 *
 * WHAT IT PROVES: for both operand orders, for the input classes below, the
 * EC-optimized script and the `disableEcOptimizer` script return the same
 * value or both abort, and that answer is the one written in the table (so the
 * two cannot agree by regressing together); a wrong expected value is
 * rejected, so "accepted" is not vacuous; the optimized script with constant
 * folding ON decides every row the same way; and the rewrite still fires.
 *
 * WHAT IT DOES NOT PROVE: that the other six tiers emit the same gate. Their
 * byte parity with TS on this exact ANF is pinned by
 * packages/runar-compiler/src/__tests__/r034-ec-negate-cancel-parity.test.ts
 * (via `--ir`) and each tier's own optimizer unit test pins the gate's ANF.
 */

import { describe, it, expect } from 'vitest';
import { compileFromANF } from 'runar-compiler';
import type { ANFProgram, ANFBinding, ANFValue } from 'runar-compiler';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import { CONSENSUS_SPEND_CONTEXT, newConsensusSpend } from '../consensus-spend.js';

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const h32 = (n: bigint) => n.toString(16).padStart(64, '0');

const G = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
        + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
const O = '00'.repeat(64);

const INPUTS: Record<string, string> = {
  G,
  O,
  offCurve: h32(5n) + h32(7n),       // canonical, off the curve, y != 0
  twoTorsion: h32(5n) + h32(0n),     // canonical, off the curve, y = 0  (THE row)
  zeroX: h32(0n) + h32(5n),          // x = 0, y != 0: chord path, not a doubling
  xGeP: h32(1n + P) + h32(2n),       // non-canonical x
  short63: G.slice(0, 126),          // 63 bytes
};

type Outcome = 'O' | 'abort';

const EXPECTED: Record<string, Outcome> = {
  G: 'O',
  O: 'O',
  offCurve: 'O',
  twoTorsion: 'abort',
  zeroX: 'O',
  xGeP: 'abort',
  short63: 'abort',
};

function b(name: string, value: ANFValue): ANFBinding {
  return { name, value };
}

/** `r = ecAdd(q, ecNegate(q))` (or reversed) over ONE binding of q; `assert(r === e)`. */
function probe(order: 'forward' | 'reversed'): ANFProgram {
  const addArgs = order === 'forward' ? ['t0', 't2'] : ['t2', 't0'];
  return {
    contractName: 'NegCancelY0',
    properties: [],
    methods: [
      {
        name: 'constructor',
        params: [],
        body: [b('c0', { kind: 'call', func: 'super', args: [] })],
        isPublic: false,
      },
      {
        name: 'check',
        params: [{ name: 'q', type: 'Point' }, { name: 'e', type: 'Point' }],
        body: [
          b('t0', { kind: 'load_param', name: 'q' }),
          b('t1', { kind: 'load_param', name: 'e' }),
          b('t2', { kind: 'call', func: 'ecNegate', args: ['t0'] }),
          b('t3', { kind: 'call', func: 'ecAdd', args: addArgs }),
          b('t4', { kind: 'bin_op', op: '===', left: 't3', right: 't1', result_type: 'bytes' }),
          b('t5', { kind: 'assert', value: 't4' }),
        ],
        isPublic: true,
      },
    ],
  };
}

/** Minimal push of a blob under 76 bytes (every input here is 63 or 64). */
function push(hex: string): string {
  const len = hex.length / 2;
  if (len >= 0x4c) throw new Error('push helper only handles < 76 bytes');
  return len.toString(16).padStart(2, '0') + hex;
}

function accepts(scriptHex: string, q: string, e: string): boolean {
  const spend = newConsensusSpend({
    ...CONSENSUS_SPEND_CONTEXT,
    lockingScript: LockingScript.fromHex(scriptHex),
    otherInputs: [],
    outputs: [],
    unlockingScript: UnlockingScript.fromHex(push(q) + push(e)),
  });
  try {
    return spend.validate();
  } catch {
    return false;
  }
}

/** What the script returns for q: 'O', or 'abort' (it never returns anything else here). */
function outcome(scriptHex: string, q: string): Outcome {
  if (accepts(scriptHex, q, O)) {
    // A real `assert(r === e)` must also reject a wrong e, or "accepted" means nothing.
    expect(accepts(scriptHex, q, G)).toBe(false);
    return 'O';
  }
  // Not O: it must not be returning some other value either.
  expect(accepts(scriptHex, q, G)).toBe(false);
  expect(accepts(scriptHex, q, q)).toBe(false);
  return 'abort';
}

function compileHex(anf: ANFProgram, opts: { disableEcOptimizer?: boolean; disableConstantFolding?: boolean }): string {
  return compileFromANF(anf, opts).scriptHex as string;
}

describe('N-251 negate-cancel rewrite agrees with the adder on (x, 0)', () => {
  for (const order of ['forward', 'reversed'] as const) {
    describe(order, () => {
      const modes = {
        optimized: compileHex(probe(order), { disableConstantFolding: true }),
        unoptimized: compileHex(probe(order), { disableConstantFolding: true, disableEcOptimizer: true }),
        'optimized, fold ON': compileHex(probe(order), {}),
      };
      for (const [mode, hex] of Object.entries(modes)) {
        it(`${mode}: every input class gets the pinned answer`, () => {
          const got: Record<string, Outcome> = {};
          for (const [name, q] of Object.entries(INPUTS)) got[name] = outcome(hex, q);
          expect(got).toEqual(EXPECTED);
        });
      }
      it('the rewrite still fires: the optimized script is a small fraction of the adder', () => {
        expect(modes.optimized.length * 3).toBeLessThan(modes.unoptimized.length);
      });
    });
  }
}, 600_000);
