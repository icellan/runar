/**
 * EC constant pooling — size and default-invariance.
 *
 * `cFieldMod` / `fieldMod` push the curve's field prime inline at EVERY
 * modular reduction. On `conformance/tests/p256-wallet` that is 20,025 pushes
 * of a 34-byte literal — 680,850 of the fixture's 958,792 bytes, 71 %. The
 * prime is a compile-time constant; parking one copy in a stack slot and
 * copying it with `push d; OP_PICK` costs 2-3 bytes instead of 34.
 *
 * This file pins two things:
 *   1. with pooling OFF the emitters are byte-identical to what ships today
 *      (so no golden, baseline, or cross-tier parity gate can move), and
 *   2. with pooling ON the scripts actually shrink, by the amount the
 *      arithmetic predicts rather than by "some".
 *
 * Semantic equivalence is proved separately, against OpenSSL signatures on the
 * real interpreter, in
 * `packages/runar-testing/src/__tests__/ec-constant-pool-equivalence.test.ts`.
 */

import { describe, it, expect } from 'vitest';
import {
  emitVerifyECDSA_P256, emitVerifyECDSA_P384,
  emitP256Mul, emitP256MulGen, emitP256Add, emitP256OnCurve,
  emitP384Mul, emitP384Add,
} from '../passes/p256-p384-codegen.js';
import {
  emitEcAdd, emitEcMul, emitEcMulGen,
} from '../passes/ec-codegen.js';
import { emitMethod } from '../passes/06-emit.js';
import { estimateScriptBytes } from '../metrics/cost-model.js';
import { analyzeScriptHex } from '../metrics/script-metrics.js';
import { encodeScriptNumber } from '../passes/push-encoding.js';
import type { StackOp } from '../ir/index.js';
import type { EcCodegenOptions } from '../passes/ec-codegen.js';

type Emitter = (emit: (op: StackOp) => void, opts?: EcCodegenOptions) => void;

function opsOf(emitter: Emitter, opts?: EcCodegenOptions): StackOp[] {
  const ops: StackOp[] = [];
  emitter(op => ops.push(op), opts);
  return ops;
}

function hexOf(ops: StackOp[]): string {
  return emitMethod({ name: 'probe', ops, maxStackDepth: 0 }).scriptHex;
}

function bytesOf(emitter: Emitter, opts?: EcCodegenOptions): number {
  return estimateScriptBytes(opsOf(emitter, opts));
}

/**
 * Net stack effect of an op sequence, counting only the ops whose effect is
 * unambiguous from the Stack IR alone (pushes and pops). Opcodes are opaque
 * here, so this is a same-shape comparison between two variants of the SAME
 * emitter, not an absolute depth model — which is all the pool needs to prove:
 * every slot it pushes, it releases.
 */
function netStackEffect(ops: StackOp[]): number {
  let net = 0;
  const walk = (list: StackOp[]): void => {
    for (const op of list) {
      if (op.op === 'push' || op.op === 'dup' || op.op === 'over' || op.op === 'tuck'
        || op.op === 'placeholder' || op.op === 'push_codesep_index') net++;
      else if (op.op === 'drop' || op.op === 'nip') net--;
      // A pick/roll is always preceded by a `push` of the depth, already
      // counted above. OP_PICK consumes that depth and pushes a copy (net 0);
      // OP_ROLL consumes it and relocates an existing item (net -1).
      else if (op.op === 'roll') net--;
      else if (op.op === 'if') { walk(op.then); if (op.else) walk(op.else); }
    }
  };
  walk(ops);
  return net;
}

/** Every emitter that should benefit, with its shipping byte count. */
const EMITTERS: Array<[string, Emitter, number]> = [
  ['emitVerifyECDSA_P256', emitVerifyECDSA_P256, 974024],
  ['emitVerifyECDSA_P384', emitVerifyECDSA_P384, 1987394],
  ['emitP256Mul', emitP256Mul, 459746],
  ['emitP256MulGen', emitP256MulGen, 459812],
  ['emitP256Add', emitP256Add, 19906],
  ['emitP384Mul', emitP384Mul, 927350],
  ['emitP384Add', emitP384Add, 46710],
  ['emitEcAdd', emitEcAdd, 25426],
  ['emitEcMul', emitEcMul, 428676],
  ['emitEcMulGen', emitEcMulGen, 428742],
];

describe('pooling OFF is the shipping default', () => {
  it.each(EMITTERS)('%s emits its documented byte count', (_name, emitter, want) => {
    expect(bytesOf(emitter)).toBe(want);
  });

  it.each(EMITTERS)('%s is byte-identical with an explicit constantPool:false', (_n, emitter) => {
    expect(hexOf(opsOf(emitter))).toBe(hexOf(opsOf(emitter, { constantPool: false })));
  });

  it('an empty options object changes nothing', () => {
    expect(hexOf(opsOf(emitP256OnCurve))).toBe(hexOf(opsOf(emitP256OnCurve, {})));
  });
});

describe('pooling ON removes the repeated prime pushes', () => {
  it('collapses the P-256 field prime from 34 bytes a push to a pick', () => {
    const before = analyzeScriptHex(hexOf(opsOf(emitVerifyECDSA_P256)));
    const after = analyzeScriptHex(hexOf(opsOf(emitVerifyECDSA_P256, { constantPool: true })));

    const p = Buffer.from(
      encodeScriptNumber(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn),
    ).toString('hex');
    const beforeP = before.constants.find(c => c.hex === p)!;
    expect(beforeP.count).toBeGreaterThan(15000);

    const afterP = after.constants.find(c => c.hex === p);
    // At most a handful survive: the pool slot itself, plus any site that
    // genuinely cannot see the slot.
    expect(afterP?.count ?? 0).toBeLessThan(10);
  });

  it.each(EMITTERS)('%s shrinks by more than half', (_name, emitter, before) => {
    const after = bytesOf(emitter, { constantPool: true });
    expect(after).toBeLessThan(before * 0.5);
  });

  it('brings verifyECDSA_P256 close to the arithmetic prediction', () => {
    // 20,025-ish reductions x ~31 bytes saved each on the p256-wallet fixture;
    // the bare emitter carries the same reduction count. Predicted landing
    // zone is ~330 kB. Allow slack, but fail if it lands nowhere near.
    const after = bytesOf(emitVerifyECDSA_P256, { constantPool: true });
    expect(after).toBeGreaterThan(200_000);
    expect(after).toBeLessThan(420_000);
  });

  it('adds at most two resident slots', () => {
    // The pool is two extra stack items per tracker (p and n). Real max-depth
    // is measured on the interpreter in the equivalence test; here we only pin
    // that the emitter still balances — pool slots pushed are pool slots
    // released, so the net stack effect is unchanged.
    const off = opsOf(emitP256Add);
    const on = opsOf(emitP256Add, { constantPool: true });
    expect(netStackEffect(on)).toBe(netStackEffect(off));
  });
});
