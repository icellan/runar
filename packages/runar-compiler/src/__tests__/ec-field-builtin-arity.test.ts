/**
 * R-063 — the five builtin dispatch arms that pop `args.length` stack-map
 * entries while their codegen consumes a FIXED, per-function operand count.
 *
 * In 05-stack-lower.ts these five helpers all share the same shape:
 *
 *     for (const arg of args) this.bringToTop(arg, ...);
 *     for (let i = 0; i < args.length; i++) this.stackMap.pop();
 *     switch (func) { case 'ecPointX': emitEcPointX(emitFn); break; ... }
 *
 *   1. lowerEcBuiltin        — secp256k1 (ecAdd/ecMul/.../ecPointY)
 *   2. lowerNistEcBuiltin    — NIST P-256 / P-384
 *   3. lowerBN254Builtin     — BN254 field + G1
 *   4. lowerBBFieldBuiltin   — Baby Bear field
 *   5. lowerKBFieldBuiltin   — KoalaBear field
 *
 * The emitters have a fixed documented stack contract (`emitEcPointX` =
 * "Stack in: [point]", `emitEcAdd` = "Stack in: [point_a, point_b]", ...), so
 * whenever `args.length` differs from that count the stack-map and the real
 * runtime stack part company — silently. No opcode faults; later operand loads
 * are simply computed at the wrong depth and the method epilogue's cleanup is
 * short (or long) by that many slots.
 *
 * The sixth arm with this shape, `lowerKBPoseidon2Builtin`, already guards
 * (`requires exactly 16 arguments`) — which is the wording this fix follows.
 *
 * REACHABILITY: NOT reachable from source — every one of these builtins has a
 * signature in 03-typecheck.ts, and `checkCallArgs` rejects
 * `args.length !== sig.params.length`. It IS reachable through
 * `compileFromANF` / CLI `--from-ir`, which never runs a typecheck.
 *
 * OBSERVED SYMPTOM before the guard landed (`ecPointX(p, j)` — 2 args for a
 * 1-operand emitter, against the same program compiled with `ecPointX(p)`):
 *
 *   GOOD tail: ... OP_NUMEQUALVERIFY OP_NIP OP_NIP
 *   BAD  tail: ... OP_NUMEQUALVERIFY OP_NIP          <- one cleanup NIP missing
 *
 * Same script length, no error, junk left on the stack. Reproduced identically
 * for p256Negate, bn254FieldNeg, bbFieldInv and kbFieldInv.
 */

import { describe, it, expect } from 'vitest';
import { compile, compileFromANF } from '../index.js';
import type { ANFProgram, ANFBinding } from '../ir/index.js';

const P = (name: string, type: string) => ({ name, type });

function prog(params: { name: string; type: string }[], body: ANFBinding[]): ANFProgram {
  return {
    contractName: 'ArityProbe',
    properties: [],
    methods: [{ name: 'unlock', params, body, isPublic: true }],
  };
}

/** `unlock(...) { assert(<func>(...args)) }` over the --ir path. */
function call(func: string, args: string[], params: { name: string; type: string }[]) {
  return () => compileFromANF(
    prog(params, [
      { name: 't0', value: { kind: 'call', func, args } } as unknown as ANFBinding,
      { name: 't1', value: { kind: 'call', func: 'assert', args: ['t0'] } } as unknown as ANFBinding,
    ]),
    { disableConstantFolding: true },
  );
}

const B = (n: number) => Array.from({ length: n }, (_, i) => P(`a${i}`, 'bigint'));
const REFS = (n: number) => Array.from({ length: n }, (_, i) => `a${i}`);

/**
 * One representative per arm, with the arity its emitter actually consumes.
 * `arm` names the dispatch helper the case exercises.
 */
const CASES: { arm: string; func: string; arity: number; params: { name: string; type: string }[] }[] = [
  { arm: 'lowerEcBuiltin', func: 'ecPointX', arity: 1, params: [P('a0', 'Point')] },
  { arm: 'lowerEcBuiltin', func: 'ecAdd', arity: 2, params: [P('a0', 'Point'), P('a1', 'Point')] },
  { arm: 'lowerNistEcBuiltin', func: 'p256Negate', arity: 1, params: [P('a0', 'P256Point')] },
  { arm: 'lowerNistEcBuiltin', func: 'p384Add', arity: 2, params: [P('a0', 'P384Point'), P('a1', 'P384Point')] },
  { arm: 'lowerBN254Builtin', func: 'bn254FieldNeg', arity: 1, params: B(1) },
  { arm: 'lowerBN254Builtin', func: 'bn254FieldAdd', arity: 2, params: B(2) },
  { arm: 'lowerBBFieldBuiltin', func: 'bbFieldInv', arity: 1, params: B(1) },
  { arm: 'lowerBBFieldBuiltin', func: 'bbExt4Inv0', arity: 4, params: B(4) },
  { arm: 'lowerKBFieldBuiltin', func: 'kbFieldInv', arity: 1, params: B(1) },
  { arm: 'lowerKBFieldBuiltin', func: 'kbExt4Inv0', arity: 4, params: B(4) },
];

describe('R-063: fixed-arity EC / field builtins', () => {
  describe('reachability: the source pipeline already rejects wrong arity', () => {
    it.each([
      ['ecPointX', 'ecPointX(x, x)', 1, 2],
      ['bn254FieldAdd', 'bn254FieldAdd(x)', 2, 1],
      ['kbFieldInv', 'kbFieldInv(x, x)', 1, 2],
    ])('%s: typecheck reports the arity error', (func, expr, expected, got) => {
      const src = `
import { SmartContract, assert, ${func} } from 'runar-lang';
export class Probe extends SmartContract {
  constructor() { super(); }
  public unlock(x: bigint): void {
    assert(${expr} === 1n);
  }
}`;
      const messages = compile(src, { fileName: 'Probe.runar.ts' }).diagnostics.map(d => d.message).join('\n');
      expect(messages).toMatch(
        new RegExp(`${func}\\(\\) expects ${expected} argument\\(s\\), got ${got}`),
      );
    });
  });

  describe('the --ir path (compileFromANF) must reject wrong arity too', () => {
    it.each(CASES)('$arm / $func rejects $arity+1 arguments', ({ func, arity, params }) => {
      const extra = [...params, P(`a${params.length}`, 'bigint')];
      expect(call(func, REFS(arity + 1), extra)).toThrow(
        new RegExp(`${func} requires exactly ${arity} argument`),
      );
    });

    it.each(CASES)('$arm / $func rejects $arity-1 arguments', ({ func, arity, params }) => {
      expect(call(func, REFS(arity - 1), params)).toThrow(
        new RegExp(`${func} requires exactly ${arity} argument`),
      );
    });
  });

  describe('controls: correct-arity calls compile byte-unchanged', () => {
    // sha256 of the emitted locking-script hex, captured before the guard
    // landed. A moved digest means the guard changed codegen — it must not.
    //
    // The four EC digests were RE-STAMPED for R-052 / CL-BUG-095 (the Point
    // width gate), which deliberately moves those four primitives' bytes. The
    // five non-EC digests below are the CONTROL and are byte-unchanged, which
    // is the evidence that the width gate stayed inside the EC / P-256 / P-384
    // families and did not leak into bn254 / BabyBear / KoalaBear codegen.
    const BASELINE: Record<string, string> = {
      // R-053 / CL-BUG-096 re-stamped ONLY the two adder digests. ecPointX and
      // p384Negate below were unchanged then, which was the control: the
      // infinity select lives inside affineAdd and must not reach any other
      // emitter.
      //
      // R-117 (the coordinate-canonicity gate) re-stamps THREE: ecAdd, p256Add
      // and p384Negate. p384Negate moves this time BECAUSE the gate is on every
      // value-producing consumer of a Point, negation included — it is only the
      // infinity select that was confined to the adders. ecPointX is the
      // control that still must NOT move: byte accessors are deliberately
      // ungated, because each returns a value derived injectively from the
      // bytes it was handed and so has no selector for a non-canonical
      // coordinate to fool. The five non-EC digests below stay the CONTROL that
      // nothing leaked into bn254 / BabyBear / KoalaBear codegen.
      //
      // R-119 (the field-element canonicity gate) re-stamps exactly the THREE
      // BabyBear / KoalaBear digests — bbFieldAdd, bbExt4Inv0 and kbFieldInv —
      // because the gate is one `<0> <p> OP_WITHIN OP_VERIFY` per witness
      // operand on those builtins' public entry points. The two bn254 FIELD
      // digests are the control that went the other way and must NOT move:
      // R-141 landed in the same branch and touched only the G1 POINT
      // builtins, so bn254FieldAdd / bn254FieldNeg are the evidence that the
      // coordinate gate stayed off the field surface. The four EC digests are
      // likewise unchanged by both.
      ecAdd: '98a71715a649bbb34b70882213d7588ef1d44b44279bbffe3d72263d99e1ba2a',
      ecPointX: '4579847d2e40a84e69f14ae1f87da077e6937a0aa405d93a0e309cd2edd8c191',
      p256Add: '6fd2d8ea132fedaa3ab9ce31bcb0c80a91b5053849f5e15a5dabd8a2ed6c1399',
      p384Negate: 'd776c22a2e492f48539119a6543c2421633807c2d953c961ce9c30364f1cb8a3',
      bn254FieldAdd: 'fe9e984bb631a254e07b304b081a5cc3b0ebe6394302ef48c52e27340c75ca97',
      bn254FieldNeg: '354ac5ea0ab4cb6d88ec17b91b1ae01cc58428414b1f32994e803e93d4457d4e',
      bbFieldAdd: '315257826b086e89f32e63a39807c7b8c6ef936cebedc776bad99c092288b1e9',
      bbExt4Inv0: 'e9996b756bae7b44bcf76eeecc7e1823363a57d486fca5f29440679b10a8ed59',
      kbFieldInv: 'bf76a8b2434ba6a2a36de161e78e55e0d67aca72ee758aed2ec2f89c156d0d28',
    };

    const CONTROLS: { func: string; args: string[]; params: { name: string; type: string }[] }[] = [
      { func: 'ecAdd', args: ['p', 'q'], params: [P('p', 'Point'), P('q', 'Point')] },
      { func: 'ecPointX', args: ['p'], params: [P('p', 'Point')] },
      { func: 'p256Add', args: ['p', 'q'], params: [P('p', 'P256Point'), P('q', 'P256Point')] },
      { func: 'p384Negate', args: ['p'], params: [P('p', 'P384Point')] },
      { func: 'bn254FieldAdd', args: ['a', 'b'], params: [P('a', 'bigint'), P('b', 'bigint')] },
      { func: 'bn254FieldNeg', args: ['a'], params: [P('a', 'bigint')] },
      { func: 'bbFieldAdd', args: ['a', 'b'], params: [P('a', 'bigint'), P('b', 'bigint')] },
      { func: 'bbExt4Inv0', args: ['a', 'b', 'c', 'd'], params: ['a', 'b', 'c', 'd'].map(n => P(n, 'bigint')) },
      { func: 'kbFieldInv', args: ['a'], params: [P('a', 'bigint')] },
    ];

    it.each(CONTROLS)('$func', async ({ func, args, params }) => {
      const { createHash } = await import('node:crypto');
      const { scriptHex } = call(func, args, params)();
      expect(createHash('sha256').update(scriptHex).digest('hex')).toBe(BASELINE[func]);
    });

    it('poseidon2KBPermute keeps its pre-existing exact-arity guard', () => {
      expect(call('poseidon2KBPermute', REFS(15), B(15))).toThrow(
        /poseidon2KBPermute requires exactly 16 arguments, got 15/,
      );
    });
  });
});
