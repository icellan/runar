/**
 * EC codegen — secp256k1 elliptic curve operations for Bitcoin Script.
 *
 * Follows the slh-dsa-codegen.ts pattern: self-contained module imported by
 * 05-stack-lower.ts. Uses an ECTracker (similar to SLHTracker) for named
 * stack state tracking.
 *
 * Point representation: 64 bytes (x[32] || y[32], big-endian unsigned).
 * Internal arithmetic uses Jacobian coordinates for scalar multiplication.
 */

import type { StackOp } from '../ir/index.js';
import { stackDelta } from './stack-op-effects.js';

// ===========================================================================
// Constants
// ===========================================================================

/** secp256k1 field prime p = 2^256 - 2^32 - 977 */
const FIELD_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
/** p - 2, used for Fermat's little theorem modular inverse */
const FIELD_P_MINUS_2 = FIELD_P - 2n;
/** secp256k1 curve order */
const CURVE_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
/** secp256k1 generator x-coordinate */
const GEN_X = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
/** secp256k1 generator y-coordinate */
const GEN_Y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

function bigintToBytes32(n: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

// ===========================================================================
// ECTracker — named stack state tracker (mirrors SLHTracker)
// ===========================================================================

/**
 * R-285 (CL-GAP-075) — check an `emitIf` branch against what it claims to leave.
 *
 * The tracker updates `nm` from the CALLER's `resultName` argument: one name
 * pushed, or none. Nothing verified that against the opcodes the two arms
 * actually emit, so a `resultName` that disagreed with the arms — or two arms
 * that disagreed with each other — desynchronised the model from the real
 * stack. Every `findDepth` after that point returns a depth that is wrong by
 * the same amount, and PICK/ROLL silently address the wrong item: a different
 * locking script, not a compile error. The secp256k1 ladder runs this path 257
 * times per `ecMul`, and the P-256/P-384 and BN254 codegens reuse it.
 *
 * Both arms must leave the same depth, and that depth must be the one
 * `resultName` promises: +1 for a named result, 0 for none.
 */
function assertArmsMatchDeclaredResult(
  thenOps: StackOp[],
  elseOps: StackOp[],
  resultName: string | null,
): void {
  const expected = resultName === null ? 0 : 1;
  const thenDelta = stackDelta(thenOps);
  const elseDelta = stackDelta(elseOps);
  if (thenDelta !== elseDelta) {
    throw new Error(
      `ECTracker.emitIf: branch arms leave different stack depths ` +
      `(then ${thenDelta}, else ${elseDelta})`,
    );
  }
  if (thenDelta !== expected) {
    throw new Error(
      `ECTracker.emitIf: arms leave ${thenDelta} item(s) but the branch declares ` +
      `${resultName === null ? 'no result' : `result '${resultName}'`} (${expected})`,
    );
  }
}

export class ECTracker {
  nm: (string | null)[];
  _e: (op: StackOp) => void;

  constructor(init: (string | null)[], emit: (op: StackOp) => void) {
    this.nm = [...init];
    this._e = emit;
  }

  get depth(): number { return this.nm.length; }

  findDepth(name: string): number {
    for (let i = this.nm.length - 1; i >= 0; i--)
      if (this.nm[i] === name)
        return this.nm.length - 1 - i;
    throw new Error(`ECTracker: '${name}' not on stack [${this.nm.join(',')}]`);
  }

  pushBytes(n: string, v: Uint8Array): void { this._e({ op: 'push', value: v }); this.nm.push(n); }
  pushInt(n: string, v: bigint): void { this._e({ op: 'push', value: v }); this.nm.push(n); }
  dup(n: string): void { this._e({ op: 'dup' }); this.nm.push(n); }
  drop(): void { this._e({ op: 'drop' }); this.nm.pop(); }
  nip(): void {
    this._e({ op: 'nip' });
    const L = this.nm.length;
    if (L >= 2) this.nm.splice(L - 2, 1);
  }
  over(n: string): void { this._e({ op: 'over' }); this.nm.push(n); }
  swap(): void {
    this._e({ op: 'swap' });
    const L = this.nm.length;
    if (L >= 2) {
      const t = this.nm[L - 1];
      this.nm[L - 1] = this.nm[L - 2]!;
      this.nm[L - 2] = t!;
    }
  }
  rot(): void {
    this._e({ op: 'rot' });
    const L = this.nm.length;
    if (L >= 3) {
      const r = this.nm.splice(L - 3, 1)[0]!;
      this.nm.push(r);
    }
  }
  op(code: string): void { this._e({ op: 'opcode', code }); }
  roll(d: number): void {
    if (d === 0) return;
    if (d === 1) { this.swap(); return; }
    if (d === 2) { this.rot(); return; }
    this._e({ op: 'push', value: BigInt(d) });
    this.nm.push(null);
    this._e({ op: 'roll', depth: d });
    this.nm.pop();
    const idx = this.nm.length - 1 - d;
    const r = this.nm.splice(idx, 1)[0] ?? null;
    this.nm.push(r);
  }
  pick(d: number, n: string): void {
    if (d === 0) { this.dup(n); return; }
    if (d === 1) { this.over(n); return; }
    this._e({ op: 'push', value: BigInt(d) });
    this.nm.push(null);
    this._e({ op: 'pick', depth: d });
    this.nm.pop();
    this.nm.push(n);
  }
  toTop(name: string): void { this.roll(this.findDepth(name)); }
  copyToTop(name: string, n?: string): void { this.pick(this.findDepth(name), n ?? name); }
  toAlt(): void { this.op('OP_TOALTSTACK'); this.nm.pop(); }
  fromAlt(n: string): void { this.op('OP_FROMALTSTACK'); this.nm.push(n); }
  rename(n: string): void {
    if (this.nm.length > 0)
      this.nm[this.nm.length - 1] = n;
  }

  /** Emit raw opcodes tracking only net stack effect. */
  rawBlock(consume: string[], produce: string | null, fn: (e: (op: StackOp) => void) => void): void {
    for (let i = consume.length - 1; i >= 0; i--)
      this.nm.pop();
    fn(this._e);
    if (produce !== null)
      this.nm.push(produce);
  }

  /** Emit if/else with tracked stack effect. */
  emitIf(condName: string, thenFn: (e: (op: StackOp) => void) => void, elseFn: (e: (op: StackOp) => void) => void, resultName: string | null): void {
    this.toTop(condName);
    this.nm.pop(); // condition consumed
    const thenOps: StackOp[] = [];
    const elseOps: StackOp[] = [];
    thenFn((op) => thenOps.push(op));
    elseFn((op) => elseOps.push(op));
    assertArmsMatchDeclaredResult(thenOps, elseOps, resultName);
    this._e({ op: 'if', then: thenOps, else: elseOps });
    if (resultName !== null)
      this.nm.push(resultName);
  }
}

// ===========================================================================
// Field arithmetic helpers
// ===========================================================================

/** Push the field prime p onto the stack as a script number. */
function pushFieldP(t: ECTracker, name: string): void {
  // Push p directly as a BigInt — the emit pass encodes it as a proper
  // little-endian sign-magnitude script number push.
  t.pushInt(name, FIELD_P);
}

/**
 * Reduce a scalar to [0, n-1]: ((k mod n) + n) mod n.
 *
 * OP_MOD takes the sign of the DIVIDEND, so `k mod n` alone lands in (-n, n);
 * the `+ n, mod n` normalises the negative half. One push of n covers both
 * reductions — the same shape as `emitEcModReduce`.
 *
 * Without it, `emitEcMul`'s ladder is only correct while 2^257 <= k + 3n < 2^258:
 * a scalar >= ~n sets bit 258, the 257-iteration loop never sees it, and the
 * ladder returns a DIFFERENT multiple of P rather than failing. Scalars are
 * contract input, so that is attacker-chosen. Reducing costs 1 push + 7 opcodes
 * (41 bytes) against a ~429 KB script, and makes k >= n, k < 0 and k = 0 all
 * well defined.
 */
function emitScalarReduce(t: ECTracker, kName: string, resultName: string): void {
  t.pushInt('_n_red', CURVE_N);
  t.rawBlock([kName, '_n_red'], resultName, (e) => {
    e({ op: 'opcode', code: 'OP_2DUP' });
    e({ op: 'opcode', code: 'OP_MOD' });
    e({ op: 'rot' });
    e({ op: 'drop' });
    e({ op: 'over' });
    e({ op: 'opcode', code: 'OP_ADD' });
    e({ op: 'swap' });
    e({ op: 'opcode', code: 'OP_MOD' });
  });
}

/**
 * fieldMod: reduce TOS mod p, ensure non-negative.
 * Expects 'aName' to be on the tracker stack.
 */
function fieldMod(t: ECTracker, aName: string, resultName: string): void {
  t.toTop(aName);
  pushFieldP(t, '_fmod_p');
  // (a % p + p) % p
  t.rawBlock([aName, '_fmod_p'], resultName, (e) => {
    e({ op: 'opcode', code: 'OP_2DUP' }); // a p a p
    e({ op: 'opcode', code: 'OP_MOD' });   // a p (a%p)
    e({ op: 'rot' });                       // p (a%p) a
    e({ op: 'drop' });                      // p (a%p)
    e({ op: 'over' });                      // p (a%p) p
    e({ op: 'opcode', code: 'OP_ADD' });    // p (a%p+p)
    e({ op: 'swap' });                      // (a%p+p) p
    e({ op: 'opcode', code: 'OP_MOD' });    // ((a%p+p)%p)
  });
}

/** fieldAdd: (a + b) mod p */
function fieldAdd(t: ECTracker, aName: string, bName: string, resultName: string): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_fadd_sum', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  fieldMod(t, '_fadd_sum', resultName);
}

/** fieldSub: (a - b) mod p (non-negative) */
function fieldSub(t: ECTracker, aName: string, bName: string, resultName: string): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_fsub_diff', (e) => {
    e({ op: 'opcode', code: 'OP_SUB' });
  });
  fieldMod(t, '_fsub_diff', resultName);
}

/** fieldMul: (a * b) mod p */
function fieldMul(t: ECTracker, aName: string, bName: string, resultName: string): void {
  t.toTop(aName);
  t.toTop(bName);
  t.rawBlock([aName, bName], '_fmul_prod', (e) => {
    e({ op: 'opcode', code: 'OP_MUL' });
  });
  fieldMod(t, '_fmul_prod', resultName);
}

/** fieldMulConst: (a * c) mod p where c is a small constant. Uses OP_2MUL for c=2. */
function fieldMulConst(t: ECTracker, aName: string, c: bigint, resultName: string): void {
  t.toTop(aName);
  t.rawBlock([aName], '_fmc_prod', (e) => {
    if (c === 2n) {
      e({ op: 'opcode', code: 'OP_2MUL' });
    } else {
      e({ op: 'push', value: c });
      e({ op: 'opcode', code: 'OP_MUL' });
    }
  });
  fieldMod(t, '_fmc_prod', resultName);
}

/** fieldSqr: (a * a) mod p */
function fieldSqr(t: ECTracker, aName: string, resultName: string): void {
  t.copyToTop(aName, '_fsqr_copy');
  fieldMul(t, aName, '_fsqr_copy', resultName);
}

/**
 * fieldInv: a^(p-2) mod p via square-and-multiply.
 * Consumes aName from the tracker.
 */
function fieldInv(t: ECTracker, aName: string, resultName: string): void {
  // p-2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
  // Bits 255..32: 224 bits, all 1 except bit 32 which is 0
  // Bits 31..0: 0xFFFFFC2D

  // Start: result = a (bit 255 = 1)
  t.copyToTop(aName, '_inv_r');
  // Bits 254 down to 33: all 1's (222 bits). Bit 32 is 0 (handled below).
  for (let i = 0; i < 222; i++) {
    fieldSqr(t, '_inv_r', '_inv_r2');
    t.rename('_inv_r');
    t.copyToTop(aName, '_inv_a');
    fieldMul(t, '_inv_r', '_inv_a', '_inv_m');
    t.rename('_inv_r');
  }
  // Bit 32 is 0: square only (no multiply)
  fieldSqr(t, '_inv_r', '_inv_r2');
  t.rename('_inv_r');
  // Bits 31 down to 0 of p-2
  const lowBits = Number(FIELD_P_MINUS_2 & 0xffffffffn);
  for (let i = 31; i >= 0; i--) {
    fieldSqr(t, '_inv_r', '_inv_r2');
    t.rename('_inv_r');
    if ((lowBits >> i) & 1) {
      t.copyToTop(aName, '_inv_a');
      fieldMul(t, '_inv_r', '_inv_a', '_inv_m');
      t.rename('_inv_r');
    }
  }
  // Clean up original input and rename result
  t.toTop(aName);
  t.drop();
  t.toTop('_inv_r');
  t.rename(resultName);
}

// ===========================================================================
// Point decompose / compose
// ===========================================================================

/**
 * CL-BUG-095 — length gate for a `Point` argument, ABORTING form.
 *
 * A `Point` is DEFINED as exactly `want` bytes (x ‖ y, big-endian, no prefix).
 * Nothing checked that: `Point` carries no width in the builtin table, and
 * every one of these values arrives as an unlock argument, so the blob is
 * attacker-sized. Surplus bytes were then silently DISCARDED, because
 * `decomposePoint` splits at the coordinate width and `emitReverse32` reverses
 * exactly 32 bytes and drops whatever is left over — so `ecOnCurve(G ‖ 0xff)`
 * returned TRUE and `ecEncodeCompressed` took its parity bit from the surplus.
 *
 * This is NOT a new failure channel. An UNDER-length point already aborted, by
 * accident: `OP_SPLIT` runs off the end of the value. The gate makes the same
 * outcome explicit, and extends it to the over-length case that used to pass.
 *
 * Aborting is right for every Point consumer that produces a VALUE and has no
 * error channel to report through — `ecAdd`, `ecMul`, `ecNegate`, `ecPointX`,
 * `ecPointY`, `ecEncodeCompressed`. There is no correct value to return for a
 * blob that is not a point. The PREDICATES (`ecOnCurve` and friends) use
 * `emitPointLengthGate` below instead, because for them "no" is an answer.
 */
export function emitPointLenVerify(e: (op: StackOp) => void, want: number): void {
  e({ op: 'opcode', code: 'OP_SIZE' });
  e({ op: 'push', value: BigInt(want) });
  e({ op: 'opcode', code: 'OP_NUMEQUALVERIFY' });
}

/**
 * CL-BUG-095 — length gate for a `Point` argument, CLAMPING form: leaves
 * `[flag, clamped]`, where `clamped` is the value forced to exactly `want`
 * bytes (`v ‖ 00*want` split at `want`, tail dropped) and `flag` is
 * `OP_SIZE(v) == want`.
 *
 * Same shape, and the same reasoning, as `cEmitLengthGate` in
 * p256-p384-codegen.ts: the clamp exists so the gate can stay a FLAG. It is
 * used by the on-curve predicates, whose whole job is to answer "is this an
 * acceptable point?" over untrusted bytes — and for a wrong-length blob the
 * correct answer is `false`, not an aborted script. Aborting would break
 * `if (ecOnCurve(p)) { … } else { … }`, which is the exact idiom this module's
 * own comments tell contract authors to write. The caller ANDs `flag` into its
 * boolean result, so whatever the clamped bytes happen to compute can never
 * make a wrong-length point certify as on-curve.
 *
 * Branch-free: the emitted op sequence, and the tracker's static stack model,
 * are identical for every input length.
 */
export function emitPointLengthGate(t: ECTracker, name: string, want: number, flagName: string): void {
  t.toTop(name);
  t.rawBlock([name], null, (e) => {
    e({ op: 'opcode', code: 'OP_SIZE' });
    e({ op: 'push', value: BigInt(want) });
    e({ op: 'opcode', code: 'OP_NUMEQUAL' });
    e({ op: 'swap' });
    e({ op: 'push', value: new Uint8Array(want) });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'push', value: BigInt(want) });
    e({ op: 'opcode', code: 'OP_SPLIT' });
    e({ op: 'drop' });
  });
  t.nm.push(flagName);
  t.nm.push(name);
}

/**
 * R-117 — a Point's two coordinates must be FIELD ELEMENTS, aborting form.
 *
 * `decomposePoint` BIN2NUMs each half of the blob as an unsigned integer, so
 * any value that fits in the coordinate width is accepted — `x + p` included,
 * whenever `x + p < 2^256` (on secp256k1 that is every `x < 2^32 + 977`).
 * Downstream field arithmetic reduces mod p, so `(x+p) ‖ y` behaves as the
 * point `(x, y)`; `affineAdd`'s two case selectors do NOT reduce, and they are
 * bare OP_NUMEQUAL on exactly these raw values:
 *
 *     cond   = (px == qx) AND (py == qy)      "same point" -> tangent
 *     notinf = NOT(px == qx AND NOT cond)     "P and -P"   -> the O mask
 *
 * so for P and its alias both read 0, the chord path runs on two equal points,
 * `den_chord = qx - px ≡ 0 (mod p)`, and `fieldInv` is Fermat with inv(0) = 0.
 * Measured before this gate landed, x = 1: `ecAdd(P, P)` gave the correct 2P
 * and `ecAdd(P, P')` gave x = p-2 — a script that SUCCEEDED and returned a
 * blob that is not a point. Both the doubling case and the P + (-P) case are
 * driven by these selectors, so both are defeated by the same trick.
 *
 * REJECT rather than reduce. `ecOnCurve` already answers "no" to a
 * non-canonical encoding (GAP-301, and its P-256/P-384 twin), so reducing here
 * would leave the predicate and the value builtins disagreeing about whether
 * the blob is a point at all. Rejecting keeps them aligned, and it is the
 * policy CL-BUG-095 already set for the WIDTH: predicates clamp and flag,
 * value producers OP_VERIFY.
 *
 * Callers are the user-facing value builtins only. It is deliberately NOT
 * folded into `decomposePoint`: that helper also runs inside `ecOnCurve`,
 * which must stay total.
 *
 * `x` and `y` are unsigned by construction (BIN2NUM of a sign-extended
 * big-endian blob), so `< p` is the whole check; no lower bound is needed.
 */
function emitCoordCanonVerify(t: ECTracker, xName: string, yName: string): void {
  t.copyToTop(xName, '_cc_x');
  pushFieldP(t, '_cc_px');
  t.rawBlock(['_cc_x', '_cc_px'], '_cc_xok', (e) => {
    e({ op: 'opcode', code: 'OP_LESSTHAN' });
  });
  t.copyToTop(yName, '_cc_y');
  pushFieldP(t, '_cc_py');
  t.rawBlock(['_cc_y', '_cc_py'], '_cc_yok', (e) => {
    e({ op: 'opcode', code: 'OP_LESSTHAN' });
  });
  t.rawBlock(['_cc_xok', '_cc_yok'], null, (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
    e({ op: 'opcode', code: 'OP_VERIFY' });
  });
}

/**
 * Decompose 64-byte Point → (x_num, y_num) on stack.
 * Consumes pointName, produces xName and yName.
 */
function decomposePoint(t: ECTracker, pointName: string, xName: string, yName: string): void {
  t.toTop(pointName);
  // OP_SPLIT at 32 produces x_bytes (bottom) and y_bytes (top) — but only for
  // a value that really is 64 bytes. CL-BUG-095: gate the width first, here,
  // so every consumer that decomposes a Point inherits the check.
  t.rawBlock([pointName], null, (e) => {
    emitPointLenVerify(e, 64);
    e({ op: 'push', value: 32n });
    e({ op: 'opcode', code: 'OP_SPLIT' });
  });
  // Manually track the two new items
  t.nm.push('_dp_xb');
  t.nm.push('_dp_yb');

  // Convert y_bytes (on top) to num
  // Reverse from BE to LE, append 0x00 sign byte to ensure unsigned, then BIN2NUM
  t.rawBlock(['_dp_yb'], yName, (e) => {
    emitReverse32(e);
    e({ op: 'push', value: new Uint8Array([0x00]) });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'opcode', code: 'OP_BIN2NUM' });
  });

  // Convert x_bytes to num
  t.toTop('_dp_xb');
  t.rawBlock(['_dp_xb'], xName, (e) => {
    emitReverse32(e);
    e({ op: 'push', value: new Uint8Array([0x00]) });
    e({ op: 'opcode', code: 'OP_CAT' });
    e({ op: 'opcode', code: 'OP_BIN2NUM' });
  });

  // Stack: [yName, xName] — swap to standard order [xName, yName]
  t.swap();
}

/**
 * Compose (x_num, y_num) → 64-byte Point.
 * Consumes xName and yName, produces resultName.
 */
function composePoint(t: ECTracker, xName: string, yName: string, resultName: string): void {
  // Convert x to 32-byte big-endian
  // Use NUM2BIN(33) to accommodate the sign byte, then drop the last byte
  t.toTop(xName);
  t.rawBlock([xName], '_cp_xb', (e) => {
    e({ op: 'push', value: 33n });
    e({ op: 'opcode', code: 'OP_NUM2BIN' });
    // Drop the sign byte (last byte) — split at 32, keep left
    e({ op: 'push', value: 32n });
    e({ op: 'opcode', code: 'OP_SPLIT' });
    e({ op: 'drop' });
    emitReverse32(e);
  });

  // Convert y to 32-byte big-endian
  t.toTop(yName);
  t.rawBlock([yName], '_cp_yb', (e) => {
    e({ op: 'push', value: 33n });
    e({ op: 'opcode', code: 'OP_NUM2BIN' });
    e({ op: 'push', value: 32n });
    e({ op: 'opcode', code: 'OP_SPLIT' });
    e({ op: 'drop' });
    emitReverse32(e);
  });

  // Cat: x_be || y_be (x is below y after the two toTop calls)
  t.toTop('_cp_xb');
  t.toTop('_cp_yb');
  t.rawBlock(['_cp_xb', '_cp_yb'], resultName, (e) => {
    e({ op: 'opcode', code: 'OP_CAT' });
  });
}

/**
 * Emit inline byte reversal for a 32-byte value on TOS.
 * After: reversed 32-byte value on TOS.
 */
function emitReverse32(e: (op: StackOp) => void): void {
  // Push empty accumulator, swap with data
  e({ op: 'opcode', code: 'OP_0' });
  e({ op: 'swap' });
  // 32 iterations: peel first byte, prepend to accumulator
  for (let i = 0; i < 32; i++) {
    // Stack: [accum, remaining]
    e({ op: 'push', value: 1n });
    e({ op: 'opcode', code: 'OP_SPLIT' });
    // Stack: [accum, byte0, rest]
    e({ op: 'rot' });
    // Stack: [byte0, rest, accum]
    e({ op: 'rot' });
    // Stack: [rest, accum, byte0]
    e({ op: 'swap' });
    // Stack: [rest, byte0, accum]
    e({ op: 'opcode', code: 'OP_CAT' });
    // Stack: [rest, byte0||accum]
    e({ op: 'swap' });
    // Stack: [byte0||accum, rest]
  }
  // Stack: [reversed, empty]
  e({ op: 'drop' });
}

// ===========================================================================
// Affine point addition (for ecAdd)
// ===========================================================================

/**
 * Affine point addition: expects px, py, qx, qy on tracker.
 * Produces rx, ry. Consumes all four inputs.
 */
function affineAdd(t: ECTracker): void {
  // The chord slope s = (qy - py) / (qx - px) is undefined when P == Q: the
  // denominator is zero and the correct slope is the TANGENT, 3px^2 / (2py).
  // Without this, ecAdd(P, P) silently produced a wrong point, so every
  // contract that doubled deployed an unspendable script — byte-identically
  // across all seven tiers, because they all shared the same omission.
  //
  // Both cases are the same shape, `s = num / den`, so only the NUMERATOR and
  // DENOMINATOR are selected; the single expensive fieldInv is still performed
  // exactly once. rx = s^2 - px - qx and ry = s*(px - rx) - py are already
  // correct for doubling (px == qx makes the first s^2 - 2px).
  //
  //   cond   = (px == qx) AND (py == qy)     1 when doubling, else 0
  //   num    = cond ? 3*px^2 : (qy - py)
  //   den    = cond ? 2*py   : (qx - px)
  //
  // selected as `b + cond*(a - b)` over the field, which needs no branch and
  // so keeps the emitted op sequence — and the tracker's static stack model —
  // identical on both paths.
  //
  // THE THIRD CASE, P == -Q: px == qx but py != qy. Testing px == qx ALONE
  // sends it down the tangent path and returns 2P — an on-curve, entirely
  // plausible, WRONG point. Before the doubling fix the chord path ran there,
  // divided by zero (fieldInv is Fermat, inv(0) = 0) and produced an OFF-curve
  // blob, so `assert(ecOnCurve(ecAdd(a, b)))` — the idiom this codegen tells
  // authors to write — happened to reject it. Selecting on px alone would have
  // silently disarmed that.
  //
  // P + (-P) is the point at infinity, which affine x||y cannot represent. This
  // codegen already has a representation for O: the ALL-ZERO blob, which is
  // what `ecMul(P, 0n)` returns and what the `ec-mulgen-linear` rewrite in
  // optimizer/ec-rules.json produces for k1 + k2 ≡ 0 (mod n). So return that,
  // by masking the result with `notinf = NOT(px == qx AND NOT cond)`:
  //
  //   - it agrees with the rewrite, so the same source cannot give two answers
  //     depending on whether the optimizer fired;
  //   - O is not on the curve (0^2 != 0^3 + 7), so the on-curve gate rejects it
  //     and the idiom above works again;
  //   - it adds no failure channel to what is a pure value-producing
  //     expression, the same reason emitScalarReduce reduces instead of
  //     rejecting.
  //
  // The mask is a bare OP_MUL with no reduction: rx, ry are already in [0, p)
  // and notinf is 0 or 1, so the product is canonical either way.
  t.copyToTop('px', '_px_eq');
  t.copyToTop('qx', '_qx_eq');
  t.rawBlock(['_px_eq', '_qx_eq'], '_xeq', (e) => {
    e({ op: 'opcode', code: 'OP_NUMEQUAL' });
  });
  t.copyToTop('py', '_py_eq');
  t.copyToTop('qy', '_qy_eq');
  t.rawBlock(['_py_eq', '_qy_eq'], '_yeq', (e) => {
    e({ op: 'opcode', code: 'OP_NUMEQUAL' });
  });
  t.copyToTop('_xeq', '_xeq_c');
  t.toTop('_yeq');
  t.rawBlock(['_xeq_c', '_yeq'], '_cond', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });
  // notinf = NOT(xeq - cond): xeq - cond is 1 exactly when px == qx and the
  // points are not equal, i.e. exactly the P == -Q case.
  t.toTop('_xeq');
  t.copyToTop('_cond', '_cond_c');
  t.rawBlock(['_xeq', '_cond_c'], '_notinf', (e) => {
    e({ op: 'opcode', code: 'OP_SUB' });
    e({ op: 'opcode', code: 'OP_NOT' });
  });

  // chord numerator / denominator
  t.copyToTop('qy', '_qy1');
  t.copyToTop('py', '_py1');
  fieldSub(t, '_qy1', '_py1', '_num_chord');
  t.copyToTop('qx', '_qx1');
  t.copyToTop('px', '_px1');
  fieldSub(t, '_qx1', '_px1', '_den_chord');

  // tangent numerator / denominator: 3*px^2 and 2*py
  t.copyToTop('px', '_px_t');
  fieldSqr(t, '_px_t', '_px_sq');
  fieldMulConst(t, '_px_sq', 3n, '_num_tan');
  t.copyToTop('py', '_py_t');
  fieldMulConst(t, '_py_t', 2n, '_den_tan');

  // num = num_chord + cond*(num_tan - num_chord)
  t.copyToTop('_num_chord', '_num_chord_c');
  fieldSub(t, '_num_tan', '_num_chord_c', '_num_diff');
  t.copyToTop('_cond', '_cond_n');
  fieldMul(t, '_num_diff', '_cond_n', '_num_sel');
  fieldAdd(t, '_num_chord', '_num_sel', '_s_num');

  // den = den_chord + cond*(den_tan - den_chord)
  t.copyToTop('_den_chord', '_den_chord_c');
  fieldSub(t, '_den_tan', '_den_chord_c', '_den_diff');
  t.toTop('_cond');
  t.rename('_cond_d');
  fieldMul(t, '_den_diff', '_cond_d', '_den_sel');
  fieldAdd(t, '_den_chord', '_den_sel', '_s_den');

  // s = s_num / s_den mod p
  fieldInv(t, '_s_den', '_s_den_inv');
  fieldMul(t, '_s_num', '_s_den_inv', '_s');

  // rx = s² - px - qx mod p
  t.copyToTop('_s', '_s_keep');
  fieldSqr(t, '_s', '_s2');
  t.copyToTop('px', '_px2');
  fieldSub(t, '_s2', '_px2', '_rx1');
  t.copyToTop('qx', '_qx2');
  fieldSub(t, '_rx1', '_qx2', 'rx');

  // ry = s * (px - rx) - py mod p
  t.copyToTop('px', '_px3');
  t.copyToTop('rx', '_rx2');
  fieldSub(t, '_px3', '_rx2', '_px_rx');
  fieldMul(t, '_s_keep', '_px_rx', '_s_px_rx');
  t.copyToTop('py', '_py2');
  fieldSub(t, '_s_px_rx', '_py2', 'ry');

  // CL-BUG-096: select over the infinity operands and the P == -Q case, and
  // consume px/py/qx/qy in doing so. This subsumes the standalone `notinf`
  // mask that used to live here. See emitAffineInfinitySelect.
  emitAffineInfinitySelect(t);
}

/**
 * CL-BUG-096 — the infinity-operand case of affine addition, shared by
 * secp256k1 and the two NIST curves because it is pure integer masking and
 * touches no field parameter.
 *
 * The group law has an identity, and this codegen has a representation for it:
 * the ALL-ZERO blob. It is not a theoretical value — the codegen MANUFACTURES
 * it, from `ecMul(P, k)` whenever k ≡ 0 (mod n), from affineAdd's own P + (−P)
 * masking, and from the `ec-mul-zero` / `ec-add-negate-cancel` rewrites in
 * optimizer/ec-rules.json. `affineAdd` nonetheless had no case for it: fed
 * (G, O) it took the chord path with s = Gy/Gx and returned an off-curve blob
 * from a script that SUCCEEDED.
 *
 * And the always-on EC optimizer already believed the right answer:
 * `ec-add-identity-right` / `-left` rewrite `ecAdd($x, INFINITY)` to `$x`. So
 * the same source meant "P" with the optimizer on and "garbage" with it off.
 * Fixing the adder rather than deleting the two rules is the only option that
 * works, because the rules cannot see a zero scalar that only exists at
 * runtime — deleting them would leave the runtime path just as wrong and
 * rewrite nothing.
 *
 * Branch-free, in the style the rest of this adder uses. Exactly one of the
 * three masks is 1 and the other two are 0, so the sum selects one term:
 *
 *   pinf = (px == 0) AND (py == 0)          P is O
 *   qinf = (qx == 0) AND (qy == 0)          Q is O
 *   usep = qinf AND NOT pinf                -> answer is P
 *   useq = pinf                             -> answer is Q  (covers O + O = O)
 *   user = notinf AND NOT(pinf OR qinf)     -> answer is the computed sum
 *
 * `user` folds in the pre-existing `notinf` mask (the P == −Q case), so P + (−P)
 * still yields the all-zero blob and nothing about that case changes.
 *
 * Requiring BOTH coordinates to be zero is load-bearing, not belt-and-braces.
 * x = 0 has genuine curve points whenever the curve's b is a quadratic residue
 * — (0, sqrt(b)) — and testing x alone would map them to O. y = 0 has none on
 * any of these three curves (all have prime order, so no point of order 2), but
 * the conjunction makes that fact not need to be true.
 *
 * Plain OP_MUL / OP_ADD with no field reduction: px, qx, rx are already in
 * [0, p) and the masks are 0 or 1, so each product and the sum are canonical.
 *
 * Consumes px, py, qx, qy and the field-computed rx, ry; leaves the selected
 * rx, ry in their place.
 */
export function emitAffineInfinitySelect(t: ECTracker): void {
  // pinf = (px == 0) AND (py == 0)
  t.copyToTop('px', '_px_z');
  t.pushInt('_zero_px', 0n);
  t.rawBlock(['_px_z', '_zero_px'], '_pxz', (e) => {
    e({ op: 'opcode', code: 'OP_NUMEQUAL' });
  });
  t.copyToTop('py', '_py_z');
  t.pushInt('_zero_py', 0n);
  t.rawBlock(['_py_z', '_zero_py'], '_pyz', (e) => {
    e({ op: 'opcode', code: 'OP_NUMEQUAL' });
  });
  t.rawBlock(['_pxz', '_pyz'], '_pinf', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });

  // qinf = (qx == 0) AND (qy == 0)
  t.copyToTop('qx', '_qx_z');
  t.pushInt('_zero_qx', 0n);
  t.rawBlock(['_qx_z', '_zero_qx'], '_qxz', (e) => {
    e({ op: 'opcode', code: 'OP_NUMEQUAL' });
  });
  t.copyToTop('qy', '_qy_z');
  t.pushInt('_zero_qy', 0n);
  t.rawBlock(['_qy_z', '_zero_qy'], '_qyz', (e) => {
    e({ op: 'opcode', code: 'OP_NUMEQUAL' });
  });
  t.rawBlock(['_qxz', '_qyz'], '_qinf', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });

  // usep = qinf AND NOT pinf
  t.copyToTop('_qinf', '_usep_q');
  t.copyToTop('_pinf', '_usep_p');
  t.rawBlock(['_usep_q', '_usep_p'], '_usep', (e) => {
    e({ op: 'opcode', code: 'OP_NOT' });
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });

  // useq = pinf
  t.copyToTop('_pinf', '_useq');

  // user = notinf AND NOT(pinf OR qinf)
  t.toTop('_pinf');
  t.toTop('_qinf');
  t.rawBlock(['_pinf', '_qinf'], '_anyinf', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLOR' });
  });
  t.toTop('_notinf');
  t.toTop('_anyinf');
  t.rawBlock(['_notinf', '_anyinf'], '_user', (e) => {
    e({ op: 'opcode', code: 'OP_NOT' });
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });

  // rx = px*usep + qx*useq + rx*user
  t.toTop('px');
  t.copyToTop('_usep', '_usep_x');
  t.rawBlock(['px', '_usep_x'], '_selx_p', (e) => {
    e({ op: 'opcode', code: 'OP_MUL' });
  });
  t.toTop('qx');
  t.copyToTop('_useq', '_useq_x');
  t.rawBlock(['qx', '_useq_x'], '_selx_q', (e) => {
    e({ op: 'opcode', code: 'OP_MUL' });
  });
  t.toTop('rx');
  t.copyToTop('_user', '_user_x');
  t.rawBlock(['rx', '_user_x'], '_selx_r', (e) => {
    e({ op: 'opcode', code: 'OP_MUL' });
  });
  t.rawBlock(['_selx_q', '_selx_r'], '_selx_qr', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  t.rawBlock(['_selx_p', '_selx_qr'], 'rx', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });

  // ry = py*usep + qy*useq + ry*user  (last use of each mask: consume them)
  t.toTop('py');
  t.toTop('_usep');
  t.rawBlock(['py', '_usep'], '_sely_p', (e) => {
    e({ op: 'opcode', code: 'OP_MUL' });
  });
  t.toTop('qy');
  t.toTop('_useq');
  t.rawBlock(['qy', '_useq'], '_sely_q', (e) => {
    e({ op: 'opcode', code: 'OP_MUL' });
  });
  t.toTop('ry');
  t.toTop('_user');
  t.rawBlock(['ry', '_user'], '_sely_r', (e) => {
    e({ op: 'opcode', code: 'OP_MUL' });
  });
  t.rawBlock(['_sely_q', '_sely_r'], '_sely_qr', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  t.rawBlock(['_sely_p', '_sely_qr'], 'ry', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
}

// ===========================================================================
// Jacobian point operations (for ecMul)
// ===========================================================================

/**
 * Jacobian point doubling (a=0 for secp256k1).
 * Expects jx, jy, jz on tracker. Replaces with updated values.
 */
function jacobianDouble(t: ECTracker): void {
  // Save copies of jx, jy, jz for later use
  t.copyToTop('jy', '_jy_save');
  t.copyToTop('jx', '_jx_save');
  t.copyToTop('jz', '_jz_save');

  // A = jy²
  fieldSqr(t, 'jy', '_A');

  // B = 4 * jx * A
  t.copyToTop('_A', '_A_save');
  fieldMul(t, 'jx', '_A', '_xA');
  t.pushInt('_four', 4n);
  fieldMul(t, '_xA', '_four', '_B');

  // C = 8 * A²
  fieldSqr(t, '_A_save', '_A2');
  t.pushInt('_eight', 8n);
  fieldMul(t, '_A2', '_eight', '_C');

  // D = 3 * X²
  fieldSqr(t, '_jx_save', '_x2');
  t.pushInt('_three', 3n);
  fieldMul(t, '_x2', '_three', '_D');

  // nx = D² - 2*B
  t.copyToTop('_D', '_D_save');
  t.copyToTop('_B', '_B_save');
  fieldSqr(t, '_D', '_D2');
  t.copyToTop('_B', '_B1');
  fieldMulConst(t, '_B1', 2n, '_2B');
  fieldSub(t, '_D2', '_2B', '_nx');

  // ny = D*(B - nx) - C
  t.copyToTop('_nx', '_nx_copy');
  fieldSub(t, '_B_save', '_nx_copy', '_B_nx');
  fieldMul(t, '_D_save', '_B_nx', '_D_B_nx');
  fieldSub(t, '_D_B_nx', '_C', '_ny');

  // nz = 2 * Y * Z
  fieldMul(t, '_jy_save', '_jz_save', '_yz');
  fieldMulConst(t, '_yz', 2n, '_nz');

  // Clean up leftovers: _B (used via _B_save/_B1) and old jz (only copied, never consumed)
  t.toTop('_B'); t.drop();
  t.toTop('jz'); t.drop();
  t.toTop('_nx'); t.rename('jx');
  t.toTop('_ny'); t.rename('jy');
  t.toTop('_nz'); t.rename('jz');
}

/**
 * Jacobian → Affine conversion.
 * Consumes jx, jy, jz; produces rxName, ryName.
 */
function jacobianToAffine(t: ECTracker, rxName: string, ryName: string): void {
  fieldInv(t, 'jz', '_zinv');
  t.copyToTop('_zinv', '_zinv_keep');
  fieldSqr(t, '_zinv', '_zinv2');
  t.copyToTop('_zinv2', '_zinv2_keep');
  fieldMul(t, '_zinv_keep', '_zinv2', '_zinv3');
  fieldMul(t, 'jx', '_zinv2_keep', rxName);
  fieldMul(t, 'jy', '_zinv3', ryName);
}

// ===========================================================================
// Jacobian mixed addition (P_jacobian + Q_affine)
// ===========================================================================

/**
 * Build Jacobian mixed-add ops for use inside OP_IF.
 * Uses an inner ECTracker to leverage field arithmetic helpers.
 *
 * Stack layout: [..., ax, ay, _k, jx, jy, jz]
 * After:        [..., ax, ay, _k, jx', jy', jz']
 */
function buildJacobianAddAffineInline(e: (op: StackOp) => void, t: ECTracker): void {
  // Create inner tracker with cloned stack state
  jacobianAddAffineBody(new ECTracker([...t.nm], e), false);
}

/**
 * The mixed-add itself, emitting through an ECTracker the caller owns.
 *
 * `keepHR` additionally leaves copies of H and R on the stack. They are the
 * exception detector: H = U2 - X1 and R = S2 - Y1 are both zero exactly when
 * the Jacobian accumulator is the same curve point as the affine operand, the
 * one case these formulas cannot compute (see buildJacobianAddOrDoubleInline).
 */
function jacobianAddAffineBody(it: ECTracker, keepHR: boolean): void {
  // Save copies of values that get consumed but are needed later
  it.copyToTop('jz', '_jz_for_z1cu');   // consumed by Z1sq, needed for Z1cu
  it.copyToTop('jz', '_jz_for_z3');     // needed for Z3
  it.copyToTop('jy', '_jy_for_y3');     // consumed by R, needed for Y3
  it.copyToTop('jx', '_jx_for_u1h2');   // consumed by H, needed for U1H2

  // Z1sq = jz²
  fieldSqr(it, 'jz', '_Z1sq');

  // Z1cu = _jz_for_z1cu * Z1sq (copy Z1sq for U2)
  it.copyToTop('_Z1sq', '_Z1sq_for_u2');
  fieldMul(it, '_jz_for_z1cu', '_Z1sq', '_Z1cu');

  // U2 = ax * Z1sq_for_u2
  it.copyToTop('ax', '_ax_c');
  fieldMul(it, '_ax_c', '_Z1sq_for_u2', '_U2');

  // S2 = ay * Z1cu
  it.copyToTop('ay', '_ay_c');
  fieldMul(it, '_ay_c', '_Z1cu', '_S2');

  // H = U2 - jx
  fieldSub(it, '_U2', 'jx', '_H');

  // R = S2 - jy
  fieldSub(it, '_S2', 'jy', '_R');

  if (keepHR) {
    it.copyToTop('_H', '_H_keep');
    it.copyToTop('_R', '_R_keep');
  }

  // Save copies of H (consumed by H2 sqr, needed for H3 and Z3)
  it.copyToTop('_H', '_H_for_h3');
  it.copyToTop('_H', '_H_for_z3');

  // H2 = H²
  fieldSqr(it, '_H', '_H2');

  // Save H2 for U1H2
  it.copyToTop('_H2', '_H2_for_u1h2');

  // H3 = H_for_h3 * H2
  fieldMul(it, '_H_for_h3', '_H2', '_H3');

  // U1H2 = _jx_for_u1h2 * H2_for_u1h2
  fieldMul(it, '_jx_for_u1h2', '_H2_for_u1h2', '_U1H2');

  // Save R, U1H2, H3 for Y3 computation
  it.copyToTop('_R', '_R_for_y3');
  it.copyToTop('_U1H2', '_U1H2_for_y3');
  it.copyToTop('_H3', '_H3_for_y3');

  // X3 = R² - H3 - 2*U1H2
  fieldSqr(it, '_R', '_R2');
  fieldSub(it, '_R2', '_H3', '_x3_tmp');
  fieldMulConst(it, '_U1H2', 2n, '_2U1H2');
  fieldSub(it, '_x3_tmp', '_2U1H2', '_X3');

  // Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
  it.copyToTop('_X3', '_X3_c');
  fieldSub(it, '_U1H2_for_y3', '_X3_c', '_u_minus_x');
  fieldMul(it, '_R_for_y3', '_u_minus_x', '_r_tmp');
  fieldMul(it, '_jy_for_y3', '_H3_for_y3', '_jy_h3');
  fieldSub(it, '_r_tmp', '_jy_h3', '_Y3');

  // Z3 = _jz_for_z3 * _H_for_z3
  fieldMul(it, '_jz_for_z3', '_H_for_z3', '_Z3');

  // Rename results to jx/jy/jz
  it.toTop('_X3'); it.rename('jx');
  it.toTop('_Y3'); it.rename('jy');
  it.toTop('_Z3'); it.rename('jz');
}

/**
 * Branchless select of one Jacobian coordinate: `add + cond*(dbl - add)`.
 * Same shape as the numerator/denominator select in affineAdd, so both paths
 * emit the identical op sequence and the tracker's static stack model holds.
 * Consumes addName, dblName and condName.
 */
function selectCoord(t: ECTracker, addName: string, dblName: string, condName: string, resultName: string): void {
  t.copyToTop(addName, '_sel_add_c');
  fieldSub(t, dblName, '_sel_add_c', '_sel_diff');
  fieldMul(t, '_sel_diff', condName, '_sel_scaled');
  fieldAdd(t, addName, '_sel_scaled', resultName);
}

/**
 * The ladder's LAST conditional step: mixed-add, but correct when the
 * accumulator already equals the point being added.
 *
 * The Jacobian mixed-add cannot double. It computes H = U2 - X1, and when the
 * two operands are the same curve point H = 0, so Z3 = Z1*H = 0 — the point at
 * infinity — and since fieldInv is Fermat (inv(0) = 0), jacobianToAffine turns
 * that into the ALL-ZERO point instead of 2P. `ecMul(P, 2n)` and
 * `ecMulGen(2n)` returned 64 zero bytes.
 *
 * WHY ONLY THE LAST STEP. After step i the accumulator holds c_i*P where
 * c_i = k' >> i and k' = k + 3n, so the conditional step adds P to
 * (c_i - 1)*P. Every curve here has cofactor 1, so P has order n and the
 * degenerate cases are exactly c_i ≡ 2 (mod n) — accumulator == P — and
 * c_i ≡ 0 or 1 (mod n) — accumulator == -P or O. c_i ranges over a CONTIGUOUS
 * interval determined only by i, so this is decidable by interval arithmetic
 * rather than by sampling, and over the whole domain k ∈ [0, n-1] only two
 * steps qualify, both at i = 0:
 *
 *   k = 2  ->  c_0 = 3n+2 ≡ 2, odd, so the add runs: accumulator == P.  <- bug
 *   k = 0  ->  c_0 = 3n   ≡ 0, odd, so the add runs: accumulator == -P,
 *              true result the point at infinity, which affine coordinates
 *              cannot represent; it stays the all-zero point, as before.
 *
 * At i ≥ 1, c_i lies in [3n>>i, (4n-1)>>i] — the lower bound is 3n, not 3n+1,
 * because the reduce puts k = 0 in the domain — and that interval contains no
 * value ≡ 0, 1 or 2 (mod n) that is also odd; c_256 = 2 is even, so no add
 * runs. Handling H == 0 at every one of the 257 steps would cost ~62% more
 * script bytes; handling it here costs 0.24%.
 *
 * THE ENTIRE ARGUMENT IS CONDITIONED ON k ∈ [0, n-1], which is only true
 * because emitEcMul reduces k mod n before adding 3n. That reduce landed one
 * commit AFTER this select (03f50d48 then f16790a9). 03f50d48 ON ITS OWN IS
 * UNSOUND: a last-step-only select while the scalar is still unbounded leaves
 * c_i free to hit 0, 1 or 2 (mod n) at other steps. The two commits must land
 * together and must never be bisected, cherry-picked or reverted apart.
 *
 * The interval argument does 100% of the work; there is no defence in depth
 * here. In particular c_i ≡ 1 (mod n) — a pre-add accumulator of O — is
 * UNREACHABLE, not handled: were it reachable the select would still take the
 * ADD path, because O is carried as Z1 = 0, which makes U2 = 0 and
 * H = -X1 != 0. Anything that changes the +3n offset, the iteration count or
 * the reduce must redo the interval check, not assume this still holds.
 *
 * This is NOT a "no honest input hits it" argument: the operand P is caller-
 * supplied and cannot move the exception, because the condition depends only
 * on c_i mod ord(P) and ord(P) = n for every point on the curve. A point that
 * is NOT on the curve has no such guarantee — but nor does any other part of
 * this codegen; callers who accept untrusted points must gate them on
 * `ecOnCurve` first.
 *
 * Stack layout: [..., ax, ay, _k, jx, jy, jz] — same in and out.
 */
function buildJacobianAddOrDoubleInline(e: (op: StackOp) => void, t: ECTracker): void {
  const it = new ECTracker([...t.nm], e);

  // Keep the pre-add accumulator: it is what must be DOUBLED in the
  // exceptional case, and the add below consumes jx/jy/jz.
  it.copyToTop('jx', '_sx');
  it.copyToTop('jy', '_sy');
  it.copyToTop('jz', '_sz');

  jacobianAddAffineBody(it, true);

  // cond = (H == 0) AND (R == 0). Requiring R == 0 too keeps the
  // accumulator == -P case (k = 0) on the add path, where Z3 = 0 correctly
  // signals the point at infinity.
  it.toTop('_H_keep');
  it.pushInt('_zero_h', 0n);
  it.rawBlock(['_H_keep', '_zero_h'], '_h_is0', (e2) => {
    e2({ op: 'opcode', code: 'OP_NUMEQUAL' });
  });
  it.toTop('_R_keep');
  it.pushInt('_zero_r', 0n);
  it.rawBlock(['_R_keep', '_zero_r'], '_r_is0', (e2) => {
    e2({ op: 'opcode', code: 'OP_NUMEQUAL' });
  });
  it.toTop('_h_is0');
  it.toTop('_r_is0');
  it.rawBlock(['_h_is0', '_r_is0'], '_cond', (e2) => {
    e2({ op: 'opcode', code: 'OP_BOOLAND' });
  });

  // Move the add result aside so jacobianDouble can work on jx/jy/jz again,
  // this time holding the saved accumulator.
  it.toTop('jx'); it.rename('_add_x');
  it.toTop('jy'); it.rename('_add_y');
  it.toTop('jz'); it.rename('_add_z');
  it.toTop('_sx'); it.rename('jx');
  it.toTop('_sy'); it.rename('jy');
  it.toTop('_sz'); it.rename('jz');
  jacobianDouble(it);
  it.toTop('jx'); it.rename('_dbl_x');
  it.toTop('jy'); it.rename('_dbl_y');
  it.toTop('jz'); it.rename('_dbl_z');

  it.copyToTop('_cond', '_cond_x');
  selectCoord(it, '_add_x', '_dbl_x', '_cond_x', 'jx');
  it.copyToTop('_cond', '_cond_y');
  selectCoord(it, '_add_y', '_dbl_y', '_cond_y', 'jy');
  it.toTop('_cond'); it.rename('_cond_z');
  selectCoord(it, '_add_z', '_dbl_z', '_cond_z', 'jz');
}

// ===========================================================================
// Public entry points (called from stack lowerer)
// ===========================================================================

/**
 * ecAdd: add two points.
 * Stack in: [point_a, point_b] (b on top)
 * Stack out: [result_point]
 */
export function emitEcAdd(emit: (op: StackOp) => void): void {
  const t = new ECTracker(['_pa', '_pb'], emit);
  decomposePoint(t, '_pa', 'px', 'py');
  decomposePoint(t, '_pb', 'qx', 'qy');
  // R-117: affineAdd's selectors compare these four values RAW.
  emitCoordCanonVerify(t, 'px', 'py');
  emitCoordCanonVerify(t, 'qx', 'qy');
  affineAdd(t);
  composePoint(t, 'rx', 'ry', '_result');
}

/**
 * ecMul: scalar multiplication P * k.
 * Stack in: [point, scalar] (scalar on top)
 * Stack out: [result_point]
 *
 * Uses 257-iteration MSB-first double-and-add with Jacobian coordinates.
 * Adds 3n to k so that bit 257 is always set: k+3n ∈ [3n, 4n-1], and
 * since 3n > 2^257, bit 257 is guaranteed to be 1 for all valid k.
 * This avoids the k+n overflow issue where bit 256 was only set for
 * large k, causing incorrect results for ~half of all scalar values.
 */
/**
 * R-157 — gate a Point operand of the scalar ladder: it must be ON the curve,
 * or be the point at infinity. ABORTS otherwise. Raw ops, straight-line, run
 * before the ladder's tracker exists.
 *
 * `ecMul(P, k)` does not compute `k·P`. It computes `((k mod n) + 3n)·P`: the
 * MSB-first ladder adds `3n` so a fixed high bit is always set, and `+3n` is a
 * no-op ONLY when ord(P) divides n. Cofactor 1 gives ord(P) = n for every point
 * on the curve, so the trick is sound there and nowhere else. An off-curve
 * point lies on some other curve `y² = x³ + b′` of unrelated order, and the
 * ladder silently answers a different question. Measured on @bsv/sdk's Spend
 * with the off-curve P = (5, 7), which lies on `y² = x³ − 76`:
 *
 *     ecMul(P, 1n) -> c8b039d1…9438f2ff, which is NOT P
 *
 * matching `(1 + 3n)·P` on that other curve exactly. So the primitive violated
 * its own contract for EVERY off-curve input, not merely a contrived one.
 *
 * The degenerate sub-case is worse. For a 2-torsion point of the other curve —
 * any `(x, 0)` — every multiple collapses to the all-zero blob, because the
 * ladder's unguarded mixed-add hits H = R = 0 mid-ladder, sets Z3 = 0, and a
 * Jacobian accumulator at infinity never leaves it. Combined with R-053, which
 * correctly taught `ecAdd` that the all-zero blob is the identity, that turns a
 * Schnorr-shaped `s·G == R + e·P` check into a free pass: choose an off-curve
 * `P` of order 2, `e·P` is O, `R + O` is R, and any `s` with `R = s·G` verifies
 * with no knowledge of any discrete log.
 *
 * WHY HERE AND NOT IN THE CALLER. The `+3n` offset is INTERNAL to `ecMul`. A
 * caller cannot see it, cannot know the obligation exists without reading this
 * codegen, and gains nothing by checking what `ecMul` can check more cheaply
 * (`ecOnCurve` is 816 bytes against `ecMul`'s 428 KB — 0.2%). The obligation
 * WAS written down, in all seven tiers, in `buildJacobianAddOrDoubleInline`'s
 * own docstring: "callers who accept untrusted points must gate them on
 * `ecOnCurve` first". Nothing enforced it, and the repository's own
 * `schnorr-zkp` fixture takes its `pubKey` from a DEPLOYER-supplied constructor
 * slot, where that idiom is not even reachable.
 *
 * WHY NOT `ecAdd`, which is the other half of the boundary: `affineAdd`
 * implements the group law with no n-dependent trick, so on an off-curve
 * operand it returns the CORRECT sum on that operand's own curve. It does not
 * lie. And O — deliberately not on the curve — must keep flowing through
 * `ecAdd` for R-053 to hold. Gating the adder would break a working primitive
 * to fix a different one.
 *
 * WHY O IS EXEMPT, and it is load-bearing: `ecMul(P, 0n)` returns the all-zero
 * blob, `ecAdd(P, -P)` returns it, and the EC optimizer folds to it, so O is a
 * reachable runtime operand — while `ecOnCurve(O)` is false by construction
 * (0² ≠ 0³ + b). A bare on-curve gate would reject the identity this codegen
 * manufactures itself.
 *
 * This SUBSUMES R-117's coordinate-canonicity gate on the mul builtins, which
 * is why that call is removed here rather than left as defence in depth: a
 * non-canonical coordinate makes `ecOnCurve` false and cannot equal the
 * all-zero blob, so it still aborts, and keeping both would be 74 bytes saying
 * the same thing twice in two places that must agree.
 *
 * Stack in/out: [point, scalar] — unchanged.
 */
function emitPointGate(
  emit: (op: StackOp) => void,
  emitOnCurve: (e: (op: StackOp) => void) => void,
  coordBytes: number,
): void {
  // [pt, k] -> [pt, k, pt]
  emit({ op: 'over' });
  // -> [pt, k, isInf]
  emit({ op: 'push', value: new Uint8Array(coordBytes * 2) });
  emit({ op: 'opcode', code: 'OP_EQUAL' });
  // -> [pt, k, isInf, pt]
  emit({ op: 'push', value: 2n });
  emit({ op: 'pick', depth: 2 });
  // -> [pt, k, isInf, onCurve]
  emitOnCurve(emit);
  // -> [pt, k]
  emit({ op: 'opcode', code: 'OP_BOOLOR' });
  emit({ op: 'opcode', code: 'OP_VERIFY' });
}

export function emitEcMul(emit: (op: StackOp) => void): void {
  // R-157: the ladder's +3n trick is a no-op only for ord(P) | n.
  emitPointGate(emit, emitEcOnCurve, 32);
  const t = new ECTracker(['_pt', '_k'], emit);
  decomposePoint(t, '_pt', 'ax', 'ay');

  // k' = k + 3n: guarantees bit 257 is set for MSB-first double-and-add.
  // k ∈ [1, n-1], so k+3n ∈ [3n+1, 4n-1]. Since 3n > 2^257, bit 257
  // is always 1. Adding 3n (≡ 0 mod n) preserves the EC point: k*G = (k+3n)*G.
  //
  // "k ∈ [1, n-1]" is a PRECONDITION the caller cannot enforce — the scalar is
  // usually an unlock argument — so reduce it first. See emitScalarReduce.
  t.toTop('_k');
  emitScalarReduce(t, '_k', '_kr');
  t.pushInt('_n', CURVE_N);
  t.rawBlock(['_kr', '_n'], '_kn', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  t.pushInt('_n2', CURVE_N);
  t.rawBlock(['_kn', '_n2'], '_kn2', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  t.pushInt('_n3', CURVE_N);
  t.rawBlock(['_kn2', '_n3'], '_kn3', (e) => {
    e({ op: 'opcode', code: 'OP_ADD' });
  });
  t.rename('_k');

  // Init accumulator = P (bit 257 of k+3n is always 1)
  t.copyToTop('ax', 'jx');
  t.copyToTop('ay', 'jy');
  t.pushInt('jz', 1n);

  // 257 iterations: bits 256 down to 0
  for (let bit = 256; bit >= 0; bit--) {
    jacobianDouble(t);

    // Extract bit: (k >> bit) & 1, using OP_RSHIFTNUM / OP_2DIV
    t.copyToTop('_k', '_k_copy');
    if (bit === 1) {
      // Single-bit shift: OP_2DIV (no push needed)
      t.rawBlock(['_k_copy'], '_shifted', (e) => {
        e({ op: 'opcode', code: 'OP_2DIV' });
      });
    } else if (bit > 1) {
      // Multi-bit shift: push shift amount, OP_RSHIFTNUM
      t.pushInt('_shift', BigInt(bit));
      t.rawBlock(['_k_copy', '_shift'], '_shifted', (e) => {
        e({ op: 'opcode', code: 'OP_RSHIFTNUM' });
      });
    } else {
      t.rename('_shifted');
    }
    t.pushInt('_two', 2n);
    t.rawBlock(['_shifted', '_two'], '_bit', (e) => {
      e({ op: 'opcode', code: 'OP_MOD' });
    });

    // Move _bit to TOS and remove from tracker BEFORE generating add ops,
    // because OP_IF consumes _bit and the add ops run with _bit already gone.
    t.toTop('_bit');
    t.nm.pop(); // _bit consumed by IF
    const addOps: StackOp[] = [];
    const addEmit = (op: StackOp) => addOps.push(op);
    // Only the final step can be handed two equal operands — see
    // buildJacobianAddOrDoubleInline for why, and for what it costs not to.
    if (bit === 0) buildJacobianAddOrDoubleInline(addEmit, t);
    else buildJacobianAddAffineInline(addEmit, t);
    emit({ op: 'if', then: addOps, else: [] });
  }

  jacobianToAffine(t, '_rx', '_ry');

  // Clean up
  t.toTop('ax'); t.drop();
  t.toTop('ay'); t.drop();
  t.toTop('_k'); t.drop();

  composePoint(t, '_rx', '_ry', '_result');
}

/**
 * ecMulGen: scalar multiplication G * k.
 * Stack in: [scalar]
 * Stack out: [result_point]
 */
export function emitEcMulGen(emit: (op: StackOp) => void): void {
  // Push generator point as 64-byte blob, then delegate to ecMul
  const gPoint = new Uint8Array(64);
  gPoint.set(bigintToBytes32(GEN_X), 0);
  gPoint.set(bigintToBytes32(GEN_Y), 32);
  emit({ op: 'push', value: gPoint });
  emit({ op: 'swap' }); // [point, scalar]
  emitEcMul(emit);
}

/**
 * ecNegate: negate a point (x, p - y).
 * Stack in: [point]
 * Stack out: [negated_point]
 */
export function emitEcNegate(emit: (op: StackOp) => void): void {
  const t = new ECTracker(['_pt'], emit);
  decomposePoint(t, '_pt', '_nx', '_ny');
  emitCoordCanonVerify(t, '_nx', '_ny');
  pushFieldP(t, '_fp');
  fieldSub(t, '_fp', '_ny', '_neg_y');
  composePoint(t, '_nx', '_neg_y', '_result');
}

/**
 * ecOnCurve: check if point is on secp256k1 (y² ≡ x³ + 7 mod p).
 * Stack in: [point]
 * Stack out: [boolean]
 */
export function emitEcOnCurve(emit: (op: StackOp) => void): void {
  const t = new ECTracker(['_pt'], emit);

  // CL-BUG-095: width. `ecOnCurve(G ‖ 0xff)` returned TRUE — decomposePoint
  // discarded the surplus byte, so 2^8 distinct blobs all certified as the
  // same point and a point's identity AS BYTES stopped being unique. Clamp and
  // remember the width, rather than abort, because this is the predicate
  // contracts are told to gate untrusted points on and it must stay total; the
  // flag is ANDed into the result at the end.
  emitPointLengthGate(t, '_pt', 64, '_len_ok');

  decomposePoint(t, '_pt', '_x', '_y');

  // GAP-301: coordinate canonicity. `decomposePoint` BIN2NUMs each coordinate
  // as an unsigned value that may be ≥ p; the field arithmetic below would
  // silently reduce it mod p, so a non-canonical encoding of a valid point
  // would pass. Reject it: require x < p AND y < p (coordinates are unsigned,
  // so the 0 ≤ lower bound holds by construction). Combined with the curve
  // equation at the end via OP_BOOLAND so ecOnCurve still returns a boolean.
  t.copyToTop('_x', '_x_lt');
  pushFieldP(t, '_p_for_x');
  t.rawBlock(['_x_lt', '_p_for_x'], '_x_canon', (e) => {
    e({ op: 'opcode', code: 'OP_LESSTHAN' });
  });
  t.copyToTop('_y', '_y_lt');
  pushFieldP(t, '_p_for_y');
  t.rawBlock(['_y_lt', '_p_for_y'], '_y_canon', (e) => {
    e({ op: 'opcode', code: 'OP_LESSTHAN' });
  });
  t.toTop('_x_canon');
  t.toTop('_y_canon');
  t.rawBlock(['_x_canon', '_y_canon'], '_canon', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });

  // lhs = y²
  fieldSqr(t, '_y', '_y2');

  // rhs = x³ + 7
  t.copyToTop('_x', '_x_copy');
  fieldSqr(t, '_x', '_x2');
  fieldMul(t, '_x2', '_x_copy', '_x3');
  t.pushInt('_seven', 7n);
  fieldAdd(t, '_x3', '_seven', '_rhs');

  // Compare curve equation
  t.toTop('_y2');
  t.toTop('_rhs');
  t.rawBlock(['_y2', '_rhs'], '_curve_eq', (e) => {
    e({ op: 'opcode', code: 'OP_EQUAL' });
  });

  // on-curve = right width AND canonical AND curve-equation
  t.toTop('_canon');
  t.toTop('_curve_eq');
  t.rawBlock(['_canon', '_curve_eq'], '_eq_ok', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });
  t.toTop('_len_ok');
  t.toTop('_eq_ok');
  t.rawBlock(['_len_ok', '_eq_ok'], '_result', (e) => {
    e({ op: 'opcode', code: 'OP_BOOLAND' });
  });
}

/**
 * ecModReduce: ((value % mod) + mod) % mod
 * Stack in: [value, mod]
 * Stack out: [result]
 */
export function emitEcModReduce(emit: (op: StackOp) => void): void {
  emit({ op: 'opcode', code: 'OP_2DUP' });
  emit({ op: 'opcode', code: 'OP_MOD' });
  emit({ op: 'rot' });
  emit({ op: 'drop' });
  emit({ op: 'over' });
  emit({ op: 'opcode', code: 'OP_ADD' });
  emit({ op: 'swap' });
  emit({ op: 'opcode', code: 'OP_MOD' });
}

/**
 * ecEncodeCompressed: point → 33-byte compressed pubkey.
 * Stack in: [point (64 bytes)]
 * Stack out: [compressed (33 bytes)]
 */
export function emitEcEncodeCompressed(emit: (op: StackOp) => void): void {
  // CL-BUG-095, and the reason this one is the sharpest edge of it: the parity
  // byte used to be taken from the blob's LAST byte (OP_SIZE 1 OP_SUB
  // OP_SPLIT), not from a fixed offset. So appending one byte FLIPPED THE SIGN
  // of the compressed encoding — the same 64-byte point compressed to 02‖x or
  // 03‖x at the caller's choice, and anything that hashes a compressed pubkey
  // (a P2PKH address, a commitment) became forgeable between the two
  // spellings. Two independent fixes, both kept: the width is verified, and
  // the parity byte is read from offset 31 of y whatever the caller sent.
  emitPointLenVerify(emit, 64);
  // Split at 32: [x_bytes, y_bytes]
  emit({ op: 'push', value: 32n });
  emit({ op: 'opcode', code: 'OP_SPLIT' });
  // Take y[31] at a FIXED offset: [x_bytes, y_head, y_last]
  emit({ op: 'push', value: 31n });
  emit({ op: 'opcode', code: 'OP_SPLIT' });
  emit({ op: 'opcode', code: 'OP_NIP' }); // drop y_head
  // Stack: [x_bytes, last_byte]
  emit({ op: 'opcode', code: 'OP_BIN2NUM' });
  emit({ op: 'push', value: 2n });
  emit({ op: 'opcode', code: 'OP_MOD' });
  // Stack: [x_bytes, parity]
  emit({ op: 'if',
    then: [{ op: 'push', value: new Uint8Array([0x03]) }],
    else: [{ op: 'push', value: new Uint8Array([0x02]) }],
  });
  // Stack: [x_bytes, prefix_byte]
  emit({ op: 'swap' });
  emit({ op: 'opcode', code: 'OP_CAT' });
}

/**
 * R-156 — verify that the script number on TOS is a FIELD ELEMENT, 0 <= v < p.
 * Leaves the value in place (OP_DUP feeds the check, OP_VERIFY consumes the
 * flag), so the caller's stack shape is unchanged.
 *
 * `ecMakePoint` converts each coordinate with `push 33, OP_NUM2BIN, push 32,
 * OP_SPLIT, OP_DROP`. NUM2BIN(33) writes a 33-byte little-endian SIGN-MAGNITUDE
 * script number, so byte 32 is exactly where the sign bit lives AND where any
 * bits >= 2^256 land — and the split drops precisely that byte. The result was
 * an ecMakePoint that is NOT INJECTIVE:
 *
 *     ecMakePoint( 1n, y) == ecMakePoint(-1n, y)            sign discarded
 *     ecMakePoint( 1n, y) == ecMakePoint(1n + 2^256, y)     magnitude truncated
 *     ecMakePoint( x,  y) == ecMakePoint(x, -y)             and on the y half
 *
 * all three measured on @bsv/sdk's Spend. The y-half collision is the sharpest:
 * `ecMakePoint(x, 0n - y)` is how an author spells negation by hand, and it
 * silently produced (x, +y) — the point being negated — rather than (x, p-y).
 *
 * R-117's coordinate-canonicity gate does not cover this and cannot: the bytes
 * emitted for `-1n` are the perfectly canonical encoding of 1, so no downstream
 * consumer can tell. The aliasing happens before any Point exists.
 *
 * REJECT rather than reduce, for the reason R-117 gives: `ecOnCurve` answers
 * "no" to a coordinate outside [0, p), so reducing here would leave the
 * constructor and the predicate disagreeing about what a point is. Rejecting
 * also restores injectivity, which is the property the defect broke.
 *
 * OP_WITHIN(v, 0, p) is `0 <= v < p` in one opcode — the same half-open bound
 * the `within` builtin exposes to contract authors.
 */
function emitFieldElementVerify(emit: (op: StackOp) => void): void {
  emit({ op: 'dup' });
  emit({ op: 'push', value: 0n });
  emit({ op: 'push', value: FIELD_P });
  emit({ op: 'opcode', code: 'OP_WITHIN' });
  emit({ op: 'opcode', code: 'OP_VERIFY' });
}

/**
 * ecMakePoint: (x: bigint, y: bigint) → Point.
 * Stack in: [x_num, y_num] (y on top)
 * Stack out: [point_bytes (64 bytes)]
 */
export function emitEcMakePoint(emit: (op: StackOp) => void): void {
  // R-156: y must be a field element before its sign byte is dropped.
  emitFieldElementVerify(emit);
  // Convert y to 32 bytes big-endian (NUM2BIN(33) to handle sign byte, then take first 32)
  emit({ op: 'push', value: 33n });
  emit({ op: 'opcode', code: 'OP_NUM2BIN' });
  emit({ op: 'push', value: 32n });
  emit({ op: 'opcode', code: 'OP_SPLIT' });
  emit({ op: 'drop' });
  emitReverse32(emit);
  // Stack: [x_num, y_be]
  emit({ op: 'swap' });
  // Stack: [y_be, x_num]
  // R-156: and so must x.
  emitFieldElementVerify(emit);
  emit({ op: 'push', value: 33n });
  emit({ op: 'opcode', code: 'OP_NUM2BIN' });
  emit({ op: 'push', value: 32n });
  emit({ op: 'opcode', code: 'OP_SPLIT' });
  emit({ op: 'drop' });
  emitReverse32(emit);
  // Stack: [y_be, x_be]
  emit({ op: 'swap' });
  // Stack: [x_be, y_be]
  emit({ op: 'opcode', code: 'OP_CAT' });
}

/**
 * ecPointX: extract x-coordinate from Point.
 * Stack in: [point (64 bytes)]
 * Stack out: [x as bigint]
 */
export function emitEcPointX(emit: (op: StackOp) => void): void {
  // CL-BUG-095: a 32-byte blob used to SUCCEED here and return itself as x —
  // the split at 32 left an empty tail that `drop` happily removed. ecPointY
  // on the identical input already aborted, which is how the hole survived: a
  // short point looked "already rejected".
  emitPointLenVerify(emit, 64);
  emit({ op: 'push', value: 32n });
  emit({ op: 'opcode', code: 'OP_SPLIT' });
  emit({ op: 'drop' });
  emitReverse32(emit);
  // Append 0x00 sign byte to ensure unsigned interpretation
  emit({ op: 'push', value: new Uint8Array([0x00]) });
  emit({ op: 'opcode', code: 'OP_CAT' });
  emit({ op: 'opcode', code: 'OP_BIN2NUM' });
}

/**
 * ecPointY: extract y-coordinate from Point.
 * Stack in: [point (64 bytes)]
 * Stack out: [y as bigint]
 */
export function emitEcPointY(emit: (op: StackOp) => void): void {
  emitPointLenVerify(emit, 64);
  emit({ op: 'push', value: 32n });
  emit({ op: 'opcode', code: 'OP_SPLIT' });
  emit({ op: 'swap' });
  emit({ op: 'drop' });
  emitReverse32(emit);
  // Append 0x00 sign byte to ensure unsigned interpretation
  emit({ op: 'push', value: new Uint8Array([0x00]) });
  emit({ op: 'opcode', code: 'OP_CAT' });
  emit({ op: 'opcode', code: 'OP_BIN2NUM' });
}
