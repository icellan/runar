/**
 * Execution tests for BN254 Fp/Fp2 field arithmetic Script codegen.
 *
 * Generates StackOp sequences, emits them to hex via a minimal emitter,
 * and runs them through the BSV SDK Script interpreter.
 */
import { describe, it, expect } from 'vitest';
import { LockingScript, UnlockingScript, Spend } from '@bsv/sdk';
import type { StackOp } from 'runar-ir-schema';
import {
  emitInitP, emitCleanupP,
  emitFpAdd, emitFpSub, emitFpMul, emitFpSqr, emitFpNeg, emitFpInv,
  emitPushFp,
} from '../bn254/field-script.js';
import {
  emitFp2Add, emitFp2Sub, emitFp2Mul, emitFp2Sqr, emitFp2Neg, emitFp2MulByXi, emitFp2Inv,
  emitPushFp2,
} from '../bn254/fp2-script.js';
import {
  emitFp6Add, emitFp6Sub, emitFp6Neg, emitFp6Mul, emitFp6Sqr, emitFp6Inv,
} from '../bn254/fp6-script.js';
import {
  emitFp12Mul, emitFp12Sqr, emitFp12Conj, emitFp12Inv,
} from '../bn254/fp12-script.js';
import { P } from '../bn254/constants.js';
import { fpAdd, fpSub, fpMul, fpSqr, fpNeg, fpMod } from '../bn254/field.js';
import { fp2, fp2Add, fp2Sub, fp2Mul, fp2Sqr, fp2Neg, fp2Inv } from '../bn254/fp2.js';
import type { Fp2, Fp6, Fp12 } from '../types.js';

// ---------------------------------------------------------------------------
// Minimal StackOp-to-hex emitter (standalone, no compiler dependency)
// ---------------------------------------------------------------------------

const OPCODES: Record<string, number> = {
  'OP_0': 0x00, 'OP_FALSE': 0x00,
  'OP_PUSHDATA1': 0x4c, 'OP_PUSHDATA2': 0x4d,
  'OP_1NEGATE': 0x4f, 'OP_TRUE': 0x51,
  'OP_1': 0x51, 'OP_2': 0x52, 'OP_3': 0x53, 'OP_4': 0x54,
  'OP_5': 0x55, 'OP_6': 0x56, 'OP_7': 0x57, 'OP_8': 0x58,
  'OP_9': 0x59, 'OP_10': 0x5a, 'OP_11': 0x5b, 'OP_12': 0x5c,
  'OP_13': 0x5d, 'OP_14': 0x5e, 'OP_15': 0x5f, 'OP_16': 0x60,
  'OP_NOP': 0x61, 'OP_IF': 0x63, 'OP_NOTIF': 0x64,
  'OP_ELSE': 0x67, 'OP_ENDIF': 0x68,
  'OP_VERIFY': 0x69, 'OP_RETURN': 0x6a,
  'OP_TOALTSTACK': 0x6b, 'OP_FROMALTSTACK': 0x6c,
  'OP_DUP': 0x76, 'OP_NIP': 0x77, 'OP_OVER': 0x78,
  'OP_PICK': 0x79, 'OP_ROLL': 0x7a,
  'OP_ROT': 0x7b, 'OP_SWAP': 0x7c, 'OP_TUCK': 0x7d,
  'OP_DROP': 0x75, 'OP_2DROP': 0x6d,
  'OP_EQUAL': 0x87, 'OP_EQUALVERIFY': 0x88,
  'OP_ADD': 0x93, 'OP_SUB': 0x94, 'OP_MUL': 0x95,
  'OP_MOD': 0x97, 'OP_NUMEQUAL': 0x9c, 'OP_NUMEQUALVERIFY': 0x9d,
  'OP_SPLIT': 0x7f, 'OP_CAT': 0x7e,
  'OP_LSHIFT': 0x98, 'OP_RSHIFT': 0x99,
};

function byteToHex(b: number): string {
  return b.toString(16).padStart(2, '0');
}

function encodeScriptNumber(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array(0);
  const negative = n < 0n;
  let abs = negative ? -n : n;
  const bytes: number[] = [];
  while (abs > 0n) {
    bytes.push(Number(abs & 0xffn));
    abs >>= 8n;
  }
  if (bytes[bytes.length - 1]! & 0x80) {
    bytes.push(negative ? 0x80 : 0x00);
  } else if (negative) {
    bytes[bytes.length - 1]! |= 0x80;
  }
  return new Uint8Array(bytes);
}

function encodePushData(data: Uint8Array): string {
  const len = data.length;
  if (len === 0) return '00';
  let prefix: string;
  if (len <= 75) {
    prefix = byteToHex(len);
  } else if (len <= 0xff) {
    prefix = '4c' + byteToHex(len);
  } else if (len <= 0xffff) {
    prefix = '4d' + byteToHex(len & 0xff) + byteToHex((len >> 8) & 0xff);
  } else {
    throw new Error('pushdata too large');
  }
  return prefix + Array.from(data, b => byteToHex(b)).join('');
}

function emitBigIntHex(n: bigint): string {
  if (n === 0n) return '00';
  if (n === -1n) return '4f';
  if (n >= 1n && n <= 16n) return byteToHex(0x50 + Number(n));
  const numBytes = encodeScriptNumber(n);
  return encodePushData(numBytes);
}

function stackOpsToHex(ops: StackOp[]): string {
  const parts: string[] = [];
  for (const op of ops) {
    switch (op.op) {
      case 'push':
        if (typeof op.value === 'boolean') {
          parts.push(op.value ? '51' : '00');
        } else if (typeof op.value === 'bigint') {
          parts.push(emitBigIntHex(op.value));
        } else {
          // Uint8Array
          parts.push(encodePushData(op.value as Uint8Array));
        }
        break;
      case 'opcode': {
        const byte = OPCODES[op.code];
        if (byte === undefined) throw new Error(`Unknown opcode: ${op.code}`);
        parts.push(byteToHex(byte));
        break;
      }
      case 'drop': parts.push('75'); break;
      case 'swap': parts.push('7c'); break;
      case 'dup': parts.push('76'); break;
      case 'nip': parts.push('77'); break;
      case 'over': parts.push('78'); break;
      case 'rot': parts.push('7b'); break;
      case 'tuck': parts.push('7d'); break;
      case 'roll': parts.push('7a'); break; // depth already pushed before
      case 'pick': parts.push('79'); break; // depth already pushed before
      default:
        throw new Error(`Unsupported op: ${(op as { op: string }).op}`);
    }
  }
  return parts.join('');
}

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

function runScript(lockingHex: string, unlockingHex: string): { success: boolean; error?: string } {
  const lockingScript = LockingScript.fromHex(lockingHex);
  // Empty unlocking = push OP_TRUE then OP_DROP in locking, but simpler:
  // BSV SDK requires non-empty unlock, so use OP_0 (0x00) which pushes empty [].
  // Since CLEANSTACK is not enforced for this test harness, we just use OP_TRUE.
  const unlockingScript = UnlockingScript.fromHex(unlockingHex !== '' ? unlockingHex : '51'); // OP_TRUE
  const spend = new Spend({
    sourceTXID: '00'.repeat(32),
    sourceOutputIndex: 0,
    sourceSatoshis: 100000,
    lockingScript,
    transactionVersion: 2,
    otherInputs: [],
    outputs: [],
    unlockingScript,
    inputIndex: 0,
    inputSequence: 0xffffffff,
    lockTime: 0,
  });
  try {
    const ok = spend.validate();
    return { success: ok };
  } catch (e: unknown) {
    return { success: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * Run StackOps that leave a single Fp value on the stack,
 * check it equals `expected` using OP_NUMEQUAL.
 */
function runFpTest(ops: StackOp[], expected: bigint): { success: boolean; error?: string } {
  const scriptHex = stackOpsToHex(ops);
  // Locking: ops + push(expected) + OP_NUMEQUAL
  const lockingHex = scriptHex + emitBigIntHex(fpMod(expected)) + '9c';
  return runScript(lockingHex, '');
}

/**
 * Run StackOps that leave [c0, c1] (Fp2) on the stack,
 * check c1 == expected.c1, then c0 == expected.c0.
 */
function runFp2Test(ops: StackOp[], expected: { c0: bigint; c1: bigint }): { success: boolean; error?: string } {
  const scriptHex = stackOpsToHex(ops);
  // Stack: [c0, c1] => check c1 first (on top), then c0
  const lockingHex = scriptHex +
    emitBigIntHex(fpMod(expected.c1)) + '9d' + // OP_NUMEQUALVERIFY (check c1)
    emitBigIntHex(fpMod(expected.c0)) + '9c';  // OP_NUMEQUAL (check c0)
  return runScript(lockingHex, '');
}

// ---------------------------------------------------------------------------
// Fp tests
// ---------------------------------------------------------------------------

describe('BN254 Fp field arithmetic — Script execution', () => {
  const A = 42n;
  const B = 17n;
  const LARGE_A = P - 5n;
  const LARGE_B = P - 3n;

  it('fpAdd: small values', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp(ops, A);
    emitPushFp(ops, B);
    emitFpAdd(ops);
    emitCleanupP(ops);
    const result = runFpTest(ops, fpAdd(A, B));
    if (!result.success) console.log('fpAdd error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fpAdd: wraps around P', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp(ops, LARGE_A);
    emitPushFp(ops, LARGE_B);
    emitFpAdd(ops);
    emitCleanupP(ops);
    const result = runFpTest(ops, fpAdd(LARGE_A, LARGE_B));
    if (!result.success) console.log('fpAdd wrap error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fpSub: basic', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp(ops, A);
    emitPushFp(ops, B);
    emitFpSub(ops);
    emitCleanupP(ops);
    const result = runFpTest(ops, fpSub(A, B));
    if (!result.success) console.log('fpSub error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fpSub: handles underflow', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp(ops, B);
    emitPushFp(ops, A);
    emitFpSub(ops);
    emitCleanupP(ops);
    const result = runFpTest(ops, fpSub(B, A));
    if (!result.success) console.log('fpSub underflow error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fpMul: small values', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp(ops, A);
    emitPushFp(ops, B);
    emitFpMul(ops);
    emitCleanupP(ops);
    const result = runFpTest(ops, fpMul(A, B));
    if (!result.success) console.log('fpMul error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fpMul: (-1) * (-1) = 1', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp(ops, P - 1n);
    emitPushFp(ops, P - 1n);
    emitFpMul(ops);
    emitCleanupP(ops);
    const result = runFpTest(ops, 1n);
    if (!result.success) console.log('fpMul (-1)^2 error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fpSqr: consistent with fpMul', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp(ops, A);
    emitFpSqr(ops);
    emitCleanupP(ops);
    const result = runFpTest(ops, fpSqr(A));
    if (!result.success) console.log('fpSqr error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fpNeg: basic', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp(ops, A);
    emitFpNeg(ops);
    emitCleanupP(ops);
    const result = runFpTest(ops, fpNeg(A));
    if (!result.success) console.log('fpNeg error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fpNeg(0) = 0', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp(ops, 0n);
    emitFpNeg(ops);
    emitCleanupP(ops);
    const result = runFpTest(ops, 0n);
    if (!result.success) console.log('fpNeg(0) error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fpInv: a * a^{-1} = 1', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp(ops, A);      // for multiplication
    emitPushFp(ops, A);      // for inverse
    emitFpInv(ops);           // [..., A, A^{-1}]
    emitFpMul(ops);           // [..., A * A^{-1}] = 1
    emitCleanupP(ops);
    const result = runFpTest(ops, 1n);
    if (!result.success) console.log('fpInv error:', result.error);
    expect(result.success).toBe(true);
  });

  it('compound: (a*b) + (a-b)', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp(ops, A);
    emitPushFp(ops, B);
    emitFpMul(ops);
    emitPushFp(ops, A);
    emitPushFp(ops, B);
    emitFpSub(ops);
    emitFpAdd(ops);
    emitCleanupP(ops);
    const expected = fpAdd(fpMul(A, B), fpSub(A, B));
    const result = runFpTest(ops, expected);
    if (!result.success) console.log('compound error:', result.error);
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Fp2 tests
// ---------------------------------------------------------------------------

describe('BN254 Fp2 field arithmetic — Script execution', () => {
  const a = fp2(7n, 11n);
  const b = fp2(3n, 5n);

  it('fp2Add: basic', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp2(ops, a.c0, a.c1);
    emitPushFp2(ops, b.c0, b.c1);
    emitFp2Add(ops);
    emitCleanupP(ops);
    const result = runFp2Test(ops, fp2Add(a, b));
    if (!result.success) console.log('fp2Add error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fp2Sub: basic', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp2(ops, a.c0, a.c1);
    emitPushFp2(ops, b.c0, b.c1);
    emitFp2Sub(ops);
    emitCleanupP(ops);
    const result = runFp2Test(ops, fp2Sub(a, b));
    if (!result.success) console.log('fp2Sub error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fp2Mul: Karatsuba', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp2(ops, a.c0, a.c1);
    emitPushFp2(ops, b.c0, b.c1);
    emitFp2Mul(ops);
    emitCleanupP(ops);
    const result = runFp2Test(ops, fp2Mul(a, b));
    if (!result.success) console.log('fp2Mul error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fp2Sqr: consistent with fp2Mul', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp2(ops, a.c0, a.c1);
    emitFp2Sqr(ops);
    emitCleanupP(ops);
    const result = runFp2Test(ops, fp2Sqr(a));
    if (!result.success) console.log('fp2Sqr error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fp2Neg: basic', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp2(ops, a.c0, a.c1);
    emitFp2Neg(ops);
    emitCleanupP(ops);
    const result = runFp2Test(ops, fp2Neg(a));
    if (!result.success) console.log('fp2Neg error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fp2MulByXi: multiply by 9+u', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp2(ops, a.c0, a.c1);
    emitFp2MulByXi(ops);
    emitCleanupP(ops);
    // fp2MulByXi(a) = fp2Mul(a, {c0:9, c1:1})
    const xi = fp2(9n, 1n);
    const expected = fp2Mul(a, xi);
    const result = runFp2Test(ops, expected);
    if (!result.success) console.log('fp2MulByXi error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fp2Mul with large values near P', () => {
    const la = fp2(P - 1n, P - 2n);
    const lb = fp2(P - 3n, P - 4n);
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp2(ops, la.c0, la.c1);
    emitPushFp2(ops, lb.c0, lb.c1);
    emitFp2Mul(ops);
    emitCleanupP(ops);
    const expected = fp2Mul(la, lb);
    const result = runFp2Test(ops, expected);
    if (!result.success) console.log('fp2Mul large error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fp2Inv: a * a^{-1} = (1, 0)', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp2(ops, a.c0, a.c1);   // for multiplication
    emitPushFp2(ops, a.c0, a.c1);   // for inverse
    emitFp2Inv(ops);                  // [..., a, a^{-1}]
    emitFp2Mul(ops);                  // [..., a * a^{-1}] = (1, 0)
    emitCleanupP(ops);
    const result = runFp2Test(ops, fp2(1n, 0n));
    if (!result.success) console.log('fp2Inv error:', result.error);
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Fp6 reference implementations (inline for test independence)
// ---------------------------------------------------------------------------

const XI: Fp2 = fp2(9n, 1n);

function fp6(c0: Fp2, c1: Fp2, c2: Fp2): Fp6 { return { c0, c1, c2 }; }

function fp6Add_ref(a: Fp6, b: Fp6): Fp6 {
  return { c0: fp2Add(a.c0, b.c0), c1: fp2Add(a.c1, b.c1), c2: fp2Add(a.c2, b.c2) };
}

function fp6Sub_ref(a: Fp6, b: Fp6): Fp6 {
  return { c0: fp2Sub(a.c0, b.c0), c1: fp2Sub(a.c1, b.c1), c2: fp2Sub(a.c2, b.c2) };
}

function fp6Neg_ref(a: Fp6): Fp6 {
  return { c0: fp2Neg(a.c0), c1: fp2Neg(a.c1), c2: fp2Neg(a.c2) };
}

function fp6Mul_ref(a: Fp6, b: Fp6): Fp6 {
  const t0 = fp2Mul(a.c0, b.c0);
  const t1 = fp2Mul(a.c1, b.c1);
  const t2 = fp2Mul(a.c2, b.c2);
  return {
    c0: fp2Add(t0, fp2Mul(fp2Sub(fp2Mul(fp2Add(a.c1, a.c2), fp2Add(b.c1, b.c2)), fp2Add(t1, t2)), XI)),
    c1: fp2Add(fp2Sub(fp2Mul(fp2Add(a.c0, a.c1), fp2Add(b.c0, b.c1)), fp2Add(t0, t1)), fp2Mul(t2, XI)),
    c2: fp2Add(fp2Sub(fp2Mul(fp2Add(a.c0, a.c2), fp2Add(b.c0, b.c2)), fp2Add(t0, t2)), t1),
  };
}

function emitPushFp6(ops: StackOp[], v: Fp6): void {
  emitPushFp2(ops, v.c0.c0, v.c0.c1);
  emitPushFp2(ops, v.c1.c0, v.c1.c1);
  emitPushFp2(ops, v.c2.c0, v.c2.c1);
}

/**
 * Run StackOps that leave [c0_0, c0_1, c1_0, c1_1, c2_0, c2_1] (Fp6) on the stack.
 * Check each component matches expected.
 */
function runFp6Test(ops: StackOp[], expected: Fp6): { success: boolean; error?: string } {
  const scriptHex = stackOpsToHex(ops);
  // Stack: [c0_0, c0_1, c1_0, c1_1, c2_0, c2_1] (c2_1 on top)
  // Check from top: c2_1, c2_0, c1_1, c1_0, c0_1, c0_0
  const lockingHex = scriptHex +
    emitBigIntHex(fpMod(expected.c2.c1)) + '9d' + // NUMEQUALVERIFY c2_1
    emitBigIntHex(fpMod(expected.c2.c0)) + '9d' + // NUMEQUALVERIFY c2_0
    emitBigIntHex(fpMod(expected.c1.c1)) + '9d' + // NUMEQUALVERIFY c1_1
    emitBigIntHex(fpMod(expected.c1.c0)) + '9d' + // NUMEQUALVERIFY c1_0
    emitBigIntHex(fpMod(expected.c0.c1)) + '9d' + // NUMEQUALVERIFY c0_1
    emitBigIntHex(fpMod(expected.c0.c0)) + '9c';  // NUMEQUAL c0_0
  return runScript(lockingHex, '');
}

// ---------------------------------------------------------------------------
// Fp6 tests
// ---------------------------------------------------------------------------

describe('BN254 Fp6 field arithmetic — Script execution', () => {
  const a6 = fp6(fp2(7n, 11n), fp2(3n, 5n), fp2(13n, 17n));
  const b6 = fp6(fp2(2n, 4n), fp2(6n, 8n), fp2(10n, 12n));

  it('fp6Add: basic', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp6(ops, a6);
    emitPushFp6(ops, b6);
    emitFp6Add(ops);
    emitCleanupP(ops);
    const result = runFp6Test(ops, fp6Add_ref(a6, b6));
    if (!result.success) console.log('fp6Add error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fp6Sub: basic', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp6(ops, a6);
    emitPushFp6(ops, b6);
    emitFp6Sub(ops);
    emitCleanupP(ops);
    const result = runFp6Test(ops, fp6Sub_ref(a6, b6));
    if (!result.success) console.log('fp6Sub error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fp6Neg: basic', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp6(ops, a6);
    emitFp6Neg(ops);
    emitCleanupP(ops);
    const result = runFp6Test(ops, fp6Neg_ref(a6));
    if (!result.success) console.log('fp6Neg error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fp6Mul: Karatsuba', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp6(ops, a6);
    emitPushFp6(ops, b6);
    emitFp6Mul(ops);
    emitCleanupP(ops);
    const result = runFp6Test(ops, fp6Mul_ref(a6, b6));
    if (!result.success) console.log('fp6Mul error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fp6Sqr: consistent with fp6Mul', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp6(ops, a6);
    emitFp6Sqr(ops);
    emitCleanupP(ops);
    const result = runFp6Test(ops, fp6Mul_ref(a6, a6));
    if (!result.success) console.log('fp6Sqr error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fp6Inv: check against reference', () => {
    // Reference implementation of fp6Inv (from pairing.ts)
    function fp6Inv_ref(a: Fp6): Fp6 {
      const c0s = fp2Sqr(a.c0);
      const c1s = fp2Sqr(a.c1);
      const c2s = fp2Sqr(a.c2);
      const mulByXi = (x: Fp2) => fp2Mul(x, XI);
      const t0 = fp2Sub(c0s, mulByXi(fp2Mul(a.c1, a.c2)));
      const t1 = fp2Sub(mulByXi(c2s), fp2Mul(a.c0, a.c1));
      const t2 = fp2Sub(c1s, fp2Mul(a.c0, a.c2));
      const det = fp2Add(
        fp2Mul(a.c0, t0),
        mulByXi(fp2Add(fp2Mul(a.c2, t1), fp2Mul(a.c1, t2))),
      );
      const detInv = fp2Inv(det);
      return {
        c0: fp2Mul(t0, detInv),
        c1: fp2Mul(t1, detInv),
        c2: fp2Mul(t2, detInv),
      };
    }

    const expected = fp6Inv_ref(a6);
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp6(ops, a6);
    emitFp6Inv(ops);
    emitCleanupP(ops);
    const result = runFp6Test(ops, expected);
    if (!result.success) console.log('fp6Inv error:', result.error);
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Fp12 reference implementations (inline for test independence)
// ---------------------------------------------------------------------------

function fp12(c0: Fp6, c1: Fp6): Fp12 { return { c0, c1 }; }

function fp6MulByV_ref(a: Fp6): Fp6 {
  // v-multiplication: (c0, c1, c2) → (xi*c2, c0, c1)
  return { c0: fp2Mul(a.c2, XI), c1: a.c0, c2: a.c1 };
}

function fp12Mul_ref(f: Fp12, g: Fp12): Fp12 {
  const a0b0 = fp6Mul_ref(f.c0, g.c0);
  const a1b1 = fp6Mul_ref(f.c1, g.c1);
  return {
    c0: fp6Add_ref(a0b0, fp6MulByV_ref(a1b1)),
    c1: fp6Sub_ref(
      fp6Sub_ref(fp6Mul_ref(fp6Add_ref(f.c0, f.c1), fp6Add_ref(g.c0, g.c1)), a0b0),
      a1b1
    ),
  };
}

function fp12Conj_ref(f: Fp12): Fp12 {
  return { c0: f.c0, c1: fp6Neg_ref(f.c1) };
}

function emitPushFp12(ops: StackOp[], v: Fp12): void {
  emitPushFp6(ops, v.c0);
  emitPushFp6(ops, v.c1);
}

/**
 * Run StackOps that leave 12 Fp slots (Fp12) on the stack.
 * Check each slot matches expected.
 */
function runFp12Test(ops: StackOp[], expected: Fp12): { success: boolean; error?: string } {
  const scriptHex = stackOpsToHex(ops);
  // Stack (bottom to top): c0.c0_0, c0.c0_1, c0.c1_0, c0.c1_1, c0.c2_0, c0.c2_1,
  //                         c1.c0_0, c1.c0_1, c1.c1_0, c1.c1_1, c1.c2_0, c1.c2_1
  // Check from top: c1.c2_1, c1.c2_0, c1.c1_1, c1.c1_0, c1.c0_1, c1.c0_0,
  //                 c0.c2_1, c0.c2_0, c0.c1_1, c0.c1_0, c0.c0_1, c0.c0_0
  const lockingHex = scriptHex +
    emitBigIntHex(fpMod(expected.c1.c2.c1)) + '9d' +
    emitBigIntHex(fpMod(expected.c1.c2.c0)) + '9d' +
    emitBigIntHex(fpMod(expected.c1.c1.c1)) + '9d' +
    emitBigIntHex(fpMod(expected.c1.c1.c0)) + '9d' +
    emitBigIntHex(fpMod(expected.c1.c0.c1)) + '9d' +
    emitBigIntHex(fpMod(expected.c1.c0.c0)) + '9d' +
    emitBigIntHex(fpMod(expected.c0.c2.c1)) + '9d' +
    emitBigIntHex(fpMod(expected.c0.c2.c0)) + '9d' +
    emitBigIntHex(fpMod(expected.c0.c1.c1)) + '9d' +
    emitBigIntHex(fpMod(expected.c0.c1.c0)) + '9d' +
    emitBigIntHex(fpMod(expected.c0.c0.c1)) + '9d' +
    emitBigIntHex(fpMod(expected.c0.c0.c0)) + '9c';
  return runScript(lockingHex, '');
}

// ---------------------------------------------------------------------------
// Fp12 tests
// ---------------------------------------------------------------------------

describe('BN254 Fp12 field arithmetic — Script execution', () => {
  const f12 = fp12(
    fp6(fp2(7n, 11n), fp2(3n, 5n), fp2(13n, 17n)),
    fp6(fp2(2n, 4n), fp2(6n, 8n), fp2(10n, 12n)),
  );
  const g12 = fp12(
    fp6(fp2(19n, 23n), fp2(29n, 31n), fp2(37n, 41n)),
    fp6(fp2(43n, 47n), fp2(53n, 59n), fp2(61n, 67n)),
  );

  it('fp12Mul: basic', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp12(ops, f12);
    emitPushFp12(ops, g12);
    emitFp12Mul(ops);
    emitCleanupP(ops);
    const expected = fp12Mul_ref(f12, g12);
    const result = runFp12Test(ops, expected);
    if (!result.success) console.log('fp12Mul error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fp12Sqr: consistent with fp12Mul', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp12(ops, f12);
    emitFp12Sqr(ops);
    emitCleanupP(ops);
    const expected = fp12Mul_ref(f12, f12);
    const result = runFp12Test(ops, expected);
    if (!result.success) console.log('fp12Sqr error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fp12Conj: negate c1', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp12(ops, f12);
    emitFp12Conj(ops);
    emitCleanupP(ops);
    const expected = fp12Conj_ref(f12);
    const result = runFp12Test(ops, expected);
    if (!result.success) console.log('fp12Conj error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fp12Mul: identity check (f * conj(f) should have c1 components)', () => {
    // f * conj(f) tests both mul and conjugate correctness
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp12(ops, f12);
    emitPushFp12(ops, fp12Conj_ref(f12));
    emitFp12Mul(ops);
    emitCleanupP(ops);
    const expected = fp12Mul_ref(f12, fp12Conj_ref(f12));
    const result = runFp12Test(ops, expected);
    if (!result.success) console.log('fp12Mul*Conj error:', result.error);
    expect(result.success).toBe(true);
  });

  it('fp12Inv: f * f^{-1} = 1', () => {
    // Compute f^{-1} via Script, then multiply with f and check for identity
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp12(ops, f12);   // for the multiplication
    emitPushFp12(ops, f12);   // for the inverse
    emitFp12Inv(ops);          // [..., f, f^{-1}]
    emitFp12Mul(ops);          // [..., f * f^{-1}] = 1
    emitCleanupP(ops);
    // Fp12 identity: c0 = (1, 0, 0, 0, 0, 0), c1 = (0, 0, 0, 0, 0, 0)
    const fp12One = fp12(
      fp6(fp2(1n, 0n), fp2(0n, 0n), fp2(0n, 0n)),
      fp6(fp2(0n, 0n), fp2(0n, 0n), fp2(0n, 0n)),
    );
    const result = runFp12Test(ops, fp12One);
    if (!result.success) console.log('fp12Inv error:', result.error);
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Line evaluation tests (verifies Script codegen matches off-chain)
// ---------------------------------------------------------------------------

import { fp2MulScalar } from '../bn254/fp2.js';
import { G1_X, G1_Y, G2_X_C0, G2_X_C1, G2_Y_C0, G2_Y_C1 } from '../bn254/constants.js';
import { precomputeG2Trace, emitLineEvalAndMul, emitPushFp12One } from '../bn254/pairing-script.js';
import type { G2Point } from '../types.js';

describe('BN254 line evaluation — Script execution', () => {
  const G2: G2Point = {
    x: { c0: G2_X_C0, c1: G2_X_C1 },
    y: { c0: G2_Y_C0, c1: G2_Y_C1 },
  };
  const px = G1_X; // G1 generator x
  const py = G1_Y; // G1 generator y

  it('line eval at G1 matches off-chain D-type twist formula', () => {
    // Precompute the G2 trace (first doubling line)
    const trace = precomputeG2Trace(G2);
    const line = trace.doublingLines[0]!;

    // Off-chain: build the expected sparse Fp12 line element
    // c0 = (s0, 0, 0) where s0 = (py, 0)
    // c1 = (s1, s2, 0) where s1 = -λ·px, s2 = λ·rx - ry
    const s0: Fp2 = fp2(fpMod(py), 0n);
    const s1: Fp2 = fp2MulScalar(line.lambda, fpNeg(px));
    const s2: Fp2 = line.lambdaRxMinusRy;

    // Build full Fp12 from sparse: c0 = (s0, 0, 0), c1 = (s1, s2, 0)
    const expectedLine: Fp12 = fp12(
      fp6(s0, fp2(0n, 0n), fp2(0n, 0n)),
      fp6(s1, s2, fp2(0n, 0n)),
    );

    // Multiply identity × line = line
    const expected = fp12Mul_ref(
      fp12(fp6(fp2(1n, 0n), fp2(0n, 0n), fp2(0n, 0n)), fp6(fp2(0n, 0n), fp2(0n, 0n), fp2(0n, 0n))),
      expectedLine,
    );

    // Script: push identity Fp12, push G1 point, apply line eval
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp12One(ops);           // f = 1 (identity)
    emitPushFp(ops, fpMod(px));     // push G1.x
    emitPushFp(ops, fpMod(py));     // push G1.y
    emitLineEvalAndMul(ops, line);  // f' = 1 · line(P)
    emitCleanupP(ops);

    const result = runFp12Test(ops, expected);
    if (!result.success) console.log('lineEval error:', result.error);
    expect(result.success).toBe(true);
  });

  it('line eval with different G1 point produces different result', () => {
    const trace = precomputeG2Trace(G2);
    const line = trace.doublingLines[0]!;

    // Use a different G1 point: px=5, py=some value (doesn't need to be on curve for line eval)
    const px2 = 5n;
    const py2 = 7n;

    const s0: Fp2 = fp2(fpMod(py2), 0n);
    const s1: Fp2 = fp2MulScalar(line.lambda, fpNeg(px2));
    const s2: Fp2 = line.lambdaRxMinusRy;

    const expectedLine: Fp12 = fp12(
      fp6(s0, fp2(0n, 0n), fp2(0n, 0n)),
      fp6(s1, s2, fp2(0n, 0n)),
    );

    const expected = fp12Mul_ref(
      fp12(fp6(fp2(1n, 0n), fp2(0n, 0n), fp2(0n, 0n)), fp6(fp2(0n, 0n), fp2(0n, 0n), fp2(0n, 0n))),
      expectedLine,
    );

    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp12One(ops);
    emitPushFp(ops, fpMod(px2));
    emitPushFp(ops, fpMod(py2));
    emitLineEvalAndMul(ops, line);
    emitCleanupP(ops);

    const result = runFp12Test(ops, expected);
    if (!result.success) console.log('lineEval alt point error:', result.error);
    expect(result.success).toBe(true);
  });

  it('addition line eval matches off-chain', () => {
    const trace = precomputeG2Trace(G2);
    // Find the first addition line
    const bits = getMillerBitsForTest();
    let addIdx = -1;
    for (let i = 1; i < bits.length; i++) {
      if (bits[i] === 1) { addIdx = i - 1; break; }
    }
    if (addIdx < 0) throw new Error('No addition line found');
    const line = trace.additionLines.get(addIdx)!;
    expect(line).toBeDefined();

    const s0: Fp2 = fp2(fpMod(py), 0n);
    const s1: Fp2 = fp2MulScalar(line.lambda, fpNeg(px));
    const s2: Fp2 = line.lambdaRxMinusRy;

    const expectedLine: Fp12 = fp12(
      fp6(s0, fp2(0n, 0n), fp2(0n, 0n)),
      fp6(s1, s2, fp2(0n, 0n)),
    );
    const expected = fp12Mul_ref(
      fp12(fp6(fp2(1n, 0n), fp2(0n, 0n), fp2(0n, 0n)), fp6(fp2(0n, 0n), fp2(0n, 0n), fp2(0n, 0n))),
      expectedLine,
    );

    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp12One(ops);
    emitPushFp(ops, fpMod(px));
    emitPushFp(ops, fpMod(py));
    emitLineEvalAndMul(ops, line);
    emitCleanupP(ops);

    const result = runFp12Test(ops, expected);
    if (!result.success) console.log('addLine error:', result.error);
    expect(result.success).toBe(true);
  });
});

/** Helper to get Miller loop bits (duplicates logic from pairing-script for test use). */
function getMillerBitsForTest(): number[] {
  const BN_X = 4965661367192848881n;
  const v = 6n * BN_X + 2n;
  const bits: number[] = [];
  let val = v;
  while (val > 0n) {
    bits.push(Number(val & 1n));
    val >>= 1n;
  }
  bits.reverse();
  return bits;
}
