/**
 * End-to-end test: Groth16 verifier executed in Bitcoin Script.
 *
 * Creates a synthetic valid proof, generates a verifier script using
 * generateGroth16VerifierForKnownProof, and runs it through the BSV SDK
 * Script interpreter to verify correctness.
 *
 * This is the ultimate correctness test for the BN254 pairing codegen:
 * every field operation, line evaluation, Miller loop step, and final
 * exponentiation step is executed as real Bitcoin Script opcodes.
 */

import { describe, it, expect } from 'vitest';
import { LockingScript, UnlockingScript, Spend } from '@bsv/sdk';
import type { StackOp } from 'runar-ir-schema';
import { g1Mul } from '../bn254/g1.js';
import { g2Mul } from '../bn254/g2.js';
import { G1_X, G1_Y, G2_X_C0, G2_X_C1, G2_Y_C0, G2_Y_C1, R } from '../bn254/constants.js';
import {
  generateGroth16VerifierForKnownProof,
  generateRuntimeGroth16Verifier,
  emitFinalExpEasy, emitFinalExpHard, emitFp12EqOne,
  emitPushFp12One,
  emitG2AffineDoubleWithLine,
  emitSinglePairingMillerLoop,
  precomputeG2Trace,
  getMillerBits,
  emitApplyLineConst,
  emitApplyLine,
} from '../bn254/pairing-script.js';
import { verifyGroth16 } from '../groth16/verify.js';
import {
  millerLoop, finalExponentiation, checkPairingProduct,
  fp12Mul, fp12IsOne,
} from '../bn254/pairing.js';
import { g1Neg } from '../bn254/g1.js';
import { emitInitP, emitCleanupP, emitPushFp, emitFpNeg } from '../bn254/field-script.js';
import { emitPushFp2, emitRoll, emitDrop, emitToAlt, emitFromAlt } from '../bn254/fp2-script.js';
import {
  emitFp12Mul, emitFp12Sqr, emitFp12Inv, emitFp12Conj,
  emitFp12FrobeniusP2,
} from '../bn254/fp12-script.js';
import { fpMod } from '../bn254/field.js';
import { fp2Add, fp2Sub, fp2Mul, fp2Sqr, fp2Inv } from '../bn254/fp2.js';
import type { VerificationKey, Groth16Proof, G1Point, G2Point, Fp12 } from '../types.js';

const G1_GEN: G1Point = { x: G1_X, y: G1_Y };
const G2_GEN: G2Point = { x: { c0: G2_X_C0, c1: G2_X_C1 }, y: { c0: G2_Y_C0, c1: G2_Y_C1 } };

// ---------------------------------------------------------------------------
// Minimal StackOp-to-hex emitter (same as field-script-exec.test.ts)
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
  'OP_BOOLAND': 0x9a,
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
      case 'roll': parts.push('7a'); break;
      case 'pick': parts.push('79'); break;
      default:
        throw new Error(`Unsupported op: ${(op as { op: string }).op}`);
    }
  }
  return parts.join('');
}

function runScript(lockingHex: string, unlockingHex: string): { success: boolean; error?: string } {
  const lockingScript = LockingScript.fromHex(lockingHex);
  const unlockingScript = UnlockingScript.fromHex(unlockingHex !== '' ? unlockingHex : '51');
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Groth16 verifier — Script execution', () => {
  it('verifies a synthetic proof (0 public inputs) in Script', () => {
    // Create synthetic valid proof (same as groth16-verify.test.ts)
    const alpha_s = 7n;
    const beta_s = 11n;
    const ic0_s = 5n;
    const a_s = 13n;
    const b_s = 17n;

    const alpha = g1Mul(G1_GEN, alpha_s);
    const beta = g2Mul(G2_GEN, beta_s);
    const gamma = G2_GEN;
    const delta = G2_GEN;
    const ic0 = g1Mul(G1_GEN, ic0_s);

    const A = g1Mul(G1_GEN, a_s);
    const B = g2Mul(G2_GEN, b_s);
    const c_scalar = ((a_s * b_s - alpha_s * beta_s - ic0_s) % R + R) % R;
    const C = g1Mul(G1_GEN, c_scalar);

    const vk: VerificationKey = { alpha, beta, gamma, delta, ic: [ic0] };
    const proof: Groth16Proof = { a: A, b: B, c: C };

    // Sanity: off-chain verification should pass
    expect(verifyGroth16(vk, proof, [])).toBe(true);

    // Generate Script verifier
    const { ops, sizeBytes } = generateGroth16VerifierForKnownProof(vk, proof, []);
    console.log(`Groth16 Script verifier: ${ops.length} ops, ~${(sizeBytes / 1024).toFixed(0)} KB`);

    // Convert to hex and run. Unlock script pushes OP_TRUE which stays at bottom.
    // We add OP_DROP at the locking script start to consume it.
    const allOps: StackOp[] = [
      { op: 'drop' } as StackOp,
      ...ops as StackOp[],
    ];
    const lockingHex = stackOpsToHex(allOps);
    const result = runScript(lockingHex, '');
    if (!result.success) {
      console.log('Groth16 Script verification failed:', result.error);
    }
    expect(result.success).toBe(true);
  }, 300000); // 5 minute timeout for this heavy test

  it('isolated: final exponentiation on known Fp12 produces correct result', () => {
    // Compute the product of Miller loops off-chain for our 4 pairing pairs
    const alpha_s = 7n;
    const beta_s = 11n;
    const ic0_s = 5n;
    const a_s = 13n;
    const b_s = 17n;

    const alpha = g1Mul(G1_GEN, alpha_s);
    const beta = g2Mul(G2_GEN, beta_s);
    const gamma = G2_GEN;
    const delta = G2_GEN;
    const ic0 = g1Mul(G1_GEN, ic0_s);
    const A = g1Mul(G1_GEN, a_s);
    const B = g2Mul(G2_GEN, b_s);
    const c_scalar = ((a_s * b_s - alpha_s * beta_s - ic0_s) % R + R) % R;
    const C = g1Mul(G1_GEN, c_scalar);

    // Verify off-chain
    const L = ic0;
    const offChainResult = checkPairingProduct([
      { g1: A, g2: B },
      { g1: g1Neg(alpha), g2: beta },
      { g1: g1Neg(L), g2: gamma },
      { g1: g1Neg(C), g2: delta },
    ]);
    console.log('Off-chain pairing product check:', offChainResult);
    expect(offChainResult).toBe(true);

    // Compute individual Miller loops and their product
    let mlProduct: Fp12 = millerLoop(A, B);
    mlProduct = fp12Mul(mlProduct, millerLoop(g1Neg(alpha), beta));
    mlProduct = fp12Mul(mlProduct, millerLoop(g1Neg(L), gamma));
    mlProduct = fp12Mul(mlProduct, millerLoop(g1Neg(C), delta));

    const feResult = finalExponentiation(mlProduct);
    console.log('Off-chain final exp of product is 1?', fp12IsOne(feResult));

    // Push mlProduct, run final exp in Script, check == 1
    const ops: StackOp[] = [];
    emitInitP(ops);

    const pushFp12Script = (f: Fp12) => {
      emitPushFp2(ops, fpMod(f.c0.c0.c0), fpMod(f.c0.c0.c1));
      emitPushFp2(ops, fpMod(f.c0.c1.c0), fpMod(f.c0.c1.c1));
      emitPushFp2(ops, fpMod(f.c0.c2.c0), fpMod(f.c0.c2.c1));
      emitPushFp2(ops, fpMod(f.c1.c0.c0), fpMod(f.c1.c0.c1));
      emitPushFp2(ops, fpMod(f.c1.c1.c0), fpMod(f.c1.c1.c1));
      emitPushFp2(ops, fpMod(f.c1.c2.c0), fpMod(f.c1.c2.c1));
    };
    pushFp12Script(mlProduct);

    emitFinalExpEasy(ops);
    emitFinalExpHard(ops);
    emitFp12EqOne(ops);
    emitCleanupP(ops);

    console.log(`Final exp Script: ${ops.length} ops`);
    const lockingHex = stackOpsToHex([{ op: 'drop' } as StackOp, ...ops as StackOp[]]);
    const scriptResult = runScript(lockingHex, '');
    if (!scriptResult.success) {
      console.log('Final exp Script test failed:', scriptResult.error);
    }
    expect(scriptResult.success).toBe(true);
  }, 300000);

  it('Fp12 Frobenius P2 on identity', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp12One(ops);
    emitFp12FrobeniusP2(ops);
    emitFp12EqOne(ops);
    emitCleanupP(ops);
    const lockingHex = stackOpsToHex([{ op: 'drop' } as StackOp, ...ops as StackOp[]]);
    const result = runScript(lockingHex, '');
    expect(result.success).toBe(true);
  });

  it('isolated: easy part on identity produces identity', () => {
    // Fp12(1) through the easy part should give 1
    // Easy: t = conj(f) · f^{-1} = 1; result = frobP2(t) · t = 1
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp12One(ops);
    emitFinalExpEasy(ops);
    emitFp12EqOne(ops);
    emitCleanupP(ops);

    const lockingHex = stackOpsToHex([{ op: 'drop' } as StackOp, ...ops as StackOp[]]);
    const scriptResult = runScript(lockingHex, '');
    if (!scriptResult.success) {
      console.log('Easy part identity test failed:', scriptResult.error);
    }
    expect(scriptResult.success).toBe(true);
  }, 60000);

  it('isolated: hard part on identity produces identity', () => {
    const ops: StackOp[] = [];
    emitInitP(ops);
    emitPushFp12One(ops);
    emitFinalExpHard(ops);
    emitFp12EqOne(ops);
    emitCleanupP(ops);

    console.log(`Hard part identity: ${ops.length} ops`);
    const lockingHex = stackOpsToHex([{ op: 'drop' } as StackOp, ...ops as StackOp[]]);
    const scriptResult = runScript(lockingHex, '');
    if (!scriptResult.success) {
      console.log('Hard part identity test failed:', scriptResult.error);
    }
    expect(scriptResult.success).toBe(true);
  }, 300000);

  it('rejects a tampered proof in Script', () => {
    const alpha_s = 7n;
    const beta_s = 11n;
    const ic0_s = 5n;
    const a_s = 13n;
    const b_s = 17n;

    const alpha = g1Mul(G1_GEN, alpha_s);
    const beta = g2Mul(G2_GEN, beta_s);
    const gamma = G2_GEN;
    const delta = G2_GEN;
    const ic0 = g1Mul(G1_GEN, ic0_s);

    const A = g1Mul(G1_GEN, a_s);
    const B = g2Mul(G2_GEN, b_s);
    const c_scalar = ((a_s * b_s - alpha_s * beta_s - ic0_s) % R + R) % R;
    const C = g1Mul(G1_GEN, c_scalar);

    // Tamper: use wrong A
    const badA = g1Mul(G1_GEN, 999n);
    const vk: VerificationKey = { alpha, beta, gamma, delta, ic: [ic0] };

    // Off-chain verification should fail
    expect(verifyGroth16(vk, { a: badA, b: B, c: C }, [])).toBe(false);

    // Script verification should also fail (the EqOne check should produce 0)
    const { ops } = generateGroth16VerifierForKnownProof(vk, { a: badA, b: B, c: C }, []);
    const lockingHex = stackOpsToHex(ops as StackOp[]);
    const result = runScript(lockingHex, '');
    // Should fail — the pairing check doesn't hold
    expect(result.success).toBe(false);
  }, 300000);
});

describe('G2 affine arithmetic — Script execution', () => {
  const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

  it('G2 affine doubling matches off-chain computation', () => {
    // Use the BN254 G2 generator as input
    const Rx = { c0: G2_X_C0, c1: G2_X_C1 };
    const Ry = { c0: G2_Y_C0, c1: G2_Y_C1 };

    // Off-chain doubling
    // lambda = 3*Rx^2 / (2*Ry)
    const rx2 = fp2Sqr(Rx);
    const threeRx2 = fp2Add(fp2Add(rx2, rx2), rx2);
    const twoRy = fp2Add(Ry, Ry);
    const lambda = fp2Mul(threeRx2, fp2Inv(twoRy));
    const lRxRy = fp2Sub(fp2Mul(lambda, Rx), Ry);
    // R'x = lambda^2 - 2*Rx
    const lamSq = fp2Sqr(lambda);
    const twoRx = fp2Add(Rx, Rx);
    const rpX = fp2Sub(lamSq, twoRx);
    // R'y = lambda*(Rx - R'x) - Ry
    const rpY = fp2Sub(fp2Mul(lambda, fp2Sub(Rx, rpX)), Ry);

    // Build script: push Rx, Ry, call doubleWithLine, verify output
    const ops: StackOp[] = [];
    emitInitP(ops);
    // Push Rx, Ry (Fp2 = c0 below c1)
    emitPushFp(ops, Rx.c0);
    emitPushFp(ops, Rx.c1);
    emitPushFp(ops, Ry.c0);
    emitPushFp(ops, Ry.c1);
    // Stack: [Rx(2), Ry(2)]
    emitG2AffineDoubleWithLine(ops);
    // Stack: [R'x(2), R'y(2), lambda(2), lRxRy(2)]

    // Verify lRxRy.c1 (TOS)
    emitPushFp(ops, fpMod(lRxRy.c1));
    ops.push({ op: 'opcode', code: 'OP_NUMEQUALVERIFY' } as StackOp);
    // Verify lRxRy.c0
    emitPushFp(ops, fpMod(lRxRy.c0));
    ops.push({ op: 'opcode', code: 'OP_NUMEQUALVERIFY' } as StackOp);
    // Verify lambda.c1
    emitPushFp(ops, fpMod(lambda.c1));
    ops.push({ op: 'opcode', code: 'OP_NUMEQUALVERIFY' } as StackOp);
    // Verify lambda.c0
    emitPushFp(ops, fpMod(lambda.c0));
    ops.push({ op: 'opcode', code: 'OP_NUMEQUALVERIFY' } as StackOp);
    // Verify R'y.c1
    emitPushFp(ops, fpMod(rpY.c1));
    ops.push({ op: 'opcode', code: 'OP_NUMEQUALVERIFY' } as StackOp);
    // Verify R'y.c0
    emitPushFp(ops, fpMod(rpY.c0));
    ops.push({ op: 'opcode', code: 'OP_NUMEQUALVERIFY' } as StackOp);
    // Verify R'x.c1
    emitPushFp(ops, fpMod(rpX.c1));
    ops.push({ op: 'opcode', code: 'OP_NUMEQUALVERIFY' } as StackOp);
    // Verify R'x.c0
    emitPushFp(ops, fpMod(rpX.c0));
    ops.push({ op: 'opcode', code: 'OP_NUMEQUALVERIFY' } as StackOp);

    emitCleanupP(ops);
    ops.push({ op: 'opcode', code: 'OP_TRUE' } as StackOp);

    const lockingHex = stackOpsToHex(ops);
    const result = runScript(lockingHex, '');
    if (!result.success) {
      console.log('G2 doubling failed:', result.error);
    }
    expect(result.success).toBe(true);
  }, 120000);
});

describe('Runtime Groth16 verifier — Script execution', () => {
  /**
   * Helper: push an Fp element as a script number in the unlock script.
   */
  function pushFp(n: bigint): string {
    const mod = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
    const v = ((n % mod) + mod) % mod;
    return emitBigIntHex(v);
  }

  it('verifies a synthetic proof with runtime B (0 public inputs)', () => {
    // Same synthetic proof as the precomputed test
    const alpha_s = 7n;
    const beta_s = 11n;
    const ic0_s = 5n;
    const a_s = 13n;
    const b_s = 17n;

    const alpha = g1Mul(G1_GEN, alpha_s);
    const beta = g2Mul(G2_GEN, beta_s);
    const gamma = G2_GEN;
    const delta = G2_GEN;
    const ic0 = g1Mul(G1_GEN, ic0_s);

    const A = g1Mul(G1_GEN, a_s);
    const B = g2Mul(G2_GEN, b_s);
    const c_scalar = ((a_s * b_s - alpha_s * beta_s - ic0_s) % R + R) % R;
    const C = g1Mul(G1_GEN, c_scalar);

    const vk: VerificationKey = { alpha, beta, gamma, delta, ic: [ic0] };

    // Sanity: off-chain verification should pass
    expect(verifyGroth16(vk, { a: A, b: B, c: C }, [])).toBe(true);

    // Sanity: verify the split equation off-chain
    // Runtime verifier computes: e(-A,B) · e(α,β) · e(L,γ) · e(C,δ) = 1
    const negA = g1Neg(A);
    const L = ic0; // 0 public inputs, L = IC[0]
    const f_ab = millerLoop(negA, B);
    const f_alpha_beta = millerLoop(alpha, beta);
    const f_L_gamma = millerLoop(L, gamma);
    const f_C_delta = millerLoop(C, delta);
    const f_vk = fp12Mul(fp12Mul(f_alpha_beta, f_L_gamma), f_C_delta);
    const f_total = fp12Mul(f_vk, f_ab);
    const feResult = finalExponentiation(f_total);
    console.log('Off-chain split equation result is 1?', fp12IsOne(feResult));
    expect(fp12IsOne(feResult)).toBe(true);

    // Generate runtime verifier (VK baked in, proof as stack inputs)
    const { ops, sizeBytes } = generateRuntimeGroth16Verifier(vk, 0);
    console.log(`Runtime Groth16 verifier: ${ops.length} ops, ~${(sizeBytes / 1024).toFixed(0)} KB`);

    // Build unlock script: push B(4 Fp2 coords), A(2 Fp coords), C(2 Fp coords)
    // Stack order (bottom to top):
    //   B.x.c0, B.x.c1, B.y.c0, B.y.c1, A.x, A.y, C.x, C.y
    const unlockHex = [
      pushFp(B.x.c0), pushFp(B.x.c1),
      pushFp(B.y.c0), pushFp(B.y.c1),
      pushFp(A.x), pushFp(A.y),
      pushFp(C.x), pushFp(C.y),
    ].join('');

    const lockingHex = stackOpsToHex(ops as StackOp[]);
    console.log(`Runtime verifier locking script: ${lockingHex.length / 2} bytes`);
    console.log(`Runtime verifier unlock script: ${unlockHex.length / 2} bytes`);

    const result = runScript(lockingHex, unlockHex);
    if (!result.success) {
      console.log('Runtime Groth16 Script verification failed:', result.error);
    }
    expect(result.success).toBe(true);
  }, 600000); // 10 minute timeout — runtime verifier is much larger

  it('rejects a tampered proof with runtime B', () => {
    const alpha_s = 7n;
    const beta_s = 11n;
    const ic0_s = 5n;
    const a_s = 13n;
    const b_s = 17n;

    const alpha = g1Mul(G1_GEN, alpha_s);
    const beta = g2Mul(G2_GEN, beta_s);
    const gamma = G2_GEN;
    const delta = G2_GEN;
    const ic0 = g1Mul(G1_GEN, ic0_s);

    const B = g2Mul(G2_GEN, b_s);
    const c_scalar = ((a_s * b_s - alpha_s * beta_s - ic0_s) % R + R) % R;
    const C = g1Mul(G1_GEN, c_scalar);

    // Tamper: use wrong A
    const badA = g1Mul(G1_GEN, 999n);
    const vk: VerificationKey = { alpha, beta, gamma, delta, ic: [ic0] };

    // Off-chain verification should fail
    expect(verifyGroth16(vk, { a: badA, b: B, c: C }, [])).toBe(false);

    // Generate runtime verifier
    const { ops } = generateRuntimeGroth16Verifier(vk, 0);

    // Build unlock script with tampered A
    const unlockHex = [
      pushFp(B.x.c0), pushFp(B.x.c1),
      pushFp(B.y.c0), pushFp(B.y.c1),
      pushFp(badA.x), pushFp(badA.y),
      pushFp(C.x), pushFp(C.y),
    ].join('');

    const lockingHex = stackOpsToHex(ops as StackOp[]);
    const result = runScript(lockingHex, unlockHex);
    expect(result.success).toBe(false);
  }, 600000);

  it('3-pairing VK ML with C from unlock script', () => {
    // Same as isolated test but C is pushed from the unlock script
    const alpha_s = 7n;
    const beta_s = 11n;
    const ic0_s = 5n;
    const a_s = 13n;
    const b_s = 17n;

    const alpha = g1Mul(G1_GEN, alpha_s);
    const beta = g2Mul(G2_GEN, beta_s);
    const gamma = G2_GEN;
    const delta = G2_GEN;
    const ic0 = g1Mul(G1_GEN, ic0_s);
    const c_scalar = ((a_s * b_s - alpha_s * beta_s - ic0_s) % R + R) % R;
    const C = g1Mul(G1_GEN, c_scalar);
    const vk: VerificationKey = { alpha, beta, gamma, delta, ic: [ic0] };

    // Compute f_vk off-chain
    const f_alpha_beta = millerLoop(alpha, beta);
    const f_L_gamma = millerLoop(ic0, gamma);
    const f_C_delta = millerLoop(C, delta);
    const f_vk = fp12Mul(fp12Mul(f_alpha_beta, f_L_gamma), f_C_delta);

    // Push C via unlock script
    const unlockHex = [
      pushFp(C.x), pushFp(C.y),
    ].join('');

    const ops: StackOp[] = [];
    emitInitP(ops);

    // Stack: [C.x, C.y] (from unlock)
    // Push L as constant
    emitPushFp(ops, fpMod(ic0.x));
    emitPushFp(ops, fpMod(ic0.y));
    // Stack: [C.x, C.y, L.x, L.y]
    // Rearrange to [L.x, L.y, C.x, C.y]
    emitRoll(ops, 3); emitRoll(ops, 3);
    // Stack: [L.x, L.y, C.x, C.y]

    const traceBeta = precomputeG2Trace(vk.beta);
    const traceGamma = precomputeG2Trace(vk.gamma);
    const traceDelta = precomputeG2Trace(vk.delta);

    emitPushFp12One(ops);
    const bits = getMillerBits();
    for (let i = 1; i < bits.length; i++) {
      const stepIdx = i - 1;
      emitFp12Sqr(ops);
      emitApplyLineConst(ops, traceBeta.doublingLines[stepIdx]!, vk.alpha);
      emitApplyLine(ops, traceGamma.doublingLines[stepIdx]!, 14);
      emitApplyLine(ops, traceDelta.doublingLines[stepIdx]!, 12);
      if (bits[i] === 1) {
        const a0 = traceBeta.additionLines.get(stepIdx);
        if (a0) emitApplyLineConst(ops, a0, vk.alpha);
        const a1 = traceGamma.additionLines.get(stepIdx);
        if (a1) emitApplyLine(ops, a1, 14);
        const a2 = traceDelta.additionLines.get(stepIdx);
        if (a2) emitApplyLine(ops, a2, 12);
      }
    }
    emitApplyLineConst(ops, traceBeta.frobLine1, vk.alpha);
    emitApplyLine(ops, traceGamma.frobLine1, 14);
    emitApplyLine(ops, traceDelta.frobLine1, 12);
    emitApplyLineConst(ops, traceBeta.frobLine2, vk.alpha);
    emitApplyLine(ops, traceGamma.frobLine2, 14);
    emitApplyLine(ops, traceDelta.frobLine2, 12);

    // Cleanup L, C
    for (let k = 0; k < 4; k++) {
      emitRoll(ops, 12 + (3 - k));
      emitDrop(ops);
    }

    // Verify against f_vk
    const expected = [
      fpMod(f_vk.c1.c2.c1), fpMod(f_vk.c1.c2.c0),
      fpMod(f_vk.c1.c1.c1), fpMod(f_vk.c1.c1.c0),
      fpMod(f_vk.c1.c0.c1), fpMod(f_vk.c1.c0.c0),
      fpMod(f_vk.c0.c2.c1), fpMod(f_vk.c0.c2.c0),
      fpMod(f_vk.c0.c1.c1), fpMod(f_vk.c0.c1.c0),
      fpMod(f_vk.c0.c0.c1), fpMod(f_vk.c0.c0.c0),
    ];
    for (const val of expected) {
      emitPushFp(ops, val);
      ops.push({ op: 'opcode', code: 'OP_NUMEQUALVERIFY' } as StackOp);
    }
    emitCleanupP(ops);
    ops.push({ op: 'opcode', code: 'OP_TRUE' } as StackOp);

    const lockingHex = stackOpsToHex(ops as StackOp[]);
    const result = runScript(lockingHex, unlockHex);
    if (!result.success) {
      console.log('3-pairing VK ML (C from unlock) mismatch:', result.error);
    }
    expect(result.success).toBe(true);
  }, 600000);

  it('3-pairing VK ML matches off-chain f_vk', () => {
    // Run ONLY the 3-pairing VK multi-ML in Script and verify output
    const alpha_s = 7n;
    const beta_s = 11n;
    const ic0_s = 5n;
    const a_s = 13n;
    const b_s = 17n;

    const alpha = g1Mul(G1_GEN, alpha_s);
    const beta = g2Mul(G2_GEN, beta_s);
    const gamma = G2_GEN;
    const delta = G2_GEN;
    const ic0 = g1Mul(G1_GEN, ic0_s);
    const c_scalar = ((a_s * b_s - alpha_s * beta_s - ic0_s) % R + R) % R;
    const C = g1Mul(G1_GEN, c_scalar);

    const vk: VerificationKey = { alpha, beta, gamma, delta, ic: [ic0] };

    // Compute f_vk off-chain
    const f_alpha_beta = millerLoop(alpha, beta);
    const f_L_gamma = millerLoop(ic0, gamma);
    const f_C_delta = millerLoop(C, delta);
    const f_vk = fp12Mul(fp12Mul(f_alpha_beta, f_L_gamma), f_C_delta);

    // Build script that reproduces ONLY the 3-pairing VK ML from generateRuntimeGroth16Verifier
    const ops: StackOp[] = [];
    emitInitP(ops);

    // Push L and C (same layout as runtime verifier after IC computation and rearrangement)
    // Stack: [L.x, L.y, C.x, C.y]
    emitPushFp(ops, fpMod(ic0.x));
    emitPushFp(ops, fpMod(ic0.y));
    emitPushFp(ops, fpMod(C.x));
    emitPushFp(ops, fpMod(C.y));

    const traceBeta = precomputeG2Trace(vk.beta);
    const traceGamma = precomputeG2Trace(vk.gamma);
    const traceDelta = precomputeG2Trace(vk.delta);

    emitPushFp12One(ops);
    // Stack: [L.x, L.y, C.x, C.y, f(12)]

    const bits = getMillerBits();
    for (let i = 1; i < bits.length; i++) {
      const stepIdx = i - 1;
      emitFp12Sqr(ops);

      emitApplyLineConst(ops, traceBeta.doublingLines[stepIdx]!, vk.alpha);
      emitApplyLine(ops, traceGamma.doublingLines[stepIdx]!, 14);
      emitApplyLine(ops, traceDelta.doublingLines[stepIdx]!, 12);

      if (bits[i] === 1) {
        const a0 = traceBeta.additionLines.get(stepIdx);
        if (a0) emitApplyLineConst(ops, a0, vk.alpha);
        const a1 = traceGamma.additionLines.get(stepIdx);
        if (a1) emitApplyLine(ops, a1, 14);
        const a2 = traceDelta.additionLines.get(stepIdx);
        if (a2) emitApplyLine(ops, a2, 12);
      }
    }

    // Frobenius corrections
    emitApplyLineConst(ops, traceBeta.frobLine1, vk.alpha);
    emitApplyLine(ops, traceGamma.frobLine1, 14);
    emitApplyLine(ops, traceDelta.frobLine1, 12);

    emitApplyLineConst(ops, traceBeta.frobLine2, vk.alpha);
    emitApplyLine(ops, traceGamma.frobLine2, 14);
    emitApplyLine(ops, traceDelta.frobLine2, 12);

    // Cleanup L, C from below f
    for (let k = 0; k < 4; k++) {
      emitRoll(ops, 12 + (3 - k));
      emitDrop(ops);
    }
    // Stack: [f_vk(12)]

    // Verify against off-chain f_vk
    const expected = [
      fpMod(f_vk.c1.c2.c1), fpMod(f_vk.c1.c2.c0),
      fpMod(f_vk.c1.c1.c1), fpMod(f_vk.c1.c1.c0),
      fpMod(f_vk.c1.c0.c1), fpMod(f_vk.c1.c0.c0),
      fpMod(f_vk.c0.c2.c1), fpMod(f_vk.c0.c2.c0),
      fpMod(f_vk.c0.c1.c1), fpMod(f_vk.c0.c1.c0),
      fpMod(f_vk.c0.c0.c1), fpMod(f_vk.c0.c0.c0),
    ];

    for (const val of expected) {
      emitPushFp(ops, val);
      ops.push({ op: 'opcode', code: 'OP_NUMEQUALVERIFY' } as StackOp);
    }

    emitCleanupP(ops);
    ops.push({ op: 'opcode', code: 'OP_TRUE' } as StackOp);

    const lockingHex = stackOpsToHex(ops as StackOp[]);
    const result = runScript(lockingHex, '');
    if (!result.success) {
      console.log('3-pairing VK ML mismatch:', result.error);
    }
    expect(result.success).toBe(true);
  }, 600000);

  it('manual full runtime verifier (code copied from generateRuntimeGroth16Verifier)', () => {
    const alpha_s = 7n;
    const beta_s = 11n;
    const ic0_s = 5n;
    const a_s = 13n;
    const b_s = 17n;

    const alpha = g1Mul(G1_GEN, alpha_s);
    const beta = g2Mul(G2_GEN, beta_s);
    const gamma = G2_GEN;
    const delta = G2_GEN;
    const ic0 = g1Mul(G1_GEN, ic0_s);
    const A = g1Mul(G1_GEN, a_s);
    const B = g2Mul(G2_GEN, b_s);
    const c_scalar = ((a_s * b_s - alpha_s * beta_s - ic0_s) % R + R) % R;
    const C = g1Mul(G1_GEN, c_scalar);
    const vk: VerificationKey = { alpha, beta, gamma, delta, ic: [ic0] };

    const unlockHex = [
      pushFp(B.x.c0), pushFp(B.x.c1),
      pushFp(B.y.c0), pushFp(B.y.c1),
      pushFp(A.x), pushFp(A.y),
      pushFp(C.x), pushFp(C.y),
    ].join('');

    const ops: StackOp[] = [];
    emitInitP(ops);

    // Phase 1: IC computation (0 inputs)
    emitPushFp(ops, fpMod(ic0.x));
    emitPushFp(ops, fpMod(ic0.y));

    // Phase 2: negate A
    emitRoll(ops, 5);
    emitRoll(ops, 5);
    emitFpNeg(ops);

    // Phase 3: save A and B
    emitToAlt(ops); emitToAlt(ops);
    for (let k = 0; k < 4; k++) emitRoll(ops, 7);
    for (let k = 0; k < 4; k++) emitToAlt(ops);
    emitRoll(ops, 3); emitRoll(ops, 3);

    // 3-pairing ML
    const traceBeta = precomputeG2Trace(vk.beta);
    const traceGamma = precomputeG2Trace(vk.gamma);
    const traceDelta = precomputeG2Trace(vk.delta);
    emitPushFp12One(ops);
    const bits = getMillerBits();
    for (let i = 1; i < bits.length; i++) {
      const stepIdx = i - 1;
      emitFp12Sqr(ops);
      emitApplyLineConst(ops, traceBeta.doublingLines[stepIdx]!, vk.alpha);
      emitApplyLine(ops, traceGamma.doublingLines[stepIdx]!, 14);
      emitApplyLine(ops, traceDelta.doublingLines[stepIdx]!, 12);
      if (bits[i] === 1) {
        const a0 = traceBeta.additionLines.get(stepIdx);
        if (a0) emitApplyLineConst(ops, a0, vk.alpha);
        const a1 = traceGamma.additionLines.get(stepIdx);
        if (a1) emitApplyLine(ops, a1, 14);
        const a2 = traceDelta.additionLines.get(stepIdx);
        if (a2) emitApplyLine(ops, a2, 12);
      }
    }
    emitApplyLineConst(ops, traceBeta.frobLine1, vk.alpha);
    emitApplyLine(ops, traceGamma.frobLine1, 14);
    emitApplyLine(ops, traceDelta.frobLine1, 12);
    emitApplyLineConst(ops, traceBeta.frobLine2, vk.alpha);
    emitApplyLine(ops, traceGamma.frobLine2, 14);
    emitApplyLine(ops, traceDelta.frobLine2, 12);

    // Cleanup L, C
    for (let k = 0; k < 4; k++) {
      emitRoll(ops, 12 + (3 - k));
      emitDrop(ops);
    }

    // Phase 4: restore B and A
    for (let k = 0; k < 4; k++) emitFromAlt(ops);
    for (let k = 0; k < 2; k++) emitFromAlt(ops);

    // Single-pairing ML
    emitSinglePairingMillerLoop(ops);
    emitFp12Mul(ops);
    emitFinalExpEasy(ops);
    emitFinalExpHard(ops);
    emitFp12EqOne(ops);
    emitCleanupP(ops);

    console.log(`Manual runtime verifier: ${ops.length} ops`);

    const lockingHex = stackOpsToHex(ops as StackOp[]);
    const result = runScript(lockingHex, unlockHex);
    if (!result.success) {
      console.log('Manual runtime verifier failed:', result.error);
    }
    expect(result.success).toBe(true);
  }, 600000);

  it('full glue: unlock push → save A,B → const f_vk → restore → single ML', () => {
    // Full runtime verifier flow but with constant f_vk instead of 3-pairing ML
    const alpha_s = 7n;
    const beta_s = 11n;
    const ic0_s = 5n;
    const a_s = 13n;
    const b_s = 17n;

    const alpha = g1Mul(G1_GEN, alpha_s);
    const beta = g2Mul(G2_GEN, beta_s);
    const gamma = G2_GEN;
    const delta = G2_GEN;
    const ic0 = g1Mul(G1_GEN, ic0_s);
    const A = g1Mul(G1_GEN, a_s);
    const negA = g1Neg(A);
    const B = g2Mul(G2_GEN, b_s);
    const c_scalar = ((a_s * b_s - alpha_s * beta_s - ic0_s) % R + R) % R;
    const C = g1Mul(G1_GEN, c_scalar);

    // Compute f_vk off-chain
    const f_alpha_beta = millerLoop(alpha, beta);
    const f_L_gamma = millerLoop(ic0, gamma);
    const f_C_delta = millerLoop(C, delta);
    const f_vk = fp12Mul(fp12Mul(f_alpha_beta, f_L_gamma), f_C_delta);

    // Build unlock script (same as runtime verifier test)
    const unlockHex = [
      pushFp(B.x.c0), pushFp(B.x.c1),
      pushFp(B.y.c0), pushFp(B.y.c1),
      pushFp(A.x), pushFp(A.y),
      pushFp(C.x), pushFp(C.y),
    ].join('');

    const ops: StackOp[] = [];
    emitInitP(ops);
    // Stack: [B(4), A.x, A.y, C.x, C.y]

    // Phase 1: IC (0 inputs) — just push ic0
    emitPushFp(ops, fpMod(ic0.x));
    emitPushFp(ops, fpMod(ic0.y));

    // Phase 2: negate A
    emitRoll(ops, 5);
    emitRoll(ops, 5);
    emitFpNeg(ops);
    // Stack: [B(4), C.x, C.y, L.x, L.y, A.x, -A.y]

    // Phase 3: save A and B
    emitToAlt(ops); emitToAlt(ops);
    // Stack: [B(4), C.x, C.y, L.x, L.y]

    for (let k = 0; k < 4; k++) emitRoll(ops, 7);
    for (let k = 0; k < 4; k++) emitToAlt(ops);
    // Stack: [C.x, C.y, L.x, L.y]  Alt: [A(2), B(4)]

    emitRoll(ops, 3); emitRoll(ops, 3);
    // Stack: [L.x, L.y, C.x, C.y]

    // Skip 3-pairing ML: just drop L and C, push constant f_vk
    for (let k = 0; k < 4; k++) emitDrop(ops);

    const pushFp12Script = (f: Fp12) => {
      emitPushFp2(ops, fpMod(f.c0.c0.c0), fpMod(f.c0.c0.c1));
      emitPushFp2(ops, fpMod(f.c0.c1.c0), fpMod(f.c0.c1.c1));
      emitPushFp2(ops, fpMod(f.c0.c2.c0), fpMod(f.c0.c2.c1));
      emitPushFp2(ops, fpMod(f.c1.c0.c0), fpMod(f.c1.c0.c1));
      emitPushFp2(ops, fpMod(f.c1.c1.c0), fpMod(f.c1.c1.c1));
      emitPushFp2(ops, fpMod(f.c1.c2.c0), fpMod(f.c1.c2.c1));
    };
    pushFp12Script(f_vk);
    // Stack: [f_vk(12)]  Alt: [A(2), B(4)]

    // Phase 4: restore B and A
    for (let k = 0; k < 4; k++) emitFromAlt(ops);
    for (let k = 0; k < 2; k++) emitFromAlt(ops);
    // Stack: [f_vk(12), B(4), A.x, -A.y]

    emitSinglePairingMillerLoop(ops);
    // Stack: [f_vk(12), f_ab(12)]

    emitFp12Mul(ops);
    emitFinalExpEasy(ops);
    emitFinalExpHard(ops);
    emitFp12EqOne(ops);
    emitCleanupP(ops);

    const lockingHex = stackOpsToHex(ops as StackOp[]);
    const result = runScript(lockingHex, unlockHex);
    if (!result.success) {
      console.log('Full glue test failed:', result.error);
    }
    expect(result.success).toBe(true);
  }, 600000);

  it('f_vk_const * single_ML gives correct pairing result', () => {
    // Push f_vk as a constant, run single-pairing ML for e(-A,B), multiply, final exp
    // This isolates whether the combination works
    const alpha_s = 7n;
    const beta_s = 11n;
    const ic0_s = 5n;
    const a_s = 13n;
    const b_s = 17n;

    const alpha = g1Mul(G1_GEN, alpha_s);
    const beta = g2Mul(G2_GEN, beta_s);
    const gamma = G2_GEN;
    const delta = G2_GEN;
    const ic0 = g1Mul(G1_GEN, ic0_s);
    const A = g1Mul(G1_GEN, a_s);
    const negA = g1Neg(A);
    const B = g2Mul(G2_GEN, b_s);
    const c_scalar = ((a_s * b_s - alpha_s * beta_s - ic0_s) % R + R) % R;
    const C = g1Mul(G1_GEN, c_scalar);

    // Compute f_vk off-chain
    const f_alpha_beta = millerLoop(alpha, beta);
    const f_L_gamma = millerLoop(ic0, gamma);
    const f_C_delta = millerLoop(C, delta);
    const f_vk = fp12Mul(fp12Mul(f_alpha_beta, f_L_gamma), f_C_delta);

    const ops: StackOp[] = [];
    emitInitP(ops);

    // Push f_vk as constant
    const pushFp12Script = (f: Fp12) => {
      emitPushFp2(ops, fpMod(f.c0.c0.c0), fpMod(f.c0.c0.c1));
      emitPushFp2(ops, fpMod(f.c0.c1.c0), fpMod(f.c0.c1.c1));
      emitPushFp2(ops, fpMod(f.c0.c2.c0), fpMod(f.c0.c2.c1));
      emitPushFp2(ops, fpMod(f.c1.c0.c0), fpMod(f.c1.c0.c1));
      emitPushFp2(ops, fpMod(f.c1.c1.c0), fpMod(f.c1.c1.c1));
      emitPushFp2(ops, fpMod(f.c1.c2.c0), fpMod(f.c1.c2.c1));
    };
    pushFp12Script(f_vk);
    // Stack: [f_vk(12)]

    // Push B and negA for single-pairing ML
    emitPushFp2(ops, B.x.c0, B.x.c1);
    emitPushFp2(ops, B.y.c0, B.y.c1);
    emitPushFp(ops, fpMod(negA.x));
    emitPushFp(ops, fpMod(negA.y));
    // Stack: [f_vk(12), B(4), negA.x, negA.y]

    emitSinglePairingMillerLoop(ops);
    // Stack: [f_vk(12), f_ab(12)]

    emitFp12Mul(ops);
    // Stack: [f(12)]

    emitFinalExpEasy(ops);
    emitFinalExpHard(ops);
    emitFp12EqOne(ops);
    emitCleanupP(ops);

    const lockingHex = stackOpsToHex([{ op: 'drop' } as StackOp, ...ops as StackOp[]]);
    const result = runScript(lockingHex, '');
    if (!result.success) {
      console.log('f_vk_const * single_ML failed:', result.error);
    }
    expect(result.success).toBe(true);
  }, 600000);

  it('single-pairing Miller loop matches off-chain reference', () => {
    // Compute millerLoop(-A, B) off-chain and compare with emitSinglePairingMillerLoop
    const a_s = 13n;
    const b_s = 17n;

    const A = g1Mul(G1_GEN, a_s);
    const negA = g1Neg(A);
    const B = g2Mul(G2_GEN, b_s);

    // Off-chain Miller loop
    const offChainF = millerLoop(negA, B);

    // Build Script: push B(4), negA(2), run single-pairing ML, verify each Fp12 component
    const ops: StackOp[] = [];
    emitInitP(ops);

    // Push B (G2 point: Bx.c0, Bx.c1, By.c0, By.c1)
    emitPushFp2(ops, B.x.c0, B.x.c1);
    emitPushFp2(ops, B.y.c0, B.y.c1);
    // Push negA (G1 point: negA.x, negA.y)
    emitPushFp(ops, fpMod(negA.x));
    emitPushFp(ops, fpMod(negA.y));
    // Stack: [B(4), negA.x, negA.y]

    emitSinglePairingMillerLoop(ops);
    // Stack: [f(12)]

    // Verify each of the 12 Fp components (top to bottom)
    // Fp12 layout: c0=(c0,c1,c2), c1=(c0,c1,c2) where each Fp6 component is Fp2
    // Stack order (TOS first): c1.c2.c1, c1.c2.c0, c1.c1.c1, c1.c1.c0, c1.c0.c1, c1.c0.c0,
    //                          c0.c2.c1, c0.c2.c0, c0.c1.c1, c0.c1.c0, c0.c0.c1, c0.c0.c0
    const expected = [
      fpMod(offChainF.c1.c2.c1), fpMod(offChainF.c1.c2.c0),
      fpMod(offChainF.c1.c1.c1), fpMod(offChainF.c1.c1.c0),
      fpMod(offChainF.c1.c0.c1), fpMod(offChainF.c1.c0.c0),
      fpMod(offChainF.c0.c2.c1), fpMod(offChainF.c0.c2.c0),
      fpMod(offChainF.c0.c1.c1), fpMod(offChainF.c0.c1.c0),
      fpMod(offChainF.c0.c0.c1), fpMod(offChainF.c0.c0.c0),
    ];

    for (const val of expected) {
      emitPushFp(ops, val);
      ops.push({ op: 'opcode', code: 'OP_NUMEQUALVERIFY' } as StackOp);
    }

    emitCleanupP(ops);
    ops.push({ op: 'opcode', code: 'OP_TRUE' } as StackOp);

    const lockingHex = stackOpsToHex(ops as StackOp[]);
    const result = runScript(lockingHex, '');
    if (!result.success) {
      console.log('Single-pairing ML mismatch:', result.error);
    }
    expect(result.success).toBe(true);
  }, 600000);
});
