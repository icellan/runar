/**
 * OP_PUSH_TX on-chain signature derivation (BUG-100 fix).
 *
 * The insecure legacy `checkPreimage` accepted a witness signature over the
 * *real* spending transaction and checked it against pubkey G with OP_CHECKSIG,
 * never reading the pushed preimage — so the preimage was decoupled from the tx
 * (a spender could pay themselves while presenting a forged continuation
 * preimage). This module derives the ECDSA signature *from the preimage on
 * chain*, so OP_CHECKSIG passes only when hash256(preimage) equals the real tx
 * sighash — restoring the binding.
 *
 * Two constructions live in this module:
 *
 * CURRENT — the Any-S construction (k=1, r=Gx, d=2²⁴⁸·Gx⁻¹ mod n ⇒ s=z+2²⁴⁸
 * mod n, low-S by (r,n−s) malleation), ~433 bytes; see the block comment above
 * `anySBindingBytes` for the derivation and each optimization.
 *
 * LEGACY — fixed nonce k=2, privkey d=1 ⇒ pubkey = G, ~760 bytes:
 *   z    = hash256(preimage)                     (the ECDSA message)
 *   r    = (k·G).x mod n                          (compile-time constant)
 *   kinv = k^-1 mod n                             (compile-time constant)
 *   s    = (z + r)·kinv mod n                     (d=1 ⇒ no r·d term beyond r)
 *   low-S: s ← s - (s>n/2)·(2s - n)               (branchless)
 * Then DER-assemble sig = 0x30‖len‖0x02‖rlen‖r‖0x02‖slen‖s ‖ 0x41 and run
 * OP_CHECKSIGVERIFY against compressed G.
 *
 * The math is validated off-chain (manual ECDSA verify of the derived (r,s)
 * against pubkey=G passes for all sampled z), and the emitted Script is
 * validated end-to-end through the BSV interpreter (oppushtx-binding.test.ts).
 * Because s ≤ n/2 < 2^255, its big-endian magnitude MSB is ≤ 0x7F, so s never
 * needs a DER sign byte and its DER content is exactly OP_SIZE(s) bytes — the
 * minimal encoding is obtained without any leading-zero-stripping branch.
 */

import type { StackOp } from '../ir/index.js';
import { ECTracker } from './ec-codegen.js';
import { emitMethod } from './06-emit.js';

// secp256k1 curve order n
const CURVE_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
// n/2 (low-S threshold)
const N_HALF = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;
// r = (2·G).x mod n
const R_CONST = 0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5n;
// kinv = 2^-1 mod n
const KINV = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1n;

// DER-encoded r (constant): 0x02 0x21 0x00 || r(32 bytes). The 0x00 is the DER
// positive-sign byte because r's MSB (0xC6) has its top bit set. Length 35.
const R_DER = new Uint8Array([
  0x02, 0x21, 0x00,
  0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d,
  0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8,
  0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7,
  0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5,
]);
const R_DER_LEN = R_DER.length; // 35

// compressed secp256k1 generator G (pubkey for privkey d=1)
const G_COMPRESSED = new Uint8Array([
  0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb,
  0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
  0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
  0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
]);

// SIGHASH_ALL | SIGHASH_FORKID — default when a method declares no @sighash.
const SIGHASH_FLAG_DEFAULT = 0x41;

/** Reverse a fixed-length byte string on TOS (N bytes → N bytes, order flipped). */
function emitReverseN(e: (op: StackOp) => void, N: number): void {
  e({ op: 'opcode', code: 'OP_0' }); // accumulator
  e({ op: 'swap' });
  for (let i = 0; i < N; i++) {
    // [accum, remaining]
    e({ op: 'push', value: 1n });
    e({ op: 'opcode', code: 'OP_SPLIT' }); // [accum, byte0, rest]
    e({ op: 'rot' });                       // [byte0, rest, accum]
    e({ op: 'rot' });                       // [rest, accum, byte0]
    e({ op: 'swap' });                      // [rest, byte0, accum]
    e({ op: 'opcode', code: 'OP_CAT' });    // [rest, byte0||accum]
    e({ op: 'swap' });                      // [byte0||accum, rest]
  }
  e({ op: 'drop' }); // drop empty remaining
}

/** (a mod n) forced non-negative, mirroring ec-codegen fieldMod. Consumes aName. */
function modN(t: ECTracker, aName: string, resultName: string): void {
  t.toTop(aName);
  t.pushInt('_ppt_modn', CURVE_N);
  t.rawBlock([aName, '_ppt_modn'], resultName, (e) => {
    e({ op: 'opcode', code: 'OP_2DUP' }); // a n a n
    e({ op: 'opcode', code: 'OP_MOD' });  // a n (a%n)
    e({ op: 'rot' });                      // n (a%n) a
    e({ op: 'drop' });                     // n (a%n)
    e({ op: 'over' });                     // n (a%n) n
    e({ op: 'opcode', code: 'OP_ADD' });   // n (a%n+n)
    e({ op: 'swap' });                     // (a%n+n) n
    e({ op: 'opcode', code: 'OP_MOD' });   // ((a%n+n)%n)
  });
}

/**
 * LEGACY construction (k=2, d=1; ~760 bytes). Superseded by the Any-S
 * construction below (~433 bytes) but kept intact for reference, A/B tests,
 * and as a fallback. Same contract: preimage in → preimage out, aborts unless
 * hash256(preimage) == the real tx sighash.
 */
export function emitCheckPreimageBindingLegacy(
  emit: (op: StackOp) => void,
  sighashFlag: number = SIGHASH_FLAG_DEFAULT,
): void {
  const t = new ECTracker(['preimage'], emit);

  // --- z = hash256(preimage) as a positive script number --------------------
  t.copyToTop('preimage', '_ppt_pi');
  t.rawBlock(['_ppt_pi'], '_ppt_z', (e) => {
    e({ op: 'opcode', code: 'OP_HASH256' }); // 32-byte big-endian digest
    emitReverseN(e, 32);                      // → little-endian
    e({ op: 'push', value: new Uint8Array([0x00]) });
    e({ op: 'opcode', code: 'OP_CAT' });      // append sign byte → positive
    e({ op: 'opcode', code: 'OP_BIN2NUM' });  // → z (script number)
  });

  // --- s0 = (z + r) * kinv --------------------------------------------------
  t.pushInt('_ppt_r', R_CONST);
  t.rawBlock(['_ppt_z', '_ppt_r'], '_ppt_zr', (e) => e({ op: 'opcode', code: 'OP_ADD' }));
  t.pushInt('_ppt_kinv', KINV);
  t.rawBlock(['_ppt_zr', '_ppt_kinv'], '_ppt_s0', (e) => e({ op: 'opcode', code: 'OP_MUL' }));

  // --- s = s0 mod n ---------------------------------------------------------
  modN(t, '_ppt_s0', '_ppt_s');

  // --- low-S (branchless): s ← s - (s > n/2) * (2s - n) ---------------------
  t.copyToTop('_ppt_s', '_ppt_s_hi');
  t.pushInt('_ppt_nh', N_HALF);
  t.rawBlock(['_ppt_s_hi', '_ppt_nh'], '_ppt_hi', (e) => e({ op: 'opcode', code: 'OP_GREATERTHAN' }));
  t.copyToTop('_ppt_s', '_ppt_s_d');
  t.pushInt('_ppt_n1', CURVE_N);
  t.rawBlock(['_ppt_s_d', '_ppt_n1'], '_ppt_delta', (e) => {
    // delta = 2s - n
    e({ op: 'swap' });                       // n s
    e({ op: 'opcode', code: 'OP_2MUL' });    // n 2s
    e({ op: 'swap' });                       // 2s n
    e({ op: 'opcode', code: 'OP_SUB' });     // 2s - n
  });
  t.rawBlock(['_ppt_hi', '_ppt_delta'], '_ppt_corr', (e) => e({ op: 'opcode', code: 'OP_MUL' }));
  t.rawBlock(['_ppt_s', '_ppt_corr'], '_ppt_slow', (e) => e({ op: 'opcode', code: 'OP_SUB' }));

  // --- DER content of s = last SIZE(s) bytes of reverse32(NUM2BIN(s,32)) ----
  t.toTop('_ppt_slow');
  t._e({ op: 'opcode', code: 'OP_SIZE' }); // [slow, L]
  t.nm.push('_ppt_L');
  t._e({ op: 'opcode', code: 'OP_TOALTSTACK' }); // alt=[L]; [slow]
  t.nm.pop();
  t.rawBlock(['_ppt_slow'], '_ppt_sbe', (e) => {
    e({ op: 'push', value: 32n });
    e({ op: 'opcode', code: 'OP_NUM2BIN' }); // 32-byte LE
    emitReverseN(e, 32);                      // 32-byte BE (32−L leading zeros)
  });
  t.fromAlt('_ppt_L2'); // [sbe, L]
  t.rawBlock(['_ppt_sbe', '_ppt_L2'], '_ppt_sc', (e) => {
    e({ op: 'push', value: 32n }); // [sbe, L, 32]
    e({ op: 'swap' });             // [sbe, 32, L]
    e({ op: 'opcode', code: 'OP_SUB' });   // [sbe, 32-L]
    e({ op: 'opcode', code: 'OP_SPLIT' }); // [left(zeros), content]
    e({ op: 'nip' });                       // drop left → content (L bytes BE)
  });

  // --- sDER = 0x02 || Lbyte || content --------------------------------------
  t.copyToTop('_ppt_sc', '_ppt_sc_sz');
  t.rawBlock(['_ppt_sc_sz'], '_ppt_slen', (e) => {
    e({ op: 'opcode', code: 'OP_SIZE' });
    e({ op: 'nip' });                        // L
    e({ op: 'push', value: 1n });
    e({ op: 'opcode', code: 'OP_NUM2BIN' }); // L as 1 byte
  });
  t.rawBlock(['_ppt_sc', '_ppt_slen'], '_ppt_sder', (e) => {
    // stack: [content, slenByte]
    e({ op: 'push', value: new Uint8Array([0x02]) }); // [content, slen, 02]
    e({ op: 'swap' });                    // [content, 02, slen]
    e({ op: 'opcode', code: 'OP_CAT' });  // [content, 02||slen]
    e({ op: 'swap' });                    // [02||slen, content]
    e({ op: 'opcode', code: 'OP_CAT' });  // [02||slen||content] = sDER
  });

  // --- sig = 0x30 || totLen || rDER || sDER || 0x41 -------------------------
  // totLen = len(rDER) + len(sDER) = 35 + SIZE(sDER)
  t.copyToTop('_ppt_sder', '_ppt_sder_sz');
  t.rawBlock(['_ppt_sder_sz'], '_ppt_totlen', (e) => {
    e({ op: 'opcode', code: 'OP_SIZE' });
    e({ op: 'nip' });
    e({ op: 'push', value: BigInt(R_DER_LEN) });
    e({ op: 'opcode', code: 'OP_ADD' });
    e({ op: 'push', value: 1n });
    e({ op: 'opcode', code: 'OP_NUM2BIN' }); // 1 byte
  });
  // stack: [sder, totLen]. Build header = 0x30 || totLen || rDER.
  t.pushBytes('_ppt_rder', R_DER); // [sder, totLen, rDER]
  t.rawBlock(['_ppt_sder', '_ppt_totlen', '_ppt_rder'], '_ppt_sig', (e) => {
    // [sder, totLen, rDER]
    e({ op: 'push', value: new Uint8Array([0x30]) }); // [sder, totLen, rDER, 30]
    e({ op: 'push', value: 2n });
    e({ op: 'opcode', code: 'OP_ROLL' }); // bring totLen (depth 2) to top: [sder, rDER, 30, totLen]
    e({ op: 'opcode', code: 'OP_CAT' });  // [sder, rDER, 30||totLen]
    e({ op: 'swap' });                    // [sder, 30||totLen, rDER]
    e({ op: 'opcode', code: 'OP_CAT' });  // [sder, 30||totLen||rDER]
    e({ op: 'swap' });                    // [30||totLen||rDER, sder]
    e({ op: 'opcode', code: 'OP_CAT' });  // [30||totLen||rDER||sder]
    e({ op: 'push', value: new Uint8Array([sighashFlag & 0xff]) }); // append sighash byte
    e({ op: 'opcode', code: 'OP_CAT' });  // full sig
  });

  // --- OP_CHECKSIGVERIFY against G ------------------------------------------
  t.pushBytes('_ppt_G', G_COMPRESSED);
  t.rawBlock(['_ppt_sig', '_ppt_G'], null, (e) => {
    e({ op: 'opcode', code: 'OP_CHECKSIGVERIFY' });
  });

  // preimage remains on top (unchanged).
}

/** Hex of the legacy construction, kept for A/B comparison in tests. */
export function checkPreimageBindingBytesLegacy(sighashFlag: number = SIGHASH_FLAG_DEFAULT): Uint8Array {
  const ops: StackOp[] = [];
  emitCheckPreimageBindingLegacy((op) => ops.push(op), sighashFlag);
  const { scriptHex } = emitMethod({ name: 'checkPreimageBinding', ops, maxStackDepth: 200 });
  const out = new Uint8Array(scriptHex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(scriptHex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ————————————————————————————————————————————————————————————————————————————
// Any-S PushTx construction (optimized; ~433 bytes vs ~760 legacy).
//
// Technique credit: Brendan Lee — the "Any-S" OP_PUSH_TX signing context from
// the BitcoinSX `std.sxLib` `#signCtx` primitive, adapted to this compiler's
// interface (preimage in → preimage out, sighash flag baked at compile time).
//
// Differences from the legacy construction, and why each saves bytes/ops:
//   1. k=1 instead of k=2  ⇒ k⁻¹ = 1, so s = z + r·d mod n needs NO OP_MUL and
//      no 33-byte k⁻¹ push. r = Gx also has MSB 0x79 < 0x80, so its DER field
//      needs no 0x00 sign pad (34 bytes vs 35).
//   2. d = 2²⁴⁸·Gx⁻¹ mod n instead of d=1 ⇒ r·d ≡ 2²⁴⁸ (mod n), and the addend
//      2²⁴⁸ is BUILT on-stack in 6 script bytes (OP_0 <0x1f> OP_NUM2BIN OP_1
//      OP_CAT) instead of pushing a 33-byte constant. The verifying pubkey
//      becomes P = d·G (ANYS_PUBKEY below; d is public — binding never relied
//      on the key being secret, only on the sig being derived from the
//      preimage on-chain).
//   3. Byte reversal as 31×(OP_1 OP_SPLIT) then 31×(OP_SWAP OP_CAT) — 4 bytes
//      per element vs 7 in the legacy accumulator loop.
//   4. mod n + low-S as a two-level branch (19 bytes, ≤1 OP_MOD, 0 OP_MUL)
//      instead of branchless arithmetic on two more 33-byte constants. Uses
//      the standard ECDSA malleation (r, n−s) ≡ (r, s) for the high-S fixup.
//   5. s is reversed straight out of its minimal script-number encoding via
//      31×(OP_DUP OP_0NOTEQUAL OP_SPLIT) — minimal LE encoding of a positive
//      number IS the DER magnitude byte-reversed (low-S ⇒ MSB ≤ 0x7f ⇒ no
//      sign pad; minimality ⇒ no leading zeros), so the legacy NUM2BIN(32) /
//      strip-zeros dance disappears. Splitting an exhausted (empty) remainder
//      degrades to zero-length splits, so short s values need no branch.
//
// The tail is `01<flag> 7e 21<ANYS_PUBKEY> ad`, preserving the fixed-position
// sighash-flag patching every tier relies on.
// ————————————————————————————————————————————————————————————————————————————

// Compressed P = d·G for d = 2²⁴⁸·Gx⁻¹ mod n (verified off-chain).
const ANYS_PUBKEY_HEX = '02b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0';
// Curve order n as a 33-byte little-endian script number (0x00 sign byte last).
const N_LE_HEX = '414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00';
// DER: 0x02 0x20 || Gx (r-field, no sign pad) || 0x02 (opening tag of s-field).
const R_DER_S_TAG_HEX = '022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802';

const OP = {
  OP_0: 0x00, OP_1: 0x51, OP_2: 0x52, OP_IF: 0x63, OP_ELSE: 0x67, OP_ENDIF: 0x68,
  OP_NIP: 0x77, OP_OVER: 0x78, OP_SWAP: 0x7c, OP_TUCK: 0x7d, OP_CAT: 0x7e,
  OP_SPLIT: 0x7f, OP_NUM2BIN: 0x80, OP_BIN2NUM: 0x81, OP_SIZE: 0x82,
  OP_0NOTEQUAL: 0x92, OP_ADD: 0x93, OP_SUB: 0x94, OP_DIV: 0x96, OP_MOD: 0x97,
  OP_PICK: 0x79, OP_2MUL: 0x8d, OP_MUL: 0x95,
  OP_LESSTHAN: 0x9f, OP_DUP: 0x76, OP_HASH256: 0xaa, OP_CHECKSIGVERIFY: 0xad,
} as const;

/** Assemble the Any-S binding blob (fixed bytes; opcode-level, no emitter). */
function anySBindingBytes(sighashFlag: number): Uint8Array {
  const b: number[] = [];
  const op = (...codes: number[]) => b.push(...codes);
  const pushHex = (hex: string) => {
    const data = hex.match(/../g)!.map((h) => parseInt(h, 16));
    if (data.length >= 0x4c) throw new Error('unexpected long push');
    b.push(data.length, ...data);
  };

  // [preimage] → [preimage, digest]
  op(OP.OP_DUP, OP.OP_HASH256);
  // reverse 32-byte digest: fan out, then cat back (top-down ⇒ reversed)
  for (let i = 0; i < 31; i++) op(OP.OP_1, OP.OP_SPLIT);
  for (let i = 0; i < 31; i++) op(OP.OP_SWAP, OP.OP_CAT);
  // little-endian digest + 0x00 sign byte → z as a positive script number
  pushHex('00'); op(OP.OP_CAT, OP.OP_BIN2NUM);
  // s0 = z + 2²⁴⁸  (2²⁴⁸ built as 31 zero bytes ‖ 0x01, interpreted LE)
  op(OP.OP_0); pushHex('1f'); op(OP.OP_NUM2BIN, OP.OP_1, OP.OP_CAT, OP.OP_ADD);
  // s = s0 mod n, then low-S: s' = s + (s > n/2)·(n − 2s)  — BRANCHLESS, like
  // the legacy construction: no OP_IF, so static analyzers (which enumerate
  // execution paths, and must agree on them across tiers) see the same path
  // structure as before. (s>n/2 ⇒ s' = n−s, the standard ECDSA malleation.)
  pushHex(N_LE_HEX);
  op(OP.OP_TUCK, OP.OP_MOD);                        // [n, s]
  op(OP.OP_OVER, OP.OP_2, OP.OP_DIV);               // [n, s, n/2]
  op(OP.OP_OVER, OP.OP_LESSTHAN);                   // [n, s, hi]
  op(OP.OP_2, OP.OP_PICK, OP.OP_2, OP.OP_PICK);     // [n, s, hi, n, s]
  op(OP.OP_2MUL, OP.OP_SUB);                        // [n, s, hi, n-2s]
  op(OP.OP_MUL, OP.OP_ADD);                         // [n, s']
  op(OP.OP_NIP);                                    // [s']
  // s (minimal LE script number) → big-endian DER magnitude: fan out one byte
  // while the remainder is a nonzero number (empty splits once exhausted).
  for (let i = 0; i < 31; i++) op(OP.OP_DUP, OP.OP_0NOTEQUAL, OP.OP_SPLIT);
  for (let i = 0; i < 31; i++) op(OP.OP_SWAP, OP.OP_CAT);
  // sig = 0x30 ‖ totLen ‖ 0x02 0x20 Gx ‖ 0x02 ‖ len(s) ‖ s ‖ flag
  op(OP.OP_SIZE, OP.OP_SWAP, OP.OP_CAT);          // len(s) ‖ s
  pushHex(R_DER_S_TAG_HEX); op(OP.OP_SWAP, OP.OP_CAT);
  op(OP.OP_SIZE, OP.OP_SWAP, OP.OP_CAT);          // totLen ‖ fields
  pushHex('30'); op(OP.OP_SWAP, OP.OP_CAT);
  pushHex((sighashFlag & 0xff).toString(16).padStart(2, '0')); op(OP.OP_CAT);
  // verify against P = d·G; abort unless hash256(preimage) == real tx sighash
  pushHex(ANYS_PUBKEY_HEX);
  op(OP.OP_CHECKSIGVERIFY);
  return new Uint8Array(b);
}

/**
 * Emit the on-chain preimage-binding check (Any-S construction).
 *
 * Precondition:  the preimage byte-string is on top of the stack.
 * Postcondition: the same preimage is on top of the stack (unchanged); the
 * derived ECDSA signature has been verified against P = d·G with
 * OP_CHECKSIGVERIFY, aborting the script unless hash256(preimage) == the real
 * tx sighash. Net stack effect: 0 (preimage in → preimage out).
 *
 * Emitted as a single opaque `raw_bytes` op — the construction is a FIXED byte
 * sequence, byte-identical across all seven compiler tiers and peephole-proof
 * (the peephole must NOT rewrite inside the delicate DER/ECDSA assembly).
 * These bytes are the single source of truth; the six non-TS tiers pin the
 * same constant hex (CHECK_PREIMAGE_BINDING_HEX), with the cross-tier
 * conformance suite as guard.
 */
export function emitCheckPreimageBinding(
  emit: (op: StackOp) => void,
  sighashFlag: number = SIGHASH_FLAG_DEFAULT,
): void {
  emit({ op: 'raw_bytes', bytes: anySBindingBytes(sighashFlag), in_arity: 1, out_arity: 1 });
}

export function checkPreimageBindingBytes(sighashFlag: number = SIGHASH_FLAG_DEFAULT): Uint8Array {
  const ops: StackOp[] = [];
  emitCheckPreimageBinding((op) => ops.push(op), sighashFlag);
  const { scriptHex } = emitMethod({ name: 'checkPreimageBinding', ops, maxStackDepth: 200 });
  const out = new Uint8Array(scriptHex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(scriptHex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Hex of the canonical construction (the value the other 6 tiers must pin). */
export const CHECK_PREIMAGE_BINDING_HEX: string = Array.from(
  checkPreimageBindingBytes(),
  (b) => b.toString(16).padStart(2, '0'),
).join('');

/**
 * Emit the on-chain preimage binding as a single opaque raw_bytes op. Net stack
 * effect is 0 (preimage in → preimage out), declared as in=1/out=1 so the static
 * analyzer keeps the depth consistent.
 */
export function emitCheckPreimageBindingRaw(
  emit: (op: StackOp) => void,
  sighashFlag: number = SIGHASH_FLAG_DEFAULT,
): void {
  emit({ op: 'raw_bytes', bytes: checkPreimageBindingBytes(sighashFlag), in_arity: 1, out_arity: 1 });
}
