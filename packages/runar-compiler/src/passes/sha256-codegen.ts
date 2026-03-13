/**
 * SHA-256 compression codegen for Bitcoin Script.
 *
 * emitSha256Compress: [state(32), block(64)] → [newState(32)]
 *
 * Optimized architecture (inspired by twostack/tstokenlib):
 *   - All 32-bit words stored as **4-byte little-endian** during computation.
 *     LE→num conversion is just push(0x00)+CAT+BIN2NUM (3 ops) vs 15 ops for BE.
 *   - Bitwise ops (AND, OR, XOR, INVERT) are endian-agnostic on equal-length arrays.
 *   - ROTR uses arithmetic (DIV+MUL+MOD) on script numbers — no OP_LSHIFT needed.
 *   - Batched addN for T1 (5 addends) converts all to numeric once, adds, converts back.
 *   - BE→LE conversion only at input unpack; LE→BE only at output pack.
 *
 * Stack layout during rounds:
 *   [W0..W63, a, b, c, d, e, f, g, h]  (all LE 4-byte values)
 *   a at depth 0 (TOS), h at depth 7. W[t] at depth 8+(63-t).
 *   Alt: [initState(32 bytes BE)]
 */

import type { StackOp } from '../ir/index.js';
import { Emitter, u32ToLE } from './codegen-emitter.js';

// SHA-256 round constants
const K: number[] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// =========================================================================
// SHA-256 sigma/ch/maj functions (standalone, take Emitter parameter)
// =========================================================================
// The LE→BE→sigma→BE→LE pattern costs 24 ops wrapper overhead per sigma call,
// but each ROTR drops from 17 ops (arithmetic) to 7 ops (native shifts),
// netting ~6 ops saved per big sigma and ~4 per small sigma.

/** Σ0(a) = ROTR(2)^ROTR(13)^ROTR(22). [a(LE)] → [Σ0(LE)]. Net: 0. */
function bigSigma0(em: Emitter): void {
  em.reverseBytes4();
  em.dup(); em.dup();
  em.rotrBE(2); em.swap(); em.rotrBE(13);
  em.binOp('OP_XOR');
  em.swap(); em.rotrBE(22);
  em.binOp('OP_XOR');
  em.reverseBytes4();
}

/** Σ1(e) = ROTR(6)^ROTR(11)^ROTR(25). [e(LE)] → [Σ1(LE)]. Net: 0. */
function bigSigma1(em: Emitter): void {
  em.reverseBytes4();
  em.dup(); em.dup();
  em.rotrBE(6); em.swap(); em.rotrBE(11);
  em.binOp('OP_XOR');
  em.swap(); em.rotrBE(25);
  em.binOp('OP_XOR');
  em.reverseBytes4();
}

/** σ0(x) = ROTR(7)^ROTR(18)^SHR(3). [x(LE)] → [σ0(LE)]. Net: 0. */
function smallSigma0(em: Emitter): void {
  em.reverseBytes4();
  em.dup(); em.dup();
  em.rotrBE(7); em.swap(); em.rotrBE(18);
  em.binOp('OP_XOR');
  em.swap(); em.shrBE(3);
  em.binOp('OP_XOR');
  em.reverseBytes4();
}

/** σ1(x) = ROTR(17)^ROTR(19)^SHR(10). [x(LE)] → [σ1(LE)]. Net: 0. */
function smallSigma1(em: Emitter): void {
  em.reverseBytes4();
  em.dup(); em.dup();
  em.rotrBE(17); em.swap(); em.rotrBE(19);
  em.binOp('OP_XOR');
  em.swap(); em.shrBE(10);
  em.binOp('OP_XOR');
  em.reverseBytes4();
}

/** Ch(e,f,g) = (e&f)^(~e&g). [e, f, g] (g=TOS), all LE → [Ch(LE)]. Net: -2. */
function ch(em: Emitter): void {
  em.rot();
  em.dup();
  em.uniOp('OP_INVERT');
  em.rot();
  em.binOp('OP_AND');
  em.toAlt();
  em.binOp('OP_AND');
  em.fromAlt();
  em.binOp('OP_XOR');
}

/** Maj(a,b,c) = (a&b)|(c&(a^b)). [a, b, c] (c=TOS), all LE → [Maj(LE)]. Net: -2. */
function maj(em: Emitter): void {
  em.toAlt();
  em.dup2();
  em.binOp('OP_AND');
  em.toAlt();
  em.binOp('OP_XOR');
  em.fromAlt();
  em.swap();
  em.fromAlt();
  em.binOp('OP_AND');
  em.binOp('OP_OR');
}

// =========================================================================
// Reusable compress ops generator
// =========================================================================

/**
 * Generate SHA-256 compression ops.
 * Assumes top of stack is [..., state(32 BE), block(64 BE)].
 * After: [..., newState(32 BE)]. Net depth: -1.
 */
function generateCompressOps(): StackOp[] {
  const em = new Emitter(2); // pretend state+block are the only items

  // Phase 1: Save init state to alt, unpack block into 16 LE words
  em.swap();
  em.dup(); em.toAlt();
  em.toAlt();
  em.assert(1, 'compress: after state save');

  for (let i = 0; i < 15; i++) em.split4();
  em.assert(16, 'compress: after block unpack');
  em.beWordsToLE(16);
  em.assert(16, 'compress: after block LE convert');

  // Phase 2: W expansion
  for (let _t = 16; _t < 64; _t++) {
    em.over(); smallSigma1(em);
    em.pick(6 + 1);
    em.pick(14 + 2); smallSigma0(em);
    em.pick(15 + 3);
    em.addN(4);
  }
  em.assert(64, 'compress: after W expansion');

  // Phase 3: Unpack state into 8 LE working vars
  em.fromAlt();
  for (let i = 0; i < 7; i++) em.split4();
  em.assert(72, 'compress: after state unpack');
  em.beWordsToLEReversed8();
  em.assert(72, 'compress: after state LE convert');

  // Phase 4: 64 compression rounds
  for (let t = 0; t < 64; t++) {
    const d0 = em.depth;
    emitRound(em, t);
    em.assert(d0, `compress: after round ${t}`);
  }

  // Phase 5: Add initial state, pack result
  em.fromAlt();
  em.assert(73, 'compress: before final add');

  for (let i = 0; i < 7; i++) em.split4();
  em.beWordsToLEReversed8();
  em.assert(80, 'compress: after init unpack');

  for (let i = 0; i < 8; i++) {
    em.roll(8 - i);
    em.add32();
    em.toAlt();
  }
  em.assert(64, 'compress: after final add');

  em.fromAlt();
  em.reverseBytes4();
  for (let i = 1; i < 8; i++) {
    em.fromAlt();
    em.reverseBytes4();
    em.swap();
    em.binOp('OP_CAT');
  }
  em.assert(65, 'compress: after pack');

  for (let i = 0; i < 64; i++) {
    em.swap(); em.drop();
  }
  em.assert(1, 'compress: final');

  return em.ops;
}

// Cache the ops since they're identical every time
let _compressOpsCache: StackOp[] | null = null;
function getCompressOps(): StackOp[] {
  if (!_compressOpsCache) _compressOpsCache = generateCompressOps();
  return _compressOpsCache;
}

// =========================================================================
// Public entry points
// =========================================================================

/**
 * Emit SHA-256 compression in Bitcoin Script.
 * Stack on entry: [..., state(32 BE), block(64 BE)]
 * Stack on exit:  [..., newState(32 BE)]
 */
export function emitSha256Compress(emit: (op: StackOp) => void): void {
  for (const op of getCompressOps()) emit(op);
}

/**
 * Emit SHA-256 finalization in Bitcoin Script.
 * Stack on entry: [..., state(32 BE), remaining(var len BE), msgBitLen(bigint)]
 * Stack on exit:  [..., hash(32 BE)]
 *
 * Applies SHA-256 padding to `remaining`, then compresses 1 or 2 blocks.
 * Uses OP_IF branching: script contains sha256Compress code twice (~46KB total).
 */
export function emitSha256Finalize(emit: (op: StackOp) => void): void {
  const em = new Emitter(3); // state + remaining + msgBitLen

  // ---- Step 1: Convert msgBitLen to 8-byte BE ----
  // [state, remaining, msgBitLen]
  em.pushI(9n);
  em.binOp('OP_NUM2BIN');       // 9-byte LE
  em.pushI(8n);
  em.split();                   // [8-byte LE, sign byte]
  em.drop();                    // [8-byte LE]
  // Reverse 8 bytes to BE: split(4), reverse each half, cat
  em.pushI(4n); em.split();    // [lo4_LE, hi4_LE]
  em.reverseBytes4();           // [lo4_LE, hi4_rev]
  em.swap();
  em.reverseBytes4();           // [hi4_rev, lo4_rev]
  em.binOp('OP_CAT');          // [bitLenBE(8)]
  em.toAlt();                   // save bitLenBE to alt
  em.assert(2, 'finalize: after bitLen conversion');

  // ---- Step 2: Pad remaining ----
  // [state, remaining]
  em.pushB(new Uint8Array([0x80]));
  em.binOp('OP_CAT');          // [state, remaining||0x80]

  // Get padded length
  em.oc('OP_SIZE'); em.depth++;  // [state, padded, paddedLen]

  // Branch: 1 block (paddedLen ≤ 56) or 2 blocks (paddedLen > 56)
  em.dup();
  em.pushI(57n);
  em.binOp('OP_LESSTHAN');     // paddedLen < 57?
  // [state, padded, paddedLen, flag]

  em.oc('OP_IF'); em.depth--;  // consume flag
  // ---- 1-block path: pad to 56 bytes ----
  em.pushI(56n);
  em.swap();
  em.binOp('OP_SUB');          // zeroCount = 56 - paddedLen
  em.pushI(0n);
  em.swap();
  em.binOp('OP_NUM2BIN');      // zero bytes
  em.binOp('OP_CAT');          // [state, padded(56 bytes)]
  em.fromAlt();                 // bitLenBE from alt
  em.binOp('OP_CAT');          // [state, block1(64 bytes)]
  // Splice sha256Compress ops (consumes state+block, produces result)
  const compressOps = getCompressOps();
  for (const op of compressOps) em.e_raw(op);
  em.depth = 1; // after compress: 1 result

  em.oc('OP_ELSE');
  em.depth = 3; // reset to branch entry: [state, padded, paddedLen]

  // ---- 2-block path: pad to 120 bytes ----
  em.pushI(120n);
  em.swap();
  em.binOp('OP_SUB');          // zeroCount = 120 - paddedLen
  em.pushI(0n);
  em.swap();
  em.binOp('OP_NUM2BIN');      // zero bytes
  em.binOp('OP_CAT');          // [state, padded(120 bytes)]
  em.fromAlt();                 // bitLenBE from alt
  em.binOp('OP_CAT');          // [state, fullPadded(128 bytes)]

  // Split into 2 blocks
  em.pushI(64n);
  em.split();                   // [state, block1(64), block2(64)]
  em.toAlt();                   // save block2

  // First compress: [state, block1]
  for (const op of compressOps) em.e_raw(op);
  em.depth = 1; // after first compress: [midState]

  // Second compress: [midState, block2]
  em.fromAlt();                 // [midState, block2]
  for (const op of compressOps) em.e_raw(op);
  em.depth = 1; // after second compress: [result]

  em.oc('OP_ENDIF');
  // Both paths leave 1 item (result) on stack
  em.assert(1, 'finalize: final');

  for (const op of em.ops) emit(op);
}

/** Emit one compression round. Stack: [W0..W63, a,b,c,d,e,f,g,h] (a=TOS, all LE). Net: 0. */
function emitRound(em: Emitter, t: number): void {
  // Depths: a(0) b(1) c(2) d(3) e(4) f(5) g(6) h(7). W[t] at 71-t.

  // --- T1 = Σ1(e) + Ch(e,f,g) + h + K[t] + W[t] ---
  // Compute all 5 components, then batch-add with addN(5).

  em.pick(4);                             // e copy                    (+1)
  bigSigma1(em);                         // Σ1(e)                     (0)
  // Stack: Σ1(0) a(1) b(2) c(3) d(4) e(5) f(6) g(7) h(8)

  em.pick(5); em.pick(7); em.pick(9);    // e, f, g copies            (+3)
  ch(em);                                // Ch(e,f,g)                 (-2) → net +2
  // Stack: Ch(0) Σ1(1) a(2) b(3) c(4) d(5) e(6) f(7) g(8) h(9)

  em.pick(9);                             // h copy                    (+1) → net +3
  em.pushB(u32ToLE(K[t]!));              // K[t] as LE                (+1) → net +4
  em.pick(75 - t);                        // W[t] copy                 (+1) → net +5
  // Stack: W K h Ch Σ1 a b c d e f g h [W0..W63]

  em.addN(5);                             // T1 = sum of 5             (-4) → net +1
  // Stack: T1(0) a(1) b(2) c(3) d(4) e(5) f(6) g(7) h(8)

  // --- T2 = Σ0(a) + Maj(a,b,c) ---
  em.dup(); em.toAlt();                  // save T1 copy to alt

  em.pick(1);                             // a copy                    (+1) → net +2
  bigSigma0(em);                         // Σ0(a)                     (0)
  // Stack: Σ0(0) T1(1) a(2) b(3) c(4) d(5) e(6) f(7) g(8) h(9)

  em.pick(2); em.pick(4); em.pick(6);   // a, b, c copies            (+3) → net +5
  maj(em);                               // Maj(a,b,c)                (-2) → net +3
  em.add32();                             // T2 = Σ0 + Maj            (-1) → net +2
  // Stack: T2(0) T1(1) a(2) b(3) c(4) d(5) e(6) f(7) g(8) h(9)

  // --- Register update ---
  em.fromAlt();                           // T1 copy from alt          (+1) → net +3

  em.swap();
  em.add32();                             // new_a = T1 + T2           (-1) → net +2
  // Stack: new_a(0) T1(1) a(2) b(3) c(4) d(5) e(6) f(7) g(8) h(9)

  em.swap();
  em.roll(5);                             // d to top
  em.add32();                             // new_e = d + T1            (-1) → net +1
  // Stack: new_e(0) new_a(1) a(2) b(3) c(4) e(5) f(6) g(7) h(8)

  em.roll(8); em.drop();                 // drop h                    (-1) → net 0
  // Stack: new_e(0) new_a(1) a(2) b(3) c(4) e(5) f(6) g(7)

  // Rotate: [ne,na,a,b,c,e,f,g] → [na,a,b,c,ne,e,f,g]
  em.swap(); em.roll(4); em.roll(4); em.roll(4); em.roll(3);
}
