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

/** Encode a uint32 as 4-byte little-endian (precomputed at codegen time). */
function u32ToLE(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}

// =========================================================================
// Emitter with depth tracking
// =========================================================================

class Emitter {
  readonly ops: StackOp[] = [];
  depth: number;
  altDepth = 0;

  constructor(initialDepth: number) { this.depth = initialDepth; }

  private e(sop: StackOp): void { this.ops.push(sop); }

  /** Push a raw op without depth tracking (for splicing pre-generated ops). */
  e_raw(sop: StackOp): void { this.ops.push(sop); }

  oc(code: string): void { this.e({ op: 'opcode', code }); }

  pushI(v: bigint): void { this.e({ op: 'push', value: v }); this.depth++; }
  pushB(v: Uint8Array): void { this.e({ op: 'push', value: v }); this.depth++; }

  dup(): void { this.e({ op: 'dup' }); this.depth++; }
  drop(): void { this.e({ op: 'drop' }); this.depth--; }
  swap(): void { this.e({ op: 'swap' }); }
  over(): void { this.e({ op: 'over' }); this.depth++; }
  nip(): void { this.e({ op: 'nip' }); this.depth--; }
  rot(): void { this.e({ op: 'rot' }); }

  pick(d: number): void {
    if (d === 0) { this.dup(); return; }
    if (d === 1) { this.over(); return; }
    this.pushI(BigInt(d));
    this.e({ op: 'pick', depth: d });
  }

  roll(d: number): void {
    if (d === 0) return;
    if (d === 1) { this.swap(); return; }
    if (d === 2) { this.rot(); return; }
    this.pushI(BigInt(d));
    this.e({ op: 'roll', depth: d });
    this.depth--;
  }

  toAlt(): void { this.oc('OP_TOALTSTACK'); this.depth--; this.altDepth++; }
  fromAlt(): void { this.oc('OP_FROMALTSTACK'); this.depth++; this.altDepth--; }

  binOp(code: string): void { this.oc(code); this.depth--; }
  uniOp(code: string): void { this.oc(code); }
  dup2(): void { this.oc('OP_2DUP'); this.depth += 2; }

  split(): void { this.oc('OP_SPLIT'); }
  split4(): void { this.pushI(4n); this.split(); }

  assert(expected: number, msg: string): void {
    if (this.depth !== expected) {
      throw new Error(`SHA256 codegen: ${msg}. Expected depth ${expected}, got ${this.depth}`);
    }
  }

  // --- Byte reversal (only for BE↔LE conversion at boundaries) ---

  /** Reverse 4 bytes on TOS: [abcd] → [dcba]. Net: 0. 12 ops. */
  reverseBytes4(): void {
    this.pushI(1n); this.split();
    this.pushI(1n); this.split();
    this.pushI(1n); this.split();
    this.swap(); this.binOp('OP_CAT');
    this.swap(); this.binOp('OP_CAT');
    this.swap(); this.binOp('OP_CAT');
  }

  // --- LE ↔ Numeric conversions (cheap — no byte reversal) ---

  /** Convert 4-byte LE to unsigned script number. [le4] → [num]. Net: 0. 3 ops. */
  le2num(): void {
    this.pushB(new Uint8Array([0x00]));  // unsigned padding
    this.binOp('OP_CAT');
    this.uniOp('OP_BIN2NUM');
  }

  /** Convert script number to 4-byte LE (truncates to 32 bits). [num] → [le4]. Net: 0. 5 ops. */
  num2le(): void {
    this.pushI(5n);
    this.binOp('OP_NUM2BIN');   // 5-byte LE
    this.pushI(4n);
    this.split();               // [4-byte LE, overflow+sign]
    this.drop();                // discard overflow byte
  }

  // --- LE arithmetic ---

  /** [a(LE), b(LE)] → [(a+b mod 2^32)(LE)]. Net: -1. 13 ops. */
  add32(): void {
    this.le2num();
    this.swap();
    this.le2num();
    this.binOp('OP_ADD');
    this.num2le();
  }

  /** Add N LE values. [v0..vN-1] (vN-1=TOS) → [sum(LE)]. Net: -(N-1). */
  addN(n: number): void {
    if (n < 2) return;
    this.le2num();
    for (let i = 1; i < n; i++) {
      this.swap();
      this.le2num();
      this.binOp('OP_ADD');
    }
    this.num2le();
  }

  // --- ROTR/SHR using OP_LSHIFT/OP_RSHIFT (native BE byte-array shifts) ---

  /**
   * ROTR(x, n) on BE 4-byte value. [x_BE] → [rotated_BE]. Net: 0. 7 ops.
   * ROTR(x,n) = (x >> n) | (x << (32-n))
   */
  rotrBE(n: number): void {
    this.dup();                            // [x, x]
    this.pushI(BigInt(n));
    this.binOp('OP_RSHIFT');               // [x, x>>n]
    this.swap();                           // [x>>n, x]
    this.pushI(BigInt(32 - n));
    this.binOp('OP_LSHIFT');               // [x>>n, x<<(32-n)]
    this.binOp('OP_OR');                   // [ROTR result]
  }

  /** SHR(x, n) on BE 4-byte value. [x_BE] → [shifted_BE]. Net: 0. 2 ops. */
  shrBE(n: number): void {
    this.pushI(BigInt(n));
    this.binOp('OP_RSHIFT');
  }

  // --- SHA-256 sigma functions (LE values, internally convert to BE for shifts) ---
  // The LE→BE→sigma→BE→LE pattern costs 24 ops wrapper overhead per sigma call,
  // but each ROTR drops from 17 ops (arithmetic) to 7 ops (native shifts),
  // netting ~6 ops saved per big sigma and ~4 per small sigma.
  // The real win is bytes: arithmetic ROTR uses 5-6 byte push constants (2^n, 2^32)
  // while native shifts use 1-2 byte push amounts. Net: ~6.5KB smaller script.

  /** Σ0(a) = ROTR(2)^ROTR(13)^ROTR(22). [a(LE)] → [Σ0(LE)]. Net: 0. */
  bigSigma0(): void {
    this.reverseBytes4();                  // LE → BE
    this.dup(); this.dup();
    this.rotrBE(2); this.swap(); this.rotrBE(13);
    this.binOp('OP_XOR');
    this.swap(); this.rotrBE(22);
    this.binOp('OP_XOR');
    this.reverseBytes4();                  // BE → LE
  }

  /** Σ1(e) = ROTR(6)^ROTR(11)^ROTR(25). [e(LE)] → [Σ1(LE)]. Net: 0. */
  bigSigma1(): void {
    this.reverseBytes4();
    this.dup(); this.dup();
    this.rotrBE(6); this.swap(); this.rotrBE(11);
    this.binOp('OP_XOR');
    this.swap(); this.rotrBE(25);
    this.binOp('OP_XOR');
    this.reverseBytes4();
  }

  /** σ0(x) = ROTR(7)^ROTR(18)^SHR(3). [x(LE)] → [σ0(LE)]. Net: 0. */
  smallSigma0(): void {
    this.reverseBytes4();
    this.dup(); this.dup();
    this.rotrBE(7); this.swap(); this.rotrBE(18);
    this.binOp('OP_XOR');
    this.swap(); this.shrBE(3);
    this.binOp('OP_XOR');
    this.reverseBytes4();
  }

  /** σ1(x) = ROTR(17)^ROTR(19)^SHR(10). [x(LE)] → [σ1(LE)]. Net: 0. */
  smallSigma1(): void {
    this.reverseBytes4();
    this.dup(); this.dup();
    this.rotrBE(17); this.swap(); this.rotrBE(19);
    this.binOp('OP_XOR');
    this.swap(); this.shrBE(10);
    this.binOp('OP_XOR');
    this.reverseBytes4();
  }

  /** Ch(e,f,g) = (e&f)^(~e&g). [e, f, g] (g=TOS), all LE → [Ch(LE)]. Net: -2. */
  ch(): void {
    this.rot();
    this.dup();
    this.uniOp('OP_INVERT');
    this.rot();
    this.binOp('OP_AND');
    this.toAlt();
    this.binOp('OP_AND');
    this.fromAlt();
    this.binOp('OP_XOR');
  }

  /** Maj(a,b,c) = (a&b)|(c&(a^b)). [a, b, c] (c=TOS), all LE → [Maj(LE)]. Net: -2. */
  maj(): void {
    this.toAlt();
    this.dup2();
    this.binOp('OP_AND');
    this.toAlt();
    this.binOp('OP_XOR');
    this.fromAlt();
    this.swap();
    this.fromAlt();
    this.binOp('OP_AND');
    this.binOp('OP_OR');
  }

  /** Convert N × BE words on TOS to LE, preserving stack order.
   *  Uses alt stack round-trip (push all, pop all = identity order). */
  beWordsToLE(n: number): void {
    for (let i = 0; i < n; i++) { this.reverseBytes4(); this.toAlt(); }
    for (let i = 0; i < n; i++) this.fromAlt();
  }

  /** Convert 8 × BE words on TOS to LE AND reverse order.
   *  Pre:  [a(deep)..h(TOS)] as BE.
   *  Post: [h(deep)..a(TOS)] as LE.
   *  Uses roll to process from bottom, so alt gets a first → a pops last → a on TOS. */
  beWordsToLEReversed8(): void {
    for (let i = 7; i >= 0; i--) {
      this.roll(i);          // bring deepest remaining to TOS
      this.reverseBytes4();  // BE → LE
      this.toAlt();
    }
    for (let i = 0; i < 8; i++) this.fromAlt();
  }
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
    em.over(); em.smallSigma1();
    em.pick(6 + 1);
    em.pick(14 + 2); em.smallSigma0();
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
  em.bigSigma1();                         // Σ1(e)                     (0)
  // Stack: Σ1(0) a(1) b(2) c(3) d(4) e(5) f(6) g(7) h(8)

  em.pick(5); em.pick(7); em.pick(9);    // e, f, g copies            (+3)
  em.ch();                                // Ch(e,f,g)                 (-2) → net +2
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
  em.bigSigma0();                         // Σ0(a)                     (0)
  // Stack: Σ0(0) T1(1) a(2) b(3) c(4) d(5) e(6) f(7) g(8) h(9)

  em.pick(2); em.pick(4); em.pick(6);   // a, b, c copies            (+3) → net +5
  em.maj();                               // Maj(a,b,c)                (-2) → net +3
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
