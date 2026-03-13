/**
 * Shared Emitter for hash/crypto codegen (SHA-256, BLAKE3, etc.).
 *
 * Tracks main + alt stack depth and emits StackOp instructions.
 * All 32-bit words are assumed 4-byte little-endian during computation.
 * BE↔LE conversion happens only at input/output boundaries.
 */

import type { StackOp } from '../ir/index.js';

/** Encode a uint32 as 4-byte little-endian (precomputed at codegen time). */
export function u32ToLE(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}

/** Encode a uint32 as 4-byte big-endian (precomputed at codegen time). */
export function u32ToBE(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

export class Emitter {
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
      throw new Error(`Codegen: ${msg}. Expected depth ${expected}, got ${this.depth}`);
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

  // --- ROTR on LE values ---

  /**
   * ROTR(x, 16) on LE 4-byte value. Net: 0. 4 ops.
   * Swaps the two 16-bit halves: [b0,b1,b2,b3] → [b2,b3,b0,b1].
   */
  rotr16_LE(): void {
    this.pushI(2n);
    this.split();         // [lo2, hi2]
    this.swap();          // [hi2, lo2]
    this.binOp('OP_CAT'); // [hi2||lo2]
  }

  /**
   * ROTR(x, 8) on LE 4-byte value. Net: 0. 4 ops.
   * [b0,b1,b2,b3] → [b1,b2,b3,b0]
   */
  rotr8_LE(): void {
    this.pushI(1n);
    this.split();         // [b0, b1b2b3]
    this.swap();          // [b1b2b3, b0]
    this.binOp('OP_CAT'); // [b1b2b3||b0]
  }

  /**
   * ROTR(x, n) on LE 4-byte value (general, non-byte-aligned). Net: 0. 31 ops.
   * Converts LE→BE, applies rotrBE, converts back.
   */
  rotr_LE_general(n: number): void {
    this.reverseBytes4();  // LE → BE (12 ops)
    this.rotrBE(n);        // rotate on BE (7 ops)
    this.reverseBytes4();  // BE → LE (12 ops)
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
