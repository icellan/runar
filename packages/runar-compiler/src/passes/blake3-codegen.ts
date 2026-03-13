/**
 * BLAKE3 compression codegen for Bitcoin Script.
 *
 * emitBlake3Compress: [chainingValue(32 BE), block(64 BE)] → [hash(32 BE)]
 * emitBlake3Hash:     [message(≤64 BE)]                    → [hash(32 BE)]
 *
 * Architecture (same as sha256-codegen.ts):
 *   - All 32-bit words stored as 4-byte little-endian during computation.
 *   - LE additions via BIN2NUM/NUM2BIN (13 ops per add32).
 *   - Byte-aligned rotations (16, 8) via SPLIT/SWAP/CAT on LE (4 ops).
 *   - Non-byte-aligned rotations (12, 7) via LE→BE→rotrBE→BE→LE (31 ops).
 *   - BE↔LE conversion only at input unpack and output pack.
 *
 * Stack layout during rounds:
 *   [m0..m15, v0..v15]  (all LE 4-byte values)
 *   v15 at TOS (depth 0), v0 at depth 15, m15 at depth 16, m0 at depth 31.
 */

import type { StackOp } from '../ir/index.js';
import { Emitter, u32ToLE, u32ToBE } from './codegen-emitter.js';

// =========================================================================
// BLAKE3 constants
// =========================================================================

const BLAKE3_IV: number[] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const MSG_PERMUTATION: number[] = [
  2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
];

// Flags
const CHUNK_START = 1;
const CHUNK_END = 2;
const ROOT = 8;

// =========================================================================
// Precompute message schedule for all 7 rounds
// =========================================================================

/**
 * For each round, compute which original message word index is used at each
 * position. Returns msgSchedule[round][position] = original msg word index.
 * This eliminates runtime message permutation — we just pick from the
 * right depth at codegen time.
 */
function computeMsgSchedule(): number[][] {
  const schedule: number[][] = [];
  let current = Array.from({ length: 16 }, (_, i) => i);
  for (let round = 0; round < 7; round++) {
    schedule.push([...current]);
    const next = new Array<number>(16);
    for (let i = 0; i < 16; i++) {
      next[i] = current[MSG_PERMUTATION[i]!]!;
    }
    current = next;
  }
  return schedule;
}

const MSG_SCHEDULE = computeMsgSchedule();

// =========================================================================
// State word position tracker
// =========================================================================

/**
 * Tracks the stack depth of each of the 16 state words.
 * Depth 0 = TOS. Message words sit below the state area at fixed positions.
 */
class StateTracker {
  /** positions[i] = current depth of state word v[i] from TOS */
  readonly positions: number[];

  constructor() {
    // Initial: v0 at depth 15 (deepest state word), v15 at depth 0 (TOS)
    this.positions = new Array(16);
    for (let i = 0; i < 16; i++) {
      this.positions[i] = 15 - i;
    }
  }

  depth(wordIdx: number): number {
    return this.positions[wordIdx]!;
  }

  /** Update after rolling a state word from its current depth to TOS. */
  onRollToTop(wordIdx: number): void {
    const d = this.positions[wordIdx]!;
    for (let j = 0; j < 16; j++) {
      if (j !== wordIdx && this.positions[j]! >= 0 && this.positions[j]! < d) {
        this.positions[j]!++;
      }
    }
    this.positions[wordIdx] = 0;
  }
}

// =========================================================================
// G function (quarter-round)
// =========================================================================

/**
 * Emit one half of the G function.
 * Stack entry: [a, b, c, d, m] (m on TOS) — 5 items
 * Stack exit:  [a', b', c', d'] (d' on TOS) — 4 items
 * Net depth: -1
 *
 * Operations:
 *   a' = a + b + m
 *   d' = (d ^ a') >>> rotD
 *   c' = c + d'
 *   b' = (original_b ^ c') >>> rotB
 */
function emitHalfG(em: Emitter, rotD: number, rotB: number): void {
  const d0 = em.depth;

  // Save original b for step 4 (b is at depth 3)
  em.pick(3);
  em.toAlt();

  // Step 1: a' = a + b + m
  // Stack: [a, b, c, d, m] — a=4, b=3, c=2, d=1, m=0
  em.roll(3);    // [a, c, d, m, b]
  em.roll(4);    // [c, d, m, b, a]
  em.addN(3);    // [c, d, a']
  em.assert(d0 - 2, 'halfG step1');

  // Step 2: d' = (d ^ a') >>> rotD
  // Stack: [c, d, a'] — c=2, d=1, a'=0
  em.dup();           // [c, d, a', a']
  em.rot();           // [c, a', a', d]
  em.binOp('OP_XOR'); // [c, a', (d^a')]
  if (rotD === 16) em.rotr16_LE();
  else if (rotD === 8) em.rotr8_LE();
  else em.rotr_LE_general(rotD);
  em.assert(d0 - 2, 'halfG step2');

  // Step 3: c' = c + d'
  // Stack: [c, a', d']
  em.dup();           // [c, a', d', d']
  em.roll(3);         // [a', d', d', c]
  em.add32();         // [a', d', c']
  em.assert(d0 - 2, 'halfG step3');

  // Step 4: b' = (original_b ^ c') >>> rotB
  // Stack: [a', d', c']
  em.fromAlt();       // [a', d', c', b]
  em.over();          // [a', d', c', b, c']
  em.binOp('OP_XOR'); // [a', d', c', (b^c')]
  em.rotr_LE_general(rotB);
  // Stack: [a', d', c', b']
  em.assert(d0 - 1, 'halfG step4');

  // Rearrange: [a', d', c', b'] → [a', b', c', d']
  em.swap();          // [a', d', b', c']
  em.rot();           // [a', b', c', d']
  em.assert(d0 - 1, 'halfG done');
}

/**
 * Emit the full G function (quarter-round).
 * Stack entry: [a, b, c, d, mx, my] (my on TOS) — 6 items
 * Stack exit:  [a', b', c', d'] (d' on TOS) — 4 items
 * Net depth: -2
 */
function emitG(em: Emitter): void {
  const d0 = em.depth;

  // Save my to alt for phase 2
  em.toAlt();       // [a, b, c, d, mx]

  // Phase 1: first half with mx, ROTR(16) and ROTR(12)
  emitHalfG(em, 16, 12);
  em.assert(d0 - 2, 'G phase1');

  // Restore my for phase 2
  em.fromAlt();     // [a', b', c', d', my]
  em.assert(d0 - 1, 'G before phase2');

  // Phase 2: second half with my, ROTR(8) and ROTR(7)
  emitHalfG(em, 8, 7);
  em.assert(d0 - 2, 'G done');
}

// =========================================================================
// G call with state management
// =========================================================================

/**
 * Emit a single G call with state word roll management.
 *
 * Rolls 4 state words (ai, bi, ci, di) to top, picks 2 message words,
 * runs G, then updates tracker.
 */
function emitGCall(
  em: Emitter,
  tracker: StateTracker,
  ai: number, bi: number, ci: number, di: number,
  mxOrigIdx: number, myOrigIdx: number,
): void {
  const d0 = em.depth;

  // Roll 4 state words to top: a, b, c, d (d ends up as TOS)
  for (const idx of [ai, bi, ci, di]) {
    em.roll(tracker.depth(idx));
    tracker.onRollToTop(idx);
  }

  // Pick message words from below the 16 state word area
  // m[i] is at depth: 16 (state words) + (15 - i)
  em.pick(16 + (15 - mxOrigIdx));
  em.pick(16 + (15 - myOrigIdx) + 1); // +1 for mx just pushed
  em.assert(d0 + 2, 'before G');

  // Run G: consumes 6 (a, b, c, d, mx, my), produces 4 (a', b', c', d')
  emitG(em);
  em.assert(d0, 'after G');

  // Update tracker: result words at depths 0-3
  tracker.positions[ai] = 3;
  tracker.positions[bi] = 2;
  tracker.positions[ci] = 1;
  tracker.positions[di] = 0;
}

// =========================================================================
// Full compression ops generator
// =========================================================================

/**
 * Generate BLAKE3 compression ops.
 * Stack entry: [..., chainingValue(32 BE), block(64 BE)] — 2 items
 * Stack exit:  [..., hash(32 BE)] — 1 item
 * Net depth: -1
 */
/** @internal Generate just the setup ops (for debugging). Returns ops that leave 32 items on stack. */
export function generateSetupOps(): StackOp[] {
  const em = new Emitter(2);
  // Copy the setup phase exactly as in generateCompressOps
  for (let i = 0; i < 15; i++) em.split4();
  em.beWordsToLE(16);
  em.roll(16);
  em.toAlt();
  em.fromAlt();
  for (let i = 0; i < 7; i++) em.split4();
  em.beWordsToLE(8);
  for (let i = 0; i < 4; i++) em.pushB(u32ToLE(BLAKE3_IV[i]!));
  em.pushB(u32ToLE(0));
  em.pushB(u32ToLE(0));
  em.pushB(u32ToLE(64));
  em.pushB(u32ToLE(CHUNK_START | CHUNK_END | ROOT));
  return em.ops;
}

/** @internal Exposed for testing only */
export function generateCompressOps(numRounds = 7): StackOp[] {
  const em = new Emitter(2);

  // ================================================================
  // Phase 1: Unpack block into 16 LE message words
  // ================================================================
  // Stack: [chainingValue(32 BE), block(64 BE)]
  // Split block into 16 × 4-byte BE words, convert to LE
  for (let i = 0; i < 15; i++) em.split4();
  em.assert(17, 'after block unpack'); // 16 block words + 1 chainingValue
  em.beWordsToLE(16);
  em.assert(17, 'after block LE convert');
  // Stack: [CV, m0(LE), m1(LE), ..., m15(LE)] — m0 deepest of msg words, m15 TOS

  // ================================================================
  // Phase 2: Initialize 16-word state on top of message words
  // ================================================================
  // Move CV to alt (it's below the 16 msg words, at depth 16)
  em.roll(16);
  em.toAlt();
  em.assert(16, 'after CV to alt');
  // Stack: [m0, m1, ..., m15]  Alt: [CV]

  // Get CV back, split into 8 LE words, place on top of msg
  em.fromAlt();
  em.assert(17, 'after CV from alt');
  for (let i = 0; i < 7; i++) em.split4();
  em.assert(24, 'after cv unpack');
  em.beWordsToLE(8);
  em.assert(24, 'after cv LE convert');
  // Stack: [m0..m15, cv0(LE)..cv7(LE)]

  // v[0..7] = chaining value (already on stack)
  // v[8..11] = IV[0..3]
  for (let i = 0; i < 4; i++) em.pushB(u32ToLE(BLAKE3_IV[i]!));
  em.assert(28, 'after IV push');

  // v[12] = counter_low = 0, v[13] = counter_high = 0
  em.pushB(u32ToLE(0));
  em.pushB(u32ToLE(0));
  // v[14] = block_len = 64
  em.pushB(u32ToLE(64));
  // v[15] = flags = CHUNK_START | CHUNK_END | ROOT = 11
  em.pushB(u32ToLE(CHUNK_START | CHUNK_END | ROOT));
  em.assert(32, 'after state init');

  // Stack: [m0..m15(bottom), v0..v15(top)] — v15=TOS, m0=deepest

  // ================================================================
  // Phase 3: 7 rounds of G function calls
  // ================================================================
  const tracker = new StateTracker();

  for (let round = 0; round < numRounds; round++) {
    const s = MSG_SCHEDULE[round]!;

    // Column mixing
    emitGCall(em, tracker, 0, 4, 8, 12, s[0]!, s[1]!);
    emitGCall(em, tracker, 1, 5, 9, 13, s[2]!, s[3]!);
    emitGCall(em, tracker, 2, 6, 10, 14, s[4]!, s[5]!);
    emitGCall(em, tracker, 3, 7, 11, 15, s[6]!, s[7]!);

    // Diagonal mixing
    emitGCall(em, tracker, 0, 5, 10, 15, s[8]!, s[9]!);
    emitGCall(em, tracker, 1, 6, 11, 12, s[10]!, s[11]!);
    emitGCall(em, tracker, 2, 7, 8, 13, s[12]!, s[13]!);
    emitGCall(em, tracker, 3, 4, 9, 14, s[14]!, s[15]!);
  }

  em.assert(32, 'after all rounds');

  // ================================================================
  // Phase 4: Output — hash[i] = state[i] XOR state[i+8], for i=0..7
  // ================================================================

  // Reorder state words to canonical positions using alt stack
  for (let i = 15; i >= 0; i--) {
    const d = tracker.depth(i);
    em.roll(d);
    tracker.onRollToTop(i);
    em.toAlt();
    // Remaining words shift up because one was removed from main
    for (let j = 0; j < 16; j++) {
      if (j !== i && tracker.positions[j]! >= 0) {
        tracker.positions[j]!--;
      }
    }
    tracker.positions[i] = -1;
  }

  // Pop to get canonical order: [v0(bottom)..v15(TOS)]
  for (let i = 0; i < 16; i++) em.fromAlt();
  em.assert(32, 'after canonical reorder');

  // State: [m0..m15, v0(bottom)..v15(TOS)], canonical order.
  // XOR pairs: h[7-k] = v[7-k] ^ v[15-k] for k=0..7
  // Process top-down: v15^v7, v14^v6, ..., v8^v0. Send each result to alt.
  for (let k = 0; k < 8; k++) {
    em.roll(8 - k);       // bring v[7-k] to TOS (past v[15-k] and remaining)
    em.binOp('OP_XOR');   // h[7-k] = v[7-k] ^ v[15-k]
    em.toAlt();           // result to alt; main shrinks by 2
  }
  em.assert(16, 'after XOR pairs');
  // Alt (bottom→top): h7, h6, h5, h4, h3, h2, h1, h0. Main: [m0..m15].

  // Pop results to main: h0 first (LIFO), then h1, ..., h7
  for (let i = 0; i < 8; i++) em.fromAlt();
  em.assert(24, 'after XOR results restored');
  // Main: [m0..m15, h0, h1, ..., h7] h7=TOS

  // Pack into 32-byte BE result: h0_BE || h1_BE || ... || h7_BE
  em.reverseBytes4();  // h7 → h7_BE
  for (let i = 1; i < 8; i++) {
    em.swap();           // bring h[7-i] (LE) to TOS
    em.reverseBytes4();  // → BE
    em.swap();           // [new_BE, accumulated]
    em.binOp('OP_CAT');  // new_BE || accumulated
  }
  em.assert(17, 'after hash pack');

  // Drop 16 message words
  for (let i = 0; i < 16; i++) {
    em.swap();
    em.drop();
  }
  em.assert(1, 'compress final');

  return em.ops;
}

// =========================================================================
// Cache and public API
// =========================================================================

let _compressOpsCache: StackOp[] | null = null;
function getCompressOps(): StackOp[] {
  if (!_compressOpsCache) _compressOpsCache = generateCompressOps();
  return _compressOpsCache;
}

/**
 * Emit BLAKE3 single-block compression in Bitcoin Script.
 * Stack on entry: [..., chainingValue(32 BE), block(64 BE)]
 * Stack on exit:  [..., hash(32 BE)]
 * Net depth: -1
 */
export function emitBlake3Compress(emit: (op: StackOp) => void): void {
  for (const op of getCompressOps()) emit(op);
}

/**
 * Emit BLAKE3 hash for a message up to 64 bytes.
 * Stack on entry: [..., message(≤64 BE)]
 * Stack on exit:  [..., hash(32 BE)]
 * Net depth: 0
 *
 * Applies zero-padding and uses IV as chaining value.
 */
export function emitBlake3Hash(emit: (op: StackOp) => void): void {
  const em = new Emitter(1);

  // Pad message to 64 bytes (BLAKE3 zero-pads, no length suffix)
  em.oc('OP_SIZE'); em.depth++;  // [message, len]
  em.pushI(64n);
  em.swap();
  em.binOp('OP_SUB');    // [message, 64-len]
  em.pushI(0n);
  em.swap();
  em.binOp('OP_NUM2BIN'); // [message, zeros]
  em.binOp('OP_CAT');    // [paddedMessage(64)]

  // Push IV as 32-byte BE chaining value
  const ivBytes = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const be = u32ToBE(BLAKE3_IV[i]!);
    ivBytes.set(be, i * 4);
  }
  em.pushB(ivBytes);
  em.swap();  // [IV(32 BE), paddedMessage(64 BE)]

  // Splice compression ops
  const compressOps = getCompressOps();
  for (const op of compressOps) em.e_raw(op);
  em.depth = 1;

  em.assert(1, 'blake3Hash final');
  for (const op of em.ops) emit(op);
}
