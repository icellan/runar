//! BLAKE3 compression codegen for Bitcoin Script.
//!
//! Port of packages/runar-compiler/src/passes/blake3-codegen.ts.
//!
//! emit_blake3_compress: [chainingValue(32 BE), block(64 BE)] -> [hash(32 BE)]
//! emit_blake3_hash:     [message(<=64 BE)]                   -> [hash(32 BE)]
//!
//! Architecture (same as sha256.rs):
//!   - All 32-bit words stored as 4-byte little-endian during computation.
//!   - LE additions via BIN2NUM/NUM2BIN (13 ops per add32).
//!   - Byte-aligned rotations (16, 8) via SPLIT/SWAP/CAT on LE (4 ops).
//!   - Non-byte-aligned rotations (12, 7) via LE->BE->rotrBE->BE->LE (31 ops).
//!   - BE<->LE conversion only at input unpack and output pack.
//!
//! Stack layout during rounds:
//!   [m0..m15, v0..v15]  (all LE 4-byte values)
//!   v15 at TOS (depth 0), v0 at depth 15, m15 at depth 16, m0 at depth 31.

use super::stack::{PushValue, StackOp};

use std::sync::OnceLock;

// =========================================================================
// BLAKE3 constants
// =========================================================================

const BLAKE3_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

// Flags
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const ROOT: u32 = 8;

// =========================================================================
// Helper: encode u32 as 4-byte little-endian
// =========================================================================

fn u32_to_le(n: u32) -> Vec<u8> {
    vec![
        (n & 0xff) as u8,
        ((n >> 8) & 0xff) as u8,
        ((n >> 16) & 0xff) as u8,
        ((n >> 24) & 0xff) as u8,
    ]
}

fn u32_to_be(n: u32) -> Vec<u8> {
    vec![
        ((n >> 24) & 0xff) as u8,
        ((n >> 16) & 0xff) as u8,
        ((n >> 8) & 0xff) as u8,
        (n & 0xff) as u8,
    ]
}

// =========================================================================
// Precompute message schedule for all 7 rounds
// =========================================================================

/// For each round, compute which original message word index is used at each
/// position. Returns msg_schedule[round][position] = original msg word index.
fn compute_msg_schedule() -> [[usize; 16]; 7] {
    let mut current: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let mut schedule = [[0usize; 16]; 7];
    for round in 0..7 {
        schedule[round] = current;
        let mut next = [0usize; 16];
        for i in 0..16 {
            next[i] = current[MSG_PERMUTATION[i]];
        }
        current = next;
    }
    schedule
}

// =========================================================================
// Emitter with depth tracking
// =========================================================================

struct Emitter {
    ops: Vec<StackOp>,
    depth: i64,
    alt_depth: i64,
}

impl Emitter {
    fn new(initial_depth: i64) -> Self {
        Emitter {
            ops: Vec::new(),
            depth: initial_depth,
            alt_depth: 0,
        }
    }

    fn e_raw(&mut self, sop: StackOp) {
        self.ops.push(sop);
    }

    fn oc(&mut self, code: &str) {
        self.ops.push(StackOp::Opcode(code.to_string()));
    }

    fn push_i(&mut self, v: i128) {
        self.ops.push(StackOp::Push(PushValue::Int(v)));
        self.depth += 1;
    }

    fn push_b(&mut self, v: Vec<u8>) {
        self.ops.push(StackOp::Push(PushValue::Bytes(v)));
        self.depth += 1;
    }

    fn dup(&mut self) {
        self.ops.push(StackOp::Dup);
        self.depth += 1;
    }

    fn drop(&mut self) {
        self.ops.push(StackOp::Drop);
        self.depth -= 1;
    }

    fn swap(&mut self) {
        self.ops.push(StackOp::Swap);
    }

    fn over(&mut self) {
        self.ops.push(StackOp::Over);
        self.depth += 1;
    }

    fn rot(&mut self) {
        self.ops.push(StackOp::Rot);
    }

    fn pick(&mut self, d: usize) {
        if d == 0 {
            self.dup();
            return;
        }
        if d == 1 {
            self.over();
            return;
        }
        self.push_i(d as i128);
        self.ops.push(StackOp::Pick { depth: d });
        // push_i added 1, pick removes the depth literal but adds the picked value = net 0
    }

    fn roll(&mut self, d: usize) {
        if d == 0 {
            return;
        }
        if d == 1 {
            self.swap();
            return;
        }
        if d == 2 {
            self.rot();
            return;
        }
        self.push_i(d as i128);
        self.ops.push(StackOp::Roll { depth: d });
        self.depth -= 1; // push_i added 1, roll removes depth literal and item = net -1
    }

    fn to_alt(&mut self) {
        self.oc("OP_TOALTSTACK");
        self.depth -= 1;
        self.alt_depth += 1;
    }

    fn from_alt(&mut self) {
        self.oc("OP_FROMALTSTACK");
        self.depth += 1;
        self.alt_depth -= 1;
    }

    fn bin_op(&mut self, code: &str) {
        self.oc(code);
        self.depth -= 1;
    }

    fn uni_op(&mut self, code: &str) {
        self.oc(code);
    }

    fn split(&mut self) {
        self.oc("OP_SPLIT");
        // splits: consumes 2 (value + position), produces 2 = net 0
    }

    fn split4(&mut self) {
        self.push_i(4);
        self.split();
    }

    fn assert_depth(&self, expected: i64, msg: &str) {
        assert_eq!(
            self.depth, expected,
            "BLAKE3 codegen: {}. Expected depth {}, got {}",
            msg, expected, self.depth
        );
    }

    // --- Byte reversal (only for BE<->LE conversion at boundaries) ---

    /// Reverse 4 bytes on TOS: [abcd] -> [dcba]. Net: 0. 12 ops.
    fn reverse_bytes4(&mut self) {
        self.push_i(1);
        self.split();
        self.push_i(1);
        self.split();
        self.push_i(1);
        self.split();
        self.swap();
        self.bin_op("OP_CAT");
        self.swap();
        self.bin_op("OP_CAT");
        self.swap();
        self.bin_op("OP_CAT");
    }

    // --- LE <-> Numeric conversions ---

    /// Convert 4-byte LE to unsigned script number. [le4] -> [num]. Net: 0. 3 ops.
    fn le2num(&mut self) {
        self.push_b(vec![0x00]); // unsigned padding
        self.bin_op("OP_CAT");
        self.uni_op("OP_BIN2NUM");
    }

    /// Convert script number to 4-byte LE (truncates to 32 bits). [num] -> [le4]. Net: 0. 5 ops.
    fn num2le(&mut self) {
        self.push_i(5);
        self.bin_op("OP_NUM2BIN"); // 5-byte LE
        self.push_i(4);
        self.split(); // [4-byte LE, overflow+sign]
        self.drop(); // discard overflow byte
    }

    // --- LE arithmetic ---

    /// [a(LE), b(LE)] -> [(a+b mod 2^32)(LE)]. Net: -1. 13 ops.
    fn add32(&mut self) {
        self.le2num();
        self.swap();
        self.le2num();
        self.bin_op("OP_ADD");
        self.num2le();
    }

    /// Add N LE values. [v0..vN-1] (vN-1=TOS) -> [sum(LE)]. Net: -(N-1).
    fn add_n(&mut self, n: usize) {
        if n < 2 {
            return;
        }
        self.le2num();
        for _ in 1..n {
            self.swap();
            self.le2num();
            self.bin_op("OP_ADD");
        }
        self.num2le();
    }

    // --- ROTR using OP_LSHIFT/OP_RSHIFT (native BE byte-array shifts) ---

    /// ROTR(x, n) on BE 4-byte value. [x_BE] -> [rotated_BE]. Net: 0. 7 ops.
    fn rotr_be(&mut self, n: usize) {
        self.dup(); // [x, x]
        self.push_i(n as i128);
        self.bin_op("OP_RSHIFT"); // [x, x>>n]
        self.swap(); // [x>>n, x]
        self.push_i((32 - n) as i128);
        self.bin_op("OP_LSHIFT"); // [x>>n, x<<(32-n)]
        self.bin_op("OP_OR"); // [ROTR result]
    }

    // --- ROTR on LE values ---

    /// ROTR(x, 16) on LE 4-byte value. Net: 0. 4 ops.
    /// Swaps the two 16-bit halves: [b0,b1,b2,b3] -> [b2,b3,b0,b1].
    fn rotr16_le(&mut self) {
        self.push_i(2);
        self.split(); // [lo2, hi2]
        self.swap(); // [hi2, lo2]
        self.bin_op("OP_CAT"); // [hi2||lo2]
    }

    /// ROTR(x, 8) on LE 4-byte value. Net: 0. 4 ops.
    /// [b0,b1,b2,b3] -> [b1,b2,b3,b0]
    fn rotr8_le(&mut self) {
        self.push_i(1);
        self.split(); // [b0, b1b2b3]
        self.swap(); // [b1b2b3, b0]
        self.bin_op("OP_CAT"); // [b1b2b3||b0]
    }

    /// ROTR(x, n) on LE 4-byte value (general, non-byte-aligned). Net: 0. 31 ops.
    /// Converts LE->BE, applies rotr_be, converts back.
    fn rotr_le_general(&mut self, n: usize) {
        self.reverse_bytes4(); // LE -> BE (12 ops)
        self.rotr_be(n); // rotate on BE (7 ops)
        self.reverse_bytes4(); // BE -> LE (12 ops)
    }

    /// Convert N x BE words on TOS to LE, preserving stack order.
    fn be_words_to_le(&mut self, n: usize) {
        for _ in 0..n {
            self.reverse_bytes4();
            self.to_alt();
        }
        for _ in 0..n {
            self.from_alt();
        }
    }
}

// =========================================================================
// State word position tracker
// =========================================================================

/// Tracks the stack depth of each of the 16 state words.
/// Depth 0 = TOS. Message words sit below the state area at fixed positions.
struct StateTracker {
    /// positions[i] = current depth of state word v[i] from TOS
    positions: [i32; 16],
}

impl StateTracker {
    fn new() -> Self {
        let mut positions = [0i32; 16];
        // Initial: v0 at depth 15 (deepest state word), v15 at depth 0 (TOS)
        for i in 0..16 {
            positions[i] = (15 - i) as i32;
        }
        StateTracker { positions }
    }

    fn depth(&self, word_idx: usize) -> i32 {
        self.positions[word_idx]
    }

    /// Update after rolling a state word from its current depth to TOS.
    fn on_roll_to_top(&mut self, word_idx: usize) {
        let d = self.positions[word_idx];
        for j in 0..16 {
            if j != word_idx && self.positions[j] >= 0 && self.positions[j] < d {
                self.positions[j] += 1;
            }
        }
        self.positions[word_idx] = 0;
    }
}

// =========================================================================
// G function (quarter-round)
// =========================================================================

/// Emit one half of the G function.
/// Stack entry: [a, b, c, d, m] (m on TOS) -- 5 items
/// Stack exit:  [a', b', c', d'] (d' on TOS) -- 4 items
/// Net depth: -1
///
/// Operations:
///   a' = a + b + m
///   d' = (d ^ a') >>> rotD
///   c' = c + d'
///   b' = (original_b ^ c') >>> rotB
fn emit_half_g(em: &mut Emitter, rot_d: usize, rot_b: usize) {
    let d0 = em.depth;

    // Save original b for step 4 (b is at depth 3)
    em.pick(3);
    em.to_alt();

    // Step 1: a' = a + b + m
    // Stack: [a, b, c, d, m] -- a=4, b=3, c=2, d=1, m=0
    em.roll(3); // [a, c, d, m, b]
    em.roll(4); // [c, d, m, b, a]
    em.add_n(3); // [c, d, a']
    em.assert_depth(d0 - 2, "halfG step1");

    // Step 2: d' = (d ^ a') >>> rotD
    // Stack: [c, d, a'] -- c=2, d=1, a'=0
    em.dup(); // [c, d, a', a']
    em.rot(); // [c, a', a', d]
    em.bin_op("OP_XOR"); // [c, a', (d^a')]
    if rot_d == 16 {
        em.rotr16_le();
    } else if rot_d == 8 {
        em.rotr8_le();
    } else {
        em.rotr_le_general(rot_d);
    }
    em.assert_depth(d0 - 2, "halfG step2");

    // Step 3: c' = c + d'
    // Stack: [c, a', d']
    em.dup(); // [c, a', d', d']
    em.roll(3); // [a', d', d', c]
    em.add32(); // [a', d', c']
    em.assert_depth(d0 - 2, "halfG step3");

    // Step 4: b' = (original_b ^ c') >>> rotB
    // Stack: [a', d', c']
    em.from_alt(); // [a', d', c', b]
    em.over(); // [a', d', c', b, c']
    em.bin_op("OP_XOR"); // [a', d', c', (b^c')]
    em.rotr_le_general(rot_b);
    // Stack: [a', d', c', b']
    em.assert_depth(d0 - 1, "halfG step4");

    // Rearrange: [a', d', c', b'] -> [a', b', c', d']
    em.swap(); // [a', d', b', c']
    em.rot(); // [a', b', c', d']
    em.assert_depth(d0 - 1, "halfG done");
}

/// Emit the full G function (quarter-round).
/// Stack entry: [a, b, c, d, mx, my] (my on TOS) -- 6 items
/// Stack exit:  [a', b', c', d'] (d' on TOS) -- 4 items
/// Net depth: -2
fn emit_g(em: &mut Emitter) {
    let d0 = em.depth;

    // Save my to alt for phase 2
    em.to_alt(); // [a, b, c, d, mx]

    // Phase 1: first half with mx, ROTR(16) and ROTR(12)
    emit_half_g(em, 16, 12);
    em.assert_depth(d0 - 2, "G phase1");

    // Restore my for phase 2
    em.from_alt(); // [a', b', c', d', my]
    em.assert_depth(d0 - 1, "G before phase2");

    // Phase 2: second half with my, ROTR(8) and ROTR(7)
    emit_half_g(em, 8, 7);
    em.assert_depth(d0 - 2, "G done");
}

// =========================================================================
// G call with state management
// =========================================================================

/// Emit a single G call with state word roll management.
///
/// Rolls 4 state words (ai, bi, ci, di) to top, picks 2 message words,
/// runs G, then updates tracker.
fn emit_g_call(
    em: &mut Emitter,
    tracker: &mut StateTracker,
    ai: usize,
    bi: usize,
    ci: usize,
    di: usize,
    mx_orig_idx: usize,
    my_orig_idx: usize,
) {
    let d0 = em.depth;

    // Roll 4 state words to top: a, b, c, d (d ends up as TOS)
    for &idx in &[ai, bi, ci, di] {
        let d = tracker.depth(idx) as usize;
        em.roll(d);
        tracker.on_roll_to_top(idx);
    }

    // Pick message words from below the 16 state word area
    // m[i] is at depth: 16 (state words) + (15 - i)
    em.pick(16 + (15 - mx_orig_idx));
    em.pick(16 + (15 - my_orig_idx) + 1); // +1 for mx just pushed
    em.assert_depth(d0 + 2, "before G");

    // Run G: consumes 6 (a, b, c, d, mx, my), produces 4 (a', b', c', d')
    emit_g(em);
    em.assert_depth(d0, "after G");

    // Update tracker: result words at depths 0-3
    tracker.positions[ai] = 3;
    tracker.positions[bi] = 2;
    tracker.positions[ci] = 1;
    tracker.positions[di] = 0;
}

// =========================================================================
// Full compression ops generator
// =========================================================================

fn generate_compress_ops() -> Vec<StackOp> {
    let mut em = Emitter::new(2);
    let msg_schedule = compute_msg_schedule();

    // ================================================================
    // Phase 1: Unpack block into 16 LE message words
    // ================================================================
    // Stack: [chainingValue(32 BE), block(64 BE)]
    // Split block into 16 x 4-byte BE words, convert to LE
    for _ in 0..15 {
        em.split4();
    }
    em.assert_depth(17, "after block unpack"); // 16 block words + 1 chainingValue
    em.be_words_to_le(16);
    em.assert_depth(17, "after block LE convert");
    // Stack: [CV, m0(LE), m1(LE), ..., m15(LE)] -- m0 deepest of msg words, m15 TOS

    // ================================================================
    // Phase 2: Initialize 16-word state on top of message words
    // ================================================================
    // Move CV to alt (it's below the 16 msg words, at depth 16)
    em.roll(16);
    em.to_alt();
    em.assert_depth(16, "after CV to alt");
    // Stack: [m0, m1, ..., m15]  Alt: [CV]

    // Get CV back, split into 8 LE words, place on top of msg
    em.from_alt();
    em.assert_depth(17, "after CV from alt");
    for _ in 0..7 {
        em.split4();
    }
    em.assert_depth(24, "after cv unpack");
    em.be_words_to_le(8);
    em.assert_depth(24, "after cv LE convert");
    // Stack: [m0..m15, cv0(LE)..cv7(LE)]

    // v[0..7] = chaining value (already on stack)
    // v[8..11] = IV[0..3]
    for i in 0..4 {
        em.push_b(u32_to_le(BLAKE3_IV[i]));
    }
    em.assert_depth(28, "after IV push");

    // v[12] = counter_low = 0, v[13] = counter_high = 0
    em.push_b(u32_to_le(0));
    em.push_b(u32_to_le(0));
    // v[14] = block_len = 64
    em.push_b(u32_to_le(64));
    // v[15] = flags = CHUNK_START | CHUNK_END | ROOT = 11
    em.push_b(u32_to_le(CHUNK_START | CHUNK_END | ROOT));
    em.assert_depth(32, "after state init");

    // Stack: [m0..m15(bottom), v0..v15(top)] -- v15=TOS, m0=deepest

    // ================================================================
    // Phase 3: 7 rounds of G function calls
    // ================================================================
    let mut tracker = StateTracker::new();

    for round in 0..7 {
        let s = &msg_schedule[round];

        // Column mixing
        emit_g_call(&mut em, &mut tracker, 0, 4, 8, 12, s[0], s[1]);
        emit_g_call(&mut em, &mut tracker, 1, 5, 9, 13, s[2], s[3]);
        emit_g_call(&mut em, &mut tracker, 2, 6, 10, 14, s[4], s[5]);
        emit_g_call(&mut em, &mut tracker, 3, 7, 11, 15, s[6], s[7]);

        // Diagonal mixing
        emit_g_call(&mut em, &mut tracker, 0, 5, 10, 15, s[8], s[9]);
        emit_g_call(&mut em, &mut tracker, 1, 6, 11, 12, s[10], s[11]);
        emit_g_call(&mut em, &mut tracker, 2, 7, 8, 13, s[12], s[13]);
        emit_g_call(&mut em, &mut tracker, 3, 4, 9, 14, s[14], s[15]);
    }

    em.assert_depth(32, "after all rounds");

    // ================================================================
    // Phase 4: Output -- hash[i] = state[i] XOR state[i+8], for i=0..7
    // ================================================================

    // Canonical reorder via alt stack
    for i in (0..=15usize).rev() {
        let d = tracker.depth(i);
        em.roll(d as usize);
        tracker.on_roll_to_top(i);
        em.to_alt();
        for j in 0..16 {
            if j != i && tracker.positions[j] >= 0 {
                tracker.positions[j] -= 1;
            }
        }
        tracker.positions[i] = -1;
    }

    // Pop to get canonical order: [v0(bottom)..v15(TOS)]
    for _ in 0..16 {
        em.from_alt();
    }
    em.assert_depth(32, "after canonical reorder");

    // State: [m0..m15, v0(bottom)..v15(TOS)], canonical order.
    // XOR pairs: h[7-k] = v[7-k] ^ v[15-k] for k=0..7
    // Process top-down: v15^v7, v14^v6, ..., v8^v0. Send each result to alt.
    for k in 0..8usize {
        em.roll(8 - k); // bring v[7-k] to TOS (past v[15-k] and remaining)
        em.bin_op("OP_XOR"); // h[7-k] = v[7-k] ^ v[15-k]
        em.to_alt(); // result to alt; main shrinks by 2
    }
    em.assert_depth(16, "after XOR pairs");
    // Alt (bottom->top): h7, h6, h5, h4, h3, h2, h1, h0. Main: [m0..m15].

    // Pop results to main: h0 first (LIFO), then h1, ..., h7
    for _ in 0..8 {
        em.from_alt();
    }
    em.assert_depth(24, "after XOR results restored");
    // Main: [m0..m15, h0, h1, ..., h7] h7=TOS

    // Pack into 32-byte BE result: h0_BE || h1_BE || ... || h7_BE
    em.reverse_bytes4(); // h7 -> h7_BE
    for _ in 1..8 {
        em.swap(); // bring h[7-i] (LE) to TOS
        em.reverse_bytes4(); // -> BE
        em.swap(); // [new_BE, accumulated]
        em.bin_op("OP_CAT"); // new_BE || accumulated
    }
    em.assert_depth(17, "after hash pack");

    // Drop 16 message words
    for _ in 0..16 {
        em.swap();
        em.drop();
    }
    em.assert_depth(1, "compress final");

    em.ops
}

// Cache the ops since they're identical every time
static COMPRESS_OPS: OnceLock<Vec<StackOp>> = OnceLock::new();

fn get_compress_ops() -> &'static Vec<StackOp> {
    COMPRESS_OPS.get_or_init(generate_compress_ops)
}

// =========================================================================
// Public entry points
// =========================================================================

/// Emit BLAKE3 single-block compression in Bitcoin Script.
/// Stack on entry: [..., chainingValue(32 BE), block(64 BE)]
/// Stack on exit:  [..., hash(32 BE)]
/// Net depth: -1
pub fn emit_blake3_compress(emit: &mut dyn FnMut(StackOp)) {
    for op in get_compress_ops() {
        emit(op.clone());
    }
}

/// Emit BLAKE3 hash for a message up to 64 bytes.
/// Stack on entry: [..., message(<=64 BE)]
/// Stack on exit:  [..., hash(32 BE)]
/// Net depth: 0
///
/// Applies zero-padding and uses IV as chaining value.
pub fn emit_blake3_hash(emit: &mut dyn FnMut(StackOp)) {
    let mut em = Emitter::new(1);

    // Pad message to 64 bytes (BLAKE3 zero-pads, no length suffix)
    em.oc("OP_SIZE");
    em.depth += 1; // [message, len]
    em.push_i(64);
    em.swap();
    em.bin_op("OP_SUB"); // [message, 64-len]
    em.push_i(0);
    em.swap();
    em.bin_op("OP_NUM2BIN"); // [message, zeros]
    em.bin_op("OP_CAT"); // [paddedMessage(64)]

    // Push IV as 32-byte BE chaining value
    let mut iv_bytes = Vec::with_capacity(32);
    for i in 0..8 {
        iv_bytes.extend_from_slice(&u32_to_be(BLAKE3_IV[i]));
    }
    em.push_b(iv_bytes);
    em.swap(); // [IV(32 BE), paddedMessage(64 BE)]

    // Splice compression ops
    let compress_ops = get_compress_ops();
    for op in compress_ops {
        em.e_raw(op.clone());
    }
    em.depth = 1;

    em.assert_depth(1, "blake3Hash final");

    for op in em.ops {
        emit(op);
    }
}
