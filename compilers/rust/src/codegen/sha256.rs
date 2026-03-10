//! SHA-256 compression codegen for Bitcoin Script.
//!
//! Port of packages/runar-compiler/src/passes/sha256-codegen.ts.
//!
//! emitSha256Compress: [state(32), block(64)] -> [newState(32)]
//!
//! Optimized architecture (inspired by twostack/tstokenlib):
//!   - All 32-bit words stored as 4-byte little-endian during computation.
//!   - Bitwise ops (AND, OR, XOR, INVERT) are endian-agnostic on equal-length arrays.
//!   - ROTR uses OP_RSHIFT/OP_LSHIFT (native BE byte-array shifts).
//!   - Batched addN for T1 (5 addends) converts all to numeric once, adds, converts back.
//!   - BE<->LE conversion only at input unpack / output pack.

use super::stack::{PushValue, StackOp};

use std::sync::OnceLock;

// SHA-256 round constants
const K: [u32; 64] = [
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

/// Encode a uint32 as 4-byte little-endian.
fn u32_to_le(n: u32) -> Vec<u8> {
    vec![
        (n & 0xff) as u8,
        ((n >> 8) & 0xff) as u8,
        ((n >> 16) & 0xff) as u8,
        ((n >> 24) & 0xff) as u8,
    ]
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

    fn dup2(&mut self) {
        self.oc("OP_2DUP");
        self.depth += 2;
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
            "SHA256 codegen: {}. Expected depth {}, got {}",
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

    // --- ROTR/SHR using OP_LSHIFT/OP_RSHIFT (native BE byte-array shifts) ---

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

    /// SHR(x, n) on BE 4-byte value. [x_BE] -> [shifted_BE]. Net: 0. 2 ops.
    fn shr_be(&mut self, n: usize) {
        self.push_i(n as i128);
        self.bin_op("OP_RSHIFT");
    }

    // --- SHA-256 sigma functions ---

    /// big_sigma0(a) = ROTR(2)^ROTR(13)^ROTR(22). [a(LE)] -> [S0(LE)]. Net: 0.
    fn big_sigma0(&mut self) {
        self.reverse_bytes4(); // LE -> BE
        self.dup();
        self.dup();
        self.rotr_be(2);
        self.swap();
        self.rotr_be(13);
        self.bin_op("OP_XOR");
        self.swap();
        self.rotr_be(22);
        self.bin_op("OP_XOR");
        self.reverse_bytes4(); // BE -> LE
    }

    /// big_sigma1(e) = ROTR(6)^ROTR(11)^ROTR(25). [e(LE)] -> [S1(LE)]. Net: 0.
    fn big_sigma1(&mut self) {
        self.reverse_bytes4();
        self.dup();
        self.dup();
        self.rotr_be(6);
        self.swap();
        self.rotr_be(11);
        self.bin_op("OP_XOR");
        self.swap();
        self.rotr_be(25);
        self.bin_op("OP_XOR");
        self.reverse_bytes4();
    }

    /// small_sigma0(x) = ROTR(7)^ROTR(18)^SHR(3). [x(LE)] -> [s0(LE)]. Net: 0.
    fn small_sigma0(&mut self) {
        self.reverse_bytes4();
        self.dup();
        self.dup();
        self.rotr_be(7);
        self.swap();
        self.rotr_be(18);
        self.bin_op("OP_XOR");
        self.swap();
        self.shr_be(3);
        self.bin_op("OP_XOR");
        self.reverse_bytes4();
    }

    /// small_sigma1(x) = ROTR(17)^ROTR(19)^SHR(10). [x(LE)] -> [s1(LE)]. Net: 0.
    fn small_sigma1(&mut self) {
        self.reverse_bytes4();
        self.dup();
        self.dup();
        self.rotr_be(17);
        self.swap();
        self.rotr_be(19);
        self.bin_op("OP_XOR");
        self.swap();
        self.shr_be(10);
        self.bin_op("OP_XOR");
        self.reverse_bytes4();
    }

    /// Ch(e,f,g) = (e&f)^(~e&g). [e, f, g] (g=TOS), all LE -> [Ch(LE)]. Net: -2.
    fn ch(&mut self) {
        self.rot();
        self.dup();
        self.uni_op("OP_INVERT");
        self.rot();
        self.bin_op("OP_AND");
        self.to_alt();
        self.bin_op("OP_AND");
        self.from_alt();
        self.bin_op("OP_XOR");
    }

    /// Maj(a,b,c) = (a&b)|(c&(a^b)). [a, b, c] (c=TOS), all LE -> [Maj(LE)]. Net: -2.
    fn maj(&mut self) {
        self.to_alt();
        self.dup2();
        self.bin_op("OP_AND");
        self.to_alt();
        self.bin_op("OP_XOR");
        self.from_alt();
        self.swap();
        self.from_alt();
        self.bin_op("OP_AND");
        self.bin_op("OP_OR");
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

    /// Convert 8 x BE words on TOS to LE AND reverse order.
    fn be_words_to_le_reversed8(&mut self) {
        for i in (0..8).rev() {
            self.roll(i);
            self.reverse_bytes4();
            self.to_alt();
        }
        for _ in 0..8 {
            self.from_alt();
        }
    }
}

// =========================================================================
// One compression round
// =========================================================================

/// Emit one compression round. Stack: [W0..W63, a,b,c,d,e,f,g,h] (a=TOS, all LE). Net: 0.
fn emit_round(em: &mut Emitter, t: usize) {
    let d0 = em.depth;

    // --- T1 = Sigma1(e) + Ch(e,f,g) + h + K[t] + W[t] ---
    em.pick(4); // e copy (+1)
    em.big_sigma1(); // Sigma1(e) (0)

    em.pick(5);
    em.pick(7);
    em.pick(9); // e, f, g copies (+3)
    em.ch(); // Ch(e,f,g) (-2) -> net +2

    em.pick(9); // h copy (+1) -> net +3
    em.push_b(u32_to_le(K[t])); // K[t] as LE (+1) -> net +4
    em.pick(75 - t); // W[t] copy (+1) -> net +5

    em.add_n(5); // T1 = sum of 5 (-4) -> net +1

    // --- T2 = Sigma0(a) + Maj(a,b,c) ---
    em.dup();
    em.to_alt(); // save T1 copy to alt

    em.pick(1); // a copy (+1) -> net +2
    em.big_sigma0(); // Sigma0(a) (0)

    em.pick(2);
    em.pick(4);
    em.pick(6); // a, b, c copies (+3) -> net +5
    em.maj(); // Maj(a,b,c) (-2) -> net +3
    em.add32(); // T2 = Sigma0 + Maj (-1) -> net +2

    // --- Register update ---
    em.from_alt(); // T1 copy from alt (+1) -> net +3

    em.swap();
    em.add32(); // new_a = T1 + T2 (-1) -> net +2

    em.swap();
    em.roll(5); // d to top
    em.add32(); // new_e = d + T1 (-1) -> net +1

    em.roll(8);
    em.drop(); // drop h (-1) -> net 0

    // Rotate: [ne,na,a,b,c,e,f,g] -> [na,a,b,c,ne,e,f,g]
    em.swap();
    em.roll(4);
    em.roll(4);
    em.roll(4);
    em.roll(3);

    em.assert_depth(d0, &format!("compress: after round {}", t));
}

// =========================================================================
// Reusable compress ops generator
// =========================================================================

fn generate_compress_ops() -> Vec<StackOp> {
    let mut em = Emitter::new(2); // pretend state+block are the only items

    // Phase 1: Save init state to alt, unpack block into 16 LE words
    em.swap();
    em.dup();
    em.to_alt();
    em.to_alt();
    em.assert_depth(1, "compress: after state save");

    for _ in 0..15 {
        em.split4();
    }
    em.assert_depth(16, "compress: after block unpack");
    em.be_words_to_le(16);
    em.assert_depth(16, "compress: after block LE convert");

    // Phase 2: W expansion
    for _t in 16..64 {
        em.over();
        em.small_sigma1();
        em.pick(6 + 1);
        em.pick(14 + 2);
        em.small_sigma0();
        em.pick(15 + 3);
        em.add_n(4);
    }
    em.assert_depth(64, "compress: after W expansion");

    // Phase 3: Unpack state into 8 LE working vars
    em.from_alt();
    for _ in 0..7 {
        em.split4();
    }
    em.assert_depth(72, "compress: after state unpack");
    em.be_words_to_le_reversed8();
    em.assert_depth(72, "compress: after state LE convert");

    // Phase 4: 64 compression rounds
    for t in 0..64 {
        emit_round(&mut em, t);
    }

    // Phase 5: Add initial state, pack result
    em.from_alt();
    em.assert_depth(73, "compress: before final add");

    for _ in 0..7 {
        em.split4();
    }
    em.be_words_to_le_reversed8();
    em.assert_depth(80, "compress: after init unpack");

    for i in 0..8 {
        em.roll(8 - i);
        em.add32();
        em.to_alt();
    }
    em.assert_depth(64, "compress: after final add");

    em.from_alt();
    em.reverse_bytes4();
    for _ in 1..8 {
        em.from_alt();
        em.reverse_bytes4();
        em.swap();
        em.bin_op("OP_CAT");
    }
    em.assert_depth(65, "compress: after pack");

    for _ in 0..64 {
        em.swap();
        em.drop();
    }
    em.assert_depth(1, "compress: final");

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

/// Emit SHA-256 compression in Bitcoin Script.
/// Stack on entry: [..., state(32 BE), block(64 BE)]
/// Stack on exit:  [..., newState(32 BE)]
pub fn emit_sha256_compress(emit: &mut dyn FnMut(StackOp)) {
    for op in get_compress_ops() {
        emit(op.clone());
    }
}

/// Emit SHA-256 finalization in Bitcoin Script.
/// Stack on entry: [..., state(32 BE), remaining(var len BE), msgBitLen(bigint)]
/// Stack on exit:  [..., hash(32 BE)]
pub fn emit_sha256_finalize(emit: &mut dyn FnMut(StackOp)) {
    let mut em = Emitter::new(3); // state + remaining + msgBitLen

    // ---- Step 1: Convert msgBitLen to 8-byte BE ----
    em.push_i(9);
    em.bin_op("OP_NUM2BIN"); // 9-byte LE
    em.push_i(8);
    em.split(); // [8-byte LE, sign byte]
    em.drop(); // [8-byte LE]
    // Reverse 8 bytes to BE: split(4), reverse each half, cat
    em.push_i(4);
    em.split(); // [lo4_LE, hi4_LE]
    em.reverse_bytes4(); // [lo4_LE, hi4_rev]
    em.swap();
    em.reverse_bytes4(); // [hi4_rev, lo4_rev]
    em.bin_op("OP_CAT"); // [bitLenBE(8)]
    em.to_alt(); // save bitLenBE to alt
    em.assert_depth(2, "finalize: after bitLen conversion");

    // ---- Step 2: Pad remaining ----
    em.push_b(vec![0x80]);
    em.bin_op("OP_CAT"); // [state, remaining||0x80]

    // Get padded length
    em.oc("OP_SIZE");
    em.depth += 1; // [state, padded, paddedLen]

    // Branch: 1 block (paddedLen <= 56) or 2 blocks (paddedLen > 56)
    em.dup();
    em.push_i(57);
    em.bin_op("OP_LESSTHAN"); // paddedLen < 57?

    em.oc("OP_IF");
    em.depth -= 1; // consume flag

    // ---- 1-block path: pad to 56 bytes ----
    em.push_i(56);
    em.swap();
    em.bin_op("OP_SUB"); // zeroCount = 56 - paddedLen
    em.push_i(0);
    em.swap();
    em.bin_op("OP_NUM2BIN"); // zero bytes
    em.bin_op("OP_CAT"); // [state, padded(56 bytes)]
    em.from_alt(); // bitLenBE from alt
    em.bin_op("OP_CAT"); // [state, block1(64 bytes)]
    // Splice sha256Compress ops
    let compress_ops = get_compress_ops();
    for op in compress_ops {
        em.e_raw(op.clone());
    }
    em.depth = 1; // after compress: 1 result

    em.oc("OP_ELSE");
    em.depth = 3; // reset to branch entry: [state, padded, paddedLen]

    // ---- 2-block path: pad to 120 bytes ----
    em.push_i(120);
    em.swap();
    em.bin_op("OP_SUB"); // zeroCount = 120 - paddedLen
    em.push_i(0);
    em.swap();
    em.bin_op("OP_NUM2BIN"); // zero bytes
    em.bin_op("OP_CAT"); // [state, padded(120 bytes)]
    em.from_alt(); // bitLenBE from alt
    em.bin_op("OP_CAT"); // [state, fullPadded(128 bytes)]

    // Split into 2 blocks
    em.push_i(64);
    em.split(); // [state, block1(64), block2(64)]
    em.to_alt(); // save block2

    // First compress: [state, block1]
    for op in compress_ops {
        em.e_raw(op.clone());
    }
    em.depth = 1; // after first compress: [midState]

    // Second compress: [midState, block2]
    em.from_alt(); // [midState, block2]
    for op in compress_ops {
        em.e_raw(op.clone());
    }
    em.depth = 1; // after second compress: [result]

    em.oc("OP_ENDIF");
    // Both paths leave 1 item (result) on stack
    em.assert_depth(1, "finalize: final");

    for op in em.ops {
        emit(op);
    }
}
