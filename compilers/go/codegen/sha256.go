// Package codegen SHA-256 compression codegen for Bitcoin Script.
//
// emitSha256Compress: [state(32), block(64)] → [newState(32)]
//
// Optimized architecture (inspired by twostack/tstokenlib):
//   - All 32-bit words stored as 4-byte little-endian during computation.
//     LE→num conversion is just push(0x00)+CAT+BIN2NUM (3 ops) vs 15 ops for BE.
//   - Bitwise ops (AND, OR, XOR, INVERT) are endian-agnostic on equal-length arrays.
//   - ROTR uses native OP_LSHIFT/OP_RSHIFT on BE 4-byte values.
//   - Batched addN for T1 (5 addends) converts all to numeric once, adds, converts back.
//   - BE→LE conversion only at input unpack; LE→BE only at output pack.
//
// Stack layout during rounds:
//
//	[W0..W63, a, b, c, d, e, f, g, h]  (all LE 4-byte values)
//	a at depth 0 (TOS), h at depth 7. W[t] at depth 8+(63-t).
//	Alt: [initState(32 bytes BE)]
package codegen

import "math/big"

// SHA-256 round constants
var sha256K = [64]uint32{
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
}

// u32ToLE encodes a uint32 as 4-byte little-endian (precomputed at codegen time).
func u32ToLE(n uint32) []byte {
	return []byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
}

// =========================================================================
// sha256Emitter with depth tracking
// =========================================================================

type sha256Emitter struct {
	ops      []StackOp
	depth    int
	altDepth int
}

func newSha256Emitter(initialDepth int) *sha256Emitter {
	return &sha256Emitter{depth: initialDepth}
}

func (e *sha256Emitter) emit(sop StackOp)    { e.ops = append(e.ops, sop) }
func (e *sha256Emitter) emitRaw(sop StackOp) { e.ops = append(e.ops, sop) }

func (e *sha256Emitter) oc(code string) { e.emit(StackOp{Op: "opcode", Code: code}) }

func (e *sha256Emitter) pushI(v int64) {
	e.emit(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(v)}})
	e.depth++
}

func (e *sha256Emitter) pushB(v []byte) {
	e.emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: v}})
	e.depth++
}

func (e *sha256Emitter) dup()  { e.emit(StackOp{Op: "dup"}); e.depth++ }
func (e *sha256Emitter) drop() { e.emit(StackOp{Op: "drop"}); e.depth-- }
func (e *sha256Emitter) swap() { e.emit(StackOp{Op: "swap"}) }
func (e *sha256Emitter) over() { e.emit(StackOp{Op: "over"}); e.depth++ }
func (e *sha256Emitter) nip()  { e.emit(StackOp{Op: "nip"}); e.depth-- }
func (e *sha256Emitter) rot()  { e.emit(StackOp{Op: "rot"}) }

func (e *sha256Emitter) pick(d int) {
	if d == 0 {
		e.dup()
		return
	}
	if d == 1 {
		e.over()
		return
	}
	e.pushI(int64(d))
	e.emit(StackOp{Op: "pick", Depth: d})
}

func (e *sha256Emitter) roll(d int) {
	if d == 0 {
		return
	}
	if d == 1 {
		e.swap()
		return
	}
	if d == 2 {
		e.rot()
		return
	}
	e.pushI(int64(d))
	e.emit(StackOp{Op: "roll", Depth: d})
	e.depth--
}

func (e *sha256Emitter) toAlt()   { e.oc("OP_TOALTSTACK"); e.depth--; e.altDepth++ }
func (e *sha256Emitter) fromAlt() { e.oc("OP_FROMALTSTACK"); e.depth++; e.altDepth-- }

func (e *sha256Emitter) binOp(code string) { e.oc(code); e.depth-- }
func (e *sha256Emitter) uniOp(code string) { e.oc(code) }
func (e *sha256Emitter) dup2()             { e.oc("OP_2DUP"); e.depth += 2 }

func (e *sha256Emitter) split()  { e.oc("OP_SPLIT") }
func (e *sha256Emitter) split4() { e.pushI(4); e.split() }

func (e *sha256Emitter) assertDepth(expected int, msg string) {
	if e.depth != expected {
		panic("SHA256 codegen: " + msg + ". Expected depth " + itoa(expected) + ", got " + itoa(e.depth))
	}
}

func itoa(n int) string {
	if n < 0 {
		return "-" + uitoa(-n)
	}
	return uitoa(n)
}

func uitoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return uitoa(n/10) + string(rune('0'+n%10))
}

// --- Byte reversal (only for BE↔LE conversion at boundaries) ---

// reverseBytes4 reverses 4 bytes on TOS: [abcd] → [dcba]. Net: 0. 12 ops.
func (e *sha256Emitter) reverseBytes4() {
	e.pushI(1)
	e.split()
	e.pushI(1)
	e.split()
	e.pushI(1)
	e.split()
	e.swap()
	e.binOp("OP_CAT")
	e.swap()
	e.binOp("OP_CAT")
	e.swap()
	e.binOp("OP_CAT")
}

// --- LE ↔ Numeric conversions (cheap — no byte reversal) ---

// le2num converts 4-byte LE to unsigned script number. [le4] → [num]. Net: 0. 3 ops.
func (e *sha256Emitter) le2num() {
	e.pushB([]byte{0x00}) // unsigned padding
	e.binOp("OP_CAT")
	e.uniOp("OP_BIN2NUM")
}

// num2le converts script number to 4-byte LE (truncates to 32 bits). [num] → [le4]. Net: 0. 5 ops.
func (e *sha256Emitter) num2le() {
	e.pushI(5)
	e.binOp("OP_NUM2BIN") // 5-byte LE
	e.pushI(4)
	e.split() // [4-byte LE, overflow+sign]
	e.drop()  // discard overflow byte
}

// --- LE arithmetic ---

// add32: [a(LE), b(LE)] → [(a+b mod 2^32)(LE)]. Net: -1. 13 ops.
func (e *sha256Emitter) add32() {
	e.le2num()
	e.swap()
	e.le2num()
	e.binOp("OP_ADD")
	e.num2le()
}

// addN adds N LE values. [v0..vN-1] (vN-1=TOS) → [sum(LE)]. Net: -(N-1).
func (e *sha256Emitter) addN(n int) {
	if n < 2 {
		return
	}
	e.le2num()
	for i := 1; i < n; i++ {
		e.swap()
		e.le2num()
		e.binOp("OP_ADD")
	}
	e.num2le()
}

// --- ROTR/SHR using OP_LSHIFT/OP_RSHIFT (native BE byte-array shifts) ---

// rotrBE: ROTR(x, n) on BE 4-byte value. [x_BE] → [rotated_BE]. Net: 0. 7 ops.
func (e *sha256Emitter) rotrBE(n int) {
	e.dup()
	e.pushI(int64(n))
	e.binOp("OP_RSHIFT")
	e.swap()
	e.pushI(int64(32 - n))
	e.binOp("OP_LSHIFT")
	e.binOp("OP_OR")
}

// shrBE: SHR(x, n) on BE 4-byte value. [x_BE] → [shifted_BE]. Net: 0. 2 ops.
func (e *sha256Emitter) shrBE(n int) {
	e.pushI(int64(n))
	e.binOp("OP_RSHIFT")
}

// --- SHA-256 sigma functions ---

// bigSigma0: Σ0(a) = ROTR(2)^ROTR(13)^ROTR(22). [a(LE)] → [Σ0(LE)]. Net: 0.
func (e *sha256Emitter) bigSigma0() {
	e.reverseBytes4() // LE → BE
	e.dup()
	e.dup()
	e.rotrBE(2)
	e.swap()
	e.rotrBE(13)
	e.binOp("OP_XOR")
	e.swap()
	e.rotrBE(22)
	e.binOp("OP_XOR")
	e.reverseBytes4() // BE → LE
}

// bigSigma1: Σ1(e) = ROTR(6)^ROTR(11)^ROTR(25). [e(LE)] → [Σ1(LE)]. Net: 0.
func (e *sha256Emitter) bigSigma1() {
	e.reverseBytes4()
	e.dup()
	e.dup()
	e.rotrBE(6)
	e.swap()
	e.rotrBE(11)
	e.binOp("OP_XOR")
	e.swap()
	e.rotrBE(25)
	e.binOp("OP_XOR")
	e.reverseBytes4()
}

// smallSigma0: σ0(x) = ROTR(7)^ROTR(18)^SHR(3). [x(LE)] → [σ0(LE)]. Net: 0.
func (e *sha256Emitter) smallSigma0() {
	e.reverseBytes4()
	e.dup()
	e.dup()
	e.rotrBE(7)
	e.swap()
	e.rotrBE(18)
	e.binOp("OP_XOR")
	e.swap()
	e.shrBE(3)
	e.binOp("OP_XOR")
	e.reverseBytes4()
}

// smallSigma1: σ1(x) = ROTR(17)^ROTR(19)^SHR(10). [x(LE)] → [σ1(LE)]. Net: 0.
func (e *sha256Emitter) smallSigma1() {
	e.reverseBytes4()
	e.dup()
	e.dup()
	e.rotrBE(17)
	e.swap()
	e.rotrBE(19)
	e.binOp("OP_XOR")
	e.swap()
	e.shrBE(10)
	e.binOp("OP_XOR")
	e.reverseBytes4()
}

// ch: Ch(e,f,g) = (e&f)^(~e&g). [e, f, g] (g=TOS), all LE → [Ch(LE)]. Net: -2.
func (e *sha256Emitter) ch() {
	e.rot()
	e.dup()
	e.uniOp("OP_INVERT")
	e.rot()
	e.binOp("OP_AND")
	e.toAlt()
	e.binOp("OP_AND")
	e.fromAlt()
	e.binOp("OP_XOR")
}

// maj: Maj(a,b,c) = (a&b)|(c&(a^b)). [a, b, c] (c=TOS), all LE → [Maj(LE)]. Net: -2.
func (e *sha256Emitter) maj() {
	e.toAlt()
	e.dup2()
	e.binOp("OP_AND")
	e.toAlt()
	e.binOp("OP_XOR")
	e.fromAlt()
	e.swap()
	e.fromAlt()
	e.binOp("OP_AND")
	e.binOp("OP_OR")
}

// beWordsToLE converts N BE words on TOS to LE, preserving stack order.
func (e *sha256Emitter) beWordsToLE(n int) {
	for i := 0; i < n; i++ {
		e.reverseBytes4()
		e.toAlt()
	}
	for i := 0; i < n; i++ {
		e.fromAlt()
	}
}

// beWordsToLEReversed8 converts 8 BE words on TOS to LE AND reverses order.
func (e *sha256Emitter) beWordsToLEReversed8() {
	for i := 7; i >= 0; i-- {
		e.roll(i)
		e.reverseBytes4()
		e.toAlt()
	}
	for i := 0; i < 8; i++ {
		e.fromAlt()
	}
}

// =========================================================================
// Reusable compress ops generator
// =========================================================================

// generateCompressOps generates SHA-256 compression ops.
// Assumes top of stack is [..., state(32 BE), block(64 BE)].
// After: [..., newState(32 BE)]. Net depth: -1.
func generateCompressOps() []StackOp {
	em := newSha256Emitter(2)

	// Phase 1: Save init state to alt, unpack block into 16 LE words
	em.swap()
	em.dup()
	em.toAlt()
	em.toAlt()
	em.assertDepth(1, "compress: after state save")

	for i := 0; i < 15; i++ {
		em.split4()
	}
	em.assertDepth(16, "compress: after block unpack")
	em.beWordsToLE(16)
	em.assertDepth(16, "compress: after block LE convert")

	// Phase 2: W expansion
	for t := 16; t < 64; t++ {
		em.over()
		em.smallSigma1()
		em.pick(6 + 1)
		em.pick(14 + 2)
		em.smallSigma0()
		em.pick(15 + 3)
		em.addN(4)
	}
	em.assertDepth(64, "compress: after W expansion")

	// Phase 3: Unpack state into 8 LE working vars
	em.fromAlt()
	for i := 0; i < 7; i++ {
		em.split4()
	}
	em.assertDepth(72, "compress: after state unpack")
	em.beWordsToLEReversed8()
	em.assertDepth(72, "compress: after state LE convert")

	// Phase 4: 64 compression rounds
	for t := 0; t < 64; t++ {
		d0 := em.depth
		emitRound(em, t)
		em.assertDepth(d0, "compress: after round "+itoa(t))
	}

	// Phase 5: Add initial state, pack result
	em.fromAlt()
	em.assertDepth(73, "compress: before final add")

	for i := 0; i < 7; i++ {
		em.split4()
	}
	em.beWordsToLEReversed8()
	em.assertDepth(80, "compress: after init unpack")

	for i := 0; i < 8; i++ {
		em.roll(8 - i)
		em.add32()
		em.toAlt()
	}
	em.assertDepth(64, "compress: after final add")

	em.fromAlt()
	em.reverseBytes4()
	for i := 1; i < 8; i++ {
		em.fromAlt()
		em.reverseBytes4()
		em.swap()
		em.binOp("OP_CAT")
	}
	em.assertDepth(65, "compress: after pack")

	for i := 0; i < 64; i++ {
		em.swap()
		em.drop()
	}
	em.assertDepth(1, "compress: final")

	return em.ops
}

// Cache the ops since they're identical every time
var sha256CompressOpsCache []StackOp

func getCompressOps() []StackOp {
	if sha256CompressOpsCache == nil {
		sha256CompressOpsCache = generateCompressOps()
	}
	return sha256CompressOpsCache
}

// =========================================================================
// Public entry points
// =========================================================================

// EmitSha256Compress emits SHA-256 compression in Bitcoin Script.
// Stack on entry: [..., state(32 BE), block(64 BE)]
// Stack on exit:  [..., newState(32 BE)]
func EmitSha256Compress(emit func(StackOp)) {
	for _, op := range getCompressOps() {
		emit(op)
	}
}

// EmitSha256Finalize emits SHA-256 finalization in Bitcoin Script.
// Stack on entry: [..., state(32 BE), remaining(var len BE), msgBitLen(bigint)]
// Stack on exit:  [..., hash(32 BE)]
//
// Applies SHA-256 padding to remaining, then compresses 1 or 2 blocks.
// Uses OP_IF branching: script contains sha256Compress code twice (~46KB total).
func EmitSha256Finalize(emit func(StackOp)) {
	em := newSha256Emitter(3) // state + remaining + msgBitLen

	// ---- Step 1: Convert msgBitLen to 8-byte BE ----
	// [state, remaining, msgBitLen]
	em.pushI(9)
	em.binOp("OP_NUM2BIN") // 9-byte LE
	em.pushI(8)
	em.split() // [8-byte LE, sign byte]
	em.drop()  // [8-byte LE]
	// Reverse 8 bytes to BE: split(4), reverse each half, cat
	em.pushI(4)
	em.split()         // [lo4_LE, hi4_LE]
	em.reverseBytes4() // [lo4_LE, hi4_rev]
	em.swap()
	em.reverseBytes4() // [hi4_rev, lo4_rev]
	em.binOp("OP_CAT") // [bitLenBE(8)]
	em.toAlt()         // save bitLenBE to alt
	em.assertDepth(2, "finalize: after bitLen conversion")

	// ---- Step 2: Pad remaining ----
	// [state, remaining]
	em.pushB([]byte{0x80})
	em.binOp("OP_CAT") // [state, remaining||0x80]

	// Get padded length
	em.oc("OP_SIZE")
	em.depth++ // [state, padded, paddedLen]

	// Branch: 1 block (paddedLen <= 56) or 2 blocks (paddedLen > 56)
	em.dup()
	em.pushI(57)
	em.binOp("OP_LESSTHAN") // paddedLen < 57?
	// [state, padded, paddedLen, flag]

	em.oc("OP_IF")
	em.depth-- // consume flag
	// ---- 1-block path: pad to 56 bytes ----
	em.pushI(56)
	em.swap()
	em.binOp("OP_SUB") // zeroCount = 56 - paddedLen
	em.pushI(0)
	em.swap()
	em.binOp("OP_NUM2BIN") // zero bytes
	em.binOp("OP_CAT")     // [state, padded(56 bytes)]
	em.fromAlt()           // bitLenBE from alt
	em.binOp("OP_CAT")     // [state, block1(64 bytes)]
	// Splice sha256Compress ops (consumes state+block, produces result)
	compressOps := getCompressOps()
	for _, op := range compressOps {
		em.emitRaw(op)
	}
	em.depth = 1 // after compress: 1 result

	em.oc("OP_ELSE")
	em.depth = 3 // reset to branch entry: [state, padded, paddedLen]

	// ---- 2-block path: pad to 120 bytes ----
	em.pushI(120)
	em.swap()
	em.binOp("OP_SUB") // zeroCount = 120 - paddedLen
	em.pushI(0)
	em.swap()
	em.binOp("OP_NUM2BIN") // zero bytes
	em.binOp("OP_CAT")     // [state, padded(120 bytes)]
	em.fromAlt()           // bitLenBE from alt
	em.binOp("OP_CAT")     // [state, fullPadded(128 bytes)]

	// Split into 2 blocks
	em.pushI(64)
	em.split() // [state, block1(64), block2(64)]
	em.toAlt() // save block2

	// First compress: [state, block1]
	for _, op := range compressOps {
		em.emitRaw(op)
	}
	em.depth = 1 // after first compress: [midState]

	// Second compress: [midState, block2]
	em.fromAlt() // [midState, block2]
	for _, op := range compressOps {
		em.emitRaw(op)
	}
	em.depth = 1 // after second compress: [result]

	em.oc("OP_ENDIF")
	// Both paths leave 1 item (result) on stack
	em.assertDepth(1, "finalize: final")

	for _, op := range em.ops {
		emit(op)
	}
}

// emitRound emits one compression round.
// Stack: [W0..W63, a,b,c,d,e,f,g,h] (a=TOS, all LE). Net: 0.
func emitRound(em *sha256Emitter, t int) {
	// Depths: a(0) b(1) c(2) d(3) e(4) f(5) g(6) h(7). W[t] at 71-t.

	// --- T1 = Σ1(e) + Ch(e,f,g) + h + K[t] + W[t] ---
	em.pick(4)     // e copy (+1)
	em.bigSigma1() // Σ1(e) (0)

	em.pick(5)
	em.pick(7)
	em.pick(9) // e, f, g copies (+3)
	em.ch()    // Ch(e,f,g) (-2) → net +2

	em.pick(9)                    // h copy (+1) → net +3
	em.pushB(u32ToLE(sha256K[t])) // K[t] as LE (+1) → net +4
	em.pick(75 - t)               // W[t] copy (+1) → net +5

	em.addN(5) // T1 = sum of 5 (-4) → net +1

	// --- T2 = Σ0(a) + Maj(a,b,c) ---
	em.dup()
	em.toAlt() // save T1 copy to alt

	em.pick(1)     // a copy (+1) → net +2
	em.bigSigma0() // Σ0(a) (0)

	em.pick(2)
	em.pick(4)
	em.pick(6) // a, b, c copies (+3) → net +5
	em.maj()   // Maj(a,b,c) (-2) → net +3
	em.add32() // T2 = Σ0 + Maj (-1) → net +2

	// --- Register update ---
	em.fromAlt() // T1 copy from alt (+1) → net +3

	em.swap()
	em.add32() // new_a = T1 + T2 (-1) → net +2

	em.swap()
	em.roll(5) // d to top
	em.add32() // new_e = d + T1 (-1) → net +1

	em.roll(8)
	em.drop() // drop h (-1) → net 0

	// Rotate: [ne,na,a,b,c,e,f,g] → [na,a,b,c,ne,e,f,g]
	em.swap()
	em.roll(4)
	em.roll(4)
	em.roll(4)
	em.roll(3)
}
