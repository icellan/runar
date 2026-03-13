// Package codegen BLAKE3 compression codegen for Bitcoin Script.
//
// EmitBlake3Compress: [chainingValue(32 BE), block(64 BE)] → [hash(32 BE)]
// EmitBlake3Hash:     [message(≤64 BE)]                    → [hash(32 BE)]
//
// Architecture (same as sha256.go):
//   - All 32-bit words stored as 4-byte little-endian during computation.
//   - LE additions via BIN2NUM/NUM2BIN (13 ops per add32).
//   - Byte-aligned rotations (16, 8) via SPLIT/SWAP/CAT on LE (4 ops).
//   - Non-byte-aligned rotations (12, 7) via LE→BE→rotrBE→BE→LE (31 ops).
//   - BE↔LE conversion only at input unpack and output pack.
//
// Stack layout during rounds:
//
//	[m0..m15, v0..v15]  (all LE 4-byte values)
//	v15 at TOS (depth 0), v0 at depth 15, m15 at depth 16, m0 at depth 31.
package codegen

import "math/big"

// =========================================================================
// BLAKE3 constants
// =========================================================================

var blake3IV = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

var msgPermutation = [16]int{
	2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
}

const (
	blake3ChunkStart = 1
	blake3ChunkEnd   = 2
	blake3Root       = 8
)

// u32ToBE encodes a uint32 as 4-byte big-endian (precomputed at codegen time).
func u32ToBE(n uint32) []byte {
	return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// =========================================================================
// Precompute message schedule for all 7 rounds
// =========================================================================

// computeMsgSchedule returns msgSchedule[round][position] = original msg word index.
// This eliminates runtime message permutation — we just pick from the right depth at codegen time.
func computeMsgSchedule() [7][16]int {
	var schedule [7][16]int
	var current [16]int
	for i := 0; i < 16; i++ {
		current[i] = i
	}
	for round := 0; round < 7; round++ {
		schedule[round] = current
		var next [16]int
		for i := 0; i < 16; i++ {
			next[i] = current[msgPermutation[i]]
		}
		current = next
	}
	return schedule
}

var msgSchedule = computeMsgSchedule()

// =========================================================================
// blake3Emitter with depth tracking
// =========================================================================

type blake3Emitter struct {
	ops      []StackOp
	depth    int
	altDepth int
}

func newBlake3Emitter(initialDepth int) *blake3Emitter {
	return &blake3Emitter{depth: initialDepth}
}

func (em *blake3Emitter) emit(sop StackOp)    { em.ops = append(em.ops, sop) }
func (em *blake3Emitter) emitRaw(sop StackOp) { em.ops = append(em.ops, sop) }

func (em *blake3Emitter) oc(code string) { em.emit(StackOp{Op: "opcode", Code: code}) }

func (em *blake3Emitter) pushI(v int64) {
	em.emit(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(v)}})
	em.depth++
}

func (em *blake3Emitter) pushB(v []byte) {
	em.emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: v}})
	em.depth++
}

func (em *blake3Emitter) dup()  { em.emit(StackOp{Op: "dup"}); em.depth++ }
func (em *blake3Emitter) drop() { em.emit(StackOp{Op: "drop"}); em.depth-- }
func (em *blake3Emitter) swap() { em.emit(StackOp{Op: "swap"}) }
func (em *blake3Emitter) over() { em.emit(StackOp{Op: "over"}); em.depth++ }
func (em *blake3Emitter) nip()  { em.emit(StackOp{Op: "nip"}); em.depth-- }
func (em *blake3Emitter) rot()  { em.emit(StackOp{Op: "rot"}) }

func (em *blake3Emitter) pick(d int) {
	if d == 0 {
		em.dup()
		return
	}
	if d == 1 {
		em.over()
		return
	}
	em.pushI(int64(d))
	em.emit(StackOp{Op: "pick", Depth: d})
}

func (em *blake3Emitter) roll(d int) {
	if d == 0 {
		return
	}
	if d == 1 {
		em.swap()
		return
	}
	if d == 2 {
		em.rot()
		return
	}
	em.pushI(int64(d))
	em.emit(StackOp{Op: "roll", Depth: d})
	em.depth--
}

func (em *blake3Emitter) toAlt()   { em.oc("OP_TOALTSTACK"); em.depth--; em.altDepth++ }
func (em *blake3Emitter) fromAlt() { em.oc("OP_FROMALTSTACK"); em.depth++; em.altDepth-- }

func (em *blake3Emitter) binOp(code string) { em.oc(code); em.depth-- }
func (em *blake3Emitter) uniOp(code string) { em.oc(code) }

func (em *blake3Emitter) split()  { em.oc("OP_SPLIT") }
func (em *blake3Emitter) split4() { em.pushI(4); em.split() }

func (em *blake3Emitter) assertDepth(expected int, msg string) {
	if em.depth != expected {
		panic("BLAKE3 codegen: " + msg + ". Expected depth " + itoa(expected) + ", got " + itoa(em.depth))
	}
}

// --- Byte reversal (only for BE↔LE conversion at boundaries) ---

// reverseBytes4 reverses 4 bytes on TOS: [abcd] → [dcba]. Net: 0. 12 ops.
func (em *blake3Emitter) reverseBytes4() {
	em.pushI(1)
	em.split()
	em.pushI(1)
	em.split()
	em.pushI(1)
	em.split()
	em.swap()
	em.binOp("OP_CAT")
	em.swap()
	em.binOp("OP_CAT")
	em.swap()
	em.binOp("OP_CAT")
}

// --- LE ↔ Numeric conversions ---

// le2num converts 4-byte LE to unsigned script number. [le4] → [num]. Net: 0. 3 ops.
func (em *blake3Emitter) le2num() {
	em.pushB([]byte{0x00}) // unsigned padding
	em.binOp("OP_CAT")
	em.uniOp("OP_BIN2NUM")
}

// num2le converts script number to 4-byte LE (truncates to 32 bits). [num] → [le4]. Net: 0. 5 ops.
func (em *blake3Emitter) num2le() {
	em.pushI(5)
	em.binOp("OP_NUM2BIN") // 5-byte LE
	em.pushI(4)
	em.split() // [4-byte LE, overflow+sign]
	em.drop()  // discard overflow byte
}

// --- LE arithmetic ---

// add32: [a(LE), b(LE)] → [(a+b mod 2^32)(LE)]. Net: -1. 13 ops.
func (em *blake3Emitter) add32() {
	em.le2num()
	em.swap()
	em.le2num()
	em.binOp("OP_ADD")
	em.num2le()
}

// addN adds N LE values. [v0..vN-1] (vN-1=TOS) → [sum(LE)]. Net: -(N-1).
func (em *blake3Emitter) addN(n int) {
	if n < 2 {
		return
	}
	em.le2num()
	for i := 1; i < n; i++ {
		em.swap()
		em.le2num()
		em.binOp("OP_ADD")
	}
	em.num2le()
}

// --- ROTR/SHR using OP_LSHIFT/OP_RSHIFT ---

// rotrBE: ROTR(x, n) on BE 4-byte value. [x_BE] → [rotated_BE]. Net: 0. 7 ops.
func (em *blake3Emitter) rotrBE(n int) {
	em.dup()
	em.pushI(int64(n))
	em.binOp("OP_RSHIFT")
	em.swap()
	em.pushI(int64(32 - n))
	em.binOp("OP_LSHIFT")
	em.binOp("OP_OR")
}

// --- ROTR on LE values ---

// rotr16LE: ROTR(x, 16) on LE 4-byte value. Net: 0. 4 ops.
// Swaps the two 16-bit halves: [b0,b1,b2,b3] → [b2,b3,b0,b1].
func (em *blake3Emitter) rotr16LE() {
	em.pushI(2)
	em.split()        // [lo2, hi2]
	em.swap()         // [hi2, lo2]
	em.binOp("OP_CAT") // [hi2||lo2]
}

// rotr8LE: ROTR(x, 8) on LE 4-byte value. Net: 0. 4 ops.
// [b0,b1,b2,b3] → [b1,b2,b3,b0]
func (em *blake3Emitter) rotr8LE() {
	em.pushI(1)
	em.split()        // [b0, b1b2b3]
	em.swap()         // [b1b2b3, b0]
	em.binOp("OP_CAT") // [b1b2b3||b0]
}

// rotrLEGeneral: ROTR(x, n) on LE 4-byte value (non-byte-aligned). Net: 0. 31 ops.
// Converts LE→BE, applies rotrBE, converts back.
func (em *blake3Emitter) rotrLEGeneral(n int) {
	em.reverseBytes4() // LE → BE
	em.rotrBE(n)       // rotate on BE
	em.reverseBytes4() // BE → LE
}

// beWordsToLE converts N BE words on TOS to LE, preserving stack order.
func (em *blake3Emitter) beWordsToLE(n int) {
	for i := 0; i < n; i++ {
		em.reverseBytes4()
		em.toAlt()
	}
	for i := 0; i < n; i++ {
		em.fromAlt()
	}
}

// =========================================================================
// State word position tracker
// =========================================================================

// stateTracker tracks the stack depth of each of the 16 state words.
// Depth 0 = TOS. Message words sit below the state area at fixed positions.
type stateTracker struct {
	// positions[i] = current depth of state word v[i] from TOS
	positions [16]int
}

func newStateTracker() *stateTracker {
	t := &stateTracker{}
	// Initial: v0 at depth 15 (deepest state word), v15 at depth 0 (TOS)
	for i := 0; i < 16; i++ {
		t.positions[i] = 15 - i
	}
	return t
}

func (t *stateTracker) depth(wordIdx int) int {
	return t.positions[wordIdx]
}

// onRollToTop updates tracker after rolling a state word from its current depth to TOS.
func (t *stateTracker) onRollToTop(wordIdx int) {
	d := t.positions[wordIdx]
	for j := 0; j < 16; j++ {
		if j != wordIdx && t.positions[j] >= 0 && t.positions[j] < d {
			t.positions[j]++
		}
	}
	t.positions[wordIdx] = 0
}

// =========================================================================
// G function (quarter-round)
// =========================================================================

// emitHalfG emits one half of the G function.
// Stack entry: [a, b, c, d, m] (m on TOS) — 5 items
// Stack exit:  [a', b', c', d'] (d' on TOS) — 4 items
// Net depth: -1
//
// Operations:
//
//	a' = a + b + m
//	d' = (d ^ a') >>> rotD
//	c' = c + d'
//	b' = (original_b ^ c') >>> rotB
func emitHalfG(em *blake3Emitter, rotD int, rotB int) {
	d0 := em.depth

	// Save original b for step 4 (b is at depth 3)
	em.pick(3)
	em.toAlt()

	// Step 1: a' = a + b + m
	// Stack: [a, b, c, d, m] — a=4, b=3, c=2, d=1, m=0
	em.roll(3)  // [a, c, d, m, b]
	em.roll(4)  // [c, d, m, b, a]
	em.addN(3)  // [c, d, a']
	em.assertDepth(d0-2, "halfG step1")

	// Step 2: d' = (d ^ a') >>> rotD
	// Stack: [c, d, a'] — c=2, d=1, a'=0
	em.dup()           // [c, d, a', a']
	em.rot()           // [c, a', a', d]
	em.binOp("OP_XOR") // [c, a', (d^a')]
	if rotD == 16 {
		em.rotr16LE()
	} else if rotD == 8 {
		em.rotr8LE()
	} else {
		em.rotrLEGeneral(rotD)
	}
	em.assertDepth(d0-2, "halfG step2")

	// Step 3: c' = c + d'
	// Stack: [c, a', d']
	em.dup()   // [c, a', d', d']
	em.roll(3) // [a', d', d', c]
	em.add32() // [a', d', c']
	em.assertDepth(d0-2, "halfG step3")

	// Step 4: b' = (original_b ^ c') >>> rotB
	// Stack: [a', d', c']
	em.fromAlt()       // [a', d', c', b]
	em.over()          // [a', d', c', b, c']
	em.binOp("OP_XOR") // [a', d', c', (b^c')]
	em.rotrLEGeneral(rotB)
	// Stack: [a', d', c', b']
	em.assertDepth(d0-1, "halfG step4")

	// Rearrange: [a', d', c', b'] → [a', b', c', d']
	em.swap() // [a', d', b', c']
	em.rot()  // [a', b', c', d']
	em.assertDepth(d0-1, "halfG done")
}

// emitG emits the full G function (quarter-round).
// Stack entry: [a, b, c, d, mx, my] (my on TOS) — 6 items
// Stack exit:  [a', b', c', d'] (d' on TOS) — 4 items
// Net depth: -2
func emitG(em *blake3Emitter) {
	d0 := em.depth

	// Save my to alt for phase 2
	em.toAlt() // [a, b, c, d, mx]

	// Phase 1: first half with mx, ROTR(16) and ROTR(12)
	emitHalfG(em, 16, 12)
	em.assertDepth(d0-2, "G phase1")

	// Restore my for phase 2
	em.fromAlt() // [a', b', c', d', my]
	em.assertDepth(d0-1, "G before phase2")

	// Phase 2: second half with my, ROTR(8) and ROTR(7)
	emitHalfG(em, 8, 7)
	em.assertDepth(d0-2, "G done")
}

// =========================================================================
// G call with state management
// =========================================================================

// emitGCall emits a single G call with state word roll management.
// Rolls 4 state words (ai, bi, ci, di) to top, picks 2 message words,
// runs G, then updates tracker.
func emitGCall(
	em *blake3Emitter,
	tracker *stateTracker,
	ai, bi, ci, di int,
	mxOrigIdx, myOrigIdx int,
) {
	d0 := em.depth

	// Roll 4 state words to top: a, b, c, d (d ends up as TOS)
	for _, idx := range []int{ai, bi, ci, di} {
		em.roll(tracker.depth(idx))
		tracker.onRollToTop(idx)
	}

	// Pick message words from below the 16 state word area
	// m[i] is at depth: 16 (state words) + (15 - i)
	em.pick(16 + (15 - mxOrigIdx))
	em.pick(16 + (15 - myOrigIdx) + 1) // +1 for mx just pushed
	em.assertDepth(d0+2, "before G")

	// Run G: consumes 6 (a, b, c, d, mx, my), produces 4 (a', b', c', d')
	emitG(em)
	em.assertDepth(d0, "after G")

	// Update tracker: result words at depths 0-3
	tracker.positions[ai] = 3
	tracker.positions[bi] = 2
	tracker.positions[ci] = 1
	tracker.positions[di] = 0
}

// =========================================================================
// Full compression ops generator
// =========================================================================

// generateBlake3CompressOps generates BLAKE3 compression ops.
// Stack entry: [..., chainingValue(32 BE), block(64 BE)] — 2 items
// Stack exit:  [..., hash(32 BE)] — 1 item
// Net depth: -1
func generateBlake3CompressOps() []StackOp {
	em := newBlake3Emitter(2)

	// ================================================================
	// Phase 1: Unpack block into 16 LE message words
	// ================================================================
	// Stack: [chainingValue(32 BE), block(64 BE)]
	// Split block into 16 × 4-byte BE words, convert to LE
	for i := 0; i < 15; i++ {
		em.split4()
	}
	em.assertDepth(17, "after block unpack") // 16 block words + 1 chainingValue
	em.beWordsToLE(16)
	em.assertDepth(17, "after block LE convert")
	// Stack: [CV, m0(LE), m1(LE), ..., m15(LE)] — m0 deepest of msg words, m15 TOS

	// ================================================================
	// Phase 2: Initialize 16-word state on top of message words
	// ================================================================
	// Move CV to alt (it's below the 16 msg words, at depth 16)
	em.roll(16)
	em.toAlt()
	em.assertDepth(16, "after CV to alt")
	// Stack: [m0, m1, ..., m15]  Alt: [CV]

	// Get CV back, split into 8 LE words, place on top of msg
	em.fromAlt()
	em.assertDepth(17, "after CV from alt")
	for i := 0; i < 7; i++ {
		em.split4()
	}
	em.assertDepth(24, "after cv unpack")
	em.beWordsToLE(8)
	em.assertDepth(24, "after cv LE convert")
	// Stack: [m0..m15, cv0(LE)..cv7(LE)]

	// v[0..7] = chaining value (already on stack)
	// v[8..11] = IV[0..3]
	for i := 0; i < 4; i++ {
		em.pushB(u32ToLE(blake3IV[i]))
	}
	em.assertDepth(28, "after IV push")

	// v[12] = counter_low = 0, v[13] = counter_high = 0
	em.pushB(u32ToLE(0))
	em.pushB(u32ToLE(0))
	// v[14] = block_len = 64
	em.pushB(u32ToLE(64))
	// v[15] = flags = CHUNK_START | CHUNK_END | ROOT = 11
	em.pushB(u32ToLE(blake3ChunkStart | blake3ChunkEnd | blake3Root))
	em.assertDepth(32, "after state init")

	// Stack: [m0..m15(bottom), v0..v15(top)] — v15=TOS, m0=deepest

	// ================================================================
	// Phase 3: 7 rounds of G function calls
	// ================================================================
	tracker := newStateTracker()

	for round := 0; round < 7; round++ {
		s := msgSchedule[round]

		// Column mixing
		emitGCall(em, tracker, 0, 4, 8, 12, s[0], s[1])
		emitGCall(em, tracker, 1, 5, 9, 13, s[2], s[3])
		emitGCall(em, tracker, 2, 6, 10, 14, s[4], s[5])
		emitGCall(em, tracker, 3, 7, 11, 15, s[6], s[7])

		// Diagonal mixing
		emitGCall(em, tracker, 0, 5, 10, 15, s[8], s[9])
		emitGCall(em, tracker, 1, 6, 11, 12, s[10], s[11])
		emitGCall(em, tracker, 2, 7, 8, 13, s[12], s[13])
		emitGCall(em, tracker, 3, 4, 9, 14, s[14], s[15])
	}

	em.assertDepth(32, "after all rounds")

	// ================================================================
	// Phase 4: Output — hash[i] = state[i] XOR state[i+8], for i=0..7
	// ================================================================

	// Reorder state words to canonical positions using alt stack
	for i := 15; i >= 0; i-- {
		d := tracker.depth(i)
		em.roll(d)
		tracker.onRollToTop(i)
		em.toAlt()
		// Remaining words shift up because one was removed from main
		for j := 0; j < 16; j++ {
			if j != i && tracker.positions[j] >= 0 {
				tracker.positions[j]--
			}
		}
		tracker.positions[i] = -1
	}

	// Pop to get canonical order: [v0(bottom)..v15(TOS)]
	for i := 0; i < 16; i++ {
		em.fromAlt()
	}
	em.assertDepth(32, "after canonical reorder")

	// State: [m0..m15, v0(bottom)..v15(TOS)], canonical order.
	// XOR pairs: h[7-k] = v[7-k] ^ v[15-k] for k=0..7
	// Process top-down: v15^v7, v14^v6, ..., v8^v0. Send each result to alt.
	for k := 0; k < 8; k++ {
		em.roll(8 - k)      // bring v[7-k] to TOS (past v[15-k] and remaining)
		em.binOp("OP_XOR")  // h[7-k] = v[7-k] ^ v[15-k]
		em.toAlt()          // result to alt; main shrinks by 2
	}
	em.assertDepth(16, "after XOR pairs")
	// Alt (bottom→top): h7, h6, h5, h4, h3, h2, h1, h0. Main: [m0..m15].

	// Pop results to main: h0 first (LIFO), then h1, ..., h7
	for i := 0; i < 8; i++ {
		em.fromAlt()
	}
	em.assertDepth(24, "after XOR results restored")
	// Main: [m0..m15, h0, h1, ..., h7] h7=TOS

	// Pack into 32-byte BE result: h0_BE || h1_BE || ... || h7_BE
	em.reverseBytes4() // h7 → h7_BE
	for i := 1; i < 8; i++ {
		em.swap()           // bring h[7-i] (LE) to TOS
		em.reverseBytes4()  // → BE
		em.swap()           // [new_BE, accumulated]
		em.binOp("OP_CAT")  // new_BE || accumulated
	}
	em.assertDepth(17, "after hash pack")

	// Drop 16 message words
	for i := 0; i < 16; i++ {
		em.swap()
		em.drop()
	}
	em.assertDepth(1, "compress final")

	return em.ops
}

// Cache the ops since they're identical every time
var blake3CompressOpsCache []StackOp

func getBlake3CompressOps() []StackOp {
	if blake3CompressOpsCache == nil {
		blake3CompressOpsCache = generateBlake3CompressOps()
	}
	return blake3CompressOpsCache
}

// =========================================================================
// Public entry points
// =========================================================================

// EmitBlake3Compress emits BLAKE3 single-block compression in Bitcoin Script.
// Stack on entry: [..., chainingValue(32 BE), block(64 BE)]
// Stack on exit:  [..., hash(32 BE)]
// Net depth: -1
func EmitBlake3Compress(emit func(StackOp)) {
	for _, op := range getBlake3CompressOps() {
		emit(op)
	}
}

// EmitBlake3Hash emits BLAKE3 hash for a message up to 64 bytes.
// Stack on entry: [..., message(≤64 BE)]
// Stack on exit:  [..., hash(32 BE)]
// Net depth: 0
//
// Applies zero-padding and uses IV as chaining value.
func EmitBlake3Hash(emit func(StackOp)) {
	em := newBlake3Emitter(1)

	// Pad message to 64 bytes (BLAKE3 zero-pads, no length suffix)
	em.oc("OP_SIZE")
	em.depth++ // [message, len]
	em.pushI(64)
	em.swap()
	em.binOp("OP_SUB")     // [message, 64-len]
	em.pushI(0)
	em.swap()
	em.binOp("OP_NUM2BIN") // [message, zeros]
	em.binOp("OP_CAT")     // [paddedMessage(64)]

	// Push IV as 32-byte BE chaining value
	ivBytes := make([]byte, 32)
	for i := 0; i < 8; i++ {
		be := u32ToBE(blake3IV[i])
		ivBytes[i*4+0] = be[0]
		ivBytes[i*4+1] = be[1]
		ivBytes[i*4+2] = be[2]
		ivBytes[i*4+3] = be[3]
	}
	em.pushB(ivBytes)
	em.swap() // [IV(32 BE), paddedMessage(64 BE)]

	// Splice compression ops
	compressOps := getBlake3CompressOps()
	for _, op := range compressOps {
		em.emitRaw(op)
	}
	em.depth = 1

	em.assertDepth(1, "blake3Hash final")
	for _, op := range em.ops {
		emit(op)
	}
}
