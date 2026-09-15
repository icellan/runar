// EC codegen -- secp256k1 elliptic curve operations for Bitcoin Script.
//
// Follows the slh_dsa.go pattern: self-contained module imported by stack.go.
// Uses an ECTracker (similar to SLHTracker) for named stack state tracking.
//
// Point representation: 64 bytes (x[32] || y[32], big-endian unsigned).
// Internal arithmetic uses Jacobian coordinates for scalar multiplication.
package codegen

import (
	"fmt"
	"math/big"
)

// ===========================================================================
// Constants
// ===========================================================================

// secp256k1 field prime p = 2^256 - 2^32 - 977
var ecFieldP *big.Int

// p - 2, used for Fermat's little theorem modular inverse
var ecFieldPMinus2 *big.Int

// secp256k1 generator x-coordinate
var ecGenX *big.Int

// secp256k1 generator y-coordinate
var ecGenY *big.Int

// secp256k1 domain parameters.
//
// Source: SEC 2: Recommended Elliptic Curve Domain Parameters, Version 2.0,
// section 2.4.1 (Certicom Research, 2010) —
// https://www.secg.org/sec2-v2.pdf
//
// p  = 2^256 - 2^32 - 977, the field prime
// Gx, Gy — the standard generator, uncompressed
//
// R-239: these were bare literals, while the Poseidon2 round constants in this
// same package cite Plonky3 and the SLH-DSA parameters cite FIPS 205. A wrong
// digit here does not fail a vector — it produces an EC implementation that
// agrees with itself, passes every self-consistency check, and is not the curve
// anyone else is on. Checking the digits against the standard is the only
// defence, and that needs the standard named.
func init() {
	ecFieldP, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	ecFieldPMinus2 = new(big.Int).Sub(ecFieldP, big.NewInt(2))
	ecGenX, _ = new(big.Int).SetString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)
	ecGenY, _ = new(big.Int).SetString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)
}

// bigintToBytes32 converts a *big.Int to a 32-byte big-endian byte slice.
func bigintToBytes32(n *big.Int) []byte {
	bytes := make([]byte, 32)
	b := n.Bytes()
	// Right-align into 32-byte slice
	copy(bytes[32-len(b):], b)
	return bytes
}

// ===========================================================================
// ECTracker -- named stack state tracker (mirrors TS ECTracker)
// ===========================================================================

// ECTracker tracks named stack positions and emits StackOps for EC codegen.
type ECTracker struct {
	nm []string // stack names ("" for anonymous)
	e  func(StackOp)
}

// NewECTracker creates a new tracker with initial named stack slots.
func NewECTracker(init []string, emit func(StackOp)) *ECTracker {
	nm := make([]string, len(init))
	copy(nm, init)
	return &ECTracker{nm: nm, e: emit}
}

func (t *ECTracker) findDepth(name string) int {
	for i := len(t.nm) - 1; i >= 0; i-- {
		if t.nm[i] == name {
			return len(t.nm) - 1 - i
		}
	}
	panic(fmt.Sprintf("ECTracker: '%s' not on stack %v", name, t.nm))
}

func (t *ECTracker) pushBytes(n string, v []byte) {
	t.e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: v}})
	t.nm = append(t.nm, n)
}

func (t *ECTracker) pushBigInt(n string, v *big.Int) {
	t.e(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(v)}})
	t.nm = append(t.nm, n)
}

func (t *ECTracker) pushInt(n string, v int64) {
	t.e(StackOp{Op: "push", Value: bigIntPush(v)})
	t.nm = append(t.nm, n)
}

func (t *ECTracker) dup(n string) {
	t.e(StackOp{Op: "dup"})
	t.nm = append(t.nm, n)
}

func (t *ECTracker) drop() {
	t.e(StackOp{Op: "drop"})
	if len(t.nm) > 0 {
		t.nm = t.nm[:len(t.nm)-1]
	}
}

func (t *ECTracker) nip() {
	t.e(StackOp{Op: "nip"})
	L := len(t.nm)
	if L >= 2 {
		t.nm = append(t.nm[:L-2], t.nm[L-1])
	}
}

func (t *ECTracker) over(n string) {
	t.e(StackOp{Op: "over"})
	t.nm = append(t.nm, n)
}

func (t *ECTracker) swap() {
	t.e(StackOp{Op: "swap"})
	L := len(t.nm)
	if L >= 2 {
		t.nm[L-1], t.nm[L-2] = t.nm[L-2], t.nm[L-1]
	}
}

func (t *ECTracker) rot() {
	t.e(StackOp{Op: "rot"})
	L := len(t.nm)
	if L >= 3 {
		r := t.nm[L-3]
		t.nm = append(t.nm[:L-3], t.nm[L-2:]...)
		t.nm = append(t.nm, r)
	}
}

func (t *ECTracker) op(code string) {
	t.e(StackOp{Op: "opcode", Code: code})
}

func (t *ECTracker) roll(d int) {
	if d == 0 {
		return
	}
	if d == 1 {
		t.swap()
		return
	}
	if d == 2 {
		t.rot()
		return
	}
	t.e(StackOp{Op: "push", Value: bigIntPush(int64(d))})
	t.nm = append(t.nm, "")
	t.e(StackOp{Op: "roll", Depth: d})
	t.nm = t.nm[:len(t.nm)-1] // pop the push placeholder
	idx := len(t.nm) - 1 - d
	r := t.nm[idx]
	t.nm = append(t.nm[:idx], t.nm[idx+1:]...)
	t.nm = append(t.nm, r)
}

func (t *ECTracker) pick(d int, n string) {
	if d == 0 {
		t.dup(n)
		return
	}
	if d == 1 {
		t.over(n)
		return
	}
	t.e(StackOp{Op: "push", Value: bigIntPush(int64(d))})
	t.nm = append(t.nm, "")
	t.e(StackOp{Op: "pick", Depth: d})
	t.nm = t.nm[:len(t.nm)-1] // pop the push placeholder
	t.nm = append(t.nm, n)
}

func (t *ECTracker) toTop(name string) {
	t.roll(t.findDepth(name))
}

func (t *ECTracker) copyToTop(name, n string) {
	t.pick(t.findDepth(name), n)
}

func (t *ECTracker) toAlt() {
	t.op("OP_TOALTSTACK")
	if len(t.nm) > 0 {
		t.nm = t.nm[:len(t.nm)-1]
	}
}

func (t *ECTracker) fromAlt(n string) {
	t.op("OP_FROMALTSTACK")
	t.nm = append(t.nm, n)
}

func (t *ECTracker) rename(n string) {
	if len(t.nm) > 0 {
		t.nm[len(t.nm)-1] = n
	}
}

// rawBlock emits raw opcodes; tracker only records net stack effect.
// produce="" means no output pushed.
func (t *ECTracker) rawBlock(consume []string, produce string, fn func(emit func(StackOp))) {
	for i := len(consume) - 1; i >= 0; i-- {
		if len(t.nm) > 0 {
			t.nm = t.nm[:len(t.nm)-1]
		}
	}
	fn(t.e)
	if produce != "" {
		t.nm = append(t.nm, produce)
	}
}

// emitIf emits if/else with tracked stack effect.
// resultName="" means no result pushed.
func (t *ECTracker) emitIf(condName string, thenFn func(func(StackOp)), elseFn func(func(StackOp)), resultName string) {
	t.toTop(condName)
	// condition consumed
	if len(t.nm) > 0 {
		t.nm = t.nm[:len(t.nm)-1]
	}
	var thenOps []StackOp
	var elseOps []StackOp
	thenFn(func(op StackOp) { thenOps = append(thenOps, op) })
	elseFn(func(op StackOp) { elseOps = append(elseOps, op) })
	t.e(StackOp{Op: "if", Then: thenOps, Else: elseOps})
	if resultName != "" {
		t.nm = append(t.nm, resultName)
	}
}

// ===========================================================================
// Field arithmetic helpers
// ===========================================================================

// ecPushFieldP pushes the field prime p onto the stack as a script number.
func ecPushFieldP(t *ECTracker, name string) {
	t.pushBigInt(name, ecFieldP)
}

// ecFieldMod reduces TOS mod p, ensuring non-negative result.
func ecFieldMod(t *ECTracker, aName, resultName string) {
	t.toTop(aName)
	ecPushFieldP(t, "_fmod_p")
	// (a % p + p) % p
	t.rawBlock([]string{aName, "_fmod_p"}, resultName, func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_2DUP"}) // a p a p
		e(StackOp{Op: "opcode", Code: "OP_MOD"})  // a p (a%p)
		e(StackOp{Op: "rot"})                     // p (a%p) a
		e(StackOp{Op: "drop"})                    // p (a%p)
		e(StackOp{Op: "over"})                    // p (a%p) p
		e(StackOp{Op: "opcode", Code: "OP_ADD"})  // p (a%p+p)
		e(StackOp{Op: "swap"})                    // (a%p+p) p
		e(StackOp{Op: "opcode", Code: "OP_MOD"})  // ((a%p+p)%p)
	})
}

// ecFieldAdd computes (a + b) mod p.
func ecFieldAdd(t *ECTracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_fadd_sum", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	ecFieldMod(t, "_fadd_sum", resultName)
}

// ecFieldSub computes (a - b) mod p (non-negative).
func ecFieldSub(t *ECTracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_fsub_diff", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_SUB"})
	})
	ecFieldMod(t, "_fsub_diff", resultName)
}

// ecFieldMul computes (a * b) mod p.
func ecFieldMul(t *ECTracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_fmul_prod", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
	ecFieldMod(t, "_fmul_prod", resultName)
}

// ecFieldMulConst computes (a * c) mod p where c is a small constant.
func ecFieldMulConst(t *ECTracker, aName string, c int64, resultName string) {
	t.toTop(aName)
	t.rawBlock([]string{aName}, "_fmc_prod", func(e func(StackOp)) {
		if c == 2 {
			// Use OP_2MUL (single opcode, no push needed)
			e(StackOp{Op: "opcode", Code: "OP_2MUL"})
		} else {
			e(StackOp{Op: "push", Value: bigIntPush(c)})
			e(StackOp{Op: "opcode", Code: "OP_MUL"})
		}
	})
	ecFieldMod(t, "_fmc_prod", resultName)
}

// ecFieldSqr computes (a * a) mod p.
func ecFieldSqr(t *ECTracker, aName, resultName string) {
	t.copyToTop(aName, "_fsqr_copy")
	ecFieldMul(t, aName, "_fsqr_copy", resultName)
}

// ecFieldInv computes a^(p-2) mod p via square-and-multiply.
// Consumes aName from the tracker.
func ecFieldInv(t *ECTracker, aName, resultName string) {
	// p-2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
	// Bits 255..32: 224 bits, all 1 except bit 32 which is 0
	// Bits 31..0: 0xFFFFFC2D

	// Start: result = a (bit 255 = 1)
	t.copyToTop(aName, "_inv_r")
	// Bits 254 down to 33: all 1's (222 bits). Bit 32 is 0 (handled below).
	for i := 0; i < 222; i++ {
		ecFieldSqr(t, "_inv_r", "_inv_r2")
		t.rename("_inv_r")
		t.copyToTop(aName, "_inv_a")
		ecFieldMul(t, "_inv_r", "_inv_a", "_inv_m")
		t.rename("_inv_r")
	}
	// Bit 32 is 0: square only (no multiply)
	ecFieldSqr(t, "_inv_r", "_inv_r2")
	t.rename("_inv_r")
	// Bits 31 down to 0 of p-2
	lowBits := uint32(ecFieldPMinus2.Uint64() & 0xffffffff)
	for i := 31; i >= 0; i-- {
		ecFieldSqr(t, "_inv_r", "_inv_r2")
		t.rename("_inv_r")
		if (lowBits>>uint(i))&1 == 1 {
			t.copyToTop(aName, "_inv_a")
			ecFieldMul(t, "_inv_r", "_inv_a", "_inv_m")
			t.rename("_inv_r")
		}
	}
	// Clean up original input and rename result
	t.toTop(aName)
	t.drop()
	t.toTop("_inv_r")
	t.rename(resultName)
}

// ===========================================================================
// Point decompose / compose
// ===========================================================================

// ecEmitPointLenVerify -- CL-BUG-095 -- is a length gate for a `Point`
// argument, ABORTING form.
//
// A `Point` is DEFINED as exactly `want` bytes (x || y, big-endian, no
// prefix). Nothing checked that: surplus bytes were silently discarded
// because decomposePoint splits at the coordinate width and the reversal
// helper reverses exactly that many bytes and drops the remainder. Aborting
// is right here because every caller of this form produces a VALUE with no
// error channel to report through (ecAdd, ecMul, ecNegate, ecPointX,
// ecPointY, ecEncodeCompressed) -- there is no correct value to return for a
// blob that is not a point. Predicates use ecEmitPointLengthGate instead,
// because for them "no" is an answer.
func ecEmitPointLenVerify(e func(StackOp), want int) {
	e(StackOp{Op: "opcode", Code: "OP_SIZE"})
	e(StackOp{Op: "push", Value: bigIntPush(int64(want))})
	e(StackOp{Op: "opcode", Code: "OP_NUMEQUALVERIFY"})
}

// ecEmitPointLengthGate -- CL-BUG-095 -- is a length gate for a `Point`
// argument, CLAMPING form: leaves [flag, clamped] on the tracker, where
// clamped is the value forced to exactly want bytes (v || 00*want, split at
// want, tail dropped) and flag is OP_SIZE(v) == want.
//
// Used by the on-curve predicates, whose whole job is to answer "is this an
// acceptable point?" over untrusted bytes -- for a wrong-length blob the
// correct answer is false, not an aborted script. The caller ANDs flag into
// its boolean result, so whatever the clamped bytes happen to compute can
// never make a wrong-length point certify as on-curve. Same shape as
// cEmitLengthGate in p256_p384.go.
func ecEmitPointLengthGate(t *ECTracker, name string, want int, flagName string) {
	t.toTop(name)
	t.rawBlock([]string{name}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_SIZE"})
		e(StackOp{Op: "push", Value: bigIntPush(int64(want))})
		e(StackOp{Op: "opcode", Code: "OP_NUMEQUAL"})
		e(StackOp{Op: "swap"})
		e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: make([]byte, want)}})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "push", Value: bigIntPush(int64(want))})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		e(StackOp{Op: "drop"})
	})
	t.nm = append(t.nm, flagName)
	t.nm = append(t.nm, name)
}

// ecDecomposePoint decomposes a 64-byte Point into (x_num, y_num) on stack.
// Consumes pointName, produces xName and yName.
func ecDecomposePoint(t *ECTracker, pointName, xName, yName string) {
	t.toTop(pointName)
	// OP_SPLIT at 32 produces x_bytes (bottom) and y_bytes (top) -- but only
	// for a value that really is 64 bytes. CL-BUG-095: gate the width first,
	// here, so every consumer that decomposes a Point inherits the check.
	t.rawBlock([]string{pointName}, "", func(e func(StackOp)) {
		ecEmitPointLenVerify(e, 64)
		e(StackOp{Op: "push", Value: bigIntPush(32)})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	})
	// Manually track the two new items
	t.nm = append(t.nm, "_dp_xb")
	t.nm = append(t.nm, "_dp_yb")

	// Convert y_bytes (on top) to num
	// Reverse from BE to LE, append 0x00 sign byte to ensure unsigned, then BIN2NUM
	t.rawBlock([]string{"_dp_yb"}, yName, func(e func(StackOp)) {
		ecEmitReverse32(e)
		e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	})

	// Convert x_bytes to num
	t.toTop("_dp_xb")
	t.rawBlock([]string{"_dp_xb"}, xName, func(e func(StackOp)) {
		ecEmitReverse32(e)
		e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	})

	// Stack: [yName, xName] -- swap to standard order [xName, yName]
	t.swap()
}

// ecComposePoint composes (x_num, y_num) into a 64-byte Point.
// Consumes xName and yName, produces resultName.
func ecComposePoint(t *ECTracker, xName, yName, resultName string) {
	// Convert x to 32-byte big-endian
	// Use NUM2BIN(33) to accommodate the sign byte, then drop the last byte
	t.toTop(xName)
	t.rawBlock([]string{xName}, "_cp_xb", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(33)})
		e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		// Drop the sign byte (last byte) — split at 32, keep left
		e(StackOp{Op: "push", Value: bigIntPush(32)})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		e(StackOp{Op: "drop"})
		ecEmitReverse32(e)
	})

	// Convert y to 32-byte big-endian
	t.toTop(yName)
	t.rawBlock([]string{yName}, "_cp_yb", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(33)})
		e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		e(StackOp{Op: "push", Value: bigIntPush(32)})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		e(StackOp{Op: "drop"})
		ecEmitReverse32(e)
	})

	// Cat: x_be || y_be (x is below y after the two toTop calls)
	t.toTop("_cp_xb")
	t.toTop("_cp_yb")
	t.rawBlock([]string{"_cp_xb", "_cp_yb"}, resultName, func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
	})
}

// ecEmitReverse32 emits inline byte reversal for a 32-byte value on TOS.
func ecEmitReverse32(e func(StackOp)) {
	// Push empty accumulator, swap with data
	e(StackOp{Op: "opcode", Code: "OP_0"})
	e(StackOp{Op: "swap"})
	// 32 iterations: peel first byte, prepend to accumulator
	for i := 0; i < 32; i++ {
		// Stack: [accum, remaining]
		e(StackOp{Op: "push", Value: bigIntPush(1)})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		// Stack: [accum, byte0, rest]
		e(StackOp{Op: "rot"})
		// Stack: [byte0, rest, accum]
		e(StackOp{Op: "rot"})
		// Stack: [rest, accum, byte0]
		e(StackOp{Op: "swap"})
		// Stack: [rest, byte0, accum]
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		// Stack: [rest, byte0||accum]
		e(StackOp{Op: "swap"})
		// Stack: [byte0||accum, rest]
	}
	// Stack: [reversed, empty]
	e(StackOp{Op: "drop"})
}

// ===========================================================================
// Affine point addition (for ecAdd)
// ===========================================================================

// ecAffineAdd performs affine point addition.
// Expects px, py, qx, qy on tracker. Produces rx, ry. Consumes all four inputs.
func ecAffineAdd(t *ECTracker) {
	// The chord slope s = (qy - py) / (qx - px) is undefined when P == Q: the
	// denominator is zero and the correct slope is the TANGENT, 3px^2 / (2py).
	// Without this, ecAdd(P, P) silently produced a wrong point, so every
	// contract that doubled deployed an unspendable script.
	//
	// Both cases are `s = num / den`, so only the NUMERATOR and DENOMINATOR are
	// selected and the single expensive fieldInv still runs exactly once.
	// rx and ry below are already correct for doubling.
	//
	//   cond   = (px == qx) AND (py == qy)     1 when doubling, else 0
	//   num    = cond ? 3*px^2 : (qy - py)
	//   den    = cond ? 2*py   : (qx - px)
	//
	// selected as `b + cond*(a - b)`, which needs no branch and keeps the
	// emitted op sequence identical on both paths.
	//
	// THE THIRD CASE, P == -Q: px == qx but py != qy. Testing px == qx ALONE
	// sends it down the tangent path and returns 2P — an on-curve, entirely
	// plausible, WRONG point. Before the doubling fix the chord path ran there,
	// divided by zero (ecFieldInv is Fermat, inv(0) = 0) and produced an
	// OFF-curve blob, so `assert(ecOnCurve(ecAdd(a, b)))` — the idiom this
	// codegen tells authors to write — happened to reject it. Selecting on px
	// alone would have silently disarmed that.
	//
	// P + (-P) is the point at infinity, which affine x||y cannot represent.
	// This codegen already has a representation for O: the ALL-ZERO blob, which
	// is what `ecMul(P, 0n)` returns and what the ec-mulgen-linear rewrite in
	// frontend/ec-rules.json produces for k1 + k2 ≡ 0 (mod n). So return that,
	// by masking the result with `notinf = NOT(px == qx AND NOT cond)`:
	//
	//   - it agrees with the rewrite, so the same source cannot give two
	//     answers depending on whether the optimizer fired;
	//   - O is not on the curve (0^2 != 0^3 + 7), so the on-curve gate rejects
	//     it and the idiom above works again;
	//   - it adds no failure channel to what is a pure value-producing
	//     expression, the same reason ecEmitScalarReduce reduces instead of
	//     rejecting.
	//
	// The mask is a bare OP_MUL with no reduction: rx, ry are already in
	// [0, p) and notinf is 0 or 1, so the product is canonical either way.
	t.copyToTop("px", "_px_eq")
	t.copyToTop("qx", "_qx_eq")
	t.rawBlock([]string{"_px_eq", "_qx_eq"}, "_xeq", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_NUMEQUAL"})
	})
	t.copyToTop("py", "_py_eq")
	t.copyToTop("qy", "_qy_eq")
	t.rawBlock([]string{"_py_eq", "_qy_eq"}, "_yeq", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_NUMEQUAL"})
	})
	t.copyToTop("_xeq", "_xeq_c")
	t.toTop("_yeq")
	t.rawBlock([]string{"_xeq_c", "_yeq"}, "_cond", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_BOOLAND"})
	})
	// notinf = NOT(xeq - cond): xeq - cond is 1 exactly when px == qx and the
	// points are not equal, i.e. exactly the P == -Q case.
	t.toTop("_xeq")
	t.copyToTop("_cond", "_cond_c")
	t.rawBlock([]string{"_xeq", "_cond_c"}, "_notinf", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_SUB"})
		e(StackOp{Op: "opcode", Code: "OP_NOT"})
	})

	// chord numerator / denominator
	t.copyToTop("qy", "_qy1")
	t.copyToTop("py", "_py1")
	ecFieldSub(t, "_qy1", "_py1", "_num_chord")
	t.copyToTop("qx", "_qx1")
	t.copyToTop("px", "_px1")
	ecFieldSub(t, "_qx1", "_px1", "_den_chord")

	// tangent numerator / denominator: 3*px^2 and 2*py
	t.copyToTop("px", "_px_t")
	ecFieldSqr(t, "_px_t", "_px_sq")
	ecFieldMulConst(t, "_px_sq", 3, "_num_tan")
	t.copyToTop("py", "_py_t")
	ecFieldMulConst(t, "_py_t", 2, "_den_tan")

	// num = num_chord + cond*(num_tan - num_chord)
	t.copyToTop("_num_chord", "_num_chord_c")
	ecFieldSub(t, "_num_tan", "_num_chord_c", "_num_diff")
	t.copyToTop("_cond", "_cond_n")
	ecFieldMul(t, "_num_diff", "_cond_n", "_num_sel")
	ecFieldAdd(t, "_num_chord", "_num_sel", "_s_num")

	// den = den_chord + cond*(den_tan - den_chord)
	t.copyToTop("_den_chord", "_den_chord_c")
	ecFieldSub(t, "_den_tan", "_den_chord_c", "_den_diff")
	t.toTop("_cond")
	t.rename("_cond_d")
	ecFieldMul(t, "_den_diff", "_cond_d", "_den_sel")
	ecFieldAdd(t, "_den_chord", "_den_sel", "_s_den")

	// s = s_num / s_den mod p
	ecFieldInv(t, "_s_den", "_s_den_inv")
	ecFieldMul(t, "_s_num", "_s_den_inv", "_s")

	// rx = s^2 - px - qx mod p
	t.copyToTop("_s", "_s_keep")
	ecFieldSqr(t, "_s", "_s2")
	t.copyToTop("px", "_px2")
	ecFieldSub(t, "_s2", "_px2", "_rx1")
	t.copyToTop("qx", "_qx2")
	ecFieldSub(t, "_rx1", "_qx2", "rx")

	// ry = s * (px - rx) - py mod p
	t.copyToTop("px", "_px3")
	t.copyToTop("rx", "_rx2")
	ecFieldSub(t, "_px3", "_rx2", "_px_rx")
	ecFieldMul(t, "_s_keep", "_px_rx", "_s_px_rx")
	t.copyToTop("py", "_py2")
	ecFieldSub(t, "_s_px_rx", "_py2", "ry")

	// CL-BUG-096: select over the infinity operands and the P == -Q case, and
	// consume px/py/qx/qy in doing so. This subsumes the standalone `notinf`
	// mask that used to live here. See emitAffineInfinitySelect.
	emitAffineInfinitySelect(t)
}

// emitAffineInfinitySelect handles the infinity-operand case of affine
// addition, shared by secp256k1 and the two NIST curves because it is pure
// integer masking and touches no field parameter.
//
// The group law has an identity, and this codegen has a representation for it:
// the ALL-ZERO blob. It is not a theoretical value -- the codegen MANUFACTURES
// it, from ecMul(P, k) whenever k = 0 (mod n), from affineAdd's own P + (-P)
// masking, and from the ec-mul-zero / ec-add-negate-cancel rewrites in
// optimizer/ec-rules.json. affineAdd nonetheless had no case for it: fed
// (G, O) it took the chord path with s = Gy/Gx and returned an off-curve blob
// from a script that SUCCEEDED.
//
// And the always-on EC optimizer already believed the right answer:
// ec-add-identity-right / -left rewrite ecAdd($x, INFINITY) to $x. So the
// same source meant "P" with the optimizer on and "garbage" with it off.
// Fixing the adder rather than deleting the two rules is the only option that
// works, because the rules cannot see a zero scalar that only exists at
// runtime -- deleting them would leave the runtime path just as wrong and
// rewrite nothing.
//
// Branch-free, in the style the rest of this adder uses. Exactly one of the
// three masks is 1 and the other two are 0, so the sum selects one term:
//
//	pinf = (px == 0) AND (py == 0)          P is O
//	qinf = (qx == 0) AND (qy == 0)          Q is O
//	usep = qinf AND NOT pinf                -> answer is P
//	useq = pinf                             -> answer is Q  (covers O + O = O)
//	user = notinf AND NOT(pinf OR qinf)     -> answer is the computed sum
//
// `user` folds in the pre-existing `notinf` mask (the P == -Q case), so
// P + (-P) still yields the all-zero blob and nothing about that case changes.
//
// Requiring BOTH coordinates to be zero is load-bearing, not belt-and-braces.
// x = 0 has genuine curve points whenever the curve's b is a quadratic
// residue -- (0, sqrt(b)) -- and testing x alone would map them to O. y = 0
// has none on any of these three curves (all have prime order, so no point of
// order 2), but the conjunction makes that fact not need to be true.
//
// Plain OP_MUL / OP_ADD with no field reduction: px, qx, rx are already in
// [0, p) and the masks are 0 or 1, so each product and the sum are canonical.
//
// Consumes px, py, qx, qy and the field-computed rx, ry; leaves the selected
// rx, ry in their place.
func emitAffineInfinitySelect(t *ECTracker) {
	// pinf = (px == 0) AND (py == 0)
	t.copyToTop("px", "_px_z")
	t.pushInt("_zero_px", 0)
	t.rawBlock([]string{"_px_z", "_zero_px"}, "_pxz", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_NUMEQUAL"})
	})
	t.copyToTop("py", "_py_z")
	t.pushInt("_zero_py", 0)
	t.rawBlock([]string{"_py_z", "_zero_py"}, "_pyz", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_NUMEQUAL"})
	})
	t.rawBlock([]string{"_pxz", "_pyz"}, "_pinf", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_BOOLAND"})
	})

	// qinf = (qx == 0) AND (qy == 0)
	t.copyToTop("qx", "_qx_z")
	t.pushInt("_zero_qx", 0)
	t.rawBlock([]string{"_qx_z", "_zero_qx"}, "_qxz", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_NUMEQUAL"})
	})
	t.copyToTop("qy", "_qy_z")
	t.pushInt("_zero_qy", 0)
	t.rawBlock([]string{"_qy_z", "_zero_qy"}, "_qyz", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_NUMEQUAL"})
	})
	t.rawBlock([]string{"_qxz", "_qyz"}, "_qinf", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_BOOLAND"})
	})

	// usep = qinf AND NOT pinf
	t.copyToTop("_qinf", "_usep_q")
	t.copyToTop("_pinf", "_usep_p")
	t.rawBlock([]string{"_usep_q", "_usep_p"}, "_usep", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_NOT"})
		e(StackOp{Op: "opcode", Code: "OP_BOOLAND"})
	})

	// useq = pinf
	t.copyToTop("_pinf", "_useq")

	// user = notinf AND NOT(pinf OR qinf)
	t.toTop("_pinf")
	t.toTop("_qinf")
	t.rawBlock([]string{"_pinf", "_qinf"}, "_anyinf", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_BOOLOR"})
	})
	t.toTop("_notinf")
	t.toTop("_anyinf")
	t.rawBlock([]string{"_notinf", "_anyinf"}, "_user", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_NOT"})
		e(StackOp{Op: "opcode", Code: "OP_BOOLAND"})
	})

	// rx = px*usep + qx*useq + rx*user
	t.toTop("px")
	t.copyToTop("_usep", "_usep_x")
	t.rawBlock([]string{"px", "_usep_x"}, "_selx_p", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
	t.toTop("qx")
	t.copyToTop("_useq", "_useq_x")
	t.rawBlock([]string{"qx", "_useq_x"}, "_selx_q", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
	t.toTop("rx")
	t.copyToTop("_user", "_user_x")
	t.rawBlock([]string{"rx", "_user_x"}, "_selx_r", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
	t.rawBlock([]string{"_selx_q", "_selx_r"}, "_selx_qr", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.rawBlock([]string{"_selx_p", "_selx_qr"}, "rx", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})

	// ry = py*usep + qy*useq + ry*user  (last use of each mask: consume them)
	t.toTop("py")
	t.toTop("_usep")
	t.rawBlock([]string{"py", "_usep"}, "_sely_p", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
	t.toTop("qy")
	t.toTop("_useq")
	t.rawBlock([]string{"qy", "_useq"}, "_sely_q", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
	t.toTop("ry")
	t.toTop("_user")
	t.rawBlock([]string{"ry", "_user"}, "_sely_r", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
	t.rawBlock([]string{"_sely_q", "_sely_r"}, "_sely_qr", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.rawBlock([]string{"_sely_p", "_sely_qr"}, "ry", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
}

// ===========================================================================
// Jacobian point operations (for ecMul)
// ===========================================================================

// ecJacobianDouble performs Jacobian point doubling (a=0 for secp256k1).
// Expects jx, jy, jz on tracker. Replaces with updated values.
func ecJacobianDouble(t *ECTracker) {
	// Save copies of jx, jy, jz for later use
	t.copyToTop("jy", "_jy_save")
	t.copyToTop("jx", "_jx_save")
	t.copyToTop("jz", "_jz_save")

	// A = jy^2
	ecFieldSqr(t, "jy", "_A")

	// B = 4 * jx * A
	t.copyToTop("_A", "_A_save")
	ecFieldMul(t, "jx", "_A", "_xA")
	t.pushInt("_four", 4)
	ecFieldMul(t, "_xA", "_four", "_B")

	// C = 8 * A^2
	ecFieldSqr(t, "_A_save", "_A2")
	t.pushInt("_eight", 8)
	ecFieldMul(t, "_A2", "_eight", "_C")

	// D = 3 * X^2
	ecFieldSqr(t, "_jx_save", "_x2")
	t.pushInt("_three", 3)
	ecFieldMul(t, "_x2", "_three", "_D")

	// nx = D^2 - 2*B
	t.copyToTop("_D", "_D_save")
	t.copyToTop("_B", "_B_save")
	ecFieldSqr(t, "_D", "_D2")
	t.copyToTop("_B", "_B1")
	ecFieldMulConst(t, "_B1", 2, "_2B")
	ecFieldSub(t, "_D2", "_2B", "_nx")

	// ny = D*(B - nx) - C
	t.copyToTop("_nx", "_nx_copy")
	ecFieldSub(t, "_B_save", "_nx_copy", "_B_nx")
	ecFieldMul(t, "_D_save", "_B_nx", "_D_B_nx")
	ecFieldSub(t, "_D_B_nx", "_C", "_ny")

	// nz = 2 * Y * Z
	ecFieldMul(t, "_jy_save", "_jz_save", "_yz")
	ecFieldMulConst(t, "_yz", 2, "_nz")

	// Clean up leftovers: _B and old jz (only copied, never consumed)
	t.toTop("_B")
	t.drop()
	t.toTop("jz")
	t.drop()
	t.toTop("_nx")
	t.rename("jx")
	t.toTop("_ny")
	t.rename("jy")
	t.toTop("_nz")
	t.rename("jz")
}

// ecJacobianToAffine converts Jacobian to affine coordinates.
// Consumes jx, jy, jz; produces rxName, ryName.
func ecJacobianToAffine(t *ECTracker, rxName, ryName string) {
	ecFieldInv(t, "jz", "_zinv")
	t.copyToTop("_zinv", "_zinv_keep")
	ecFieldSqr(t, "_zinv", "_zinv2")
	t.copyToTop("_zinv2", "_zinv2_keep")
	ecFieldMul(t, "_zinv_keep", "_zinv2", "_zinv3")
	ecFieldMul(t, "jx", "_zinv2_keep", rxName)
	ecFieldMul(t, "jy", "_zinv3", ryName)
}

// ===========================================================================
// Jacobian mixed addition (P_jacobian + Q_affine)
// ===========================================================================

// ecBuildJacobianAddAffineInline builds Jacobian mixed-add ops for use inside OP_IF.
// Uses an inner ECTracker to leverage field arithmetic helpers.
//
// Stack layout: [..., ax, ay, _k, jx, jy, jz]
// After:        [..., ax, ay, _k, jx', jy', jz']
func ecBuildJacobianAddAffineInline(e func(StackOp), t *ECTracker) {
	// Create inner tracker with cloned stack state
	initNm := make([]string, len(t.nm))
	copy(initNm, t.nm)
	ecJacobianAddAffineBody(NewECTracker(initNm, e), false)
}

// ecJacobianAddAffineBody is the mixed-add itself, emitting through a tracker
// the caller owns.
//
// keepHR additionally leaves copies of H and R on the stack. They are the
// exception detector: H = U2 - X1 and R = S2 - Y1 are both zero exactly when
// the Jacobian accumulator is the same curve point as the affine operand, the
// one case these formulas cannot compute (see ecBuildJacobianAddOrDoubleInline).
func ecJacobianAddAffineBody(it *ECTracker, keepHR bool) {
	// Save copies of values that get consumed but are needed later
	it.copyToTop("jz", "_jz_for_z1cu") // consumed by Z1sq, needed for Z1cu
	it.copyToTop("jz", "_jz_for_z3")   // needed for Z3
	it.copyToTop("jy", "_jy_for_y3")   // consumed by R, needed for Y3
	it.copyToTop("jx", "_jx_for_u1h2") // consumed by H, needed for U1H2

	// Z1sq = jz^2
	ecFieldSqr(it, "jz", "_Z1sq")

	// Z1cu = _jz_for_z1cu * Z1sq (copy Z1sq for U2)
	it.copyToTop("_Z1sq", "_Z1sq_for_u2")
	ecFieldMul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu")

	// U2 = ax * Z1sq_for_u2
	it.copyToTop("ax", "_ax_c")
	ecFieldMul(it, "_ax_c", "_Z1sq_for_u2", "_U2")

	// S2 = ay * Z1cu
	it.copyToTop("ay", "_ay_c")
	ecFieldMul(it, "_ay_c", "_Z1cu", "_S2")

	// H = U2 - jx
	ecFieldSub(it, "_U2", "jx", "_H")

	// R = S2 - jy
	ecFieldSub(it, "_S2", "jy", "_R")

	if keepHR {
		it.copyToTop("_H", "_H_keep")
		it.copyToTop("_R", "_R_keep")
	}

	// Save copies of H (consumed by H2 sqr, needed for H3 and Z3)
	it.copyToTop("_H", "_H_for_h3")
	it.copyToTop("_H", "_H_for_z3")

	// H2 = H^2
	ecFieldSqr(it, "_H", "_H2")

	// Save H2 for U1H2
	it.copyToTop("_H2", "_H2_for_u1h2")

	// H3 = H_for_h3 * H2
	ecFieldMul(it, "_H_for_h3", "_H2", "_H3")

	// U1H2 = _jx_for_u1h2 * H2_for_u1h2
	ecFieldMul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2")

	// Save R, U1H2, H3 for Y3 computation
	it.copyToTop("_R", "_R_for_y3")
	it.copyToTop("_U1H2", "_U1H2_for_y3")
	it.copyToTop("_H3", "_H3_for_y3")

	// X3 = R^2 - H3 - 2*U1H2
	ecFieldSqr(it, "_R", "_R2")
	ecFieldSub(it, "_R2", "_H3", "_x3_tmp")
	ecFieldMulConst(it, "_U1H2", 2, "_2U1H2")
	ecFieldSub(it, "_x3_tmp", "_2U1H2", "_X3")

	// Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
	it.copyToTop("_X3", "_X3_c")
	ecFieldSub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x")
	ecFieldMul(it, "_R_for_y3", "_u_minus_x", "_r_tmp")
	ecFieldMul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3")
	ecFieldSub(it, "_r_tmp", "_jy_h3", "_Y3")

	// Z3 = _jz_for_z3 * _H_for_z3
	ecFieldMul(it, "_jz_for_z3", "_H_for_z3", "_Z3")

	// Rename results to jx/jy/jz
	it.toTop("_X3")
	it.rename("jx")
	it.toTop("_Y3")
	it.rename("jy")
	it.toTop("_Z3")
	it.rename("jz")
}

// ecSelectCoord is a branchless select of one Jacobian coordinate:
// `add + cond*(dbl - add)`. Same shape as the numerator/denominator select in
// ecAffineAdd, so both paths emit the identical op sequence and the tracker's
// static stack model holds. Consumes addName, dblName and condName.
func ecSelectCoord(t *ECTracker, addName, dblName, condName, resultName string) {
	t.copyToTop(addName, "_sel_add_c")
	ecFieldSub(t, dblName, "_sel_add_c", "_sel_diff")
	ecFieldMul(t, "_sel_diff", condName, "_sel_scaled")
	ecFieldAdd(t, addName, "_sel_scaled", resultName)
}

// ecBuildJacobianAddOrDoubleInline is the ladder's LAST conditional step:
// mixed-add, but correct when the accumulator already equals the point being
// added.
//
// The Jacobian mixed-add cannot double. It computes H = U2 - X1, and when the
// two operands are the same curve point H = 0, so Z3 = Z1*H = 0 — the point at
// infinity — and since ecFieldInv is Fermat (inv(0) = 0), ecJacobianToAffine
// turns that into the ALL-ZERO point instead of 2P. ecMul(P, 2n) and
// ecMulGen(2n) returned 64 zero bytes.
//
// WHY ONLY THE LAST STEP. After step i the accumulator holds c_i*P where
// c_i = k' >> i and k' = k + 3n, so the conditional step adds P to
// (c_i - 1)*P. secp256k1 has cofactor 1, so P has order n and the degenerate
// cases are exactly c_i ≡ 2 (mod n) — accumulator == P — and c_i ≡ 0 or 1
// (mod n) — accumulator == -P or O. c_i ranges over a CONTIGUOUS interval
// determined only by i, so this is decidable by interval arithmetic rather
// than by sampling, and over the whole domain k ∈ [0, n-1] only two steps
// qualify, both at i = 0:
//
//	k = 2  ->  c_0 = 3n+2 ≡ 2, odd, so the add runs: accumulator == P.  <- bug
//	k = 0  ->  c_0 = 3n   ≡ 0, odd, so the add runs: accumulator == -P,
//	           true result the point at infinity, which affine coordinates
//	           cannot represent; it stays the all-zero point, as before.
//
// At i ≥ 1, c_i lies in [3n>>i, (4n-1)>>i] — the lower bound is 3n, not 3n+1,
// because the reduce puts k = 0 in the domain — and that interval contains no
// value ≡ 0, 1 or 2 (mod n) that is also odd; c_256 = 2 is even, so no add
// runs. Handling H == 0 at every one of the 257 steps would cost ~70% more
// script bytes; handling it here costs 0.26%.
//
// THE ENTIRE ARGUMENT IS CONDITIONED ON k ∈ [0, n-1], which is only true
// because EmitEcMul reduces k mod n before adding 3n. That reduce landed one
// commit AFTER this select (03f50d48 then f16790a9). 03f50d48 ON ITS OWN IS
// UNSOUND: a last-step-only select while the scalar is still unbounded leaves
// c_i free to hit 0, 1 or 2 (mod n) at other steps. The two commits must land
// together and must never be bisected, cherry-picked or reverted apart.
//
// The interval argument does 100% of the work; there is no defence in depth
// here. In particular c_i ≡ 1 (mod n) — a pre-add accumulator of O — is
// UNREACHABLE, not handled: were it reachable the select would still take the
// ADD path, because O is carried as Z1 = 0, which makes U2 = 0 and
// H = -X1 != 0. Anything that changes the +3n offset, the iteration count or
// the reduce must redo the interval check, not assume this still holds.
//
// The operand P is caller-supplied but cannot move the exception, because the
// condition depends only on c_i mod ord(P) and ord(P) = n for every point on
// the curve. Points that are NOT on the curve carry no such guarantee — gate
// untrusted input on ecOnCurve first.
//
// Stack layout: [..., ax, ay, _k, jx, jy, jz] — same in and out.
func ecBuildJacobianAddOrDoubleInline(e func(StackOp), t *ECTracker) {
	initNm := make([]string, len(t.nm))
	copy(initNm, t.nm)
	it := NewECTracker(initNm, e)

	// Keep the pre-add accumulator: it is what must be DOUBLED in the
	// exceptional case, and the add below consumes jx/jy/jz.
	it.copyToTop("jx", "_sx")
	it.copyToTop("jy", "_sy")
	it.copyToTop("jz", "_sz")

	ecJacobianAddAffineBody(it, true)

	// cond = (H == 0) AND (R == 0). Requiring R == 0 too keeps the
	// accumulator == -P case (k = 0) on the add path, where Z3 = 0 correctly
	// signals the point at infinity.
	it.toTop("_H_keep")
	it.pushInt("_zero_h", 0)
	it.rawBlock([]string{"_H_keep", "_zero_h"}, "_h_is0", func(e2 func(StackOp)) {
		e2(StackOp{Op: "opcode", Code: "OP_NUMEQUAL"})
	})
	it.toTop("_R_keep")
	it.pushInt("_zero_r", 0)
	it.rawBlock([]string{"_R_keep", "_zero_r"}, "_r_is0", func(e2 func(StackOp)) {
		e2(StackOp{Op: "opcode", Code: "OP_NUMEQUAL"})
	})
	it.toTop("_h_is0")
	it.toTop("_r_is0")
	it.rawBlock([]string{"_h_is0", "_r_is0"}, "_cond", func(e2 func(StackOp)) {
		e2(StackOp{Op: "opcode", Code: "OP_BOOLAND"})
	})

	// Move the add result aside so ecJacobianDouble can work on jx/jy/jz
	// again, this time holding the saved accumulator.
	it.toTop("jx")
	it.rename("_add_x")
	it.toTop("jy")
	it.rename("_add_y")
	it.toTop("jz")
	it.rename("_add_z")
	it.toTop("_sx")
	it.rename("jx")
	it.toTop("_sy")
	it.rename("jy")
	it.toTop("_sz")
	it.rename("jz")
	ecJacobianDouble(it)
	it.toTop("jx")
	it.rename("_dbl_x")
	it.toTop("jy")
	it.rename("_dbl_y")
	it.toTop("jz")
	it.rename("_dbl_z")

	it.copyToTop("_cond", "_cond_x")
	ecSelectCoord(it, "_add_x", "_dbl_x", "_cond_x", "jx")
	it.copyToTop("_cond", "_cond_y")
	ecSelectCoord(it, "_add_y", "_dbl_y", "_cond_y", "jy")
	it.toTop("_cond")
	it.rename("_cond_z")
	ecSelectCoord(it, "_add_z", "_dbl_z", "_cond_z", "jz")
}

// ===========================================================================
// Public entry points (called from stack lowerer)
// ===========================================================================

// ecEmitCoordCanonVerify -- R-117: a Point's two coordinates must be FIELD
// ELEMENTS, aborting form.
//
// ecDecomposePoint BIN2NUMs each half of the blob as an unsigned integer, so
// any value that fits in the coordinate width is accepted -- x + p included,
// whenever x + p < 2^256 (on secp256k1 that is every x < 2^32 + 977).
// Downstream field arithmetic reduces mod p, so (x+p)||y behaves as the point
// (x, y); ecAffineAdd's two case selectors do NOT reduce, and they are bare
// OP_NUMEQUAL on exactly these raw values:
//
//	cond   = (px == qx) AND (py == qy)      "same point" -> tangent
//	notinf = NOT(px == qx AND NOT cond)     "P and -P"   -> the O mask
//
// so for P and its alias both read 0, the chord path runs on two equal points,
// den_chord = qx - px == 0 (mod p), and ecFieldInv is Fermat with inv(0) = 0.
// Measured before this gate landed, x = 1: ecAdd(P, P) gave the correct 2P and
// ecAdd(P, P') gave x = p-2 -- a script that SUCCEEDED and returned a blob that
// is not a point. Both the doubling case and the P + (-P) case are driven by
// these selectors, so both are defeated by the same trick.
//
// REJECT rather than reduce: EmitEcOnCurve already answers "no" to a
// non-canonical encoding, so reducing here would leave the predicate and the
// value builtins disagreeing about whether the blob is a point at all. This is
// also the policy CL-BUG-095 set for the WIDTH -- predicates clamp and flag,
// value producers OP_VERIFY.
//
// Callers are the user-facing value builtins only; deliberately NOT folded into
// ecDecomposePoint, which also runs inside EmitEcOnCurve and must stay total.
//
// x and y are unsigned by construction, so "< p" is the whole check.
func ecEmitCoordCanonVerify(t *ECTracker, xName, yName string) {
	t.copyToTop(xName, "_cc_x")
	ecPushFieldP(t, "_cc_px")
	t.rawBlock([]string{"_cc_x", "_cc_px"}, "_cc_xok", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_LESSTHAN"})
	})
	t.copyToTop(yName, "_cc_y")
	ecPushFieldP(t, "_cc_py")
	t.rawBlock([]string{"_cc_y", "_cc_py"}, "_cc_yok", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_LESSTHAN"})
	})
	t.rawBlock([]string{"_cc_xok", "_cc_yok"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_BOOLAND"})
		e(StackOp{Op: "opcode", Code: "OP_VERIFY"})
	})
}

// EmitEcAdd adds two points.
// Stack in: [point_a, point_b] (b on top)
// Stack out: [result_point]
func EmitEcAdd(emit func(StackOp)) {
	t := NewECTracker([]string{"_pa", "_pb"}, emit)
	ecDecomposePoint(t, "_pa", "px", "py")
	ecDecomposePoint(t, "_pb", "qx", "qy")
	// R-117: ecAffineAdd's selectors compare these four values RAW.
	ecEmitCoordCanonVerify(t, "px", "py")
	ecEmitCoordCanonVerify(t, "qx", "qy")
	ecAffineAdd(t)
	ecComposePoint(t, "rx", "ry", "_result")
}

// ecEmitScalarReduce reduces a scalar to [0, n-1]: ((k mod n) + n) mod n.
//
// OP_MOD takes the sign of the DIVIDEND, so `k mod n` alone lands in (-n, n);
// the `+ n, mod n` normalises the negative half. One push of n covers both
// reductions — the same shape as EmitEcModReduce.
//
// Without it, EmitEcMul's ladder is only correct while 2^257 <= k + 3n < 2^258:
// a scalar >= ~n sets bit 258, the 257-iteration loop never sees it, and the
// ladder returns a DIFFERENT multiple of P rather than failing. Scalars are
// contract input, so that is attacker-chosen. Reducing costs 1 push + 8 opcodes
// (42 bytes) against a ~429 KB script, and makes k >= n, k < 0 and k = 0 all
// well defined.
func ecEmitScalarReduce(t *ECTracker, kName, resultName string, n *big.Int) {
	t.pushBigInt("_n_red", n)
	t.rawBlock([]string{kName, "_n_red"}, resultName, func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_2DUP"})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
		e(StackOp{Op: "rot"})
		e(StackOp{Op: "drop"})
		e(StackOp{Op: "over"})
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
		e(StackOp{Op: "swap"})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})
}

// EmitEcMul performs scalar multiplication P * k.
// Stack in: [point, scalar] (scalar on top)
// Stack out: [result_point]
//
// Uses 256-iteration double-and-add with Jacobian coordinates.
func EmitEcMul(emit func(StackOp)) {
	t := NewECTracker([]string{"_pt", "_k"}, emit)
	// Decompose to affine base point
	ecDecomposePoint(t, "_pt", "ax", "ay")
	ecEmitCoordCanonVerify(t, "ax", "ay")

	// k' = k + 3n: guarantees bit 257 is set.
	// k ∈ [1, n-1], so k+3n ∈ [3n+1, 4n-1]. Since 3n > 2^257, bit 257
	// is always 1. Adding 3n (≡ 0 mod n) preserves the EC point: k*G = (k+3n)*G.
	//
	// "k ∈ [1, n-1]" is a PRECONDITION the caller cannot enforce — the scalar is
	// usually an unlock argument — so reduce it first. See ecEmitScalarReduce.
	curveN, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	t.toTop("_k")
	ecEmitScalarReduce(t, "_k", "_kr", curveN)
	t.pushBigInt("_n", curveN)
	t.rawBlock([]string{"_kr", "_n"}, "_kn", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.pushBigInt("_n2", curveN)
	t.rawBlock([]string{"_kn", "_n2"}, "_kn2", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.pushBigInt("_n3", curveN)
	t.rawBlock([]string{"_kn2", "_n3"}, "_kn3", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.rename("_k")

	// Init accumulator = P (bit 257 of k+3n is always 1)
	t.copyToTop("ax", "jx")
	t.copyToTop("ay", "jy")
	t.pushInt("jz", 1)

	// 257 iterations: bits 256 down to 0
	for bit := 256; bit >= 0; bit-- {
		// Double accumulator
		ecJacobianDouble(t)

		// Extract bit: (k >> bit) & 1, using OP_RSHIFTNUM / OP_2DIV
		t.copyToTop("_k", "_k_copy")
		if bit == 1 {
			// Single-bit shift: OP_2DIV (no push needed)
			t.rawBlock([]string{"_k_copy"}, "_shifted", func(e func(StackOp)) {
				e(StackOp{Op: "opcode", Code: "OP_2DIV"})
			})
		} else if bit > 1 {
			// Multi-bit shift: push shift amount, OP_RSHIFTNUM
			t.pushInt("_shift", int64(bit))
			t.rawBlock([]string{"_k_copy", "_shift"}, "_shifted", func(e func(StackOp)) {
				e(StackOp{Op: "opcode", Code: "OP_RSHIFTNUM"})
			})
		} else {
			t.rename("_shifted")
		}
		t.pushInt("_two", 2)
		t.rawBlock([]string{"_shifted", "_two"}, "_bit", func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_MOD"})
		})

		// Move _bit to TOS and remove from tracker BEFORE generating add ops,
		// because OP_IF consumes _bit and the add ops run with _bit already gone.
		t.toTop("_bit")
		t.nm = t.nm[:len(t.nm)-1] // _bit consumed by IF
		var addOps []StackOp
		addEmit := func(op StackOp) { addOps = append(addOps, op) }
		// Only the final step can be handed two equal operands — see
		// ecBuildJacobianAddOrDoubleInline for why, and for what it costs not to.
		if bit == 0 {
			ecBuildJacobianAddOrDoubleInline(addEmit, t)
		} else {
			ecBuildJacobianAddAffineInline(addEmit, t)
		}
		emit(StackOp{Op: "if", Then: addOps, Else: []StackOp{}})
	}

	// Convert Jacobian to affine
	ecJacobianToAffine(t, "_rx", "_ry")

	// Clean up base point and scalar
	t.toTop("ax")
	t.drop()
	t.toTop("ay")
	t.drop()
	t.toTop("_k")
	t.drop()

	// Compose result
	ecComposePoint(t, "_rx", "_ry", "_result")
}

// EmitEcMulGen performs scalar multiplication G * k.
// Stack in: [scalar]
// Stack out: [result_point]
func EmitEcMulGen(emit func(StackOp)) {
	// Push generator point as 64-byte blob, then delegate to ecMul
	gPoint := make([]byte, 64)
	copy(gPoint[0:32], bigintToBytes32(ecGenX))
	copy(gPoint[32:64], bigintToBytes32(ecGenY))
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: gPoint}})
	emit(StackOp{Op: "swap"}) // [point, scalar]
	EmitEcMul(emit)
}

// EmitEcNegate negates a point (x, p - y).
// Stack in: [point]
// Stack out: [negated_point]
func EmitEcNegate(emit func(StackOp)) {
	t := NewECTracker([]string{"_pt"}, emit)
	ecDecomposePoint(t, "_pt", "_nx", "_ny")
	ecEmitCoordCanonVerify(t, "_nx", "_ny")
	ecPushFieldP(t, "_fp")
	ecFieldSub(t, "_fp", "_ny", "_neg_y")
	ecComposePoint(t, "_nx", "_neg_y", "_result")
}

// EmitEcOnCurve checks if point is on secp256k1 (y^2 = x^3 + 7 mod p).
// Stack in: [point]
// Stack out: [boolean]
func EmitEcOnCurve(emit func(StackOp)) {
	t := NewECTracker([]string{"_pt"}, emit)

	// CL-BUG-095: width. `ecOnCurve(G || 0xff)` returned TRUE -- decomposePoint
	// discarded the surplus byte. Clamp and remember the width, rather than
	// abort, because this predicate must stay total; the flag is ANDed into
	// the result at the end.
	ecEmitPointLengthGate(t, "_pt", 64, "_len_ok")

	ecDecomposePoint(t, "_pt", "_x", "_y")

	// GAP-301: coordinate canonicity. ecDecomposePoint BIN2NUMs each coordinate
	// as an unsigned value that may be >= p; the field arithmetic below would
	// silently reduce it mod p, so a non-canonical encoding of a valid point
	// would pass. Reject it: require x < p AND y < p (coordinates are unsigned,
	// so the 0 <= lower bound holds by construction). Combined with the curve
	// equation at the end via OP_BOOLAND so ecOnCurve still returns a boolean.
	t.copyToTop("_x", "_x_lt")
	ecPushFieldP(t, "_p_for_x")
	t.rawBlock([]string{"_x_lt", "_p_for_x"}, "_x_canon", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_LESSTHAN"})
	})
	t.copyToTop("_y", "_y_lt")
	ecPushFieldP(t, "_p_for_y")
	t.rawBlock([]string{"_y_lt", "_p_for_y"}, "_y_canon", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_LESSTHAN"})
	})
	t.toTop("_x_canon")
	t.toTop("_y_canon")
	t.rawBlock([]string{"_x_canon", "_y_canon"}, "_canon", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_BOOLAND"})
	})

	// lhs = y^2
	ecFieldSqr(t, "_y", "_y2")

	// rhs = x^3 + 7
	t.copyToTop("_x", "_x_copy")
	ecFieldSqr(t, "_x", "_x2")
	ecFieldMul(t, "_x2", "_x_copy", "_x3")
	t.pushInt("_seven", 7)
	ecFieldAdd(t, "_x3", "_seven", "_rhs")

	// Compare curve equation
	t.toTop("_y2")
	t.toTop("_rhs")
	t.rawBlock([]string{"_y2", "_rhs"}, "_curve_eq", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUAL"})
	})

	// on-curve = right width AND canonical AND curve-equation
	t.toTop("_canon")
	t.toTop("_curve_eq")
	t.rawBlock([]string{"_canon", "_curve_eq"}, "_eq_ok", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_BOOLAND"})
	})
	t.toTop("_len_ok")
	t.toTop("_eq_ok")
	t.rawBlock([]string{"_len_ok", "_eq_ok"}, "_result", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_BOOLAND"})
	})
}

// EmitEcModReduce computes ((value % mod) + mod) % mod.
// Stack in: [value, mod]
// Stack out: [result]
func EmitEcModReduce(emit func(StackOp)) {
	emit(StackOp{Op: "opcode", Code: "OP_2DUP"})
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})
	emit(StackOp{Op: "rot"})
	emit(StackOp{Op: "drop"})
	emit(StackOp{Op: "over"})
	emit(StackOp{Op: "opcode", Code: "OP_ADD"})
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})
}

// EmitEcEncodeCompressed encodes a point as a 33-byte compressed pubkey.
// Stack in: [point (64 bytes)]
// Stack out: [compressed (33 bytes)]
func EmitEcEncodeCompressed(emit func(StackOp)) {
	// CL-BUG-095: the parity byte used to be taken from the blob's LAST byte
	// (OP_SIZE, OP_SUB 1, OP_SPLIT), not a fixed offset -- so appending one
	// byte flipped the sign of the compressed encoding. Width is now verified
	// AND the parity byte is read from a fixed offset.
	ecEmitPointLenVerify(emit, 64)
	// Split at 32: [x_bytes, y_bytes]
	emit(StackOp{Op: "push", Value: bigIntPush(32)})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	// Take y[31] at a FIXED offset: [x_bytes, y_head, y_last]
	emit(StackOp{Op: "push", Value: bigIntPush(31)})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	emit(StackOp{Op: "nip"}) // drop y_head
	// Stack: [x_bytes, last_byte]
	emit(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	emit(StackOp{Op: "push", Value: bigIntPush(2)})
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})
	// Stack: [x_bytes, parity]
	emit(StackOp{Op: "if",
		Then: []StackOp{{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x03}}}},
		Else: []StackOp{{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x02}}}},
	})
	// Stack: [x_bytes, prefix_byte]
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
}

// EmitEcMakePoint converts (x: bigint, y: bigint) to a 64-byte Point.
// Stack in: [x_num, y_num] (y on top)
// Stack out: [point_bytes (64 bytes)]
func EmitEcMakePoint(emit func(StackOp)) {
	// Convert y to 32 bytes big-endian (NUM2BIN(33) to handle sign byte, then take first 32)
	emit(StackOp{Op: "push", Value: bigIntPush(33)})
	emit(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
	emit(StackOp{Op: "push", Value: bigIntPush(32)})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	emit(StackOp{Op: "drop"})
	ecEmitReverse32(emit)
	// Stack: [x_num, y_be]
	emit(StackOp{Op: "swap"})
	// Stack: [y_be, x_num]
	emit(StackOp{Op: "push", Value: bigIntPush(33)})
	emit(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
	emit(StackOp{Op: "push", Value: bigIntPush(32)})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	emit(StackOp{Op: "drop"})
	ecEmitReverse32(emit)
	// Stack: [y_be, x_be]
	emit(StackOp{Op: "swap"})
	// Stack: [x_be, y_be]
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
}

// EmitEcPointX extracts the x-coordinate from a Point.
// Stack in: [point (64 bytes)]
// Stack out: [x as bigint]
func EmitEcPointX(emit func(StackOp)) {
	// CL-BUG-095: a 32-byte blob used to SUCCEED here and return itself as x --
	// the split at 32 left an empty tail that `drop` happily removed.
	ecEmitPointLenVerify(emit, 64)
	emit(StackOp{Op: "push", Value: bigIntPush(32)})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	emit(StackOp{Op: "drop"})
	ecEmitReverse32(emit)
	// Append 0x00 sign byte to ensure unsigned interpretation
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	emit(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
}

// EmitEcPointY extracts the y-coordinate from a Point.
// Stack in: [point (64 bytes)]
// Stack out: [y as bigint]
func EmitEcPointY(emit func(StackOp)) {
	ecEmitPointLenVerify(emit, 64)
	emit(StackOp{Op: "push", Value: bigIntPush(32)})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "drop"})
	ecEmitReverse32(emit)
	// Append 0x00 sign byte to ensure unsigned interpretation
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	emit(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
}
