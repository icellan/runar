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

// secp256k1 curve order
var ecCurveN *big.Int

// secp256k1 generator x-coordinate
var ecGenX *big.Int

// secp256k1 generator y-coordinate
var ecGenY *big.Int

func init() {
	ecFieldP, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	ecFieldPMinus2 = new(big.Int).Sub(ecFieldP, big.NewInt(2))
	ecCurveN, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
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
// EcCodegenOptions are the codegen options shared by every EC / NIST-curve
// emitter.
//
// Off by default: with a nil pointer (or all-false struct) each emitter is
// byte-identical to what the seven tiers ship today, so no golden, size
// baseline, or cross-tier parity gate can move.
type EcCodegenOptions struct {
	// ConstantPool parks large repeated constants (the field prime, the group
	// order) in a stack slot and copies them with OP_PICK instead of re-pushing
	// the literal.
	//
	// ecFieldMod pushes the 256-bit prime at every modular reduction — 34 bytes
	// a time, 20,025 times in p256-wallet (71 % of that fixture). A pick from a
	// slot a dozen deep costs 2.
	ConstantPool bool

	// ReductionSinking emits `a mod p` without the sign fix-up wherever the
	// dividend is provably non-negative, and the cheap `a - b + p` form for
	// subtraction wherever the subtrahend is provably reduced.
	//
	// Which reductions qualify is decided by the sign lattice below — never
	// assumed. Only sound alongside ConstantPool: the cheap subtraction
	// references the prime twice, so without a pooled slot it is a regression.
	ReductionSinking bool

	// FixedBaseComb uses a Lim-Lee comb instead of the binary ladder wherever
	// the base point is a compile-time constant (EcMulGen, P256MulGen,
	// P384MulGen, and the u1*G half of ECDSA verification).
	//
	// The window width is not fixed: the emitter renders each candidate and
	// keeps whichever the byte-cost model scores smallest.
	FixedBaseComb bool
}

// ecDom is what is known about a tracked value's sign and range.
//
// domReduced implies domNonNegative; the ordering is what the transfer
// functions meet over. domUnknown is the default for every slot the analysis
// has not explicitly proved something about — including everything a rawBlock
// or an OP_IF produces — so an un-analysed value can only ever fall back to the
// shipping reduction.
//
// The distinction is not academic. OP_BIN2NUM of 32 unsigned coordinate bytes
// gives domNonNegative but NOT domReduced: a coordinate may legitimately be up
// to 2^256 - 1 while p is 2^32 + 977 smaller. Multiplication and addition need
// only domNonNegative; subtraction's cheap form needs the subtrahend
// domReduced, and conflating the two produces a script that passes 256 EC
// oracle assertions and is still wrong on ecAdd((0,1), (2^256-1,1)).
type ecDom int

const (
	// domUnknown means nothing is known; the value may be negative.
	domUnknown ecDom = iota
	// domNonNegative means the value is provably >= 0. It may be >= p.
	domNonNegative
	// domReduced means the value is provably in [0, p).
	domReduced
)

// isNonNegative reports whether d proves the value is >= 0.
func isNonNegative(d ecDom) bool { return d >= domNonNegative }

// Stack slot names reserved for pooled constants.
const (
	ecPoolFieldP = "_pool$p"
	ecPoolGroupN = "_pool$n"
)

type ECTracker struct {
	nm []string // stack names ("" for anonymous)
	// dm holds the sign-lattice fact per stack SLOT, kept parallel to nm.
	//
	// Slot-parallel rather than keyed by name on purpose: names are reused
	// (_fmul_prod is written by every multiply) and the same name can be
	// resident twice, so a name-keyed map would go stale in exactly the cases
	// that matter. Every mutation of nm below mirrors into dm with the same
	// splice, so the two cannot drift.
	dm []ecDom
	// altDm holds lattice facts for values parked on the alt stack, bottom to top.
	altDm []ecDom
	e     func(StackOp)
	// pooling is true when this tracker may serve constants from a pooled slot.
	pooling bool
	// sinking is true when this tracker may emit sunk reductions.
	sinking bool
	// comb is true when a compile-time-known base may use a fixed-base comb.
	comb bool
}

// NewECTracker creates a new tracker with initial named stack slots.
func NewECTracker(init []string, emit func(StackOp)) *ECTracker {
	return NewECTrackerOpts(init, emit, nil, nil)
}

// NewECTrackerOpts creates a tracker carrying codegen options and, optionally,
// initial lattice facts for the pre-existing slots.
func NewECTrackerOpts(init []string, emit func(StackOp), opts *EcCodegenOptions, initDomains []ecDom) *ECTracker {
	nm := make([]string, len(init))
	copy(nm, init)
	dm := make([]ecDom, len(init))
	if initDomains != nil {
		copy(dm, initDomains)
	}
	t := &ECTracker{nm: nm, dm: dm, e: emit}
	if opts != nil {
		t.pooling = opts.ConstantPool
		t.sinking = opts.ReductionSinking
		t.comb = opts.FixedBaseComb
	}
	return t
}

// options returns the options this tracker was built with, for handing to a
// nested tracker.
func (t *ECTracker) options() *EcCodegenOptions {
	return &EcCodegenOptions{ConstantPool: t.pooling, ReductionSinking: t.sinking, FixedBaseComb: t.comb}
}

// domainsCopy returns a copy of the lattice facts, for seeding a nested tracker.
func (t *ECTracker) domainsCopy() []ecDom {
	out := make([]ecDom, len(t.dm))
	copy(out, t.dm)
	return out
}

// namesCopy returns a copy of the stack names, for seeding a nested tracker.
func (t *ECTracker) namesCopy() []string {
	out := make([]string, len(t.nm))
	copy(out, t.nm)
	return out
}

// -- sign lattice ------------------------------------------------------------

// domainOf reports what is known about the named value. domUnknown when the
// name is absent.
func (t *ECTracker) domainOf(name string) ecDom {
	// A silent desync here would hand a transfer function a fact about the
	// WRONG slot, which is the one failure mode that produces a smaller script
	// that quietly computes something else. Fail loudly instead.
	if len(t.dm) != len(t.nm) {
		panic(fmt.Sprintf(
			"ECTracker: lattice desynchronised (%d slots, %d facts). "+
				"Every nm mutation must go through a tracker method or pushTracked/popTracked.",
			len(t.nm), len(t.dm)))
	}
	for i := len(t.nm) - 1; i >= 0; i-- {
		if t.nm[i] == name {
			return t.dm[i]
		}
	}
	return domUnknown
}

// setDomain records a fact about the named value's slot.
func (t *ECTracker) setDomain(name string, d ecDom) {
	for i := len(t.nm) - 1; i >= 0; i-- {
		if t.nm[i] == name {
			t.dm[i] = d
			return
		}
	}
}

// pushTracked pushes a slot the caller tracks itself (used where raw opcodes
// create items).
func (t *ECTracker) pushTracked(name string, d ecDom) {
	t.nm = append(t.nm, name)
	t.dm = append(t.dm, d)
}

// popTracked pops a slot the caller tracks itself. Mirror of pushTracked.
func (t *ECTracker) popTracked() string {
	if len(t.nm) == 0 {
		return ""
	}
	n := t.nm[len(t.nm)-1]
	t.nm = t.nm[:len(t.nm)-1]
	t.dm = t.dm[:len(t.dm)-1]
	return n
}

// removeSlotAt removes the slot at an absolute (bottom-relative) index.
func (t *ECTracker) removeSlotAt(index int) {
	t.nm = append(t.nm[:index], t.nm[index+1:]...)
	t.dm = append(t.dm[:index], t.dm[index+1:]...)
}

func (t *ECTracker) depth() int { return len(t.nm) }

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
	// A byte blob is not a number until BIN2NUM decides how to read it.
	t.pushTracked(n, domUnknown)
}

func (t *ECTracker) pushBigInt(n string, v *big.Int) {
	t.e(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(v)}})
	d := domUnknown
	if v.Sign() >= 0 {
		d = domNonNegative
	}
	t.pushTracked(n, d)
}

func (t *ECTracker) pushInt(n string, v int64) {
	t.e(StackOp{Op: "push", Value: bigIntPush(v)})
	d := domUnknown
	if v >= 0 {
		d = domNonNegative
	}
	t.pushTracked(n, d)
}

func (t *ECTracker) dup(n string) {
	t.e(StackOp{Op: "dup"})
	d := domUnknown
	if len(t.dm) > 0 {
		d = t.dm[len(t.dm)-1]
	}
	t.pushTracked(n, d)
}

func (t *ECTracker) drop() {
	t.e(StackOp{Op: "drop"})
	t.popTracked()
}

func (t *ECTracker) nip() {
	t.e(StackOp{Op: "nip"})
	L := len(t.nm)
	if L >= 2 {
		t.removeSlotAt(L - 2)
	}
}

func (t *ECTracker) over(n string) {
	t.e(StackOp{Op: "over"})
	d := domUnknown
	if len(t.dm) >= 2 {
		d = t.dm[len(t.dm)-2]
	}
	t.pushTracked(n, d)
}

func (t *ECTracker) swap() {
	t.e(StackOp{Op: "swap"})
	L := len(t.nm)
	if L >= 2 {
		t.nm[L-1], t.nm[L-2] = t.nm[L-2], t.nm[L-1]
		t.dm[L-1], t.dm[L-2] = t.dm[L-2], t.dm[L-1]
	}
}

func (t *ECTracker) rot() {
	t.e(StackOp{Op: "rot"})
	L := len(t.nm)
	if L >= 3 {
		r, rd := t.nm[L-3], t.dm[L-3]
		t.removeSlotAt(L - 3)
		t.pushTracked(r, rd)
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
	t.pushTracked("", domNonNegative)
	t.e(StackOp{Op: "roll", Depth: d})
	t.popTracked() // the depth literal
	idx := len(t.nm) - 1 - d
	r, rd := t.nm[idx], t.dm[idx]
	t.removeSlotAt(idx)
	t.pushTracked(r, rd)
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
	t.pushTracked("", domNonNegative)
	t.e(StackOp{Op: "pick", Depth: d})
	t.popTracked() // the depth literal
	// Once the depth literal is gone the copied slot sits at depth d.
	src := domUnknown
	if idx := len(t.dm) - 1 - d; idx >= 0 {
		src = t.dm[idx]
	}
	t.pushTracked(n, src)
}

func (t *ECTracker) toTop(name string) {
	t.roll(t.findDepth(name))
}

func (t *ECTracker) copyToTop(name, n string) {
	t.pick(t.findDepth(name), n)
}

// -- constant pool -----------------------------------------------------------
//
// A pooled constant is an ordinary tracked slot; nothing about the stack model
// changes. pushConst just chooses, per call site and by emitted bytes, between
// copying that slot and re-pushing the literal. Nested trackers built from
// namesCopy() inherit the slot for free, so pooled constants work unchanged
// inside an OP_IF arm.

func (t *ECTracker) hasSlot(slot string) bool {
	for _, n := range t.nm {
		if n == slot {
			return true
		}
	}
	return false
}

// poolConstant parks value in slot for the lifetime of this emitter. No-op when
// pooling is off.
func (t *ECTracker) poolConstant(slot string, value *big.Int) {
	if !t.pooling || t.hasSlot(slot) {
		return
	}
	t.pushBigInt(slot, value)
}

// releaseConstant removes a pooled slot. No-op when pooling is off or the slot
// is absent.
func (t *ECTracker) releaseConstant(slot string) {
	if !t.pooling || !t.hasSlot(slot) {
		return
	}
	t.toTop(slot)
	t.drop()
}

// constCost is the emitted byte cost a pushConst of this constant would incur
// right now.
//
// The comparison is exact — SizeOfPushBigInt is the same encoder the emit pass
// uses — so pooling can never make a call site bigger. A pick at depth d costs
// SizeOfPushBigInt(d) + 1; depths 0 and 1 are OP_DUP / OP_OVER, 1 byte each.
func (t *ECTracker) constCost(slot string, value *big.Int) int {
	if t.pooling && t.hasSlot(slot) {
		d := t.findDepth(slot)
		pickCost := 1
		if d > 1 {
			pickCost = SizeOfPushBigInt(big.NewInt(int64(d))) + 1
		}
		if pickCost < SizeOfPushBigInt(value) {
			return pickCost
		}
	}
	return SizeOfPushBigInt(value)
}

// pushConst materializes value on top as name, from the pooled slot when that
// is cheaper in emitted bytes than pushing the literal.
func (t *ECTracker) pushConst(slot string, value *big.Int, name string) {
	if t.pooling && t.hasSlot(slot) {
		d := t.findDepth(slot)
		pickCost := 1
		if d > 1 {
			pickCost = SizeOfPushBigInt(big.NewInt(int64(d))) + 1
		}
		if pickCost < SizeOfPushBigInt(value) {
			t.pick(d, name)
			return
		}
	}
	t.pushBigInt(name, value)
}

func (t *ECTracker) toAlt() {
	t.op("OP_TOALTSTACK")
	if len(t.nm) > 0 {
		d := t.dm[len(t.dm)-1]
		t.popTracked()
		t.altDm = append(t.altDm, d)
	}
}

func (t *ECTracker) fromAlt(n string) {
	t.op("OP_FROMALTSTACK")
	d := domUnknown
	if len(t.altDm) > 0 {
		d = t.altDm[len(t.altDm)-1]
		t.altDm = t.altDm[:len(t.altDm)-1]
	}
	t.pushTracked(n, d)
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
		t.popTracked()
	}
	fn(t.e)
	if produce != "" {
		// Opaque opcodes: nothing is known about the result unless the caller
		// proves it and records that with setDomain afterwards.
		t.pushTracked(produce, domUnknown)
	}
}

// emitIf emits if/else with tracked stack effect.
// resultName="" means no result pushed.
func (t *ECTracker) emitIf(condName string, thenFn func(func(StackOp)), elseFn func(func(StackOp)), resultName string) {
	t.toTop(condName)
	t.popTracked() // condition consumed
	var thenOps []StackOp
	var elseOps []StackOp
	thenFn(func(op StackOp) { thenOps = append(thenOps, op) })
	elseFn(func(op StackOp) { elseOps = append(elseOps, op) })
	t.e(StackOp{Op: "if", Then: thenOps, Else: elseOps})
	if resultName != "" {
		// A join over two arms this tracker did not analyse: nothing is known.
		t.pushTracked(resultName, domUnknown)
	}
}

// ===========================================================================
// Field arithmetic helpers
// ===========================================================================

// ecPushFieldP pushes the field prime p onto the stack as a script number.
func ecPushFieldP(t *ECTracker, name string) {
	t.pushConst(ecPoolFieldP, ecFieldP, name)
}

// ecFieldModShort emits `a mod p` with no sign fix-up: 1 opcode instead of 7.
//
// Sound only when the dividend is provably >= 0, because OP_MOD takes the sign
// of the dividend. The caller proves that; this function does not check.
func ecFieldModShort(t *ECTracker, aName, resultName string) {
	t.toTop(aName)
	ecPushFieldP(t, "_fmods_p")
	t.rawBlock([]string{aName, "_fmods_p"}, resultName, func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})
	t.setDomain(resultName, domReduced)
}

// ecFieldMod reduces TOS mod p, ensuring non-negative result.
func ecFieldMod(t *ECTracker, aName, resultName string) {
	if t.sinking && isNonNegative(t.domainOf(aName)) {
		ecFieldModShort(t, aName, resultName)
		return
	}
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
	t.setDomain(resultName, domReduced)
}

// ecFieldAdd computes (a + b) mod p.
func ecFieldAdd(t *ECTracker, aName, bName, resultName string) {
	// Read the operand facts BEFORE rawBlock consumes their slots.
	sumNonNeg := isNonNegative(t.domainOf(aName)) && isNonNegative(t.domainOf(bName))
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_fadd_sum", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	if sumNonNeg {
		t.setDomain("_fadd_sum", domNonNegative)
	}
	ecFieldMod(t, "_fadd_sum", resultName)
}

// ecCheapSubPays reports whether the cheap subtraction shape pays here.
//
// `a - b + p` then one OP_MOD references the prime TWICE; the shipping shape
// references it once and pays six more opcodes. So it only wins when the prime
// is cheap to materialise — i.e. when it is pooled. Without a pool this rewrite
// makes p256-wallet LARGER (958,792 -> 999,371 measured), which is why it is a
// cost comparison and not a flag.
func ecCheapSubPays(t *ECTracker) bool {
	c := t.constCost(ecPoolFieldP, ecFieldP)
	return 2*c+2 < c+8
}

// ecFieldSub computes (a - b) mod p (non-negative).
func ecFieldSub(t *ECTracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	// The cheap shape needs a >= 0 AND b in [0, p): then a - b > -p, so a single
	// shifted reduction is exact. `b >= 0` alone is NOT enough — a coordinate
	// decoded from 32 unsigned bytes can exceed p by up to 2^32 + 977, which is
	// precisely the ecAdd((0,1), (2^256-1,1)) counterexample.
	cheap := t.sinking &&
		isNonNegative(t.domainOf(aName)) &&
		t.domainOf(bName) == domReduced &&
		ecCheapSubPays(t)

	t.rawBlock([]string{aName, bName}, "_fsub_diff", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_SUB"})
	})

	if cheap {
		ecPushFieldP(t, "_fsub_p")
		t.rawBlock([]string{"_fsub_diff", "_fsub_p"}, "_fsub_shift", func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_ADD"})
		})
		t.setDomain("_fsub_shift", domNonNegative)
		ecFieldModShort(t, "_fsub_shift", resultName)
		return
	}
	ecFieldMod(t, "_fsub_diff", resultName)
}

// ecFieldMul computes (a * b) mod p.
func ecFieldMul(t *ECTracker, aName, bName, resultName string) {
	ecFieldMulSigned(t, aName, bName, resultName, false)
}

// ecFieldMulSigned is ecFieldMul with an explicit assertion about the product's
// sign, independent of the operands — ecFieldSqr uses it, since a*a >= 0 for any
// a whatsoever.
func ecFieldMulSigned(t *ECTracker, aName, bName, resultName string, productNonNegative bool) {
	nonNeg := productNonNegative ||
		(isNonNegative(t.domainOf(aName)) && isNonNegative(t.domainOf(bName)))
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, "_fmul_prod", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
	if nonNeg {
		t.setDomain("_fmul_prod", domNonNegative)
	}
	ecFieldMod(t, "_fmul_prod", resultName)
}

// ecFieldMulConst computes (a * c) mod p where c is a small constant.
func ecFieldMulConst(t *ECTracker, aName string, c int64, resultName string) {
	// Every call site passes a small positive c, so the product keeps a's sign.
	nonNeg := c > 0 && isNonNegative(t.domainOf(aName))
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
	if nonNeg {
		t.setDomain("_fmc_prod", domNonNegative)
	}
	ecFieldMod(t, "_fmc_prod", resultName)
}

// ecFieldSqr computes (a * a) mod p. A square is non-negative whatever a's sign is.
func ecFieldSqr(t *ECTracker, aName, resultName string) {
	t.copyToTop(aName, "_fsqr_copy")
	ecFieldMulSigned(t, aName, "_fsqr_copy", resultName, true)
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

// ecDecomposePoint decomposes a 64-byte Point into (x_num, y_num) on stack.
// Consumes pointName, produces xName and yName.
func ecDecomposePoint(t *ECTracker, pointName, xName, yName string) {
	t.toTop(pointName)
	// OP_SPLIT at 32 produces x_bytes (bottom) and y_bytes (top)
	t.rawBlock([]string{pointName}, "", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(32)})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	})
	// Manually track the two new items
	t.pushTracked("_dp_xb", domUnknown)
	t.pushTracked("_dp_yb", domUnknown)

	// Convert y_bytes (on top) to num
	// Reverse from BE to LE, append 0x00 sign byte to ensure unsigned, then BIN2NUM
	t.rawBlock([]string{"_dp_yb"}, yName, func(e func(StackOp)) {
		ecEmitReverse32(e)
		e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	})
	// A 0x00 sign byte is appended before BIN2NUM, so the coordinate decodes
	// UNSIGNED: >= 0, but it may be up to 2^256 - 1 and therefore >= p. That gap
	// is exactly what the subtraction precondition turns on.
	t.setDomain(yName, domNonNegative)

	// Convert x_bytes to num
	t.toTop("_dp_xb")
	t.rawBlock([]string{"_dp_xb"}, xName, func(e func(StackOp)) {
		ecEmitReverse32(e)
		e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{0x00}}})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	})
	t.setDomain(xName, domNonNegative)

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

	// Clean up original points
	t.toTop("px")
	t.drop()
	t.toTop("py")
	t.drop()
	t.toTop("qx")
	t.drop()
	t.toTop("qy")
	t.drop()

	// P == -Q -> force the all-zero point (see the header comment).
	t.toTop("rx")
	t.copyToTop("_notinf", "_notinf_x")
	t.rawBlock([]string{"rx", "_notinf_x"}, "rx", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
	t.toTop("ry")
	t.toTop("_notinf")
	t.rawBlock([]string{"ry", "_notinf"}, "ry", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
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
	// Create inner tracker with cloned stack state AND lattice facts: the
	// operands' proved domains are what decide which reduction shape the body
	// emits, so dropping them here would silently fall back everywhere.
	ecJacobianAddAffineBody(NewECTrackerOpts(t.namesCopy(), e, t.options(), t.domainsCopy()), false)
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
	it := NewECTrackerOpts(t.namesCopy(), e, t.options(), t.domainsCopy())

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

// EmitEcAdd adds two points.
// Stack in: [point_a, point_b] (b on top)
// Stack out: [result_point]
func EmitEcAdd(emit func(StackOp), opts *EcCodegenOptions) {
	t := NewECTrackerOpts([]string{"_pa", "_pb"}, emit, opts, nil)
	t.poolConstant(ecPoolFieldP, ecFieldP)
	ecDecomposePoint(t, "_pa", "px", "py")
	ecDecomposePoint(t, "_pb", "qx", "qy")
	ecAffineAdd(t)
	ecComposePoint(t, "rx", "ry", "_result")
	t.releaseConstant(ecPoolFieldP)
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
	t.pushConst(ecPoolGroupN, n, "_n_red")
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
func EmitEcMul(emit func(StackOp), opts *EcCodegenOptions) {
	t := NewECTrackerOpts([]string{"_pt", "_k"}, emit, opts, nil)
	t.poolConstant(ecPoolFieldP, ecFieldP)
	t.poolConstant(ecPoolGroupN, ecCurveN)
	// Decompose to affine base point
	ecDecomposePoint(t, "_pt", "ax", "ay")

	// k' = k + 3n: guarantees bit 257 is set.
	// k ∈ [1, n-1], so k+3n ∈ [3n+1, 4n-1]. Since 3n > 2^257, bit 257
	// is always 1. Adding 3n (≡ 0 mod n) preserves the EC point: k*G = (k+3n)*G.
	//
	// "k ∈ [1, n-1]" is a PRECONDITION the caller cannot enforce — the scalar is
	// usually an unlock argument — so reduce it first. See ecEmitScalarReduce.
	t.toTop("_k")
	ecEmitScalarReduce(t, "_k", "_kr", ecCurveN)
	t.pushConst(ecPoolGroupN, ecCurveN, "_n")
	t.rawBlock([]string{"_kr", "_n"}, "_kn", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.pushConst(ecPoolGroupN, ecCurveN, "_n2")
	t.rawBlock([]string{"_kn", "_n2"}, "_kn2", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.pushConst(ecPoolGroupN, ecCurveN, "_n3")
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
		t.popTracked() // _bit consumed by IF
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
	t.releaseConstant(ecPoolGroupN)
	t.releaseConstant(ecPoolFieldP)
}

// ===========================================================================
// Fixed-base comb (secp256k1)
// ===========================================================================

// ecEmitCombMulGen emits k*G by a Lim-Lee fixed-base comb instead of the
// 257-round binary ladder, returning false when no geometry exists for w.
//
// The ladder doubles and conditionally adds once per SCALAR BIT. A comb splits
// the scalar into w blocks of d bits and reads one bit from each block per
// round, so it performs one doubling and one conditional add per COLUMN: the
// round count falls from w*d to d at the price of a 2^w - 1 entry table. G is a
// compile-time constant here, so the table costs nothing to build — it is
// 2*(2^w - 1) literal pushes, resident for the whole emitter, read by every
// round with a 2-3 byte OP_PICK.
//
// This is the secp256k1 twin of cEmitCombMulGen in p256_p384.go. The curve
// arithmetic is NOT shared: secp256k1 has a = 0, so ecJacobianDouble computes
// D = 3X^2 where the NIST version computes 3(X-Z^2)(X+Z^2). Only comb.go — the
// compile-time table and the interval checker — is common, and it takes a from
// the curve record rather than assuming it.
//
// SOUNDNESS. The cheap incomplete mixed add cannot represent a pre-add
// accumulator equal to the addend, its negation, or the point at infinity.
// ecBuildJacobianAddOrDoubleInline's comment justifies using it everywhere but
// the ladder's LAST step by an interval argument over c_i mod n, and insists
// that argument be re-derived by anything changing the offset or the iteration
// count. A comb changes both, so it is re-derived: CombSafeRounds evaluates the
// same argument as executable interval arithmetic over the comb's own geometry,
// and any round it cannot prove gets the complete add-or-double form instead.
// Nothing is assumed safe.
//
// The other half of that argument is that the accumulator never starts at
// infinity, which needs the first digit non-zero. CombGeometry searches for the
// scalar offset that guarantees it rather than reusing the ladder's hardcoded
// +3n — which happens to be right for secp256k1 at w=3 and is wrong for P-384.
//
// Stack in: [_k]. Stack out: [_result].
func ecEmitCombMulGen(emit func(StackOp), w int, opts *EcCodegenOptions) bool {
	curve := Secp256k1CombCurve
	params := CombGeometry(w, curve)
	if params == nil {
		return false
	}
	d := params.D
	table := CombTable(w, d, curve)
	safe := CombSafeRounds(params, curve)
	entries := (1 << w) - 1

	t := NewECTrackerOpts([]string{"_k"}, emit, opts, nil)
	t.poolConstant(ecPoolFieldP, ecFieldP)
	t.poolConstant(ecPoolGroupN, ecCurveN)

	// k' = (k mod n) + m*n. The reduce is what confines k to [0, n-1] and so
	// what makes the interval argument apply at all; see ecEmitScalarReduce.
	t.toTop("_k")
	ecEmitScalarReduce(t, "_k", "_kr", ecCurveN)
	t.rename("_k")
	for i := int64(0); i < params.OffsetMultiple.Int64(); i++ {
		off := fmt.Sprintf("_off%d", i)
		t.pushConst(ecPoolGroupN, ecCurveN, off)
		t.rawBlock([]string{"_k", off}, "_k", func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_ADD"})
		})
	}
	t.setDomain("_k", domNonNegative)

	// Table, resident for the whole comb: picking an entry costs 2-3 bytes
	// against a 34-byte literal push, and every round reads all of them.
	for j := 1; j <= entries; j++ {
		t.pushBigInt(fmt.Sprintf("_Tx%d", j), table[j].X)
		t.pushBigInt(fmt.Sprintf("_Ty%d", j), table[j].Y)
		t.setDomain(fmt.Sprintf("_Tx%d", j), domReduced)
		t.setDomain(fmt.Sprintf("_Ty%d", j), domReduced)
	}

	// emitSelect materializes round i's digit and the selected table entry as
	// ax/ay/_flag.
	//
	// Exactly one equality holds, so sum(eq_j * T_j) is that entry's coordinate
	// and every term is non-negative and below p — no reduction is needed, and
	// the result is domReduced by construction. When the digit is zero every
	// term vanishes and _flag is 0, so no add runs.
	emitSelect := func(i int) {
		for b := 0; b < w; b++ {
			shift := i + b*d
			kc := fmt.Sprintf("_kc%d", b)
			sh := fmt.Sprintf("_sh%d", b)
			t.copyToTop("_k", kc)
			if shift == 0 {
				t.rename(sh)
			} else if shift == 1 {
				t.rawBlock([]string{kc}, sh, func(e func(StackOp)) {
					e(StackOp{Op: "opcode", Code: "OP_2DIV"})
				})
			} else {
				sd := fmt.Sprintf("_sd%d", b)
				t.pushInt(sd, int64(shift))
				t.rawBlock([]string{kc, sd}, sh, func(e func(StackOp)) {
					e(StackOp{Op: "opcode", Code: "OP_RSHIFTNUM"})
				})
			}
			two := fmt.Sprintf("_two%d", b)
			bit := fmt.Sprintf("_b%d", b)
			t.pushInt(two, 2)
			t.rawBlock([]string{sh, two}, bit, func(e func(StackOp)) {
				e(StackOp{Op: "opcode", Code: "OP_MOD"})
			})
			t.setDomain(bit, domReduced)
		}

		t.toTop("_b0")
		t.rename("_idx")
		for b := 1; b < w; b++ {
			bit := fmt.Sprintf("_b%d", b)
			wt := fmt.Sprintf("_wt%d", b)
			bw := fmt.Sprintf("_bw%d", b)
			t.toTop(bit)
			t.pushInt(wt, int64(1<<b))
			t.rawBlock([]string{bit, wt}, bw, func(e func(StackOp)) {
				e(StackOp{Op: "opcode", Code: "OP_MUL"})
			})
			t.toTop("_idx")
			t.rawBlock([]string{bw, "_idx"}, "_idx", func(e func(StackOp)) {
				e(StackOp{Op: "opcode", Code: "OP_ADD"})
			})
		}
		t.setDomain("_idx", domReduced)

		for j := 1; j <= entries; j++ {
			ic := fmt.Sprintf("_ic%d", j)
			jv := fmt.Sprintf("_jv%d", j)
			eq := fmt.Sprintf("_eq%d", j)
			t.copyToTop("_idx", ic)
			t.pushInt(jv, int64(j))
			t.rawBlock([]string{ic, jv}, eq, func(e func(StackOp)) {
				e(StackOp{Op: "opcode", Code: "OP_NUMEQUAL"})
			})
			t.setDomain(eq, domReduced)
		}

		for _, coord := range []string{"x", "y"} {
			acc := "ax"
			if coord == "y" {
				acc = "ay"
			}
			for j := 1; j <= entries; j++ {
				ec := fmt.Sprintf("_e%s%d", coord, j)
				tc := fmt.Sprintf("_t%s%d", coord, j)
				pr := fmt.Sprintf("_pr%s%d", coord, j)
				t.copyToTop(fmt.Sprintf("_eq%d", j), ec)
				t.copyToTop(fmt.Sprintf("_T%s%d", coord, j), tc)
				t.rawBlock([]string{ec, tc}, pr, func(e func(StackOp)) {
					e(StackOp{Op: "opcode", Code: "OP_MUL"})
				})
				if j == 1 {
					t.rename(acc)
				} else {
					t.toTop(acc)
					t.rawBlock([]string{pr, acc}, acc, func(e func(StackOp)) {
						e(StackOp{Op: "opcode", Code: "OP_ADD"})
					})
				}
			}
			t.setDomain(acc, domReduced)
		}

		for j := entries; j >= 1; j-- {
			t.toTop(fmt.Sprintf("_eq%d", j))
			t.drop()
		}

		t.toTop("_idx")
		t.rawBlock([]string{"_idx"}, "_flag", func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_0NOTEQUAL"})
		})
	}

	// Round d-1 initialises the accumulator. The first digit is non-zero by
	// construction (CombGeometry), so this is a real point and never infinity.
	emitSelect(d - 1)
	t.toTop("_flag")
	t.drop()
	t.toTop("ax")
	t.rename("jx")
	t.toTop("ay")
	t.rename("jy")
	t.pushInt("jz", 1)
	t.setDomain("jz", domReduced)

	for i := d - 2; i >= 0; i-- {
		ecJacobianDouble(t)
		emitSelect(i)

		// ecJacobianAddAffineBody documents its layout as [..., ax, ay, jx, jy,
		// jz] and replaces the accumulator IN PLACE at the top. The selection
		// leaves ax/ay above jz, so restore the contract before the branch —
		// otherwise the add arm would reorder the stack and the empty else arm
		// would not, leaving the two arms with different layouts at OP_ENDIF.
		t.toTop("_flag")
		t.toAlt()
		t.toTop("jx")
		t.toTop("jy")
		t.toTop("jz")
		t.fromAlt("_flag")

		t.popTracked() // consumed by OP_IF
		var addOps []StackOp
		addEmit := func(op StackOp) { addOps = append(addOps, op) }
		if safe[i] {
			ecBuildJacobianAddAffineInline(addEmit, t)
		} else {
			ecBuildJacobianAddOrDoubleInline(addEmit, t)
		}
		emit(StackOp{Op: "if", Then: addOps, Else: []StackOp{}})

		// The addend was selected fresh for this round; the add only copied it.
		t.toTop("ay")
		t.drop()
		t.toTop("ax")
		t.drop()
	}

	ecJacobianToAffine(t, "_rx", "_ry")

	for j := entries; j >= 1; j-- {
		t.toTop(fmt.Sprintf("_Ty%d", j))
		t.drop()
		t.toTop(fmt.Sprintf("_Tx%d", j))
		t.drop()
	}
	t.toTop("_k")
	t.drop()

	ecComposePoint(t, "_rx", "_ry", "_result")
	t.releaseConstant(ecPoolGroupN)
	t.releaseConstant(ecPoolFieldP)
	return true
}

// ecEmitCombBest emits the cheapest comb over the candidate window widths.
//
// Each candidate is rendered in full and scored with the same byte-cost model
// the emitter is measured by, and the smallest wins — the window width is not
// hardcoded. w=1 is the binary ladder and is excluded; beyond w=4 the 2^w
// selection logic outgrows the saving.
//
// Returns nil when no candidate could be built, so the caller falls back to the
// ladder rather than emitting nothing.
func ecEmitCombBest(opts *EcCodegenOptions) []StackOp {
	var best []StackOp
	for _, w := range []int{2, 3, 4} {
		var ops []StackOp
		if !ecEmitCombMulGen(func(op StackOp) { ops = append(ops, op) }, w, opts) {
			continue
		}
		if best == nil || EstimateScriptBytes(ops) < EstimateScriptBytes(best) {
			best = ops
		}
	}
	return best
}

// EmitEcMulGen performs scalar multiplication G * k.
// Stack in: [scalar]
// Stack out: [result_point]
func EmitEcMulGen(emit func(StackOp), opts *EcCodegenOptions) {
	// G is a compile-time constant, so this is the one secp256k1 call site where
	// a fixed-base comb applies. EmitEcMul cannot use it: its base arrives at
	// run time.
	if opts != nil && opts.FixedBaseComb {
		if ops := ecEmitCombBest(opts); ops != nil {
			for _, op := range ops {
				emit(op)
			}
			return
		}
	}

	// Push generator point as 64-byte blob, then delegate to ecMul
	gPoint := make([]byte, 64)
	copy(gPoint[0:32], bigintToBytes32(ecGenX))
	copy(gPoint[32:64], bigintToBytes32(ecGenY))
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: gPoint}})
	emit(StackOp{Op: "swap"}) // [point, scalar]
	EmitEcMul(emit, opts)
}

// EmitEcNegate negates a point (x, p - y).
// Stack in: [point]
// Stack out: [negated_point]
func EmitEcNegate(emit func(StackOp), opts *EcCodegenOptions) {
	t := NewECTrackerOpts([]string{"_pt"}, emit, opts, nil)
	t.poolConstant(ecPoolFieldP, ecFieldP)
	ecDecomposePoint(t, "_pt", "_nx", "_ny")
	ecPushFieldP(t, "_fp")
	ecFieldSub(t, "_fp", "_ny", "_neg_y")
	ecComposePoint(t, "_nx", "_neg_y", "_result")
	t.releaseConstant(ecPoolFieldP)
}

// EmitEcOnCurve checks if point is on secp256k1 (y^2 = x^3 + 7 mod p).
// Stack in: [point]
// Stack out: [boolean]
func EmitEcOnCurve(emit func(StackOp), opts *EcCodegenOptions) {
	t := NewECTrackerOpts([]string{"_pt"}, emit, opts, nil)
	t.poolConstant(ecPoolFieldP, ecFieldP)
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

	// on-curve = canonical AND curve-equation
	t.toTop("_canon")
	t.toTop("_curve_eq")
	t.rawBlock([]string{"_canon", "_curve_eq"}, "_result", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_BOOLAND"})
	})
	t.releaseConstant(ecPoolFieldP)
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
	// Split at 32: [x_bytes, y_bytes]
	emit(StackOp{Op: "push", Value: bigIntPush(32)})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	// Get last byte of y for parity
	emit(StackOp{Op: "opcode", Code: "OP_SIZE"})
	emit(StackOp{Op: "push", Value: bigIntPush(1)})
	emit(StackOp{Op: "opcode", Code: "OP_SUB"})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
	// Stack: [x_bytes, y_prefix, last_byte]
	emit(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
	emit(StackOp{Op: "push", Value: bigIntPush(2)})
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})
	// Stack: [x_bytes, y_prefix, parity]
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "drop"}) // drop y_prefix
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
