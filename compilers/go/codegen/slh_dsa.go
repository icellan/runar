// SLH-DSA (FIPS 205) Bitcoin Script codegen for the Rúnar Go stack lowerer.
//
// Splice into LoweringContext in stack.go. All helpers self-contained.
// Entry: lowerVerifySLHDSA() → calls EmitVerifySLHDSA().
//
// Alt-stack convention: pkSeedPad (64 bytes) on alt permanently.
// Tweakable hash pops pkSeedPad, DUPs, pushes copy back, uses original.
//
// Compile-time ADRS: treeAddr=0, keypair=0 where runtime values needed.
// WOTS+ chain hashAddress built dynamically from a counter on the stack.
package codegen

import (
	"fmt"
	"math"
	"math/big"
)

// ===========================================================================
// 1. Parameter Sets (FIPS 205 Table 1, SHA2)
// ===========================================================================

// SLHCodegenParams holds the SLH-DSA parameter set for codegen.
type SLHCodegenParams struct {
	N    int // Security parameter (hash bytes): 16, 24, 32
	H    int // Total tree height
	D    int // Hypertree layers
	HP   int // Subtree height (h/d)
	A    int // FORS tree height
	K    int // FORS tree count
	W    int // Winternitz parameter (16)
	Len  int // WOTS+ chain count
	Len1 int // Message chains (2*n)
	Len2 int // Checksum chains (3 for all SHA2 sets)
}

func slhMk(n, h, d, a, k int) SLHCodegenParams {
	len1 := 2 * n
	len2 := int(math.Floor(math.Log2(float64(len1*15))/math.Log2(16))) + 1
	return SLHCodegenParams{
		N: n, H: h, D: d, HP: h / d, A: a, K: k, W: 16,
		Len: len1 + len2, Len1: len1, Len2: len2,
	}
}

// SLHParams maps parameter-set names to their codegen parameters.
var SLHParams = map[string]SLHCodegenParams{
	"SHA2_128s": slhMk(16, 63, 7, 12, 14),
	"SHA2_128f": slhMk(16, 66, 22, 6, 33),
	"SHA2_192s": slhMk(24, 63, 7, 14, 17),
	"SHA2_192f": slhMk(24, 66, 22, 8, 33),
	"SHA2_256s": slhMk(32, 64, 8, 14, 22),
	"SHA2_256f": slhMk(32, 68, 17, 8, 35),
}

// ===========================================================================
// 2. Compressed ADRS (22 bytes)
// ===========================================================================
// [0] layer  [1..8] tree  [9] type  [10..13] keypair
// [14..17] chain/treeHeight  [18..21] hash/treeIndex

const (
	slhWOTSHash  = 0
	slhWOTSPK    = 1
	slhTree      = 2
	slhFORSTree  = 3
	slhFORSRoots = 4
)

type slhADRSOpts struct {
	layer   int
	tree    int64
	adrsTyp int
	keypair int
	chain   int
	hash    int
}

func slhADRS(opts slhADRSOpts) []byte {
	c := make([]byte, 22)
	c[0] = byte(opts.layer & 0xff)
	tr := opts.tree
	for i := 0; i < 8; i++ {
		c[1+7-i] = byte((tr >> (8 * i)) & 0xff)
	}
	c[9] = byte(opts.adrsTyp & 0xff)
	kp := opts.keypair
	c[10] = byte((kp >> 24) & 0xff)
	c[11] = byte((kp >> 16) & 0xff)
	c[12] = byte((kp >> 8) & 0xff)
	c[13] = byte(kp & 0xff)
	ch := opts.chain
	c[14] = byte((ch >> 24) & 0xff)
	c[15] = byte((ch >> 16) & 0xff)
	c[16] = byte((ch >> 8) & 0xff)
	c[17] = byte(ch & 0xff)
	ha := opts.hash
	c[18] = byte((ha >> 24) & 0xff)
	c[19] = byte((ha >> 16) & 0xff)
	c[20] = byte((ha >> 8) & 0xff)
	c[21] = byte(ha & 0xff)
	return c
}

// slhADRS18 returns the 18-byte prefix (bytes 0..17): everything before hashAddress.
func slhADRS18(opts slhADRSOpts) []byte {
	full := slhADRS(slhADRSOpts{
		layer: opts.layer, tree: opts.tree, adrsTyp: opts.adrsTyp,
		keypair: opts.keypair, chain: opts.chain, hash: 0,
	})
	return full[:18]
}

// ===========================================================================
// 3. SLH Stack Tracker
// ===========================================================================

// SLHTracker tracks named stack positions and emits StackOps.
type SLHTracker struct {
	nm []string // stack names ("" for anonymous)
	e  func(StackOp)
}

// NewSLHTracker creates a new tracker with initial named stack slots.
func NewSLHTracker(init []string, emit func(StackOp)) *SLHTracker {
	nm := make([]string, len(init))
	copy(nm, init)
	return &SLHTracker{nm: nm, e: emit}
}

func (t *SLHTracker) depth() int { return len(t.nm) }

func (t *SLHTracker) findDepth(name string) int {
	for i := len(t.nm) - 1; i >= 0; i-- {
		if t.nm[i] == name {
			return len(t.nm) - 1 - i
		}
	}
	panic(fmt.Sprintf("SLHTracker: '%s' not on stack %v", name, t.nm))
}

func (t *SLHTracker) has(name string) bool {
	for _, s := range t.nm {
		if s == name {
			return true
		}
	}
	return false
}

func (t *SLHTracker) pushBytes(n string, v []byte) {
	t.e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: v}})
	t.nm = append(t.nm, n)
}

func (t *SLHTracker) pushInt(n string, v int64) {
	t.e(StackOp{Op: "push", Value: bigIntPush(v)})
	t.nm = append(t.nm, n)
}

func (t *SLHTracker) pushEmpty(n string) {
	t.e(StackOp{Op: "opcode", Code: "OP_0"})
	t.nm = append(t.nm, n)
}

func (t *SLHTracker) dup(n string) {
	t.e(StackOp{Op: "dup"})
	t.nm = append(t.nm, n)
}

func (t *SLHTracker) drop() {
	t.e(StackOp{Op: "drop"})
	if len(t.nm) > 0 {
		t.nm = t.nm[:len(t.nm)-1]
	}
}

func (t *SLHTracker) nip() {
	t.e(StackOp{Op: "nip"})
	L := len(t.nm)
	if L >= 2 {
		t.nm = append(t.nm[:L-2], t.nm[L-1])
	}
}

func (t *SLHTracker) over(n string) {
	t.e(StackOp{Op: "over"})
	t.nm = append(t.nm, n)
}

func (t *SLHTracker) swap() {
	t.e(StackOp{Op: "swap"})
	L := len(t.nm)
	if L >= 2 {
		t.nm[L-1], t.nm[L-2] = t.nm[L-2], t.nm[L-1]
	}
}

func (t *SLHTracker) rot() {
	t.e(StackOp{Op: "rot"})
	L := len(t.nm)
	if L >= 3 {
		r := t.nm[L-3]
		t.nm = append(t.nm[:L-3], t.nm[L-2:]...)
		t.nm = append(t.nm, r)
	}
}

func (t *SLHTracker) op(code string) {
	t.e(StackOp{Op: "opcode", Code: code})
}

func (t *SLHTracker) roll(d int) {
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
	t.e(StackOp{Op: "opcode", Code: "OP_ROLL"})
	t.nm = t.nm[:len(t.nm)-1] // pop the push
	idx := len(t.nm) - 1 - d
	r := t.nm[idx]
	t.nm = append(t.nm[:idx], t.nm[idx+1:]...)
	t.nm = append(t.nm, r)
}

func (t *SLHTracker) pick(d int, n string) {
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
	t.e(StackOp{Op: "opcode", Code: "OP_PICK"})
	t.nm = t.nm[:len(t.nm)-1] // pop the push
	t.nm = append(t.nm, n)
}

func (t *SLHTracker) toTop(name string) {
	t.roll(t.findDepth(name))
}

func (t *SLHTracker) copyToTop(name, n string) {
	t.pick(t.findDepth(name), n)
}

func (t *SLHTracker) toAlt() {
	t.op("OP_TOALTSTACK")
	if len(t.nm) > 0 {
		t.nm = t.nm[:len(t.nm)-1]
	}
}

func (t *SLHTracker) fromAlt(n string) {
	t.op("OP_FROMALTSTACK")
	t.nm = append(t.nm, n)
}

func (t *SLHTracker) split(left, right string) {
	t.op("OP_SPLIT")
	if len(t.nm) >= 1 {
		t.nm = t.nm[:len(t.nm)-1]
	}
	// OP_SPLIT replaces TOS with two values: left (below), right (on top)
	// But we already popped one, and the original was one item, so net +1.
	// Actually: input is 2 items (value, position). OP_SPLIT pops both, pushes left and right.
	if len(t.nm) >= 1 {
		t.nm = t.nm[:len(t.nm)-1]
	}
	t.nm = append(t.nm, left)
	t.nm = append(t.nm, right)
}

func (t *SLHTracker) cat(n string) {
	t.op("OP_CAT")
	if len(t.nm) >= 2 {
		t.nm = t.nm[:len(t.nm)-2]
	}
	t.nm = append(t.nm, n)
}

func (t *SLHTracker) sha256(n string) {
	t.op("OP_SHA256")
	if len(t.nm) >= 1 {
		t.nm = t.nm[:len(t.nm)-1]
	}
	t.nm = append(t.nm, n)
}

func (t *SLHTracker) equal(n string) {
	t.op("OP_EQUAL")
	if len(t.nm) >= 2 {
		t.nm = t.nm[:len(t.nm)-2]
	}
	t.nm = append(t.nm, n)
}

func (t *SLHTracker) rename(n string) {
	if len(t.nm) > 0 {
		t.nm[len(t.nm)-1] = n
	}
}

// rawBlock emits raw opcodes; tracker only records net stack effect.
func (t *SLHTracker) rawBlock(consume []string, produce string, fn func(emit func(StackOp))) {
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

// ===========================================================================
// 4. Tweakable Hash T(pkSeed, ADRS, M)
// ===========================================================================
// trunc_n(SHA-256(pkSeedPad(64) || ADRSc(22) || M))
// pkSeedPad on alt; pop, DUP, push back, use.

// emitSLHT emits a tracked tweakable hash.
func emitSLHT(t *SLHTracker, n int, adrs, msg, result string) {
	t.toTop(adrs)
	t.toTop(msg)
	t.cat("_am")
	t.fromAlt("_psp")
	t.dup("_psp2")
	t.toAlt()
	t.swap()
	t.cat("_pre")
	t.sha256("_h32")
	if n < 32 {
		t.pushInt("", int64(n))
		t.split(result, "_tr")
		t.drop()
	} else {
		t.rename(result)
	}
}

// emitSLHTRaw emits a raw tweakable hash. Stack: adrsC(1) msg(0) -> result(n). pkSeedPad on alt.
func emitSLHTRaw(e func(StackOp), n int) {
	e(StackOp{Op: "opcode", Code: "OP_CAT"})
	e(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	e(StackOp{Op: "opcode", Code: "OP_DUP"})
	e(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
	e(StackOp{Op: "swap"})
	e(StackOp{Op: "opcode", Code: "OP_CAT"})
	e(StackOp{Op: "opcode", Code: "OP_SHA256"})
	if n < 32 {
		e(StackOp{Op: "push", Value: bigIntPush(int64(n))})
		e(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		e(StackOp{Op: "drop"})
	}
}

// ===========================================================================
// 5. WOTS+ One Chain (tweakable hash, dynamic hashAddress)
// ===========================================================================

// slhChainStepThen returns one conditional hash step (if-then body).
//
// Entry: sigElem(2) steps(1) hashAddr(0)
// Exit:  newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
func slhChainStepThen(adrsPrefix []byte, n int) []StackOp {
	ops := []StackOp{}
	// DUP hashAddr before consuming it in ADRS construction
	ops = append(ops, StackOp{Op: "dup"})
	// sigElem(3) steps(2) hashAddr(1) hashAddr_copy(0)
	// Convert copy to 4-byte big-endian
	ops = append(ops, StackOp{Op: "push", Value: bigIntPush(4)})
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_REVERSE"})
	// Build ADRS = prefix(18) || hashAddrBE(4)
	ops = append(ops, StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: adrsPrefix}})
	ops = append(ops, StackOp{Op: "swap"})
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_CAT"})
	// sigElem(3) steps(2) hashAddr(1) adrsC(0)
	// Move sigElem to top: ROLL 3
	ops = append(ops, StackOp{Op: "push", Value: bigIntPush(3)})
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_ROLL"})
	// steps(2) hashAddr(1) adrsC(0) sigElem(top)
	// CAT: adrsC(1) || sigElem(0) -> adrsC||sigElem
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_CAT"})
	// steps(1) hashAddr(0) (adrsC||sigElem)(top)
	// pkSeedPad from alt
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_DUP"})
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
	// steps(2) hashAddr(1) (adrsC||sigElem)(0) pkSeedPad(top)
	ops = append(ops, StackOp{Op: "swap"})
	// steps(2) hashAddr(1) pkSeedPad(0) (adrsC||sigElem)(top)
	// CAT: pkSeedPad || (adrsC||sigElem)
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_CAT"})
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_SHA256"})
	if n < 32 {
		ops = append(ops, StackOp{Op: "push", Value: bigIntPush(int64(n))})
		ops = append(ops, StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ops = append(ops, StackOp{Op: "drop"})
	}
	// steps(2) hashAddr(1) newSigElem(0)
	// Rearrange -> newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
	// ROT: brings steps(depth 2) to top
	ops = append(ops, StackOp{Op: "rot"})
	// hashAddr(1) newSigElem(0) steps(top)
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_1SUB"})
	// hashAddr(1) newSigElem(0) (steps-1)(top)
	// ROT: brings hashAddr(depth 2) to top
	ops = append(ops, StackOp{Op: "rot"})
	// newSigElem(1) (steps-1)(0) hashAddr(top)
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_1ADD"})
	// newSigElem(1) (steps-1)(0) (hashAddr+1)(top)
	// Save (hashAddr+1), swap bottom two, restore
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
	ops = append(ops, StackOp{Op: "swap"})
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	// newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
	return ops
}

// emitSLHOneChain emits one WOTS+ chain with tweakable hashing (raw opcodes).
//
// Input:  sig(3) csum(2) endptAcc(1) digit(0)
// Output: sigRest(2) newCsum(1) newEndptAcc(0)
// Alt: pkSeedPad persists. 4 internal push/pop balanced.
func emitSLHOneChain(emit func(StackOp), n, layer, chainIdx int) {
	// Input: sig(3) csum(2) endptAcc(1) digit(0)

	// steps = 15 - digit
	emit(StackOp{Op: "push", Value: bigIntPush(15)})
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "opcode", Code: "OP_SUB"})
	// sig(3) csum(2) endptAcc(1) steps(0)

	// Save steps_copy, endptAcc, csum to alt
	emit(StackOp{Op: "opcode", Code: "OP_DUP"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // alt: steps_copy
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // alt: steps_copy, endptAcc
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // alt: steps_copy, endptAcc, csum(top)
	// main: sig(1) steps(0)

	// Split n-byte sig element
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "push", Value: bigIntPush(int64(n))})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})       // steps sigElem sigRest
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // alt: ..., csum, sigRest(top)
	emit(StackOp{Op: "swap"})
	// main: sigElem(1) steps(0)

	// Compute hashAddr = 15 - steps (= digit) on main stack
	emit(StackOp{Op: "opcode", Code: "OP_DUP"})
	emit(StackOp{Op: "push", Value: bigIntPush(15)})
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "opcode", Code: "OP_SUB"})
	// main: sigElem(2) steps(1) hashAddr(0)

	// Build ADRS prefix for this chain
	prefix := slhADRS18(slhADRSOpts{layer: layer, adrsTyp: slhWOTSHash, chain: chainIdx})
	thenOps := slhChainStepThen(prefix, n)

	// 15 unrolled conditional hash iterations
	for j := 0; j < 15; j++ {
		// sigElem(2) steps(1) hashAddr(0)
		// Check steps > 0: OVER copies steps (depth 1) to top
		emit(StackOp{Op: "over"})
		emit(StackOp{Op: "opcode", Code: "OP_0NOTEQUAL"})
		emit(StackOp{Op: "if", Then: thenOps})
	}

	// endpoint(2) 0(1) finalHashAddr(0)
	emit(StackOp{Op: "drop"})
	emit(StackOp{Op: "drop"})
	// main: endpoint

	// Restore from alt (LIFO): sigRest, csum, endptAcc, steps_copy
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // sigRest
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // csum
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // endptAcc
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // steps_copy
	// bottom->top: endpoint sigRest csum endptAcc steps_copy

	// csum += steps_copy: ROT top-3 to bring csum up
	emit(StackOp{Op: "rot"})
	emit(StackOp{Op: "opcode", Code: "OP_ADD"})
	// endpoint sigRest endptAcc newCsum

	// Cat endpoint to endptAcc
	emit(StackOp{Op: "swap"})
	// endpoint sigRest newCsum endptAcc
	emit(StackOp{Op: "push", Value: bigIntPush(3)})
	emit(StackOp{Op: "opcode", Code: "OP_ROLL"})
	// sigRest newCsum endptAcc endpoint
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	// sigRest(2) newCsum(1) newEndptAcc(0)
}

// ===========================================================================
// Full WOTS+ Processing (all len chains)
// ===========================================================================
// Input:  wotsSig(len*n)(1) msg(n)(0)
// Output: wotsPk(n)

func emitSLHWotsAll(emit func(StackOp), p SLHCodegenParams, layer int) {
	n := p.N
	len1 := p.Len1
	len2 := p.Len2

	// Rearrange: sigRem(3) csum=0(2) endptAcc=empty(1) msgRem(0)
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "push", Value: bigIntPush(0)})
	emit(StackOp{Op: "opcode", Code: "OP_0"})
	emit(StackOp{Op: "push", Value: bigIntPush(3)})
	emit(StackOp{Op: "opcode", Code: "OP_ROLL"})

	// Process n bytes -> 2*n message chains
	for byteIdx := 0; byteIdx < n; byteIdx++ {
		if byteIdx < n-1 {
			emit(StackOp{Op: "push", Value: bigIntPush(1)})
			emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
			emit(StackOp{Op: "swap"})
		}
		// Unsigned byte conversion
		emit(StackOp{Op: "push", Value: bigIntPush(0)})
		emit(StackOp{Op: "push", Value: bigIntPush(1)})
		emit(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		emit(StackOp{Op: "opcode", Code: "OP_CAT"})
		emit(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
		// High/low nibbles
		emit(StackOp{Op: "opcode", Code: "OP_DUP"})
		emit(StackOp{Op: "push", Value: bigIntPush(16)})
		emit(StackOp{Op: "opcode", Code: "OP_DIV"})
		emit(StackOp{Op: "swap"})
		emit(StackOp{Op: "push", Value: bigIntPush(16)})
		emit(StackOp{Op: "opcode", Code: "OP_MOD"})

		if byteIdx < n-1 {
			emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
			emit(StackOp{Op: "swap"})
			emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		} else {
			emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		}

		emitSLHOneChain(emit, n, layer, byteIdx*2)

		if byteIdx < n-1 {
			emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
			emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
			emit(StackOp{Op: "swap"})
			emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		} else {
			emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		}

		emitSLHOneChain(emit, n, layer, byteIdx*2+1)

		if byteIdx < n-1 {
			emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		}
	}

	// sigRest(2) totalCsum(1) endptAcc(0)
	// Checksum digits (len2=3)
	emit(StackOp{Op: "swap"})

	emit(StackOp{Op: "opcode", Code: "OP_DUP"})
	emit(StackOp{Op: "push", Value: bigIntPush(16)})
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})

	emit(StackOp{Op: "opcode", Code: "OP_DUP"})
	emit(StackOp{Op: "push", Value: bigIntPush(16)})
	emit(StackOp{Op: "opcode", Code: "OP_DIV"})
	emit(StackOp{Op: "push", Value: bigIntPush(16)})
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})

	emit(StackOp{Op: "push", Value: bigIntPush(256)})
	emit(StackOp{Op: "opcode", Code: "OP_DIV"})
	emit(StackOp{Op: "push", Value: bigIntPush(16)})
	emit(StackOp{Op: "opcode", Code: "OP_MOD"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})

	// sigRest(1) endptAcc(0) | alt: ..., d2, d1, d0(top)
	for ci := 0; ci < len2; ci++ {
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		emit(StackOp{Op: "push", Value: bigIntPush(0)})
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})

		emitSLHOneChain(emit, n, layer, len1+ci)

		emit(StackOp{Op: "swap"})
		emit(StackOp{Op: "drop"})
	}

	// empty(1) endptAcc(0)
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "drop"})

	// Compress -> wotsPk via T(pkSeed, ADRS_WOTS_PK, endptAcc)
	pkAdrs := slhADRS(slhADRSOpts{layer: layer, adrsTyp: slhWOTSPK})
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: pkAdrs}})
	emit(StackOp{Op: "swap"})
	emitSLHTRaw(emit, n)
}

// ===========================================================================
// 6. Merkle Auth Path Verification
// ===========================================================================
// Input:  leafIdx(2) authPath(hp*n)(1) node(n)(0)
// Output: root(n)

func emitSLHMerkle(emit func(StackOp), p SLHCodegenParams, layer int) {
	n := p.N
	hp := p.HP

	// Move leafIdx to alt
	emit(StackOp{Op: "push", Value: bigIntPush(2)})
	emit(StackOp{Op: "opcode", Code: "OP_ROLL"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
	// authPath(1) node(0) | alt: ..., leafIdx

	for j := 0; j < hp; j++ {
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // node -> alt

		emit(StackOp{Op: "push", Value: bigIntPush(int64(n))})
		emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		emit(StackOp{Op: "swap"}) // authPathRest authJ

		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // node
		// authPathRest(2) authJ(1) node(0)

		// Get leafIdx
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		emit(StackOp{Op: "opcode", Code: "OP_DUP"})
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		// authPathRest(3) authJ(2) node(1) leafIdx(0)

		// bit = (leafIdx >> j) & 1
		if j > 0 {
			emit(StackOp{Op: "push", Value: bigIntPush(int64(j))})
			emit(StackOp{Op: "opcode", Code: "OP_RSHIFT"})
		}
		emit(StackOp{Op: "push", Value: bigIntPush(1)})
		emit(StackOp{Op: "opcode", Code: "OP_AND"})

		adrs := slhADRS(slhADRSOpts{layer: layer, adrsTyp: slhTree, chain: j + 1, hash: 0})

		mkTweakHash := []StackOp{
			{Op: "push", Value: PushValue{Kind: "bytes", Bytes: adrs}},
			{Op: "swap"},
			{Op: "opcode", Code: "OP_CAT"},
			{Op: "opcode", Code: "OP_FROMALTSTACK"},
			{Op: "opcode", Code: "OP_DUP"},
			{Op: "opcode", Code: "OP_TOALTSTACK"},
			{Op: "swap"},
			{Op: "opcode", Code: "OP_CAT"},
			{Op: "opcode", Code: "OP_SHA256"},
		}
		if n < 32 {
			mkTweakHash = append(mkTweakHash,
				StackOp{Op: "push", Value: bigIntPush(int64(n))},
				StackOp{Op: "opcode", Code: "OP_SPLIT"},
				StackOp{Op: "drop"},
			)
		}

		thenBranch := append([]StackOp{
			{Op: "opcode", Code: "OP_CAT"},
		}, mkTweakHash...)

		elseBranch := append([]StackOp{
			{Op: "swap"},
			{Op: "opcode", Code: "OP_CAT"},
		}, mkTweakHash...)

		emit(StackOp{
			Op:   "if",
			Then: thenBranch,
			Else: elseBranch,
		})
	}

	// Drop leafIdx from alt
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	emit(StackOp{Op: "drop"})

	// authPathRest(empty)(1) root(0)
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "drop"})
}

// ===========================================================================
// 7. FORS Verification
// ===========================================================================
// Input:  forsSig(k*(1+a)*n)(1) md(ceil(k*a/8))(0)
// Output: forsPk(n)

func emitSLHFors(emit func(StackOp), p SLHCodegenParams) {
	n := p.N
	a := p.A
	k := p.K

	// Save md to alt, push empty rootAcc to alt
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})  // md -> alt
	emit(StackOp{Op: "opcode", Code: "OP_0"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})  // rootAcc(empty) -> alt
	// main: forsSig | alt: pkSeedPad, md, rootAcc(top)

	for i := 0; i < k; i++ {
		// main: forsSigRem | alt: pkSeedPad, md, rootAcc

		// Get md: pop rootAcc, pop md, dup md, push md back, push rootAcc back
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // rootAcc
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // md
		emit(StackOp{Op: "opcode", Code: "OP_DUP"})
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})   // md back
		emit(StackOp{Op: "swap"})
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})   // rootAcc back
		// main: forsSigRem md_copy

		// Extract idx: `a` bits at position i*a from md_copy
		bitStart := i * a
		byteStart := bitStart / 8
		bitOffset := bitStart % 8
		bitsInFirst := 8 - bitOffset
		if bitsInFirst > a {
			bitsInFirst = a
		}
		take := 1
		if a > bitsInFirst {
			take = 2
		}

		if byteStart > 0 {
			emit(StackOp{Op: "push", Value: bigIntPush(int64(byteStart))})
			emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
			emit(StackOp{Op: "nip"})
		}
		emit(StackOp{Op: "push", Value: bigIntPush(int64(take))})
		emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		emit(StackOp{Op: "drop"})
		if take > 1 {
			emit(StackOp{Op: "opcode", Code: "OP_REVERSE"})
		}
		emit(StackOp{Op: "push", Value: bigIntPush(0)})
		emit(StackOp{Op: "push", Value: bigIntPush(1)})
		emit(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		emit(StackOp{Op: "opcode", Code: "OP_CAT"})
		emit(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
		totalBits := take * 8
		rightShift := totalBits - bitOffset - a
		if rightShift > 0 {
			emit(StackOp{Op: "push", Value: bigIntPush(int64(rightShift))})
			emit(StackOp{Op: "opcode", Code: "OP_RSHIFT"})
		}
		emit(StackOp{Op: "push", Value: bigIntPush(int64((1 << a) - 1))})
		emit(StackOp{Op: "opcode", Code: "OP_AND"})
		// main: forsSigRem idx

		// Save idx to alt (above rootAcc)
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		// main: forsSigRem | alt: ..., md, rootAcc, idx(top)

		// Split sk(n) from sigRem
		emit(StackOp{Op: "push", Value: bigIntPush(int64(n))})
		emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		emit(StackOp{Op: "swap"})
		// main: sigRest sk

		// Leaf = T(pkSeed, ADRS_FORS_TREE{h=0}, sk)
		leafAdrs := slhADRS(slhADRSOpts{adrsTyp: slhFORSTree, chain: 0, hash: 0})
		emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: leafAdrs}})
		emit(StackOp{Op: "swap"})
		emitSLHTRaw(emit, n)
		// main: sigRest(1) node(0)

		// Auth path walk: a levels
		for j := 0; j < a; j++ {
			// sigRest(1) node(0)
			emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // node -> alt

			emit(StackOp{Op: "push", Value: bigIntPush(int64(n))})
			emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
			emit(StackOp{Op: "swap"})
			// sigRest authJ

			emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // node
			// sigRest(2) authJ(1) node(0)

			// Get idx: pop from alt (idx is top of alt), dup, push back
			emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
			emit(StackOp{Op: "opcode", Code: "OP_DUP"})
			emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
			// sigRest(3) authJ(2) node(1) idx(0)

			// bit = (idx >> j) & 1
			if j > 0 {
				emit(StackOp{Op: "push", Value: bigIntPush(int64(j))})
				emit(StackOp{Op: "opcode", Code: "OP_RSHIFT"})
			}
			emit(StackOp{Op: "push", Value: bigIntPush(1)})
			emit(StackOp{Op: "opcode", Code: "OP_AND"})

			levelAdrs := slhADRS(slhADRSOpts{adrsTyp: slhFORSTree, chain: j + 1, hash: 0})

			hashTail := []StackOp{
				{Op: "push", Value: PushValue{Kind: "bytes", Bytes: levelAdrs}},
				{Op: "swap"},
				{Op: "opcode", Code: "OP_CAT"},
				{Op: "opcode", Code: "OP_FROMALTSTACK"},
				{Op: "opcode", Code: "OP_DUP"},
				{Op: "opcode", Code: "OP_TOALTSTACK"},
				{Op: "swap"},
				{Op: "opcode", Code: "OP_CAT"},
				{Op: "opcode", Code: "OP_SHA256"},
			}
			if n < 32 {
				hashTail = append(hashTail,
					StackOp{Op: "push", Value: bigIntPush(int64(n))},
					StackOp{Op: "opcode", Code: "OP_SPLIT"},
					StackOp{Op: "drop"},
				)
			}

			thenBranch := append([]StackOp{
				{Op: "opcode", Code: "OP_CAT"},
			}, hashTail...)

			elseBranch := append([]StackOp{
				{Op: "swap"},
				{Op: "opcode", Code: "OP_CAT"},
			}, hashTail...)

			emit(StackOp{
				Op:   "if",
				Then: thenBranch,
				Else: elseBranch,
			})
		}

		// sigRest(1) treeRoot(0) | alt: ..., md, rootAcc, idx

		// Drop idx from alt
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		emit(StackOp{Op: "drop"})

		// Append treeRoot to rootAcc
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // rootAcc
		emit(StackOp{Op: "swap"})
		emit(StackOp{Op: "opcode", Code: "OP_CAT"})
		// main: sigRest(1) newRootAcc(0)

		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // rootAcc -> alt
		// main: sigRest | alt: ..., md, newRootAcc
	}

	// Drop empty sigRest
	emit(StackOp{Op: "drop"})

	// Get rootAcc, drop md
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // rootAcc
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // md
	emit(StackOp{Op: "drop"})
	// main: rootAcc(k*n)

	// Compress: T(pkSeed, ADRS_FORS_ROOTS, rootAcc)
	forsAdrs := slhADRS(slhADRSOpts{adrsTyp: slhFORSRoots})
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: forsAdrs}})
	emit(StackOp{Op: "swap"})
	emitSLHTRaw(emit, n)
}

// ===========================================================================
// 8. Hmsg — Message Digest (SHA-256 MGF1)
// ===========================================================================
// Input:  R(3) pkSeed(2) pkRoot(1) msg(0)
// Output: digest(outLen bytes)

func emitSLHHmsg(emit func(StackOp), n, outLen int) {
	// CAT: R || pkSeed || pkRoot || msg
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	emit(StackOp{Op: "opcode", Code: "OP_SHA256"}) // seed(32B)

	blocks := (outLen + 31) / 32 // ceil(outLen / 32)
	if blocks == 1 {
		emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: make([]byte, 4)}})
		emit(StackOp{Op: "opcode", Code: "OP_CAT"})
		emit(StackOp{Op: "opcode", Code: "OP_SHA256"})
		if outLen < 32 {
			emit(StackOp{Op: "push", Value: bigIntPush(int64(outLen))})
			emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
			emit(StackOp{Op: "drop"})
		}
	} else {
		emit(StackOp{Op: "opcode", Code: "OP_0"})  // seed resultAcc
		emit(StackOp{Op: "swap"})                    // resultAcc seed

		for ctr := 0; ctr < blocks; ctr++ {
			if ctr < blocks-1 {
				emit(StackOp{Op: "opcode", Code: "OP_DUP"})
			}
			ctrBytes := make([]byte, 4)
			ctrBytes[3] = byte(ctr & 0xff)
			ctrBytes[2] = byte((ctr >> 8) & 0xff)
			ctrBytes[1] = byte((ctr >> 16) & 0xff)
			ctrBytes[0] = byte((ctr >> 24) & 0xff)
			emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: ctrBytes}})
			emit(StackOp{Op: "opcode", Code: "OP_CAT"})
			emit(StackOp{Op: "opcode", Code: "OP_SHA256"})

			if ctr == blocks-1 {
				rem := outLen - ctr*32
				if rem < 32 {
					emit(StackOp{Op: "push", Value: bigIntPush(int64(rem))})
					emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
					emit(StackOp{Op: "drop"})
				}
			}

			if ctr < blocks-1 {
				emit(StackOp{Op: "rot"})
				emit(StackOp{Op: "swap"})
				emit(StackOp{Op: "opcode", Code: "OP_CAT"})
				emit(StackOp{Op: "swap"})
			} else {
				emit(StackOp{Op: "swap"})
				emit(StackOp{Op: "opcode", Code: "OP_CAT"})
			}
		}
	}
}

// ===========================================================================
// 9. Main Entry — EmitVerifySLHDSA
// ===========================================================================
// Input:  msg(2) sig(1) pubkey(0)  [pubkey on top]
// Output: boolean

// EmitVerifySLHDSA emits the full SLH-DSA verification script.
func EmitVerifySLHDSA(emit func(StackOp), paramKey string) {
	p, ok := SLHParams[paramKey]
	if !ok {
		panic(fmt.Sprintf("Unknown SLH-DSA params: %s", paramKey))
	}

	n := p.N
	d := p.D
	hp := p.HP
	k := p.K
	a := p.A
	ln := p.Len
	forsSigLen := k * (1 + a) * n
	xmssSigLen := (ln + hp) * n
	mdLen := (k*a + 7) / 8 // ceil(k*a / 8)
	treeIdxLen := (p.H - hp + 7) / 8
	leafIdxLen := (hp + 7) / 8
	digestLen := mdLen + treeIdxLen + leafIdxLen

	t := NewSLHTracker([]string{"msg", "sig", "pubkey"}, emit)

	// ---- 1. Parse pubkey -> pkSeed, pkRoot ----
	t.toTop("pubkey")
	t.pushInt("", int64(n))
	t.split("pkSeed", "pkRoot")

	// Build pkSeedPad = pkSeed || zeros(64-n), push to alt
	t.copyToTop("pkSeed", "_psp")
	if 64-n > 0 {
		t.pushBytes("", make([]byte, 64-n))
		t.cat("_pkSeedPad")
	} else {
		t.rename("_pkSeedPad")
	}
	t.toAlt()

	// ---- 2. Parse R from sig ----
	t.toTop("sig")
	t.pushInt("", int64(n))
	t.split("R", "sigRest")

	// ---- 3. Compute Hmsg(R, pkSeed, pkRoot, msg) ----
	t.copyToTop("R", "_R")
	t.copyToTop("pkSeed", "_pks")
	t.copyToTop("pkRoot", "_pkr")
	t.copyToTop("msg", "_msg")
	t.rawBlock([]string{"_R", "_pks", "_pkr", "_msg"}, "digest", func(e func(StackOp)) {
		emitSLHHmsg(e, n, digestLen)
	})

	// ---- 4. Extract md, treeIdx, leafIdx ----
	t.toTop("digest")
	t.pushInt("", int64(mdLen))
	t.split("md", "_drest")

	t.toTop("_drest")
	t.pushInt("", int64(treeIdxLen))
	t.split("_treeBytes", "_leafBytes")

	// Convert _treeBytes -> treeIdx
	t.toTop("_treeBytes")
	t.rawBlock([]string{"_treeBytes"}, "treeIdx", func(e func(StackOp)) {
		if treeIdxLen > 1 {
			e(StackOp{Op: "opcode", Code: "OP_REVERSE"})
		}
		e(StackOp{Op: "push", Value: bigIntPush(0)})
		e(StackOp{Op: "push", Value: bigIntPush(1)})
		e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
		mask := (int64(1) << (p.H - hp)) - 1
		e(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(mask)}})
		e(StackOp{Op: "opcode", Code: "OP_AND"})
	})

	// Convert _leafBytes -> leafIdx
	t.toTop("_leafBytes")
	t.rawBlock([]string{"_leafBytes"}, "leafIdx", func(e func(StackOp)) {
		if leafIdxLen > 1 {
			e(StackOp{Op: "opcode", Code: "OP_REVERSE"})
		}
		e(StackOp{Op: "push", Value: bigIntPush(0)})
		e(StackOp{Op: "push", Value: bigIntPush(1)})
		e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
		e(StackOp{Op: "push", Value: bigIntPush(int64((1 << hp) - 1))})
		e(StackOp{Op: "opcode", Code: "OP_AND"})
	})

	// ---- 5. Parse FORS sig ----
	t.toTop("sigRest")
	t.pushInt("", int64(forsSigLen))
	t.split("forsSig", "htSigRest")

	// ---- 6. FORS -> forsPk ----
	t.toTop("forsSig")
	t.toTop("md")
	t.rawBlock([]string{"forsSig", "md"}, "forsPk", func(e func(StackOp)) {
		emitSLHFors(e, p)
	})

	// ---- 7. Hypertree: d layers ----
	for layer := 0; layer < d; layer++ {
		// Split xmssSig from htSigRest
		t.toTop("htSigRest")
		t.pushInt("", int64(xmssSigLen))
		t.split(fmt.Sprintf("xsig%d", layer), "htSigRest")

		// Split wotsSig and authPath
		t.toTop(fmt.Sprintf("xsig%d", layer))
		t.pushInt("", int64(ln*n))
		t.split(fmt.Sprintf("wsig%d", layer), fmt.Sprintf("auth%d", layer))

		// WOTS+: wotsSig + currentMsg -> wotsPk
		curMsg := "forsPk"
		if layer > 0 {
			curMsg = fmt.Sprintf("root%d", layer-1)
		}
		t.toTop(fmt.Sprintf("wsig%d", layer))
		t.toTop(curMsg)
		wsigName := fmt.Sprintf("wsig%d", layer)
		wpkName := fmt.Sprintf("wpk%d", layer)
		t.rawBlock([]string{wsigName, curMsg}, wpkName, func(e func(StackOp)) {
			emitSLHWotsAll(e, p, layer)
		})

		// Merkle: leafIdx + authPath + wotsPk -> root
		t.toTop("leafIdx")
		authName := fmt.Sprintf("auth%d", layer)
		t.toTop(authName)
		t.toTop(wpkName)
		rootName := fmt.Sprintf("root%d", layer)
		t.rawBlock([]string{"leafIdx", authName, wpkName}, rootName, func(e func(StackOp)) {
			emitSLHMerkle(e, p, layer)
		})

		// Update leafIdx, treeIdx for next layer
		if layer < d-1 {
			t.toTop("treeIdx")
			t.dup("_tic")
			t.pushInt("", int64((1<<hp)-1))
			t.op("OP_AND")
			t.rename("leafIdx")

			t.toTop("_tic")
			t.pushInt("", int64(hp))
			t.op("OP_RSHIFT")
			t.rename("treeIdx")
		}
	}

	// ---- 8. Compare root to pkRoot ----
	t.toTop(fmt.Sprintf("root%d", d-1))
	t.toTop("pkRoot")
	t.equal("_result")

	// ---- 9. Cleanup ----
	t.toTop("_result")
	t.toAlt()

	// Drop all remaining tracked values
	leftover := []string{"msg", "R", "pkSeed", "htSigRest", "treeIdx", "leafIdx"}
	for _, nm := range leftover {
		if t.has(nm) {
			t.toTop(nm)
			t.drop()
		}
	}
	for t.depth() > 0 {
		t.drop()
	}

	t.fromAlt("_result")
	// Pop pkSeedPad from alt
	t.fromAlt("")
	t.drop()
}
