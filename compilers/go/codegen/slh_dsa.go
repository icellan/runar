// SLH-DSA (FIPS 205) Bitcoin Script codegen for the Runar Go stack lowerer.
//
// Splice into LoweringContext in stack.go. All helpers self-contained.
// Entry: lowerVerifySLHDSA() -> calls EmitVerifySLHDSA().
//
// Main-stack convention: pkSeedPad (64 bytes) tracked as '_pkSeedPad' on the
// main stack, accessed via PICK at known depth. Never placed on alt.
//
// Runtime ADRS: treeAddr (8-byte BE) and keypair (4-byte BE) are tracked on
// the main stack as 'treeAddr8' and 'keypair4', threaded into rawBlocks.
// ADRS is built at runtime using emitBuildADRS / emitBuildADRS18 helpers.
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
// 1b. Fixed-length byte reversal helper
// ===========================================================================

// emitReverseN generates an unrolled fixed-length byte reversal for n bytes.
// Uses (n-1) split-swap-cat operations. Only valid when n is known at compile time.
func emitReverseN(n int) []StackOp {
	if n <= 1 {
		return nil
	}
	ops := make([]StackOp, 0, 4*(n-1))
	// Phase 1: split into n individual bytes
	for i := 0; i < n-1; i++ {
		ops = append(ops, StackOp{Op: "push", Value: bigIntPush(1)})
		ops = append(ops, StackOp{Op: "opcode", Code: "OP_SPLIT"})
	}
	// Phase 2: concatenate in reverse order
	for i := 0; i < n-1; i++ {
		ops = append(ops, StackOp{Op: "swap"})
		ops = append(ops, StackOp{Op: "opcode", Code: "OP_CAT"})
	}
	return ops
}

// ===========================================================================
// 1c. Collect ops into array helper
// ===========================================================================

func collectOps(fn func(emit func(StackOp))) []StackOp {
	ops := []StackOp{}
	fn(func(op StackOp) { ops = append(ops, op) })
	return ops
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
// 2b. Runtime ADRS builders
// ===========================================================================

// int4BE converts a compile-time integer to a 4-byte big-endian byte slice.
func int4BE(v int) []byte {
	b := make([]byte, 4)
	b[0] = byte((v >> 24) & 0xff)
	b[1] = byte((v >> 16) & 0xff)
	b[2] = byte((v >> 8) & 0xff)
	b[3] = byte(v & 0xff)
	return b
}

// emitBuildADRS18 emits runtime 18-byte ADRS prefix:
// layer(1B) || PICK(treeAddr8)(8B) || type(1B) || PICK(keypair4)(4B) || chain(4B).
//
// Net stack effect: +1 (the 18-byte result on TOS).
// ta8Depth and kp4Depth are from TOS *before* this function pushes anything.
func emitBuildADRS18(
	emit func(StackOp),
	layer, adrsType, chain int,
	ta8Depth, kp4Depth int,
) {
	// Push layer byte (1B)
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{byte(layer & 0xff)}}})
	// After push: ta8 at ta8Depth+1, kp4 at kp4Depth+1

	// PICK ta8: depth = ta8Depth + 1 (one extra item on stack)
	emit(StackOp{Op: "push", Value: bigIntPush(int64(ta8Depth + 1))})
	emit(StackOp{Op: "pick", Depth: ta8Depth + 1})
	// Stack: ... layerByte ta8Copy (2 items above original TOS)
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	// Stack: ... (layer||ta8)(9B) -- net +1 from start
	// kp4 at kp4Depth + 1

	// Push type byte (1B)
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: []byte{byte(adrsType & 0xff)}}})
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	// Stack: ... partial10B -- net +1
	// kp4 at kp4Depth + 1

	// keypair4: if kp4Depth < 0, push 4 zero bytes (WOTS_PK / TREE types zero the keypair);
	// otherwise PICK kp4 from the stack at depth kp4Depth + 1.
	if kp4Depth < 0 {
		emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: make([]byte, 4)}})
	} else {
		emit(StackOp{Op: "push", Value: bigIntPush(int64(kp4Depth + 1))})
		emit(StackOp{Op: "pick", Depth: kp4Depth + 1})
	}
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	// Stack: ... partial14B -- net +1

	// Push chain (4B BE)
	emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: int4BE(chain)}})
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	// Stack: ... prefix18B -- net +1
}

// emitBuildADRS emits a runtime 22-byte ADRS.
//
// hash mode:
//   - "zero"  -- append 4 zero bytes (hash=0)
//   - "stack" -- TOS has a 4-byte BE hash value; consumed and appended
//
// For "zero": net stack effect = +1 (22B ADRS on TOS).
// For "stack": net stack effect = 0 (TOS hash4 replaced by 22B ADRS).
//
// ta8Depth/kp4Depth measured from TOS before this function pushes anything.
func emitBuildADRS(
	emit func(StackOp),
	layer, adrsType, chain int,
	ta8Depth, kp4Depth int,
	hash string,
) {
	if hash == "stack" {
		// Save hash4 from TOS to alt
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		// Depths shift by -1 (one item removed from main).
		// If kp4Depth < 0 (sentinel for zero keypair), keep it negative.
		adjKp4 := kp4Depth - 1
		if kp4Depth < 0 {
			adjKp4 = kp4Depth
		}
		emitBuildADRS18(emit, layer, adrsType, chain, ta8Depth-1, adjKp4)
		// 18-byte prefix on TOS
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		emit(StackOp{Op: "opcode", Code: "OP_CAT"})
		// 22-byte ADRS on TOS. Net: replaced hash4 with adrs22.
	} else {
		// "zero"
		emitBuildADRS18(emit, layer, adrsType, chain, ta8Depth, kp4Depth)
		emit(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: make([]byte, 4)}})
		emit(StackOp{Op: "opcode", Code: "OP_CAT"})
		// 22-byte ADRS on TOS. Net: +1.
	}
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
// pkSeedPad on main stack, accessed via PICK.

// emitSLHT emits a tracked tweakable hash. Accesses _pkSeedPad via copyToTop.
func emitSLHT(t *SLHTracker, n int, adrs, msg, result string) {
	t.toTop(adrs)
	t.toTop(msg)
	t.cat("_am")
	// Access pkSeedPad via PICK on main stack
	t.copyToTop("_pkSeedPad", "_psp")
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

// emitSLHTRaw emits a raw tweakable hash with pkSeedPad on main stack via PICK.
//
// Stack in:  adrsC(1) msg(0), pkSeedPad at depth pkSeedPadDepth from TOS
// After CAT: (adrsC||msg)(0), pkSeedPad at depth pkSeedPadDepth-1
// PICK pkSeedPad, SWAP, CAT, SHA256, truncate
// Stack out: result(0)
func emitSLHTRaw(e func(StackOp), n int, pkSeedPadDepth int) {
	e(StackOp{Op: "opcode", Code: "OP_CAT"})
	// After CAT: 2 consumed, 1 produced. pkSeedPad depth = pkSeedPadDepth - 1.
	pickDepth := pkSeedPadDepth - 1
	e(StackOp{Op: "push", Value: bigIntPush(int64(pickDepth))})
	e(StackOp{Op: "pick", Depth: pickDepth})
	// pkSeedPad copy on TOS, original still in place
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
//
//	with ADRS prefix (18B) on alt (FROMALT/DUP/TOALT pattern)
//	and pkSeedPad at pkSeedPadDepth from TOS.
//
// Exit:  newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
func slhChainStepThen(n int, pkSeedPadDepth int) []StackOp {
	ops := []StackOp{}
	// DUP hashAddr before consuming it in ADRS construction
	ops = append(ops, StackOp{Op: "dup"})
	// sigElem(3) steps(2) hashAddr(1) hashAddr_copy(0)
	// Convert copy to 4-byte big-endian
	ops = append(ops, StackOp{Op: "push", Value: bigIntPush(4)})
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
	ops = append(ops, emitReverseN(4)...)
	// sigElem(3) steps(2) hashAddr(1) hashAddrBE4(0) -- 4 items above base

	// Get prefix from alt: FROMALT; DUP; TOALT
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_DUP"})
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
	// sigElem(4) steps(3) hashAddr(2) hashAddrBE4(1) prefix18(0) -- 5 items
	ops = append(ops, StackOp{Op: "swap"})
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_CAT"})
	// sigElem(3) steps(2) hashAddr(1) adrsC22(0) -- 4 items

	// Move sigElem to top: ROLL 3
	ops = append(ops, StackOp{Op: "push", Value: bigIntPush(3)})
	ops = append(ops, StackOp{Op: "roll", Depth: 3})
	// steps(2) hashAddr(1) adrsC22(0) sigElem(top) -- 4 items
	// CAT: adrsC(1) || sigElem(0) -> adrsC||sigElem
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_CAT"})
	// steps(1) hashAddr(0) (adrsC||sigElem)(top) -- 3 items

	// pkSeedPad via PICK (3 items on main above base, same as entry)
	ops = append(ops, StackOp{Op: "push", Value: bigIntPush(int64(pkSeedPadDepth))})
	ops = append(ops, StackOp{Op: "pick", Depth: pkSeedPadDepth})
	// steps(2) hashAddr(1) (adrsC||sigElem)(0) pkSeedPad(top) -- 4 items
	ops = append(ops, StackOp{Op: "swap"})
	// steps(2) hashAddr(1) pkSeedPad(0) (adrsC||sigElem)(top)
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_CAT"})
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_SHA256"})
	if n < 32 {
		ops = append(ops, StackOp{Op: "push", Value: bigIntPush(int64(n))})
		ops = append(ops, StackOp{Op: "opcode", Code: "OP_SPLIT"})
		ops = append(ops, StackOp{Op: "drop"})
	}
	// steps(2) hashAddr(1) newSigElem(0) -- 3 items
	// Rearrange -> newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
	ops = append(ops, StackOp{Op: "rot"})
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_1SUB"})
	ops = append(ops, StackOp{Op: "rot"})
	ops = append(ops, StackOp{Op: "opcode", Code: "OP_1ADD"})
	// newSigElem(2) (steps-1)(1) (hashAddr+1)(0)
	return ops
}

// emitSLHOneChain emits one WOTS+ chain with tweakable hashing (raw opcodes).
//
// Input:  sig(3) csum(2) endptAcc(1) digit(0)
//
//	pkSeedPad at pkSeedPadDepth from TOS (digit)
//	treeAddr8 at ta8Depth from TOS
//	keypair4 at kp4Depth from TOS
//
// Output: sigRest(2) newCsum(1) newEndptAcc(0)
//
//	(3 items replaces 4 input items, so depths shift by -1)
//
// Alt: not used for pkSeedPad. Uses alt internally (balanced).
func emitSLHOneChain(emit func(StackOp), n, layer, chainIdx int, pkSeedPadDepth, ta8Depth, kp4Depth int) {
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
	// pspD = pkSeedPadDepth - 2 (4 items removed, 2 remain = -2)
	// ta8D = ta8Depth - 2, kp4D = kp4Depth - 2

	// Split n-byte sig element
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "push", Value: bigIntPush(int64(n))})
	emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})       // steps sigElem sigRest
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // alt: ..., csum, sigRest(top)
	emit(StackOp{Op: "swap"})
	// main: sigElem(1) steps(0)
	// pspD = pkSeedPadDepth - 2 (since we went from 2 to 2 items via split+toalt+swap)

	// Compute hashAddr = 15 - steps (= digit) on main stack
	emit(StackOp{Op: "opcode", Code: "OP_DUP"})
	emit(StackOp{Op: "push", Value: bigIntPush(15)})
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "opcode", Code: "OP_SUB"})
	// main: sigElem(2) steps(1) hashAddr(0) -- 3 items
	// pspD = pkSeedPadDepth - 1 (was pspD_base - 2, now 3 items instead of 2 = +1 => -1 total)
	pspDChain := pkSeedPadDepth - 1
	ta8DChain := ta8Depth - 1
	kp4DChain := kp4Depth - 1

	// Build 18-byte ADRS prefix using runtime treeAddr8 and keypair4
	// After emitBuildADRS18: +1 item on stack => 4 items: sigElem steps hashAddr prefix18
	emitBuildADRS18(emit, layer, slhWOTSHash, chainIdx, ta8DChain, kp4DChain)
	// pspD = pspDChain + 1 = pkSeedPadDepth
	// Save prefix18 to alt for loop reuse
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
	// main: sigElem(2) steps(1) hashAddr(0) -- back to 3 items
	// pspD = pspDChain = pkSeedPadDepth - 1

	// Build then-ops for chain step
	// At step entry: sigElem(2) steps(1) hashAddr(0), 3 items above base
	// pspD at step entry = pkSeedPadDepth - 1
	thenOps := slhChainStepThen(n, pspDChain)

	// 15 unrolled conditional hash iterations
	for j := 0; j < 15; j++ {
		emit(StackOp{Op: "over"})
		emit(StackOp{Op: "opcode", Code: "OP_0NOTEQUAL"})
		emit(StackOp{Op: "if", Then: thenOps})
	}

	// endpoint(2) 0(1) finalHashAddr(0)
	emit(StackOp{Op: "drop"})
	emit(StackOp{Op: "drop"})
	// main: endpoint

	// Drop prefix from alt
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	emit(StackOp{Op: "drop"})

	// Restore from alt (LIFO): sigRest, csum, endptAcc, steps_copy
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // sigRest
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // csum
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // endptAcc
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // steps_copy
	// bottom->top: endpoint sigRest csum endptAcc steps_copy

	// csum += steps_copy: ROT top-3 to bring csum up
	emit(StackOp{Op: "rot"})
	emit(StackOp{Op: "opcode", Code: "OP_ADD"})

	// Cat endpoint to endptAcc
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "push", Value: bigIntPush(3)})
	emit(StackOp{Op: "roll", Depth: 3})
	emit(StackOp{Op: "opcode", Code: "OP_CAT"})
	// sigRest(2) newCsum(1) newEndptAcc(0)
}

// ===========================================================================
// Full WOTS+ Processing (all len chains)
// ===========================================================================
// Input:  psp(4) ta8(3) kp4(2) wotsSig(1) msg(0)
// Output: psp(3) ta8(2) kp4(1) wotsPk(0)

func emitSLHWotsAll(emit func(StackOp), p SLHCodegenParams, layer int) {
	n := p.N
	len1 := p.Len1
	len2 := p.Len2

	// Input: psp(4) ta8(3) kp4(2) wotsSig(1) msg(0)
	// Rearrange: psp(6) ta8(5) kp4(4) sigRem(3) csum=0(2) endptAcc=empty(1) msgRem(0)
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "push", Value: bigIntPush(0)})
	emit(StackOp{Op: "opcode", Code: "OP_0"})
	emit(StackOp{Op: "push", Value: bigIntPush(3)})
	emit(StackOp{Op: "roll", Depth: 3})
	// psp(6) ta8(5) kp4(4) sigRem(3) csum(2) endptAcc(1) msgRem(0)
	// pspD=6, ta8D=5, kp4D=4

	// Process n bytes -> 2*n message chains
	for byteIdx := 0; byteIdx < n; byteIdx++ {
		// State: psp(6) ta8(5) kp4(4) sigRem(3) csum(2) endptAcc(1) msgRem(0)
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
		// Stack: ..kp4 sig csum endptAcc [msgRest if non-last] hiNib loNib

		if byteIdx < n-1 {
			// Stack: psp ta8 kp4 sig csum endptAcc msgRest hiNib loNib
			emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // loNib -> alt
			emit(StackOp{Op: "swap"})                            // msgRest hiNib -> hiNib msgRest
			emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // msgRest -> alt
			// Stack: psp(6) ta8(5) kp4(4) sig(3) csum(2) endptAcc(1) hiNib(0)
			// pspD=6, ta8D=5, kp4D=4
		} else {
			// Stack: psp ta8 kp4 sig csum endptAcc hiNib loNib
			emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // loNib -> alt
			// Stack: psp(6) ta8(5) kp4(4) sig(3) csum(2) endptAcc(1) hiNib(0)
		}

		// First chain call (hiNib)
		// sig(3) csum(2) endptAcc(1) digit=hiNib(0), pspD=6, ta8D=5, kp4D=4
		emitSLHOneChain(emit, n, layer, byteIdx*2, 6, 5, 4)
		// Output: sigRest(2) newCsum(1) newEndptAcc(0)
		// pspD=5, ta8D=4, kp4D=3

		if byteIdx < n-1 {
			// Restore loNib and msgRest from alt
			emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // msgRest
			emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // loNib
			emit(StackOp{Op: "swap"})
			emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // msgRest -> alt
			// Stack: psp(6) ta8(5) kp4(4) sigRest(3) newCsum(2) newEndptAcc(1) loNib(0)
		} else {
			emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // loNib
			// Stack: psp(6) ta8(5) kp4(4) sigRest(3) newCsum(2) newEndptAcc(1) loNib(0)
		}

		// Second chain call (loNib)
		emitSLHOneChain(emit, n, layer, byteIdx*2+1, 6, 5, 4)
		// Output: sigRest(2) newCsum(1) newEndptAcc(0)
		// pspD=5, ta8D=4, kp4D=3

		if byteIdx < n-1 {
			// Restore msgRest from alt
			emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // msgRest
			// Stack: psp(6) ta8(5) kp4(4) sigRest(3) csum(2) endptAcc(1) msgRest(0)
		}
		// Back to shape: psp(6) ta8(5) kp4(4) sigRest(3) csum(2) endptAcc(1) msgRem(0)
	}

	// After all message chains: psp(5) ta8(4) kp4(3) sigRest(2) totalCsum(1) endptAcc(0)
	// Checksum digits (len2=3)
	emit(StackOp{Op: "swap"})
	// psp(5) ta8(4) kp4(3) sigRest(2) endptAcc(1) totalCsum(0)

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
	// psp(4) ta8(3) kp4(2) sigRest(1) endptAcc(0) | alt: d2, d1, d0(top)

	for ci := 0; ci < len2; ci++ {
		// psp(4) ta8(3) kp4(2) sigRest(1) endptAcc(0)
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // endptAcc -> alt
		emit(StackOp{Op: "push", Value: bigIntPush(0)})
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // endptAcc
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // digit
		// psp(6) ta8(5) kp4(4) sigRest(3) 0(2) endptAcc(1) digit(0)

		emitSLHOneChain(emit, n, layer, len1+ci, 6, 5, 4)
		// sigRest(2) newCsum(1) newEndptAcc(0) -- pspD=5, ta8D=4, kp4D=3

		emit(StackOp{Op: "swap"})
		emit(StackOp{Op: "drop"})
		// psp(4) ta8(3) kp4(2) sigRest(1) newEndptAcc(0)
	}

	// psp(4) ta8(3) kp4(2) empty(1) endptAcc(0)
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "drop"})
	// psp(3) ta8(2) kp4(1) endptAcc(0)

	// Compress -> wotsPk via T(pkSeed, ADRS_WOTS_PK, endptAcc)
	// Build ADRS: ta8 at depth 2, keypair zeroed (WOTS_PK type clears keypair per spec)
	emitBuildADRS(emit, layer, slhWOTSPK, 0, 2, -1, "zero")
	// psp(4) ta8(3) kp4(2) endptAcc(1) adrs22(0)
	emit(StackOp{Op: "swap"})
	// psp(4) ta8(3) kp4(2) adrs22(1) endptAcc(0)
	emitSLHTRaw(emit, n, 4)
	// psp(3) ta8(2) kp4(1) wotsPk(0)
}

// ===========================================================================
// 6. Merkle Auth Path Verification
// ===========================================================================
// Input:  psp(5) ta8(4) kp4(3) leafIdx(2) authPath(hp*n)(1) node(n)(0)
// Output: psp(3) ta8(2) kp4(1) root(0)

func emitSLHMerkle(emit func(StackOp), p SLHCodegenParams, layer int) {
	n := p.N
	hp := p.HP

	// Input: psp(5) ta8(4) kp4(3) leafIdx(2) authPath(1) node(0)
	// Move leafIdx to alt
	emit(StackOp{Op: "push", Value: bigIntPush(2)})
	emit(StackOp{Op: "roll", Depth: 2})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
	// psp(4) ta8(3) kp4(2) authPath(1) node(0) | alt: leafIdx

	for j := 0; j < hp; j++ {
		// psp(4) ta8(3) kp4(2) authPath(1) node(0)
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // node -> alt

		emit(StackOp{Op: "push", Value: bigIntPush(int64(n))})
		emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		emit(StackOp{Op: "swap"}) // authPathRest authJ

		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // node
		// psp(4) ta8(3) kp4(2) authPathRest(2) authJ(1) node(0)

		// Get leafIdx
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		emit(StackOp{Op: "opcode", Code: "OP_DUP"})
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		// psp(5) ta8(4) kp4(3) authPathRest(3) authJ(2) node(1) leafIdx(0)

		// bit = (leafIdx >> j) % 2
		if j > 0 {
			emit(StackOp{Op: "push", Value: bigIntPush(int64(1 << j))})
			emit(StackOp{Op: "opcode", Code: "OP_DIV"})
		}
		emit(StackOp{Op: "push", Value: bigIntPush(2)})
		emit(StackOp{Op: "opcode", Code: "OP_MOD"})

		// Build the tweakable hash ops for both branches.
		// After CAT in branch: authPathRest(1) children(0)
		// psp(3) ta8(2) kp4(1) authPathRest(1) children(0)
		// pspD=3, ta8D=2, kp4D=1

		// Need ADRS with hash = leafIdx >> (j+1) as 4-byte BE
		// Build hash: get leafIdx from alt, shift, convert to 4B BE
		mkTweakHash := collectOps(func(e func(StackOp)) {
			// Stack in: authPathRest(1) children(0)
			// pspD=4, ta8D=3, kp4D=2

			// Get leafIdx from alt to compute hash
			e(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
			e(StackOp{Op: "opcode", Code: "OP_DUP"})
			e(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
			// authPathRest(2) children(1) leafIdx(0); pspD=5, ta8D=4, kp4D=3
			if j+1 > 0 {
				e(StackOp{Op: "push", Value: bigIntPush(int64(1 << (j + 1)))})
				e(StackOp{Op: "opcode", Code: "OP_DIV"})
			}
			// Convert to 4-byte BE
			e(StackOp{Op: "push", Value: bigIntPush(4)})
			e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
			for _, op := range emitReverseN(4) {
				e(op)
			}
			// authPathRest(2) children(1) hash4BE(0); pspD=5, ta8D=4, kp4D=3

			// Build ADRS (22B) with hash='stack', keypair zeroed (TREE type clears keypair per spec)
			emitBuildADRS(e, layer, slhTree, j+1, 4, -1, "stack")
			// Net 0 (hash4 replaced by adrs22). pspD=5, ta8D=4, kp4D=3
			// authPathRest(2) children(1) adrs22(0)
			e(StackOp{Op: "swap"})
			// authPathRest(2) adrs22(1) children(0)
			// Now tweakable hash: adrs(1) msg(0) -> result. pspD=5
			emitSLHTRaw(e, n, 5)
			// authPathRest(1) result(0); pspD=4
		})

		thenBranch := append([]StackOp{
			// bit==1: authJ||node. Stack: authJ(1) node(0). CAT -> authJ||node.
			{Op: "opcode", Code: "OP_CAT"},
		}, mkTweakHash...)

		elseBranch := append([]StackOp{
			// bit==0: node||authJ. Stack: authJ(1) node(0). SWAP -> node(1) authJ(0). CAT -> node||authJ.
			{Op: "swap"},
			{Op: "opcode", Code: "OP_CAT"},
		}, mkTweakHash...)

		emit(StackOp{
			Op:   "if",
			Then: thenBranch,
			Else: elseBranch,
		})
		// psp(3) ta8(2) kp4(1) authPathRest(1) result(0) | alt: leafIdx
	}

	// Drop leafIdx from alt
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
	emit(StackOp{Op: "drop"})

	// psp(3) ta8(2) kp4(1) authPathRest(empty)(1) root(0)
	emit(StackOp{Op: "swap"})
	emit(StackOp{Op: "drop"})
	// psp(3) ta8(2) kp4(1) root(0)
}

// ===========================================================================
// 7. FORS Verification
// ===========================================================================
// Input:  psp(4) ta8(3) kp4(2) forsSig(1) md(0)
// Output: psp(3) ta8(2) kp4(1) forsPk(0)

func emitSLHFors(emit func(StackOp), p SLHCodegenParams) {
	n := p.N
	a := p.A
	k := p.K

	// Input: psp(4) ta8(3) kp4(2) forsSig(1) md(0)
	// Save md to alt, push empty rootAcc to alt
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})  // md -> alt
	emit(StackOp{Op: "opcode", Code: "OP_0"})
	emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})  // rootAcc(empty) -> alt
	// psp(3) ta8(2) kp4(1) forsSig(0) | alt: md, rootAcc(top)
	// pspD=3, ta8D=2, kp4D=1

	for i := 0; i < k; i++ {
		// psp(3) ta8(2) kp4(1) forsSigRem(0) | alt: md, rootAcc

		// Get md: pop rootAcc, pop md, dup md, push md back, push rootAcc back
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // rootAcc
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // md
		emit(StackOp{Op: "opcode", Code: "OP_DUP"})
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})   // md back
		emit(StackOp{Op: "swap"})
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})   // rootAcc back
		// psp(4) ta8(3) kp4(2) forsSigRem(1) md_copy(0)

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
			for _, op := range emitReverseN(take) {
				emit(op)
			}
		}
		emit(StackOp{Op: "push", Value: bigIntPush(0)})
		emit(StackOp{Op: "push", Value: bigIntPush(1)})
		emit(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		emit(StackOp{Op: "opcode", Code: "OP_CAT"})
		emit(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
		totalBits := take * 8
		rightShift := totalBits - bitOffset - a
		if rightShift > 0 {
			emit(StackOp{Op: "push", Value: bigIntPush(int64(1 << rightShift))})
			emit(StackOp{Op: "opcode", Code: "OP_DIV"})
		}
		// Use OP_MOD instead of OP_AND to avoid byte-length mismatch
		emit(StackOp{Op: "push", Value: bigIntPush(int64(1 << a))})
		emit(StackOp{Op: "opcode", Code: "OP_MOD"})
		// psp(4) ta8(3) kp4(2) forsSigRem(1) idx(0)

		// Save idx to alt (above rootAcc)
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
		// psp(3) ta8(2) kp4(1) forsSigRem(0) | alt: md, rootAcc, idx(top)

		// Split sk(n) from sigRem
		emit(StackOp{Op: "push", Value: bigIntPush(int64(n))})
		emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
		emit(StackOp{Op: "swap"})
		// psp(4) ta8(3) kp4(2) sigRest(1) sk(0)

		// Leaf = T(pkSeed, ADRS_FORS_TREE{chain=0, hash=runtime}, sk)
		// The FORS leaf hash index is: i * (1<<a) + idx
		// Need to get idx from alt, compute, convert to 4B BE, build ADRS
		// Get idx from alt (above rootAcc)
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // idx
		emit(StackOp{Op: "opcode", Code: "OP_DUP"})
		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // idx back
		// psp(5) ta8(4) kp4(3) sigRest(2) sk(1) idx(0)

		// Compute hash = i*(1<<a) + idx
		if i > 0 {
			emit(StackOp{Op: "push", Value: bigIntPush(int64(i * (1 << a)))})
			emit(StackOp{Op: "opcode", Code: "OP_ADD"})
		}
		// Convert to 4B BE
		emit(StackOp{Op: "push", Value: bigIntPush(4)})
		emit(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		for _, op := range emitReverseN(4) {
			emit(op)
		}
		// psp(5) ta8(4) kp4(3) sigRest(2) sk(1) hash4BE(0)

		// Build ADRS with hash='stack': ta8D=4, kp4D=3
		emitBuildADRS(emit, 0, slhFORSTree, 0, 4, 3, "stack")
		// hash4 replaced by adrs22. psp(5) ta8(4) kp4(3) sigRest(2) sk(1) adrs22(0)
		emit(StackOp{Op: "swap"})
		// psp(5) ta8(4) kp4(3) sigRest(2) adrs22(1) sk(0)
		emitSLHTRaw(emit, n, 5)
		// psp(4) ta8(3) kp4(2) sigRest(1) node(0)

		// Auth path walk: a levels
		for j := 0; j < a; j++ {
			// psp(4) ta8(3) kp4(2) sigRest(1) node(0)
			emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // node -> alt

			emit(StackOp{Op: "push", Value: bigIntPush(int64(n))})
			emit(StackOp{Op: "opcode", Code: "OP_SPLIT"})
			emit(StackOp{Op: "swap"})
			// sigRest authJ

			emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // node
			// psp(4) ta8(3) kp4(2) sigRest(2) authJ(1) node(0)

			// Get idx: pop from alt (idx is top of alt), dup, push back
			emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
			emit(StackOp{Op: "opcode", Code: "OP_DUP"})
			emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
			// psp(5) ta8(4) kp4(3) sigRest(3) authJ(2) node(1) idx(0)

			// bit = (idx >> j) % 2
			if j > 0 {
				emit(StackOp{Op: "push", Value: bigIntPush(int64(1 << j))})
				emit(StackOp{Op: "opcode", Code: "OP_DIV"})
			}
			// Use OP_MOD instead of OP_AND to avoid byte-length mismatch
			emit(StackOp{Op: "push", Value: bigIntPush(2)})
			emit(StackOp{Op: "opcode", Code: "OP_MOD"})

			// After if/then branches: CAT children -> children(0)
			// psp(4) ta8(3) kp4(2) sigRest(1) children(0)
			// Need tweakable hash with ADRS. hash = i*(1<<(a-j-1)) + (idx >> (j+1))
			mkForsAuthHash := collectOps(func(e func(StackOp)) {
				// Stack: sigRest(1) children(0)
				// pspD=4, ta8D=3, kp4D=2

				// Get idx from alt to compute hash
				e(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
				e(StackOp{Op: "opcode", Code: "OP_DUP"})
				e(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
				// sigRest(2) children(1) idx(0); pspD=5, ta8D=4, kp4D=3
				// hash = i*(1<<(a-j-1)) + (idx >> (j+1))
				if j+1 > 0 {
					e(StackOp{Op: "push", Value: bigIntPush(int64(1 << (j + 1)))})
					e(StackOp{Op: "opcode", Code: "OP_DIV"})
				}
				base := i * (1 << (a - j - 1))
				if base > 0 {
					e(StackOp{Op: "push", Value: bigIntPush(int64(base))})
					e(StackOp{Op: "opcode", Code: "OP_ADD"})
				}
				// Convert to 4B BE
				e(StackOp{Op: "push", Value: bigIntPush(4)})
				e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
				for _, op := range emitReverseN(4) {
					e(op)
				}
				// sigRest(2) children(1) hash4BE(0); ta8D=4, kp4D=3

				// Build ADRS with hash='stack'
				emitBuildADRS(e, 0, slhFORSTree, j+1, 4, 3, "stack")
				// sigRest(2) children(1) adrs22(0); pspD=5, ta8D=4, kp4D=3
				e(StackOp{Op: "swap"})
				emitSLHTRaw(e, n, 5)
				// sigRest(1) result(0); pspD=4
			})

			thenBranch := append([]StackOp{
				{Op: "opcode", Code: "OP_CAT"},
			}, mkForsAuthHash...)

			elseBranch := append([]StackOp{
				{Op: "swap"},
				{Op: "opcode", Code: "OP_CAT"},
			}, mkForsAuthHash...)

			emit(StackOp{
				Op:   "if",
				Then: thenBranch,
				Else: elseBranch,
			})
			// psp(4) ta8(3) kp4(2) sigRest(1) result(0)
		}

		// psp(4) ta8(3) kp4(2) sigRest(1) treeRoot(0) | alt: md, rootAcc, idx

		// Drop idx from alt
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		emit(StackOp{Op: "drop"})

		// Append treeRoot to rootAcc
		emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // rootAcc
		emit(StackOp{Op: "swap"})
		emit(StackOp{Op: "opcode", Code: "OP_CAT"})
		// psp(3) ta8(2) kp4(1) sigRest(1) newRootAcc(0)

		emit(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // rootAcc -> alt
		// psp(3) ta8(2) kp4(1) sigRest(0) | alt: md, newRootAcc
	}

	// Drop empty sigRest
	emit(StackOp{Op: "drop"})

	// Get rootAcc, drop md
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // rootAcc
	emit(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // md
	emit(StackOp{Op: "drop"})
	// psp(3) ta8(2) kp4(1) rootAcc(0)

	// Compress: T(pkSeed, ADRS_FORS_ROOTS, rootAcc)
	// Build ADRS: ta8D=2, kp4D=1
	emitBuildADRS(emit, 0, slhFORSRoots, 0, 2, 1, "zero")
	// psp(4) ta8(3) kp4(2) rootAcc(1) adrs22(0)
	emit(StackOp{Op: "swap"})
	emitSLHTRaw(emit, n, 4)
	// psp(3) ta8(2) kp4(1) forsPk(0)
}

// ===========================================================================
// 8. Hmsg -- Message Digest (SHA-256 MGF1)
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
		emit(StackOp{Op: "opcode", Code: "OP_0"}) // seed resultAcc
		emit(StackOp{Op: "swap"})                   // resultAcc seed

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
// 9. Main Entry -- EmitVerifySLHDSA
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

	// Build pkSeedPad = pkSeed || zeros(64-n), keep on main stack
	t.copyToTop("pkSeed", "_psp")
	if 64-n > 0 {
		t.pushBytes("", make([]byte, 64-n))
		t.cat("_pkSeedPad")
	} else {
		t.rename("_pkSeedPad")
	}
	// _pkSeedPad stays on main stack (tracked)

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
			for _, op := range emitReverseN(treeIdxLen) {
				e(op)
			}
		}
		e(StackOp{Op: "push", Value: bigIntPush(0)})
		e(StackOp{Op: "push", Value: bigIntPush(1)})
		e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
		// Use OP_MOD instead of OP_AND to avoid byte-length mismatch
		modulus := int64(1) << (p.H - hp)
		e(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(modulus)}})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})

	// Convert _leafBytes -> leafIdx
	t.toTop("_leafBytes")
	t.rawBlock([]string{"_leafBytes"}, "leafIdx", func(e func(StackOp)) {
		if leafIdxLen > 1 {
			for _, op := range emitReverseN(leafIdxLen) {
				e(op)
			}
		}
		e(StackOp{Op: "push", Value: bigIntPush(0)})
		e(StackOp{Op: "push", Value: bigIntPush(1)})
		e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		e(StackOp{Op: "opcode", Code: "OP_CAT"})
		e(StackOp{Op: "opcode", Code: "OP_BIN2NUM"})
		// Use OP_MOD instead of OP_AND to avoid byte-length mismatch
		e(StackOp{Op: "push", Value: bigIntPush(int64(1 << hp))})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})

	// ---- 4b. Compute treeAddr8 and keypair4 for ADRS construction ----
	// treeAddr8 = treeIdx as 8-byte big-endian
	t.copyToTop("treeIdx", "_ti8")
	t.rawBlock([]string{"_ti8"}, "treeAddr8", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(8)})
		e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		for _, op := range emitReverseN(8) {
			e(op)
		}
	})

	// keypair4 = leafIdx as 4-byte big-endian
	t.copyToTop("leafIdx", "_li4")
	t.rawBlock([]string{"_li4"}, "keypair4", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(4)})
		e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		for _, op := range emitReverseN(4) {
			e(op)
		}
	})

	// ---- 5. Parse FORS sig ----
	t.toTop("sigRest")
	t.pushInt("", int64(forsSigLen))
	t.split("forsSig", "htSigRest")

	// ---- 6. FORS -> forsPk ----
	// Copy psp/ta8/kp4 to top, then forsSig, md
	t.copyToTop("_pkSeedPad", "_psp")
	t.copyToTop("treeAddr8", "_ta")
	t.copyToTop("keypair4", "_kp")
	t.toTop("forsSig")
	t.toTop("md")
	t.rawBlock([]string{"_psp", "_ta", "_kp", "forsSig", "md"}, "forsPk", func(e func(StackOp)) {
		// Stack: psp(4) ta8(3) kp4(2) forsSig(1) md(0)
		emitSLHFors(e, p)
		// Stack: psp(3) ta8(2) kp4(1) forsPk(0)
		// Drop psp, ta8, kp4
		e(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"}) // forsPk -> alt
		e(StackOp{Op: "drop"})                            // kp4
		e(StackOp{Op: "drop"})                            // ta8
		e(StackOp{Op: "drop"})                            // psp
		e(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"}) // forsPk back
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

		// WOTS+: copy psp/ta8/kp4 + wotsSig + currentMsg -> wotsPk
		curMsg := "forsPk"
		if layer > 0 {
			curMsg = fmt.Sprintf("root%d", layer-1)
		}
		t.copyToTop("_pkSeedPad", "_psp")
		t.copyToTop("treeAddr8", "_ta")
		t.copyToTop("keypair4", "_kp")
		wsigName := fmt.Sprintf("wsig%d", layer)
		t.toTop(wsigName)
		t.toTop(curMsg)
		wpkName := fmt.Sprintf("wpk%d", layer)
		t.rawBlock([]string{"_psp", "_ta", "_kp", wsigName, curMsg}, wpkName, func(e func(StackOp)) {
			// Stack: psp(4) ta8(3) kp4(2) wotsSig(1) msg(0)
			emitSLHWotsAll(e, p, layer)
			// Stack: psp(3) ta8(2) kp4(1) wotsPk(0)
			e(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
			e(StackOp{Op: "drop"})
			e(StackOp{Op: "drop"})
			e(StackOp{Op: "drop"})
			e(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		})

		// Merkle: copy psp/ta8/kp4 + leafIdx + authPath + wotsPk -> root
		t.copyToTop("_pkSeedPad", "_psp")
		t.copyToTop("treeAddr8", "_ta")
		t.copyToTop("keypair4", "_kp")
		t.toTop("leafIdx")
		authName := fmt.Sprintf("auth%d", layer)
		t.toTop(authName)
		t.toTop(wpkName)
		rootName := fmt.Sprintf("root%d", layer)
		t.rawBlock([]string{"_psp", "_ta", "_kp", "leafIdx", authName, wpkName}, rootName, func(e func(StackOp)) {
			// Stack: psp(5) ta8(4) kp4(3) leafIdx(2) authPath(1) node(0)
			emitSLHMerkle(e, p, layer)
			// Stack: psp(3) ta8(2) kp4(1) root(0)
			e(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
			e(StackOp{Op: "drop"})
			e(StackOp{Op: "drop"})
			e(StackOp{Op: "drop"})
			e(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
		})

		// Update leafIdx, treeIdx, treeAddr8, keypair4 for next layer
		if layer < d-1 {
			t.toTop("treeIdx")
			t.dup("_tic")
			// leafIdx = _tic % (1 << hp)
			t.rawBlock([]string{"_tic"}, "leafIdx", func(e func(StackOp)) {
				e(StackOp{Op: "push", Value: bigIntPush(int64(1 << hp))})
				e(StackOp{Op: "opcode", Code: "OP_MOD"})
			})
			// treeIdx = treeIdx >> hp
			t.swap()
			t.rawBlock([]string{"treeIdx"}, "treeIdx", func(e func(StackOp)) {
				e(StackOp{Op: "push", Value: bigIntPush(int64(1 << hp))})
				e(StackOp{Op: "opcode", Code: "OP_DIV"})
			})

			// Update treeAddr8 = new treeIdx as 8-byte BE
			// Drop old treeAddr8
			t.toTop("treeAddr8")
			t.drop()
			t.copyToTop("treeIdx", "_ti8")
			t.rawBlock([]string{"_ti8"}, "treeAddr8", func(e func(StackOp)) {
				e(StackOp{Op: "push", Value: bigIntPush(8)})
				e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
				for _, op := range emitReverseN(8) {
					e(op)
				}
			})

			// Update keypair4 = new leafIdx as 4-byte BE
			// Drop old keypair4
			t.toTop("keypair4")
			t.drop()
			t.copyToTop("leafIdx", "_li4")
			t.rawBlock([]string{"_li4"}, "keypair4", func(e func(StackOp)) {
				e(StackOp{Op: "push", Value: bigIntPush(4)})
				e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
				for _, op := range emitReverseN(4) {
					e(op)
				}
			})
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
	leftover := []string{"msg", "R", "pkSeed", "htSigRest", "treeIdx", "leafIdx",
		"_pkSeedPad", "treeAddr8", "keypair4"}
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
}
