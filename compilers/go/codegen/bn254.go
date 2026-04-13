// BN254 codegen -- BN254 elliptic curve field arithmetic and G1 point operations
// for Bitcoin Script.
//
// Follows the ec.go pattern: self-contained module imported by stack.go.
// Uses a BN254Tracker (mirrors ECTracker) for named stack state tracking.
//
// BN254 parameters:
//   Field prime: p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
//   Curve order: r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//   Curve:       y^2 = x^3 + 3
//   Generator:   G1 = (1, 2)
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

// bn254FieldP is the BN254 field prime.
var bn254FieldP *big.Int

// bn254FieldPMinus2 is p - 2, used for Fermat's little theorem modular inverse.
var bn254FieldPMinus2 *big.Int

// bn254CurveR is the BN254 curve order.
var bn254CurveR *big.Int

// bn254GenX is the BN254 G1 generator x-coordinate.
var bn254GenX *big.Int

// bn254GenY is the BN254 G1 generator y-coordinate.
var bn254GenY *big.Int

func init() {
	var ok bool
	bn254FieldP, ok = new(big.Int).SetString("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16)
	if !ok {
		panic("bn254: failed to parse field prime")
	}
	bn254FieldPMinus2 = new(big.Int).Sub(bn254FieldP, big.NewInt(2))
	bn254CurveR, ok = new(big.Int).SetString("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)
	if !ok {
		panic("bn254: failed to parse curve order")
	}
	bn254GenX = big.NewInt(1)
	bn254GenY = big.NewInt(2)
}

// ===========================================================================
// BN254Tracker -- named stack state tracker (mirrors ECTracker)
// ===========================================================================

// BN254Tracker tracks named stack positions and emits StackOps for BN254 codegen.
type BN254Tracker struct {
	nm             []string // stack names ("" for anonymous)
	e              func(StackOp)
	primeCacheActive bool // true when the field prime is cached on the alt-stack
	// qAtBottom indicates the field modulus is stored at the bottom of the main stack.
	// When true, fetchPrime uses OP_DEPTH OP_1SUB OP_PICK instead of alt-stack.
	// This frees the alt-stack for other uses at the same 3-byte cost.
	qAtBottom bool
	// modThreshold controls deferred mod reduction in the flat emitter.
	// 0 = always reduce (default), >0 = only reduce when estimated byte size exceeds threshold.
	modThreshold int
}

// NewBN254Tracker creates a new tracker with initial named stack slots.
func NewBN254Tracker(init []string, emit func(StackOp)) *BN254Tracker {
	nm := make([]string, len(init))
	copy(nm, init)
	return &BN254Tracker{nm: nm, e: emit}
}

// PushPrimeCache pushes the BN254 field prime onto the alt-stack for caching.
// Subsequent calls to bn254FieldMod will use OP_FROMALTSTACK/DUP/OP_TOALTSTACK
// instead of pushing the 34-byte prime literal, saving ~93 bytes per Fp mod.
func (t *BN254Tracker) PushPrimeCache() {
	t.pushBigInt("_pcache_p", bn254FieldP)
	t.op("OP_TOALTSTACK")
	if len(t.nm) > 0 {
		t.nm = t.nm[:len(t.nm)-1]
	}
	t.primeCacheActive = true
}

// PopPrimeCache removes the cached field prime from the alt-stack.
func (t *BN254Tracker) PopPrimeCache() {
	t.op("OP_FROMALTSTACK")
	t.nm = append(t.nm, "_pcache_cleanup")
	t.drop()
	t.primeCacheActive = false
}

// SetQAtBottom marks that the field modulus is already at the bottom of the
// main stack. When active, fetchPrime uses OP_DEPTH OP_1SUB OP_PICK (3 bytes)
// instead of the alt-stack pattern, freeing the alt-stack for other uses.
func (t *BN254Tracker) SetQAtBottom() {
	t.qAtBottom = true
}

// PushQToBottom pushes the BN254 field prime and sinks it to the bottom
// of the main stack. Sets qAtBottom = true so that subsequent prime fetches
// use OP_DEPTH OP_1SUB OP_PICK.
//
// Implementation: pushes the prime, then uses OP_TOALTSTACK to shuttle all
// N existing items off the stack, leaving the prime alone on the main stack,
// then OP_FROMALTSTACK to bring everything back on top of it. This costs
// 2*N single-byte opcodes but is only done once at setup.
func (t *BN254Tracker) PushQToBottom() {
	t.pushBigInt("_qbot_p", bn254FieldP)
	// Number of items below _qbot_p (everything that was there before the push)
	depth := len(t.nm) - 1
	if depth > 0 {
		// Save tracked names before rawBlock
		savedNames := make([]string, depth)
		copy(savedNames, t.nm[:depth])
		// rawBlock consumes all names (including _qbot_p) and we rebuild
		allNames := make([]string, len(t.nm))
		copy(allNames, t.nm)
		t.rawBlock(allNames, "", func(e func(StackOp)) {
			// Shuttle all items above the prime off to alt-stack
			for i := 0; i < depth; i++ {
				e(StackOp{Op: "swap"})
				e(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
			}
			// Now only _qbot_p is on the main stack.
			// Bring everything back from alt-stack (LIFO = reverse order)
			for i := 0; i < depth; i++ {
				e(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
			}
		})
		// Rebuild tracker: prime at bottom, then original items on top
		t.nm = append(t.nm, "_qbot_p")
		t.nm = append(t.nm, savedNames...)
	}
	t.qAtBottom = true
	t.primeCacheActive = true
}

// PopQFromBottom removes the field prime from the bottom of the main stack.
func (t *BN254Tracker) PopQFromBottom() {
	// Roll bottom element to top, then drop it
	depth := len(t.nm) - 1
	if depth >= 0 {
		// Find _qbot_p in nm
		idx := -1
		for i, n := range t.nm {
			if n == "_qbot_p" {
				idx = i
				break
			}
		}
		if idx >= 0 {
			rollDepth := len(t.nm) - 1 - idx
			t.roll(rollDepth)
			t.drop()
		}
	}
	t.qAtBottom = false
	t.primeCacheActive = false
}

func (t *BN254Tracker) findDepth(name string) int {
	for i := len(t.nm) - 1; i >= 0; i-- {
		if t.nm[i] == name {
			return len(t.nm) - 1 - i
		}
	}
	panic(fmt.Sprintf("BN254Tracker: '%s' not on stack %v", name, t.nm))
}

func (t *BN254Tracker) pushBytes(n string, v []byte) {
	t.e(StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: v}})
	t.nm = append(t.nm, n)
}

func (t *BN254Tracker) pushBigInt(n string, v *big.Int) {
	t.e(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(v)}})
	t.nm = append(t.nm, n)
}

func (t *BN254Tracker) pushInt(n string, v int64) {
	t.e(StackOp{Op: "push", Value: bigIntPush(v)})
	t.nm = append(t.nm, n)
}

func (t *BN254Tracker) dup(n string) {
	t.e(StackOp{Op: "dup"})
	t.nm = append(t.nm, n)
}

func (t *BN254Tracker) drop() {
	t.e(StackOp{Op: "drop"})
	if len(t.nm) > 0 {
		t.nm = t.nm[:len(t.nm)-1]
	}
}

func (t *BN254Tracker) nip() {
	t.e(StackOp{Op: "nip"})
	L := len(t.nm)
	if L >= 2 {
		t.nm = append(t.nm[:L-2], t.nm[L-1])
	}
}

func (t *BN254Tracker) over(n string) {
	t.e(StackOp{Op: "over"})
	t.nm = append(t.nm, n)
}

func (t *BN254Tracker) swap() {
	t.e(StackOp{Op: "swap"})
	L := len(t.nm)
	if L >= 2 {
		t.nm[L-1], t.nm[L-2] = t.nm[L-2], t.nm[L-1]
	}
}

func (t *BN254Tracker) rot() {
	t.e(StackOp{Op: "rot"})
	L := len(t.nm)
	if L >= 3 {
		r := t.nm[L-3]
		t.nm = append(t.nm[:L-3], t.nm[L-2:]...)
		t.nm = append(t.nm, r)
	}
}

func (t *BN254Tracker) op(code string) {
	t.e(StackOp{Op: "opcode", Code: code})
}

func (t *BN254Tracker) roll(d int) {
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

func (t *BN254Tracker) pick(d int, n string) {
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

func (t *BN254Tracker) toTop(name string) {
	t.roll(t.findDepth(name))
}

func (t *BN254Tracker) copyToTop(name, n string) {
	t.pick(t.findDepth(name), n)
}

func (t *BN254Tracker) toAlt() {
	t.op("OP_TOALTSTACK")
	if len(t.nm) > 0 {
		t.nm = t.nm[:len(t.nm)-1]
	}
}

func (t *BN254Tracker) fromAlt(n string) {
	t.op("OP_FROMALTSTACK")
	t.nm = append(t.nm, n)
}

func (t *BN254Tracker) rename(n string) {
	if len(t.nm) > 0 {
		t.nm[len(t.nm)-1] = n
	}
}

// rawBlock emits raw opcodes; tracker only records net stack effect.
// produce="" means no output pushed.
func (t *BN254Tracker) rawBlock(consume []string, produce string, fn func(emit func(StackOp))) {
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
func (t *BN254Tracker) emitIf(condName string, thenFn func(func(StackOp)), elseFn func(func(StackOp)), resultName string) {
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

// bn254PushFieldP pushes the BN254 field prime p onto the stack.
func bn254PushFieldP(t *BN254Tracker, name string) {
	t.pushBigInt(name, bn254FieldP)
}

// bn254FieldMod reduces TOS mod p, ensuring non-negative result.
// Pattern: (a % p + p) % p
//
// When primeCacheActive is true, the field prime is fetched from a cache:
//   - qAtBottom: uses OP_DEPTH OP_1SUB OP_PICK (3 bytes, prime at stack bottom)
//   - otherwise: uses OP_FROMALTSTACK/DUP/OP_TOALTSTACK (3 bytes, alt-stack)
// Both save ~93 bytes per mod reduction vs pushing a fresh 34-byte literal.
// At ~70,000 Fp operations in a Groth16 verifier, this totals ~6.5 MB saved.
func bn254FieldMod(t *BN254Tracker, aName, resultName string) {
	t.toTop(aName)
	if t.primeCacheActive {
		t.rawBlock([]string{aName}, resultName, func(e func(StackOp)) {
			if t.qAtBottom {
				e(StackOp{Op: "opcode", Code: "OP_DEPTH"})
				e(StackOp{Op: "opcode", Code: "OP_1SUB"})
				e(StackOp{Op: "opcode", Code: "OP_PICK"})
			} else {
				e(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
				e(StackOp{Op: "opcode", Code: "OP_DUP"})
				e(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
			}
			// [a, p] -> TUCK -> [p, a, p]
			e(StackOp{Op: "opcode", Code: "OP_TUCK"})
			// [p, a, p] -> MOD -> [p, a%p]
			e(StackOp{Op: "opcode", Code: "OP_MOD"})
			// [p, a%p] -> OVER -> [p, a%p, p]
			e(StackOp{Op: "over"})
			// [p, a%p, p] -> ADD -> [p, a%p+p]
			e(StackOp{Op: "opcode", Code: "OP_ADD"})
			// [p, a%p+p] -> SWAP -> [a%p+p, p]
			e(StackOp{Op: "swap"})
			// [a%p+p, p] -> MOD -> [(a%p+p)%p]
			e(StackOp{Op: "opcode", Code: "OP_MOD"})
		})
	} else {
		bn254PushFieldP(t, "_fmod_p")
		t.rawBlock([]string{aName, "_fmod_p"}, resultName, func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_TUCK"})
			e(StackOp{Op: "opcode", Code: "OP_MOD"})
			e(StackOp{Op: "over"})
			e(StackOp{Op: "opcode", Code: "OP_ADD"})
			e(StackOp{Op: "swap"})
			e(StackOp{Op: "opcode", Code: "OP_MOD"})
		})
	}
}

// bn254FieldAdd computes (a + b) mod p.
// Both operands are non-negative, so the sum is non-negative; use single-mod.
func bn254FieldAdd(t *BN254Tracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	if t.qAtBottom {
		t.rawBlock([]string{aName, bName}, resultName, func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_ADD"})
			e(StackOp{Op: "opcode", Code: "OP_DEPTH"})
			e(StackOp{Op: "opcode", Code: "OP_1SUB"})
			e(StackOp{Op: "opcode", Code: "OP_PICK"})
			e(StackOp{Op: "opcode", Code: "OP_MOD"})
		})
		return
	}
	t.rawBlock([]string{aName, bName}, "_fadd_sum", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	bn254FieldModPositive(t, "_fadd_sum", resultName)
}

// bn254FieldAddUnreduced computes a + b WITHOUT modular reduction.
// The result is in [0, 2p-2] for inputs in [0, p-1]. This is safe for
// intermediate values that will be immediately consumed by multiplication,
// which applies its own mod reduction. Skipping the mod here saves one
// full (a % p + p) % p reduction per call site.
//
// SAFETY: Only use when the result is immediately consumed by
// bn254FieldMul or bn254FieldSqr. Do NOT use when the result feeds
// into comparison, another add (risk of multi-accumulation overflow in
// deeply chained adds -- though BSV script numbers can handle it), or
// is a final output value.
func bn254FieldAddUnreduced(t *BN254Tracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, resultName, func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
}

// bn254FieldSubUnreduced computes a - b WITHOUT modular reduction.
// The result may be negative (when a < b). Safe only when the result is
// immediately consumed by bn254FieldMod or fed into another operation
// that will apply mod reduction before any comparison or output.
func bn254FieldSubUnreduced(t *BN254Tracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, resultName, func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_SUB"})
	})
}

// bn254FieldMulUnreduced computes a * b WITHOUT modular reduction.
// Result can be up to p^2 ~ 2^508 (64 bytes). Safe for BSV (supports up to
// 32 MB numbers). Use when the result will be consumed by further arithmetic
// before a final mod reduction.
func bn254FieldMulUnreduced(t *BN254Tracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	t.rawBlock([]string{aName, bName}, resultName, func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
}

// bn254FieldSub computes (a - b) mod p (non-negative).
// Computes (a - b + p) mod p. Works for a >= 0 (including unreduced values)
// and b in [0, p-1]. The single OP_MOD handles the reduction correctly since
// a - b + p is always positive. Fetches p once and reuses it for both add and mod.
func bn254FieldSub(t *BN254Tracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	if t.primeCacheActive {
		// Single rawBlock: (a - b + p) % p, fetching p once using TUCK
		t.rawBlock([]string{aName, bName}, resultName, func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_SUB"}) // [diff]
			if t.qAtBottom {
				e(StackOp{Op: "opcode", Code: "OP_DEPTH"})
				e(StackOp{Op: "opcode", Code: "OP_1SUB"})
				e(StackOp{Op: "opcode", Code: "OP_PICK"})
			} else {
				e(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
				e(StackOp{Op: "opcode", Code: "OP_DUP"})
				e(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
			}
			// [diff, p] -> TUCK -> [p, diff, p]
			e(StackOp{Op: "opcode", Code: "OP_TUCK"})
			// [p, diff, p] -> ADD -> [p, diff+p]
			e(StackOp{Op: "opcode", Code: "OP_ADD"})
			// [p, diff+p] -> SWAP -> [diff+p, p]
			e(StackOp{Op: "swap"})
			// [diff+p, p] -> MOD -> [(diff+p)%p]
			e(StackOp{Op: "opcode", Code: "OP_MOD"})
		})
	} else {
		t.rawBlock([]string{aName, bName}, "_fsub_diff", func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_SUB"})
		})
		bn254FieldMod(t, "_fsub_diff", resultName)
	}
}

// bn254FieldMul computes (a * b) mod p.
// Since both operands are non-negative (field elements or unreduced sums/products),
// the product is always non-negative, so we use the optimized single-mod reduction.
func bn254FieldMul(t *BN254Tracker, aName, bName, resultName string) {
	t.toTop(aName)
	t.toTop(bName)
	if t.qAtBottom {
		// Flat: a b -> a*b -> (a*b) % q. All in one rawBlock.
		t.rawBlock([]string{aName, bName}, resultName, func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_MUL"})
			e(StackOp{Op: "opcode", Code: "OP_DEPTH"})
			e(StackOp{Op: "opcode", Code: "OP_1SUB"})
			e(StackOp{Op: "opcode", Code: "OP_PICK"})
			e(StackOp{Op: "opcode", Code: "OP_MOD"})
		})
		return
	}
	t.rawBlock([]string{aName, bName}, "_fmul_prod", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_MUL"})
	})
	bn254FieldModPositive(t, "_fmul_prod", resultName)
}

// bn254FieldModPositive reduces a non-negative value modulo p using a single OP_MOD.
// This is an optimization over bn254FieldMod which uses the double-mod (a%p+p)%p
// to handle negative inputs. When we know the input is non-negative (e.g., after
// OP_MUL of two non-negative values, or after OP_ADD of non-negative values),
// a single a%p suffices and saves 6 bytes per call (5 bytes vs 11 bytes).
//
// SAFETY: Only use when the input is guaranteed non-negative. After OP_SUB, the
// result can be negative and MUST use bn254FieldMod instead.
func bn254FieldModPositive(t *BN254Tracker, aName, resultName string) {
	t.toTop(aName)
	if t.primeCacheActive {
		t.rawBlock([]string{aName}, resultName, func(e func(StackOp)) {
			if t.qAtBottom {
				e(StackOp{Op: "opcode", Code: "OP_DEPTH"})
				e(StackOp{Op: "opcode", Code: "OP_1SUB"})
				e(StackOp{Op: "opcode", Code: "OP_PICK"})
			} else {
				e(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
				e(StackOp{Op: "opcode", Code: "OP_DUP"})
				e(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
			}
			// [a, p] -> a % p (single mod, since a >= 0)
			e(StackOp{Op: "opcode", Code: "OP_MOD"})
		})
	} else {
		bn254PushFieldP(t, "_fmodp_p")
		t.rawBlock([]string{aName, "_fmodp_p"}, resultName, func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_MOD"})
		})
	}
}

// bn254FieldSqr computes (a * a) mod p.
func bn254FieldSqr(t *BN254Tracker, aName, resultName string) {
	t.copyToTop(aName, "_fsqr_copy")
	bn254FieldMul(t, aName, "_fsqr_copy", resultName)
}

// bn254FieldNeg computes (p - a) mod p.
// Since a is a field element in [0, p-1], p - a is always in [1, p].
// We fetch p once, DUP for reuse: one copy for the subtraction, one for the mod.
func bn254FieldNeg(t *BN254Tracker, aName, resultName string) {
	t.toTop(aName)
	if t.primeCacheActive {
		t.rawBlock([]string{aName}, resultName, func(e func(StackOp)) {
			// [a]
			if t.qAtBottom {
				e(StackOp{Op: "opcode", Code: "OP_DEPTH"})
				e(StackOp{Op: "opcode", Code: "OP_1SUB"})
				e(StackOp{Op: "opcode", Code: "OP_PICK"})
			} else {
				e(StackOp{Op: "opcode", Code: "OP_FROMALTSTACK"})
				e(StackOp{Op: "opcode", Code: "OP_DUP"})
				e(StackOp{Op: "opcode", Code: "OP_TOALTSTACK"})
			}
			// [a, p] -> DUP -> [a, p, p]
			e(StackOp{Op: "opcode", Code: "OP_DUP"})
			// [a, p, p] -> ROT -> [p, p, a]
			e(StackOp{Op: "rot"})
			// [p, p, a] -> SUB -> [p, p-a]
			e(StackOp{Op: "opcode", Code: "OP_SUB"})
			// [p, p-a] -> SWAP -> [p-a, p]
			e(StackOp{Op: "swap"})
			// [p-a, p] -> MOD -> [(p-a)%p]
			e(StackOp{Op: "opcode", Code: "OP_MOD"})
		})
	} else {
		bn254PushFieldP(t, "_fneg_p")
		t.rawBlock([]string{aName, "_fneg_p"}, resultName, func(e func(StackOp)) {
			e(StackOp{Op: "opcode", Code: "OP_DUP"})
			e(StackOp{Op: "rot"})
			e(StackOp{Op: "opcode", Code: "OP_SUB"})
			e(StackOp{Op: "swap"})
			e(StackOp{Op: "opcode", Code: "OP_MOD"})
		})
	}
}

// bn254FieldInv computes a^(p-2) mod p via square-and-multiply (Fermat's little theorem).
//
// BN254 p is a 254-bit prime, so p-2 is also 254 bits with MSB at bit 253. We
// handle the MSB by initializing result = a (which is equivalent to processing
// bit 253 with an empty accumulator), then loop over bits 252 down to 0. That
// gives 253 squarings (one per loop iteration) plus one conditional multiply
// per set bit in positions 252..0. The popcount of p-2 is 110 total; one of
// those is the implicit MSB, so the loop performs 109 multiplies.
//
// NOTE: This is not constant-time — the branch pattern depends on the bits of p-2.
// Since p-2 is a public constant this does not leak secret information. If field
// inversion of secret values is ever needed, a constant-time variant should be used.
func bn254FieldInv(t *BN254Tracker, aName, resultName string) {
	// result = a implicitly handles bit 253 (the MSB of p-2, always set)
	t.copyToTop(aName, "_inv_r")

	// Process bits 252 down to 0 (253 iterations, one squaring each)
	for i := 252; i >= 0; i-- {
		// Always square
		bn254FieldSqr(t, "_inv_r", "_inv_r2")
		t.rename("_inv_r")

		// Multiply if bit is set
		if bn254FieldPMinus2.Bit(i) == 1 {
			t.copyToTop(aName, "_inv_a")
			bn254FieldMul(t, "_inv_r", "_inv_a", "_inv_m")
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

// bn254DecomposePoint decomposes a 64-byte Point into (x_num, y_num) on stack.
// Consumes pointName, produces xName and yName.
func bn254DecomposePoint(t *BN254Tracker, pointName, xName, yName string) {
	t.toTop(pointName)
	// OP_SPLIT at 32 produces x_bytes (bottom) and y_bytes (top)
	t.rawBlock([]string{pointName}, "", func(e func(StackOp)) {
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

// bn254ComposePoint composes (x_num, y_num) into a 64-byte Point.
// Consumes xName and yName, produces resultName.
//
// IMPORTANT: Callers must ensure x and y are valid field elements in [0, p-1].
// This function does not validate input range. Passing values >= p will produce
// incorrect big-endian encodings.
func bn254ComposePoint(t *BN254Tracker, xName, yName, resultName string) {
	// Convert x to 32-byte big-endian
	t.toTop(xName)
	t.rawBlock([]string{xName}, "_cp_xb", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(33)})
		e(StackOp{Op: "opcode", Code: "OP_NUM2BIN"})
		// Drop the sign byte (last byte) -- split at 32, keep left
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

// ===========================================================================
// Affine point addition (for bn254G1Add)
// ===========================================================================

// bn254G1AffineAdd performs affine point addition on BN254 G1.
// Expects px, py, qx, qy on tracker. Produces rx, ry. Consumes all four inputs.
func bn254G1AffineAdd(t *BN254Tracker) {
	// s_num = qy - py
	t.copyToTop("qy", "_qy1")
	t.copyToTop("py", "_py1")
	bn254FieldSub(t, "_qy1", "_py1", "_s_num")

	// s_den = qx - px
	t.copyToTop("qx", "_qx1")
	t.copyToTop("px", "_px1")
	bn254FieldSub(t, "_qx1", "_px1", "_s_den")

	// s = s_num / s_den mod p
	bn254FieldInv(t, "_s_den", "_s_den_inv")
	bn254FieldMul(t, "_s_num", "_s_den_inv", "_s")

	// rx = s^2 - px - qx mod p
	t.copyToTop("_s", "_s_keep")
	bn254FieldSqr(t, "_s", "_s2")
	t.copyToTop("px", "_px2")
	bn254FieldSub(t, "_s2", "_px2", "_rx1")
	t.copyToTop("qx", "_qx2")
	bn254FieldSub(t, "_rx1", "_qx2", "rx")

	// ry = s * (px - rx) - py mod p
	t.copyToTop("px", "_px3")
	t.copyToTop("rx", "_rx2")
	bn254FieldSub(t, "_px3", "_rx2", "_px_rx")
	bn254FieldMul(t, "_s_keep", "_px_rx", "_s_px_rx")
	t.copyToTop("py", "_py2")
	bn254FieldSub(t, "_s_px_rx", "_py2", "ry")

	// Clean up original points
	t.toTop("px")
	t.drop()
	t.toTop("py")
	t.drop()
	t.toTop("qx")
	t.drop()
	t.toTop("qy")
	t.drop()
}

// ===========================================================================
// Jacobian point operations (for bn254G1ScalarMul)
// ===========================================================================

// bn254G1JacobianDouble performs Jacobian point doubling (a=0 for BN254).
// Expects jx, jy, jz on tracker. Replaces with updated values.
//
// Formulas (a=0 since y^2 = x^3 + b):
//   A  = Y^2
//   B  = 4*X*A
//   C  = 8*A^2
//   D  = 3*X^2  (a=0, so 3*X^2 + a*Z^4 simplifies to 3*X^2)
//   X' = D^2 - 2*B
//   Y' = D*(B - X') - C
//   Z' = 2*Y*Z
func bn254G1JacobianDouble(t *BN254Tracker) {
	// Save copies of jx, jy, jz for later use
	t.copyToTop("jy", "_jy_save")
	t.copyToTop("jx", "_jx_save")
	t.copyToTop("jz", "_jz_save")

	// A = jy^2
	bn254FieldSqr(t, "jy", "_A")

	// B = 4 * jx * A
	t.copyToTop("_A", "_A_save")
	bn254FieldMul(t, "jx", "_A", "_xA")
	t.pushInt("_four", 4)
	bn254FieldMul(t, "_xA", "_four", "_B")

	// C = 8 * A^2
	bn254FieldSqr(t, "_A_save", "_A2")
	t.pushInt("_eight", 8)
	bn254FieldMul(t, "_A2", "_eight", "_C")

	// D = 3 * X^2
	bn254FieldSqr(t, "_jx_save", "_x2")
	t.pushInt("_three", 3)
	bn254FieldMul(t, "_x2", "_three", "_D")

	// nx = D^2 - 2*B
	t.copyToTop("_D", "_D_save")
	t.copyToTop("_B", "_B_save")
	bn254FieldSqr(t, "_D", "_D2")
	t.copyToTop("_B", "_B1")
	bn254FieldMulConst(t, "_B1", 2, "_2B")
	bn254FieldSub(t, "_D2", "_2B", "_nx")

	// ny = D*(B - nx) - C
	t.copyToTop("_nx", "_nx_copy")
	bn254FieldSub(t, "_B_save", "_nx_copy", "_B_nx")
	bn254FieldMul(t, "_D_save", "_B_nx", "_D_B_nx")
	bn254FieldSub(t, "_D_B_nx", "_C", "_ny")

	// nz = 2 * Y * Z
	bn254FieldMul(t, "_jy_save", "_jz_save", "_yz")
	bn254FieldMulConst(t, "_yz", 2, "_nz")

	// Clean up leftovers: _B and old jz
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

// bn254G1JacobianToAffine converts Jacobian to affine coordinates.
// Consumes jx, jy, jz; produces rxName, ryName.
func bn254G1JacobianToAffine(t *BN254Tracker, rxName, ryName string) {
	bn254FieldInv(t, "jz", "_zinv")
	t.copyToTop("_zinv", "_zinv_keep")
	bn254FieldSqr(t, "_zinv", "_zinv2")
	t.copyToTop("_zinv2", "_zinv2_keep")
	bn254FieldMul(t, "_zinv_keep", "_zinv2", "_zinv3")
	bn254FieldMul(t, "jx", "_zinv2_keep", rxName)
	bn254FieldMul(t, "jy", "_zinv3", ryName)
}

// ===========================================================================
// Jacobian mixed addition (P_jacobian + Q_affine)
// ===========================================================================

// bn254BuildJacobianAddAffineInline builds Jacobian mixed-add ops for use inside OP_IF.
// Uses an inner BN254Tracker to leverage field arithmetic helpers.
//
// Stack layout: [..., ax, ay, _k, jx, jy, jz]
// After:        [..., ax, ay, _k, jx', jy', jz']
func bn254BuildJacobianAddAffineInline(e func(StackOp), t *BN254Tracker) {
	// Create inner tracker with cloned stack state
	initNm := make([]string, len(t.nm))
	copy(initNm, t.nm)
	it := NewBN254Tracker(initNm, e)
	// Propagate prime cache state: the cached prime on the alt-stack is
	// accessible within OP_IF branches since alt-stack persists across
	// IF/ELSE/ENDIF boundaries.
	it.primeCacheActive = t.primeCacheActive

	// Save copies of values that get consumed but are needed later
	it.copyToTop("jz", "_jz_for_z1cu")  // consumed by Z1sq, needed for Z1cu
	it.copyToTop("jz", "_jz_for_z3")    // needed for Z3
	it.copyToTop("jy", "_jy_for_y3")    // consumed by R, needed for Y3
	it.copyToTop("jx", "_jx_for_u1h2")  // consumed by H, needed for U1H2

	// Z1sq = jz^2
	bn254FieldSqr(it, "jz", "_Z1sq")

	// Z1cu = _jz_for_z1cu * Z1sq (copy Z1sq for U2)
	it.copyToTop("_Z1sq", "_Z1sq_for_u2")
	bn254FieldMul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu")

	// U2 = ax * Z1sq_for_u2
	it.copyToTop("ax", "_ax_c")
	bn254FieldMul(it, "_ax_c", "_Z1sq_for_u2", "_U2")

	// S2 = ay * Z1cu
	it.copyToTop("ay", "_ay_c")
	bn254FieldMul(it, "_ay_c", "_Z1cu", "_S2")

	// H = U2 - jx
	bn254FieldSub(it, "_U2", "jx", "_H")

	// R = S2 - jy
	bn254FieldSub(it, "_S2", "jy", "_R")

	// Save copies of H (consumed by H2 sqr, needed for H3 and Z3)
	it.copyToTop("_H", "_H_for_h3")
	it.copyToTop("_H", "_H_for_z3")

	// H2 = H^2
	bn254FieldSqr(it, "_H", "_H2")

	// Save H2 for U1H2
	it.copyToTop("_H2", "_H2_for_u1h2")

	// H3 = H_for_h3 * H2
	bn254FieldMul(it, "_H_for_h3", "_H2", "_H3")

	// U1H2 = _jx_for_u1h2 * H2_for_u1h2
	bn254FieldMul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2")

	// Save R, U1H2, H3 for Y3 computation
	it.copyToTop("_R", "_R_for_y3")
	it.copyToTop("_U1H2", "_U1H2_for_y3")
	it.copyToTop("_H3", "_H3_for_y3")

	// X3 = R^2 - H3 - 2*U1H2
	bn254FieldSqr(it, "_R", "_R2")
	bn254FieldSub(it, "_R2", "_H3", "_x3_tmp")
	bn254FieldMulConst(it, "_U1H2", 2, "_2U1H2")
	bn254FieldSub(it, "_x3_tmp", "_2U1H2", "_X3")

	// Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
	it.copyToTop("_X3", "_X3_c")
	bn254FieldSub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x")
	bn254FieldMul(it, "_R_for_y3", "_u_minus_x", "_r_tmp")
	bn254FieldMul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3")
	bn254FieldSub(it, "_r_tmp", "_jy_h3", "_Y3")

	// Z3 = _jz_for_z3 * _H_for_z3
	bn254FieldMul(it, "_jz_for_z3", "_H_for_z3", "_Z3")

	// Rename results to jx/jy/jz
	it.toTop("_X3")
	it.rename("jx")
	it.toTop("_Y3")
	it.rename("jy")
	it.toTop("_Z3")
	it.rename("jz")
}

// ===========================================================================
// G1 point negation
// ===========================================================================

// bn254G1Negate negates a point: (x, p - y).
func bn254G1Negate(t *BN254Tracker, pointName, resultName string) {
	bn254DecomposePoint(t, pointName, "_nx", "_ny")
	// Use bn254FieldNeg which already handles prime caching
	bn254FieldNeg(t, "_ny", "_neg_y")
	bn254ComposePoint(t, "_nx", "_neg_y", resultName)
}

// ===========================================================================
// Public emit functions -- entry points called from stack.go
// ===========================================================================

// EmitBN254FieldAdd emits BN254 field addition.
// Stack in: [..., a, b] (b on top)
// Stack out: [..., (a + b) mod p]
func EmitBN254FieldAdd(emit func(StackOp)) {
	t := NewBN254Tracker([]string{"a", "b"}, emit)
	t.PushPrimeCache()
	bn254FieldAdd(t, "a", "b", "result")
	t.PopPrimeCache()
}

// EmitBN254FieldSub emits BN254 field subtraction.
// Stack in: [..., a, b] (b on top)
// Stack out: [..., (a - b) mod p]
func EmitBN254FieldSub(emit func(StackOp)) {
	t := NewBN254Tracker([]string{"a", "b"}, emit)
	t.PushPrimeCache()
	bn254FieldSub(t, "a", "b", "result")
	t.PopPrimeCache()
}

// EmitBN254FieldMul emits BN254 field multiplication.
// Stack in: [..., a, b] (b on top)
// Stack out: [..., (a * b) mod p]
func EmitBN254FieldMul(emit func(StackOp)) {
	t := NewBN254Tracker([]string{"a", "b"}, emit)
	t.PushPrimeCache()
	bn254FieldMul(t, "a", "b", "result")
	t.PopPrimeCache()
}

// EmitBN254FieldInv emits BN254 field multiplicative inverse.
// Stack in: [..., a]
// Stack out: [..., a^(p-2) mod p]
func EmitBN254FieldInv(emit func(StackOp)) {
	t := NewBN254Tracker([]string{"a"}, emit)
	t.PushPrimeCache()
	bn254FieldInv(t, "a", "result")
	t.PopPrimeCache()
}

// EmitBN254FieldNeg emits BN254 field negation.
// Stack in: [..., a]
// Stack out: [..., (p - a) mod p]
func EmitBN254FieldNeg(emit func(StackOp)) {
	t := NewBN254Tracker([]string{"a"}, emit)
	t.PushPrimeCache()
	bn254FieldNeg(t, "a", "result")
	t.PopPrimeCache()
}

// EmitBN254G1Add adds two BN254 G1 points.
// Stack in: [point_a, point_b] (b on top)
// Stack out: [result_point]
func EmitBN254G1Add(emit func(StackOp)) {
	t := NewBN254Tracker([]string{"_pa", "_pb"}, emit)
	t.PushPrimeCache()
	bn254DecomposePoint(t, "_pa", "px", "py")
	bn254DecomposePoint(t, "_pb", "qx", "qy")
	bn254G1AffineAdd(t)
	bn254ComposePoint(t, "rx", "ry", "_result")
	t.PopPrimeCache()
}

// EmitBN254G1ScalarMul performs scalar multiplication P * k on BN254 G1.
// Stack in: [point, scalar] (scalar on top)
// Stack out: [result_point]
//
// Uses 254-bit double-and-add with Jacobian coordinates.
// k' = k + 3*r guarantees bit 255 is set (r is the curve order).
func EmitBN254G1ScalarMul(emit func(StackOp)) {
	t := NewBN254Tracker([]string{"_pt", "_k"}, emit)
	t.PushPrimeCache()
	// Decompose to affine base point
	bn254DecomposePoint(t, "_pt", "ax", "ay")

	// k' = k + 3r: guarantees bit 255 is set.
	// k in [1, r-1], so k+3r in [3r+1, 4r-1]. Since 3r > 2^255, bit 255
	// is always 1. Adding 3r (= 0 mod r) preserves the EC point: k*G = (k+3r)*G.
	t.toTop("_k")
	t.pushBigInt("_r1", bn254CurveR)
	t.rawBlock([]string{"_k", "_r1"}, "_kr1", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.pushBigInt("_r2", bn254CurveR)
	t.rawBlock([]string{"_kr1", "_r2"}, "_kr2", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.pushBigInt("_r3", bn254CurveR)
	t.rawBlock([]string{"_kr2", "_r3"}, "_kr3", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_ADD"})
	})
	t.rename("_k")

	// Init accumulator = P (bit 255 of k+3r is always 1)
	t.copyToTop("ax", "jx")
	t.copyToTop("ay", "jy")
	t.pushInt("jz", 1)

	// 255 iterations: bits 254 down to 0
	for bit := 254; bit >= 0; bit-- {
		// Double accumulator
		bn254G1JacobianDouble(t)

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
		bn254BuildJacobianAddAffineInline(addEmit, t)
		emit(StackOp{Op: "if", Then: addOps, Else: []StackOp{}})
	}

	// Convert Jacobian to affine
	bn254G1JacobianToAffine(t, "_rx", "_ry")

	// Clean up base point and scalar
	t.toTop("ax")
	t.drop()
	t.toTop("ay")
	t.drop()
	t.toTop("_k")
	t.drop()

	// Compose result
	bn254ComposePoint(t, "_rx", "_ry", "_result")
	t.PopPrimeCache()
}

// EmitBN254G1Negate negates a BN254 G1 point (x, p - y).
// Stack in: [point]
// Stack out: [negated_point]
func EmitBN254G1Negate(emit func(StackOp)) {
	t := NewBN254Tracker([]string{"_pt"}, emit)
	t.PushPrimeCache()
	bn254G1Negate(t, "_pt", "_result")
	t.PopPrimeCache()
}

// EmitBN254G1OnCurve checks if point is on BN254 G1 (y^2 = x^3 + 3 mod p).
// Stack in: [point]
// Stack out: [boolean]
func EmitBN254G1OnCurve(emit func(StackOp)) {
	t := NewBN254Tracker([]string{"_pt"}, emit)
	t.PushPrimeCache()
	bn254DecomposePoint(t, "_pt", "_x", "_y")

	// lhs = y^2
	bn254FieldSqr(t, "_y", "_y2")

	// rhs = x^3 + 3
	t.copyToTop("_x", "_x_copy")
	bn254FieldSqr(t, "_x", "_x2")
	bn254FieldMul(t, "_x2", "_x_copy", "_x3")
	t.pushInt("_three", 3) // b = 3 for BN254
	bn254FieldAdd(t, "_x3", "_three", "_rhs")

	// Compare
	t.toTop("_y2")
	t.toTop("_rhs")
	t.rawBlock([]string{"_y2", "_rhs"}, "_result", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_EQUAL"})
	})
	t.PopPrimeCache()
}
