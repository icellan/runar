// BN254 flat emission codegen -- optimized opcode emission for the Groth16
// witness-assisted verifier. Instead of using BN254Tracker's named-slot system
// (which generates excessive swap/pick/roll/drop for stack management), this
// module emits fixed opcode sequences with known stack positions computed at
// codegen time.
//
// The flat emitter tracks the stack depth as a compile-time integer. Since
// field operations have deterministic stack effects, the depth is always known
// exactly. This allows pick/roll to use precomputed depth arguments,
// eliminating the tracker's O(n) name-lookup and its many unnecessary
// swap/roll ops when items are not adjacent.
//
// Key convention: q (the BN254 field modulus) is always at stack position 0
// (the bottom). To fetch it, we use push(depth) OP_PICK where depth is
// computed at codegen time (2 bytes), instead of OP_DEPTH OP_1SUB OP_PICK
// (3 bytes). Since the flat emitter always knows stackSize exactly, this
// saves 1 byte per q-fetch.
//
// Stack notation: [bottom ... top], rightmost = TOS.
// "depth" means distance from TOS: TOS is depth 0, TOS-1 is depth 1, etc.
//
// OP_SUB semantics: pops b=TOS, pops a=TOS-1, pushes a-b.
// So [..., a, b] OP_SUB -> [..., a-b].
package codegen

import "math/big"

// =========================================================================
// flatEmitter core
// =========================================================================

// flatEmitter tracks stack size at codegen time and emits optimal opcodes.
// It also tracks estimated byte sizes of values on the stack for deferred
// mod reduction (modulo threshold technique from nChain paper).
type flatEmitter struct {
	emit      func(StackOp)
	stackSize int   // current number of items on stack
	sizes     []int // estimated byte sizes of stack items (top is last element)
	modThreshold int // max bytes before mod reduction (0 = always reduce)
}

func newFlatEmitter(emit func(StackOp), initialStackSize int) *flatEmitter {
	sizes := make([]int, initialStackSize)
	for i := range sizes {
		sizes[i] = 48 // default: field element = 48 bytes
	}
	return &flatEmitter{emit: emit, stackSize: initialStackSize, sizes: sizes, modThreshold: 0}
}

// newFlatEmitterWithThreshold creates a flat emitter with deferred mod reduction.
// Values are only reduced mod q when their estimated size exceeds threshold bytes.
func newFlatEmitterWithThreshold(emit func(StackOp), initialStackSize, threshold int) *flatEmitter {
	sizes := make([]int, initialStackSize)
	for i := range sizes {
		sizes[i] = 48
	}
	return &flatEmitter{emit: emit, stackSize: initialStackSize, sizes: sizes, modThreshold: threshold}
}

// topSize returns the estimated byte size of TOS.
func (f *flatEmitter) topSize() int {
	if len(f.sizes) == 0 { return 48 }
	return f.sizes[len(f.sizes)-1]
}

// setTopSize sets the estimated byte size of TOS.
func (f *flatEmitter) setTopSize(n int) {
	if len(f.sizes) > 0 { f.sizes[len(f.sizes)-1] = n }
}

// sizeAt returns the estimated byte size at depth d (0 = TOS).
func (f *flatEmitter) sizeAt(d int) int {
	idx := len(f.sizes) - 1 - d
	if idx < 0 || idx >= len(f.sizes) { return 48 }
	return f.sizes[idx]
}

func (f *flatEmitter) push(v int64) {
	f.emit(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: big.NewInt(v)}})
	f.stackSize++
	f.sizes = append(f.sizes, 8) // small constant
}

func (f *flatEmitter) pushBig(v *big.Int) {
	f.emit(StackOp{Op: "push", Value: PushValue{Kind: "bigint", BigInt: new(big.Int).Set(v)}})
	f.stackSize++
	f.sizes = append(f.sizes, (v.BitLen()+7)/8+1)
}

func (f *flatEmitter) op(code string) {
	f.emit(StackOp{Op: "opcode", Code: code})
}

// pick copies item at depth d to TOS. stackSize += 1.
func (f *flatEmitter) pick(d int) {
	sz := f.sizeAt(d)
	if d == 0 {
		f.emit(StackOp{Op: "dup"})
	} else if d == 1 {
		f.emit(StackOp{Op: "over"})
	} else {
		f.emit(StackOp{Op: "push", Value: bigIntPush(int64(d))})
		f.emit(StackOp{Op: "pick", Depth: d})
	}
	f.stackSize++
	f.sizes = append(f.sizes, sz)
}

// roll moves item at depth d to TOS. stackSize unchanged.
func (f *flatEmitter) roll(d int) {
	if d == 0 {
		return
	}
	// Move size from position [len-1-d] to end
	idx := len(f.sizes) - 1 - d
	if idx >= 0 && idx < len(f.sizes) {
		sz := f.sizes[idx]
		f.sizes = append(f.sizes[:idx], f.sizes[idx+1:]...)
		f.sizes = append(f.sizes, sz)
	}
	if d == 1 {
		f.emit(StackOp{Op: "swap"})
	} else if d == 2 {
		f.emit(StackOp{Op: "rot"})
	} else {
		f.emit(StackOp{Op: "push", Value: bigIntPush(int64(d))})
		f.emit(StackOp{Op: "roll", Depth: d})
	}
}

func (f *flatEmitter) drop() {
	f.emit(StackOp{Op: "drop"})
	f.stackSize--
	if len(f.sizes) > 0 { f.sizes = f.sizes[:len(f.sizes)-1] }
}
func (f *flatEmitter) drop2() {
	f.emit(StackOp{Op: "opcode", Code: "OP_2DROP"})
	f.stackSize -= 2
	if len(f.sizes) >= 2 { f.sizes = f.sizes[:len(f.sizes)-2] }
}
func (f *flatEmitter) swap() {
	f.emit(StackOp{Op: "swap"})
	L := len(f.sizes)
	if L >= 2 { f.sizes[L-1], f.sizes[L-2] = f.sizes[L-2], f.sizes[L-1] }
}
func (f *flatEmitter) rot() {
	f.emit(StackOp{Op: "rot"})
	L := len(f.sizes)
	if L >= 3 {
		s := f.sizes[L-3]
		f.sizes[L-3] = f.sizes[L-2]
		f.sizes[L-2] = f.sizes[L-1]
		f.sizes[L-1] = s
	}
}
func (f *flatEmitter) dup() {
	sz := f.topSize()
	f.emit(StackOp{Op: "dup"})
	f.stackSize++
	f.sizes = append(f.sizes, sz)
}
func (f *flatEmitter) over() {
	sz := f.sizeAt(1)
	f.emit(StackOp{Op: "over"})
	f.stackSize++
	f.sizes = append(f.sizes, sz)
}
func (f *flatEmitter) nip() {
	f.emit(StackOp{Op: "nip"})
	f.stackSize--
	L := len(f.sizes)
	if L >= 2 { f.sizes = append(f.sizes[:L-2], f.sizes[L-1]) }
}
func (f *flatEmitter) tuck() {
	// TUCK: copy TOS and insert below TOS-1. [a, b] -> [b, a, b]
	sz := f.topSize()
	f.emit(StackOp{Op: "opcode", Code: "OP_TUCK"})
	f.stackSize++
	L := len(f.sizes)
	if L >= 2 {
		// Insert copy of TOS below TOS-1
		f.sizes = append(f.sizes, 0) // make room
		copy(f.sizes[L-1:], f.sizes[L-2:L])
		f.sizes[L-2] = sz
	} else {
		f.sizes = append(f.sizes, sz)
	}
}

// fetchQ copies q from stack bottom to TOS using the cheapest method.
// For stack depth <= 16: push(depth) OP_PICK uses OP_1..OP_16 (1 byte) + OP_PICK = 2 bytes.
// For stack depth 17-252: push(depth) OP_PICK uses 2 bytes + OP_PICK = 3 bytes (same as DEPTH method).
// For stack depth > 252: OP_DEPTH OP_1SUB OP_PICK = 3 bytes (cheaper than multi-byte push).
// stackSize += 1.
func (f *flatEmitter) fetchQ() {
	qDepth := f.stackSize - 1
	if qDepth <= 16 {
		// OP_1..OP_16 is 1 byte, + OP_PICK = 2 bytes total. Saves 1 byte.
		f.pick(qDepth)
		return
	}
	// For depth > 16, OP_DEPTH OP_1SUB OP_PICK is 3 bytes.
	// push(depth) OP_PICK is 2 bytes (push) + 1 byte (PICK) = 3 bytes for depth <= 252,
	// or 3+ bytes for larger depths. So DEPTH method is always <= codegen method.
	f.op("OP_DEPTH")
	f.op("OP_1SUB")
	f.op("OP_PICK")
	f.stackSize++
}

// =========================================================================
// Flat Fp (field) primitives
// =========================================================================

// modPositive: [..., a] -> [..., a%q].  (a >= 0)
func (f *flatEmitter) modPositive() {
	f.fetchQ()
	f.op("OP_MOD")
	f.stackSize--
	if len(f.sizes) > 0 { f.sizes = f.sizes[:len(f.sizes)-1] }
	f.setTopSize(48) // reduced field element
}

// modFull: [..., a] -> [... ((a%q)+q)%q].  (handles negative a)
func (f *flatEmitter) modFull() {
	f.fetchQ()          // [..., a, q]
	f.tuck()            // [..., q, a, q]
	f.op("OP_MOD")     // [..., q, a%q]
	f.stackSize--
	if len(f.sizes) > 0 { f.sizes = f.sizes[:len(f.sizes)-1] }
	f.over()            // [..., q, a%q, q]
	f.op("OP_ADD")     // [..., q, a%q+q]
	f.stackSize--
	if len(f.sizes) > 0 { f.sizes = f.sizes[:len(f.sizes)-1] }
	f.swap()            // [..., a%q+q, q]
	f.op("OP_MOD")     // [..., result]
	f.stackSize--
	if len(f.sizes) > 0 { f.sizes = f.sizes[:len(f.sizes)-1] }
	f.setTopSize(48)
}

// modPositiveIfNeeded: conditionally reduce a non-negative value mod q.
// Only emits mod if the estimated size exceeds the modulo threshold.
// [..., a] -> [..., a%q] or unchanged.
func (f *flatEmitter) modPositiveIfNeeded() {
	if f.modThreshold > 0 && f.topSize() < f.modThreshold {
		return // defer mod reduction
	}
	f.modPositive()
}

// modFullIfNeeded: conditionally reduce a possibly-negative value mod q.
// Only emits mod if the estimated size exceeds the modulo threshold.
func (f *flatEmitter) modFullIfNeeded() {
	if f.modThreshold > 0 && f.topSize() < f.modThreshold {
		return // defer mod reduction
	}
	f.modFull()
}

// fMulU: [..., a, b] -> [..., a*b] unreduced.
func (f *flatEmitter) fMulU() {
	sA, sB := f.sizeAt(1), f.sizeAt(0)
	f.op("OP_MUL")
	f.stackSize--
	if len(f.sizes) >= 2 {
		f.sizes = f.sizes[:len(f.sizes)-2]
		f.sizes = append(f.sizes, sA+sB) // product size ~ sum of input sizes
	}
}

// fMul: [..., a, b] -> [..., (a*b)%q].
func (f *flatEmitter) fMul() {
	f.fMulU()
	f.modPositiveIfNeeded()
}

// fAddU: [..., a, b] -> [..., a+b] unreduced.
func (f *flatEmitter) fAddU() {
	sA, sB := f.sizeAt(1), f.sizeAt(0)
	f.op("OP_ADD")
	f.stackSize--
	if len(f.sizes) >= 2 {
		f.sizes = f.sizes[:len(f.sizes)-2]
		maxS := sA
		if sB > maxS { maxS = sB }
		f.sizes = append(f.sizes, maxS+1) // sum size ~ max + 1
	}
}

// fAdd: [..., a, b] -> [..., (a+b)%q].
func (f *flatEmitter) fAdd() {
	f.fAddU()
	f.modPositiveIfNeeded()
}

// fSubU: [..., a, b] -> [..., a-b] unreduced.
func (f *flatEmitter) fSubU() {
	sA, sB := f.sizeAt(1), f.sizeAt(0)
	f.op("OP_SUB")
	f.stackSize--
	if len(f.sizes) >= 2 {
		f.sizes = f.sizes[:len(f.sizes)-2]
		maxS := sA
		if sB > maxS { maxS = sB }
		f.sizes = append(f.sizes, maxS+1) // difference size ~ max + 1
	}
}

// fSub: [..., a, b] -> [..., (a-b+q)%q].
func (f *flatEmitter) fSub() {
	f.fSubU()           // [..., a-b]
	if f.modThreshold > 0 && f.topSize() < f.modThreshold {
		return // defer mod -- caller handles negative values
	}
	f.fetchQ()          // [..., a-b, q]
	f.tuck()            // [..., q, a-b, q]
	f.op("OP_ADD")     // [..., q, a-b+q]
	f.stackSize--
	if len(f.sizes) > 0 { f.sizes = f.sizes[:len(f.sizes)-1] }
	f.swap()            // [..., a-b+q, q]
	f.op("OP_MOD")     // [..., result]
	f.stackSize--
	if len(f.sizes) > 0 { f.sizes = f.sizes[:len(f.sizes)-1] }
	f.setTopSize(48)
}

// fNeg: [..., a] -> [..., (q-a)%q] or [..., -a] with deferred mod.
func (f *flatEmitter) fNeg() {
	if f.modThreshold > 0 && f.topSize() < f.modThreshold {
		// Deferred: just negate with OP_NEGATE (1 byte).
		// Result is negative but within threshold.
		f.op("OP_NEGATE")
		return
	}
	f.fetchQ()          // [..., a, q]
	f.op("OP_DUP")     // [..., a, q, q]
	f.stackSize++
	f.sizes = append(f.sizes, 48)
	f.rot()             // [..., q, q, a]
	f.op("OP_SUB")     // [..., q, q-a]
	f.stackSize--
	if len(f.sizes) > 0 { f.sizes = f.sizes[:len(f.sizes)-1] }
	f.setTopSize(49)
	f.swap()            // [..., q-a, q]
	f.op("OP_MOD")     // [..., result]
	f.stackSize--
	if len(f.sizes) > 0 { f.sizes = f.sizes[:len(f.sizes)-1] }
	f.setTopSize(48)
}

// fMulConst: [..., a] -> [..., (a*c)%q].
func (f *flatEmitter) fMulConst(c int64) {
	if c == 2 {
		f.op("OP_2MUL")
		f.setTopSize(f.topSize() + 1)
	} else {
		cSize := 8
		f.push(c)
		f.op("OP_MUL")
		f.stackSize--
		if len(f.sizes) >= 2 {
			f.sizes = f.sizes[:len(f.sizes)-2]
			f.sizes = append(f.sizes, f.sizeAt(0)+cSize)
		}
	}
	f.modPositiveIfNeeded()
}

// fMulConstU: [..., a] -> [..., a*c] unreduced.
func (f *flatEmitter) fMulConstU(c int64) {
	if c == 2 {
		f.op("OP_2MUL")
		f.setTopSize(f.topSize() + 1)
	} else {
		aSize := f.topSize()
		f.push(c)
		f.op("OP_MUL")
		f.stackSize--
		if len(f.sizes) >= 2 {
			f.sizes = f.sizes[:len(f.sizes)-2]
			f.sizes = append(f.sizes, aSize+8)
		}
	}
}

// =========================================================================
// Flat Fp2 operations
// =========================================================================

// fp2MulCore: Karatsuba Fp2 multiply core logic.
// [..., a0, a1, b0, b1] -> [..., r0_raw, r1_raw] if unreduced,
// or [..., r0, r1] if reduced. Net effect: -2.
//
// When reduced=true:
//   r0 = (t0-t1) mod q  (full mod, may be negative)
//   r1 = (cross-t0-t1) mod q  (positive mod, always >= 0)
// When reduced=false:
//   r0_raw = t0-t1 (unreduced, may be negative; in [-p^2, p^2])
//   r1_raw = cross-t0-t1 (unreduced, always >= 0; in [0, 4p^2])
func (f *flatEmitter) fp2MulCore(reduced bool) {
	// Stack: a0(3) a1(2) b0(1) b1(0)

	// t0 = a0 * b0
	f.pick(3) // copy a0
	f.pick(2) // copy b0 (shifted by the pick above)
	f.fMulU() // a0 a1 b0 b1 t0

	// t1 = a1 * b1
	f.pick(3) // copy a1
	f.pick(2) // copy b1
	f.fMulU() // a0 a1 b0 b1 t0 t1

	// r0 = t0 - t1 (may be negative)
	f.over()  // copy t0
	f.over()  // copy t1
	f.fSubU()
	if reduced {
		f.modFullIfNeeded() // a0 a1 b0 b1 t0 t1 r0 (or unreduced if deferred)
	}
	// else: r0_raw is just the unreduced difference

	// cross = (a0+a1) * (b0+b1)
	f.roll(6) // bring a0 to top
	f.roll(6) // bring a1 to top
	f.fAddU()
	f.roll(5) // bring b0
	f.roll(5) // bring b1
	f.fAddU()
	f.fMulU() // t0 t1 r0 cross

	// r1 = cross - t0 - t1 (non-negative: = a0*b1 + a1*b0)
	f.roll(3) // bring t0
	f.fSubU()
	f.rot()   // bring t1
	f.fSubU()
	if reduced {
		f.modPositiveIfNeeded() // r0 r1 (or unreduced if deferred)
	}
	// else: r1_raw is the unreduced cross - t0 - t1
}

// fp2Mul: Karatsuba Fp2 multiply (fully reduced).
// [..., a0, a1, b0, b1] -> [..., r0, r1]. Net effect: -2.
func (f *flatEmitter) fp2Mul() {
	f.fp2MulCore(true)
}

// fp2MulU: Karatsuba Fp2 multiply (unreduced).
// [..., a0, a1, b0, b1] -> [..., r0_raw, r1_raw]. Net effect: -2.
// r0_raw may be negative (in [-p^2, p^2]).
// r1_raw is always >= 0 (in [0, 4p^2]).
// Results must be reduced before comparison or output.
func (f *flatEmitter) fp2MulU() {
	f.fp2MulCore(false)
}

// fp2Sqr: Fp2 squaring.
// [..., a0, a1] -> [..., r0, r1]. Net: unchanged.
func (f *flatEmitter) fp2Sqr() {
	// sum = a0 + a1 (unreduced)
	f.over()  // a0 a1 a0c
	f.over()  // a0 a1 a0c a1c
	f.fAddU() // a0 a1 sum

	// diff = a0 - a1 (unreduced)
	f.pick(2) // a0 a1 sum a0c2
	f.pick(2) // a0 a1 sum a0c2 a1c2
	f.fSubU() // a0 a1 sum diff

	// r0 = (sum * diff) mod q
	f.fMulU()          // a0 a1 (sum*diff)
	f.modFullIfNeeded() // a0 a1 r0

	// prod = a0 * a1
	f.rot()   // a1 r0 a0
	f.rot()   // r0 a0 a1
	f.fMulU() // r0 prod

	// r1 = (2*prod) mod q
	f.dup()   // r0 prod prod
	f.fAddU() // r0 2*prod
	f.modPositiveIfNeeded() // r0 r1
}

// fp2Add: [..., a0, a1, b0, b1] -> [..., r0, r1]. Net: -2.
func (f *flatEmitter) fp2Add() {
	f.rot()   // a0 b0 b1 a1  (bring a1 from depth 2 to top)
	f.swap()  // a0 b0 a1 b1
	f.fAdd()  // a0 b0 r1
	f.rot()   // b0 r1 a0
	f.rot()   // r1 a0 b0
	f.fAdd()  // r1 r0
	f.swap()  // r0 r1
}

// fp2AddU: unreduced Fp2 add. [..., a0, a1, b0, b1] -> [..., r0, r1]. Net: -2.
func (f *flatEmitter) fp2AddU() {
	f.rot()   // a0 b0 b1 a1
	f.swap()  // a0 b0 a1 b1
	f.fAddU() // a0 b0 (a1+b1)
	f.rot()   // b0 (a1+b1) a0
	f.rot()   // (a1+b1) a0 b0
	f.fAddU() // (a1+b1) (a0+b0)
	f.swap()  // (a0+b0) (a1+b1)
}

// fp2Sub: [..., a0, a1, b0, b1] -> [..., r0, r1]. Net: -2.
func (f *flatEmitter) fp2Sub() {
	f.rot()   // a0 b0 b1 a1
	f.swap()  // a0 b0 a1 b1  (TOS=b1, TOS-1=a1)
	f.fSub()  // a0 b0 r1      (r1 = (a1-b1+q)%q)
	f.rot()   // b0 r1 a0
	f.rot()   // r1 a0 b0      (TOS=b0, TOS-1=a0)
	f.fSub()  // r1 r0          (r0 = (a0-b0+q)%q)
	f.swap()  // r0 r1
}

// fp2SubU: unreduced Fp2 subtraction.
// [..., a0, a1, b0, b1] -> [..., r0, r1]. Net: -2.
// Components may be negative.
func (f *flatEmitter) fp2SubU() {
	f.rot()   // a0 b0 b1 a1
	f.swap()  // a0 b0 a1 b1
	f.fSubU() // a0 b0 (a1-b1)
	f.rot()   // b0 (a1-b1) a0
	f.rot()   // (a1-b1) a0 b0
	f.fSubU() // (a1-b1) (a0-b0)
	f.swap()  // (a0-b0) (a1-b1)
}


// fp2Neg: [..., a0, a1] -> [..., -a0, -a1]. Net: unchanged.
func (f *flatEmitter) fp2Neg() {
	f.fNeg()  // a0 (-a1)
	f.swap()  // (-a1) a0
	f.fNeg()  // (-a1) (-a0)
	f.swap()  // (-a0) (-a1)
}

// fp2Conj: conjugate. [..., a0, a1] -> [..., a0, -a1]. Net: unchanged.
func (f *flatEmitter) fp2Conj() {
	f.fNeg() // a0 (-a1)
}

// fp2MulByNonResidue: multiply Fp2 by xi = 9+u.
// (a0 + a1*u)(9 + u) = (9*a0 - a1) + (a0 + 9*a1)*u
// [..., a0, a1] -> [..., r0, r1]. Net: unchanged.
func (f *flatEmitter) fp2MulByNonResidue() {
	// Stack: a0(1) a1(0)

	// Compute 9*a0 (unreduced)
	f.over()          // a0 a1 a0c
	f.fMulConstU(9)   // a0 a1 9a0

	// r0 = (9*a0 - a1) mod q  -- fetch a1 for subtraction
	f.over()          // a0 a1 9a0 a1c  (copies a1 from depth 2 after previous push)
	// Stack: a0 a1 9a0 a1c. TOS=a1c, TOS-1=9a0. fSub: (9a0-a1c+q)%q.
	f.fSub()          // a0 a1 r0

	// Compute r1 = (a0 + 9*a1) mod q
	f.swap()          // a0 r0 a1
	f.rot()           // r0 a1 a0
	f.swap()          // r0 a0 a1
	f.fMulConstU(9)   // r0 a0 9a1
	f.fAdd()          // r0 r1
}

// fp2MulByConst: multiply Fp2 on stack by constant Fp2 value.
// [..., a0, a1] -> [..., r0, r1]. Net: unchanged.
func (f *flatEmitter) fp2MulByConst(c0, c1 *big.Int) {
	if c1.Sign() == 0 {
		// (a0 + a1*u) * c0 = (a0*c0) + (a1*c0)*u
		f.pushBig(c0) // a0 a1 c0
		f.dup()       // a0 a1 c0 c0
		f.roll(3)     // a1 c0 c0 a0
		f.swap()      // a1 c0 a0 c0
		f.fMul()      // a1 c0 r0
		f.rot()       // c0 r0 a1
		f.rot()       // r0 a1 c0
		f.fMul()      // r0 r1
		return
	}
	// Full Karatsuba: push c0, c1, then fp2Mul
	f.pushBig(c0)
	f.pushBig(c1)
	f.fp2Mul()
}

// =========================================================================
// Flat Fp6 operations
// =========================================================================
//
// Fp6 = Fp2[v] / (v^3 - xi), xi = 9+u.
// Element (c0, c1, c2) has 6 Fp values on stack: c0_0, c0_1, c1_0, c1_1, c2_0, c2_1.
// c0_0 is deepest of the 6, c2_1 is on top.

// fp6Add: component-wise Fp6 addition.
// [..., a0_0, a0_1, a1_0, a1_1, a2_0, a2_1, b0_0, b0_1, b1_0, b1_1, b2_0, b2_1]
// -> [..., r0_0, r0_1, r1_0, r1_1, r2_0, r2_1]. Net: -6.
func (f *flatEmitter) fp6Add() {
	// Process c2 first: rearrange a2 next to b2, then fp2Add.
	// Initial: a0_0(11) a0_1(10) a1_0(9) a1_1(8) a2_0(7) a2_1(6)
	//          b0_0(5) b0_1(4) b1_0(3) b1_1(2) b2_0(1) b2_1(0)

	// Bring a2 past b0,b1 to be adjacent to b2:
	f.roll(6) // bring a2_1 from depth 6 to top
	f.roll(6) // bring a2_0 from depth 6 to top
	f.swap()  // swap so a2_0 is below a2_1
	f.roll(3) // rearrange: bring b2_0 below a2
	f.roll(3) // rearrange: bring b2_1 below
	// Stack: a0_0 a0_1 a1_0 a1_1 b0_0 b0_1 b1_0 b1_1 | a2_0 a2_1 b2_0 b2_1
	f.fp2Add() // -> r2_0 r2_1

	// Stack: a0_0(9) a0_1(8) a1_0(7) a1_1(6) b0_0(5) b0_1(4) b1_0(3) b1_1(2) r2_0(1) r2_1(0)

	// Bring a1 past b0 to be adjacent to b1:
	f.roll(6) // bring a1_1 to top
	f.roll(6) // bring a1_0 to top
	f.swap()
	f.roll(3)
	f.roll(3)
	f.fp2Add()

	// Stack: a0_0(5) a0_1(4) b0_0(3) b0_1(2) r2_0(1) r2_1(0) r1_0(-) r1_1(-)
	// Wait, let me recount. After c1: a0_0 a0_1 b0_0 b0_1 r2_0 r2_1 r1_0 r1_1

	// c0: a0 and b0 need to be paired
	f.roll(6) // bring a0_1 to top
	f.roll(6) // bring a0_0 to top
	f.swap()
	f.roll(3)
	f.roll(3)
	f.fp2Add()

	// Stack: r2_0 r2_1 r1_0 r1_1 r0_0 r0_1
	// Reorder to: r0_0 r0_1 r1_0 r1_1 r2_0 r2_1
	f.roll(5)
	f.roll(5)
	f.roll(5)
	f.roll(5)
	f.roll(3)
	f.roll(3)
}

// fp6Sub: component-wise Fp6 subtraction.
// [..., a(6 slots), b(6 slots)] -> [..., r(6 slots)]. Net: -6.
func (f *flatEmitter) fp6Sub() {
	// Same strategy as fp6Add but using fp2Sub.
	f.roll(6)
	f.roll(6)
	f.swap()
	f.roll(3)
	f.roll(3)
	f.fp2Sub()

	f.roll(6)
	f.roll(6)
	f.swap()
	f.roll(3)
	f.roll(3)
	f.fp2Sub()

	f.roll(6)
	f.roll(6)
	f.swap()
	f.roll(3)
	f.roll(3)
	f.fp2Sub()

	// Reorder: r2 r1 r0 -> r0 r1 r2
	f.roll(5)
	f.roll(5)
	f.roll(5)
	f.roll(5)
	f.roll(3)
	f.roll(3)
}

// fp6AddU: component-wise unreduced Fp6 addition.
// [..., a(6 slots), b(6 slots)] -> [..., r(6 slots)]. Net: -6.
func (f *flatEmitter) fp6AddU() {
	// Same strategy but with fp2AddU
	f.roll(6)
	f.roll(6)
	f.swap()
	f.roll(3)
	f.roll(3)
	f.fp2AddU()

	f.roll(6)
	f.roll(6)
	f.swap()
	f.roll(3)
	f.roll(3)
	f.fp2AddU()

	f.roll(6)
	f.roll(6)
	f.swap()
	f.roll(3)
	f.roll(3)
	f.fp2AddU()

	f.roll(5)
	f.roll(5)
	f.roll(5)
	f.roll(5)
	f.roll(3)
	f.roll(3)
}

// fp6MulByNonResidue: multiply Fp6 by v (the variable).
// (c0, c1, c2) -> (xi*c2, c0, c1)
// [..., c0_0, c0_1, c1_0, c1_1, c2_0, c2_1]
// -> [..., xi*c2_0, xi*c2_1, c0_0, c0_1, c1_0, c1_1]
// Net: unchanged.
func (f *flatEmitter) fp6MulByNonResidue() {
	// Stack: c0_0(5) c0_1(4) c1_0(3) c1_1(2) c2_0(1) c2_1(0)
	// Apply xi to c2 (top 2)
	f.fp2MulByNonResidue() // c0_0 c0_1 c1_0 c1_1 xi*c2_0 xi*c2_1
	// Now rotate: want xi*c2, c0, c1
	// Roll xi*c2 to the bottom of the 6-element block
	f.roll(5)  // c0_1 c1_0 c1_1 xi*c2_0 xi*c2_1 c0_0
	f.roll(5)  // c1_0 c1_1 xi*c2_0 xi*c2_1 c0_0 c0_1
	f.roll(5)  // c1_1 xi*c2_0 xi*c2_1 c0_0 c0_1 c1_0
	f.roll(5)  // xi*c2_0 xi*c2_1 c0_0 c0_1 c1_0 c1_1
	// Result: xi*c2_0 xi*c2_1 c0_0 c0_1 c1_0 c1_1 = (xi*c2, c0, c1)
}

// fp6Neg: negate all components.
// [..., c0_0, c0_1, c1_0, c1_1, c2_0, c2_1]
// -> [..., -c0_0, -c0_1, -c1_0, -c1_1, -c2_0, -c2_1]
func (f *flatEmitter) fp6Neg() {
	// Process from top: negate c2, then roll and negate c1, then c0
	f.fp2Neg() // negate c2 (top 2)
	f.roll(5)
	f.roll(5)
	f.fp2Neg() // negate c1
	f.roll(5)
	f.roll(5)
	f.fp2Neg() // negate c0
	f.roll(5)
	f.roll(5)
	// Now on stack: -c2_0 -c2_1 -c1_0 -c1_1 -c0_0 -c0_1
	// Reorder to: -c0 -c1 -c2
	f.roll(5)
	f.roll(5)
	f.roll(5)
	f.roll(5)
	f.roll(3)
	f.roll(3)
}

// fp2Reduce: reduce an unreduced Fp2 value from fp2MulU.
// Component 0 may be negative (from t0-t1), component 1 is always non-negative.
// [..., r0_raw, r1_raw] -> [..., r0, r1]. Net: unchanged.
// Cost: modFull (9 bytes) + modPositive (4 bytes) = 13 bytes.
func (f *flatEmitter) fp2Reduce() {
	f.swap()
	f.modFull() // reduce component 0 (may be negative)
	f.swap()
	f.modPositive() // reduce component 1 (always non-negative)
}

// fp2MulByNonResidueU: multiply Fp2 by xi = 9+u, unreduced.
// (a0 + a1*u)(9 + u) = (9*a0 - a1) + (a0 + 9*a1)*u
// [..., a0, a1] -> [..., r0, r1]. Net: unchanged.
// r0 may be negative (9*a0 - a1), r1 is non-negative.
func (f *flatEmitter) fp2MulByNonResidueU() {
	// Stack: a0(1) a1(0)
	f.over()          // a0 a1 a0c
	f.fMulConstU(9)   // a0 a1 9a0
	f.over()          // a0 a1 9a0 a1c
	f.fSubU()         // a0 a1 (9a0-a1)  -- may be negative
	f.swap()          // a0 (9a0-a1) a1
	f.rot()           // (9a0-a1) a1 a0
	f.swap()          // (9a0-a1) a0 a1
	f.fMulConstU(9)   // (9a0-a1) a0 9a1
	f.fAddU()         // (9a0-a1) (a0+9a1)
	// r0 = 9a0-a1 (may be negative), r1 = a0+9a1 (non-negative)
}

// fp6MulByC2Zero: multiply Fp6 a=(a0,a1,a2) by sparse (b0,b1,0).
// Stack in:  [..., a0_0, a0_1, a1_0, a1_1, a2_0, a2_1, b0_0, b0_1, b1_0, b1_1]
// Stack out: [..., r0_0, r0_1, r1_0, r1_1, r2_0, r2_1]. Net: -4.
//
// r0 = a0*b0 + xi*(a2*b1)
// r1 = a0*b1 + a1*b0
// r2 = a1*b1 + a2*b0
//
// All 6 Fp2 multiplies use unreduced output. Mod reduction is deferred to the
// Fp2 adds that combine the products. This saves 6 * 13 = 78 bytes per call
// (each Fp2Mul saves 1 modFull + 1 modPositive = 9 + 4 = 13 bytes).
func (f *flatEmitter) fp6MulByC2Zero() {
	// Stack layout (depth from TOS):
	//   b1_1(0) b1_0(1) b0_1(2) b0_0(3)
	//   a2_1(4) a2_0(5) a1_1(6) a1_0(7) a0_1(8) a0_0(9)

	// Strategy: compute all 6 unreduced Fp2 products by picking operands,
	// then combine with add/sub + mod at the end.

	// Product 1: a0*b0 (for r0 and r1)
	f.pick(9) // a0_0
	f.pick(9) // a0_1
	f.pick(5) // b0_0
	f.pick(5) // b0_1
	f.fp2MulU()
	// Stack: ...(10 orig) a0b0_0 a0b0_1

	// Product 2: a2*b1 (for r0, xi*a2b1)
	f.pick(6) // a2_0
	f.pick(6) // a2_1
	f.pick(4) // b1_0
	f.pick(4) // b1_1
	f.fp2MulU()
	// Stack: ...(10 orig) a0b0_0 a0b0_1 a2b1_0 a2b1_1

	// Apply xi to a2b1 (unreduced)
	f.fp2MulByNonResidueU()
	// Stack: ...(10 orig) a0b0_0 a0b0_1 xi_a2b1_0 xi_a2b1_1

	// r0 = a0b0 + xi*a2b1 (add, then reduce)
	// Both operands may be unreduced. a0b0 components in [-p^2, 4p^2],
	// xi*a2b1 components may be negative (from the subtraction in xi multiply).
	// Sum can be negative, so use modFull on each component.
	f.fp2AddU()
	f.fp2Reduce()
	// Stack: ...(10 orig) r0_0 r0_1

	// Product 3: a0*b1 (for r1)
	f.pick(11) // a0_0
	f.pick(11) // a0_1
	f.pick(5)  // b1_0
	f.pick(5)  // b1_1
	f.fp2MulU()
	// Stack: ...(10 orig) r0_0 r0_1 a0b1_0 a0b1_1

	// Product 4: a1*b0 (for r1)
	f.pick(11) // a1_0
	f.pick(11) // a1_1
	f.pick(9)  // b0_0
	f.pick(9)  // b0_1
	f.fp2MulU()
	// Stack: ...(10 orig) r0_0 r0_1 a0b1_0 a0b1_1 a1b0_0 a1b0_1

	// r1 = a0b1 + a1b0 (both non-negative unreduced)
	f.fp2AddU()
	f.fp2Reduce()
	// Stack: ...(10 orig) r0_0 r0_1 r1_0 r1_1

	// Product 5: a1*b1 (for r2)
	f.pick(11) // a1_0
	f.pick(11) // a1_1
	f.pick(7)  // b1_0
	f.pick(7)  // b1_1
	f.fp2MulU()
	// Stack: ...(10 orig) r0_0 r0_1 r1_0 r1_1 a1b1_0 a1b1_1

	// Product 6: a2*b0 (for r2)
	f.pick(11) // a2_0
	f.pick(11) // a2_1
	f.pick(13) // b0_0
	f.pick(13) // b0_1
	f.fp2MulU()
	// Stack: ...(10 orig) r0_0 r0_1 r1_0 r1_1 a1b1_0 a1b1_1 a2b0_0 a2b0_1

	// r2 = a1b1 + a2b0
	f.fp2AddU()
	f.fp2Reduce()
	// Stack: ...(10 orig) r0_0 r0_1 r1_0 r1_1 r2_0 r2_1

	// Clean up: remove the 10 original items below the 6 results
	// Roll each original to the top and drop it. The originals are at
	// depths 15..6 (there are 10 of them, below our 6 results).
	for i := 0; i < 10; i++ {
		f.roll(15 - i)
		f.drop()
	}
}

// fp6MulByFp2: multiply Fp6 a=(a0,a1,a2) by scalar Fp2 b.
// Stack in:  [..., a0_0, a0_1, a1_0, a1_1, a2_0, a2_1, b_0, b_1]
// Stack out: [..., r0_0, r0_1, r1_0, r1_1, r2_0, r2_1]. Net: -2.
//
// r = (a0*b, a1*b, a2*b) — 3 Fp2 muls.
// Uses unreduced Fp2Mul + single mod at the end.
func (f *flatEmitter) fp6MulByFp2() {
	// Stack: a0_0(7) a0_1(6) a1_0(5) a1_1(4) a2_0(3) a2_1(2) b_0(1) b_1(0)

	// r0 = a0 * b
	f.pick(7) // a0_0
	f.pick(7) // a0_1
	f.pick(3) // b_0
	f.pick(3) // b_1
	f.fp2MulU()
	f.fp2Reduce()
	// Stack: ...(8 orig) r0_0 r0_1

	// r1 = a1 * b
	f.pick(7) // a1_0
	f.pick(7) // a1_1
	f.pick(5) // b_0
	f.pick(5) // b_1
	f.fp2MulU()
	f.fp2Reduce()
	// Stack: ...(8 orig) r0_0 r0_1 r1_0 r1_1

	// r2 = a2 * b
	f.pick(7) // a2_0
	f.pick(7) // a2_1
	f.pick(7) // b_0
	f.pick(7) // b_1
	f.fp2MulU()
	f.fp2Reduce()
	// Stack: ...(8 orig) r0_0 r0_1 r1_0 r1_1 r2_0 r2_1

	// Clean up 8 originals
	for i := 0; i < 8; i++ {
		f.roll(13 - i)
		f.drop()
	}
}

// =========================================================================
// Hybrid adapters: let BN254Tracker delegate to flat Fp2 ops
// =========================================================================
//
// These functions arrange inputs on the stack top using the tracker, then
// hand off to the flat emitter for the actual computation. The tracker
// then records the results. This eliminates tracker overhead for the
// innermost Fp2 operations while keeping higher-level Fp6/Fp12 logic
// in the tracker.

// bn254Fp2MulFlat is a drop-in replacement for bn254Fp2Mul that uses
// flat emission for the actual multiplication.
func bn254Fp2MulFlat(t *BN254Tracker, a0, a1, b0, b1, r0, r1 string) {
	// Check if the 4 items are already the top 4 in the right order.
	// If so, skip the toTop calls entirely.
	L := len(t.nm)
	if L >= 4 && t.nm[L-4] == a0 && t.nm[L-3] == a1 && t.nm[L-2] == b0 && t.nm[L-1] == b1 {
		fe := newFlatEmitterWithThreshold(t.e, L, t.modThreshold)
		t.nm = t.nm[:L-4]
		fe.fp2Mul()
		t.nm = append(t.nm, r0, r1)
		return
	}
	t.toTop(a0)
	t.toTop(a1)
	t.toTop(b0)
	t.toTop(b1)
	fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
	t.nm = t.nm[:len(t.nm)-4]
	fe.fp2Mul()
	t.nm = append(t.nm, r0, r1)
}

// bn254Fp2AddFlat is a flat-emission replacement for bn254Fp2Add.
func bn254Fp2AddFlat(t *BN254Tracker, a0, a1, b0, b1, r0, r1 string) {
	L := len(t.nm)
	if L >= 4 && t.nm[L-4] == a0 && t.nm[L-3] == a1 && t.nm[L-2] == b0 && t.nm[L-1] == b1 {
		fe := newFlatEmitterWithThreshold(t.e, L, t.modThreshold)
		t.nm = t.nm[:L-4]
		fe.fp2Add()
		t.nm = append(t.nm, r0, r1)
		return
	}
	t.toTop(a0)
	t.toTop(a1)
	t.toTop(b0)
	t.toTop(b1)
	fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
	t.nm = t.nm[:len(t.nm)-4]
	fe.fp2Add()
	t.nm = append(t.nm, r0, r1)
}

// bn254Fp2SubFlat is a flat-emission replacement for bn254Fp2Sub.
func bn254Fp2SubFlat(t *BN254Tracker, a0, a1, b0, b1, r0, r1 string) {
	L := len(t.nm)
	if L >= 4 && t.nm[L-4] == a0 && t.nm[L-3] == a1 && t.nm[L-2] == b0 && t.nm[L-1] == b1 {
		fe := newFlatEmitterWithThreshold(t.e, L, t.modThreshold)
		t.nm = t.nm[:L-4]
		fe.fp2Sub()
		t.nm = append(t.nm, r0, r1)
		return
	}
	t.toTop(a0)
	t.toTop(a1)
	t.toTop(b0)
	t.toTop(b1)
	fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
	t.nm = t.nm[:len(t.nm)-4]
	fe.fp2Sub()
	t.nm = append(t.nm, r0, r1)
}

// bn254Fp2SqrFlat is a flat-emission replacement for bn254Fp2Sqr.
func bn254Fp2SqrFlat(t *BN254Tracker, a0, a1, r0, r1 string) {
	L := len(t.nm)
	if L >= 2 && t.nm[L-2] == a0 && t.nm[L-1] == a1 {
		fe := newFlatEmitterWithThreshold(t.e, L, t.modThreshold)
		t.nm = t.nm[:L-2]
		fe.fp2Sqr()
		t.nm = append(t.nm, r0, r1)
		return
	}
	t.toTop(a0)
	t.toTop(a1)
	fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
	t.nm = t.nm[:len(t.nm)-2]
	fe.fp2Sqr()
	t.nm = append(t.nm, r0, r1)
}

// bn254Fp2AddUnreducedFlat is a flat-emission replacement for bn254Fp2AddUnreduced.
func bn254Fp2AddUnreducedFlat(t *BN254Tracker, a0, a1, b0, b1, r0, r1 string) {
	L := len(t.nm)
	if L >= 4 && t.nm[L-4] == a0 && t.nm[L-3] == a1 && t.nm[L-2] == b0 && t.nm[L-1] == b1 {
		fe := newFlatEmitterWithThreshold(t.e, L, t.modThreshold)
		t.nm = t.nm[:L-4]
		fe.fp2AddU()
		t.nm = append(t.nm, r0, r1)
		return
	}
	t.toTop(a0)
	t.toTop(a1)
	t.toTop(b0)
	t.toTop(b1)
	fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
	t.nm = t.nm[:len(t.nm)-4]
	fe.fp2AddU()
	t.nm = append(t.nm, r0, r1)
}

// bn254Fp2NegFlat is a flat-emission replacement for bn254Fp2Neg.
func bn254Fp2NegFlat(t *BN254Tracker, a0, a1, r0, r1 string) {
	L := len(t.nm)
	if L >= 2 && t.nm[L-2] == a0 && t.nm[L-1] == a1 {
		fe := newFlatEmitterWithThreshold(t.e, L, t.modThreshold)
		t.nm = t.nm[:L-2]
		fe.fp2Neg()
		t.nm = append(t.nm, r0, r1)
		return
	}
	t.toTop(a0)
	t.toTop(a1)
	fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
	t.nm = t.nm[:len(t.nm)-2]
	fe.fp2Neg()
	t.nm = append(t.nm, r0, r1)
}

// bn254Fp2MulByNonResidueFlat is a flat-emission replacement for bn254Fp2MulByNonResidue.
func bn254Fp2MulByNonResidueFlat(t *BN254Tracker, a0, a1, r0, r1 string) {
	L := len(t.nm)
	if L >= 2 && t.nm[L-2] == a0 && t.nm[L-1] == a1 {
		fe := newFlatEmitterWithThreshold(t.e, L, t.modThreshold)
		t.nm = t.nm[:L-2]
		fe.fp2MulByNonResidue()
		t.nm = append(t.nm, r0, r1)
		return
	}
	t.toTop(a0)
	t.toTop(a1)
	fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
	t.nm = t.nm[:len(t.nm)-2]
	fe.fp2MulByNonResidue()
	t.nm = append(t.nm, r0, r1)
}

// bn254Fp2ConjugateFlat is a flat-emission replacement for bn254Fp2Conjugate.
func bn254Fp2ConjugateFlat(t *BN254Tracker, a0, a1, r0, r1 string) {
	L := len(t.nm)
	if L >= 2 && t.nm[L-2] == a0 && t.nm[L-1] == a1 {
		fe := newFlatEmitterWithThreshold(t.e, L, t.modThreshold)
		t.nm = t.nm[:L-2]
		fe.fp2Conj()
		t.nm = append(t.nm, r0, r1)
		return
	}
	t.toTop(a0)
	t.toTop(a1)
	fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
	t.nm = t.nm[:len(t.nm)-2]
	fe.fp2Conj()
	t.nm = append(t.nm, r0, r1)
}

// bn254Fp2MulByFrobCoeffFlat is a flat-emission replacement for bn254Fp2MulByFrobCoeff.
func bn254Fp2MulByFrobCoeffFlat(t *BN254Tracker, aPrefix string, coeff [2]*big.Int, rPrefix string) {
	a0 := aPrefix + "_0"
	a1 := aPrefix + "_1"
	L := len(t.nm)
	if L >= 2 && t.nm[L-2] == a0 && t.nm[L-1] == a1 {
		fe := newFlatEmitterWithThreshold(t.e, L, t.modThreshold)
		t.nm = t.nm[:L-2]
		fe.fp2MulByConst(coeff[0], coeff[1])
		t.nm = append(t.nm, rPrefix+"_0", rPrefix+"_1")
		return
	}
	t.toTop(a0)
	t.toTop(a1)
	fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
	t.nm = t.nm[:len(t.nm)-2]
	fe.fp2MulByConst(coeff[0], coeff[1])
	t.nm = append(t.nm, rPrefix+"_0", rPrefix+"_1")
}

// =========================================================================
// Flat Fp6 tracker adapters
// =========================================================================

// bn254Fp6AddFlat is a flat-emission replacement for bn254Fp6Add.
// Consumes aPrefix (6 slots) and bPrefix (6 slots); produces rPrefix (6 slots).
func bn254Fp6AddFlat(t *BN254Tracker, aPrefix, bPrefix, rPrefix string) {
	// Collect all 12 slot names
	var names [12]string
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		names[i*2] = aPrefix + "_" + sfx + "_0"
		names[i*2+1] = aPrefix + "_" + sfx + "_1"
	}
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		names[6+i*2] = bPrefix + "_" + sfx + "_0"
		names[6+i*2+1] = bPrefix + "_" + sfx + "_1"
	}

	// Check if already in position
	L := len(t.nm)
	inPosition := L >= 12
	if inPosition {
		for j := 0; j < 12; j++ {
			if t.nm[L-12+j] != names[j] {
				inPosition = false
				break
			}
		}
	}

	if !inPosition {
		// Move all inputs to top in order
		for _, n := range names {
			t.toTop(n)
		}
	}

	fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
	t.nm = t.nm[:len(t.nm)-12]
	fe.fp6Add()
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		t.nm = append(t.nm, rPrefix+"_"+sfx+"_0", rPrefix+"_"+sfx+"_1")
	}
}

// bn254Fp6SubFlat is a flat-emission replacement for bn254Fp6Sub.
func bn254Fp6SubFlat(t *BN254Tracker, aPrefix, bPrefix, rPrefix string) {
	var names [12]string
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		names[i*2] = aPrefix + "_" + sfx + "_0"
		names[i*2+1] = aPrefix + "_" + sfx + "_1"
	}
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		names[6+i*2] = bPrefix + "_" + sfx + "_0"
		names[6+i*2+1] = bPrefix + "_" + sfx + "_1"
	}

	L := len(t.nm)
	inPosition := L >= 12
	if inPosition {
		for j := 0; j < 12; j++ {
			if t.nm[L-12+j] != names[j] {
				inPosition = false
				break
			}
		}
	}
	if !inPosition {
		for _, n := range names {
			t.toTop(n)
		}
	}

	fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
	t.nm = t.nm[:len(t.nm)-12]
	fe.fp6Sub()
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		t.nm = append(t.nm, rPrefix+"_"+sfx+"_0", rPrefix+"_"+sfx+"_1")
	}
}

// bn254Fp6AddUnreducedFlat is a flat-emission replacement for bn254Fp6AddUnreduced.
func bn254Fp6AddUnreducedFlat(t *BN254Tracker, aPrefix, bPrefix, rPrefix string) {
	var names [12]string
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		names[i*2] = aPrefix + "_" + sfx + "_0"
		names[i*2+1] = aPrefix + "_" + sfx + "_1"
	}
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		names[6+i*2] = bPrefix + "_" + sfx + "_0"
		names[6+i*2+1] = bPrefix + "_" + sfx + "_1"
	}

	L := len(t.nm)
	inPosition := L >= 12
	if inPosition {
		for j := 0; j < 12; j++ {
			if t.nm[L-12+j] != names[j] {
				inPosition = false
				break
			}
		}
	}
	if !inPosition {
		for _, n := range names {
			t.toTop(n)
		}
	}

	fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
	t.nm = t.nm[:len(t.nm)-12]
	fe.fp6AddU()
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		t.nm = append(t.nm, rPrefix+"_"+sfx+"_0", rPrefix+"_"+sfx+"_1")
	}
}

// bn254Fp6MulByNonResidueFlat is a flat-emission replacement for bn254Fp6MulByNonResidue.
func bn254Fp6MulByNonResidueFlat(t *BN254Tracker, aPrefix, rPrefix string) {
	var names [6]string
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		names[i*2] = aPrefix + "_" + sfx + "_0"
		names[i*2+1] = aPrefix + "_" + sfx + "_1"
	}

	L := len(t.nm)
	inPosition := L >= 6
	if inPosition {
		for j := 0; j < 6; j++ {
			if t.nm[L-6+j] != names[j] {
				inPosition = false
				break
			}
		}
	}
	if !inPosition {
		for _, n := range names {
			t.toTop(n)
		}
	}

	fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
	t.nm = t.nm[:len(t.nm)-6]
	fe.fp6MulByNonResidue()
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		t.nm = append(t.nm, rPrefix+"_"+sfx+"_0", rPrefix+"_"+sfx+"_1")
	}
}

// bn254Fp6NegFlat is a flat-emission replacement for bn254Fp6Neg.
func bn254Fp6NegFlat(t *BN254Tracker, aPrefix, rPrefix string) {
	var names [6]string
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		names[i*2] = aPrefix + "_" + sfx + "_0"
		names[i*2+1] = aPrefix + "_" + sfx + "_1"
	}

	L := len(t.nm)
	inPosition := L >= 6
	if inPosition {
		for j := 0; j < 6; j++ {
			if t.nm[L-6+j] != names[j] {
				inPosition = false
				break
			}
		}
	}
	if !inPosition {
		for _, n := range names {
			t.toTop(n)
		}
	}

	fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
	t.nm = t.nm[:len(t.nm)-6]
	fe.fp6Neg()
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		t.nm = append(t.nm, rPrefix+"_"+sfx+"_0", rPrefix+"_"+sfx+"_1")
	}
}

// bn254Fp6MulByC2ZeroFlat is a flat-emission replacement for bn254Fp6MulByC2Zero.
// Multiplies Fp6 a by sparse Fp6 (b0, b1, 0).
// a is PRESERVED (uses picks). b0, b1 are PRESERVED (uses picks).
// Produces rPrefix (6 Fp slots).
func bn254Fp6MulByC2ZeroFlat(t *BN254Tracker, aPrefix, b0Prefix, b1Prefix, rPrefix string) {
	// Pick all 10 operands onto the stack top: a (6) + b0 (2) + b1 (2)
	var names [10]string
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		names[i*2] = aPrefix + "_" + sfx + "_0"
		names[i*2+1] = aPrefix + "_" + sfx + "_1"
	}
	names[6] = b0Prefix + "_0"
	names[7] = b0Prefix + "_1"
	names[8] = b1Prefix + "_0"
	names[9] = b1Prefix + "_1"

	// Pick all operands (copies — originals stay in place)
	for i := 0; i < 10; i++ {
		d := t.findDepth(names[i])
		t.pick(d, "_f6c2z_pick_"+itoa(i))
	}

	// Now top 10 are our copies. Run flat fp6MulByC2Zero.
	fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
	t.nm = t.nm[:len(t.nm)-10]
	fe.fp6MulByC2Zero()
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		t.nm = append(t.nm, rPrefix+"_"+sfx+"_0", rPrefix+"_"+sfx+"_1")
	}
}

// bn254Fp6MulByFp2CopyFlat is a flat-emission replacement for bn254Fp6MulByFp2Copy.
// Multiplies Fp6 a by scalar Fp2 b.
// Both a and b are PRESERVED (uses picks).
// Produces rPrefix (6 Fp slots).
func bn254Fp6MulByFp2CopyFlat(t *BN254Tracker, aPrefix, bPrefix, rPrefix string) {
	// Pick all 8 operands: a (6) + b (2)
	var names [8]string
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		names[i*2] = aPrefix + "_" + sfx + "_0"
		names[i*2+1] = aPrefix + "_" + sfx + "_1"
	}
	names[6] = bPrefix + "_0"
	names[7] = bPrefix + "_1"

	for i := 0; i < 8; i++ {
		d := t.findDepth(names[i])
		t.pick(d, "_f6fp2_pick_"+itoa(i))
	}

	fe := newFlatEmitterWithThreshold(t.e, len(t.nm), t.modThreshold)
	t.nm = t.nm[:len(t.nm)-8]
	fe.fp6MulByFp2()
	for i := 0; i < 3; i++ {
		sfx := string(rune('0' + i))
		t.nm = append(t.nm, rPrefix+"_"+sfx+"_0", rPrefix+"_"+sfx+"_1")
	}
}

// =========================================================================
// BN254-specific peephole optimizer
// =========================================================================

// OptimizeBN254Ops applies BN254-specific peephole optimizations to StackOps.
// This is applied ON TOP of the general OptimizeStackOps to further reduce size.
// These transformations are safe for BN254 codegen but not necessarily for
// general Runar contracts (e.g., SWAP DROP -> NIP changes conformance golden files).
func OptimizeBN254Ops(ops []StackOp) []StackOp {
	for iter := 0; iter < 50; iter++ {
		result, changed := applyBN254Pass(ops)
		if !changed {
			return result
		}
		ops = result
	}
	return ops
}

func applyBN254Pass(ops []StackOp) ([]StackOp, bool) {
	var result []StackOp
	changed := false
	i := 0
	for i < len(ops) {
		// 2-op window
		if i+1 < len(ops) {
			a, b := ops[i], ops[i+1]
			// SWAP + DROP -> NIP
			if a.Op == "swap" && b.Op == "drop" {
				result = append(result, StackOp{Op: "nip"})
				i += 2
				changed = true
				continue
			}
			// NIP + DROP -> OP_2DROP + (need to swap first)
			// Actually NIP then DROP on [a, b, c]: NIP -> [a, c], DROP -> [a]
			// vs OP_2DROP on [a, b, c]: drops b,c -> [a]. Same!
			if a.Op == "nip" && b.Op == "drop" {
				result = append(result, StackOp{Op: "opcode", Code: "OP_2DROP"})
				i += 2
				changed = true
				continue
			}
		}
		result = append(result, ops[i])
		i++
	}
	return result, changed
}

// =========================================================================
// Standalone flat Fp2 emitters for testing
// =========================================================================

// EmitFlatFp2Mul emits flat Fp2 multiplication.
// Stack in:  [q, a0, a1, b0, b1] -> Stack out: [q, r0, r1]
func EmitFlatFp2Mul(emit func(StackOp)) {
	fe := newFlatEmitter(emit, 5)
	fe.fp2Mul()
}

// EmitFlatFp2Add emits flat Fp2 addition.
// Stack in:  [q, a0, a1, b0, b1] -> Stack out: [q, r0, r1]
func EmitFlatFp2Add(emit func(StackOp)) {
	fe := newFlatEmitter(emit, 5)
	fe.fp2Add()
}

// EmitFlatFp2Sub emits flat Fp2 subtraction.
// Stack in:  [q, a0, a1, b0, b1] -> Stack out: [q, r0, r1]
func EmitFlatFp2Sub(emit func(StackOp)) {
	fe := newFlatEmitter(emit, 5)
	fe.fp2Sub()
}

// EmitFlatFp2Sqr emits flat Fp2 squaring.
// Stack in:  [q, a0, a1] -> Stack out: [q, r0, r1]
func EmitFlatFp2Sqr(emit func(StackOp)) {
	fe := newFlatEmitter(emit, 3)
	fe.fp2Sqr()
}

// EmitFlatFp2MulByNonResidue emits flat Fp2 * xi.
// Stack in:  [q, a0, a1] -> Stack out: [q, r0, r1]
func EmitFlatFp2MulByNonResidue(emit func(StackOp)) {
	fe := newFlatEmitter(emit, 3)
	fe.fp2MulByNonResidue()
}
