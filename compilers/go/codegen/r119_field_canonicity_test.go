package codegen

import (
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// R-119 -- no canonicity or range check on any witness-supplied field element.
//
// WHAT REPRODUCED, AND WHAT DID NOT. The finding as filed names two shapes,
// `v >= p` and `v < 0`, and asks that `v + p` either be rejected or "produce
// the same verdict as v at every equality site". The SECOND disjunct already
// held for `v + p`: every emitter here reduces its result mod p, so measured on
// the go-sdk interpreter before this gate,
//
//	bbFieldAdd(5+p, 0) -> 5      bbFieldAdd(5, 0) -> 5
//	bbFieldSub(5+p, 0) -> 5      bbFieldInv(3+p)  -> 1342177281 = bbFieldInv(3)
//
// so `v + p` was already indistinguishable from `v`. It is gated here anyway,
// because leaving two accepted spellings of one element is the aliasing the
// finding is about and because the gate is one OP_WITHIN either way -- but the
// half that was actually BROKEN is the negative one:
//
//	bbFieldAdd(-1, 0)  -> -1            bbFieldAdd(p-1, 0)  -> 2013265920
//	bbFieldMul(-1, 1)  -> -1            bbFieldMul(p-1, 1)  -> 2013265920
//	bbFieldInv(-1)     -> -1            bbFieldInv(p-1)     -> 2013265920
//	kbExt4Mul0((0,-1,0,0),(0,0,0,1)) -> -3    canonical spelling -> 2130706430
//
// `bbFieldAdd` and `bbFieldMul` reduce with a BARE OP_MOD, on the documented
// assumption that both operands are already in [0, p-1] ("Sum of two values in
// [0, p-1] is always non-negative, so simple OP_MOD suffices"). OP_MOD takes the
// sign of the DIVIDEND, so a negative operand walks straight out of the field:
// the builtin returns a number that is congruent to the right answer and is NOT
// the right answer's script encoding. Script equality is numeric, so the escaped
// spelling breaks every downstream `===`, every OP_NUM2BIN of a field element,
// and the closure property the ext4 and Poseidon2 code depends on when it feeds
// one field builtin into the next.
//
// The gate, per witness operand, on the public entry points only:
//
//	OP_DUP/OP_PICK <0> <p> OP_WITHIN OP_VERIFY
//
// The two facts below are pinned as tests, not as prose: that `v + p` was
// ALREADY equivalent to `v` (so the fix is a tightening, not a correctness
// repair, on that half) and that a negative operand was NOT.
// ---------------------------------------------------------------------------

type fieldTier struct {
	name string
	p    *big.Int
	add  func(func(StackOp))
	sub  func(func(StackOp))
	mul  func(func(StackOp))
	inv  func(func(StackOp))
	// ext4Mul takes 8 operands, ext4Inv takes 4.
	ext4Mul func(func(StackOp))
	ext4Inv func(func(StackOp))
}

func fieldTiers() []fieldTier {
	return []fieldTier{
		{"babybear", bbFieldP, EmitBBFieldAdd, EmitBBFieldSub, EmitBBFieldMul, EmitBBFieldInv,
			EmitBBExt4Mul0, EmitBBExt4Inv0},
		{"koalabear", kbFieldP, EmitKBFieldAdd, EmitKBFieldSub, EmitKBFieldMul, EmitKBFieldInv,
			EmitKBExt4Mul0, EmitKBExt4Inv0},
	}
}

// runField pushes `in`, runs `emitFn`, compares the single result against
// `want` with OP_NUMEQUAL, and reports whether the script ACCEPTED. Every
// classification in this file is the interpreter's error, never prose.
func runField(t *testing.T, emitFn func(func(StackOp)), in []*big.Int, want *big.Int) bool {
	t.Helper()
	var ops []StackOp
	for _, v := range in {
		ops = append(ops, pushBigInt(v))
	}
	ops = append(ops, gatherOps(emitFn)...)
	ops = append(ops, pushBigInt(want), opcode("OP_NUMEQUAL"))
	return BuildAndExecuteOps(ops) == nil
}

// runFieldRaw runs the emitter and asserts nothing about the result — used
// where only accept/reject matters.
func runFieldRaw(t *testing.T, emitFn func(func(StackOp)), in []*big.Int) bool {
	t.Helper()
	var ops []StackOp
	for _, v := range in {
		ops = append(ops, pushBigInt(v))
	}
	ops = append(ops, gatherOps(emitFn)...)
	ops = append(ops, opcode("OP_DROP"), opcode("OP_1"))
	return BuildAndExecuteOps(ops) == nil
}

func bi(n int64) *big.Int { return big.NewInt(n) }

// TestR119_NonCanonicalScalarOperandRejected -- the finding, on the four
// scalar builtins of both fields.
func TestR119_NonCanonicalScalarOperandRejected(t *testing.T) {
	for _, F := range fieldTiers() {
		t.Run(F.name, func(t *testing.T) {
			p := F.p
			pm1 := new(big.Int).Sub(p, bi(1))
			aliasA := new(big.Int).Add(bi(5), p) // 5 + p
			big2p := new(big.Int).Add(p, p)      // 2p, i.e. 0 + 2p

			type binCase struct {
				name string
				emit func(func(StackOp))
			}
			for _, c := range []binCase{
				{"add", F.add}, {"sub", F.sub}, {"mul", F.mul},
			} {
				// >= p on either operand.
				if runFieldRaw(t, c.emit, []*big.Int{aliasA, bi(1)}) {
					t.Errorf("%s(5+p, 1) accepted", c.name)
				}
				if runFieldRaw(t, c.emit, []*big.Int{bi(1), aliasA}) {
					t.Errorf("%s(1, 5+p) accepted", c.name)
				}
				if runFieldRaw(t, c.emit, []*big.Int{big2p, bi(1)}) {
					t.Errorf("%s(2p, 1) accepted", c.name)
				}
				// negative on either operand -- the half that returned a
				// non-canonical result rather than merely an alias.
				if runFieldRaw(t, c.emit, []*big.Int{bi(-1), bi(0)}) {
					t.Errorf("%s(-1, 0) accepted", c.name)
				}
				if runFieldRaw(t, c.emit, []*big.Int{bi(0), bi(-1)}) {
					t.Errorf("%s(0, -1) accepted", c.name)
				}
				// exactly p is the first rejected value; p-1 is the last legal one.
				if runFieldRaw(t, c.emit, []*big.Int{p, bi(0)}) {
					t.Errorf("%s(p, 0) accepted", c.name)
				}
			}

			if runFieldRaw(t, F.inv, []*big.Int{aliasA}) {
				t.Errorf("inv(5+p) accepted")
			}
			if runFieldRaw(t, F.inv, []*big.Int{bi(-1)}) {
				t.Errorf("inv(-1) accepted")
			}
			if runFieldRaw(t, F.inv, []*big.Int{p}) {
				t.Errorf("inv(p) accepted")
			}
			// CONTROL: p-1 is a legal field element on every entry point.
			if !runFieldRaw(t, F.inv, []*big.Int{pm1}) {
				t.Errorf("CONTROL inv(p-1) rejected")
			}
		})
	}
}

// TestR119_ScalarControlsStillVerify -- teeth. An over-strict gate reddens
// here, and every accept is checked against a value computed OFF-CHAIN.
func TestR119_ScalarControlsStillVerify(t *testing.T) {
	for _, F := range fieldTiers() {
		t.Run(F.name, func(t *testing.T) {
			p := F.p
			pm1 := new(big.Int).Sub(p, bi(1))
			mod := func(x *big.Int) *big.Int { return new(big.Int).Mod(x, p) }

			for _, ab := range [][2]*big.Int{
				{bi(0), bi(0)}, {bi(0), pm1}, {pm1, bi(0)}, {pm1, pm1},
				{bi(5), bi(7)}, {bi(1), pm1},
			} {
				a, b := ab[0], ab[1]
				if !runField(t, F.add, []*big.Int{a, b}, mod(new(big.Int).Add(a, b))) {
					t.Errorf("CONTROL add(%s, %s) wrong or rejected", a, b)
				}
				if !runField(t, F.sub, []*big.Int{a, b}, mod(new(big.Int).Sub(a, b))) {
					t.Errorf("CONTROL sub(%s, %s) wrong or rejected", a, b)
				}
				if !runField(t, F.mul, []*big.Int{a, b}, mod(new(big.Int).Mul(a, b))) {
					t.Errorf("CONTROL mul(%s, %s) wrong or rejected", a, b)
				}
			}
			// inv: a * inv(a) == 1 for a legal non-zero a, computed off-chain.
			for _, a := range []*big.Int{bi(1), bi(3), bi(12345), pm1} {
				want := new(big.Int).Exp(a, new(big.Int).Sub(p, bi(2)), p)
				if !runField(t, F.inv, []*big.Int{a}, want) {
					t.Errorf("CONTROL inv(%s) wrong or rejected", a)
				}
			}
			// inv(0) = 0 stays defined, as Fermat gives.
			if !runField(t, F.inv, []*big.Int{bi(0)}, bi(0)) {
				t.Errorf("CONTROL inv(0) wrong or rejected")
			}
		})
	}
}

// TestR119_Ext4OperandsGated -- the eight- and four-operand entry points.
func TestR119_Ext4OperandsGated(t *testing.T) {
	for _, F := range fieldTiers() {
		t.Run(F.name, func(t *testing.T) {
			p := F.p
			pm1 := new(big.Int).Sub(p, bi(1))
			ok8 := []*big.Int{bi(1), bi(2), bi(3), bi(4), bi(5), bi(6), bi(7), pm1}
			ok4 := []*big.Int{bi(1), bi(2), bi(3), pm1}

			// CONTROL: a fully canonical operand vector still runs.
			if !runFieldRaw(t, F.ext4Mul, ok8) {
				t.Fatalf("CONTROL ext4Mul0 on canonical operands rejected")
			}
			if !runFieldRaw(t, F.ext4Inv, ok4) {
				t.Fatalf("CONTROL ext4Inv0 on canonical operands rejected")
			}

			// Each of the eight positions must be gated independently — a gate
			// on "the first operand" only would pass a weaker test.
			for i := range ok8 {
				for _, bad := range []*big.Int{new(big.Int).Add(ok8[i], p), bi(-1), p} {
					in := append([]*big.Int{}, ok8...)
					in[i] = bad
					if runFieldRaw(t, F.ext4Mul, in) {
						t.Errorf("ext4Mul0 accepted %s at operand %d", bad, i)
					}
				}
			}
			for i := range ok4 {
				for _, bad := range []*big.Int{new(big.Int).Add(ok4[i], p), bi(-1), p} {
					in := append([]*big.Int{}, ok4...)
					in[i] = bad
					if runFieldRaw(t, F.ext4Inv, in) {
						t.Errorf("ext4Inv0 accepted %s at operand %d", bad, i)
					}
				}
			}
		})
	}
}

// TestR119_GateIsIdempotentUnderComposition -- the reason the gate goes on the
// INPUT rather than fixing up the output: a gated builtin returns a canonical
// element, so feeding one into the next passes the next gate for free. If this
// reddens, the output escaped the field somewhere.
func TestR119_GateIsIdempotentUnderComposition(t *testing.T) {
	for _, F := range fieldTiers() {
		t.Run(F.name, func(t *testing.T) {
			p := F.p
			pm1 := new(big.Int).Sub(p, bi(1))
			// sub(add(a, b), b) == a, executed as one script: the inner result
			// is fed straight into the outer builtin's gate.
			for _, ab := range [][2]*big.Int{{pm1, pm1}, {bi(0), pm1}, {bi(5), bi(7)}} {
				a, b := ab[0], ab[1]
				var ops []StackOp
				ops = append(ops, pushBigInt(a), pushBigInt(b))
				ops = append(ops, gatherOps(F.add)...) // [add]
				ops = append(ops, pushBigInt(b))
				ops = append(ops, gatherOps(F.sub)...) // [sub(add, b)]
				ops = append(ops, pushBigInt(a), opcode("OP_NUMEQUAL"))
				if err := BuildAndExecuteOps(ops); err != nil {
					t.Errorf("sub(add(%s, %s), %s) != %s: %v", a, b, b, a, err)
				}
			}
		})
	}
}
