package codegen

import (
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// Static-depth modulus fetch (emitFetchQ).
//
// Every BN254 field operation under q-at-bottom needs a copy of the modulus
// on top of the stack. The tracker knows the modulus' depth whenever it is a
// named slot (_q from the Groth16 witness layout, _qbot_p from
// PushQToBottom), so the fetch can be a constant-depth OP_PICK instead of
// OP_DEPTH OP_1SUB OP_PICK. Pushes are not counted against
// maxopsperscriptpolicy, so that is two counted ops fewer per fetch; the
// Groth16 verifier performs roughly 109,000 of them.
//
// These tests pin three things: the static form is emitted when the slot is
// tracked, the dynamic form is still emitted when it is not, and both forms
// compute the right field result when executed.
// ---------------------------------------------------------------------------

var fetchQTestPrime = func() *big.Int {
	p, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
	return p
}()

// fetchQCase is one field operation routed through emitFetchQ.
type fetchQCase struct {
	name  string
	arity int
	emit  func(t *BN254Tracker, a, b, res string)
	math  func(a, b, p *big.Int) *big.Int
}

func fetchQCases() []fetchQCase {
	mod := func(x, p *big.Int) *big.Int { return new(big.Int).Mod(x, p) }
	return []fetchQCase{
		{"mul", 2,
			func(t *BN254Tracker, a, b, r string) { bn254FieldMul(t, a, b, r) },
			func(a, b, p *big.Int) *big.Int { return mod(new(big.Int).Mul(a, b), p) }},
		{"add", 2,
			func(t *BN254Tracker, a, b, r string) { bn254FieldAdd(t, a, b, r) },
			func(a, b, p *big.Int) *big.Int { return mod(new(big.Int).Add(a, b), p) }},
		{"sub", 2,
			func(t *BN254Tracker, a, b, r string) { bn254FieldSub(t, a, b, r) },
			func(a, b, p *big.Int) *big.Int { return mod(new(big.Int).Sub(a, b), p) }},
		{"neg", 1,
			func(t *BN254Tracker, a, _, r string) { bn254FieldNeg(t, a, r) },
			func(a, _, p *big.Int) *big.Int { return mod(new(big.Int).Neg(a), p) }},
		{"mod", 1,
			func(t *BN254Tracker, a, _, r string) { bn254FieldMod(t, a, r) },
			func(a, _, p *big.Int) *big.Int { return mod(a, p) }},
		{"modpositive", 1,
			func(t *BN254Tracker, a, _, r string) { bn254FieldModPositive(t, a, r) },
			func(a, _, p *big.Int) *big.Int { return mod(a, p) }},
	}
}

func fetchQOperands() (*big.Int, *big.Int) {
	a, _ := new(big.Int).SetString("17777777777777777777777777777777777777777777777777777777777777777777777777777", 10)
	b, _ := new(big.Int).SetString("12345678901234567890123456789012345678901234567890123456789012345678901234567", 10)
	a.Mod(a, fetchQTestPrime)
	b.Mod(b, fetchQTestPrime)
	return a, b
}

func countOpcode(ops []StackOp, code string) int {
	n := 0
	for _, op := range ops {
		if op.Op == "opcode" && op.Code == code {
			n++
		}
		if op.Op == "if" {
			n += countOpcode(op.Then, code)
			n += countOpcode(op.Else, code)
		}
	}
	return n
}

func countOp(ops []StackOp, kind string) int {
	n := 0
	for _, op := range ops {
		if op.Op == kind {
			n++
		}
		if op.Op == "if" {
			n += countOp(op.Then, kind)
			n += countOp(op.Else, kind)
		}
	}
	return n
}

// TestEmitFetchQ_StaticPickWhenModulusIsTracked: with the modulus sunk to
// the bottom by PushQToBottom (a tracked slot), every field op must fetch it
// with a constant-depth pick and never with OP_DEPTH, and the result must be
// the correct field value.
func TestEmitFetchQ_StaticPickWhenModulusIsTracked(t *testing.T) {
	a, b := fetchQOperands()
	for _, tc := range fetchQCases() {
		t.Run(tc.name, func(t *testing.T) {
			names := []string{"a", "b"}[:tc.arity]
			emitted := gatherOps(func(emit func(StackOp)) {
				tr := NewBN254Tracker(names, emit)
				tr.PushQToBottom()
				tc.emit(tr, "a", "b", "r")
			})

			if n := countOpcode(emitted, "OP_DEPTH"); n != 0 {
				t.Fatalf("%s: %d OP_DEPTH in emitted ops; the modulus is a tracked slot so every fetch should be a static pick", tc.name, n)
			}
			if countOp(emitted, "pick") == 0 {
				t.Fatalf("%s: no pick op emitted; expected at least one static modulus fetch", tc.name)
			}

			want := tc.math(a, b, fetchQTestPrime)
			var ops []StackOp
			ops = append(ops, pushBigInt(a))
			if tc.arity == 2 {
				ops = append(ops, pushBigInt(b))
			}
			ops = append(ops, emitted...)
			// Stack: [q, r]
			ops = append(ops, pushBigInt(want))
			ops = append(ops, opcode("OP_EQUALVERIFY"))
			ops = append(ops, opcode("OP_DROP")) // q
			ops = append(ops, opcode("OP_1"))
			if err := buildAndExecute(t, ops); err != nil {
				t.Fatalf("%s with static modulus fetch computed the wrong value: %v", tc.name, err)
			}
		})
	}
}

// TestEmitFetchQ_DynamicFallbackWhenModulusIsUntracked: SetQAtBottom marks
// the modulus as present at the bottom without it being a tracked slot (the
// caller put it there). The fetch must then stay OP_DEPTH OP_1SUB OP_PICK,
// and still compute the right value.
func TestEmitFetchQ_DynamicFallbackWhenModulusIsUntracked(t *testing.T) {
	a, b := fetchQOperands()
	for _, tc := range fetchQCases() {
		t.Run(tc.name, func(t *testing.T) {
			names := []string{"a", "b"}[:tc.arity]
			emitted := gatherOps(func(emit func(StackOp)) {
				tr := NewBN254Tracker(names, emit)
				tr.SetQAtBottom()
				tr.primeCacheActive = true
				tc.emit(tr, "a", "b", "r")
			})

			if countOpcode(emitted, "OP_DEPTH") == 0 {
				t.Fatalf("%s: no OP_DEPTH emitted; with an untracked modulus the fetch must fall back to the dynamic form", tc.name)
			}

			want := tc.math(a, b, fetchQTestPrime)
			var ops []StackOp
			ops = append(ops, pushBigInt(fetchQTestPrime)) // untracked q at the bottom
			ops = append(ops, pushBigInt(a))
			if tc.arity == 2 {
				ops = append(ops, pushBigInt(b))
			}
			ops = append(ops, emitted...)
			ops = append(ops, pushBigInt(want))
			ops = append(ops, opcode("OP_EQUALVERIFY"))
			ops = append(ops, opcode("OP_DROP")) // q
			ops = append(ops, opcode("OP_1"))
			if err := buildAndExecute(t, ops); err != nil {
				t.Fatalf("%s with dynamic modulus fetch computed the wrong value: %v", tc.name, err)
			}
		})
	}
}

// TestEmitFetchQ_StaticDepthSurvivesIntermediateSlots: the depth must be
// computed from the tracker's live slot list, not assumed from the input
// count. Interleave unrelated tracked values between the modulus and the
// operands and chain two ops so the second runs with a changed slot list.
func TestEmitFetchQ_StaticDepthSurvivesIntermediateSlots(t *testing.T) {
	a, b := fetchQOperands()
	c := big.NewInt(99)
	emitted := gatherOps(func(emit func(StackOp)) {
		tr := NewBN254Tracker([]string{"x", "y", "a", "b"}, emit)
		tr.PushQToBottom()
		bn254FieldMul(tr, "a", "b", "ab") // slots: q x y ab
		tr.pushBigInt("c", c)             // slots: q x y ab c
		bn254FieldAdd(tr, "ab", "c", "r") // slots: q x y r
		tr.toTop("r")
	})
	if n := countOpcode(emitted, "OP_DEPTH"); n != 0 {
		t.Fatalf("%d OP_DEPTH emitted; expected static fetches only", n)
	}
	want := new(big.Int).Mul(a, b)
	want.Mod(want, fetchQTestPrime)
	want.Add(want, c)
	want.Mod(want, fetchQTestPrime)

	var ops []StackOp
	ops = append(ops, pushBigInt(big.NewInt(1))) // x
	ops = append(ops, pushBigInt(big.NewInt(2))) // y
	ops = append(ops, pushBigInt(a))
	ops = append(ops, pushBigInt(b))
	ops = append(ops, emitted...)
	// Stack: [q, x, y, r]
	ops = append(ops, pushBigInt(want))
	ops = append(ops, opcode("OP_EQUALVERIFY"))
	ops = append(ops, opcode("OP_2DROP")) // x y
	ops = append(ops, opcode("OP_DROP"))  // q
	ops = append(ops, opcode("OP_1"))
	if err := buildAndExecute(t, ops); err != nil {
		t.Fatalf("chained ops with intermediate slots computed the wrong value: %v", err)
	}
}

// TestEmitFetchQ_MSMVerifierHasNoDynamicModulusFetch: the whole MSM-binding
// Groth16 verifier keeps the modulus as the tracked _q slot, so the static
// form must be used throughout. One OP_DEPTH anywhere means a field op was
// routed around emitFetchQ and the op-count saving silently regressed.
func TestEmitFetchQ_MSMVerifierHasNoDynamicModulusFetch(t *testing.T) {
	config := DefaultGroth16Config()
	genG := [2]*big.Int{big.NewInt(1), big.NewInt(2)}
	config.IC = [6][2]*big.Int{genG, genG, genG, genG, genG, genG}
	ops := gatherOps(func(emit func(StackOp)) {
		EmitGroth16VerifierWitnessAssistedWithMSM(emit, config)
	})
	if len(ops) == 0 {
		t.Fatal("verifier emitted zero ops")
	}
	if n := countOpcode(ops, "OP_DEPTH"); n != 0 {
		t.Fatalf("MSM verifier emits %d OP_DEPTH; every modulus fetch should be a static pick", n)
	}
}
