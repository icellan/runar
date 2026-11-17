package codegen

// GK-GAP-009: the G2 on-curve assertion shared by the witness-assisted Groth16
// preamble (emitWAG2OnCurveCheck) and the general pairing builtins
// (bn254ValidateMultiPairingInputs) reduces both sides of the twist equation
// mod p and compares them, but never range-checks the four Fp limbs. G2 limbs
// are bigint stack values (never decomposed from fixed-width bytes), so
// x0 + p, or the negative x0 - p, names the same group element as x0 and used
// to pass: an alternate encoding of the same point, i.e. third-party
// malleability of the unlocking script and its txid.
//
// The expected verdicts are fixed by the field, not by the codegen: a limb
// outside [0, p) is not a canonical field element and must abort; the
// unmodified BN254 G2 generator (gnark-crypto) must pass.
//
// Proves: bn254AssertG2OnCurve aborts on every non-canonical limb tested, in
// both prime-cache modes the codegen uses (alt-stack cache for the builtins,
// q at the stack bottom for the Groth16 preamble), and accepts the generator.
// Does not prove: the subgroup check or the pairing (covered elsewhere).

import (
	"math/big"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
)

func gap009G2Generator() [4]*big.Int {
	_, _, _, g2 := bn254.Generators()
	var out [4]*big.Int
	for i, e := range []interface{ BigInt(*big.Int) *big.Int }{&g2.X.A0, &g2.X.A1, &g2.Y.A0, &g2.Y.A1} {
		out[i] = new(big.Int)
		e.BigInt(out[i])
	}
	return out
}

// gap009RunG2OnCurve executes bn254AssertG2OnCurve on the given limbs. With
// qAtBottom the tracker runs in the Groth16-preamble mode (modulus pushed at
// the bottom of the stack); otherwise it uses the alt-stack prime cache the
// pairing builtins use.
func gap009RunG2OnCurve(t *testing.T, limbs [4]*big.Int, qAtBottom bool) error {
	t.Helper()
	var ops []StackOp
	var initNames []string
	if qAtBottom {
		ops = append(ops, pushBigInt(bn254FieldP))
		initNames = append(initNames, "_qbot_p")
	}
	for _, l := range limbs {
		ops = append(ops, pushBigInt(l))
	}
	initNames = append(initNames, "gx0", "gx1", "gy0", "gy1")

	emit := func(op StackOp) { ops = append(ops, op) }
	tracker := NewBN254Tracker(initNames, emit)
	if qAtBottom {
		tracker.qAtBottom = true
		tracker.primeCacheActive = true
	} else {
		tracker.PushPrimeCache()
	}
	bn254AssertG2OnCurve(tracker, "gx0", "gx1", "gy0", "gy1", "gap9")
	if !qAtBottom {
		tracker.PopPrimeCache()
	}
	for len(tracker.nm) > 0 {
		tracker.drop()
	}
	ops = append(ops, opcode("OP_1"))
	return buildAndExecute(t, ops)
}

func TestGKGAP009_G2OnCurveRejectsAliasedLimbs(t *testing.T) {
	p := new(big.Int).Set(bn254FieldP)
	gen := gap009G2Generator()
	names := [4]string{"x0", "x1", "y0", "y1"}

	for _, qAtBottom := range []bool{false, true} {
		mode := "altstack_cache"
		if qAtBottom {
			mode = "q_at_bottom"
		}
		t.Run(mode+"/control_generator", func(t *testing.T) {
			if err := gap009RunG2OnCurve(t, gen, qAtBottom); err != nil {
				t.Fatalf("G2 generator rejected: %v", err)
			}
		})
		for i := 0; i < 4; i++ {
			for _, delta := range []struct {
				name string
				k    int64
			}{{"plus_p", 1}, {"minus_p", -1}} {
				i, delta := i, delta
				t.Run(mode+"/"+names[i]+"_"+delta.name, func(t *testing.T) {
					limbs := gen
					limbs[i] = new(big.Int).Add(gen[i], new(big.Int).Mul(big.NewInt(delta.k), p))
					if err := gap009RunG2OnCurve(t, limbs, qAtBottom); err == nil {
						t.Fatalf("GK-GAP-009: G2 on-curve check ACCEPTED the non-canonical limb %s %s p", names[i], map[int64]string{1: "+", -1: "-"}[delta.k])
					}
				})
			}
		}
	}
}
