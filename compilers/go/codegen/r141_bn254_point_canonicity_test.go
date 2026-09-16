package codegen

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// R-141 -- `bn254G1OnCurve` had no coordinate-canonicity guard, and
// `bn254DecomposePoint` had no OP_SIZE-64 gate.
//
// Every other curve family in the repo carries both: ec.go's EmitEcOnCurve
// (GAP-301 for the coordinates, CL-BUG-095 for the width) and its a = -3 twin
// in p256_p384.go, plus the R-117 aborting gate on the EC value builtins. The
// BN254 body was decompose -> y^2 -> x^3+3 -> OP_EQUAL with nothing in front of
// it. Measured on the go-sdk interpreter before this commit, with the EIP-197
// generator G = (1, 2):
//
//	bn254G1OnCurve(G)             -> 1
//	bn254G1OnCurve((1+p) || 2)    -> 1     <- a non-canonical x certified
//	bn254G1OnCurve(1 || (2+p))    -> 1     <- and a non-canonical y
//	bn254G1OnCurve((1+p) || (2+p))-> 1
//	bn254G1OnCurve(G || 0xff)     -> 1     <- 65 bytes, surplus discarded
//	bn254G1OnCurve(1 || 3)        -> 0     (correctly off-curve)
//
// BN254's field prime is ~2^253.6, so x + p < 2^256 for EVERY x < p. Unlike
// secp256k1 -- where the alias only fits for x < 2^32 + 977 -- here the alias
// exists for every point on the curve, which makes the predicate answer "yes"
// to an unbounded family of encodings of each point.
//
// WHAT IS *NOT* BROKEN, measured rather than assumed: BN254's adder is not
// fooled into a WRONG ANSWER the way secp256k1's was under R-117.
// bn254G1Add(G, (1+p)||2) returned the correct 2G
// (030644e7...fd31 || 15ed738c...a2c4), because bn254G1InfinityFlag reduces
// before it compares, where ecAffineAdd's two selectors did not. So the value
// builtins are gated for a different reason, recorded in
// bn254EmitCoordCanonVerify: bn254ComposePoint's own contract says callers must
// supply [0, p-1] and that it does not check, and bn254G1Negate handed it the
// raw decomposed x -- a value builtin PRODUCING a blob that is not a point.
//
// The split follows R-117 exactly: the predicate CLAMPS and FLAGS (so it stays
// total and answers false), the value builtins OP_VERIFY, and the WIDTH check
// goes inside the shared decompose helper where every consumer inherits it --
// which is the placement CL-BUG-095 already chose for ecDecomposePoint.
// ---------------------------------------------------------------------------

func bn254BE32(v *big.Int) []byte {
	b := v.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func bn254Blob(x, y *big.Int) []byte {
	return append(bn254BE32(x), bn254BE32(y)...)
}

func bn254PushBytes(b []byte) StackOp {
	return StackOp{Op: "push", Value: PushValue{Kind: "bytes", Bytes: b}}
}

// bn254OnCurve runs EmitBN254G1OnCurve on `blob` and returns (truthy, aborted).
// The predicate must be TOTAL, so `aborted` must stay false for every input.
func bn254OnCurve(t *testing.T, blob []byte) (truthy bool, aborted bool) {
	t.Helper()
	ops := []StackOp{bn254PushBytes(blob)}
	ops = append(ops, gatherOps(EmitBN254G1OnCurve)...)
	// OP_VERIFY would conflate "false" with "aborted"; compare against 1
	// instead and read the two outcomes apart via a second run.
	truthyOps := append(append([]StackOp{}, ops...), opcode("OP_1"), opcode("OP_NUMEQUAL"))
	falseOps := append(append([]StackOp{}, ops...), opcode("OP_0"), opcode("OP_NUMEQUAL"))
	okTrue := BuildAndExecuteOps(truthyOps) == nil
	okFalse := BuildAndExecuteOps(falseOps) == nil
	if okTrue {
		return true, false
	}
	if okFalse {
		return false, false
	}
	return false, true
}

// TestR141_BN254OnCurveRejectsNonCanonicalCoordinates is the finding.
func TestR141_BN254OnCurveRejectsNonCanonicalCoordinates(t *testing.T) {
	p := bn254FieldP
	gx, gy := bn254GenX, bn254GenY
	xa := new(big.Int).Add(gx, p)
	ya := new(big.Int).Add(gy, p)

	// The alias must actually FIT in 32 bytes, or the test proves nothing.
	if xa.BitLen() > 256 || ya.BitLen() > 256 {
		t.Fatalf("alias does not fit 32 bytes: x+p %d bits, y+p %d bits", xa.BitLen(), ya.BitLen())
	}

	// CONTROL WITH TEETH: the real generator still certifies.
	if ok, ab := bn254OnCurve(t, bn254Blob(gx, gy)); !ok || ab {
		t.Fatalf("CONTROL onCurve(G) = (%v, aborted=%v), want (true, false)", ok, ab)
	}

	for _, c := range []struct {
		name string
		blob []byte
	}{
		{"(x+p, y)", bn254Blob(xa, gy)},
		{"(x, y+p)", bn254Blob(gx, ya)},
		{"(x+p, y+p)", bn254Blob(xa, ya)},
		{"(p, y)", bn254Blob(p, gy)},
		{"(x, p)", bn254Blob(gx, p)},
	} {
		ok, aborted := bn254OnCurve(t, c.blob)
		if ok {
			t.Errorf("onCurve%s returned TRUE for a non-canonical encoding", c.name)
		}
		// The predicate must stay TOTAL: false, never an abort.
		if aborted {
			t.Errorf("onCurve%s ABORTED; the predicate must answer false", c.name)
		}
	}
}

// TestR141_BN254OnCurveRejectsWrongWidth -- the OP_SIZE-64 half.
func TestR141_BN254OnCurveRejectsWrongWidth(t *testing.T) {
	gx, gy := bn254GenX, bn254GenY
	g := bn254Blob(gx, gy)

	for _, c := range []struct {
		name string
		blob []byte
	}{
		{"65 bytes (G || ff)", append(append([]byte{}, g...), 0xff)},
		{"66 bytes", append(append([]byte{}, g...), 0x00, 0x00)},
		{"63 bytes", g[:63]},
		{"32 bytes", g[:32]},
		{"empty", []byte{}},
	} {
		ok, aborted := bn254OnCurve(t, c.blob)
		if ok {
			t.Errorf("onCurve(%s) returned TRUE", c.name)
		}
		if aborted {
			t.Errorf("onCurve(%s) ABORTED; the predicate must answer false", c.name)
		}
	}
}

// TestR141_BN254OnCurveBoundIsExact -- p-1 is a legal coordinate, p is not.
// An over-strict gate reddens the accept half here.
func TestR141_BN254OnCurveBoundIsExact(t *testing.T) {
	p := bn254FieldP
	pm1 := new(big.Int).Sub(p, big.NewInt(1))

	// (p-1, 0) is not on the curve, so the expected answer is FALSE either way
	// -- what is pinned is that it does not ABORT, i.e. the gate treats p-1 as
	// a legal field element and lets the curve equation decide.
	if _, aborted := bn254OnCurve(t, bn254Blob(pm1, big.NewInt(0))); aborted {
		t.Errorf("onCurve((p-1, 0)) aborted; p-1 is a legal coordinate")
	}
	if _, aborted := bn254OnCurve(t, bn254Blob(big.NewInt(0), pm1)); aborted {
		t.Errorf("onCurve((0, p-1)) aborted; p-1 is a legal coordinate")
	}
	// The all-zero blob (the encoding the value builtins use for infinity)
	// stays a legal input and answers false: 0 != 0^3 + 3.
	zero := make([]byte, 64)
	ok, aborted := bn254OnCurve(t, zero)
	if aborted {
		t.Errorf("onCurve(O) aborted")
	}
	if ok {
		t.Errorf("onCurve(O) returned true; y^2 = 0 != 3 = x^3 + 3")
	}
}

// TestR141_BN254ValueBuiltinsAbortOnNonCanonical -- the aborting half. `negate`
// is the one that PRODUCED a non-canonical blob; `add` is included because it
// consumes two and both must be gated.
func TestR141_BN254ValueBuiltinsAbortOnNonCanonical(t *testing.T) {
	p := bn254FieldP
	gx, gy := bn254GenX, bn254GenY
	g := bn254Blob(gx, gy)
	alias := bn254Blob(new(big.Int).Add(gx, p), gy)
	g65 := append(append([]byte{}, g...), 0xff)

	run := func(emitFn func(func(StackOp)), blobs ...[]byte) bool {
		var ops []StackOp
		for _, b := range blobs {
			ops = append(ops, bn254PushBytes(b))
		}
		ops = append(ops, gatherOps(emitFn)...)
		ops = append(ops, opcode("OP_DROP"), opcode("OP_1"))
		return BuildAndExecuteOps(ops) == nil
	}

	// CONTROL WITH TEETH: the honest call still doubles, and the answer is
	// graded against 2G computed here with big.Int, not against a constant
	// copied out of the emitter's own output.
	{
		dx, dy := bn254DoubleOffChain(gx, gy, p)
		want := bn254Blob(dx, dy)
		var ops []StackOp
		ops = append(ops, bn254PushBytes(g), bn254PushBytes(g))
		ops = append(ops, gatherOps(EmitBN254G1Add)...)
		ops = append(ops, bn254PushBytes(want), opcode("OP_EQUAL"))
		if err := BuildAndExecuteOps(ops); err != nil {
			t.Fatalf("CONTROL add(G, G) must still produce 2G (%s): %v",
				hex.EncodeToString(want), err)
		}
	}
	if !run(EmitBN254G1Negate, g) {
		t.Fatalf("CONTROL negate(G) must still run")
	}

	if run(EmitBN254G1Negate, alias) {
		t.Errorf("negate((x+p) || y) accepted — it re-emitted the non-canonical x")
	}
	if run(EmitBN254G1Negate, g65) {
		t.Errorf("negate(G || 0xff) accepted")
	}
	if run(EmitBN254G1Add, g, alias) {
		t.Errorf("add(G, (x+p) || y) accepted")
	}
	if run(EmitBN254G1Add, alias, g) {
		t.Errorf("add((x+p) || y, G) accepted")
	}
	if run(EmitBN254G1Add, g, g65) {
		t.Errorf("add(G, G || 0xff) accepted")
	}
}

// bn254DoubleOffChain computes 2P on y^2 = x^3 + 3 over F_p with plain big.Int
// arithmetic -- an independent reference for the adder's doubling case.
func bn254DoubleOffChain(x, y, p *big.Int) (*big.Int, *big.Int) {
	three := big.NewInt(3)
	two := big.NewInt(2)
	num := new(big.Int).Mul(three, new(big.Int).Mul(x, x))
	num.Mod(num, p)
	den := new(big.Int).Mul(two, y)
	den.Mod(den, p)
	lam := new(big.Int).Mul(num, new(big.Int).ModInverse(den, p))
	lam.Mod(lam, p)
	rx := new(big.Int).Sub(new(big.Int).Mul(lam, lam), new(big.Int).Mul(two, x))
	rx.Mod(rx, p)
	ry := new(big.Int).Sub(new(big.Int).Mul(lam, new(big.Int).Sub(x, rx)), y)
	ry.Mod(ry, p)
	return rx, ry
}
