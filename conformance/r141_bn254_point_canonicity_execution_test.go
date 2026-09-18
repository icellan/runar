package conformance

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// ---------------------------------------------------------------------------
// R-141 -- executed coverage for the BN254 G1 point gates, at the CONTRACT
// level.
//
// There is no bn254 fixture under conformance/tests, which is half of why this
// survived: the family's only cross-tier probe (conformance/go-only-parity)
// exercised `bn254FieldMul` and never touched a G1 POINT builtin, and no test
// anywhere spent a contract that called `bn254G1OnCurve`. The gate added in
// this commit is therefore exercised here the way the repo's other crypto
// primitives are: an inline contract compiled by the TYPESCRIPT compiler and
// executed on the go-sdk consensus interpreter -- two independent
// implementations on the two sides of every assertion.
//
// The property under test is the R-117 split, applied to BN254:
//
//   - `bn254G1OnCurve` is a PREDICATE and must stay TOTAL. For a non-canonical
//     coordinate or a wrong-width blob it must answer FALSE, not abort. Before
//     the gate it answered TRUE: measured, onCurve((1+p) || 2), onCurve(1 ||
//     (2+p)) and onCurve(G || 0xff) all returned 1.
//   - `bn254G1Negate` is a VALUE builtin and must ABORT. Before the gate it
//     re-emitted the raw non-canonical x, producing a blob that is not a point.
//
// The contracts below separate the two: `probe` asserts the predicate is false
// (so an abort and a false answer are distinguishable -- an abort fails the
// script, a false answer satisfies `assert(!onCurve(p))`), and `negate` calls
// the value builtin directly.
// ---------------------------------------------------------------------------

const bn254OnCurveTrueSource = `
class Bn254OnCurveTrue extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) { super(tag); this.tag = tag; }
  public verify(p: ByteString) {
    assert(bn254G1OnCurve(p));
  }
}
`

const bn254OnCurveFalseSource = `
class Bn254OnCurveFalse extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) { super(tag); this.tag = tag; }
  public verify(p: ByteString) {
    assert(!bn254G1OnCurve(p));
  }
}
`

const bn254NegateSource = `
class Bn254NegateProbe extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) { super(tag); this.tag = tag; }
  public verify(p: ByteString) {
    // Negate twice and compare against the input: the round trip holds for any
    // canonical point, so the spend succeeds exactly when the gate lets the
    // operand through. (-(-P) = P because p - (p - y) = y for y in [0, p-1].)
    const q = bn254G1Negate(bn254G1Negate(p));
    assert(q === p);
  }
}
`

// bn254FieldPrime is the EIP-197 base-field prime.
var bn254FieldPrime, _ = new(big.Int).SetString(
	"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16)

func bn254PointBlob(x, y *big.Int) []byte {
	out := make([]byte, 64)
	xb, yb := x.Bytes(), y.Bytes()
	copy(out[32-len(xb):32], xb)
	copy(out[64-len(yb):], yb)
	return out
}

// spendBn254 compiles `src` and spends `verify(blob)`. Returns whether the
// consensus interpreter ACCEPTED.
func spendBn254(t *testing.T, src, fileName string, blob []byte) bool {
	t.Helper()
	lockingHex, err := compileRúnarInline(src, `{"tag":"1"}`, fileName)
	if err != nil {
		t.Fatalf("compile %s: %v", fileName, err)
	}
	return executeScript(lockingHex, encodePushBytes(blob)) == nil
}

// TestR141_BN254OnCurveIsTotalAndRejectsNonCanonical -- the finding, executed
// at the contract level.
func TestR141_BN254OnCurveIsTotalAndRejectsNonCanonical(t *testing.T) {
	p := bn254FieldPrime
	gx, gy := big.NewInt(1), big.NewInt(2)
	g := bn254PointBlob(gx, gy)

	// CONTROL WITH TEETH: `assert(onCurve(G))` must still spend. Without this,
	// an over-strict gate that made the predicate always-false would satisfy
	// every negative case below.
	if !spendBn254(t, bn254OnCurveTrueSource, "Bn254OnCurveTrue.runar.ts", g) {
		t.Fatalf("CONTROL assert(onCurve(G)) must still spend")
	}

	// Every one of these used to make `assert(onCurve(p))` SPEND. Now they must
	// make `assert(!onCurve(p))` spend instead -- which is a strictly stronger
	// statement than "the first contract fails", because a script that ABORTED
	// would fail both.
	for _, c := range []struct {
		name string
		blob []byte
	}{
		{"(x+p, y)", bn254PointBlob(new(big.Int).Add(gx, p), gy)},
		{"(x, y+p)", bn254PointBlob(gx, new(big.Int).Add(gy, p))},
		{"(p, y)", bn254PointBlob(p, gy)},
		{"65 bytes", append(append([]byte{}, g...), 0xff)},
		{"63 bytes", g[:63]},
		{"empty", []byte{}},
	} {
		if spendBn254(t, bn254OnCurveTrueSource, "Bn254OnCurveTrue.runar.ts", c.blob) {
			t.Errorf("assert(onCurve(%s)) spent — the predicate certified a bad encoding", c.name)
		}
		if !spendBn254(t, bn254OnCurveFalseSource, "Bn254OnCurveFalse.runar.ts", c.blob) {
			t.Errorf("assert(!onCurve(%s)) did NOT spend — the predicate aborted "+
				"instead of answering false", c.name)
		}
	}
}

// TestR141_BN254NegateAbortsOnNonCanonical -- the value-builtin half.
func TestR141_BN254NegateAbortsOnNonCanonical(t *testing.T) {
	p := bn254FieldPrime
	gx, gy := big.NewInt(1), big.NewInt(2)
	g := bn254PointBlob(gx, gy)

	// CONTROL: the honest negation still spends.
	if !spendBn254(t, bn254NegateSource, "Bn254NegateProbe.runar.ts", g) {
		t.Fatalf("CONTROL negate(G) must still spend")
	}

	for _, c := range []struct {
		name string
		blob []byte
	}{
		{"(x+p, y)", bn254PointBlob(new(big.Int).Add(gx, p), gy)},
		{"(x, y+p)", bn254PointBlob(gx, new(big.Int).Add(gy, p))},
		{"65 bytes", append(append([]byte{}, g...), 0xff)},
	} {
		if spendBn254(t, bn254NegateSource, "Bn254NegateProbe.runar.ts", c.blob) {
			t.Errorf("negate(%s) spent — a value builtin accepted a non-canonical point", c.name)
		}
	}

	// BOUNDARY: p-1 is a legal coordinate, p is not. The point is off-curve
	// either way, but negate does not check the curve equation, so this pins
	// the gate's bound and nothing else.
	pm1 := new(big.Int).Sub(p, big.NewInt(1))
	if !spendBn254(t, bn254NegateSource, "Bn254NegateProbe.runar.ts", bn254PointBlob(pm1, big.NewInt(1))) {
		t.Errorf("negate((p-1, 1)) rejected — p-1 is a legal field element")
	}
	if spendBn254(t, bn254NegateSource, "Bn254NegateProbe.runar.ts", bn254PointBlob(p, big.NewInt(1))) {
		t.Errorf("negate((p, 1)) spent — the bound must exclude p itself")
	}
	_ = hex.EncodeToString(g)
}
