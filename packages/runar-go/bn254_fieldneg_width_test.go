package runar

import (
	"math/big"
	"strings"
	"testing"
)

// Bn254FieldNegP(a) is (p - a) mod p over a 254-bit prime, so for every
// nonzero a the answer is ~254 bits and an int64 return cannot hold it. The
// function documented that in a comment — "In the mock, truncates to int64" —
// and returned the truncation anyway, which is the same shape as the bin2num
// and ecPointX defects: a wrong number with nothing to say so.
//
// It has no in-repo caller, which is why no agreement row caught it: the
// bn254FieldNeg row in mock_script_agreement_test.go exercises Bn254FieldNeg,
// the *big.Int form. Both peers stay, but the narrow one refuses rather than
// lies.
func TestBn254FieldNegP_RefusesWhatItCannotHold(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("Bn254FieldNegP(1) returned a value. p - 1 over the BN254 " +
				"base field is 254 bits; it used to return the low 64.")
		}
		if msg, _ := r.(string); !strings.Contains(msg, "Bn254FieldNegBigP") {
			t.Fatalf("the panic does not point at the wide form: %v", r)
		}
	}()
	_ = Bn254FieldNegP(1)
}

// Zero is the one input whose negation fits, and it must still work — a guard
// that refused every input would pass the test above.
func TestBn254FieldNegP_ZeroIsTheOneCaseThatFits(t *testing.T) {
	if got := Bn254FieldNegP(0); got != 0 {
		t.Fatalf("Bn254FieldNegP(0) = %d, want 0", got)
	}
}

// The wide form answers what the narrow one refuses, checked against the
// field prime rather than against itself.
func TestBn254FieldNegBigP_IsPMinusA(t *testing.T) {
	p, ok := new(big.Int).SetString(
		"21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
	if !ok {
		t.Fatal("bad prime literal")
	}
	for _, a := range []int64{1, 2, 7, 1 << 40} {
		got := Bn254FieldNeg(big.NewInt(a))
		want := new(big.Int).Sub(p, big.NewInt(a))
		if got.Cmp(want) != 0 {
			t.Fatalf("Bn254FieldNeg(%d) = %s, want %s", a, got, want)
		}
		if got.BitLen() <= 64 {
			t.Fatalf("Bn254FieldNeg(%d) is %d bits — an int64 return would have held it", a, got.BitLen())
		}
	}
}
