package contract

import (
	"math/big"
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// P384Primitives.runar.go used to carry `//go:build ignore`: `Verify(k
// runar.Bigint, …)` could not hand an int64 to runar.P384Mul, which takes the
// *big.Int a 384-bit scalar needs. So this file ran the compile check and
// nothing else — the Rúnar half of what a .runar.go port is for, without the
// Go half.
//
// The scalar parameters are `runar.BigintBig` now, both names lower to the
// same `bigint` primitive, and the contract runs. Every scalar below is
// 384 bits: a test that passed small ones would not distinguish this from
// the state it replaced.

func TestP384Primitives_Compile(t *testing.T) {
	if err := runar.CompileCheck("P384Primitives.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// wideScalar is a 384-bit scalar below the curve order. Written out rather
// than derived so it cannot quietly become small.
func wideScalar(t *testing.T) *big.Int {
	t.Helper()
	k, ok := new(big.Int).SetString("4C1D3F5A7B9D0E2C4A6F8B0D2E4C6A8F0B2D4E6C8A0F2B4D6E8C0A2F4B6D8E0C2A4F6B8D0E2C4A6F8B0D2E4C6A8F", 16)
	if !ok {
		t.Fatal("bad scalar literal")
	}
	if k.BitLen() <= 64 {
		t.Fatalf("the scalar is %d bits — an int64 parameter would have taken it", k.BitLen())
	}
	return k
}

func TestP384Primitives_VerifyMulGen(t *testing.T) {
	k := wideScalar(t)
	c := &P384Primitives{ExpectedPoint: runar.P384MulGen(k)}
	c.VerifyMulGen(k)
}

func TestP384Primitives_VerifyMulGen_WrongScalarIsRefused(t *testing.T) {
	k := wideScalar(t)
	c := &P384Primitives{ExpectedPoint: runar.P384MulGen(k)}
	mustRefuse(t, "VerifyMulGen with k+1", func() {
		c.VerifyMulGen(new(big.Int).Add(k, big.NewInt(1)))
	})
}

func TestP384Primitives_Verify(t *testing.T) {
	k := wideScalar(t)
	base := runar.P384MulGen(big.NewInt(7))
	c := &P384Primitives{ExpectedPoint: runar.P384Mul(base, k)}
	c.Verify(k, base)
	mustRefuse(t, "Verify against another base point", func() {
		c.Verify(k, runar.P384MulGen(big.NewInt(8)))
	})
}

func TestP384Primitives_VerifyAdd(t *testing.T) {
	a := runar.P384MulGen(wideScalar(t))
	b := runar.P384MulGen(big.NewInt(3))
	c := &P384Primitives{ExpectedPoint: runar.P384Add(a, b)}
	c.VerifyAdd(a, b)
	mustRefuse(t, "VerifyAdd with a different addend", func() {
		c.VerifyAdd(a, runar.P384MulGen(big.NewInt(4)))
	})
}

// mustRefuse requires fn to fail the contract's assert. Without it every test
// above would pass against a contract whose methods did nothing.
func mustRefuse(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: the contract ACCEPTED it", what)
		}
	}()
	fn()
}
