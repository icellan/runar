package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestConvergenceProof_ValidDelta(t *testing.T) {
	token := int64(42)
	oA := int64(100)
	oB := int64(37)

	rA := runar.EcMulGen(token + oA)
	rB := runar.EcMulGen(token + oB)
	deltaO := oA - oB

	c := &ConvergenceProof{RA: rA, RB: rB}
	c.ProveConvergence(deltaO) // should not panic
}

func TestConvergenceProof_WrongDelta(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong delta")
		}
	}()

	token := int64(42)
	oA := int64(100)
	oB := int64(37)

	rA := runar.EcMulGen(token + oA)
	rB := runar.EcMulGen(token + oB)
	wrongDelta := oA - oB + 1

	c := &ConvergenceProof{RA: rA, RB: rB}
	c.ProveConvergence(wrongDelta)
}

func TestConvergenceProof_DifferentTokens(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when tokens differ")
		}
	}()

	tokenA := int64(42)
	tokenB := int64(99)
	oA := int64(100)
	oB := int64(37)

	rA := runar.EcMulGen(tokenA + oA)
	rB := runar.EcMulGen(tokenB + oB)
	deltaO := oA - oB

	c := &ConvergenceProof{RA: rA, RB: rB}
	c.ProveConvergence(deltaO)
}

func TestConvergenceProof_LargerScalars(t *testing.T) {
	token := int64(1234567890)
	oA := int64(987654321)
	oB := int64(111111111)

	rA := runar.EcMulGen(token + oA)
	rB := runar.EcMulGen(token + oB)
	deltaO := oA - oB

	c := &ConvergenceProof{RA: rA, RB: rB}
	c.ProveConvergence(deltaO)
}

func TestConvergenceProof_Compile(t *testing.T) {
	if err := runar.CompileCheck("ConvergenceProof.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
