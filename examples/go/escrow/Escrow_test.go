package contract

import (
	"testing"
	runar "github.com/icellan/runar/packages/runar-go"
)

func newEscrow() *Escrow {
	return &Escrow{
		Buyer:   runar.MockPubKey(),
		Seller:  runar.MockPubKey(),
		Arbiter: runar.MockPubKey(),
	}
}

func TestEscrow_Release(t *testing.T) {
	newEscrow().Release(runar.MockSig(), runar.MockSig())
}

func TestEscrow_Refund(t *testing.T) {
	newEscrow().Refund(runar.MockSig(), runar.MockSig())
}

func TestEscrow_Compile(t *testing.T) {
	if err := runar.CompileCheck("Escrow.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
