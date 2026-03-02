package contract

import (
	"testing"
	"runar"
)

func newEscrow() *Escrow {
	return &Escrow{
		Buyer:   runar.MockPubKey(),
		Seller:  runar.MockPubKey(),
		Arbiter: runar.MockPubKey(),
	}
}

func TestEscrow_ReleaseBySeller(t *testing.T)  { newEscrow().ReleaseBySeller(runar.MockSig()) }
func TestEscrow_ReleaseByArbiter(t *testing.T) { newEscrow().ReleaseByArbiter(runar.MockSig()) }
func TestEscrow_RefundToBuyer(t *testing.T)    { newEscrow().RefundToBuyer(runar.MockSig()) }
func TestEscrow_RefundByArbiter(t *testing.T)  { newEscrow().RefundByArbiter(runar.MockSig()) }

func TestEscrow_Compile(t *testing.T) {
	if err := runar.CompileCheck("Escrow.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
