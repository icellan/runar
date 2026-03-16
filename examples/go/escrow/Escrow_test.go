package contract

import (
	"testing"
	runar "github.com/icellan/runar/packages/runar-go"
)

func newEscrow() *Escrow {
	return &Escrow{
		Buyer:   runar.Alice.PubKey,
		Seller:  runar.Bob.PubKey,
		Arbiter: runar.Charlie.PubKey,
	}
}

func TestEscrow_Release(t *testing.T) {
	sellerSig := runar.SignTestMessage(runar.Bob.PrivKey)
	arbiterSig := runar.SignTestMessage(runar.Charlie.PrivKey)
	newEscrow().Release(sellerSig, arbiterSig)
}

func TestEscrow_Refund(t *testing.T) {
	buyerSig := runar.SignTestMessage(runar.Alice.PrivKey)
	arbiterSig := runar.SignTestMessage(runar.Charlie.PrivKey)
	newEscrow().Refund(buyerSig, arbiterSig)
}

func TestEscrow_Compile(t *testing.T) {
	if err := runar.CompileCheck("Escrow.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
