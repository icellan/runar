package contract

import (
	"testing"
	"runar"
)

func newVault() *CovenantVault {
	return &CovenantVault{
		Owner:     runar.MockPubKey(),
		Recipient: runar.Hash160(runar.MockPubKey()),
		MinAmount: 1000,
	}
}

func TestCovenantVault_Spend(t *testing.T) {
	newVault().Spend(runar.MockSig(), 5000, runar.MockPreimage())
}

func TestCovenantVault_Spend_ExactMinimum(t *testing.T) {
	newVault().Spend(runar.MockSig(), 1000, runar.MockPreimage())
}

func TestCovenantVault_Spend_BelowMinimum_Fails(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure")
		}
	}()
	newVault().Spend(runar.MockSig(), 999, runar.MockPreimage())
}

func TestCovenantVault_Compile(t *testing.T) {
	if err := runar.CompileCheck("CovenantVault.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
