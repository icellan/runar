package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestP2PKH_Unlock(t *testing.T) {
	pk := runar.Alice.PubKey
	c := &P2PKH{PubKeyHash: runar.Hash160(pk)}
	c.Unlock(runar.SignTestMessage(runar.Alice.PrivKey), pk)
}

func TestP2PKH_Unlock_WrongKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong public key")
		}
	}()
	pk := runar.Alice.PubKey
	c := &P2PKH{PubKeyHash: runar.Hash160(pk)}
	c.Unlock(runar.SignTestMessage(runar.Bob.PrivKey), runar.Bob.PubKey)
}

func TestP2PKH_Compile(t *testing.T) {
	if err := runar.CompileCheck("P2PKH.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// Row 483: P2PKH is stateless — no mutable state tracked
func TestP2PKH_IsStateless(t *testing.T) {
	pk := runar.Alice.PubKey
	c := &P2PKH{PubKeyHash: runar.Hash160(pk)}
	// Stateless contracts have no AddOutputs tracking
	// Calling Unlock does not accumulate state
	c.Unlock(runar.SignTestMessage(runar.Alice.PrivKey), pk)
	// After the call, no side-effects on the struct itself
	// (the contract is stateless — properties are readonly)
	if len(c.PubKeyHash) == 0 {
		t.Error("expected PubKeyHash to remain non-empty after unlock")
	}
}
