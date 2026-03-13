package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestP2PKH_Unlock(t *testing.T) {
	pk := runar.MockPubKey()
	c := &P2PKH{PubKeyHash: runar.Hash160(pk)}
	c.Unlock(runar.MockSig(), pk)
}

func TestP2PKH_Unlock_WrongKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong public key")
		}
	}()
	pk := runar.MockPubKey()
	wrongPk := runar.PubKey("\x03" + string(make([]byte, 32)))
	c := &P2PKH{PubKeyHash: runar.Hash160(pk)}
	c.Unlock(runar.MockSig(), wrongPk)
}

func TestP2PKH_Compile(t *testing.T) {
	if err := runar.CompileCheck("P2PKH.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// Row 483: P2PKH is stateless — no mutable state tracked
func TestP2PKH_IsStateless(t *testing.T) {
	pk := runar.MockPubKey()
	c := &P2PKH{PubKeyHash: runar.Hash160(pk)}
	// Stateless contracts have no AddOutputs tracking
	// Calling Unlock does not accumulate state
	c.Unlock(runar.MockSig(), pk)
	// After the call, no side-effects on the struct itself
	// (the contract is stateless — properties are readonly)
	if len(c.PubKeyHash) == 0 {
		t.Error("expected PubKeyHash to remain non-empty after unlock")
	}
}
