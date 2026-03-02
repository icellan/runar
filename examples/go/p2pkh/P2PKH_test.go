package contract

import (
	"testing"

	"runar"
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
