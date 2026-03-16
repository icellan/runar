package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestP2Blake3PKH_Unlock(t *testing.T) {
	pk := runar.Alice.PubKey
	c := &P2Blake3PKH{PubKeyHash: runar.Blake3Hash(pk)}
	c.Unlock(runar.SignTestMessage(runar.Alice.PrivKey), pk)
}

func TestP2Blake3PKH_Unlock_WrongHash(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong public key hash")
		}
	}()
	pk := runar.Alice.PubKey
	// blake3Hash is mocked (always returns 32 zero bytes), so use a non-matching hash
	wrongHash := runar.ByteString(string(make([]byte, 31)) + "\xff")
	c := &P2Blake3PKH{PubKeyHash: wrongHash}
	c.Unlock(runar.SignTestMessage(runar.Alice.PrivKey), pk)
}

func TestP2Blake3PKH_Compile(t *testing.T) {
	if err := runar.CompileCheck("P2Blake3PKH.runar.go"); err != nil {
		t.Fatalf("Runar compile check failed: %v", err)
	}
}
