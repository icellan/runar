package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// NOTE: init() applies the property initializer (Tags = {7, 9, 11}); call it
// after constructing the struct, as the compiler bakes it into the script.

func newEmbedTags() *EmbedTags {
	c := &EmbedTags{PubKeyHash: runar.Hash160(runar.Alice.PubKey)}
	c.init()
	return c
}

func TestEmbedTags_Unlock(t *testing.T) {
	newEmbedTags().Unlock(runar.SignTestMessage(runar.Alice.PrivKey), runar.Alice.PubKey, 9)
}

func TestEmbedTags_Unlock_AmountBelowTag(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for amount < Tags[1]")
		}
	}()
	newEmbedTags().Unlock(runar.SignTestMessage(runar.Alice.PrivKey), runar.Alice.PubKey, 8)
}

func TestEmbedTags_Compile(t *testing.T) {
	if err := runar.CompileCheck("EmbedTags.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
