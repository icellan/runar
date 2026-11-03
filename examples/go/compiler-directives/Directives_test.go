package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// The directives (the `embedAlways` struct-tag option and the
// `//runar:sighash` comment) change only the compiled script and artifact;
// natively both spend paths are an ordinary P2PKH check.

func newDirectives() *Directives {
	return &Directives{PubKeyHash: runar.Hash160(runar.Alice.PubKey), DeployTag: runar.ByteString("\x01\x02")}
}

func TestDirectives_SpendAll(t *testing.T) {
	newDirectives().SpendAll(runar.SignTestMessage(runar.Alice.PrivKey), runar.Alice.PubKey)
}

func TestDirectives_SpendSingle(t *testing.T) {
	newDirectives().SpendSingle(runar.SignTestMessage(runar.Alice.PrivKey), runar.Alice.PubKey)
}

func TestDirectives_SpendSingle_WrongKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong public key")
		}
	}()
	newDirectives().SpendSingle(runar.SignTestMessage(runar.Bob.PrivKey), runar.Bob.PubKey)
}

func TestDirectives_Compile(t *testing.T) {
	if err := runar.CompileCheck("Directives.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
