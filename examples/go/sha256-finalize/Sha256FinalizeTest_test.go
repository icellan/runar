package contract

import (
	"encoding/hex"
	"testing"
	runar "github.com/icellan/runar/packages/runar-go"
)

func TestSha256FinalizeTest_Verify(t *testing.T) {
	state, _ := hex.DecodeString("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
	expected := runar.Sha256Finalize(runar.ByteString(state), runar.ByteString("abc"), 24)

	c := &Sha256FinalizeTest{Expected: expected}
	c.Verify(runar.ByteString(state), runar.ByteString("abc"), 24)
}

func TestSha256FinalizeTest_Compile(t *testing.T) {
	if err := runar.CompileCheck("Sha256FinalizeTest.runar.go"); err != nil {
		t.Fatalf("Runar compile check failed: %v", err)
	}
}
