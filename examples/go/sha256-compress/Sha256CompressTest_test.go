package contract

import (
	"encoding/hex"
	"testing"
	runar "github.com/icellan/runar/packages/runar-go"
)

func TestSha256CompressTest_Verify(t *testing.T) {
	// SHA-256("abc"): pad "abc" to 64 bytes per FIPS 180-4
	state, _ := hex.DecodeString("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
	block, _ := hex.DecodeString("6162638000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000018")
	expected := runar.Sha256Compress(runar.ByteString(state), runar.ByteString(block))

	c := &Sha256CompressTest{Expected: expected}
	c.Verify(runar.ByteString(state), runar.ByteString(block))
}

func TestSha256CompressTest_Compile(t *testing.T) {
	if err := runar.CompileCheck("Sha256CompressTest.runar.go"); err != nil {
		t.Fatalf("Runar compile check failed: %v", err)
	}
}
