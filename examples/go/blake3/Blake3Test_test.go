package contract

import (
	"encoding/hex"
	"testing"
	runar "github.com/icellan/runar/packages/runar-go"
)

// Cross-language reference vectors for the Rúnar BLAKE3 single-block
// compression with hardcoded blockLen=64, counter=0, flags=11 — the same
// values pinned in the seven runtime crates.
const (
	expectedCompressZeroCvZeroBlock = "443e523c2ed96088ceadcfefa47318bdd02bb2c26b27b7ac58ffe578f243bdfc"
	expectedHashZero32              = "7669004d96866a6330a609d9ad1a08a4f8507c4d04eefd1a50f00b02556aab86"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestBlake3Test_VerifyCompress(t *testing.T) {
	c := &Blake3Test{Expected: runar.ByteString(mustHex(expectedCompressZeroCvZeroBlock))}
	chainingValue := runar.ByteString(make([]byte, 32))
	block := runar.ByteString(make([]byte, 64))
	c.VerifyCompress(chainingValue, block)
}

func TestBlake3Test_VerifyHash(t *testing.T) {
	c := &Blake3Test{Expected: runar.ByteString(mustHex(expectedHashZero32))}
	message := runar.ByteString(make([]byte, 32))
	c.VerifyHash(message)
}

func TestBlake3Test_Compile(t *testing.T) {
	if err := runar.CompileCheck("Blake3Test.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
