package contract

import (
	"testing"
	runar "github.com/icellan/runar/packages/runar-go"
)

func newBlake3Test() *Blake3Test {
	// Mock BLAKE3 functions return 32 zero bytes, so set Expected to match.
	return &Blake3Test{
		Expected: runar.ByteString(make([]byte, 32)),
	}
}

func TestBlake3Test_VerifyCompress(t *testing.T) {
	c := newBlake3Test()
	chainingValue := runar.ByteString(make([]byte, 32))
	block := runar.ByteString(make([]byte, 64))
	c.VerifyCompress(chainingValue, block)
}

func TestBlake3Test_VerifyHash(t *testing.T) {
	c := newBlake3Test()
	message := runar.ByteString(make([]byte, 32))
	c.VerifyHash(message)
}

func TestBlake3Test_Compile(t *testing.T) {
	if err := runar.CompileCheck("Blake3Test.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
