package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// Simulated referenced output layout:
// 16 bytes prefix + 32 bytes state root + 8 bytes suffix
var (
	prefix    = runar.ByteString([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00})
	stateRoot = runar.ByteString([]byte{
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
	})
	suffix          = runar.ByteString([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	referencedOutput = prefix + stateRoot + suffix
	outputHash       = runar.Hash256(referencedOutput)
)

// ---------------------------------------------------------------------------
// verifyAndExtract
// ---------------------------------------------------------------------------

func TestCrossCovenantRef_VerifyAndExtract(t *testing.T) {
	c := &CrossCovenantRef{SourceScriptHash: outputHash}
	c.VerifyAndExtract(referencedOutput, stateRoot, 16)
}

func TestCrossCovenantRef_VerifyAndExtract_TamperedOutput(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for tampered output")
		}
	}()

	c := &CrossCovenantRef{SourceScriptHash: outputHash}
	tampered := runar.ByteString([]byte{0xff}) + referencedOutput[1:]
	c.VerifyAndExtract(tampered, stateRoot, 16)
}

func TestCrossCovenantRef_VerifyAndExtract_WrongRoot(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong state root")
		}
	}()

	c := &CrossCovenantRef{SourceScriptHash: outputHash}
	wrongRoot := runar.ByteString(make([]byte, 32))
	c.VerifyAndExtract(referencedOutput, wrongRoot, 16)
}

// ---------------------------------------------------------------------------
// verifyAndExtractNumeric
// ---------------------------------------------------------------------------

func TestCrossCovenantRef_VerifyAndExtractNumeric(t *testing.T) {
	// Build an output with a numeric value embedded at offset 16
	numPrefix := runar.ByteString(make([]byte, 16))
	// Embed the value 42 as a 4-byte LE signed-magnitude value
	numValue := runar.Num2Bin(42, 4)
	numSuffix := runar.ByteString(make([]byte, 8))
	numOutput := numPrefix + numValue + numSuffix
	numHash := runar.Hash256(numOutput)

	c := &CrossCovenantRef{SourceScriptHash: numHash}
	c.VerifyAndExtractNumeric(numOutput, 42, 16, 4)
}

// ---------------------------------------------------------------------------
// Compile check
// ---------------------------------------------------------------------------

func TestCrossCovenantRef_Compile(t *testing.T) {
	if err := runar.CompileCheck("CrossCovenantRef.runar.go"); err != nil {
		t.Fatalf("Runar compile check failed: %v", err)
	}
}
