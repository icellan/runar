package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestPostQuantumSLHDSANaiveInsecure192s_Compile(t *testing.T) {
	if err := runar.CompileCheck("PostQuantumSLHDSANaiveInsecure192s.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// The port is INSECURE by design -- it verifies a free signature over a free
// message, so any observed (msg, sig) pair replays. What it must NOT be is
// VACUOUS. runar.VerifySLHDSA_SHA2_192s is real FIPS 205 verification, not a
// stub like VerifySP1FRI, and this row is what tells the two apart: a verifier
// that returned true unconditionally would accept the garbage below, and every
// compile-only suite in this tree would still report green.
func TestPostQuantumSLHDSANaiveInsecure192s_RefusesGarbageSignature(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a garbage signature was ACCEPTED -- the PQ verifier is " +
				"not verifying anything")
		}
	}()
	c := &PostQuantumSLHDSANaiveInsecure192s{Pubkey: runar.ByteString(make([]byte, 32))}
	c.Spend(runar.ByteString("message"), runar.ByteString(make([]byte, 64)))
}
