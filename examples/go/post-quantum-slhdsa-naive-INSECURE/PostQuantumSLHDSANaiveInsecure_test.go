package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// PostQuantumSLHDSANaiveInsecure.runar.go is a pedagogical artifact that shows
// the broken pattern of verifying a free post-quantum signature against a free
// message — anyone observing one valid spend can reuse the (msg, sig) pair (or
// substitute any other pair they hold) and the script still verifies. The
// correct hybrid pattern lives in examples/go/sphincs-wallet.
//
// Insecure is not the same as vacuous. The port used to carry `//go:build
// ignore` and this suite could only run the Rúnar frontend; the tag was there
// because the file imported the module path `"runar"`, which resolves to
// nothing. With the import corrected the contract builds as Go, and the row
// below is what separates real FIPS 205 verification from a stub.

func TestPostQuantumSLHDSANaiveInsecure_Compile(t *testing.T) {
	if err := runar.CompileCheck("PostQuantumSLHDSANaiveInsecure.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

func TestPostQuantumSLHDSANaiveInsecure_RefusesGarbageSignature(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a garbage signature was ACCEPTED — the SLH-DSA verifier " +
				"is not verifying anything")
		}
	}()
	c := &PostQuantumSLHDSANaiveInsecure{Pubkey: runar.ByteString(make([]byte, 32))}
	c.Spend(runar.ByteString("message"), runar.ByteString(make([]byte, 64)))
}
