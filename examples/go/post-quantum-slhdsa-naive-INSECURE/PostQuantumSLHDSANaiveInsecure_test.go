package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// PostQuantumSLHDSANaiveInsecure.runar.go is a pedagogical artifact that
// shows the broken pattern of verifying a free post-quantum signature
// against a free message — anyone observing one valid spend can reuse the
// (msg, sig) pair (or substitute any other (msg, sig) they have) and the
// script still verifies. The contract uses //go:build ignore so the source
// is a parser-only fixture; this suite covers the Rúnar frontend (parse →
// validate → typecheck) only. The correct hybrid pattern lives in
// examples/go/sphincs-wallet.

func TestPostQuantumSLHDSANaiveInsecure_Compile(t *testing.T) {
	if err := runar.CompileCheck("PostQuantumSLHDSANaiveInsecure.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
