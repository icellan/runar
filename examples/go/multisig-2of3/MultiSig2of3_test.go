package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// R-107 — `multisig-2of3` is the canonical checkMultiSig + array-literal
// example and was tested in four of the nine formats: ts, sol, move and zig.
// Go, Rust, Python, Ruby and Java ran it nowhere.
//
// It matters more than most: the two array arguments are the canonical site
// where the `array_literal` ANF node is emitted, and `array_literal` is one of
// the four node kinds `spec/ir-format.md` did not document until R-098.
//
// MultiSig2of3.runar.go carries //go:build ignore, so the contract type is not
// constructible from this test binary — the same situation as the peer
// bounded-loop suite. What IS available, and is the cross-compiler boundary
// that matters, is the Rúnar frontend.

func TestMultiSig2of3_Compile(t *testing.T) {
	if err := runar.CompileCheck("MultiSig2of3.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
