package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// R-107 — `multisig-2of3` is the canonical checkMultiSig + array-literal
// example. The two array arguments are the canonical site where the
// `array_literal` ANF node is emitted, and `array_literal` is one of the four
// node kinds `spec/ir-format.md` did not document until R-098.
//
// MultiSig2of3.runar.go carries //go:build ignore, so the contract type is not
// constructible from this test binary and this suite covers the Rúnar frontend
// (parse → validate → typecheck) only.
//
// The reason is written at the top of the contract file: the `[N]T{...}`
// composite literal that three of the seven .runar.go parsers require does not
// convert to the `[]Sig` / `[]PubKey` the mock CheckMultiSig takes. The slice
// spelling was tried here and reverted — it builds as Go and the Go tier emits
// identical ANF, but the TypeScript, Zig and Ruby parsers reject it. Native
// business-logic tests for the ordered-pair semantics are what this exclusion
// costs; they were written, they passed, and they are not reachable while the
// type cannot be constructed.

func TestMultiSig2of3_Compile(t *testing.T) {
	if err := runar.CompileCheck("MultiSig2of3.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
