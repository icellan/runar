package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// HashRegistry.runar.go carries //go:build ignore, so the contract type is not
// constructible from this test binary and this suite covers the Rúnar frontend
// (parse → validate → typecheck) only.
//
// The reason is written at the top of HashRegistry.runar.go: `CurrentHash
// runar.Ripemd160` needs `Ripemd160` in TYPE position, and packages/runar-go
// binds that name to the hash FUNCTION because the type spelling would fail
// open. It is not, as this note used to say, about the import path — 24 other
// ports were excluded for exactly that reason and build fine now.

func TestHashRegistry_Compile(t *testing.T) {
	if err := runar.CompileCheck("HashRegistry.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
