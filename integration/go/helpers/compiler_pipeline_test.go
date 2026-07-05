//go:build integration

package helpers

import (
	"path/filepath"
	"testing"

	"github.com/icellan/runar/compilers/go/compiler"
)

// TS-BUG-001 regression.
//
// The integration compile helper hand-rolled the pipeline as
// LowerToANF → LowerToStack → OptimizeStackOps → Emit, skipping the ANF
// constant-fold and EC optimizer passes that the shipped Go compiler runs by
// default (fold-ON, see compilers/go/compiler/compiler.go CompileFromProgram).
// The Go regtest integration suite therefore validated bytes that no shipped
// Go compiler ever produces.
//
// This test pins the integration helper's deployed hex to the real compiler
// entry point (compiler.CompileFromSource, fold-ON) for a contract whose method
// body contains a foldable all-constant subexpression (`8n + 1n`, which folds
// to `9n`). Before the fix the two diverge — the integration path emits the
// unfolded push-push-OP_ADD sequence while the shipped compiler emits the
// folded constant. After the fix they are byte-identical.
func TestIntegrationPipeline_MatchesCompilerFoldedOutput(t *testing.T) {
	// StackTrackerReproV10min has no constructor args and no FixedArray
	// properties, so the ONLY pipeline difference between the integration
	// helper and compiler.CompileFromSource is the fold + EC passes.
	const src = "examples/ts/if-without-else-multi-temp/StackTrackerReproV10min.runar.ts"

	got, err := CompileContract(src, map[string]interface{}{})
	if err != nil {
		t.Fatalf("integration compile: %v", err)
	}

	absPath := filepath.Join(projectRoot(), src)
	want, err := compiler.CompileFromSource(absPath)
	if err != nil {
		t.Fatalf("shipped-compiler compile: %v", err)
	}

	if got.Script != want.Script {
		t.Fatalf("integration pipeline diverges from shipped compiler bytes (fold omitted):\n integration=%s\n compiler   =%s", got.Script, want.Script)
	}
}
