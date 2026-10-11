//go:build integration
// +build integration

package compiler

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Integration test: Full TS -> Go pipeline
//
// These tests compile .runar.ts files through the TS compiler to produce IR,
// then verify the Go compiler can process the IR and produce valid output.
// Run with: go test -tags integration -v
//
// TestGoBinaryCompilation (the CLI-level `--ir` test, F-313) lives in
// cli_ir_test.go instead, with no build tag: CI's default go-compiler job
// runs `go test ./compiler` without `-tags integration`, so a test gated
// here would never execute there.
// ---------------------------------------------------------------------------

func tsCompilerDir() string {
	return filepath.Join("..", "..", "..", "compiler")
}

// TestTStoGoIntegration compiles conformance test expected-ir.json files
// through the Go compiler and verifies they produce valid Bitcoin Script.
func TestTStoGoIntegration(t *testing.T) {
	testDirs := []string{
		"arithmetic",
		"basic-p2pkh",
		"boolean-logic",
		"bounded-loop",
		"if-else",
		"multi-method",
		"stateful",
	}

	for _, dir := range testDirs {
		t.Run(dir, func(t *testing.T) {
			irPath := filepath.Join(integrationConformanceDir(), dir, "expected-ir.json")

			// Verify the IR file exists
			if _, err := os.Stat(irPath); os.IsNotExist(err) {
				t.Skipf("conformance IR not found: %s", irPath)
			}

			// Read the IR and compile with the Go compiler
			irData, err := os.ReadFile(irPath)
			if err != nil {
				t.Fatalf("failed to read IR file: %v", err)
			}

			artifact, err := CompileFromIRBytes(irData)
			if err != nil {
				t.Fatalf("Go compilation failed for %s: %v", dir, err)
			}

			if artifact.Script == "" {
				t.Errorf("expected non-empty script hex for %s", dir)
			}
			if artifact.ASM == "" {
				t.Errorf("expected non-empty ASM for %s", dir)
			}
			if artifact.ContractName == "" {
				t.Errorf("expected non-empty contractName for %s", dir)
			}
			if artifact.Version != "runar-v1.0.0-rc.1" {
				t.Errorf("expected version runar-v1.0.0-rc.1, got %s", artifact.Version)
			}

			t.Logf("OK: %s -> %s (hex=%d bytes)", dir, artifact.ContractName, len(artifact.Script)/2)
		})
	}
}
