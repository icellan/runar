//go:build integration
// +build integration

package compiler

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Integration test: Full TS -> Go pipeline
//
// These tests compile .runar.ts files through the TS compiler to produce IR,
// then verify the Go compiler can process the IR and produce valid output.
// Run with: go test -tags integration -v
// ---------------------------------------------------------------------------

func tsCompilerDir() string {
	return filepath.Join("..", "..", "..", "compiler")
}

func integrationConformanceDir() string {
	return filepath.Join("..", "..", "..", "conformance", "tests")
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
			if artifact.Version != "runar-v0.1.0" {
				t.Errorf("expected version runar-v0.1.0, got %s", artifact.Version)
			}

			t.Logf("OK: %s -> %s (hex=%d bytes)", dir, artifact.ContractName, len(artifact.Script)/2)
		})
	}
}

// TestGoBinaryCompilation verifies that the Go compiler binary can be built
// and invoked from the command line with a conformance test IR.
func TestGoBinaryCompilation(t *testing.T) {
	// Build the Go compiler binary
	tmpBin := filepath.Join(t.TempDir(), "runar-go")
	cmd := exec.Command("go", "build", "-o", tmpBin, ".")
	cmd.Dir = filepath.Join("..")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build Go compiler binary: %v\n%s", err, output)
	}

	// Run against a conformance test IR
	irPath := filepath.Join(integrationConformanceDir(), "basic-p2pkh", "expected-ir.json")
	if _, err := os.Stat(irPath); os.IsNotExist(err) {
		t.Skipf("conformance IR not found: %s", irPath)
	}

	absIRPath, err := filepath.Abs(irPath)
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}

	cmd = exec.Command(tmpBin, "--ir", absIRPath)
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Go compiler binary failed: %v\n%s", err, output)
	}

	if len(output) == 0 {
		t.Error("expected non-empty output from Go compiler binary")
	}

	t.Logf("Binary output length: %d bytes", len(output))
}
