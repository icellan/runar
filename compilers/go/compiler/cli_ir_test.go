package compiler

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// integrationConformanceDir is also used by TestTStoGoIntegration in
// integration_test.go (build-tag gated). It lives here, untagged, because
// TestGoBinaryCompilation below must run without `-tags integration`.
func integrationConformanceDir() string {
	return filepath.Join("..", "..", "..", "conformance", "tests")
}

// TestGoBinaryCompilation verifies that the Go compiler binary can be built
// and invoked from the command line with a conformance test IR.
//
// This is the CLI-level `--ir` regression test for F-313 (CL-GAP-011):
// previously it lived in integration_test.go behind `//go:build integration`,
// so CI's go-compiler job -- which runs `go test -race -timeout 20m
// ./compiler` with no `-tags` -- never compiled or ran it; the only
// `-tags integration` CI step targets the unrelated `integration/go`
// directory. It has no such tag so the default `go test ./...` (and CI's
// go-compiler job) exercises it.
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
	requireFixtureFile(t, irPath)

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
