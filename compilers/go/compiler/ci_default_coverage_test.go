package compiler

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDefaultGoTestRunsCLIIRTest is a regression test for F-313
// (CL-GAP-011): "integration_test.go is build-tag gated; the only
// CLI-level `--ir` test never runs in CI's default `go test ./...`".
//
// CI's go-compiler job (.github/workflows/ci.yml, "go-compiler" job) runs
// `cd compilers/go && go test -race -timeout 20m ./compiler` with NO
// `-tags integration`. The only `-tags integration` step in ci.yml targets
// `integration/go`, an entirely different directory/module path. So any
// test gated behind `//go:build integration` inside compilers/go/compiler
// is invisible to that CI step.
//
// This test shells out to `go test -run ^TestGoBinaryCompilation$ -v .`
// from this same package directory -- the exact invocation shape CI uses,
// minus `-race`/`-timeout` which don't affect test selection -- and fails
// if the CLI-level `--ir` test (TestGoBinaryCompilation) is not actually
// selected and run.
func TestDefaultGoTestRunsCLIIRTest(t *testing.T) {
	cmd := exec.Command("go", "test", "-run", "^TestGoBinaryCompilation$", "-v", ".")
	out, err := cmd.CombinedOutput()
	output := string(out)

	if strings.Contains(output, "no tests to run") {
		t.Fatalf("TestGoBinaryCompilation did not run under the default build context "+
			"(no -tags passed, matching CI's go-compiler job): %s\n(exec err: %v)", output, err)
	}
	if !strings.Contains(output, "TestGoBinaryCompilation") {
		t.Fatalf("expected TestGoBinaryCompilation to appear in `go test -v` output, got: %s\n(exec err: %v)", output, err)
	}
}

// What this test proves: the CLI-level --ir regression test is reachable
// from the same bare `go test <pattern> .` invocation CI's default
// go-compiler job uses (no build tags), so a future regression in the Go
// compiler binary's `--ir` flag will actually fail CI instead of being
// silently skipped because the test was never compiled in.
//
// What this test does NOT prove: that TestGoBinaryCompilation itself is
// correct, that the `--ir` CLI flag behaves correctly, or that CI's exact
// flags (-race, -timeout) don't change selection (they don't: -run is a
// name filter, independent of those flags).
