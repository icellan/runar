//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/compiler"
	"github.com/icellan/runar/compilers/go/frontend"
)

// TestSp1FriVerifierPoc_Compile asserts that the Sp1FriVerifierPoc contract
// compiles cleanly through the Go compiler frontend:
//
//	parse → validate → typecheck → ANF lowering
//
// It does NOT assert that stack lowering or emit succeeds. The
// `runar.VerifySP1FRI` codegen body is deferred (see
// docs/sp1-fri-verifier.md §8); the Go compiler's stack-lowering
// dispatch panics on `verifySP1FRI` until the STARK verifier port lands.
//
// This test exists so BSVM's `AdvanceState` covenant can be authored
// against the `runar.VerifySP1FRI(proofBlob, publicValues, sp1VKeyHash)`
// ABI today — the frontend (parse/validate/typecheck/ANF) accepts the
// call and only the final codegen stage refuses.
func TestSp1FriVerifierPoc_Compile(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	contractPath := filepath.Join(filepath.Dir(thisFile), "contracts", "Sp1FriVerifierPoc.runar.go")

	source, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("reading contract source: %v", err)
	}

	parseResult := frontend.ParseSource(source, contractPath)
	if len(parseResult.Errors) > 0 {
		for _, e := range parseResult.Errors {
			t.Logf("parse error: %s", e.FormatMessage())
		}
		t.Fatalf("parse failed with %d errors", len(parseResult.Errors))
	}
	if parseResult.Contract == nil {
		t.Fatal("parse returned no contract")
	}

	validResult := frontend.Validate(parseResult.Contract)
	if len(validResult.Errors) > 0 {
		for _, e := range validResult.Errors {
			t.Logf("validation error: %s", e.FormatMessage())
		}
		t.Fatalf("validation failed with %d errors", len(validResult.Errors))
	}

	tcResult := frontend.TypeCheck(parseResult.Contract)
	if len(tcResult.Errors) > 0 {
		for _, e := range tcResult.Errors {
			t.Logf("typecheck error: %s", e.FormatMessage())
		}
		t.Fatalf("typecheck failed with %d errors — runar.VerifySP1FRI should be a known builtin with signature (ByteString, ByteString, ByteString) -> boolean",
			len(tcResult.Errors))
	}

	program := frontend.LowerToANF(parseResult.Contract)
	if program == nil {
		t.Fatal("ANF lowering returned nil")
	}
	if program.ContractName != "Sp1FriVerifierPoc" {
		t.Errorf("expected contract name Sp1FriVerifierPoc, got %s", program.ContractName)
	}

	foundVerify := false
	foundIntrinsicCall := false
	for _, m := range program.Methods {
		if m.Name != "verify" {
			continue
		}
		foundVerify = true
		for _, b := range m.Body {
			if b.Value.Kind == "call" && b.Value.Func == "verifySP1FRI" {
				foundIntrinsicCall = true
			}
		}
	}
	if !foundVerify {
		t.Error("expected 'verify' method in ANF output")
	}
	if !foundIntrinsicCall {
		t.Error("expected 'verifySP1FRI' call in the 'verify' method's ANF bindings")
	}
}

// TestSp1FriVerifierPoc_CodegenRefuses confirms the stack-lowering stub
// refuses to emit — this guards against silently shipping a no-op
// verifier. The error message links to docs/sp1-fri-verifier.md §8
// where the follow-up work is tracked.
func TestSp1FriVerifierPoc_CodegenRefuses(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	contractPath := filepath.Join(filepath.Dir(thisFile), "contracts", "Sp1FriVerifierPoc.runar.go")

	artifact, err := compiler.CompileFromSource(contractPath)
	if err == nil {
		t.Fatalf("expected compilation to fail at stack lowering because the verifySP1FRI codegen body is not implemented yet; got artifact %+v", artifact)
	}
	msg := err.Error()
	if !strings.Contains(msg, "verifySP1FRI") {
		t.Errorf("expected error message to mention 'verifySP1FRI'; got: %s", msg)
	}
	if !strings.Contains(msg, "docs/sp1-fri-verifier.md") {
		t.Errorf("expected error message to link to docs/sp1-fri-verifier.md; got: %s", msg)
	}
}
