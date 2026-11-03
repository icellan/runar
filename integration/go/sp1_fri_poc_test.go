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

// TestSp1FriVerifierPoc_Compile is the granular frontend-stage gate. It
// asserts that the Sp1FriVerifierPoc contract advances cleanly through each
// of the Go compiler's frontend passes:
//
//	parse → validate → typecheck → ANF lowering
//
// and inspects the resulting ANF program to confirm the `verifySP1FRI`
// intrinsic call is present in the `verify` method's bindings.
//
// This test deliberately stops at ANF so frontend-only regressions surface
// with a focused error message (parse / validate / typecheck / ANF).
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

	// F-007: rewritten to expect refusal — Validate refuses verifySP1FRI in v1 (not implemented); the later frontend
	// stages are still checked so the builtin's typing and ANF shape stay pinned.
	validResult := frontend.Validate(parseResult.Contract)
	refused := false
	for _, e := range validResult.Errors {
		if strings.Contains(e.Message, "not implemented for v1") {
			refused = true
		}
	}
	if !refused {
		t.Fatalf("F-007: Validate must refuse verifySP1FRI; got %d errors: %v",
			len(validResult.Errors), validResult.ErrorStrings())
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

// Was TestSp1FriVerifierPoc_CodegenAccepts (the contract compiled to a
// deployable locking script).
// F-007: rewritten to expect refusal — the SP1 FRI verifier is not implemented for v1; its body is fail-closed and
// the compiler refuses verifySP1FRI, so there is no artifact.
func TestSp1FriVerifierPoc_CompileRefused(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	contractPath := filepath.Join(filepath.Dir(thisFile), "contracts", "Sp1FriVerifierPoc.runar.go")

	artifact, err := compiler.CompileFromSource(contractPath)
	if err == nil {
		t.Fatalf("F-007: Sp1FriVerifierPoc compiled (|Script|=%d hex chars); v1 must refuse verifySP1FRI",
			len(artifact.Script))
	}
	if !strings.Contains(err.Error(), "not implemented for v1") {
		t.Fatalf("F-007: unexpected refusal text: %v", err)
	}
	t.Logf("Sp1FriVerifierPoc refused as required: %v", err)
}
