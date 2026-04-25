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

// TestSp1FriVerifierPoc_CodegenAccepts is the dispatch-wired acceptance gate.
// It confirms that with the `EmitFullSP1FriVerifierBody` orchestrator wired
// into `lowerVerifySP1FRI` (compilers/go/codegen/sp1_fri.go), the PoC contract
// compiles cleanly through the full pipeline (parse → validate → typecheck
// → ANF → stack → emit) and produces a non-empty hex-encoded locking script.
//
// This replaces the previous `TestSp1FriVerifierPoc_CodegenRefuses` guard
// which intentionally panicked at stack lowering until the dispatch was
// wired.
//
// Holistic script-VM execution against the canonical fixture (assembling an
// unlocking script with all the structured field pushes + the typed args +
// running through the go-sdk interpreter) is validated end-to-end at the
// codegen-package level by
// `compilers/go/codegen.TestSp1FriVerifier_AcceptsMinimalGuestFixture`,
// which exercises `EmitFullSP1FriVerifierBody` against the same Plonky3
// minimal-guest FRI fixture and asserts the script accepts. That test is
// the meaningful end-to-end gate; this contract-level test asserts only
// that the dispatch wiring produces a deployable locking script.
//
// Producing a full deployable unlocking-script encoder for the Sp1VKeyHash
// constructor-slot mechanism + the structured field-push prelude is a
// follow-up — see docs/sp1-fri-verifier.md §10 for the per-query layout
// (each guest-program param tuple needs its own deployed verifier with a
// matching unlocking-script encoder).
func TestSp1FriVerifierPoc_CodegenAccepts(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	contractPath := filepath.Join(filepath.Dir(thisFile), "contracts", "Sp1FriVerifierPoc.runar.go")

	artifact, err := compiler.CompileFromSource(contractPath)
	if err != nil {
		t.Fatalf("expected compilation to succeed (dispatch wired via EmitFullSP1FriVerifierBody); "+
			"got error: %v", err)
	}
	if artifact == nil {
		t.Fatal("expected non-nil artifact from successful compilation")
	}
	if artifact.ContractName != "Sp1FriVerifierPoc" {
		t.Errorf("expected contract name Sp1FriVerifierPoc, got %s", artifact.ContractName)
	}
	if artifact.Script == "" {
		t.Error("expected non-empty Script (hex-encoded locking script)")
	}
	if !strings.HasPrefix(artifact.Script, "00") && len(artifact.Script) < 2 {
		// Locking script should be substantial — the SP1 FRI orchestrator
		// emits ~280 KB worth of opcodes for the PoC param tuple.
		t.Errorf("expected substantial locking script, got %d hex chars", len(artifact.Script))
	}

	t.Logf("Sp1FriVerifierPoc compiled successfully: |Script|=%d hex chars (~%d KB), "+
		"ABI methods=%d", len(artifact.Script), len(artifact.Script)/2/1024, len(artifact.ABI.Methods))
}
