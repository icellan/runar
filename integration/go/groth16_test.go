//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/icellan/runar/compilers/go/codegen"
	"github.com/icellan/runar/compilers/go/frontend"
)

// ---------------------------------------------------------------------------
// Groth16 Verifier — Frontend Compilation Test
//
// Verifies that the Groth16Verifier.runar.go contract compiles through the
// full Runar frontend pipeline: parse -> validate -> typecheck.
//
// This test does NOT deploy or spend on-chain because the BN254
// multi-pairing codegen produces very large scripts (~50-100 KB) that
// require special transaction handling on regtest. The frontend pipeline
// (parse -> validate -> typecheck -> ANF) is fully verified here.
// ---------------------------------------------------------------------------

func groth16ContractPath() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "contracts", "Groth16Verifier.runar.go")
}

// TestGroth16Verifier_Parse verifies the contract parses without errors.
func TestGroth16Verifier_Parse(t *testing.T) {
	source, err := os.ReadFile(groth16ContractPath())
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}

	result := frontend.ParseSource(source, "Groth16Verifier.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	if result.Contract == nil {
		t.Fatal("no contract found")
	}

	if result.Contract.Name != "Groth16Verifier" {
		t.Errorf("expected contract name Groth16Verifier, got %s", result.Contract.Name)
	}

	// 15 readonly properties: AlphaG1, BetaNegG2{X0,X1,Y0,Y1},
	// GammaNegG2{...}, DeltaNegG2{...}, IC0, IC1
	if len(result.Contract.Properties) != 15 {
		t.Errorf("expected 15 properties, got %d", len(result.Contract.Properties))
	}

	// All properties must be readonly (stateless contract)
	for _, p := range result.Contract.Properties {
		if !p.Readonly {
			t.Errorf("property %s should be readonly", p.Name)
		}
	}

	// One public method: Verify
	if len(result.Contract.Methods) != 1 {
		t.Errorf("expected 1 method, got %d", len(result.Contract.Methods))
	}
	if result.Contract.Methods[0].Name != "verify" {
		t.Errorf("expected method name 'verify', got '%s'", result.Contract.Methods[0].Name)
	}

	// Verify method has 7 parameters: proofA, proofBX0..Y1, proofC, publicInput
	if len(result.Contract.Methods[0].Params) != 7 {
		t.Errorf("expected 7 params, got %d", len(result.Contract.Methods[0].Params))
	}

	t.Logf("Parse OK: %s — %d properties, %d methods, %d params",
		result.Contract.Name,
		len(result.Contract.Properties),
		len(result.Contract.Methods),
		len(result.Contract.Methods[0].Params))
}

// TestGroth16Verifier_Validate verifies the contract passes validation.
func TestGroth16Verifier_Validate(t *testing.T) {
	source, err := os.ReadFile(groth16ContractPath())
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}

	result := frontend.ParseSource(source, "Groth16Verifier.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}

	v := frontend.Validate(result.Contract)
	if len(v.Errors) > 0 {
		t.Fatalf("validation errors: %s", strings.Join(v.ErrorStrings(), "; "))
	}

	t.Log("Validate OK")
}

// TestGroth16Verifier_TypeCheck verifies the contract passes type checking.
func TestGroth16Verifier_TypeCheck(t *testing.T) {
	source, err := os.ReadFile(groth16ContractPath())
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}

	result := frontend.ParseSource(source, "Groth16Verifier.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}

	v := frontend.Validate(result.Contract)
	if len(v.Errors) > 0 {
		t.Fatalf("validation errors: %s", strings.Join(v.ErrorStrings(), "; "))
	}

	tc := frontend.TypeCheck(result.Contract)
	if len(tc.Errors) > 0 {
		t.Fatalf("type check errors: %s", strings.Join(tc.ErrorStrings(), "; "))
	}

	t.Log("TypeCheck OK")
}

// TestGroth16Verifier_ANFLower verifies the contract lowers to ANF IR.
func TestGroth16Verifier_ANFLower(t *testing.T) {
	source, err := os.ReadFile(groth16ContractPath())
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}

	result := frontend.ParseSource(source, "Groth16Verifier.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}

	program := frontend.LowerToANF(result.Contract)
	if program == nil {
		t.Fatal("ANF lowering returned nil")
	}

	if program.ContractName != "Groth16Verifier" {
		t.Errorf("expected ANF contract name Groth16Verifier, got %s", program.ContractName)
	}

	// ANF may include the auto-generated constructor method alongside verify.
	// Stateless SmartContract classes produce a constructor + public methods.
	if len(program.Methods) < 1 {
		t.Errorf("expected at least 1 ANF method, got %d", len(program.Methods))
	}

	// Find the verify method and check it has bindings
	foundVerify := false
	for _, m := range program.Methods {
		if m.Name == "verify" {
			foundVerify = true
			if len(m.Body) == 0 {
				t.Error("expected non-empty ANF body for verify method")
			}
		}
	}
	if !foundVerify {
		t.Error("expected to find 'verify' method in ANF output")
	}

	t.Logf("ANF OK: %d properties, %d methods, %d bindings in verify",
		len(program.Properties),
		len(program.Methods),
		len(program.Methods[0].Body))
}

// TestGroth16Verifier_FullPipeline exercises the FULL compilation pipeline:
// parse -> validate -> typecheck -> ANF -> stack lowering -> peephole optimize -> emit.
// This produces a hex-encoded Bitcoin Script and measures its size.
// No regtest node is required.
func TestGroth16Verifier_FullPipeline(t *testing.T) {
	source, err := os.ReadFile(groth16ContractPath())
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}

	// --- Parse ---
	parseStart := time.Now()
	result := frontend.ParseSource(source, "Groth16Verifier.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	if result.Contract == nil {
		t.Fatal("no contract found")
	}
	parseDur := time.Since(parseStart)

	// --- Validate ---
	valStart := time.Now()
	v := frontend.Validate(result.Contract)
	if len(v.Errors) > 0 {
		t.Fatalf("validation errors: %s", strings.Join(v.ErrorStrings(), "; "))
	}
	valDur := time.Since(valStart)

	// --- TypeCheck ---
	tcStart := time.Now()
	tc := frontend.TypeCheck(result.Contract)
	if len(tc.Errors) > 0 {
		t.Fatalf("type check errors: %s", strings.Join(tc.ErrorStrings(), "; "))
	}
	tcDur := time.Since(tcStart)

	// --- ANF Lower ---
	anfStart := time.Now()
	program := frontend.LowerToANF(result.Contract)
	if program == nil {
		t.Fatal("ANF lowering returned nil")
	}
	anfDur := time.Since(anfStart)

	// --- Stack Lower ---
	stackStart := time.Now()
	stackMethods, err := codegen.LowerToStack(program)
	if err != nil {
		t.Fatalf("stack lowering failed: %v", err)
	}
	stackDur := time.Since(stackStart)

	if len(stackMethods) == 0 {
		t.Fatal("stack lowering produced no methods")
	}

	// --- Peephole Optimize ---
	optStart := time.Now()
	for i := range stackMethods {
		stackMethods[i].Ops = codegen.OptimizeStackOps(stackMethods[i].Ops)
	}
	optDur := time.Since(optStart)

	// Count total stack ops across all methods
	totalOps := 0
	for _, m := range stackMethods {
		totalOps += len(m.Ops)
	}

	// --- Emit ---
	emitStart := time.Now()
	emitResult, err := codegen.Emit(stackMethods)
	if err != nil {
		t.Fatalf("emit failed: %v", err)
	}
	emitDur := time.Since(emitStart)

	// --- Verify output ---
	if emitResult.ScriptHex == "" {
		t.Fatal("emit produced empty script hex")
	}
	if emitResult.ScriptAsm == "" {
		t.Fatal("emit produced empty script ASM")
	}

	scriptBytes := len(emitResult.ScriptHex) / 2
	scriptKB := float64(scriptBytes) / 1024.0

	t.Logf("Full pipeline OK for Groth16Verifier")
	t.Logf("  Parse:       %v", parseDur)
	t.Logf("  Validate:    %v", valDur)
	t.Logf("  TypeCheck:   %v", tcDur)
	t.Logf("  ANF Lower:   %v", anfDur)
	t.Logf("  Stack Lower: %v", stackDur)
	t.Logf("  Optimize:    %v", optDur)
	t.Logf("  Emit:        %v", emitDur)
	t.Logf("  Total:       %v", parseDur+valDur+tcDur+anfDur+stackDur+optDur+emitDur)
	t.Logf("  Stack ops:   %d (across %d methods)", totalOps, len(stackMethods))
	t.Logf("  Script size: %d bytes (%.1f KB)", scriptBytes, scriptKB)
	t.Logf("  Constructor slots: %d", len(emitResult.ConstructorSlots))

	// Sanity checks: the Groth16 verifier with BN254 multi-pairing should
	// produce a substantial script (comment in contract says ~50-100 KB).
	if scriptBytes < 1000 {
		t.Errorf("script suspiciously small: %d bytes — expected a large script for BN254 Groth16 verifier", scriptBytes)
	}
}
