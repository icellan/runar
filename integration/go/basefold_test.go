//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/frontend"
)

// TestBasefoldVerifier_Compile verifies that the KoalaBear + Poseidon2 Merkle
// BasefoldVerifier contract compiles through the full Go compiler frontend:
//
//	parse -> validate -> typecheck -> ANF lowering
//
// Uses KoalaBear field ops (kbFieldAdd etc.), KoalaBear ext4 ops (kbExt4Mul),
// and Poseidon2 KoalaBear Merkle verification (merkleRootPoseidon2KB).
func TestBasefoldVerifier_Compile(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	contractPath := filepath.Join(filepath.Dir(thisFile), "contracts", "BasefoldVerifier.runar.go")

	source, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("reading contract source: %v", err)
	}

	// Step 1: Parse
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
	t.Logf("parsed contract: %s (%d methods, %d properties)",
		parseResult.Contract.Name,
		len(parseResult.Contract.Methods),
		len(parseResult.Contract.Properties))

	// Step 2: Validate
	validResult := frontend.Validate(parseResult.Contract)
	if len(validResult.Errors) > 0 {
		for _, e := range validResult.Errors {
			t.Logf("validation error: %s", e.FormatMessage())
		}
		t.Fatalf("validation failed with %d errors", len(validResult.Errors))
	}

	// Step 3: Type check
	tcResult := frontend.TypeCheck(parseResult.Contract)
	if len(tcResult.Errors) > 0 {
		for _, e := range tcResult.Errors {
			t.Logf("typecheck error: %s", e.FormatMessage())
		}
		t.Fatalf("type check failed with %d errors", len(tcResult.Errors))
	}

	// Step 4: ANF lowering
	program := frontend.LowerToANF(parseResult.Contract)
	if program == nil {
		t.Fatal("ANF lowering returned nil")
	}
	t.Logf("ANF program: %s — %d methods, %d properties",
		program.ContractName, len(program.Methods), len(program.Properties))

	// Verify expected structure
	if program.ContractName != "BasefoldVerifier" {
		t.Errorf("expected contract name BasefoldVerifier, got %s", program.ContractName)
	}
	if len(program.Methods) < 1 {
		t.Error("expected at least 1 method (Verify)")
	}
	foundVerify := false
	for _, m := range program.Methods {
		if m.Name == "verify" {
			foundVerify = true
			t.Logf("verify method: %d params, %d ANF bindings", len(m.Params), len(m.Body))
		}
	}
	if !foundVerify {
		t.Error("expected to find 'verify' method in ANF output")
	}

	// Verify the contract uses KoalaBear primitives (not BabyBear)
	sourceStr := string(source)
	if strings.Contains(sourceStr, "BbFieldAdd") || strings.Contains(sourceStr, "BbExt4Mul") {
		t.Error("contract should use KoalaBear (Kb*) ops, not BabyBear (Bb*)")
	}
	if !strings.Contains(sourceStr, "KbFieldAdd") {
		t.Error("contract should contain KbFieldAdd calls")
	}
	if !strings.Contains(sourceStr, "KbExt4Mul0") {
		t.Error("contract should contain KbExt4Mul0 calls")
	}
	if !strings.Contains(sourceStr, "MerkleRootPoseidon2KBv") {
		t.Error("contract should use Poseidon2 KoalaBear Merkle (MerkleRootPoseidon2KBv)")
	}
	if strings.Contains(sourceStr, "MerkleRootSha256") {
		t.Error("contract should NOT use SHA-256 Merkle (replaced by Poseidon2)")
	}
}
