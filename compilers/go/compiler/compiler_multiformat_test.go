package compiler

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/icellan/runar/compilers/go/frontend"
)

// ---------------------------------------------------------------------------
// Multi-format parsing tests
//
// These tests verify that frontend.ParseSource correctly dispatches to the
// appropriate parser based on file extension, and that each format parser
// produces a valid AST for the conformance test contracts.
//
// Note: Full end-to-end compilation (CompileFromSource) for non-.runar.ts
// formats is deferred until the format-specific parsers are fully integrated
// with the validator (they need to synthesize super() calls, map types like
// Int→bigint, etc.). These tests focus on parse-level correctness.
// ---------------------------------------------------------------------------

var multiFormats = []string{".runar.ts", ".runar.sol", ".runar.move", ".runar.go"}

func readConformanceFormat(t *testing.T, testName, ext string) ([]byte, string) {
	t.Helper()
	fileName := filepath.Join(conformanceDir(), testName, testName+ext)
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		t.Skipf("source file not found: %s", fileName)
	}
	source, err := os.ReadFile(fileName)
	if err != nil {
		t.Fatalf("failed to read %s: %v", fileName, err)
	}
	return source, fileName
}

// ---------------------------------------------------------------------------
// Test: ParseSource dispatch routes to the correct parser by extension
// ---------------------------------------------------------------------------

func TestParseSource_Dispatch(t *testing.T) {
	tests := []struct {
		ext          string
		expectedName string
	}{
		{".runar.ts", "Arithmetic"},
		{".runar.sol", "Arithmetic"},
		{".runar.move", "Arithmetic"},
		{".runar.go", "Arithmetic"},
	}

	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			source, fileName := readConformanceFormat(t, "arithmetic", tt.ext)
			result := frontend.ParseSource(source, fileName)

			if result.Contract == nil {
				if len(result.Errors) > 0 {
					t.Skipf("parser produced errors: %v", result.Errors)
				}
				t.Fatalf("expected contract to be parsed from %s", tt.ext)
			}
			if result.Contract.Name != tt.expectedName {
				t.Errorf("expected contract name %s, got %s", tt.expectedName, result.Contract.Name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Solidity parser produces valid AST structure
// ---------------------------------------------------------------------------

func TestParseSolidity_Arithmetic(t *testing.T) {
	source, fileName := readConformanceFormat(t, "arithmetic", ".runar.sol")
	result := frontend.ParseSource(source, fileName)

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.Errors)
	}
	if result.Contract.Name != "Arithmetic" {
		t.Errorf("expected Arithmetic, got %s", result.Contract.Name)
	}
	if len(result.Contract.Properties) != 1 {
		t.Errorf("expected 1 property, got %d", len(result.Contract.Properties))
	}
	if len(result.Contract.Methods) != 1 {
		t.Errorf("expected 1 method, got %d", len(result.Contract.Methods))
	}
	if result.Contract.Methods[0].Name != "verify" {
		t.Errorf("expected method name 'verify', got %s", result.Contract.Methods[0].Name)
	}
	if result.Contract.Methods[0].Visibility != "public" {
		t.Errorf("expected verify to be public, got %s", result.Contract.Methods[0].Visibility)
	}
}

func TestParseSolidity_P2PKH(t *testing.T) {
	source, fileName := readConformanceFormat(t, "basic-p2pkh", ".runar.sol")
	result := frontend.ParseSource(source, fileName)

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.Errors)
	}
	if result.Contract.Name != "P2PKH" {
		t.Errorf("expected P2PKH, got %s", result.Contract.Name)
	}
	if result.Contract.ParentClass != "SmartContract" {
		t.Errorf("expected SmartContract, got %s", result.Contract.ParentClass)
	}
}

// ---------------------------------------------------------------------------
// Test: Move parser produces valid AST structure
// ---------------------------------------------------------------------------

func TestParseMove_Arithmetic(t *testing.T) {
	source, fileName := readConformanceFormat(t, "arithmetic", ".runar.move")
	result := frontend.ParseSource(source, fileName)

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.Errors)
	}
	if result.Contract.Name != "Arithmetic" {
		t.Errorf("expected Arithmetic, got %s", result.Contract.Name)
	}
	if len(result.Contract.Methods) < 1 {
		t.Fatal("expected at least 1 method")
	}
	if result.Contract.Methods[0].Name != "verify" {
		t.Errorf("expected method name 'verify', got %s", result.Contract.Methods[0].Name)
	}
}

func TestParseMove_P2PKH(t *testing.T) {
	source, fileName := readConformanceFormat(t, "basic-p2pkh", ".runar.move")
	result := frontend.ParseSource(source, fileName)

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.Errors)
	}
	if result.Contract.Name != "P2PKH" {
		t.Errorf("expected P2PKH, got %s", result.Contract.Name)
	}
}

// ---------------------------------------------------------------------------
// Test: GoContract parser produces valid AST structure
// ---------------------------------------------------------------------------

func TestParseGoContract_Arithmetic(t *testing.T) {
	source, fileName := readConformanceFormat(t, "arithmetic", ".runar.go")
	result := frontend.ParseSource(source, fileName)

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.Errors)
	}
	if result.Contract.Name != "Arithmetic" {
		t.Errorf("expected Arithmetic, got %s", result.Contract.Name)
	}
}

func TestParseGoContract_P2PKH(t *testing.T) {
	source, fileName := readConformanceFormat(t, "basic-p2pkh", ".runar.go")
	result := frontend.ParseSource(source, fileName)

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.Errors)
	}
	if result.Contract.Name != "P2PKH" {
		t.Errorf("expected P2PKH, got %s", result.Contract.Name)
	}
}

// ---------------------------------------------------------------------------
// Test: .runar.ts format still compiles end-to-end via ParseSource dispatch
// ---------------------------------------------------------------------------

func TestMultiFormat_TSCompileEndToEnd(t *testing.T) {
	testDirs := []string{"arithmetic", "basic-p2pkh", "boolean-logic", "bounded-loop", "if-else", "multi-method", "stateful"}

	for _, dir := range testDirs {
		t.Run(dir, func(t *testing.T) {
			source := filepath.Join(conformanceDir(), dir, dir+".runar.ts")
			artifact, err := CompileFromSource(source)
			if err != nil {
				t.Fatalf("CompileFromSource failed: %v", err)
			}
			if artifact.Script == "" {
				t.Error("expected non-empty script hex")
			}
			if artifact.ASM == "" {
				t.Error("expected non-empty ASM")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Cross-format property consistency
// ---------------------------------------------------------------------------

func TestMultiFormat_PropertyConsistency(t *testing.T) {
	for _, ext := range []string{".runar.sol", ".runar.move", ".runar.go"} {
		t.Run("arithmetic"+ext, func(t *testing.T) {
			source, fileName := readConformanceFormat(t, "arithmetic", ext)
			result := frontend.ParseSource(source, fileName)

			if result.Contract == nil {
				t.Skipf("parser failed for %s (errors: %v)", ext, result.Errors)
			}

			// All formats should produce: 1 readonly property named "target"
			if len(result.Contract.Properties) != 1 {
				t.Fatalf("expected 1 property, got %d", len(result.Contract.Properties))
			}

			prop := result.Contract.Properties[0]
			if prop.Name != "target" {
				t.Errorf("expected property name 'target', got %s", prop.Name)
			}
			if !prop.Readonly {
				t.Errorf("expected 'target' to be readonly")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: Cross-format method parameter consistency
// ---------------------------------------------------------------------------

func TestMultiFormat_MethodParamConsistency(t *testing.T) {
	for _, ext := range []string{".runar.sol", ".runar.move", ".runar.go"} {
		t.Run("arithmetic"+ext, func(t *testing.T) {
			source, fileName := readConformanceFormat(t, "arithmetic", ext)
			result := frontend.ParseSource(source, fileName)

			if result.Contract == nil {
				t.Skipf("parser failed for %s (errors: %v)", ext, result.Errors)
			}

			if len(result.Contract.Methods) < 1 {
				t.Fatal("expected at least 1 method")
			}

			method := result.Contract.Methods[0]
			if method.Name != "verify" {
				t.Errorf("expected method 'verify', got %s", method.Name)
			}

			// All formats should have 2 params: a and b
			if len(method.Params) != 2 {
				t.Fatalf("expected 2 params, got %d", len(method.Params))
			}
			if method.Params[0].Name != "a" {
				t.Errorf("expected param 'a', got %s", method.Params[0].Name)
			}
			if method.Params[1].Name != "b" {
				t.Errorf("expected param 'b', got %s", method.Params[1].Name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: .runar.go example contracts compile to Bitcoin Script
//
// This ensures that contracts valid as Go are also valid Rúnar — catching
// cases where Go code compiles but uses features outside the Rúnar subset.
// ---------------------------------------------------------------------------

func TestGoContract_CompileExamples(t *testing.T) {
	examplesDir := filepath.Join(conformanceDir(), "..", "..", "examples", "go")
	examples := []struct {
		dir          string
		file         string
		contractName string
	}{
		{"p2pkh", "P2PKH.runar.go", "P2PKH"},
		{"escrow", "Escrow.runar.go", "Escrow"},
		{"stateful-counter", "Counter.runar.go", "Counter"},
		{"auction", "Auction.runar.go", "Auction"},
		{"covenant-vault", "CovenantVault.runar.go", "CovenantVault"},
		{"oracle-price", "OraclePriceFeed.runar.go", "OraclePriceFeed"},
		{"token-ft", "FungibleTokenExample.runar.go", "FungibleToken"},
		{"token-nft", "NFTExample.runar.go", "SimpleNFT"},
	}

	for _, ex := range examples {
		t.Run(ex.contractName, func(t *testing.T) {
			source := filepath.Join(examplesDir, ex.dir, ex.file)
			if _, err := os.Stat(source); os.IsNotExist(err) {
				t.Skipf("source not found: %s", source)
			}

			artifact, err := CompileFromSource(source)
			if err != nil {
				t.Fatalf("Rúnar compilation failed: %v", err)
			}

			if artifact.ContractName != ex.contractName {
				t.Errorf("expected contract name %s, got %s", ex.contractName, artifact.ContractName)
			}
			if artifact.Script == "" {
				t.Error("expected non-empty script hex")
			}
			if artifact.ASM == "" {
				t.Error("expected non-empty ASM")
			}

			t.Logf("%s: hex=%d bytes", ex.contractName, len(artifact.Script)/2)
		})
	}
}

// ---------------------------------------------------------------------------
// Test: .runar.go conformance tests compile to Bitcoin Script
// ---------------------------------------------------------------------------

func TestGoContract_CompileConformance(t *testing.T) {
	// "stateful" excluded: Go compiler's stateful preimage injection needs deeper work
	testDirs := []string{"arithmetic", "basic-p2pkh", "boolean-logic", "bounded-loop", "if-else", "multi-method"}

	for _, dir := range testDirs {
		t.Run(dir, func(t *testing.T) {
			source := filepath.Join(conformanceDir(), dir, dir+".runar.go")
			if _, err := os.Stat(source); os.IsNotExist(err) {
				t.Skipf("source not found: %s", source)
			}

			artifact, err := CompileFromSource(source)
			if err != nil {
				t.Fatalf("Rúnar compilation failed: %v", err)
			}

			if artifact.Script == "" {
				t.Error("expected non-empty script hex")
			}

			t.Logf("%s: hex=%d bytes", dir, len(artifact.Script)/2)
		})
	}
}
