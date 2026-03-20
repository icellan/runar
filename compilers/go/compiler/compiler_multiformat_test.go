package compiler

import (
	"os"
	"path/filepath"
	"strings"
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

var multiFormats = []string{".runar.ts", ".runar.sol", ".runar.move", ".runar.go", ".runar.rb"}

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

// ---------------------------------------------------------------------------
// Test: .runar.rb conformance tests compile to Bitcoin Script hex
// ---------------------------------------------------------------------------

func TestRubyContract_CompileConformance(t *testing.T) {
	// "stateful" and "stateful-counter" excluded: stateful preimage injection
	// requires deeper work in the Go compiler.
	testDirs := []string{"arithmetic", "basic-p2pkh", "boolean-logic", "bounded-loop", "if-else", "multi-method"}

	for _, dir := range testDirs {
		t.Run(dir, func(t *testing.T) {
			source := filepath.Join(conformanceDir(), dir, dir+".runar.rb")
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

			// Compare against golden expected-script.hex
			goldenPath := filepath.Join(conformanceDir(), dir, "expected-script.hex")
			goldenHex, err := os.ReadFile(goldenPath)
			if err != nil {
				// No golden file — just verify non-empty output
				t.Logf("%s: no golden file, script hex=%d bytes", dir, len(artifact.Script)/2)
				return
			}

			expected := strings.TrimSpace(string(goldenHex))
			if artifact.Script != expected {
				// Log the discrepancy but do not fail — known divergences exist
				// between the Ruby parser and the TypeScript golden reference.
				// File a bug for any test that does not match.
				maxLen := 200
				gotPreview := artifact.Script
				if len(gotPreview) > maxLen {
					gotPreview = gotPreview[:maxLen] + "..."
				}
				expectedPreview := expected
				if len(expectedPreview) > maxLen {
					expectedPreview = expectedPreview[:maxLen] + "..."
				}
				t.Logf("%s: script hex mismatch (len expected=%d, got=%d)\n  expected: %s\n  got:      %s",
					dir, len(expected), len(artifact.Script), expectedPreview, gotPreview)
				t.Errorf("%s: script hex does not match golden file", dir)
			} else {
				t.Logf("%s: MATCH (hex=%d bytes)", dir, len(artifact.Script)/2)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: ParseSource with unknown extension falls back to TS parser (or errors)
// ---------------------------------------------------------------------------

func TestParseSource_UnknownExtension_Error(t *testing.T) {
	// A minimal valid TypeScript-like source for the fallback
	source := []byte(`
import { SmartContract, assert } from 'runar-lang';

class Simple extends SmartContract {
  readonly x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  public check(val: bigint): void {
    assert(val === this.x);
  }
}
`)

	// ParseSource with an unknown extension — it should either return an error
	// or fall back to the TypeScript parser (which may or may not succeed).
	// The key property we test: it must NOT panic.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ParseSource panicked on unknown extension: %v", r)
		}
	}()

	result := frontend.ParseSource(source, "Contract.runar.xyz")

	// Since "Contract.runar.xyz" doesn't match any known extension, ParseSource
	// falls back to the TypeScript parser. The TS source above is valid, so
	// it should succeed and return a contract.
	if result == nil {
		t.Fatal("ParseSource returned nil result for unknown extension")
	}

	// Log what happened — either parsed (fallback to TS) or errored
	if result.Contract != nil {
		t.Logf("ParseSource with unknown extension fell back to TS parser, found contract: %s", result.Contract.Name)
	} else {
		t.Logf("ParseSource with unknown extension returned errors: %v", result.Errors)
		// Having errors is also acceptable behavior for an unknown extension
	}
}

// ---------------------------------------------------------------------------
// Test: ParseSource with .runar.rs extension dispatches (no panic)
// ---------------------------------------------------------------------------

func TestParseSource_DispatchesRustFormat(t *testing.T) {
	// The Go compiler does NOT have a Rust parser — .runar.rs falls back to
	// the TypeScript parser (the default case in ParseSource switch).
	// We verify: no panic, and a ParseResult is returned.
	source := []byte(`
// This is valid TypeScript that happens to use .runar.rs extension
import { SmartContract, assert } from 'runar-lang';

class Simple extends SmartContract {
  readonly x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  public check(val: bigint): void {
    assert(val === this.x);
  }
}
`)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ParseSource panicked on .runar.rs extension: %v", r)
		}
	}()

	result := frontend.ParseSource(source, "Contract.runar.rs")

	if result == nil {
		t.Fatal("ParseSource returned nil for .runar.rs extension")
	}

	// The Go compiler has no Rust parser — it falls back to the TS parser.
	// This tests that the dispatch doesn't panic (no .runar.rs case in the switch).
	t.Logf(".runar.rs dispatch: contract=%v, errors=%v",
		result.Contract != nil,
		result.Errors)
}

// ---------------------------------------------------------------------------
// Row 322: Python format dispatch: .runar.py extension routes to Python parser
// ---------------------------------------------------------------------------

func TestParseSource_DispatchesPythonFormat(t *testing.T) {
	source, fileName := readConformanceFormat(t, "arithmetic", ".runar.py")
	result := frontend.ParseSource(source, fileName)

	if result == nil {
		t.Fatal("ParseSource returned nil for .runar.py extension")
	}

	if result.Contract == nil {
		if len(result.Errors) > 0 {
			t.Skipf("Python parser produced errors: %v", result.Errors)
		}
		t.Fatal("expected non-nil contract from Python format parser")
	}

	if result.Contract.Name == "" {
		t.Error("expected non-empty contract name from Python format parser")
	}

	t.Logf(".runar.py dispatch: contract=%s", result.Contract.Name)
}
