package compiler

import (
	"encoding/json"
	"fmt"
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

var multiFormats = []string{
	".runar.ts", ".runar.sol", ".runar.move", ".runar.go",
	".runar.rs", ".runar.py", ".runar.zig", ".runar.rb",
}

// resolveConformanceFormat is the pure resolution logic behind
// readConformanceFormat below: given a fixture name and a format extension,
// it returns the resolved source bytes and path, or a descriptive error when
// the fixture cannot be resolved. It takes no *testing.T and never calls
// Fatal/Skip itself, so the fail-vs-skip decision (F-312) is unit-testable
// directly on the returned error, without relying on subtest pass/fail
// propagation to observe which T method a wrapper called — a subtest that
// genuinely fails always marks its parent as failed too (see Go's testing.T
// semantics), which would make any such observation report red forever.
func resolveConformanceFormat(testName, ext string) ([]byte, string, error) {
	// First try the legacy in-tree layout (conformance/tests/<name>/<name><ext>);
	// fall back to source.json indirection used by post-migration fixtures.
	fileName := filepath.Join(conformanceDir(), testName, testName+ext)
	if _, err := os.Stat(fileName); err == nil {
		source, err := os.ReadFile(fileName)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read %s: %w", fileName, err)
		}
		return source, fileName, nil
	}

	sourceJSON := filepath.Join(conformanceDir(), testName, "source.json")
	data, err := os.ReadFile(sourceJSON)
	if err != nil {
		// FAILS rather than skips: every fixture carries all nine formats by
		// the frontend-parity invariant (CLAUDE.md), so a fixture this helper
		// cannot resolve is broken, not a reason to report a pass. See
		// conformanceSourcePathExt below, which this mirrors (F-312).
		return nil, "", fmt.Errorf("%s: neither %s nor %s exists — the fixture cannot be resolved",
			testName, fileName, sourceJSON)
	}
	var manifest struct {
		Sources map[string]string `json:"sources"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, "", fmt.Errorf("failed to parse %s: %w", sourceJSON, err)
	}
	ref, ok := manifest.Sources[ext]
	if !ok {
		return nil, "", fmt.Errorf("%s: source.json declares no %s source; every fixture must carry all "+
			"nine formats (frontend-parity invariant)", testName, ext)
	}
	resolved := filepath.Join(conformanceDir(), testName, ref)
	source, err := os.ReadFile(resolved)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read %s: %w", resolved, err)
	}
	return source, resolved, nil
}

func readConformanceFormat(t *testing.T, testName, ext string) ([]byte, string) {
	t.Helper()
	source, path, err := resolveConformanceFormat(testName, ext)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return source, path
}

// conformanceSourcePathExt resolves a conformance fixture's source path for one
// format. It is the extension-taking peer of `conformanceSourcePath` (which is
// hard-wired to `.runar.ts`), and it resolves through the `source.json`
// manifest the fixtures have used since the migration moved the sources out to
// `examples/<format>/`.
//
// It FAILS rather than skips when a format cannot be resolved. Every fixture
// carries all nine formats by the frontend-parity invariant (CLAUDE.md), so a
// missing entry is a broken fixture, not a reason to report a pass. Looking for
// the pre-migration `<dir>/<dir><ext>` layout WITHOUT this fallback is what
// silently skipped all twelve subtests of the two conformance-compile tests
// below: the file has not existed at that path for any fixture since the
// migration, so both tests were unconditionally, permanently green-and-empty.
func conformanceSourcePathExt(t *testing.T, testName, ext string) string {
	t.Helper()

	// Pre-migration in-tree layout, still used by a few fixtures.
	direct := filepath.Join(conformanceDir(), testName, testName+ext)
	if _, err := os.Stat(direct); err == nil {
		return direct
	}

	sourceJSON := filepath.Join(conformanceDir(), testName, "source.json")
	data, err := os.ReadFile(sourceJSON)
	if err != nil {
		t.Fatalf("%s: no %s and no readable source.json (%v) — the fixture cannot be resolved",
			testName, direct, err)
	}
	var manifest struct {
		Sources map[string]string `json:"sources"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("%s: source.json is unparseable: %v", testName, err)
	}
	ref, ok := manifest.Sources[ext]
	if !ok {
		t.Fatalf("%s: source.json declares no %s source; every fixture must carry all "+
			"nine formats (frontend-parity invariant)", testName, ext)
	}
	resolved := filepath.Join(conformanceDir(), testName, ref)
	if _, err := os.Stat(resolved); err != nil {
		t.Fatalf("%s: source.json points %s at %s, which does not exist (%v)",
			testName, ext, resolved, err)
	}
	return resolved
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
					t.Fatalf("parser produced errors: %v", result.Errors)
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
			source, ok := conformanceSourcePath(dir)
			if !ok {
				t.Skipf("%s: source not found", dir)
			}
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
				t.Fatalf("parser failed for %s (errors: %v)", ext, result.Errors)
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
				t.Fatalf("parser failed for %s (errors: %v)", ext, result.Errors)
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
	// F-372: "stateful" was previously excluded behind a comment claiming the Go
	// compiler's stateful preimage injection "needs deeper work". TestConformanceGoldens
	// (conformance_goldens_test.go) already compiles every conformance/tests/*
	// directory's .runar.go source — including "stateful" — with constant folding
	// disabled and byte-matches it against the shared golden, so that premise is
	// stale. Included here too, proving .runar.go compiles via this call path
	// (default options, i.e. constant folding ON) to the same fold-OFF golden.
	testDirs := []string{"arithmetic", "basic-p2pkh", "boolean-logic", "bounded-loop", "if-else", "multi-method", "stateful"}

	for _, dir := range testDirs {
		t.Run(dir, func(t *testing.T) {
			source := conformanceSourcePathExt(t, dir, ".runar.go")

			artifact, err := CompileFromSource(source)
			if err != nil {
				t.Fatalf("Rúnar compilation failed: %v", err)
			}

			if artifact.Script == "" {
				t.Error("expected non-empty script hex")
			}

			// Compare against golden expected-script.hex. A missing golden is a
			// hard failure, not a pass: every conformance fixture ships one, so
			// its absence means the fixture is broken — and treating it as "OK"
			// would let this test go green while comparing against nothing.
			goldenPath := filepath.Join(conformanceDir(), dir, "expected-script.hex")
			goldenHex, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("%s: golden %s is unreadable (%v); compiled script hex=%d bytes "+
					"was compared against nothing", dir, goldenPath, err, len(artifact.Script)/2)
			}

			expected := strings.TrimSpace(string(goldenHex))
			if artifact.Script != expected {
				t.Errorf("%s: script hex does not match golden file (got %d chars, expected %d chars)",
					dir, len(artifact.Script), len(expected))
			} else {
				t.Logf("%s: MATCH (hex=%d bytes)", dir, len(artifact.Script)/2)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: .runar.rb conformance tests compile to Bitcoin Script hex
// ---------------------------------------------------------------------------

func TestRubyContract_CompileConformance(t *testing.T) {
	// F-372: "stateful" and "stateful-counter" were previously excluded behind a
	// comment claiming stateful preimage injection "requires deeper work in the
	// Go compiler". TestConformanceGoldens (conformance_goldens_test.go) already
	// compiles both via their .runar.go source and byte-matches the shared
	// golden, so that premise is stale for the compiler itself. Included here to
	// additionally prove the .runar.rb surface, parsed by the same Go compiler,
	// reaches the identical golden.
	testDirs := []string{"arithmetic", "basic-p2pkh", "boolean-logic", "bounded-loop", "if-else", "multi-method", "stateful", "stateful-counter"}

	for _, dir := range testDirs {
		t.Run(dir, func(t *testing.T) {
			source := conformanceSourcePathExt(t, dir, ".runar.rb")

			artifact, err := CompileFromSource(source)
			if err != nil {
				t.Fatalf("Rúnar compilation failed: %v", err)
			}

			if artifact.Script == "" {
				t.Error("expected non-empty script hex")
			}

			// Compare against golden expected-script.hex. A missing golden is a
			// hard failure, not a pass: every conformance fixture ships one, so
			// its absence means the fixture is broken — and treating it as "OK"
			// would let this test go green while comparing against nothing.
			goldenPath := filepath.Join(conformanceDir(), dir, "expected-script.hex")
			goldenHex, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("%s: golden %s is unreadable (%v); compiled script hex=%d bytes "+
					"was compared against nothing", dir, goldenPath, err, len(artifact.Script)/2)
			}

			expected := strings.TrimSpace(string(goldenHex))
			if artifact.Script != expected {
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
	// The Go compiler DOES have a Rust-macro parser (ParseRustMacro,
	// parser_rustmacro.go, 600+ lines), and ParseSource's switch dispatches
	// `.runar.rs` to it (frontend/parser.go). This test used to claim the
	// opposite — "the Go compiler does NOT have a Rust parser" — and fed
	// plain TypeScript source under a `.runar.rs` name, asserting only that
	// ParseSource didn't panic and returned a non-nil result. That assertion
	// holds regardless of which parser actually ran, so it proved nothing
	// about dispatch correctness: see F-371.
	//
	// This test instead parses a REAL Rust-DSL conformance fixture
	// (examples/rust/arithmetic/Arithmetic.runar.rs, contract name
	// "Arithmetic") through frontend.ParseSource and asserts the resulting
	// AST actually names that contract. Only the Rust-macro parser
	// understands this fixture's `struct` / `impl` / `#[runar::contract]`
	// syntax; routing it to the TypeScript parser instead would either
	// error out or silently produce a differently-shaped/unnamed contract,
	// not one named "Arithmetic".
	source, fileName := readConformanceFormat(t, "arithmetic", ".runar.rs")

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ParseSource panicked on .runar.rs extension: %v", r)
		}
	}()

	result := frontend.ParseSource(source, fileName)

	if result == nil {
		t.Fatal("ParseSource returned nil for .runar.rs extension")
	}
	if len(result.Errors) > 0 {
		t.Fatalf("ParseSource reported errors parsing the Rust-DSL fixture via the %q path: %v", fileName, result.Errors)
	}
	if result.Contract == nil {
		t.Fatal("expected a non-nil contract from the Rust-macro parser")
	}
	if result.Contract.Name != "Arithmetic" {
		t.Fatalf("expected contract name %q (the Rust fixture's struct name) — ParseSource did not dispatch %q to the Rust-macro parser, got contract %q",
			"Arithmetic", fileName, result.Contract.Name)
	}
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
			t.Fatalf("Python parser produced errors: %v", result.Errors)
		}
		t.Fatal("expected non-nil contract from Python format parser")
	}

	if result.Contract.Name == "" {
		t.Error("expected non-empty contract name from Python format parser")
	}

	t.Logf(".runar.py dispatch: contract=%s", result.Contract.Name)
}

// ---------------------------------------------------------------------------
// Test: resolveConformanceFormat/readConformanceFormat must fail, not skip,
// on a missing manifest entry (F-312)
//
// readConformanceFormat historically called t.Skipf when a fixture's
// source.json existed but declared no entry for the requested extension. Its
// hardened twin conformanceSourcePathExt (above) was fixed to t.Fatalf for the
// identical condition, citing the frontend-parity invariant (CLAUDE.md): every
// conformance fixture must carry all nine formats, so a missing manifest entry
// means a broken fixture, not something to silently skip and report green.
// readConformanceFormat backs TestMultiFormat_PropertyConsistency,
// TestMultiFormat_MethodParamConsistency, and several TestParse* subtests
// above, so leaving it on t.Skipf left that whole dispatch suite one deleted
// manifest key (or renamed extension) away from quietly skipping instead of
// catching a real regression.
//
// This test builds a throwaway fixture directory under conformanceDir()
// (removed via t.Cleanup) whose source.json deliberately omits a
// ".runar.sol" entry — the same shape as the brief's verification recipe
// (delete the .runar.sol key from conformance/tests/arithmetic/source.json)
// — but on a disposable fixture so no real conformance fixture is touched.
// It calls resolveConformanceFormat directly (the pure function
// readConformanceFormat now wraps) rather than readConformanceFormat itself,
// because a t.Fatalf from inside a nested subtest always marks its parent
// test as failed too, which would make the fixed (correct) behavior
// permanently report red in this very test. Testing the pure resolver's
// returned error is the correct way to pin "this is now an error, not a
// silent skip" without that propagation getting in the way.
func TestResolveConformanceFormat_MissingManifestEntryIsError(t *testing.T) {
	fixtureName := "f312-synthetic-missing-ext"
	fixtureDir := filepath.Join(conformanceDir(), fixtureName)
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		t.Fatalf("failed to create synthetic fixture dir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(fixtureDir); err != nil {
			t.Errorf("failed to clean up synthetic fixture dir: %v", err)
		}
	})

	manifest := `{"sources": {".runar.ts": "does-not-matter.runar.ts"}}`
	if err := os.WriteFile(filepath.Join(fixtureDir, "source.json"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("failed to write synthetic source.json: %v", err)
	}

	source, path, err := resolveConformanceFormat(fixtureName, ".runar.sol")
	if err == nil {
		t.Fatalf("resolveConformanceFormat must return an error when source.json declares no "+
			".runar.sol entry, not a silent pass — got source=%q path=%q err=nil (F-312)",
			source, path)
	}
	if !strings.Contains(err.Error(), "every fixture must carry all nine formats") {
		t.Fatalf("resolveConformanceFormat failed, but not for the expected reason: %v", err)
	}
}
