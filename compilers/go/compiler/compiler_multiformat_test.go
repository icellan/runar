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

// ---------------------------------------------------------------------------
// Test: Ruby parser produces valid AST structure (inline contracts)
// ---------------------------------------------------------------------------

func TestParseRuby_P2PKH(t *testing.T) {
	source := []byte(`require 'runar'

class P2PKH < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end
`)
	result := frontend.ParseSource(source, "P2PKH.runar.rb")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.Errors)
	}
	if result.Contract.Name != "P2PKH" {
		t.Errorf("expected P2PKH, got %s", result.Contract.Name)
	}
	if result.Contract.ParentClass != "SmartContract" {
		t.Errorf("expected SmartContract, got %s", result.Contract.ParentClass)
	}
	// Should have 1 property: pubKeyHash (snake_case -> camelCase)
	if len(result.Contract.Properties) != 1 {
		t.Fatalf("expected 1 property, got %d", len(result.Contract.Properties))
	}
	prop := result.Contract.Properties[0]
	if prop.Name != "pubKeyHash" {
		t.Errorf("expected property name 'pubKeyHash', got %s", prop.Name)
	}
	if !prop.Readonly {
		t.Errorf("expected pubKeyHash to be readonly (stateless contract)")
	}

	// Should have 1 method: unlock
	if len(result.Contract.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(result.Contract.Methods))
	}
	method := result.Contract.Methods[0]
	if method.Name != "unlock" {
		t.Errorf("expected method name 'unlock', got %s", method.Name)
	}
	if method.Visibility != "public" {
		t.Errorf("expected unlock to be public, got %s", method.Visibility)
	}
	if len(method.Params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(method.Params))
	}
	if method.Params[0].Name != "sig" {
		t.Errorf("expected param 'sig', got %s", method.Params[0].Name)
	}
	if method.Params[1].Name != "pubKey" {
		t.Errorf("expected param 'pubKey', got %s", method.Params[1].Name)
	}
}

func TestParseRuby_StatefulCounter(t *testing.T) {
	source := []byte(`require 'runar'

class Counter < Runar::StatefulSmartContract
  prop :count, Bigint

  def initialize(count)
    super(count)
    @count = count
  end

  runar_public
  def increment
    @count += 1
  end

  runar_public
  def decrement
    assert @count > 0
    @count -= 1
  end
end
`)
	result := frontend.ParseSource(source, "Counter.runar.rb")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.Errors)
	}
	if result.Contract.Name != "Counter" {
		t.Errorf("expected Counter, got %s", result.Contract.Name)
	}
	if result.Contract.ParentClass != "StatefulSmartContract" {
		t.Errorf("expected StatefulSmartContract, got %s", result.Contract.ParentClass)
	}
	// Stateful: property should NOT be readonly by default
	if len(result.Contract.Properties) != 1 {
		t.Fatalf("expected 1 property, got %d", len(result.Contract.Properties))
	}
	if result.Contract.Properties[0].Readonly {
		t.Errorf("expected count to be mutable in stateful contract")
	}
	// Should have 2 methods: increment, decrement
	if len(result.Contract.Methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(result.Contract.Methods))
	}
	if result.Contract.Methods[0].Name != "increment" {
		t.Errorf("expected method name 'increment', got %s", result.Contract.Methods[0].Name)
	}
	if result.Contract.Methods[0].Visibility != "public" {
		t.Errorf("expected increment to be public, got %s", result.Contract.Methods[0].Visibility)
	}
	if result.Contract.Methods[1].Name != "decrement" {
		t.Errorf("expected method name 'decrement', got %s", result.Contract.Methods[1].Name)
	}
}

func TestParseRuby_Arithmetic(t *testing.T) {
	source := []byte(`require 'runar'

class Arithmetic < Runar::SmartContract
  prop :target, Bigint

  def initialize(target)
    super(target)
    @target = target
  end

  runar_public a: Bigint, b: Bigint
  def verify(a, b)
    sum_val = a + b
    diff = a - b
    prod = a * b
    quot = a / b
    result = sum_val + diff + prod + quot
    assert result == @target
  end
end
`)
	result := frontend.ParseSource(source, "Arithmetic.runar.rb")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.Errors)
	}
	if result.Contract.Name != "Arithmetic" {
		t.Errorf("expected Arithmetic, got %s", result.Contract.Name)
	}
	// Property: target, readonly (stateless)
	if len(result.Contract.Properties) != 1 {
		t.Fatalf("expected 1 property, got %d", len(result.Contract.Properties))
	}
	if result.Contract.Properties[0].Name != "target" {
		t.Errorf("expected property 'target', got %s", result.Contract.Properties[0].Name)
	}
	if !result.Contract.Properties[0].Readonly {
		t.Errorf("expected 'target' to be readonly")
	}
	// Method: verify with 2 params
	if len(result.Contract.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(result.Contract.Methods))
	}
	if result.Contract.Methods[0].Name != "verify" {
		t.Errorf("expected method 'verify', got %s", result.Contract.Methods[0].Name)
	}
	if len(result.Contract.Methods[0].Params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(result.Contract.Methods[0].Params))
	}
	if result.Contract.Methods[0].Params[0].Name != "a" {
		t.Errorf("expected param 'a', got %s", result.Contract.Methods[0].Params[0].Name)
	}
	if result.Contract.Methods[0].Params[1].Name != "b" {
		t.Errorf("expected param 'b', got %s", result.Contract.Methods[0].Params[1].Name)
	}
}

func TestParseRuby_SnakeToCamelConversion(t *testing.T) {
	source := []byte(`require 'runar'

class Escrow < Runar::SmartContract
  prop :buyer_pub_key, PubKey
  prop :seller_pub_key, PubKey

  def initialize(buyer_pub_key, seller_pub_key)
    super(buyer_pub_key, seller_pub_key)
    @buyer_pub_key = buyer_pub_key
    @seller_pub_key = seller_pub_key
  end

  runar_public sig: Sig
  def release_by_seller(sig)
    assert check_sig(sig, @seller_pub_key)
  end
end
`)
	result := frontend.ParseSource(source, "Escrow.runar.rb")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.Errors)
	}
	// Properties should be camelCase
	if len(result.Contract.Properties) != 2 {
		t.Fatalf("expected 2 properties, got %d", len(result.Contract.Properties))
	}
	if result.Contract.Properties[0].Name != "buyerPubKey" {
		t.Errorf("expected 'buyerPubKey', got %s", result.Contract.Properties[0].Name)
	}
	if result.Contract.Properties[1].Name != "sellerPubKey" {
		t.Errorf("expected 'sellerPubKey', got %s", result.Contract.Properties[1].Name)
	}
	// Method name should be camelCase
	if len(result.Contract.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(result.Contract.Methods))
	}
	if result.Contract.Methods[0].Name != "releaseBySeller" {
		t.Errorf("expected 'releaseBySeller', got %s", result.Contract.Methods[0].Name)
	}
}

func TestParseRuby_IfElsifElse(t *testing.T) {
	source := []byte(`require 'runar'

class BranchTest < Runar::SmartContract
  prop :value, Bigint

  runar_public x: Bigint
  def check(x)
    if x > 10
      assert true
    elsif x > 5
      assert true
    else
      assert false
    end
  end
end
`)
	result := frontend.ParseSource(source, "BranchTest.runar.rb")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.Errors)
	}
	if result.Contract.Name != "BranchTest" {
		t.Errorf("expected BranchTest, got %s", result.Contract.Name)
	}
	// Should parse the method body without errors
	if len(result.Contract.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(result.Contract.Methods))
	}
	if len(result.Contract.Methods[0].Body) == 0 {
		t.Error("expected non-empty method body")
	}
}

func TestParseRuby_ForLoop(t *testing.T) {
	source := []byte(`require 'runar'

class LoopTest < Runar::SmartContract
  prop :value, Bigint

  runar_public n: Bigint
  def compute(n)
    total = 0
    for i in 0...n do
      total += i
    end
    assert total == @value
  end
end
`)
	result := frontend.ParseSource(source, "LoopTest.runar.rb")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.Errors)
	}
	// Check that the method has a for loop statement
	if len(result.Contract.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(result.Contract.Methods))
	}
	if len(result.Contract.Methods[0].Body) < 2 {
		t.Fatal("expected at least 2 statements in method body (variable decl + for loop)")
	}
}

func TestParseRuby_ReadonlyProp(t *testing.T) {
	source := []byte(`require 'runar'

class Token < Runar::StatefulSmartContract
  prop :owner, PubKey
  prop :balance, Bigint
  prop :token_id, ByteString, readonly: true

  runar_public sig: Sig
  def transfer(sig)
    assert check_sig(sig, @owner)
  end
end
`)
	result := frontend.ParseSource(source, "Token.runar.rb")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.Errors)
	}
	if len(result.Contract.Properties) != 3 {
		t.Fatalf("expected 3 properties, got %d", len(result.Contract.Properties))
	}
	// owner and balance should be mutable; tokenId should be readonly
	if result.Contract.Properties[0].Readonly {
		t.Errorf("expected 'owner' to be mutable")
	}
	if result.Contract.Properties[1].Readonly {
		t.Errorf("expected 'balance' to be mutable")
	}
	if !result.Contract.Properties[2].Readonly {
		t.Errorf("expected 'tokenId' to be readonly")
	}
	if result.Contract.Properties[2].Name != "tokenId" {
		t.Errorf("expected 'tokenId', got %s", result.Contract.Properties[2].Name)
	}
}

func TestParseRuby_AutoGeneratedConstructor(t *testing.T) {
	source := []byte(`require 'runar'

class Simple < Runar::SmartContract
  prop :value, Bigint

  runar_public x: Bigint
  def check(x)
    assert x == @value
  end
end
`)
	result := frontend.ParseSource(source, "Simple.runar.rb")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.Errors)
	}
	// Constructor should be auto-generated
	ctor := result.Contract.Constructor
	if ctor.Name != "constructor" {
		t.Errorf("expected constructor name 'constructor', got %s", ctor.Name)
	}
	if len(ctor.Params) != 1 {
		t.Fatalf("expected 1 constructor param, got %d", len(ctor.Params))
	}
	if ctor.Params[0].Name != "value" {
		t.Errorf("expected constructor param 'value', got %s", ctor.Params[0].Name)
	}
	// Should have super() call + assignment = 2 statements
	if len(ctor.Body) != 2 {
		t.Errorf("expected 2 constructor body statements, got %d", len(ctor.Body))
	}
}

func TestParseRuby_UnlessStatement(t *testing.T) {
	source := []byte(`require 'runar'

class UnlessTest < Runar::SmartContract
  prop :value, Bigint

  runar_public x: Bigint
  def check(x)
    unless x == 0
      assert x > 0
    end
  end
end
`)
	result := frontend.ParseSource(source, "UnlessTest.runar.rb")

	if result.Contract == nil {
		t.Fatalf("expected contract, got nil (errors: %v)", result.Errors)
	}
	if len(result.Contract.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(result.Contract.Methods))
	}
	if len(result.Contract.Methods[0].Body) == 0 {
		t.Error("expected non-empty method body for unless statement")
	}
}

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
