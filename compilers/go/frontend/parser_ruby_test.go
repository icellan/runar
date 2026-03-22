package frontend

import (
	"testing"
)

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
	result := ParseSource(source, "P2PKH.runar.rb")

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
	result := ParseSource(source, "Counter.runar.rb")

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
	result := ParseSource(source, "Arithmetic.runar.rb")

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
	result := ParseSource(source, "Escrow.runar.rb")

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
	result := ParseSource(source, "BranchTest.runar.rb")

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
	result := ParseSource(source, "LoopTest.runar.rb")

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
	result := ParseSource(source, "Token.runar.rb")

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
	result := ParseSource(source, "Simple.runar.rb")

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
	result := ParseSource(source, "UnlessTest.runar.rb")

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

func TestRubyParser_UnknownParentClass(t *testing.T) {
	source := `
class Foo < Runar::UnknownBase
  prop :x, Bigint
  def initialize(x)
    super(x)
  end
  runar_public
  def bar
    assert @x > 0
  end
end
`
	result := ParseSource([]byte(source), "Test.runar.rb")
	if result.Contract != nil && len(result.Errors) == 0 {
		t.Error("expected errors or nil contract for unknown parent class, got neither")
	}
}

func TestRubyParser_MissingPropType(t *testing.T) {
	source := `
class Foo < Runar::SmartContract
  prop :x
  def initialize(x)
    super(x)
  end
  runar_public
  def bar
    assert @x > 0
  end
end
`
	result := ParseSource([]byte(source), "Test.runar.rb")
	if result.Contract != nil && len(result.Errors) == 0 {
		t.Error("expected errors or nil contract for prop missing type, got neither")
	}
}

func TestRubyParser_MissingMethodEnd(t *testing.T) {
	source := `
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
  end
  runar_public
  def bar
    assert @x > 0
`
	result := ParseSource([]byte(source), "Test.runar.rb")
	if result.Contract != nil && len(result.Errors) == 0 {
		t.Error("expected errors or nil contract for unclosed method, got neither")
	}
}

func TestRubyParser_EmptySource(t *testing.T) {
	result := ParseSource([]byte(""), "Test.runar.rb")
	if result.Contract != nil && len(result.Errors) == 0 {
		t.Error("expected errors or nil contract for empty source, got neither")
	}
}
