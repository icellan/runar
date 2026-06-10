package frontend

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test: Parse a basic Solidity-like P2PKH contract
// ---------------------------------------------------------------------------

func TestParseSolidity_P2PKH(t *testing.T) {
	source := `
// SPDX-License-Identifier: MIT
pragma runar ^1.0.0;

import "runar-lang";

contract P2PKH is SmartContract {
    Addr immutable pubKeyHash;

    constructor(Addr _pubKeyHash) {
        pubKeyHash = _pubKeyHash;
    }

    function unlock(Sig sig, PubKey pubKey) public {
        require(hash160(pubKey) == pubKeyHash);
        require(checkSig(sig, pubKey));
    }
}
`
	result := ParseSource([]byte(source), "P2PKH.runar.sol")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	if result.Contract == nil {
		t.Fatal("expected non-nil contract")
	}

	c := result.Contract
	if c.Name != "P2PKH" {
		t.Errorf("expected contract name P2PKH, got %s", c.Name)
	}
	if c.ParentClass != "SmartContract" {
		t.Errorf("expected parentClass SmartContract, got %s", c.ParentClass)
	}
	if len(c.Properties) != 1 {
		t.Fatalf("expected 1 property, got %d", len(c.Properties))
	}
	if c.Properties[0].Name != "pubKeyHash" {
		t.Errorf("expected property name pubKeyHash, got %s", c.Properties[0].Name)
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Solidity-like contract verifies methods and params
// ---------------------------------------------------------------------------

func TestParseSolidity_MethodsAndParams(t *testing.T) {
	source := `
pragma runar ^1.0.0;
import "runar-lang";

contract Adder is SmartContract {
    int immutable target;

    constructor(int _target) {
        target = _target;
    }

    function verify(int a, int b) public {
        require(a + b == target);
    }
}
`
	result := ParseSource([]byte(source), "Adder.runar.sol")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}

	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}

	if len(c.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(c.Methods))
	}
	m := c.Methods[0]
	if m.Name != "verify" {
		t.Errorf("expected method name verify, got %s", m.Name)
	}
	if m.Visibility != "public" {
		t.Errorf("expected method visibility public, got %s", m.Visibility)
	}
	if len(m.Params) != 2 {
		t.Errorf("expected 2 params, got %d", len(m.Params))
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Solidity-like stateful contract
// ---------------------------------------------------------------------------

func TestParseSolidity_StatefulContract(t *testing.T) {
	source := `
pragma runar ^1.0.0;
import "runar-lang";

contract Counter is StatefulSmartContract {
    int count;

    constructor(int _count) {
        count = _count;
    }

    function increment() public {
        count = count + 1;
    }
}
`
	result := ParseSource([]byte(source), "Counter.runar.sol")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}

	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	if c.ParentClass != "StatefulSmartContract" {
		t.Errorf("expected parentClass StatefulSmartContract, got %s", c.ParentClass)
	}
	if c.Name != "Counter" {
		t.Errorf("expected name Counter, got %s", c.Name)
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Solidity-like contract with invalid syntax produces error
// ---------------------------------------------------------------------------

func TestParseSolidity_InvalidSyntax_Error(t *testing.T) {
	source := `
contract {
    // missing name and parent
}
`
	result := ParseSource([]byte(source), "bad.runar.sol")
	if result.Contract != nil && len(result.Errors) == 0 {
		t.Error("expected errors for invalid Solidity syntax")
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Solidity-like contract with multiple properties
// ---------------------------------------------------------------------------

func TestParseSolidity_MultipleProperties(t *testing.T) {
	source := `
pragma runar ^1.0.0;
import "runar-lang";

contract TwoProps is SmartContract {
    Addr immutable addr;
    PubKey immutable key;

    constructor(Addr _addr, PubKey _key) {
        addr = _addr;
        key = _key;
    }

    function check(int x) public {
        require(x == 1);
    }
}
`
	result := ParseSource([]byte(source), "TwoProps.runar.sol")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}

	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	if len(c.Properties) != 2 {
		t.Fatalf("expected 2 properties, got %d", len(c.Properties))
	}
	if c.Properties[0].Name != "addr" {
		t.Errorf("expected first property addr, got %s", c.Properties[0].Name)
	}
	if c.Properties[1].Name != "key" {
		t.Errorf("expected second property key, got %s", c.Properties[1].Name)
	}
}

// ---------------------------------------------------------------------------
// Test: Nested fixed-array property type `T[N][M]`
// ---------------------------------------------------------------------------

func TestParseSolidity_NestedFixedArray(t *testing.T) {
	source := `
pragma runar ^0.1.0;

contract Grid2x2 is StatefulSmartContract {
    bigint[2][2] grid = [[0, 0], [0, 0]];

    constructor() {}

    function set00(bigint v) public {
        this.grid[0][0] = v;
        require(true);
    }
}
`
	result := ParseSource([]byte(source), "Grid2x2.runar.sol")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	if len(c.Properties) != 1 {
		t.Fatalf("expected 1 property, got %d", len(c.Properties))
	}
	outer, ok := c.Properties[0].Type.(FixedArrayType)
	if !ok {
		t.Fatalf("expected outer FixedArrayType, got %T", c.Properties[0].Type)
	}
	if outer.Length != 2 {
		t.Errorf("expected outer length 2, got %d", outer.Length)
	}
	inner, ok := outer.Element.(FixedArrayType)
	if !ok {
		t.Fatalf("expected inner FixedArrayType, got %T", outer.Element)
	}
	if inner.Length != 2 {
		t.Errorf("expected inner length 2, got %d", inner.Length)
	}
	leaf, ok := inner.Element.(PrimitiveType)
	if !ok || leaf.Name != "bigint" {
		t.Errorf("expected innermost element bigint, got %#v", inner.Element)
	}
}
