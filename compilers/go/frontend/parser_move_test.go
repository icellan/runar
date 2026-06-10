package frontend

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test: Parse a basic Move-style P2PKH contract
// ---------------------------------------------------------------------------

func TestParseMove_P2PKH(t *testing.T) {
	source := `
module P2PKH {
    use runar::SmartContract;
    use runar::hash160;
    use runar::checkSig;

    struct P2PKH has SmartContract {
        pub_key_hash: Addr,
    }

    public fun unlock(contract: &P2PKH, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == contract.pub_key_hash);
        assert!(checkSig(sig, pub_key));
    }
}
`
	result := ParseSource([]byte(source), "P2PKH.runar.move")
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
}

// ---------------------------------------------------------------------------
// Test: Parse Move-style contract with properties and methods
// ---------------------------------------------------------------------------

func TestParseMove_PropertiesAndMethods(t *testing.T) {
	source := `
module Adder {
    use runar::SmartContract;

    struct Adder has SmartContract {
        target: bigint,
    }

    public fun verify(contract: &Adder, a: bigint, b: bigint) {
        assert!(a + b == contract.target);
    }
}
`
	result := ParseSource([]byte(source), "Adder.runar.move")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}

	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	if len(c.Properties) < 1 {
		t.Fatal("expected at least 1 property")
	}
	if c.Properties[0].Name != "target" {
		t.Errorf("expected property name target, got %s", c.Properties[0].Name)
	}
	if len(c.Methods) < 1 {
		t.Fatal("expected at least 1 method")
	}
	if c.Methods[0].Name != "verify" {
		t.Errorf("expected method name verify, got %s", c.Methods[0].Name)
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Move-style stateful contract
// ---------------------------------------------------------------------------

func TestParseMove_StatefulContract(t *testing.T) {
	source := `
module Counter {
    use runar::StatefulSmartContract;

    resource struct Counter {
        count: &mut Int,
    }

    public fun increment(contract: &mut Counter) {
        contract.count = contract.count + 1;
    }
}
`
	result := ParseSource([]byte(source), "Counter.runar.move")
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
}

// ---------------------------------------------------------------------------
// Test: Parse Move-style contract with invalid syntax produces error
// ---------------------------------------------------------------------------

func TestParseMove_InvalidSyntax_Error(t *testing.T) {
	source := `
module {
    // missing name
}
`
	result := ParseSource([]byte(source), "bad.runar.move")
	if result.Contract != nil && len(result.Errors) == 0 {
		t.Error("expected errors for invalid Move syntax")
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Move-style contract with multiple public functions
// ---------------------------------------------------------------------------

func TestParseMove_MultipleMethods(t *testing.T) {
	source := `
module Multi {
    use runar::SmartContract;

    struct Multi has SmartContract {
        x: bigint,
    }

    public fun method1(contract: &Multi, a: bigint) {
        assert!(a == contract.x);
    }

    public fun method2(contract: &Multi, b: bigint) {
        assert!(b == contract.x);
    }
}
`
	result := ParseSource([]byte(source), "Multi.runar.move")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}

	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	if len(c.Methods) != 2 {
		t.Errorf("expected 2 methods, got %d", len(c.Methods))
	}
}

// ---------------------------------------------------------------------------
// Test: Nested FixedArray<FixedArray<T, N>, M> in Move surface syntax
// ---------------------------------------------------------------------------

func TestParseMove_NestedFixedArray(t *testing.T) {
	source := `module Grid2x2 {
    resource struct Grid2x2 {
        grid: &mut FixedArray<FixedArray<bigint, 2>, 2> = [[0, 0], [0, 0]],
    }
    public fun set00(v: bigint) { self.grid[0][0] = v; assert!(true, 0); }
}
`
	result := ParseSource([]byte(source), "Grid2x2.runar.move")
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
