package frontend

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// TestParseRustMacro_P2PKH
// ---------------------------------------------------------------------------

func TestParseRustMacro_P2PKH(t *testing.T) {
	source := `
use runar::prelude::*;

#[runar::contract]
pub struct P2PKH {
    #[readonly]
    pub pub_key_hash: Addr,
}

#[runar::methods(P2PKH)]
impl P2PKH {
    #[public]
    pub fn unlock(&self, sig: &Sig, pub_key: &PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}
`
	result := ParseSource([]byte(source), "P2PKH.runar.rs")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.Errors, "; "))
	}
	if result.Contract == nil {
		t.Fatal("expected non-nil contract")
	}

	c := result.Contract
	if c.Name != "P2PKH" {
		t.Errorf("expected contract name P2PKH, got %s", c.Name)
	}
	if c.ParentClass != "SmartContract" {
		t.Errorf("expected parentClass SmartContract (all readonly), got %s", c.ParentClass)
	}
	if len(c.Properties) != 1 {
		t.Fatalf("expected 1 property, got %d", len(c.Properties))
	}
	if c.Properties[0].Name != "pubKeyHash" {
		t.Errorf("expected property name pubKeyHash, got %s", c.Properties[0].Name)
	}
	if !c.Properties[0].Readonly {
		t.Error("expected property to be readonly")
	}
	if len(c.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(c.Methods))
	}
	if c.Methods[0].Name != "unlock" {
		t.Errorf("expected method name unlock, got %s", c.Methods[0].Name)
	}
	if c.Methods[0].Visibility != "public" {
		t.Errorf("expected method visibility public, got %s", c.Methods[0].Visibility)
	}
	// sig and pub_key params — &self should be excluded
	if len(c.Methods[0].Params) != 2 {
		t.Errorf("expected 2 params (sig, pubKey), got %d", len(c.Methods[0].Params))
	}
	if c.Methods[0].Params[0].Name != "sig" {
		t.Errorf("expected first param sig, got %s", c.Methods[0].Params[0].Name)
	}
	if c.Methods[0].Params[1].Name != "pubKey" {
		t.Errorf("expected second param pubKey, got %s", c.Methods[0].Params[1].Name)
	}
}

// ---------------------------------------------------------------------------
// TestParseRustMacro_StatefulContract
// ---------------------------------------------------------------------------

func TestParseRustMacro_StatefulContract(t *testing.T) {
	source := `
use runar::prelude::*;

#[runar::contract]
pub struct Counter {
    pub count: Bigint,
}

#[runar::methods(Counter)]
impl Counter {
    #[public]
    pub fn increment(&mut self) {
        self.count += 1;
    }

    #[public]
    pub fn decrement(&mut self) {
        assert!(self.count > 0);
        self.count -= 1;
    }
}
`
	result := ParseSource([]byte(source), "Counter.runar.rs")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.Errors, "; "))
	}
	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	if c.Name != "Counter" {
		t.Errorf("expected name Counter, got %s", c.Name)
	}
	// count is not readonly → StatefulSmartContract
	if c.ParentClass != "StatefulSmartContract" {
		t.Errorf("expected parentClass StatefulSmartContract, got %s", c.ParentClass)
	}
	if len(c.Properties) != 1 {
		t.Fatalf("expected 1 property, got %d", len(c.Properties))
	}
	if c.Properties[0].Name != "count" {
		t.Errorf("expected property count, got %s", c.Properties[0].Name)
	}
	if c.Properties[0].Readonly {
		t.Error("expected property to NOT be readonly")
	}
	if len(c.Methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(c.Methods))
	}
	if c.Methods[0].Name != "increment" {
		t.Errorf("expected method increment, got %s", c.Methods[0].Name)
	}
	if c.Methods[0].Visibility != "public" {
		t.Errorf("expected public, got %s", c.Methods[0].Visibility)
	}
}

// ---------------------------------------------------------------------------
// TestParseRustMacro_SnakeToCamelConversion
// ---------------------------------------------------------------------------

func TestParseRustMacro_SnakeToCamelConversion(t *testing.T) {
	source := `
use runar::prelude::*;

#[runar::contract]
pub struct MyContract {
    #[readonly]
    pub pub_key_hash: Addr,
    pub my_balance: Bigint,
}

#[runar::methods(MyContract)]
impl MyContract {
    #[public]
    pub fn verify_and_pay(&mut self, sig: &Sig, pub_key: &PubKey, fee_amount: Bigint) {
        assert!(check_sig(sig, pub_key));
        self.my_balance -= fee_amount;
    }

    fn compute_fee(&self, amount: Bigint) -> Bigint {
        percent_of(amount, 100)
    }
}
`
	result := ParseSource([]byte(source), "MyContract.runar.rs")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.Errors, "; "))
	}
	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}

	// Check property name conversion
	if len(c.Properties) < 2 {
		t.Fatalf("expected 2 properties, got %d", len(c.Properties))
	}
	if c.Properties[0].Name != "pubKeyHash" {
		t.Errorf("expected pubKeyHash, got %s", c.Properties[0].Name)
	}
	if c.Properties[1].Name != "myBalance" {
		t.Errorf("expected myBalance, got %s", c.Properties[1].Name)
	}

	// Check method name conversion
	if len(c.Methods) < 2 {
		t.Fatalf("expected 2 methods, got %d", len(c.Methods))
	}
	if c.Methods[0].Name != "verifyAndPay" {
		t.Errorf("expected verifyAndPay, got %s", c.Methods[0].Name)
	}
	if c.Methods[1].Name != "computeFee" {
		t.Errorf("expected computeFee, got %s", c.Methods[1].Name)
	}

	// Check parameter name conversion
	m := c.Methods[0]
	paramNames := make([]string, len(m.Params))
	for i, p := range m.Params {
		paramNames[i] = p.Name
	}
	// sig → sig, pub_key → pubKey, fee_amount → feeAmount
	expected := []string{"sig", "pubKey", "feeAmount"}
	for i, exp := range expected {
		if i >= len(paramNames) {
			t.Errorf("missing param %s", exp)
			continue
		}
		if paramNames[i] != exp {
			t.Errorf("param[%d]: expected %s, got %s", i, exp, paramNames[i])
		}
	}

	// Check method visibility
	if c.Methods[0].Visibility != "public" {
		t.Errorf("verifyAndPay should be public, got %s", c.Methods[0].Visibility)
	}
	if c.Methods[1].Visibility != "private" {
		t.Errorf("computeFee should be private, got %s", c.Methods[1].Visibility)
	}
}

// ---------------------------------------------------------------------------
// TestParseRustMacro_InvalidSyntax_Error
// ---------------------------------------------------------------------------

func TestParseRustMacro_InvalidSyntax_Error(t *testing.T) {
	// A source file with no #[runar::contract] struct — should return an error.
	source := `
fn main() {
    println!("hello world");
}
`
	result := ParseSource([]byte(source), "notacontract.runar.rs")
	if result.Contract != nil {
		t.Error("expected nil contract for non-contract source")
	}
	if len(result.Errors) == 0 {
		t.Error("expected at least one error for non-contract source")
	}
}

// ---------------------------------------------------------------------------
// TestParseRustMacro_PropertyInitializers
// ---------------------------------------------------------------------------

func TestParseRustMacro_PropertyInitializers(t *testing.T) {
	source := `
use runar::prelude::*;

#[runar::contract]
pub struct BoundedCounter {
    pub count: Bigint,
    #[readonly]
    pub max_count: Bigint,
    #[readonly]
    pub active: bool,
}

#[runar::methods(BoundedCounter)]
impl BoundedCounter {
    pub fn init(&mut self) {
        self.count = 0;
        self.active = true;
    }

    #[public]
    pub fn increment(&mut self, amount: Bigint) {
        assert!(self.active);
        self.count = self.count + amount;
        assert!(self.count <= self.max_count);
    }
}
`
	result := ParseSource([]byte(source), "BoundedCounter.runar.rs")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.Errors, "; "))
	}
	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}

	// find count property — should have initializer 0
	var countProp *PropertyNode
	var activeProp *PropertyNode
	for i := range c.Properties {
		switch c.Properties[i].Name {
		case "count":
			countProp = &c.Properties[i]
		case "active":
			activeProp = &c.Properties[i]
		}
	}

	if countProp == nil {
		t.Fatal("expected property 'count'")
	}
	if countProp.Initializer == nil {
		t.Error("expected count to have initializer (from init() method)")
	}

	if activeProp == nil {
		t.Fatal("expected property 'active'")
	}
	if activeProp.Initializer == nil {
		t.Error("expected active to have initializer (from init() method)")
	}

	// init() should not appear as a method
	for _, m := range c.Methods {
		if m.Name == "init" {
			t.Error("init() should be consumed as initializer, not appear as a method")
		}
	}

	// Constructor should only include non-initialized props (maxCount)
	hasMaxCount := false
	for _, p := range c.Constructor.Params {
		if p.Name == "maxCount" {
			hasMaxCount = true
		}
		if p.Name == "count" || p.Name == "active" {
			t.Errorf("initialized property %s should not appear in constructor", p.Name)
		}
	}
	if !hasMaxCount {
		t.Error("expected maxCount in constructor params")
	}
}

// ---------------------------------------------------------------------------
// TestParseRustMacro_SnakeToCamel (unit tests for the helper)
// ---------------------------------------------------------------------------

func TestRustSnakeToCamel(t *testing.T) {
	cases := []struct{ in, want string }{
		{"pub_key_hash", "pubKeyHash"},
		{"check_sig", "checkSig"},
		{"count", "count"},
		{"a_b_c", "aBC"},
		{"hello_world", "helloWorld"},
		{"already", "already"},
		{"fee_amount", "feeAmount"},
		{"verify_and_pay", "verifyAndPay"},
	}
	for _, tc := range cases {
		got := rustSnakeToCamel(tc.in)
		if got != tc.want {
			t.Errorf("rustSnakeToCamel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// TestParseRustMacro_ParsesActualFile (integration: real P2PKH.runar.rs)
// ---------------------------------------------------------------------------

func TestParseRustMacro_ParsesActualP2PKHFile(t *testing.T) {
	// Mirrors the example from examples/rust/p2pkh/P2PKH.runar.rs
	source := `
use runar::prelude::*;

#[runar::contract]
pub struct P2PKH {
    #[readonly]
    pub pub_key_hash: Addr,
}

#[runar::methods(P2PKH)]
impl P2PKH {
    #[public]
    pub fn unlock(&self, sig: &Sig, pub_key: &PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}
`
	result := ParseSource([]byte(source), "P2PKH.runar.rs")
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %s", strings.Join(result.Errors, "; "))
	}
	c := result.Contract
	if c == nil {
		t.Fatal("contract should not be nil")
	}
	if c.Name != "P2PKH" {
		t.Errorf("name: got %q, want P2PKH", c.Name)
	}
	if c.SourceFile != "P2PKH.runar.rs" {
		t.Errorf("sourceFile: got %q, want P2PKH.runar.rs", c.SourceFile)
	}
}
