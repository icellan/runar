package frontend

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test: Parse a basic Go contract (P2PKH)
// ---------------------------------------------------------------------------

func TestParseGoContract_P2PKH(t *testing.T) {
	source := `
package contracts

import "github.com/icellan/runar/packages/runar-go"

type P2PKH struct {
	runar.SmartContract
	PubKeyHash runar.Addr ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *P2PKH) Unlock(sig runar.Sig, pubKey runar.PubKey) {
	runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
	runar.Assert(runar.CheckSig(sig, pubKey))
}
`
	result := ParseSource([]byte(source), "P2PKH.runar.go")
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
	if len(c.Properties) < 1 {
		t.Fatal("expected at least 1 property")
	}
	// Go parser converts PubKeyHash -> pubKeyHash (camelCase)
	if c.Properties[0].Name != "pubKeyHash" {
		t.Errorf("expected property name pubKeyHash, got %s", c.Properties[0].Name)
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Go contract verifies methods and visibility
// ---------------------------------------------------------------------------

func TestParseGoContract_MethodVisibility(t *testing.T) {
	source := `
package contracts

import "github.com/icellan/runar/packages/runar-go"

type Checker struct {
	runar.SmartContract
	Target runar.Bigint ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *Checker) Verify(a runar.Bigint, b runar.Bigint) {
	runar.Assert(a + b == c.Target)
}
`
	result := ParseSource([]byte(source), "Checker.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}

	c := result.Contract
	if c == nil {
		t.Fatal("expected non-nil contract")
	}
	if len(c.Methods) < 1 {
		t.Fatal("expected at least 1 method")
	}
	m := c.Methods[0]
	// Exported (capitalized) Go method -> public
	if m.Visibility != "public" {
		t.Errorf("expected method visibility public, got %s", m.Visibility)
	}
	// Method name should be lowered to camelCase: Verify -> verify
	if m.Name != "verify" {
		t.Errorf("expected method name verify, got %s", m.Name)
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Go stateful contract
// ---------------------------------------------------------------------------

func TestParseGoContract_Stateful(t *testing.T) {
	source := `
package contracts

import "github.com/icellan/runar/packages/runar-go"

type Counter struct {
	runar.StatefulSmartContract
	Count runar.Bigint
}

func (c *Counter) Increment() {
	c.Count = c.Count + 1
}
`
	result := ParseSource([]byte(source), "Counter.runar.go")
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
// Test: Parse Go source with no contract struct produces error
// ---------------------------------------------------------------------------

func TestParseGoContract_NoContract_Error(t *testing.T) {
	source := `
package main

type NotAContract struct {
	X int
}
`
	result := ParseSource([]byte(source), "bad.runar.go")
	if result.Contract != nil {
		t.Error("expected nil contract for non-runar struct")
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors when no contract found")
	}
}

// ---------------------------------------------------------------------------
// Test: Parse Go contract with multiple properties
// ---------------------------------------------------------------------------

func TestParseGoContract_MultipleProperties(t *testing.T) {
	source := `
package contracts

import "github.com/icellan/runar/packages/runar-go"

type TwoProps struct {
	runar.SmartContract
	Addr runar.Addr ` + "`" + `runar:"readonly"` + "`" + `
	Key  runar.PubKey ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *TwoProps) Check(x runar.Bigint) {
	runar.Assert(x == 1)
}
`
	result := ParseSource([]byte(source), "TwoProps.runar.go")
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
}

// ---------------------------------------------------------------------------
// Test: runar.Sha256Hash compiles to the sha256 builtin identically to
// runar.Sha256, so Go-mock tests using Sha256Hash (a real function) match
// the Script that runar.Sha256 would emit.
// ---------------------------------------------------------------------------

func TestParseGoContract_Sha256HashMapsToSha256Builtin(t *testing.T) {
	source := `
package contracts

import "github.com/icellan/runar/packages/runar-go"

type H struct {
	runar.SmartContract
	Expected runar.Sha256 ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *H) Check(data runar.ByteString) {
	runar.Assert(runar.Sha256Hash(data) == c.Expected)
}
`
	result := ParseSource([]byte(source), "H.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	if result.Contract == nil || len(result.Contract.Methods) == 0 {
		t.Fatal("expected a contract with at least one method")
	}
	foundSha256Call := false
	for _, stmt := range result.Contract.Methods[0].Body {
		if es, ok := stmt.(ExpressionStmt); ok {
			visitExprForSha256(es.Expr, &foundSha256Call)
		}
	}
	if !foundSha256Call {
		t.Fatal("expected a 'sha256' call in the parsed body from runar.Sha256Hash")
	}
}

func visitExprForSha256(e Expression, found *bool) {
	switch v := e.(type) {
	case CallExpr:
		if ident, ok := v.Callee.(Identifier); ok && ident.Name == "sha256" {
			*found = true
		}
		for _, a := range v.Args {
			visitExprForSha256(a, found)
		}
	case BinaryExpr:
		visitExprForSha256(v.Left, found)
		visitExprForSha256(v.Right, found)
	}
}

// TestParseGoContract_Sha256CallMapsToSha256Builtin is the parallel test for
// the renamed canonical function. `runar.Sha256(x)` used to be a Go
// type-conversion no-op (because Sha256 was a type alias for ByteString);
// it is now a real function in packages/runar-go that returns a real digest,
// and the DSL parser maps the identifier `Sha256` to the `sha256` builtin so
// the compiled Script path (OP_SHA256) and the Go-mock path produce the same
// bytes for the same source expression.
func TestParseGoContract_Sha256CallMapsToSha256Builtin(t *testing.T) {
	source := `
package contracts

import "github.com/icellan/runar/packages/runar-go"

type H struct {
	runar.SmartContract
	Expected runar.Sha256Digest ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *H) Check(data runar.ByteString) {
	runar.Assert(runar.Sha256(data) == c.Expected)
}
`
	result := ParseSource([]byte(source), "H.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	if result.Contract == nil || len(result.Contract.Methods) == 0 {
		t.Fatal("expected a contract with at least one method")
	}
	foundSha256Call := false
	for _, stmt := range result.Contract.Methods[0].Body {
		if es, ok := stmt.(ExpressionStmt); ok {
			visitExprForSha256(es.Expr, &foundSha256Call)
		}
	}
	if !foundSha256Call {
		t.Fatal("expected a 'sha256' call in the parsed body from runar.Sha256")
	}
}

// TestParseGoContract_Sha256DigestTypeRecognised confirms the `Sha256Digest`
// identifier round-trips through the type system as the `Sha256` primitive.
func TestParseGoContract_Sha256DigestTypeRecognised(t *testing.T) {
	source := `
package contracts

import "github.com/icellan/runar/packages/runar-go"

type D struct {
	runar.SmartContract
	Digest runar.Sha256Digest ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *D) Check(data runar.ByteString) {
	runar.Assert(runar.Sha256(data) == c.Digest)
}
`
	result := ParseSource([]byte(source), "D.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	if result.Contract == nil {
		t.Fatal("expected contract")
	}
	var digest *PropertyNode
	for i := range result.Contract.Properties {
		if result.Contract.Properties[i].Name == "digest" {
			digest = &result.Contract.Properties[i]
			break
		}
	}
	if digest == nil {
		t.Fatal("expected 'digest' property")
	}
	prim, ok := digest.Type.(PrimitiveType)
	if !ok {
		t.Fatalf("expected PrimitiveType for digest, got %T", digest.Type)
	}
	if prim.Name != "Sha256" {
		t.Errorf("expected Sha256Digest to map to primitive 'Sha256', got %q", prim.Name)
	}
}
