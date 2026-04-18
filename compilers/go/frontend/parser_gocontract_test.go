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

// TestParseGoContract_BigintBigTypeIsBigint confirms that `runar.BigintBig`
// (the big.Int-backed arithmetic type in the mock runtime) maps to the same
// AST primitive as `runar.Bigint` in the DSL parser. This lets contracts
// declare a `BigintBig` property and perform arithmetic / comparison against
// ordinary `Bigint` values without any typecheck friction.
func TestParseGoContract_BigintBigTypeIsBigint(t *testing.T) {
	source := `
package contracts

import "github.com/icellan/runar/packages/runar-go"

type BigMath struct {
	runar.SmartContract
	Target runar.BigintBig ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *BigMath) Check(a runar.Bigint, b runar.BigintBig) {
	runar.Assert(a + b == c.Target)
}
`
	result := ParseSource([]byte(source), "BigMath.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	c := result.Contract
	if c == nil {
		t.Fatal("expected contract")
	}

	// Property must be a bigint primitive
	var target *PropertyNode
	for i := range c.Properties {
		if c.Properties[i].Name == "target" {
			target = &c.Properties[i]
			break
		}
	}
	if target == nil {
		t.Fatal("expected 'target' property")
	}
	prim, ok := target.Type.(PrimitiveType)
	if !ok {
		t.Fatalf("expected PrimitiveType for target, got %T", target.Type)
	}
	if prim.Name != "bigint" {
		t.Errorf("expected BigintBig to map to primitive 'bigint', got %q", prim.Name)
	}

	// Method params: second arg is runar.BigintBig — must also be bigint
	if len(c.Methods) == 0 {
		t.Fatal("expected method")
	}
	m := c.Methods[0]
	if len(m.Params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(m.Params))
	}
	pp, ok := m.Params[1].Type.(PrimitiveType)
	if !ok || pp.Name != "bigint" {
		t.Errorf("expected BigintBig param to map to primitive 'bigint', got %v", m.Params[1].Type)
	}
}

// TestParseGoContract_ByteStringLiteral confirms that
// `runar.ByteString("\x00\x6a")` in a `.runar.go` source becomes a
// ByteStringLiteral whose hex value represents the raw bytes of the string.
func TestParseGoContract_ByteStringLiteral(t *testing.T) {
	source := `
package contracts

import "github.com/icellan/runar/packages/runar-go"

type LitDemo struct {
	runar.SmartContract
	Expected runar.ByteString ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *LitDemo) Check() {
	runar.Assert(runar.ByteString("\x00\x6a") == c.Expected)
}
`
	result := ParseSource([]byte(source), "LitDemo.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	c := result.Contract
	if c == nil || len(c.Methods) == 0 {
		t.Fatal("expected contract + method")
	}
	// Walk the first method body and find the BinaryExpr's left operand.
	var found *ByteStringLiteral
	for _, stmt := range c.Methods[0].Body {
		visitForByteStringLit(stmt, &found)
	}
	if found == nil {
		t.Fatal("expected a ByteStringLiteral in method body")
	}
	if found.Value != "006a" {
		t.Errorf("expected ByteStringLiteral value '006a', got %q", found.Value)
	}
}

// TestParseGoContract_ByteStringOfVariableUnwraps confirms
// `runar.ByteString(existingVar)` is still treated as a no-op type conversion.
func TestParseGoContract_ByteStringOfVariableUnwraps(t *testing.T) {
	source := `
package contracts

import "github.com/icellan/runar/packages/runar-go"

type VarDemo struct {
	runar.SmartContract
	Expected runar.ByteString ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *VarDemo) Check(data runar.ByteString) {
	runar.Assert(runar.ByteString(data) == c.Expected)
}
`
	result := ParseSource([]byte(source), "VarDemo.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	c := result.Contract
	if c == nil || len(c.Methods) == 0 {
		t.Fatal("expected contract + method")
	}
	// The left side of the == should be a plain Identifier(data), not a
	// CallExpr. This proves the ByteString(variable) was unwrapped.
	var sawPlainIdent bool
	for _, stmt := range c.Methods[0].Body {
		es, ok := stmt.(ExpressionStmt)
		if !ok {
			continue
		}
		walkForPlainByteStringIdent(es.Expr, &sawPlainIdent)
	}
	if !sawPlainIdent {
		t.Fatalf("expected runar.ByteString(data) to unwrap to an Identifier 'data'")
	}
}

func visitForByteStringLit(node interface{}, out **ByteStringLiteral) {
	switch v := node.(type) {
	case ExpressionStmt:
		visitForByteStringLit(v.Expr, out)
	case CallExpr:
		for _, a := range v.Args {
			visitForByteStringLit(a, out)
		}
	case BinaryExpr:
		visitForByteStringLit(v.Left, out)
		visitForByteStringLit(v.Right, out)
	case ByteStringLiteral:
		lit := v
		*out = &lit
	}
}

func walkForPlainByteStringIdent(e Expression, found *bool) {
	switch v := e.(type) {
	case CallExpr:
		// We should NOT see a call whose callee is identifier "byteString".
		if ident, ok := v.Callee.(Identifier); ok && ident.Name == "byteString" {
			return
		}
		for _, a := range v.Args {
			walkForPlainByteStringIdent(a, found)
		}
	case BinaryExpr:
		if id, ok := v.Left.(Identifier); ok && id.Name == "data" {
			*found = true
		}
		walkForPlainByteStringIdent(v.Left, found)
		walkForPlainByteStringIdent(v.Right, found)
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

// TestParseGoContract_Bn254BigHelpersResolve confirms that the *Big-suffixed
// BN254 wrappers (Bn254MultiPairing4Big / Bn254G1ScalarMulBigP / etc.) are
// registered in the DSL builtin map so contracts that adopt BigintBig fields
// can call them directly. All *Big variants lower to the same Script builtin
// as their int64 counterparts (the Script encoding is identical; only the
// Go-mock runtime differs).
func TestParseGoContract_Bn254BigHelpersResolve(t *testing.T) {
	source := `
package contracts

import runar "github.com/icellan/runar/packages/runar-go"

type BigPairing struct {
	runar.SmartContract
}

func (c *BigPairing) Check(
	p1 runar.Point, q1x0, q1x1, q1y0, q1y1 runar.BigintBig,
	p2 runar.Point, q2x0, q2x1, q2y0, q2y1 runar.BigintBig,
	p3 runar.Point, q3x0, q3x1, q3y0, q3y1 runar.BigintBig,
	p4 runar.Point, q4x0, q4x1, q4y0, q4y1 runar.BigintBig,
	scalar runar.BigintBig,
) {
	scaled := runar.Bn254G1ScalarMulBigP(p1, scalar)
	summed := runar.Bn254G1AddBigP(scaled, p2)
	runar.Assert(runar.Bn254G1OnCurveBigP(summed))
	runar.Assert(runar.Bn254MultiPairing4Big(
		p1, q1x0, q1x1, q1y0, q1y1,
		p2, q2x0, q2x1, q2y0, q2y1,
		p3, q3x0, q3x1, q3y0, q3y1,
		p4, q4x0, q4x1, q4y0, q4y1,
	))
}
`
	result := ParseSource([]byte(source), "BigPairing.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	if result.Contract == nil || len(result.Contract.Methods) == 0 {
		t.Fatal("expected a contract with at least one method")
	}

	// Walk the body and record every top-level call identifier.
	callNames := map[string]bool{}
	var walk func(e Expression)
	walk = func(e Expression) {
		if c, ok := e.(CallExpr); ok {
			if ident, ok := c.Callee.(Identifier); ok {
				callNames[ident.Name] = true
			}
			for _, a := range c.Args {
				walk(a)
			}
		}
	}
	for _, stmt := range result.Contract.Methods[0].Body {
		switch s := stmt.(type) {
		case ExpressionStmt:
			walk(s.Expr)
		case VariableDeclStmt:
			if s.Init != nil {
				walk(s.Init)
			}
		}
	}

	// Each *Big wrapper lowers to the same builtin as its int64 counterpart.
	for _, expected := range []string{
		"bn254G1ScalarMul",
		"bn254G1Add",
		"bn254G1OnCurve",
		"bn254MultiPairing4",
	} {
		if !callNames[expected] {
			t.Errorf("expected a %q call in the parsed body; got %v", expected, callNames)
		}
	}
}
