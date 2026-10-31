package frontend

import (
	"fmt"
	"go/ast"
	"go/token"
	"reflect"
	"strings"
	"testing"
)

// F-074 / CL-BUG-192 — the .runar.go surface parser must not map an
// unrecognised Go binary operator to `+`.
//
// mapGoOp (parser_gocontract.go) switched over the Go binary tokens it knew
// and fell through to `return "+"`. token.AND_NOT (`&^`, bit clear) had no
// case, so `c.Count = c.Count &^ k` compiled to `c.Count + k`: OP_ADD, no
// diagnostic.
//
// The reference is the TS .runar.go parser (01-parse-go.ts). Its lexer has no
// `&^` token: it reads `&` then `^`, and a prefix `^` is Go's complement, so
// `a &^ b` becomes `a & ~b` — which is exactly Go's definition of bit clear.
// Measured by running the TS compiler and all seven tiers on each of the 19 Go
// binary operators (F-074 remediation log, probe-prefix.txt): the TS reference
// and the Rust, Python, Zig, Ruby and Java .runar.go parsers all lower `&^` to
// `a & ~b`; only the Go tier produced `+`. The other 18 operators agreed
// across every tier.
//
// Proves: the Go .runar.go parser lowers each of the 19 Go binary operators to
// the AST the reference produces (`&^` to `&` over a `~` right operand), and a
// binary token it has no mapping for is a parse error naming the operator,
// not a silent `+`.
// Does not prove: script behaviour (packages/runar-testing/src/__tests__/
// f074-go-dsl-and-not.test.ts runs the compiled script under @bsv/sdk); the
// operator precedence of `&^` inside larger expressions, where go/ast uses Go
// precedence and the TS parser uses TypeScript precedence for every bitwise
// operator (a pre-existing, separate divergence).

func f074Source(expr string) string {
	return fmt.Sprintf(`package contract

import runar "github.com/icellan/runar/packages/runar-go"

type OpProbe struct {
	runar.StatefulSmartContract
	Count runar.Bigint
}

func (c *OpProbe) Step(k runar.Bigint) {
	c.Count = %s
}
`, expr)
}

func f074AssignedValue(t *testing.T, expr string) Expression {
	t.Helper()
	result := ParseGoContract([]byte(f074Source(expr)), "OpProbe.runar.go")
	if len(result.Errors) > 0 {
		t.Fatalf("%s: unexpected parse errors: %v", expr, result.Errors)
	}
	for _, m := range result.Contract.Methods {
		if m.Name != "step" {
			continue
		}
		assign, ok := m.Body[0].(AssignmentStmt)
		if !ok {
			t.Fatalf("%s: expected AssignmentStmt, got %T", expr, m.Body[0])
		}
		return assign.Value
	}
	t.Fatalf("%s: method step not found", expr)
	return nil
}

func TestF074_GoDSL_AndNotLowersToAndOfComplement(t *testing.T) {
	got := f074AssignedValue(t, "c.Count &^ k")
	want := BinaryExpr{
		Op:    "&",
		Left:  PropertyAccessExpr{Property: "count"},
		// N-464: an identifier carries its token's position on every surface
		// (line 11 is `\tc.Count = c.Count &^ k`; `k` is at column 22).
		Right: UnaryExpr{Op: "~", Operand: Identifier{Name: "k", SourceLocation: SourceLocation{File: "OpProbe.runar.go", Line: 11, Column: 22}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("c.Count &^ k lowered to %#v, want %#v (the reference's c.Count & ~k)", got, want)
	}
}

func TestF074_GoDSL_EveryBinaryOperatorMatchesReference(t *testing.T) {
	cases := map[string]string{
		"+": "+", "-": "-", "*": "*", "/": "/", "%": "%",
		"&": "&", "|": "|", "^": "^", "<<": "<<", ">>": ">>",
		"==": "===", "!=": "!==", "<": "<", "<=": "<=", ">": ">", ">=": ">=",
		"&&": "&&", "||": "||",
	}
	for goOp, want := range cases {
		t.Run(goOp, func(t *testing.T) {
			got := f074AssignedValue(t, "c.Count "+goOp+" k")
			bin, ok := got.(BinaryExpr)
			if !ok {
				t.Fatalf("%s: expected BinaryExpr, got %T", goOp, got)
			}
			if bin.Op != want {
				t.Errorf("%s: lowered to %q, want %q", goOp, bin.Op, want)
			}
		})
	}
}

// go/parser only builds a BinaryExpr from the tokens above, so the fallback
// is reached here with a hand-built node: the parser must refuse it rather
// than pick an operator.
func TestF074_GoDSL_UnmappedBinaryOperatorRefused(t *testing.T) {
	p := &goContractParser{fset: token.NewFileSet(), fileName: "OpProbe.runar.go"}
	got := p.convertExpression(&ast.BinaryExpr{
		X:  &ast.Ident{Name: "a"},
		Op: token.ARROW,
		Y:  &ast.Ident{Name: "b"},
	})
	if got != nil {
		t.Fatalf("unmapped operator %q converted to %#v, want a refusal", token.ARROW, got)
	}
	want := "Unsupported binary operator: '<-'"
	for _, e := range p.errors {
		if strings.Contains(e.Message, want) {
			return
		}
	}
	t.Fatalf("expected parse error %q, got errors %v", want, p.errors)
}
