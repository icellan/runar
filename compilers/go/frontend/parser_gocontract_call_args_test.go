package frontend

import (
	"strings"
	"testing"
)

// A call argument the Go DSL parser cannot convert must be REJECTED, not
// dropped.
//
// convertExpression returns nil for every expression form it does not
// understand. Every other consumer of that nil treats it as a hard failure:
// BinaryExpr / UnaryExpr / the statement converters all return nil in turn,
// and extractStatements turns a nil statement into an "unsupported Go
// statement" diagnostic. The *ast.CallExpr arm was the one exception — it
// appended only the non-nil arguments and returned a perfectly well-formed
// CallExpr with fewer arguments than the source wrote.
//
// For a fixed-arity builtin the typechecker later caught the shortfall, but
// with a misleading message ("expects 2 argument(s), got 1" — the developer
// wrote 2). For a VARIABLE-arity builtin nothing caught it at all:
// extractPrevOutputScript accepts a 2-arg full-hash form and a 3-arg
// prefix-hash form, so a bad third argument silently downgraded the call to
// the other overload and compiled clean. Measured on the repro below before
// the fix: zero parse errors, zero validation errors, zero typecheck errors,
// and a two-argument extractPrevOutputScript in the AST.
//
// The same arm left Callee unguarded: a call whose callee did not convert
// produced CallExpr{Callee: nil}, which lowered to a nonsense
// load_const 0 / method_call ".call" pair.

// Three arguments in the source; the third is a slice expression, which the
// Go DSL does not support. Before the fix this became the two-argument
// overload with no diagnostic at all.
const goDroppedArgSrc = `package contracts

import "github.com/icellan/runar/packages/runar-go"

type Prev struct {
	runar.SmartContract
	Expected runar.ByteString ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *Prev) Spend(raw runar.ByteString) {
	runar.Assert(runar.ExtractPrevOutputScript(0, c.Expected, raw[0:4]) == c.Expected)
}
`

// Fixed-arity variant: max() written with two arguments, the second of which
// does not convert. Before the fix the parser emitted max(a).
const goDroppedArgFixedAritySrc = `package contracts

import "github.com/icellan/runar/packages/runar-go"

type Dropper struct {
	runar.SmartContract
	Target runar.Bigint ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *Dropper) Spend(a runar.Bigint, b runar.ByteString) {
	runar.Assert(runar.Max(a, b[1:3]) == c.Target)
}
`

// A function-literal callee does not convert, so Callee came out nil.
const goNilCalleeSrc = `package contracts

import "github.com/icellan/runar/packages/runar-go"

type NilCallee struct {
	runar.SmartContract
	Target runar.Bigint ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *NilCallee) Spend(a runar.Bigint) {
	runar.Assert(func() runar.Bigint { return a }() == c.Target)
}
`

// Control: every expression form here is supported. It must keep parsing
// with zero diagnostics and with every call at the arity the source wrote —
// the three-argument prefix-hash overload must survive as three arguments.
const goSupportedCallsSrc = `package contracts

import "github.com/icellan/runar/packages/runar-go"

type Control struct {
	runar.SmartContract
	Expected runar.ByteString ` + "`" + `runar:"readonly"` + "`" + `
	Target   runar.Bigint     ` + "`" + `runar:"readonly"` + "`" + `
}

func (c *Control) helper(x runar.Bigint, y runar.Bigint) runar.Bigint {
	return x + y
}

func (c *Control) Spend(a runar.Bigint, b runar.Bigint) {
	runar.Assert(runar.ExtractPrevOutputScript(0, c.Expected, 32) == c.Expected)
	runar.Assert(runar.Max(a, b) == c.Target)
	runar.Assert(c.helper(a, b) == c.Target)
}
`

// ---------------------------------------------------------------------------
// Walkers — collect every CallExpr reachable from a parsed contract.
// ---------------------------------------------------------------------------

func collectCallExprs(contract *ContractNode) []CallExpr {
	var out []CallExpr
	if contract == nil {
		return out
	}
	var walkExpr func(Expression)
	var walkStmts func([]Statement)

	walkExpr = func(e Expression) {
		switch n := e.(type) {
		case nil:
			return
		case CallExpr:
			out = append(out, n)
			walkExpr(n.Callee)
			for _, a := range n.Args {
				walkExpr(a)
			}
		case BinaryExpr:
			walkExpr(n.Left)
			walkExpr(n.Right)
		case UnaryExpr:
			walkExpr(n.Operand)
		case TernaryExpr:
			walkExpr(n.Condition)
			walkExpr(n.Consequent)
			walkExpr(n.Alternate)
		case MemberExpr:
			walkExpr(n.Object)
		case IndexAccessExpr:
			walkExpr(n.Object)
			walkExpr(n.Index)
		case IncrementExpr:
			walkExpr(n.Operand)
		case DecrementExpr:
			walkExpr(n.Operand)
		case ArrayLiteralExpr:
			for _, el := range n.Elements {
				walkExpr(el)
			}
		}
	}

	walkStmts = func(stmts []Statement) {
		for _, s := range stmts {
			switch n := s.(type) {
			case ExpressionStmt:
				walkExpr(n.Expr)
			case VariableDeclStmt:
				walkExpr(n.Init)
			case AssignmentStmt:
				walkExpr(n.Target)
				walkExpr(n.Value)
			case ReturnStmt:
				walkExpr(n.Value)
			case IfStmt:
				walkExpr(n.Condition)
				walkStmts(n.Then)
				walkStmts(n.Else)
			case ForStmt:
				walkExpr(n.Condition)
				walkStmts(n.Body)
				if n.Update != nil {
					walkStmts([]Statement{n.Update})
				}
			}
		}
	}

	for _, m := range contract.Methods {
		walkStmts(m.Body)
	}
	return out
}

func calleeName(c CallExpr) string {
	switch n := c.Callee.(type) {
	case Identifier:
		return n.Name
	case PropertyAccessExpr:
		return n.Property
	}
	return ""
}

// anfCallFuncs returns the Func of every `call` binding the ANF lowering
// produces, so the test can prove the malformed call never reaches lowering
// rather than only that a diagnostic was printed somewhere.
func anfCallFuncs(t *testing.T, contract *ContractNode) []string {
	t.Helper()
	var out []string
	if contract == nil {
		return out
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ANF lowering panicked: %v", r)
		}
	}()
	program := LowerToANF(contract)
	if program == nil {
		return out
	}
	for _, m := range program.Methods {
		for _, b := range m.Body {
			if b.Value.Kind == "call" {
				out = append(out, b.Value.Func)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// The variable-arity case: nothing downstream can catch this one, so the
// parser must.
func TestGoParser_DroppedCallArgument_VariableArityIsRejected(t *testing.T) {
	result := ParseSource([]byte(goDroppedArgSrc), "Prev.runar.go")

	if len(result.Errors) == 0 {
		t.Fatalf("expected a parse diagnostic for the unsupported slice argument, got none")
	}
	joined := strings.Join(result.ErrorStrings(), "; ")
	if !strings.Contains(joined, "Prev.runar.go:11:") {
		t.Errorf("expected a diagnostic carrying file:line:column for the bad argument, got: %s", joined)
	}

	// Arity half: the two-argument full-hash overload must NOT exist.
	for _, c := range collectCallExprs(result.Contract) {
		if calleeName(c) == "extractPrevOutputScript" {
			t.Fatalf("extractPrevOutputScript survived in the AST with %d arguments; "+
				"the source wrote 3 and the third did not convert", len(c.Args))
		}
	}
	for _, fn := range anfCallFuncs(t, result.Contract) {
		if fn == "extractPrevOutputScript" {
			t.Fatalf("extractPrevOutputScript reached ANF lowering despite the rejected argument")
		}
	}
}

// The fixed-arity case: the typechecker did report something, but only after
// the parser had already rewritten the call. The parser must reject it, and
// the short call must not survive into the AST.
func TestGoParser_DroppedCallArgument_FixedArityIsRejected(t *testing.T) {
	result := ParseSource([]byte(goDroppedArgFixedAritySrc), "Dropper.runar.go")

	if len(result.Errors) == 0 {
		t.Fatalf("expected a parse diagnostic for the unsupported slice argument, got none")
	}
	joined := strings.Join(result.ErrorStrings(), "; ")
	if !strings.Contains(joined, "Dropper.runar.go:11:") {
		t.Errorf("expected a diagnostic carrying file:line:column for the bad argument, got: %s", joined)
	}

	for _, c := range collectCallExprs(result.Contract) {
		if calleeName(c) == "max" && len(c.Args) != 2 {
			t.Fatalf("max() survived in the AST with %d arguments; the source wrote 2", len(c.Args))
		}
	}
	for _, fn := range anfCallFuncs(t, result.Contract) {
		if fn == "max" {
			t.Fatalf("max() reached ANF lowering despite the rejected argument")
		}
	}
}

// The nil-Callee half of the finding.
func TestGoParser_NilCalleeIsRejected(t *testing.T) {
	result := ParseSource([]byte(goNilCalleeSrc), "NilCallee.runar.go")

	if len(result.Errors) == 0 {
		t.Fatalf("expected a parse diagnostic for the unsupported call target, got none")
	}
	joined := strings.Join(result.ErrorStrings(), "; ")
	if !strings.Contains(joined, "NilCallee.runar.go:11:") {
		t.Errorf("expected a diagnostic carrying file:line:column for the bad callee, got: %s", joined)
	}

	for _, c := range collectCallExprs(result.Contract) {
		if c.Callee == nil {
			t.Fatalf("a CallExpr with a nil Callee survived into the AST")
		}
	}
	// Must not panic on the way to lowering either.
	anfCallFuncs(t, result.Contract)
}

// Control: supported forms are untouched, at the arity the source wrote.
func TestGoParser_SupportedCallFormsUnaffected(t *testing.T) {
	result := ParseSource([]byte(goSupportedCallsSrc), "Control.runar.go")

	if len(result.Errors) > 0 {
		t.Fatalf("control contract must parse cleanly, got: %s", strings.Join(result.ErrorStrings(), "; "))
	}
	if result.Contract == nil {
		t.Fatal("control contract produced no ContractNode")
	}
	if diags := Validate(result.Contract); len(diags.Errors) > 0 {
		t.Fatalf("control contract must validate cleanly, got: %v", diags.ErrorStrings())
	}
	if tc := TypeCheck(result.Contract); len(tc.Errors) > 0 {
		t.Fatalf("control contract must typecheck cleanly, got: %v", tc.ErrorStrings())
	}

	want := map[string]int{
		"extractPrevOutputScript": 3,
		"max":                     2,
		"helper":                  2,
	}
	seen := map[string]bool{}
	for _, c := range collectCallExprs(result.Contract) {
		name := calleeName(c)
		if n, ok := want[name]; ok {
			seen[name] = true
			if len(c.Args) != n {
				t.Errorf("%s(): expected %d arguments, got %d", name, n, len(c.Args))
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("%s() did not survive into the AST at all", name)
		}
	}
}
