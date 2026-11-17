package frontend

import (
	"fmt"
	"math/big"
)

var bigFour = big.NewInt(4)

// R2-MSM-UNBOUND: a method calling assertGroth16WitnessAssistedWithMSM() must
// bind the statement the proof is about.
//
// The MSM preamble ties the prover-supplied prepared_inputs to the five
// witness scalars pub_0..pub_4, but the scalars themselves are the spender's
// choice. Unless something fixes at least one of them, the script accepts an
// honest proof of ANY statement the spender can prove. Two things count:
//
//  1. the vk.json the contract is compiled with pins at least one slot
//     (pinnedPublicInputs; TypeCheckOptions.Groth16WAStatementPinned), or
//  2. a TOP-LEVEL statement of the same method (not inside an if or a loop,
//     not in a private helper) of the exact form
//
//     assert(groth16PublicInput(K) == F)   or   assert(F == groth16PublicInput(K))
//
//     with K an integer literal in [0, 4] and F a fixed expression: integer,
//     boolean and byte-string literals, reads of READONLY contract
//     properties (this.x; a mutable property can be assigned from a
//     parameter first), unary / binary operators over fixed operands and
//     built-in function calls with at least one argument, all fixed. A method
//     parameter, a local, another groth16PublicInput, an intent intrinsic
//     (extractPrevOutputScript / requireOutputP2PKH, which read an
//     auto-injected unlocking parameter), `this.method()` and anything else
//     make F not fixed.
//
// Everything else is refused (fail closed): `!=`, `<`, a conjunct of `&&`,
// a comparison bound to a local first, a check on one branch. The rule is
// mirrored on the ANF in codegen (groth16WAStatementBoundInBody) for --ir
// input; that copy follows locals through their bindings, so it accepts a
// superset of what this one does and never refuses a program this accepts.
// The standalone CompileGroth16WA backend keeps its own check
// (validateGroth16PublicInputs).

// Groth16WAUnboundStatementMessage is the diagnostic for a method that calls
// assertGroth16WitnessAssistedWithMSM() and binds no public input. The stack
// lowering's --ir copy uses the same text.
func Groth16WAUnboundStatementMessage(method string) string {
	return fmt.Sprintf("method '%s' calls assertGroth16WitnessAssistedWithMSM() but does not bind the proved statement: "+
		"the five public inputs are the spender's choice, so the verifier would accept an honest proof of any statement. "+
		"Pin at least one slot with pinnedPublicInputs in the --groth16-wa-vk vk.json, or add a top-level "+
		"assert(groth16PublicInput(i) == <value>) to the method, where <value> is built from literals and readonly "+
		"contract properties only (no method parameter, local, mutable property or other groth16PublicInput)", method)
}

// checkGroth16WAStatementBound returns one diagnostic per method that calls
// the MSM marker without binding the statement. pinned reports whether the
// vk.json pins a slot (which binds every method at once).
func checkGroth16WAStatementBound(contract *ContractNode, pinned bool) []Diagnostic {
	if pinned {
		return nil
	}
	props := make(map[string]bool, len(contract.Properties))
	for _, p := range contract.Properties {
		// Only readonly properties are fixed: a mutable one can be assigned
		// from a parameter before the assert (fail closed: even an
		// unassigned state read does not count).
		if p.Readonly {
			props[p.Name] = true
		}
	}
	var out []Diagnostic
	for _, m := range contract.Methods {
		if !stmtsCallFunc(m.Body, "assertGroth16WitnessAssistedWithMSM") {
			continue
		}
		bound := false
		for _, st := range m.Body {
			if groth16WABindingAssert(st, props) {
				bound = true
				break
			}
		}
		if !bound {
			out = append(out, MakeDiagnostic(Groth16WAUnboundStatementMessage(m.Name), SeverityError, &m.SourceLocation))
		}
	}
	return out
}

// groth16WABindingAssert reports whether st is assert(groth16PublicInput(K) == F)
// (either operand order) with F fixed.
func groth16WABindingAssert(st Statement, props map[string]bool) bool {
	es, ok := st.(ExpressionStmt)
	if !ok {
		return false
	}
	call, ok := es.Expr.(CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	if id, ok := call.Callee.(Identifier); !ok || id.Name != "assert" {
		return false
	}
	eq, ok := call.Args[0].(BinaryExpr)
	if !ok || (eq.Op != "===" && eq.Op != "==") {
		return false
	}
	return (isGroth16PublicInputRead(eq.Left) && isFixedExpr(eq.Right, props)) ||
		(isGroth16PublicInputRead(eq.Right) && isFixedExpr(eq.Left, props))
}

// isGroth16PublicInputRead: groth16PublicInput(K), K an integer literal in [0, 4].
func isGroth16PublicInputRead(e Expression) bool {
	call, ok := e.(CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	if id, ok := call.Callee.(Identifier); !ok || id.Name != "groth16PublicInput" {
		return false
	}
	lit, ok := call.Args[0].(BigIntLiteral)
	return ok && lit.Value != nil && lit.Value.Sign() >= 0 && lit.Value.Cmp(bigFour) <= 0
}

// isFixedExpr: e depends on nothing the spender chooses (see the rule above).
func isFixedExpr(e Expression, props map[string]bool) bool {
	switch v := e.(type) {
	case BigIntLiteral, BoolLiteral, ByteStringLiteral:
		return true
	case PropertyAccessExpr:
		return props[v.Property]
	case UnaryExpr:
		return isFixedExpr(v.Operand, props)
	case BinaryExpr:
		return isFixedExpr(v.Left, props) && isFixedExpr(v.Right, props)
	case CallExpr:
		id, ok := v.Callee.(Identifier)
		if !ok || len(v.Args) == 0 || id.Name == "groth16PublicInput" {
			return false
		}
		// Intent intrinsics lower to an auto-injected unlocking parameter
		// (extractPrevOutputScript reads _prevOutScript_<i>, the script of an
		// input the spender picks); the ANF copy sees that load_param and
		// refuses, so the frontend must too.
		if id.Name == "extractPrevOutputScript" || id.Name == "requireOutputP2PKH" {
			return false
		}
		if _, builtin := builtinFunctions[id.Name]; !builtin {
			return false
		}
		for _, a := range v.Args {
			if !isFixedExpr(a, props) {
				return false
			}
		}
		return true
	}
	return false
}

// stmtsCallFunc reports whether any statement, at any if / loop depth, calls
// the bare built-in name anywhere in its expressions.
func stmtsCallFunc(stmts []Statement, name string) bool {
	for _, st := range stmts {
		switch s := st.(type) {
		case ExpressionStmt:
			if exprCallsFunc(s.Expr, name) {
				return true
			}
		case VariableDeclStmt:
			if exprCallsFunc(s.Init, name) {
				return true
			}
		case AssignmentStmt:
			if exprCallsFunc(s.Value, name) {
				return true
			}
		case ReturnStmt:
			if s.Value != nil && exprCallsFunc(s.Value, name) {
				return true
			}
		case IfStmt:
			if exprCallsFunc(s.Condition, name) || stmtsCallFunc(s.Then, name) || stmtsCallFunc(s.Else, name) {
				return true
			}
		case ForStmt:
			if stmtsCallFunc(s.Body, name) {
				return true
			}
		}
	}
	return false
}

func exprCallsFunc(e Expression, name string) bool {
	switch v := e.(type) {
	case CallExpr:
		if id, ok := v.Callee.(Identifier); ok && id.Name == name {
			return true
		}
		if exprCallsFunc(v.Callee, name) {
			return true
		}
		for _, a := range v.Args {
			if exprCallsFunc(a, name) {
				return true
			}
		}
	case BinaryExpr:
		return exprCallsFunc(v.Left, name) || exprCallsFunc(v.Right, name)
	case UnaryExpr:
		return exprCallsFunc(v.Operand, name)
	case TernaryExpr:
		return exprCallsFunc(v.Condition, name) || exprCallsFunc(v.Consequent, name) || exprCallsFunc(v.Alternate, name)
	case MemberExpr:
		return exprCallsFunc(v.Object, name)
	case IndexAccessExpr:
		return exprCallsFunc(v.Object, name) || exprCallsFunc(v.Index, name)
	case ArrayLiteralExpr:
		for _, el := range v.Elements {
			if exprCallsFunc(el, name) {
				return true
			}
		}
	}
	return false
}
