package frontend

import "fmt"

// N-342 — a `const` local on the `.runar.ts` surface cannot be reassigned.
//
// spec/grammar.md §9: "`const` variables cannot be reassigned." The parser
// recorded Mutable=false for `const` and nothing ever read it, so
// `const s = 1n; s = s + x;` compiled. Refused, with one sentence in all
// seven tiers: `x = e` (and the compound forms the parser desugars to it),
// `x++` / `++x` / `x--` / `--x`, and a `const` for-initializer, which the
// loop's own `i++` then advances. Element writes (`x[0] = e`) are not touched.
// Scoping follows blocks. Runs on the `.runar.ts` parse result only: other
// surfaces spell immutability differently and several parsers record
// Mutable as a constant.

// ConstReassignMessage is the shared diagnostic for reassigning const `name`.
func ConstReassignMessage(name string) string {
	return fmt.Sprintf("Cannot assign to '%s' because it is a constant.", name)
}

type constScope map[string]bool

func constLookup(scopes []constScope, name string) (mutable bool, found bool) {
	for i := len(scopes) - 1; i >= 0; i-- {
		if m, ok := scopes[i][name]; ok {
			return m, true
		}
	}
	return false, false
}

func constCheckTarget(target Expression, scopes []constScope, loc SourceLocation, out *[]Diagnostic) {
	var name string
	switch t := target.(type) {
	case Identifier:
		name = t.Name
	case *Identifier:
		name = t.Name
	default:
		return
	}
	if m, ok := constLookup(scopes, name); ok && !m {
		l := loc
		*out = append(*out, MakeDiagnostic(ConstReassignMessage(name), SeverityError, &l))
	}
}

func constCheckExpr(e Expression, scopes []constScope, loc SourceLocation, out *[]Diagnostic) {
	switch x := e.(type) {
	case IncrementExpr:
		constCheckTarget(x.Operand, scopes, loc, out)
	case *IncrementExpr:
		constCheckTarget(x.Operand, scopes, loc, out)
	case DecrementExpr:
		constCheckTarget(x.Operand, scopes, loc, out)
	case *DecrementExpr:
		constCheckTarget(x.Operand, scopes, loc, out)
	}
}

func constCheckStmt(stmt Statement, scopes []constScope, out *[]Diagnostic) {
	switch s := stmt.(type) {
	case AssignmentStmt:
		constCheckTarget(s.Target, scopes, s.SourceLocation, out)
	case *AssignmentStmt:
		constCheckTarget(s.Target, scopes, s.SourceLocation, out)
	case ExpressionStmt:
		constCheckExpr(s.Expr, scopes, s.SourceLocation, out)
	case *ExpressionStmt:
		constCheckExpr(s.Expr, scopes, s.SourceLocation, out)
	}
}

func constWalk(stmts []Statement, scopes []constScope, out *[]Diagnostic) {
	here := constScope{}
	scopes = append(scopes, here)
	for _, stmt := range stmts {
		switch s := stmt.(type) {
		case VariableDeclStmt:
			here[s.Name] = s.Mutable
		case *VariableDeclStmt:
			here[s.Name] = s.Mutable
		case IfStmt:
			constWalk(s.Then, scopes, out)
			constWalk(s.Else, scopes, out)
		case *IfStmt:
			constWalk(s.Then, scopes, out)
			constWalk(s.Else, scopes, out)
		case ForStmt:
			constWalkFor(s, scopes, out)
		case *ForStmt:
			constWalkFor(*s, scopes, out)
		default:
			constCheckStmt(stmt, scopes, out)
		}
	}
}

func constWalkFor(s ForStmt, scopes []constScope, out *[]Diagnostic) {
	loop := constScope{s.Init.Name: s.Init.Mutable}
	inner := append(scopes, loop)
	if s.Update != nil {
		constCheckStmt(s.Update, inner, out)
	}
	constWalk(s.Body, inner, out)
}

// checkConstReassignment returns a diagnostic for every reassigned const local.
func checkConstReassignment(c *ContractNode) []Diagnostic {
	if c == nil {
		return nil
	}
	var out []Diagnostic
	constWalk(c.Constructor.Body, nil, &out)
	for _, m := range c.Methods {
		constWalk(m.Body, nil, &out)
	}
	return out
}
