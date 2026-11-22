package frontend

// promoteTailReturns is N-511's parser step for the surfaces whose trailing
// expression IS the value (.runar.move with a declared return type, .runar.rb
// private helpers): the trailing expression statement becomes an explicit
// return, recursively through the arms of a trailing if/else
// (`if c { x } else { 0 }`). The return keeps the expression statement's own
// source location, so the lowered ANF is unchanged; the type checker then
// needs no tail-value heuristic. intoArms=false promotes only the top level.
func promoteTailReturns(stmts []Statement, intoArms bool) {
	if len(stmts) == 0 {
		return
	}
	switch last := stmts[len(stmts)-1].(type) {
	case ExpressionStmt:
		stmts[len(stmts)-1] = ReturnStmt{Value: last.Expr, SourceLocation: last.SourceLocation}
	case IfStmt:
		if intoArms && last.Else != nil {
			promoteTailReturns(last.Then, true)
			promoteTailReturns(last.Else, true)
		}
	}
}

// hasValueReturn reports whether a `return <value>` appears anywhere in the
// list (N-511).
func hasValueReturn(stmts []Statement) bool {
	for _, s := range stmts {
		switch st := s.(type) {
		case ReturnStmt:
			if st.Value != nil {
				return true
			}
		case IfStmt:
			if hasValueReturn(st.Then) || hasValueReturn(st.Else) {
				return true
			}
		case ForStmt:
			if hasValueReturn(st.Body) {
				return true
			}
		}
	}
	return false
}
