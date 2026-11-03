package frontend

// N-115 — normalise a reversed loop comparison to the canonical spelling.
//
// Every later pass reads a loop's iterator off the LEFT-hand side of its
// condition (W4, validateForConditionTestsIterator) and its bound off the
// right. `for i := 0; 10 > i; i++` says the same thing as `i < 10`, so the
// parser rewrites it once instead of every pass learning a second spelling:
//
//	N >  i  ->  i <  N        N <  i  ->  i >  N
//	N >= i  ->  i <= N        N <= i  ->  i >= N
//
// The rule, identical in all seven tiers: the condition is a `<`/`<=`/`>`/`>=`
// comparison, its RIGHT operand is the loop variable, and its LEFT operand is
// not -> swap the operands and mirror the operator. Nothing else is touched,
// so the W4 refusals (N40, N41) and the direction rule (N42) keep firing.

var mirroredLoopOp = map[string]string{"<": ">", "<=": ">=", ">": "<", ">=": "<="}

// normalizeLoopCondition returns the canonical form of cond for a loop over
// iter, or cond unchanged.
func normalizeLoopCondition(cond Expression, iter string) Expression {
	bin, ok := cond.(BinaryExpr)
	if !ok {
		return cond
	}
	mirrored, ok := mirroredLoopOp[bin.Op]
	if !ok {
		return cond
	}
	isIter := func(e Expression) bool {
		id, ok := e.(Identifier)
		return ok && id.Name == iter
	}
	if !isIter(bin.Right) || isIter(bin.Left) {
		return cond
	}
	return BinaryExpr{Op: mirrored, Left: bin.Right, Right: bin.Left}
}

func normalizeLoopConditionsIn(stmts []Statement) {
	for i, stmt := range stmts {
		switch s := stmt.(type) {
		case ForStmt:
			s.Condition = normalizeLoopCondition(s.Condition, s.Init.Name)
			normalizeLoopConditionsIn(s.Body)
			stmts[i] = s
		case *ForStmt:
			s.Condition = normalizeLoopCondition(s.Condition, s.Init.Name)
			normalizeLoopConditionsIn(s.Body)
		case IfStmt:
			normalizeLoopConditionsIn(s.Then)
			normalizeLoopConditionsIn(s.Else)
		case *IfStmt:
			normalizeLoopConditionsIn(s.Then)
			normalizeLoopConditionsIn(s.Else)
		}
	}
}

// normalizeLoopConditions rewrites every loop condition in c to its canonical
// spelling.
func normalizeLoopConditions(c *ContractNode) {
	if c == nil {
		return
	}
	normalizeLoopConditionsIn(c.Constructor.Body)
	for _, m := range c.Methods {
		normalizeLoopConditionsIn(m.Body)
	}
}
