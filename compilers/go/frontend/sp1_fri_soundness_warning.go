package frontend

// Compile-time refusal of the SP1 FRI verifier (F-007 / CL-BUG-037).
//
// `EmitFullSP1FriVerifierBody` binds only the Fiat-Shamir transcript and the
// grinding witnesses. It never emits the per-query MMCS openings, the FRI fold
// / colinearity chain, the final-poly equality, or the Steps 6/7 out-of-domain
// constraint check, so it cannot tell a valid proof from a forged one. It used
// to end in OP_1 and ACCEPT a proof whose every per-query opening was garbage.
//
// For v1 the verifier is not implemented: the emitted body is fail-closed
// (OP_0 OP_VERIFY, it can never accept) and every compile that reaches
// verifySP1FRI is refused, on the source path here and on the --ir path in
// compiler/sp1_fri_ir_guard.go. There is no override: the old
// `@acknowledgeUnsoundSP1FriVerifier` directive and
// `--acknowledge-unsound-sp1-fri` flag were removed. The post-v1 plan is in
// docs/sp1-fri-verifier.md.

// SP1FriNotImplementedError is the refusal both entry points return.
const SP1FriNotImplementedError = "verifySP1FRI: REFUSING to compile — the SP1 FRI verifier is not " +
	"implemented for v1. The emitted body checks only the Fiat-Shamir transcript and grinding " +
	"witnesses; the per-query MMCS openings, the FRI fold/colinearity chain, the final-poly equality " +
	"and the Steps 6/7 out-of-domain constraint check are not emitted, so the body is fail-closed " +
	"and can never accept a spend. There is no override. See docs/sp1-fri-verifier.md."

// contractCallsSP1FriVerifier reports whether any method body calls
// `verifySP1FRI`, at any nesting depth.
func contractCallsSP1FriVerifier(contract *ContractNode) bool {
	for i := range contract.Methods {
		if statementsCallSP1Fri(contract.Methods[i].Body) {
			return true
		}
	}
	return false
}

func statementsCallSP1Fri(stmts []Statement) bool {
	for _, st := range stmts {
		switch v := st.(type) {
		case VariableDeclStmt:
			if exprCallsSP1Fri(v.Init) {
				return true
			}
		case *VariableDeclStmt:
			if exprCallsSP1Fri(v.Init) {
				return true
			}
		case AssignmentStmt:
			// Target is an Expression too: `xs[verifySP1FRI(...)] = 1n`.
			if exprCallsSP1Fri(v.Target) || exprCallsSP1Fri(v.Value) {
				return true
			}
		case *AssignmentStmt:
			if exprCallsSP1Fri(v.Target) || exprCallsSP1Fri(v.Value) {
				return true
			}
		case ExpressionStmt:
			if exprCallsSP1Fri(v.Expr) {
				return true
			}
		case *ExpressionStmt:
			if exprCallsSP1Fri(v.Expr) {
				return true
			}
		case IfStmt:
			if exprCallsSP1Fri(v.Condition) || statementsCallSP1Fri(v.Then) || statementsCallSP1Fri(v.Else) {
				return true
			}
		case *IfStmt:
			if exprCallsSP1Fri(v.Condition) || statementsCallSP1Fri(v.Then) || statementsCallSP1Fri(v.Else) {
				return true
			}
		case ForStmt:
			if forStmtCallsSP1Fri(v) {
				return true
			}
		case *ForStmt:
			if forStmtCallsSP1Fri(*v) {
				return true
			}
		case ReturnStmt:
			if exprCallsSP1Fri(v.Value) {
				return true
			}
		case *ReturnStmt:
			if exprCallsSP1Fri(v.Value) {
				return true
			}
		}
	}
	return false
}

// forStmtCallsSP1Fri walks every limb of a for loop. Init and Update are easy
// to forget — Init is a VariableDeclStmt held by value and Update is a bare
// Statement — and either one can host the built-in.
func forStmtCallsSP1Fri(v ForStmt) bool {
	if exprCallsSP1Fri(v.Init.Init) || exprCallsSP1Fri(v.Condition) {
		return true
	}
	if v.Update != nil && statementsCallSP1Fri([]Statement{v.Update}) {
		return true
	}
	return statementsCallSP1Fri(v.Body)
}

// exprCallsSP1Fri reports whether the expression reaches `verifySP1FRI` at any
// depth.
//
// This switch MUST cover every type declared in ast.go that implements
// Expression, in both its value and pointer form. Any type it misses is a
// silent bypass of the refusal in Validate: the contract compiles clean into
// the known-unsound verifier. Go does not check type-switch exhaustiveness, and
// a fail-closed default is not usable here (it would refuse every contract
// using a newly-added expression form), so the leaf cases below are listed
// explicitly and TestSP1FriWalker_HandlesEveryDeclaredExpressionType fails the
// build if ast.go grows a type this switch does not name.
func exprCallsSP1Fri(e Expression) bool {
	if e == nil {
		return false
	}
	switch v := e.(type) {
	case CallExpr:
		return callExprIsSP1Fri(v)
	case *CallExpr:
		return callExprIsSP1Fri(*v)
	case BinaryExpr:
		return exprCallsSP1Fri(v.Left) || exprCallsSP1Fri(v.Right)
	case *BinaryExpr:
		return exprCallsSP1Fri(v.Left) || exprCallsSP1Fri(v.Right)
	case UnaryExpr:
		return exprCallsSP1Fri(v.Operand)
	case *UnaryExpr:
		return exprCallsSP1Fri(v.Operand)
	case TernaryExpr:
		return ternaryCallsSP1Fri(v)
	case *TernaryExpr:
		return ternaryCallsSP1Fri(*v)
	case MemberExpr:
		return exprCallsSP1Fri(v.Object)
	case *MemberExpr:
		return exprCallsSP1Fri(v.Object)
	case IndexAccessExpr:
		return exprCallsSP1Fri(v.Object) || exprCallsSP1Fri(v.Index)
	case *IndexAccessExpr:
		return exprCallsSP1Fri(v.Object) || exprCallsSP1Fri(v.Index)
	case IncrementExpr:
		return exprCallsSP1Fri(v.Operand)
	case *IncrementExpr:
		return exprCallsSP1Fri(v.Operand)
	case DecrementExpr:
		return exprCallsSP1Fri(v.Operand)
	case *DecrementExpr:
		return exprCallsSP1Fri(v.Operand)
	case ArrayLiteralExpr:
		return anyExprCallsSP1Fri(v.Elements)
	case *ArrayLiteralExpr:
		return anyExprCallsSP1Fri(v.Elements)

	// Leaves: no sub-expressions to descend into. Named explicitly rather than
	// swept up by a default so the exhaustiveness test can tell "handled" from
	// "forgotten".
	case Identifier, *Identifier,
		BigIntLiteral, *BigIntLiteral,
		BoolLiteral, *BoolLiteral,
		ByteStringLiteral, *ByteStringLiteral,
		PropertyAccessExpr, *PropertyAccessExpr:
		return false
	}
	return false
}

func ternaryCallsSP1Fri(v TernaryExpr) bool {
	return exprCallsSP1Fri(v.Condition) || exprCallsSP1Fri(v.Consequent) || exprCallsSP1Fri(v.Alternate)
}

func anyExprCallsSP1Fri(exprs []Expression) bool {
	for _, e := range exprs {
		if exprCallsSP1Fri(e) {
			return true
		}
	}
	return false
}

func callExprIsSP1Fri(c CallExpr) bool {
	switch callee := c.Callee.(type) {
	case Identifier:
		if callee.Name == "verifySP1FRI" {
			return true
		}
	case *Identifier:
		if callee.Name == "verifySP1FRI" {
			return true
		}
	}
	if exprCallsSP1Fri(c.Callee) {
		return true
	}
	return anyExprCallsSP1Fri(c.Args)
}
