package frontend

// D12 FE-F1: operand-family slots on operator nodes.
//
// The TS reference writes `operandType` straight into the AST node from the
// type checker. Go AST nodes are values held in interfaces, so the checker
// cannot mutate one in place; instead every operator whose lowering depends on
// the operand family carries a *string slot. allocateOperandSlots gives each
// such node that has none a fresh slot (rebuilding the tree in place, once, at
// the start of the type checker); the checker writes through the slot, and
// every later value copy of the node (03b's rewrites and clones) shares it.

// visitOperatorSlots walks every expression of the contract (property
// initializers, constructor, methods), rebuilding the tree in place, and calls
// f with a pointer to the OperandType slot of every typed operator: binary
// `+ === !== & | ^` and unary `~`.
func visitOperatorSlots(contract *ContractNode, f func(slot **string)) {
	if contract == nil {
		return
	}
	for i := range contract.Properties {
		if contract.Properties[i].Initializer != nil {
			contract.Properties[i].Initializer = visitSlotsExpr(contract.Properties[i].Initializer, f)
		}
	}
	visitSlotsStmts(contract.Constructor.Body, f)
	for i := range contract.Methods {
		visitSlotsStmts(contract.Methods[i].Body, f)
	}
}

func visitSlotsStmts(stmts []Statement, f func(slot **string)) {
	for i, s := range stmts {
		stmts[i] = visitSlotsStmt(s, f)
	}
}

func visitSlotsStmt(stmt Statement, f func(slot **string)) Statement {
	switch s := stmt.(type) {
	case VariableDeclStmt:
		s.Init = visitSlotsExpr(s.Init, f)
		return s
	case AssignmentStmt:
		s.Target = visitSlotsExpr(s.Target, f)
		s.Value = visitSlotsExpr(s.Value, f)
		return s
	case IfStmt:
		s.Condition = visitSlotsExpr(s.Condition, f)
		visitSlotsStmts(s.Then, f)
		visitSlotsStmts(s.Else, f)
		return s
	case ForStmt:
		if init, ok := visitSlotsStmt(s.Init, f).(VariableDeclStmt); ok {
			s.Init = init
		}
		s.Condition = visitSlotsExpr(s.Condition, f)
		if s.Update != nil {
			s.Update = visitSlotsStmt(s.Update, f)
		}
		visitSlotsStmts(s.Body, f)
		return s
	case ReturnStmt:
		s.Value = visitSlotsExpr(s.Value, f)
		return s
	case ExpressionStmt:
		s.Expr = visitSlotsExpr(s.Expr, f)
		return s
	}
	return stmt
}

func visitSlotsExpr(expr Expression, f func(slot **string)) Expression {
	switch e := expr.(type) {
	case BinaryExpr:
		e.Left = visitSlotsExpr(e.Left, f)
		e.Right = visitSlotsExpr(e.Right, f)
		if isTypedBinaryOp(e.Op) {
			f(&e.OperandType)
		}
		return e
	case UnaryExpr:
		e.Operand = visitSlotsExpr(e.Operand, f)
		if e.Op == "~" {
			f(&e.OperandType)
		}
		return e
	case CallExpr:
		e.Callee = visitSlotsExpr(e.Callee, f)
		for i, a := range e.Args {
			e.Args[i] = visitSlotsExpr(a, f)
		}
		return e
	case MemberExpr:
		e.Object = visitSlotsExpr(e.Object, f)
		return e
	case TernaryExpr:
		e.Condition = visitSlotsExpr(e.Condition, f)
		e.Consequent = visitSlotsExpr(e.Consequent, f)
		e.Alternate = visitSlotsExpr(e.Alternate, f)
		return e
	case IndexAccessExpr:
		e.Object = visitSlotsExpr(e.Object, f)
		e.Index = visitSlotsExpr(e.Index, f)
		return e
	case IncrementExpr:
		e.Operand = visitSlotsExpr(e.Operand, f)
		return e
	case DecrementExpr:
		e.Operand = visitSlotsExpr(e.Operand, f)
		return e
	case ArrayLiteralExpr:
		for i, el := range e.Elements {
			e.Elements[i] = visitSlotsExpr(el, f)
		}
		return e
	}
	return expr
}

// allocateOperandSlots gives every typed operator node that has no slot a
// fresh, empty one. Run by the type checker before it checks anything.
func allocateOperandSlots(contract *ContractNode) {
	visitOperatorSlots(contract, func(slot **string) {
		if *slot == nil {
			*slot = new(string)
		}
	})
}

// hasUntypedOperator reports whether any typed operator lacks a recorded
// operand family (the contract never went through the type checker, or the
// checker could not type the node).
func hasUntypedOperator(contract *ContractNode) bool {
	found := false
	visitOperatorSlots(contract, func(slot **string) {
		if operandTypeOf(*slot) == "" {
			found = true
		}
	})
	return found
}
