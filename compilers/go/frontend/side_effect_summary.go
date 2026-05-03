package frontend

// Side-effect summary pass.
//
// Mirrors packages/runar-compiler/src/passes/side-effect-summary.ts.
//
// Classifies each method on a ContractNode by the side effects it has on
// the contract's continuation requirements. Walks the private-method
// call graph so effects buried inside private helpers surface to their
// public callers.
//
// Consumed by anf_lower.go for:
//   - Auto-injecting continuation parameters (_changePKH, _changeAmount,
//     _newAmount, txPreimage) on public stateful methods.
//   - Gating emission of the hashOutputs continuation assertion.
//   - Deciding whether a private-helper call should be inlined into the
//     caller's binding stream so its add_output / add_data_output ANF
//     nodes register on the caller's continuation hash.
//
// Recursion across private methods is forbidden by the language
// validator, so the call-graph walk terminates.

// MethodEffects captures effects a method has on the contract's
// continuation. Each flag is true if the effect occurs anywhere
// reachable from the method body, including transitively via
// private-method calls.
type MethodEffects struct {
	MutatesState   bool // mutates a non-readonly property (assignment or ++/--)
	HasStateOutput bool // calls this.addOutput(...) or this.addRawOutput(...)
	HasDataOutput  bool // calls this.addDataOutput(...)
	UsesPreimage   bool // calls checkPreimage(...) (manually, outside auto-injected one)
}

// SideEffectSummary maps method name -> that method's effects. Includes
// the constructor under the key "constructor".
type SideEffectSummary map[string]MethodEffects

var sideEffectStateOutputIntrinsics = map[string]bool{
	"addOutput":    true,
	"addRawOutput": true,
}

var sideEffectDataOutputIntrinsics = map[string]bool{
	"addDataOutput": true,
}

// ComputeSideEffectSummary classifies every method on the contract.
// On-demand DFS with memoization. The caller does not need a topological
// sort.
func ComputeSideEffectSummary(contract *ContractNode) SideEffectSummary {
	summary := make(SideEffectSummary)
	mutableProps := make(map[string]bool)
	for _, p := range contract.Properties {
		if !p.Readonly {
			mutableProps[p.Name] = true
		}
	}

	privateByName := make(map[string]MethodNode)
	for _, m := range contract.Methods {
		if m.Visibility == "private" {
			privateByName[m.Name] = m
		}
	}

	inProgress := make(map[string]bool)

	var effectsFor func(methodName string, body []Statement) MethodEffects
	var collectStmt func(stmt Statement, into *MethodEffects)
	var collectExpr func(expr Expression, into *MethodEffects)

	effectsFor = func(methodName string, body []Statement) MethodEffects {
		if cached, ok := summary[methodName]; ok {
			return cached
		}
		if inProgress[methodName] {
			// Defensive: validation should reject recursion before we get
			// here, but if a malformed contract slips through return empty
			// effects to avoid infinite recursion.
			return MethodEffects{}
		}
		inProgress[methodName] = true
		var effects MethodEffects
		for _, s := range body {
			collectStmt(s, &effects)
		}
		delete(inProgress, methodName)
		summary[methodName] = effects
		return effects
	}

	unionInto := func(target *MethodEffects, source MethodEffects) {
		if source.MutatesState {
			target.MutatesState = true
		}
		if source.HasStateOutput {
			target.HasStateOutput = true
		}
		if source.HasDataOutput {
			target.HasDataOutput = true
		}
		if source.UsesPreimage {
			target.UsesPreimage = true
		}
	}

	collectStmt = func(stmt Statement, into *MethodEffects) {
		switch s := stmt.(type) {
		case AssignmentStmt:
			if pa, ok := s.Target.(PropertyAccessExpr); ok && mutableProps[pa.Property] {
				into.MutatesState = true
			}
			collectExpr(s.Value, into)
		case ExpressionStmt:
			collectExpr(s.Expr, into)
		case IfStmt:
			collectExpr(s.Condition, into)
			for _, inner := range s.Then {
				collectStmt(inner, into)
			}
			for _, inner := range s.Else {
				collectStmt(inner, into)
			}
		case ForStmt:
			collectStmt(s.Update, into)
			for _, inner := range s.Body {
				collectStmt(inner, into)
			}
		case ReturnStmt:
			if s.Value != nil {
				collectExpr(s.Value, into)
			}
		case VariableDeclStmt:
			if s.Init != nil {
				collectExpr(s.Init, into)
			}
		}
	}

	collectExpr = func(expr Expression, into *MethodEffects) {
		switch e := expr.(type) {
		case IncrementExpr:
			if pa, ok := e.Operand.(PropertyAccessExpr); ok && mutableProps[pa.Property] {
				into.MutatesState = true
			}
		case DecrementExpr:
			if pa, ok := e.Operand.(PropertyAccessExpr); ok && mutableProps[pa.Property] {
				into.MutatesState = true
			}
		case CallExpr:
			// this.X(...) or member.X(...) — output intrinsics or
			// private method calls.
			var calleeName string
			if pa, ok := e.Callee.(PropertyAccessExpr); ok {
				calleeName = pa.Property
			} else if me, ok := e.Callee.(MemberExpr); ok {
				calleeName = me.Property
			}
			if calleeName != "" {
				if sideEffectStateOutputIntrinsics[calleeName] {
					into.HasStateOutput = true
				}
				if sideEffectDataOutputIntrinsics[calleeName] {
					into.HasDataOutput = true
				}
				if target, ok := privateByName[calleeName]; ok {
					unionInto(into, effectsFor(target.Name, target.Body))
				}
			}

			// Bareword calls: identifiers that resolve to private methods
			// (Go DSL routes private helpers as bare identifiers) or to
			// builtins like checkPreimage.
			if id, ok := e.Callee.(Identifier); ok {
				if id.Name == "checkPreimage" {
					into.UsesPreimage = true
				}
				if target, ok := privateByName[id.Name]; ok {
					unionInto(into, effectsFor(target.Name, target.Body))
				}
			}

			for _, arg := range e.Args {
				collectExpr(arg, into)
			}
			// Walk the callee subexpression too (for nested calls /
			// property accesses). Skip Identifier — already handled.
			if _, isId := e.Callee.(Identifier); !isId {
				collectExpr(e.Callee, into)
			}
		case BinaryExpr:
			collectExpr(e.Left, into)
			collectExpr(e.Right, into)
		case UnaryExpr:
			collectExpr(e.Operand, into)
		case TernaryExpr:
			collectExpr(e.Condition, into)
			collectExpr(e.Consequent, into)
			collectExpr(e.Alternate, into)
		case IndexAccessExpr:
			collectExpr(e.Object, into)
			collectExpr(e.Index, into)
		case MemberExpr:
			collectExpr(e.Object, into)
		case ArrayLiteralExpr:
			for _, el := range e.Elements {
				collectExpr(el, into)
			}
		}
	}

	// Classify constructor + every method up front so callers do not
	// need to know about lazy evaluation order.
	effectsFor("constructor", contract.Constructor.Body)
	for _, m := range contract.Methods {
		effectsFor(m.Name, m.Body)
	}

	return summary
}

// ContinuationShape classifies a method's continuation requirements.
//
// NeedsChange controls injection of _changePKH and _changeAmount.
// NeedsNewAmount controls injection of _newAmount. The pair maps
// directly to ANF auto-param insertion; both sites must agree for a
// deployed contract to be spendable.
type ContinuationShape struct {
	NeedsChange    bool
	NeedsNewAmount bool
	IsTerminal     bool
}

// ContinuationShapeFor derives ContinuationShape from MethodEffects.
func ContinuationShapeFor(eff MethodEffects) ContinuationShape {
	needsChange := eff.MutatesState || eff.HasStateOutput || eff.HasDataOutput
	// addOutput / addRawOutput already specify per-output amounts, so
	// when those are present the single-output _newAmount is redundant.
	// Otherwise (mutating-only or data-only methods) the single-output
	// continuation path needs _newAmount to size the new state UTXO.
	needsNewAmount := (eff.MutatesState || eff.HasDataOutput) && !eff.HasStateOutput
	return ContinuationShape{
		NeedsChange:    needsChange,
		NeedsNewAmount: needsNewAmount,
		IsTerminal:     !needsChange,
	}
}
