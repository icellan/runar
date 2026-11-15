package frontend

import "fmt"

// GK-GAP-010: a public method's SigHashPreimage parameter must reach
// checkPreimage on every path.
//
// spec/type-system.md 4.2: a SigHashPreimage parameter of a public method is
// checked exactly once. The affine checker refuses a second consumption; this
// refuses none. Every field an extractor reads from an unchecked preimage is
// chosen by the spender.
//
// A must-analysis over the AST. A parameter counts as checked by a statement
// list when checkPreimage(p) is the asserted condition of assert(...) (the
// whole condition or any conjunct of its top-level && chain) with p the
// parameter or a local alias of it, or when it is passed to a private method
// that itself checks that parameter on every path, at a point every execution
// of the list reaches (R2-GK010-ASSERT: a discarded, bound, negated, ||-ed,
// compared or ternary-wrapped call, or one used as an if / ternary condition
// or returned from a helper, checks nothing):
//   - an if checks it only if both arms do (a missing else checks nothing);
//   - a ternary checks it only if both arms do;
//   - the right operand of && / || checks nothing (short-circuit);
//   - a for-loop body checks nothing (the bound may be zero);
//   - a return ends its path: a private method checks a parameter only if
//     every return (and the fall-through end) is reached after the check, and
//     an arm that returns drops out of the join after its if.
//
// A name assigned anywhere in the method body (the parameter itself or a
// local) never stands for a parameter: after `a = other` it no longer holds
// the parameter's value on every path.

// conjuncts returns the operands of a top-level && chain (e itself if it is
// not one).
func conjuncts(e Expression) []Expression {
	if b, ok := e.(BinaryExpr); ok && b.Op == "&&" {
		return append(conjuncts(b.Left), conjuncts(b.Right)...)
	}
	return []Expression{e}
}

// PreimageNotCheckedMessage is the diagnostic every tier shares.
func PreimageNotCheckedMessage(method, param string) string {
	return fmt.Sprintf("public method '%s' must pass its SigHashPreimage parameter '%s' to checkPreimage() on every path", method, param)
}

type originSet map[string]bool

func (s originSet) union(o originSet) originSet {
	out := originSet{}
	for k := range s {
		out[k] = true
	}
	for k := range o {
		out[k] = true
	}
	return out
}

func (s originSet) intersect(o originSet) originSet {
	out := originSet{}
	for k := range s {
		if o[k] {
			out[k] = true
		}
	}
	return out
}

func isPreimageType(t TypeNode) bool {
	switch pt := t.(type) {
	case PrimitiveType:
		return pt.Name == "SigHashPreimage"
	case *PrimitiveType:
		return pt != nil && pt.Name == "SigHashPreimage"
	}
	return false
}

type preimageChecker struct {
	privates   map[string]MethodNode
	memo       map[string]map[int]bool
	reassigned map[string]bool
}

func collectReassigned(stmts []Statement, out map[string]bool) map[string]bool {
	for _, s := range stmts {
		switch st := s.(type) {
		case AssignmentStmt:
			if id, ok := st.Target.(Identifier); ok {
				out[id.Name] = true
			}
		case IfStmt:
			collectReassigned(st.Then, out)
			collectReassigned(st.Else, out)
		case ForStmt:
			collectReassigned(st.Body, out)
		}
	}
	return out
}

func copyAliases(a map[string]string) map[string]string {
	out := make(map[string]string, len(a))
	for k, v := range a {
		out[k] = v
	}
	return out
}

func (pc *preimageChecker) resolve(e Expression, aliases map[string]string) (string, bool) {
	if id, ok := e.(Identifier); ok && !pc.reassigned[id.Name] {
		o, found := aliases[id.Name]
		return o, found
	}
	if id, ok := e.(*Identifier); ok && id != nil && !pc.reassigned[id.Name] {
		o, found := aliases[id.Name]
		return o, found
	}
	return "", false
}

func (pc *preimageChecker) privateTarget(callee Expression) (MethodNode, bool) {
	var name string
	switch c := callee.(type) {
	case PropertyAccessExpr:
		name = c.Property
	case MemberExpr:
		name = c.Property
	case Identifier:
		name = c.Name
	default:
		return MethodNode{}, false
	}
	m, ok := pc.privates[name]
	return m, ok
}

func (pc *preimageChecker) mustParams(m MethodNode, stack map[string]bool) map[int]bool {
	if r, ok := pc.memo[m.Name]; ok {
		return r
	}
	if stack[m.Name] {
		return map[int]bool{}
	}
	aliases := map[string]string{}
	for _, p := range m.Params {
		if isPreimageType(p.Type) {
			aliases[p.Name] = p.Name
		}
	}
	inner := map[string]bool{m.Name: true}
	for k := range stack {
		inner[k] = true
	}
	outer := pc.reassigned
	pc.reassigned = collectReassigned(m.Body, map[string]bool{})
	done := pc.walkMethod(m.Body, copyAliases(aliases), inner)
	pc.reassigned = outer
	result := map[int]bool{}
	for i, p := range m.Params {
		if _, tracked := aliases[p.Name]; tracked && done[p.Name] {
			result[i] = true
		}
	}
	pc.memo[m.Name] = result
	return result
}

func (pc *preimageChecker) exprMust(e Expression, aliases map[string]string, stack map[string]bool) originSet {
	switch x := e.(type) {
	case CallExpr:
		out := originSet{}
		for _, a := range x.Args {
			out = out.union(pc.exprMust(a, aliases, stack))
		}
		if me, ok := x.Callee.(MemberExpr); ok {
			out = out.union(pc.exprMust(me.Object, aliases, stack))
		}
		// R2-GK010-ASSERT: the call alone checks nothing; only an asserted
		// conjunct does (the assert branch below).
		if id, ok := x.Callee.(Identifier); ok && id.Name == "checkPreimage" {
			return out
		}
		if id, ok := x.Callee.(Identifier); ok && id.Name == "assert" {
			if len(x.Args) > 0 {
				for _, c := range conjuncts(x.Args[0]) {
					call, ok := c.(CallExpr)
					if !ok || len(call.Args) == 0 {
						continue
					}
					if cid, ok := call.Callee.(Identifier); ok && cid.Name == "checkPreimage" {
						if o, ok := pc.resolve(call.Args[0], aliases); ok {
							out[o] = true
						}
					}
				}
			}
			return out
		}
		if target, ok := pc.privateTarget(x.Callee); ok {
			for i := range pc.mustParams(target, stack) {
				if i < len(x.Args) {
					if o, ok := pc.resolve(x.Args[i], aliases); ok {
						out[o] = true
					}
				}
			}
		}
		return out
	case BinaryExpr:
		if x.Op == "&&" || x.Op == "||" {
			return pc.exprMust(x.Left, aliases, stack)
		}
		return pc.exprMust(x.Left, aliases, stack).union(pc.exprMust(x.Right, aliases, stack))
	case TernaryExpr:
		arms := pc.exprMust(x.Consequent, aliases, stack).intersect(pc.exprMust(x.Alternate, aliases, stack))
		return pc.exprMust(x.Condition, aliases, stack).union(arms)
	case UnaryExpr:
		return pc.exprMust(x.Operand, aliases, stack)
	case IndexAccessExpr:
		return pc.exprMust(x.Object, aliases, stack).union(pc.exprMust(x.Index, aliases, stack))
	case MemberExpr:
		return pc.exprMust(x.Object, aliases, stack)
	case ArrayLiteralExpr:
		out := originSet{}
		for _, el := range x.Elements {
			out = out.union(pc.exprMust(el, aliases, stack))
		}
		return out
	}
	return originSet{}
}

// walkMethod intersects the checked sets of every return and of the
// fall-through end of a method body.
func (pc *preimageChecker) walkMethod(body []Statement, aliases map[string]string, stack map[string]bool) originSet {
	var exits []originSet
	if fall, ok := pc.walk(body, originSet{}, aliases, stack, &exits); ok {
		exits = append(exits, fall)
	}
	done := exits[0]
	for _, e := range exits[1:] {
		done = done.intersect(e)
	}
	return done
}

// walk returns the parameters checked at the end of stmts, and false when
// every path through stmts returns first. Each return records its own
// checked set in exits.
func (pc *preimageChecker) walk(stmts []Statement, doneIn originSet, aliases map[string]string, stack map[string]bool, exits *[]originSet) (originSet, bool) {
	done := doneIn.union(nil)
	for _, s := range stmts {
		switch st := s.(type) {
		case VariableDeclStmt:
			done = done.union(pc.exprMust(st.Init, aliases, stack))
			if o, ok := pc.resolve(st.Init, aliases); ok {
				aliases[st.Name] = o
			} else {
				delete(aliases, st.Name)
			}
		case AssignmentStmt:
			done = done.union(pc.exprMust(st.Value, aliases, stack))
		case ExpressionStmt:
			done = done.union(pc.exprMust(st.Expr, aliases, stack))
		case ReturnStmt:
			*exits = append(*exits, done.union(pc.exprMust(st.Value, aliases, stack)))
			return nil, false
		case IfStmt:
			done = done.union(pc.exprMust(st.Condition, aliases, stack))
			thenDone, thenFalls := pc.walk(st.Then, done, copyAliases(aliases), stack, exits)
			elseDone, elseFalls := pc.walk(st.Else, done, copyAliases(aliases), stack, exits)
			switch {
			case !thenFalls && !elseFalls:
				return nil, false
			case !thenFalls:
				done = elseDone
			case !elseFalls:
				done = thenDone
			default:
				done = thenDone.intersect(elseDone)
			}
		case ForStmt:
			// The body checks nothing for the code after the loop, but a
			// return inside it still ends a path.
			pc.walk(st.Body, done, copyAliases(aliases), stack, exits)
		}
	}
	return done, true
}

func checkPreimageCheckedOnEveryPath(contract *ContractNode) []Diagnostic {
	pc := &preimageChecker{privates: map[string]MethodNode{}, memo: map[string]map[int]bool{}}
	for _, m := range contract.Methods {
		if m.Visibility != "public" {
			pc.privates[m.Name] = m
		}
	}
	var errs []Diagnostic
	for _, m := range contract.Methods {
		if m.Visibility != "public" {
			continue
		}
		aliases := map[string]string{}
		var tracked []string
		for _, p := range m.Params {
			if isPreimageType(p.Type) {
				aliases[p.Name] = p.Name
				tracked = append(tracked, p.Name)
			}
		}
		if len(tracked) == 0 {
			continue
		}
		pc.reassigned = collectReassigned(m.Body, map[string]bool{})
		done := pc.walkMethod(m.Body, aliases, map[string]bool{m.Name: true})
		for _, name := range tracked {
			if !done[name] {
				loc := m.SourceLocation
				errs = append(errs, Diagnostic{Message: PreimageNotCheckedMessage(m.Name, name), Severity: SeverityError, Loc: &loc})
			}
		}
	}
	return errs
}
