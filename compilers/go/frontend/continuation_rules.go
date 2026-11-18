package frontend

import "fmt"

// Two rules about where a StatefulSmartContract's satoshis can go, both read
// off the side-effect summary, so they see exactly the effects the
// continuation is injected from. Mirrors
// packages/runar-compiler/src/passes/continuation-rules.ts (same texts in all
// seven tiers).
//
// #199 (warning, validator): no public method is terminal and none sizes its
// own outputs (addOutput / addRawOutput, directly or via a private helper), so
// every spend takes the default continuation whose F-024 floor never lets the
// value shrink: the satoshis can never leave.
//
// D18 (error, typecheck), PER PATH: any addOutput / addRawOutput anywhere in
// a public method (directly or in a private helper, on any branch) removes the
// auto-injected continuation for the whole method, and only addOutput carries
// state, so a path that writes state and reaches no addOutput drops its write
// and the contract's value leaves with the spend. A path that writes nothing
// is terminal by design and is accepted.

// ReleaseTrapMessage is the shared #199 warning text.
func ReleaseTrapMessage(contract string) string {
	return fmt.Sprintf(
		"contract '%s' has no terminal method and no public method that calls "+
			"addOutput/addRawOutput; its satoshis can never leave instances of '%s'",
		contract, contract)
}

// DroppedContinuationMessage is the shared D18 error text.
func DroppedContinuationMessage(method string) string {
	return fmt.Sprintf(
		"method '%s' writes contract state on a path that reaches no addOutput(): a method "+
			"that declares its own outputs (addOutput/addRawOutput) gets no auto-injected continuation, "+
			"so on that path the state write would be lost and the contract's satoshis would leave with "+
			"the spend. Add this.addOutput(satoshis, ...) on every path that writes state, or stop "+
			"writing state on a path meant to end the contract",
		method)
}

// Path-state bits: state written / addOutput reached. A set of these (at most
// four) flows through a method body.
const (
	pathW = 1
	pathA = 2
)

type pathSet map[int]bool

func pathSetOf(xs ...int) pathSet {
	out := pathSet{}
	for _, x := range xs {
		out[x] = true
	}
	return out
}

func (s pathSet) orAll(bits int) pathSet {
	out := pathSet{}
	for x := range s {
		out[x|bits] = true
	}
	return out
}

func (s pathSet) union(o pathSet) pathSet {
	out := pathSet{}
	for x := range s {
		out[x] = true
	}
	for x := range o {
		out[x] = true
	}
	return out
}

func (s pathSet) compose(o pathSet) pathSet {
	out := pathSet{}
	for x := range s {
		for y := range o {
			out[x|y] = true
		}
	}
	return out
}

// pathsDropped: some path wrote state and reached no addOutput.
func pathsDropped(s pathSet) bool {
	for x := range s {
		if x&pathW != 0 && x&pathA == 0 {
			return true
		}
	}
	return false
}

// DropsContinuation is the D18 predicate, PER PATH: the method declares a
// state output somewhere (so it gets no auto-continuation) and some path
// through it writes state without reaching an addOutput. Mirrors
// dropsContinuation / SourcePaths in continuation-rules.ts.
func DropsContinuation(contract *ContractNode, method MethodNode, eff MethodEffects) bool {
	if !eff.HasStateOutput {
		return false
	}
	return pathsDropped(newSourcePaths(contract).exits(method.Body))
}

type sourcePaths struct {
	mutable     map[string]bool
	privates    map[string]MethodNode
	helperExits map[string]pathSet
	inProgress  map[string]bool
}

func newSourcePaths(contract *ContractNode) *sourcePaths {
	sp := &sourcePaths{
		mutable:     map[string]bool{},
		privates:    map[string]MethodNode{},
		helperExits: map[string]pathSet{},
		inProgress:  map[string]bool{},
	}
	for _, p := range contract.Properties {
		if !p.Readonly {
			sp.mutable[p.Name] = true
		}
	}
	for _, m := range contract.Methods {
		if m.Visibility == "private" {
			sp.privates[m.Name] = m
		}
	}
	return sp
}

// exits: exit states (fallthrough and return) of a body entered with a fresh path.
func (sp *sourcePaths) exits(body []Statement) pathSet {
	live, returned := sp.stmts(body, pathSetOf(0))
	return live.union(returned)
}

func (sp *sourcePaths) stmts(stmts []Statement, states pathSet) (pathSet, pathSet) {
	live := states
	returned := pathSet{}
	for _, st := range stmts {
		if len(live) == 0 {
			break
		}
		l, r := sp.stmt(st, live)
		returned = returned.union(r)
		live = l
	}
	return live, returned
}

func (sp *sourcePaths) stmt(st Statement, states pathSet) (pathSet, pathSet) {
	none := pathSet{}
	switch s := st.(type) {
	case AssignmentStmt:
		out := sp.expr(s.Target, states)
		out = sp.expr(s.Value, out)
		if sp.writesMutable(s.Target) {
			out = out.orAll(pathW)
		}
		return out, none
	case ExpressionStmt:
		return sp.expr(s.Expr, states), none
	case VariableDeclStmt:
		return sp.expr(s.Init, states), none
	case ReturnStmt:
		if s.Value != nil {
			return none, sp.expr(s.Value, states)
		}
		return none, states
	case IfStmt:
		c := sp.expr(s.Condition, states)
		tl, tr := sp.stmts(s.Then, c)
		el, er := c, none
		if s.Else != nil {
			el, er = sp.stmts(s.Else, c)
		}
		return tl.union(el), tr.union(er)
	case ForStmt:
		il, ir := sp.stmt(s.Init, states)
		c := sp.expr(s.Condition, il)
		bl, br := sp.stmts(s.Body, c)
		ul, ur := pathSet{}, pathSet{}
		if s.Update != nil {
			ul, ur = sp.stmt(s.Update, bl)
		} else {
			ul = bl
		}
		return c.union(ul), ir.union(br).union(ur)
	}
	return states, none
}

func (sp *sourcePaths) writesMutable(target Expression) bool {
	t := target
	for {
		ia, ok := t.(IndexAccessExpr)
		if !ok {
			break
		}
		t = ia.Object
	}
	pa, ok := t.(PropertyAccessExpr)
	return ok && sp.mutable[pa.Property]
}

// expr: every call in e runs, in evaluation order.
func (sp *sourcePaths) expr(e Expression, states pathSet) pathSet {
	switch x := e.(type) {
	case IncrementExpr:
		s := sp.expr(x.Operand, states)
		if sp.writesMutable(x.Operand) {
			s = s.orAll(pathW)
		}
		return s
	case DecrementExpr:
		s := sp.expr(x.Operand, states)
		if sp.writesMutable(x.Operand) {
			s = s.orAll(pathW)
		}
		return s
	case CallExpr:
		s := states
		if _, isID := x.Callee.(Identifier); !isID {
			s = sp.expr(x.Callee, s)
		}
		for _, a := range x.Args {
			s = sp.expr(a, s)
		}
		name, member := "", false
		switch c := x.Callee.(type) {
		case PropertyAccessExpr:
			name, member = c.Property, true
		case MemberExpr:
			name, member = c.Property, true
		case Identifier:
			name = c.Name
		}
		if member && name == "addOutput" {
			return s.orAll(pathA)
		}
		if helper, ok := sp.privates[name]; ok && name != "" {
			return s.compose(sp.helper(helper))
		}
		return s
	case BinaryExpr:
		return sp.expr(x.Right, sp.expr(x.Left, states))
	case UnaryExpr:
		return sp.expr(x.Operand, states)
	case TernaryExpr:
		c := sp.expr(x.Condition, states)
		return sp.expr(x.Consequent, c).union(sp.expr(x.Alternate, c))
	case IndexAccessExpr:
		return sp.expr(x.Index, sp.expr(x.Object, states))
	case MemberExpr:
		return sp.expr(x.Object, states)
	case ArrayLiteralExpr:
		s := states
		for _, el := range x.Elements {
			s = sp.expr(el, s)
		}
		return s
	}
	return states
}

func (sp *sourcePaths) helper(m MethodNode) pathSet {
	if cached, ok := sp.helperExits[m.Name]; ok {
		return cached
	}
	// Recursion is refused by the validator; a cycle contributes nothing.
	if sp.inProgress[m.Name] {
		return pathSetOf(0)
	}
	sp.inProgress[m.Name] = true
	ex := sp.exits(m.Body)
	delete(sp.inProgress, m.Name)
	sp.helperExits[m.Name] = ex
	return ex
}

// releaseTrapWarning returns the #199 warning text when it applies.
func releaseTrapWarning(contract *ContractNode, summary SideEffectSummary) (string, bool) {
	if contract.ParentClass != "StatefulSmartContract" {
		return "", false
	}
	publics := 0
	for _, m := range contract.Methods {
		if m.Visibility != "public" {
			continue
		}
		publics++
		eff, ok := summary[m.Name]
		if !ok || ContinuationShapeFor(eff).IsTerminal || eff.HasStateOutput {
			return "", false
		}
	}
	if publics == 0 {
		return "", false
	}
	return ReleaseTrapMessage(contract.Name), true
}
