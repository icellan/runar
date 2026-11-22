package frontend

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/icellan/runar/compilers/go/ir"
)

// D26: a block-height locktime gate must pin the locktime domain. Mirrors
// packages/runar-compiler/src/passes/locktime-domain.ts (same rule and text in
// all seven tiers); see that file for the full rule.
//
// Consensus reads an nLockTime below 500,000,000 as a block height and one at
// or above it as a Unix timestamp, so `assert(extractLocktime(p) >= H)` for a
// height H is passed at once by any timestamp-domain locktime. A GATE is a
// lower-bound compare on a locktime read; a PIN is an asserted domain bound
// on one (the asserted condition itself or a top-level `&&` conjunct of it).
// PER PATH, with D18's path walk and two bits (gate seen / pin seen): every
// path through a public method that carries a gate must also carry a pin.
// A value DERIVED from a read (arithmetic, a ternary arm, a builtin call, or
// a local with a non-direct binding) is a gate under any lower bound and is
// never a pin. The --ir path re-derives the same rule from the ANF.

// LocktimeDomainMessage is the shared D26 error text.
func LocktimeDomainMessage(method string) string {
	return fmt.Sprintf(
		"method '%s' compares extractLocktime against a lower bound without pinning the locktime domain: "+
			"consensus reads an nLockTime of 500000000 or more as a Unix timestamp, so on that path any such locktime "+
			"passes a block-height gate at once. On every path that compares, assert(extractLocktime(preimage) < "+
			"500000000n) for a block-height gate, or assert(extractLocktime(preimage) >= 500000000n) for a timestamp gate",
		method)
}

// The first nLockTime value consensus reads as a Unix timestamp.
var locktimeThreshold = big.NewInt(500000000)
var locktimeThresholdMinus1 = big.NewInt(499999999)

// Path-state bits: gate seen / pin seen.
const (
	ltGate = 1
	ltPin  = 2
)

func ltUnpinned(s pathSet) bool {
	for x := range s {
		if x&ltGate != 0 && x&ltPin == 0 {
			return true
		}
	}
	return false
}

// ltCompose: every caller state followed by every callee exit state (plain OR).
func ltCompose(a, b pathSet) pathSet {
	out := pathSet{}
	for x := range a {
		for y := range b {
			out[x|y] = true
		}
	}
	return out
}

const (
	ltGateK = "gate"
	ltPinK  = "pin"
	ltNoneK = "none"
)

func ltIsCmp(op string) bool { return op == "<" || op == "<=" || op == ">" || op == ">=" }

var ltFlip = map[string]string{"<": ">", "<=": ">=", ">": "<", ">=": "<="}

// ltClassify classifies `lt <op> other` (the locktime read on the left);
// other is the literal's value, or nil when it is not a bigint literal.
func ltClassify(op string, other *big.Int) string {
	if op == ">=" || op == ">" {
		// `>= 0` is vacuous (every locktime passes it): no gate. Only literal 0:
		// a negative bound is a negation in source but may be a literal in IR.
		if op == ">=" && other != nil && other.Sign() == 0 {
			return ltNoneK
		}
		ts := other != nil && ((op == ">=" && other.Cmp(locktimeThreshold) >= 0) ||
			(op == ">" && other.Cmp(locktimeThresholdMinus1) >= 0))
		if ts {
			return ltPinK
		}
		return ltGateK
	}
	if other == nil {
		return ltNoneK
	}
	var height bool
	if op == "<" {
		height = other.Sign() > 0 && other.Cmp(locktimeThreshold) <= 0
	} else {
		height = other.Sign() >= 0 && other.Cmp(locktimeThreshold) < 0
	}
	if height {
		return ltPinK
	}
	return ltNoneK
}

// Taint level of a value: not a locktime read / a direct read / derived from one.
const (
	ltNone    = 0
	ltDirect  = 1
	ltDerived = 2
)

// Binary / unary operators whose result derives from their operands.
var ltPropagate = map[string]bool{"+": true, "-": true, "*": true, "/": true, "%": true, "&": true, "|": true, "^": true, "<<": true, ">>": true}
var ltPropagateUnary = map[string]bool{"-": true, "~": true}

type ltBind[B any] struct {
	name string
	b    B
}

// ltSolveTaint: least fixpoint for the tainted set, then greatest fixpoint
// (within it) for the names all of whose bindings are direct reads.
func ltSolveTaint[B any](binds []ltBind[B], tainted func(B, map[string]bool) bool, direct func(B, map[string]bool) bool) map[string]int {
	t := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for _, bd := range binds {
			if !t[bd.name] && tainted(bd.b, t) {
				t[bd.name] = true
				changed = true
			}
		}
	}
	d := map[string]bool{}
	for n := range t {
		d[n] = true
	}
	for changed := true; changed; {
		changed = false
		for _, bd := range binds {
			if d[bd.name] && !direct(bd.b, d) {
				delete(d, bd.name)
				changed = true
			}
		}
	}
	out := map[string]int{}
	for n := range t {
		if d[n] {
			out[n] = ltDirect
		} else {
			out[n] = ltDerived
		}
	}
	return out
}

// ltClassifyCompare classifies a compare given its operands' taint levels:
// a direct read classifies against the other side's literal; a derived value
// is a gate under any lower bound and never a pin. A gate on either side wins.
func ltClassifyCompare[T any](op string, left, right T, level func(T) int, literal func(T) *big.Int) string {
	if !ltIsCmp(op) {
		return ltNoneK
	}
	side := func(lv int, o string, other T) string {
		switch lv {
		case ltDirect:
			return ltClassify(o, literal(other))
		case ltDerived:
			if o == ">=" || o == ">" {
				return ltGateK
			}
		}
		return ltNoneK
	}
	a := side(level(left), op, right)
	b := side(level(right), ltFlip[op], left)
	if a == ltGateK || b == ltGateK {
		return ltGateK
	}
	if a == ltPinK || b == ltPinK {
		return ltPinK
	}
	return ltNoneK
}

func ltHelperKey(name string, params []string, levels map[string]int) string {
	parts := make([]string, len(params))
	for i, p := range params {
		parts[i] = strconv.Itoa(levels[p])
	}
	return name + "|" + strings.Join(parts, ",")
}

// ---------------------------------------------------------------------------
// Source path
// ---------------------------------------------------------------------------

func ltIsCallTo(e Expression, name string) bool {
	c, ok := e.(CallExpr)
	if !ok {
		return false
	}
	id, ok := c.Callee.(Identifier)
	return ok && id.Name == name
}

// ltIsRead: a D26 locktime read. currentBlockHeight() is not one: it asserts
// its own value < 500000000 at the call (anf_lower.go), so it is a height by
// construction. Mirrors locktime-domain.ts.
func ltIsRead(e Expression) bool {
	return ltIsCallTo(e, "extractLocktime")
}

// ContractReadsLocktime is the D26 prefilter: some method body calls
// extractLocktime anywhere. Mirrors contractReadsLocktime.
func ContractReadsLocktime(contract *ContractNode) bool {
	var seen func(v reflect.Value) bool
	seen = func(v reflect.Value) bool {
		switch v.Kind() {
		case reflect.Interface, reflect.Pointer:
			if v.IsNil() {
				return false
			}
			if e, ok := v.Interface().(Expression); ok && ltIsRead(e) {
				return true
			}
			return seen(v.Elem())
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				if seen(v.Index(i)) {
					return true
				}
			}
		case reflect.Struct:
			if e, ok := v.Interface().(Expression); ok && ltIsRead(e) {
				return true
			}
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).IsExported() && seen(v.Field(i)) {
					return true
				}
			}
		}
		return false
	}
	for _, m := range contract.Methods {
		if seen(reflect.ValueOf(m.Body)) {
			return true
		}
	}
	return false
}

// CurrentBlockHeightTimestampMessage is the shared error text for a
// currentBlockHeight() compare against a timestamp-domain bound.
func CurrentBlockHeightTimestampMessage(method string) string {
	return fmt.Sprintf(
		"method '%s' compares currentBlockHeight() against a Unix-timestamp bound: currentBlockHeight() asserts "+
			"its value is below 500000000 (a block height), so this compare can never pass and an output gated on it "+
			"could never be spent. Use extractLocktime(this.txPreimage) for a timestamp gate",
		method)
}

// ComparesCurrentBlockHeightToTimestamp: true iff method contains, anywhere, a
// lower-bound compare of a direct currentBlockHeight() call (or a local every
// binding of which is one) against a
// timestamp-domain bigint literal (`>= N`, N >= 500000000; `> N`,
// N >= 499999999; or reversed). currentBlockHeight() asserts its value is
// below 500000000, so such a compare can never pass. Mirrors
// comparesCurrentBlockHeightToTimestamp in locktime-domain.ts.
func ComparesCurrentBlockHeightToTimestamp(method MethodNode) bool {
	lit := func(x Expression) *big.Int {
		if l, ok := x.(BigIntLiteral); ok && l.Value != nil {
			return l.Value
		}
		return nil
	}
	// Locals bound only to currentBlockHeight() (every declaration/assignment).
	cbhOnly := map[string]bool{}
	bind := func(name string, v Expression) {
		prev, seen := cbhOnly[name]
		cbhOnly[name] = (!seen || prev) && ltIsCallTo(v, "currentBlockHeight")
	}
	var collect func(stmts []Statement)
	collect = func(stmts []Statement) {
		for _, st := range stmts {
			switch s := st.(type) {
			case VariableDeclStmt:
				bind(s.Name, s.Init)
			case AssignmentStmt:
				if id, ok := s.Target.(Identifier); ok {
					bind(id.Name, s.Value)
				}
			case IfStmt:
				collect(s.Then)
				if s.Else != nil {
					collect(s.Else)
				}
			case ForStmt:
				collect([]Statement{s.Init})
				collect(s.Body)
			}
		}
	}
	collect(method.Body)
	isCbh := func(e Expression) bool {
		if ltIsCallTo(e, "currentBlockHeight") {
			return true
		}
		id, ok := e.(Identifier)
		return ok && cbhOnly[id.Name]
	}
	hit := func(e Expression) bool {
		b, ok := e.(BinaryExpr)
		if !ok || !ltIsCmp(b.Op) {
			return false
		}
		if isCbh(b.Left) && (b.Op == ">=" || b.Op == ">") && ltClassify(b.Op, lit(b.Right)) == ltPinK {
			return true
		}
		f := ltFlip[b.Op]
		return isCbh(b.Right) && (f == ">=" || f == ">") && ltClassify(f, lit(b.Left)) == ltPinK
	}
	var seen func(v reflect.Value) bool
	seen = func(v reflect.Value) bool {
		switch v.Kind() {
		case reflect.Interface, reflect.Pointer:
			if v.IsNil() {
				return false
			}
			if e, ok := v.Interface().(Expression); ok && hit(e) {
				return true
			}
			return seen(v.Elem())
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				if seen(v.Index(i)) {
					return true
				}
			}
		case reflect.Struct:
			if e, ok := v.Interface().(Expression); ok && hit(e) {
				return true
			}
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).IsExported() && seen(v.Field(i)) {
					return true
				}
			}
		}
		return false
	}
	return seen(reflect.ValueOf(method.Body))
}

// HasUnpinnedLocktimeGate is the D26 source rule: true iff some path through
// public method carries an unpinned gate.
func HasUnpinnedLocktimeGate(contract *ContractNode, method MethodNode) bool {
	return ltUnpinned(newSourceGates(contract).exits(method, map[string]int{}))
}

type sourceGates struct {
	privates map[string]MethodNode
	// Helper exits, by helper name and the taint level of each argument.
	helperExits map[string]pathSet
	inProgress  map[string]bool
	// Taint level of the locals and parameters of the method being walked.
	locals map[string]int
}

func newSourceGates(contract *ContractNode) *sourceGates {
	sg := &sourceGates{
		privates:    map[string]MethodNode{},
		helperExits: map[string]pathSet{},
		inProgress:  map[string]bool{},
		locals:      map[string]int{},
	}
	for _, m := range contract.Methods {
		if m.Visibility == "private" {
			sg.privates[m.Name] = m
		}
	}
	return sg
}

func (sg *sourceGates) exits(method MethodNode, params map[string]int) pathSet {
	saved := sg.locals
	sg.locals = collectLocktimeLocals(method.Body, params)
	live, returned := sg.stmts(method.Body, pathSetOf(0))
	sg.locals = saved
	return live.union(returned)
}

func (sg *sourceGates) level(e Expression) int { return ltExprLevel(e, sg.locals) }

func (sg *sourceGates) compare(e Expression) string {
	b, ok := e.(BinaryExpr)
	if !ok {
		return ltNoneK
	}
	return ltClassifyCompare(b.Op, b.Left, b.Right, sg.level, func(x Expression) *big.Int {
		if l, ok := x.(BigIntLiteral); ok && l.Value != nil {
			return l.Value
		}
		return nil
	})
}

func (sg *sourceGates) assertedPin(e Expression) bool {
	if sg.compare(e) == ltPinK {
		return true
	}
	if b, ok := e.(BinaryExpr); ok && b.Op == "&&" {
		return sg.assertedPin(b.Left) || sg.assertedPin(b.Right)
	}
	return false
}

func (sg *sourceGates) stmts(stmts []Statement, states pathSet) (pathSet, pathSet) {
	live := states
	returned := pathSet{}
	for _, st := range stmts {
		if len(live) == 0 {
			break
		}
		l, r := sg.stmt(st, live)
		returned = returned.union(r)
		live = l
	}
	return live, returned
}

func (sg *sourceGates) stmt(st Statement, states pathSet) (pathSet, pathSet) {
	none := pathSet{}
	switch s := st.(type) {
	case AssignmentStmt:
		return sg.expr(s.Value, sg.expr(s.Target, states)), none
	case ExpressionStmt:
		return sg.expr(s.Expr, states), none
	case VariableDeclStmt:
		return sg.expr(s.Init, states), none
	case ReturnStmt:
		if s.Value != nil {
			return none, sg.expr(s.Value, states)
		}
		return none, states
	case IfStmt:
		c := sg.expr(s.Condition, states)
		tl, tr := sg.stmts(s.Then, c)
		el, er := c, none
		if s.Else != nil {
			el, er = sg.stmts(s.Else, c)
		}
		return tl.union(el), tr.union(er)
	case ForStmt:
		il, ir := sg.stmt(s.Init, states)
		c := sg.expr(s.Condition, il)
		bl, br := sg.stmts(s.Body, c)
		ul, ur := bl, pathSet{}
		if s.Update != nil {
			ul, ur = sg.stmt(s.Update, bl)
		}
		return c.union(ul), ir.union(br).union(ur)
	}
	return states, none
}

func (sg *sourceGates) expr(e Expression, states pathSet) pathSet {
	switch x := e.(type) {
	case CallExpr:
		s := states
		if _, isID := x.Callee.(Identifier); !isID {
			s = sg.expr(x.Callee, s)
		}
		for _, a := range x.Args {
			s = sg.expr(a, s)
		}
		if ltIsCallTo(x, "assert") && len(x.Args) > 0 && sg.assertedPin(x.Args[0]) {
			return s.orAll(ltPin)
		}
		name := ""
		switch c := x.Callee.(type) {
		case PropertyAccessExpr:
			name = c.Property
		case MemberExpr:
			name = c.Property
		}
		if helper, ok := sg.privates[name]; ok && name != "" {
			levels := make([]int, len(x.Args))
			for i, a := range x.Args {
				levels[i] = sg.level(a)
			}
			return ltCompose(s, sg.helper(helper, levels))
		}
		return s
	case BinaryExpr:
		s := sg.expr(x.Right, sg.expr(x.Left, states))
		if sg.compare(x) == ltGateK {
			return s.orAll(ltGate)
		}
		return s
	case UnaryExpr:
		return sg.expr(x.Operand, states)
	case TernaryExpr:
		c := sg.expr(x.Condition, states)
		return sg.expr(x.Consequent, c).union(sg.expr(x.Alternate, c))
	case IndexAccessExpr:
		return sg.expr(x.Index, sg.expr(x.Object, states))
	case MemberExpr:
		return sg.expr(x.Object, states)
	case IncrementExpr:
		return sg.expr(x.Operand, states)
	case DecrementExpr:
		return sg.expr(x.Operand, states)
	case ArrayLiteralExpr:
		s := states
		for _, el := range x.Elements {
			s = sg.expr(el, s)
		}
		return s
	}
	return states
}

func (sg *sourceGates) helper(m MethodNode, argLevels []int) pathSet {
	params := map[string]int{}
	names := make([]string, len(m.Params))
	for i, p := range m.Params {
		names[i] = p.Name
		if i < len(argLevels) && argLevels[i] != ltNone {
			params[p.Name] = argLevels[i]
		}
	}
	key := ltHelperKey(m.Name, names, params)
	if cached, ok := sg.helperExits[key]; ok {
		return cached
	}
	// Recursion is refused by the validator; a cycle contributes nothing.
	if sg.inProgress[m.Name] {
		return pathSetOf(0)
	}
	sg.inProgress[m.Name] = true
	ex := sg.exits(m, params)
	delete(sg.inProgress, m.Name)
	sg.helperExits[key] = ex
	return ex
}

// ltExprLevel: taint level of a source expression, given the taint of the names in scope.
func ltExprLevel(e Expression, names map[string]int) int {
	if ltIsRead(e) {
		return ltDirect
	}
	anyOf := func(xs ...Expression) int {
		for _, x := range xs {
			if ltExprLevel(x, names) != ltNone {
				return ltDerived
			}
		}
		return ltNone
	}
	switch x := e.(type) {
	case Identifier:
		return names[x.Name]
	case BinaryExpr:
		if ltPropagate[x.Op] {
			return anyOf(x.Left, x.Right)
		}
	case UnaryExpr:
		if ltPropagateUnary[x.Op] {
			return anyOf(x.Operand)
		}
	case TernaryExpr:
		return anyOf(x.Consequent, x.Alternate)
	case CallExpr:
		// A builtin (identifier callee); a helper's return is not followed.
		if _, ok := x.Callee.(Identifier); ok {
			return anyOf(x.Args...)
		}
	}
	return ltNone
}

// ltSourceBind is one binding of a local: an expression, or (for a tainted
// parameter) the level its call passes it (expr nil).
type ltSourceBind struct {
	expr  Expression
	level int
}

// collectLocktimeLocals: taint of the method's locals and parameters, from
// every binding in the body (declaration or assignment, anywhere) plus one
// binding per tainted parameter. Order-blind on purpose.
func collectLocktimeLocals(body []Statement, params map[string]int) map[string]int {
	var binds []ltBind[ltSourceBind]
	for n, lv := range params {
		binds = append(binds, ltBind[ltSourceBind]{n, ltSourceBind{level: lv}})
	}
	var visit func(stmts []Statement)
	visit = func(stmts []Statement) {
		for _, st := range stmts {
			switch s := st.(type) {
			case VariableDeclStmt:
				binds = append(binds, ltBind[ltSourceBind]{s.Name, ltSourceBind{expr: s.Init}})
			case AssignmentStmt:
				if id, ok := s.Target.(Identifier); ok {
					binds = append(binds, ltBind[ltSourceBind]{id.Name, ltSourceBind{expr: s.Value}})
				}
			case IfStmt:
				visit(s.Then)
				if s.Else != nil {
					visit(s.Else)
				}
			case ForStmt:
				visit([]Statement{s.Init})
				visit(s.Body)
			}
		}
	}
	visit(body)
	asMap := func(set map[string]bool) map[string]int {
		out := make(map[string]int, len(set))
		for n := range set {
			out[n] = ltDirect
		}
		return out
	}
	return ltSolveTaint(binds,
		func(b ltSourceBind, t map[string]bool) bool {
			if b.expr == nil {
				return b.level != ltNone
			}
			return ltExprLevel(b.expr, asMap(t)) != ltNone
		},
		func(b ltSourceBind, d map[string]bool) bool {
			if b.expr == nil {
				return b.level == ltDirect
			}
			if ltIsRead(b.expr) {
				return true
			}
			id, ok := b.expr.(Identifier)
			return ok && d[id.Name]
		})
}

// ---------------------------------------------------------------------------
// --ir path
// ---------------------------------------------------------------------------

// AssertIRLocktimeDomain is D26 on the --ir path: CompileFromIR* skips
// validate, so the rule is re-derived from the ANF of every public method
// (stateless and stateful). Mirrors assertIrLocktimeDomain.
func AssertIRLocktimeDomain(program *ir.ANFProgram) error {
	// Prefilter (as ContractReadsLocktime): no extractLocktime call, no gate.
	var reads func(bs []ir.ANFBinding) bool
	reads = func(bs []ir.ANFBinding) bool {
		for i := range bs {
			v := &bs[i].Value
			switch v.Kind {
			case "call":
				if v.Func == "extractLocktime" {
					return true
				}
			case "if":
				if reads(v.Then) || reads(v.Else) {
					return true
				}
			case "loop":
				if reads(v.Body) {
					return true
				}
			}
		}
		return false
	}
	hit := false
	for i := range program.Methods {
		if reads(program.Methods[i].Body) {
			hit = true
			break
		}
	}
	if !hit {
		return nil
	}
	privates := map[string]*ir.ANFMethod{}
	for i := range program.Methods {
		m := &program.Methods[i]
		if !m.IsPublic && m.Name != "constructor" {
			privates[m.Name] = m
		}
	}
	exitsOf := map[string]pathSet{}
	inProgress := map[string]bool{}
	var exits func(m *ir.ANFMethod, argLevels []int) pathSet
	exits = func(m *ir.ANFMethod, argLevels []int) pathSet {
		params := map[string]int{}
		names := make([]string, len(m.Params))
		for i, p := range m.Params {
			names[i] = p.Name
			if i < len(argLevels) && argLevels[i] != ltNone {
				params[p.Name] = argLevels[i]
			}
		}
		key := ltHelperKey(m.Name, names, params)
		if cached, ok := exitsOf[key]; ok {
			return cached
		}
		if inProgress[m.Name] {
			return pathSetOf(0)
		}
		inProgress[m.Name] = true
		g := newIRGates(m, params, func(name string, levels []int) (pathSet, bool) {
			t, ok := privates[name]
			if !ok {
				return nil, false
			}
			return exits(t, levels), true
		})
		ex := g.run(m.Body, pathSetOf(0))
		delete(inProgress, m.Name)
		exitsOf[key] = ex
		return ex
	}
	for i := range program.Methods {
		m := &program.Methods[i]
		if !m.IsPublic || m.Name == "constructor" {
			continue
		}
		if ltUnpinned(exits(m, nil)) {
			return errors.New(LocktimeDomainMessage(m.Name))
		}
	}
	return nil
}

type irGates struct {
	// Every binding of the method, by name (a name bound more than once keeps all its values).
	defs        map[string][]*ir.ANFValue
	taint       map[string]int
	helperExits func(name string, argLevels []int) (pathSet, bool)
}

func ltRef(v *ir.ANFValue) (string, bool) {
	if v.Kind == "load_const" && v.ConstString != nil && strings.HasPrefix(*v.ConstString, "@ref:") {
		return strings.TrimPrefix(*v.ConstString, "@ref:"), true
	}
	return "", false
}

func newIRGates(method *ir.ANFMethod, params map[string]int, helperExits func(string, []int) (pathSet, bool)) *irGates {
	g := &irGates{defs: map[string][]*ir.ANFValue{}, helperExits: helperExits}
	var binds []ltBind[*ir.ANFValue]
	var index func(bs []ir.ANFBinding)
	index = func(bs []ir.ANFBinding) {
		for i := range bs {
			v := &bs[i].Value
			g.defs[bs[i].Name] = append(g.defs[bs[i].Name], v)
			binds = append(binds, ltBind[*ir.ANFValue]{bs[i].Name, v})
			if v.Kind == "if" {
				index(v.Then)
				index(v.Else)
			} else if v.Kind == "loop" {
				index(v.Body)
			}
		}
	}
	index(method.Body)
	last := func(arm []ir.ANFBinding) (string, bool) {
		if len(arm) == 0 {
			return "", false
		}
		return arm[len(arm)-1].Name, true
	}
	g.taint = ltSolveTaint(binds,
		func(v *ir.ANFValue, t map[string]bool) bool {
			if r, ok := ltRef(v); ok {
				return t[r]
			}
			switch v.Kind {
			case "call":
				if v.Func == "extractLocktime" {
					return true
				}
				for _, a := range v.Args {
					if t[a] {
						return true
					}
				}
				return false
			case "load_param":
				return params[v.Name] != ltNone
			case "bin_op":
				return ltPropagate[v.Op] && (t[v.Left] || t[v.Right])
			case "unary_op":
				return ltPropagateUnary[v.Op] && t[v.Operand]
			case "if":
				if n, ok := last(v.Then); ok && t[n] {
					return true
				}
				if n, ok := last(v.Else); ok && t[n] {
					return true
				}
				return false
			}
			return false
		},
		func(v *ir.ANFValue, d map[string]bool) bool {
			if r, ok := ltRef(v); ok {
				return d[r]
			}
			switch v.Kind {
			case "call":
				return v.Func == "extractLocktime"
			case "load_param":
				return params[v.Name] == ltDirect
			}
			return false
		})
	return g
}

func (g *irGates) level(name string) int { return g.taint[name] }

func (g *irGates) literal(name string) *big.Int {
	seen := map[string]bool{}
	for !seen[name] {
		seen[name] = true
		vs := g.defs[name]
		if len(vs) != 1 {
			return nil
		}
		v := vs[0]
		if v.Kind != "load_const" {
			return nil
		}
		if v.ConstBigInt != nil {
			return v.ConstBigInt
		}
		r, ok := ltRef(v)
		if !ok {
			return nil
		}
		name = r
	}
	return nil
}

func (g *irGates) compare(v *ir.ANFValue) string {
	if v.Kind != "bin_op" {
		return ltNoneK
	}
	return ltClassifyCompare(v.Op, v.Left, v.Right, g.level, g.literal)
}

// assertedPin: does `assert(name)` imply a pin?
func (g *irGates) assertedPin(name string, seen map[string]bool) bool {
	if seen[name] {
		return false
	}
	seen[name] = true
	vs := g.defs[name]
	if len(vs) != 1 {
		return false
	}
	v := vs[0]
	if g.compare(v) == ltPinK {
		return true
	}
	if r, ok := ltRef(v); ok {
		return g.assertedPin(r, seen)
	}
	// `a && b` lowers to `if a then [..., b] else [false]`.
	if v.Kind == "if" && ltIsConstFalseArm(v.Else) && len(v.Then) > 0 {
		return g.assertedPin(v.Cond, seen) || g.assertedPin(v.Then[len(v.Then)-1].Name, seen)
	}
	return false
}

func (g *irGates) run(bs []ir.ANFBinding, states pathSet) pathSet {
	s := states
	for i := range bs {
		v := &bs[i].Value
		switch v.Kind {
		case "bin_op":
			if g.compare(v) == ltGateK {
				s = s.orAll(ltGate)
			}
		case "assert":
			if g.assertedPin(v.ValueRef, map[string]bool{}) {
				s = s.orAll(ltPin)
			}
		case "method_call":
			levels := make([]int, len(v.Args))
			for j, a := range v.Args {
				levels[j] = g.level(a)
			}
			if ex, ok := g.helperExits(v.Method, levels); ok {
				s = ltCompose(s, ex)
			}
		case "if":
			s = g.run(v.Then, s).union(g.run(v.Else, s))
		case "loop":
			s = s.union(g.run(v.Body, s))
		}
	}
	return s
}

func ltIsConstFalseArm(arm []ir.ANFBinding) bool {
	if len(arm) != 1 {
		return false
	}
	v := &arm[0].Value
	return v.Kind == "load_const" && v.ConstBool != nil && !*v.ConstBool
}
