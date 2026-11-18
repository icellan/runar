package ir

import (
	"fmt"
	"strings"
)

// D15: the preimage rules on --ir input. Port of
// packages/runar-compiler/src/passes/ir-preimage-rules.ts (see its header for
// the full rule and for what ANF cannot carry). --ir skips the frontend, so
// D9 (no SigHashPreimage property), GK-GAP-010 (a public method's
// SigHashPreimage parameter is asserted on every path) and D14 (an extractor
// reads only a checked preimage) are re-derived here, failing closed.

const irSHP = "SigHashPreimage"

var irPreimageExtractors = map[string]bool{
	"extractVersion": true, "extractHashPrevouts": true, "extractHashSequence": true, "extractOutpoint": true,
	"extractInputIndex": true, "extractScriptCode": true, "extractAmount": true, "extractSequence": true,
	"extractOutputHash": true, "extractOutputs": true, "extractLocktime": true, "extractSigHashType": true,
}

func irPreimagePropertyMessage(name string) string {
	return "property '" + name + "' cannot hold a SigHashPreimage: a preimage stored in a property was fixed before " +
		"the spending transaction existed, so it can never pass checkPreimage() and every field an extractor " +
		"reads from it is unverified"
}

func irPreimageNotCheckedMessage(method, param string) string {
	return fmt.Sprintf("public method '%s' must assert checkPreimage(%s) on every path", method, param)
}

func irUncheckedPreimageArgMessage(fn string) string {
	return fn + "() needs a checked SigHashPreimage: its argument must be a SigHashPreimage parameter " +
		"(one a public method must assert with checkPreimage()) or the implicit txPreimage of a " +
		"StatefulSmartContract; any other value is not bound to the spending transaction, so every " +
		"field an extractor reads from it is unverified"
}

// checks is a set where nil stands for "everything" (a constant-false arm).
type checks map[string]bool

func checksUnion(a, b checks) checks {
	if a == nil || b == nil {
		return nil
	}
	out := checks{}
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func checksIntersect(a, b checks) checks {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	out := checks{}
	for k := range a {
		if b[k] {
			out[k] = true
		}
	}
	return out
}

// irPath is where a binding sits: its index in each enclosing list, with an
// arm marker (irThen / irElse / irBody) after each if / loop index.
type irPath []int

const (
	irThen = -1
	irElse = -2
	irBody = -3
)

func (p irPath) child(i int) irPath {
	out := make(irPath, len(p)+1)
	copy(out, p)
	out[len(p)] = i
	return out
}

// irVisible reports whether the binding at def is in scope at from: only if
// it sits earlier in the same list or in a list enclosing from. Stack
// lowering resolves names by position, so a binding after (or beside) a use
// never answers for it.
func irVisible(def, from irPath) bool {
	n := len(def)
	if len(from) < n {
		return false
	}
	for i := 0; i < n-1; i++ {
		if def[i] != from[i] {
			return false
		}
	}
	return def[n-1] < from[n-1]
}

type irDef struct {
	value *ANFValue
	path  irPath
}

type irMethodView struct {
	defs     map[string]irDef
	poisoned map[string]bool
	shp      map[string]bool
	implicit bool
}

func newIRMethodView(m *ANFMethod, implicitTx bool) *irMethodView {
	mv := &irMethodView{defs: map[string]irDef{}, poisoned: map[string]bool{}, shp: map[string]bool{}}
	// A name bound more than once, or bound under a parameter's name (the
	// parameter slot answers to it too), never resolves.
	for _, p := range m.Params {
		mv.poisoned[p.Name] = true
	}
	var collect func(bs []ANFBinding, at irPath)
	collect = func(bs []ANFBinding, at irPath) {
		for i := range bs {
			b := &bs[i]
			path := at.child(i)
			if _, ok := mv.defs[b.Name]; ok {
				mv.poisoned[b.Name] = true
			}
			mv.defs[b.Name] = irDef{value: &b.Value, path: path}
			if b.Value.Kind == "if" {
				collect(b.Value.Then, path.child(irThen))
				collect(b.Value.Else, path.child(irElse))
			} else if b.Value.Kind == "loop" {
				collect(b.Value.Body, path.child(irBody))
			}
		}
	}
	collect(m.Body, irPath{})
	own := false
	for _, p := range m.Params {
		if p.Type == irSHP {
			mv.shp[p.Name] = true
		}
		if p.Name == "txPreimage" {
			own = true
		}
	}
	mv.implicit = !m.IsPublic && implicitTx && !own
	return mv
}

func refTarget(v *ANFValue) (string, bool) {
	if v.Kind == "load_const" && v.ConstString != nil && strings.HasPrefix(*v.ConstString, "@ref:") {
		return strings.TrimPrefix(*v.ConstString, "@ref:"), true
	}
	return "", false
}

func (mv *irMethodView) lookup(name string, from irPath) (irDef, bool) {
	if name == "" || mv.poisoned[name] {
		return irDef{}, false
	}
	d, ok := mv.defs[name]
	if !ok || !irVisible(d.path, from) {
		return irDef{}, false
	}
	return d, true
}

// resolve is what a reference to name made at from resolves to.
func (mv *irMethodView) resolve(name string, from irPath) (string, bool) {
	for hops := 0; hops <= len(mv.defs); hops++ {
		d, ok := mv.lookup(name, from)
		if !ok {
			return "", false
		}
		v := d.value
		switch v.Kind {
		case "load_param":
			if mv.shp[v.Name] {
				return v.Name, true
			}
			return v.Name, mv.implicit && v.Name == "txPreimage"
		case "load_prop":
			return v.Name, mv.implicit && v.Name == "txPreimage"
		}
		next, ok := refTarget(v)
		if !ok {
			return "", false
		}
		name, from = next, d.path
	}
	return "", false
}

// truthOf is what a truthy reference to name made at from implies was checked.
func (mv *irMethodView) truthOf(name string, from irPath, depth int) checks {
	d, ok := mv.lookup(name, from)
	if !ok {
		return checks{}
	}
	return mv.truthValue(d.value, d.path, depth)
}

func (mv *irMethodView) truthValue(v *ANFValue, path irPath, depth int) checks {
	if depth > len(mv.defs) {
		return checks{}
	}
	switch v.Kind {
	case "check_preimage":
		if o, ok := mv.resolve(v.Preimage, path); ok {
			return checks{o: true}
		}
		return checks{}
	case "load_const":
		if v.ConstBool != nil && !*v.ConstBool {
			return nil
		}
		if next, ok := refTarget(v); ok {
			return mv.truthOf(next, path, depth+1)
		}
		return checks{}
	case "if":
		if len(v.Results) > 0 || len(v.Then) == 0 || len(v.Else) == 0 {
			return checks{}
		}
		nt, ne := len(v.Then)-1, len(v.Else)-1
		t := checksUnion(mv.truthOf(v.Cond, path, depth+1),
			mv.truthValue(&v.Then[nt].Value, path.child(irThen).child(nt), depth+1))
		return checksIntersect(t, mv.truthValue(&v.Else[ne].Value, path.child(irElse).child(ne), depth+1))
	}
	return checks{}
}

// AssertPreimageRules returns the first D9 / GK-GAP-010 / D14 violation, or nil.
func AssertPreimageRules(program *ANFProgram) error {
	var errs []string
	for _, p := range program.Properties {
		if p.Type == irSHP {
			errs = append(errs, irPreimagePropertyMessage(p.Name))
		}
	}
	// A method_call resolves exactly as stack lowering inlines it: to the LAST
	// non-public, non-constructor method of that name (codegen/stack.go). The
	// loader refuses duplicate names first; this never relies on that alone.
	privates := map[string]*ANFMethod{}
	for i := range program.Methods {
		m := &program.Methods[i]
		if !m.IsPublic && m.Name != "constructor" {
			privates[m.Name] = m
		}
	}
	implicitTx := false
	publics := 0
	allHaveTx := true
	for i := range program.Methods {
		m := &program.Methods[i]
		if !m.IsPublic || m.Name == "constructor" {
			continue
		}
		publics++
		has := false
		for _, p := range m.Params {
			if p.Name == "txPreimage" && p.Type == irSHP {
				has = true
			}
		}
		allHaveTx = allHaveTx && has
	}
	implicitTx = publics > 0 && allHaveTx
	for _, p := range program.Properties {
		if p.Name == "txPreimage" {
			implicitTx = false
		}
	}

	// Keyed by method identity, never by name.
	memo := map[*ANFMethod]map[string]bool{}
	var mustChecked func(m *ANFMethod, stack map[*ANFMethod]bool) map[string]bool
	mustChecked = func(m *ANFMethod, stack map[*ANFMethod]bool) map[string]bool {
		if r, ok := memo[m]; ok {
			return r
		}
		if stack[m] {
			return map[string]bool{}
		}
		mv := newIRMethodView(m, implicitTx)
		inner := map[*ANFMethod]bool{m: true}
		for k := range stack {
			inner[k] = true
		}
		var walk func(bs []ANFBinding, at irPath, in map[string]bool) map[string]bool
		walk = func(bs []ANFBinding, at irPath, in map[string]bool) map[string]bool {
			done := map[string]bool{}
			for k := range in {
				done[k] = true
			}
			for i := range bs {
				v := &bs[i].Value
				path := at.child(i)
				switch v.Kind {
				case "assert":
					if c := mv.truthOf(v.ValueRef, path, 0); c != nil {
						for k := range c {
							done[k] = true
						}
					}
				case "if":
					t := walk(v.Then, path.child(irThen), done)
					e := walk(v.Else, path.child(irElse), done)
					done = map[string]bool{}
					for k := range t {
						if e[k] {
							done[k] = true
						}
					}
				case "method_call":
					if target, ok := privates[v.Method]; ok {
						checked := mustChecked(target, inner)
						for pi, p := range target.Params {
							if !checked[p.Name] || pi >= len(v.Args) {
								continue
							}
							if o, ok := mv.resolve(v.Args[pi], path); ok {
								done[o] = true
							}
						}
					}
				}
			}
			return done
		}
		result := walk(m.Body, irPath{}, map[string]bool{})
		memo[m] = result
		return result
	}

	for i := range program.Methods {
		m := &program.Methods[i]
		if m.Name == "constructor" {
			continue
		}
		mv := newIRMethodView(m, implicitTx)
		var visit func(bs []ANFBinding, at irPath)
		visit = func(bs []ANFBinding, at irPath) {
			for j := range bs {
				v := &bs[j].Value
				path := at.child(j)
				switch v.Kind {
				case "call":
					if irPreimageExtractors[v.Func] {
						ok := false
						if len(v.Args) > 0 {
							_, ok = mv.resolve(v.Args[0], path)
						}
						if !ok {
							errs = append(errs, irUncheckedPreimageArgMessage(v.Func))
						}
					}
				case "method_call":
					if target, ok := privates[v.Method]; ok {
						for pi, p := range target.Params {
							if p.Type != irSHP {
								continue
							}
							ok := false
							if pi < len(v.Args) {
								_, ok = mv.resolve(v.Args[pi], path)
							}
							if !ok {
								errs = append(errs, irUncheckedPreimageArgMessage(target.Name))
								break
							}
						}
					}
				case "if":
					visit(v.Then, path.child(irThen))
					visit(v.Else, path.child(irElse))
				case "loop":
					visit(v.Body, path.child(irBody))
				}
			}
		}
		visit(m.Body, irPath{})
		if m.IsPublic {
			done := mustChecked(m, map[*ANFMethod]bool{})
			for _, p := range m.Params {
				if p.Type == irSHP && !done[p.Name] {
					errs = append(errs, irPreimageNotCheckedMessage(m.Name, p.Name))
				}
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("IR validation: %s", strings.Join(errs, "; "))
	}
	return nil
}

// AssertUniqueMethodNames refuses a repeated method name with GK-BUG-015's
// shared text: the source validator refuses it, --ir did not, so two bodies
// could share a name and a name-keyed lookup answer for the wrong one.
func AssertUniqueMethodNames(program *ANFProgram) error {
	seen := map[string]bool{}
	for _, m := range program.Methods {
		if seen[m.Name] {
			return fmt.Errorf("IR validation: method '%s' is already declared in this contract and cannot be re-declared", m.Name)
		}
		seen[m.Name] = true
	}
	return nil
}
