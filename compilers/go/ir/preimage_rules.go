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

type irMethodView struct {
	defs     map[string]*ANFValue
	dup      map[string]bool
	shp      map[string]bool
	implicit bool
}

func newIRMethodView(m *ANFMethod, implicitTx bool) *irMethodView {
	mv := &irMethodView{defs: map[string]*ANFValue{}, dup: map[string]bool{}, shp: map[string]bool{}}
	var collect func(bs []ANFBinding)
	collect = func(bs []ANFBinding) {
		for i := range bs {
			b := &bs[i]
			if _, ok := mv.defs[b.Name]; ok {
				mv.dup[b.Name] = true
			}
			mv.defs[b.Name] = &b.Value
			if b.Value.Kind == "if" {
				collect(b.Value.Then)
				collect(b.Value.Else)
			} else if b.Value.Kind == "loop" {
				collect(b.Value.Body)
			}
		}
	}
	collect(m.Body)
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

func (mv *irMethodView) resolve(name string) (string, bool) {
	seen := map[string]bool{}
	for {
		if name == "" || mv.dup[name] || seen[name] {
			return "", false
		}
		seen[name] = true
		v, ok := mv.defs[name]
		if !ok {
			return "", false
		}
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
		name = next
	}
}

// truthChecks is what a truthy `name` implies was checked.
func (mv *irMethodView) truthChecks(name string, seen map[string]bool) checks {
	if mv.dup[name] || seen[name] {
		return checks{}
	}
	seen[name] = true
	v, ok := mv.defs[name]
	if !ok {
		return checks{}
	}
	switch v.Kind {
	case "check_preimage":
		if o, ok := mv.resolve(v.Preimage); ok {
			return checks{o: true}
		}
		return checks{}
	case "load_const":
		if v.ConstBool != nil && !*v.ConstBool {
			return nil
		}
		if next, ok := refTarget(v); ok {
			return mv.truthChecks(next, seen)
		}
		return checks{}
	case "if":
		if len(v.Results) > 0 || len(v.Then) == 0 || len(v.Else) == 0 {
			return checks{}
		}
		t := checksUnion(mv.truthChecks(v.Cond, seen), mv.truthChecks(v.Then[len(v.Then)-1].Name, seen))
		return checksIntersect(t, mv.truthChecks(v.Else[len(v.Else)-1].Name, seen))
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
	methods := map[string]*ANFMethod{}
	for i := range program.Methods {
		methods[program.Methods[i].Name] = &program.Methods[i]
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

	memo := map[string]map[string]bool{}
	var mustChecked func(m *ANFMethod, stack map[string]bool) map[string]bool
	mustChecked = func(m *ANFMethod, stack map[string]bool) map[string]bool {
		if r, ok := memo[m.Name]; ok {
			return r
		}
		if stack[m.Name] {
			return map[string]bool{}
		}
		mv := newIRMethodView(m, implicitTx)
		inner := map[string]bool{m.Name: true}
		for k := range stack {
			inner[k] = true
		}
		var walk func(bs []ANFBinding, in map[string]bool) map[string]bool
		walk = func(bs []ANFBinding, in map[string]bool) map[string]bool {
			done := map[string]bool{}
			for k := range in {
				done[k] = true
			}
			for i := range bs {
				v := &bs[i].Value
				switch v.Kind {
				case "assert":
					if c := mv.truthChecks(v.ValueRef, map[string]bool{}); c != nil {
						for k := range c {
							done[k] = true
						}
					}
				case "if":
					t := walk(v.Then, done)
					e := walk(v.Else, done)
					done = map[string]bool{}
					for k := range t {
						if e[k] {
							done[k] = true
						}
					}
				case "method_call":
					if target, ok := methods[v.Method]; ok && !target.IsPublic {
						checked := mustChecked(target, inner)
						for pi, p := range target.Params {
							if !checked[p.Name] || pi >= len(v.Args) {
								continue
							}
							if o, ok := mv.resolve(v.Args[pi]); ok {
								done[o] = true
							}
						}
					}
				}
			}
			return done
		}
		result := walk(m.Body, map[string]bool{})
		memo[m.Name] = result
		return result
	}

	for i := range program.Methods {
		m := &program.Methods[i]
		if m.Name == "constructor" {
			continue
		}
		mv := newIRMethodView(m, implicitTx)
		var visit func(bs []ANFBinding)
		visit = func(bs []ANFBinding) {
			for j := range bs {
				v := &bs[j].Value
				switch v.Kind {
				case "call":
					if irPreimageExtractors[v.Func] {
						ok := false
						if len(v.Args) > 0 {
							_, ok = mv.resolve(v.Args[0])
						}
						if !ok {
							errs = append(errs, irUncheckedPreimageArgMessage(v.Func))
						}
					}
				case "method_call":
					if target, ok := methods[v.Method]; ok && !target.IsPublic {
						for pi, p := range target.Params {
							if p.Type != irSHP {
								continue
							}
							ok := false
							if pi < len(v.Args) {
								_, ok = mv.resolve(v.Args[pi])
							}
							if !ok {
								errs = append(errs, irUncheckedPreimageArgMessage(target.Name))
								break
							}
						}
					}
				case "if":
					visit(v.Then)
					visit(v.Else)
				case "loop":
					visit(v.Body)
				}
			}
		}
		visit(m.Body)
		if m.IsPublic {
			done := mustChecked(m, map[string]bool{})
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
