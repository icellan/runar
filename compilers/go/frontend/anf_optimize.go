package frontend

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/icellan/runar/compilers/go/ir"
)

// ---------------------------------------------------------------------------
// EC constants — secp256k1 curve parameters
// ---------------------------------------------------------------------------

var (
	curveN, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	genXHex   = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	genYHex   = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
	gHex      = genXHex + genYHex // 128 hex chars = 64 bytes
)

// infinityHex is 128 zero hex chars (64 zero bytes), representing the point at infinity.
var infinityHex = strings.Repeat("0", 128)

// ---------------------------------------------------------------------------
// OptimizeEC applies algebraic EC optimizations to the ANF program.
// ---------------------------------------------------------------------------

// OptimizeEC walks the ANF program and rewrites EC calls using algebraic
// identities (identity element, scalar simplifications, double-negate, etc.).
// It mutates the program in-place and returns it.
//
// N-097: dead binding elimination then runs over EVERY method iff a rewrite
// fired in ANY method, exactly the gate of the TS reference (anf-ec.ts
// optimizeEC). It used to run only on the methods that were themselves
// rewritten, so a dead pure binding in a method next to an EC-rewritten one
// survived here alone and the script carried a push/drop no other tier emits.
func OptimizeEC(program *ir.ANFProgram) *ir.ANFProgram {
	// N-201: candidates[mi] is the set of names method mi referenced before
	// any rewrite — the candidate set of the nested prune below. It is nil
	// for a method no rule fired in (whose pre-rewrite refs are its refs).
	candidates := make([]map[string]bool, len(program.Methods))
	anyChanged := false
	for mi := range program.Methods {
		if refs, changed := optimizeMethodEC(&program.Methods[mi], program.Properties); changed {
			candidates[mi] = refs
			anyChanged = true
		}
	}
	// Only run dead binding elimination if we actually rewrote something,
	// to avoid incorrectly pruning bindings in non-EC programs.
	// Delegates to the standalone DCE module (frontend/dce.go).
	if anyChanged {
		for mi := range program.Methods {
			method := &program.Methods[mi]
			// N-201: an untouched method's pre-rewrite refs are its refs
			// now, taken before the top-level DCE as TS takes them.
			refs := candidates[mi]
			if refs == nil {
				refs = make(map[string]bool)
				for j := range method.Body {
					collectValueRefs(&method.Body[j].Value, refs)
				}
			}
			EliminateDeadBindings(method)
			// N-201: a rewrite inside an if arm or a loop body orphans its
			// operands there, and the DCE above filters only the top level;
			// an orphan left in an arm unbalances the arms (the N-446
			// hazard). Same candidate rule as the constant folder's prune.
			EliminateDeadBindingsAmong(method, refs)
			// N-113: drop the inner ecMul/ecMulGen calls a fusion orphaned
			// whose abort is still performed, then prune what that orphans.
			for removeGateSubsumedEcCalls(method, refs) {
				EliminateDeadBindingsAmong(method, refs)
			}
		}
	}
	return program
}

// removeGateSubsumedEcCalls is N-113 (the TS reference's anf-ec.ts function of
// the same name): it removes dead scalar multiplications whose only effect, a
// possible abort, is provably still performed, and reports whether it removed
// any.
//
//   - `ecMulGen(<const k>)` cannot abort: its point is the fixed generator,
//     which passes ecMul's operand gate, and the ladder reduces any k.
//   - `ecMul(q, <const k>)` aborts exactly when its operand gate
//     `q === O || ecOnCurve(q)` fails (R-157). It may go when a WITNESS
//     performs the same gate: another `ecMul(q', _)`, q' the same binding as q
//     (canonicalName, F-269), not itself removable, in the same scope or an
//     ENCLOSING one — never a nested one, which runs only on some paths.
//   - `ecNegate` is never removed: R7, R8 and R8r rely on it as a gate.
//
// Only a removal candidate goes (a name referenced before the EC pass ran —
// the inner call a fusion orphaned), referenced nowhere in the method now, not
// a private method's return value (F-108) and not one of its if's Results.
func removeGateSubsumedEcCalls(method *ir.ANFMethod, candidates map[string]bool) bool {
	rebound := collectReboundNames(method)
	lookup := make(map[string]*ir.ANFValue)
	refs := make(map[string]bool)
	var index func(bindings []ir.ANFBinding)
	index = func(bindings []ir.ANFBinding) {
		for i := range bindings {
			b := &bindings[i]
			lookup[b.Name] = &b.Value
			collectValueRefs(&b.Value, refs)
			switch b.Value.Kind {
			case "if":
				index(b.Value.Then)
				index(b.Value.Else)
			case "loop":
				index(b.Value.Body)
			}
		}
	}
	index(method.Body)
	keepLast := returnsLastBinding(method)

	isConstScalar := func(name string) bool {
		return resolveConstBigInt(name, lookup, rebound) != nil
	}
	removable := func(b *ir.ANFBinding, protect map[string]bool, isReturn bool) bool {
		v := &b.Value
		if v.Kind != "call" || isReturn || !candidates[b.Name] || refs[b.Name] || protect[b.Name] {
			return false
		}
		switch v.Func {
		case "ecMulGen":
			return len(v.Args) == 1 && isConstScalar(v.Args[0])
		case "ecMul":
			if len(v.Args) != 2 || !isConstScalar(v.Args[1]) {
				return false
			}
			_, ok := canonicalName(v.Args[0], lookup, rebound)
			return ok
		}
		return false
	}

	var filter func(bindings []ir.ANFBinding, outer []string, protect map[string]bool, topLevel bool) ([]ir.ANFBinding, bool)
	filter = func(bindings []ir.ANFBinding, outer []string, protect map[string]bool, topLevel bool) ([]ir.ANFBinding, bool) {
		isCand := make([]bool, len(bindings))
		witnesses := append([]string(nil), outer...)
		for i := range bindings {
			isCand[i] = removable(&bindings[i], protect, topLevel && keepLast && i == len(bindings)-1)
		}
		for i := range bindings {
			v := &bindings[i].Value
			if !isCand[i] && v.Kind == "call" && v.Func == "ecMul" && len(v.Args) == 2 {
				if c, ok := canonicalName(v.Args[0], lookup, rebound); ok {
					witnesses = append(witnesses, c)
				}
			}
		}
		hasWitness := func(name string) bool {
			c, _ := canonicalName(name, lookup, rebound)
			for _, w := range witnesses {
				if w == c {
					return true
				}
			}
			return false
		}
		changed := false
		out := make([]ir.ANFBinding, 0, len(bindings))
		for i := range bindings {
			b := bindings[i]
			v := &b.Value
			if isCand[i] && (v.Func == "ecMulGen" || hasWitness(v.Args[0])) {
				changed = true
				continue
			}
			switch v.Kind {
			case "if":
				results := make(map[string]bool, len(v.Results))
				for _, r := range v.Results {
					results[r] = true
				}
				thenB, thenChanged := filter(v.Then, witnesses, results, false)
				elseB, elseChanged := filter(v.Else, witnesses, results, false)
				if thenChanged || elseChanged {
					v.Then = thenB
					v.Else = elseB
					changed = true
				}
			case "loop":
				bodyB, bodyChanged := filter(v.Body, witnesses, map[string]bool{}, false)
				if bodyChanged {
					v.Body = bodyB
					changed = true
				}
			}
			out = append(out, b)
		}
		if !changed {
			return bindings, false
		}
		return out, true
	}

	body, changed := filter(method.Body, nil, map[string]bool{}, true)
	if changed {
		method.Body = body
	}
	return changed
}

// optimizeMethodEC applies the EC rewrite rules to one method's bindings —
// top level, if arms and loop bodies (N-201) — until none fires, and reports
// whether any did. When one did, it also returns the names the method
// referenced BEFORE the first rewrite (the N-201 nested-prune candidates);
// optimizeBodyEC never mutates its input, so the old body is still intact
// when they are collected.
func optimizeMethodEC(method *ir.ANFMethod, properties []ir.ANFProperty) (map[string]bool, bool) {
	// F-086: names a minted helper binding must avoid (params, properties,
	// nested bindings — the lookup below only covers the current scope).
	used := collectUsedNames(method, properties)
	// F-269: names bound more than once; alias resolution never passes
	// through one (see canonicalName in ec_rules_engine.go).
	rebound := collectReboundNames(method)

	var before map[string]bool
	for {
		// N-460: the fusion guard's referrer counts, once per sweep, from the
		// body the sweep starts with. Counted on first use, so a method no
		// fusing rule matches in is never walked (optimizeBodyEC leaves its
		// input intact, so the count is the same whenever it is taken).
		start := method.Body
		var counts map[string]int
		referrers := func() map[string]int {
			if counts == nil {
				counts = countReferrers(start, method)
			}
			return counts
		}
		body, changed := optimizeBodyEC(method.Body, map[string]*ir.ANFValue{}, "", used, rebound, referrers, map[string]bool{})
		if !changed {
			break
		}
		if before == nil {
			before = make(map[string]bool)
			for j := range method.Body {
				collectValueRefs(&method.Body[j].Value, before)
			}
		}
		method.Body = body
	}
	return before, before != nil
}

// optimizeBodyEC is one left-to-right sweep over a scope (the TS reference's
// optimizeBodyOnce, anf-ec.ts): each binding is tried once against the values
// of the bindings before it, as already rewritten in this sweep. N-201: it
// descends into if arms (then before else) and loop bodies at the position of
// their binding, each with its own lookup seeded from the enclosing scope, so
// nothing an arm binds is visible in the other arm or after the if; `hidden`
// is a loop's iteration variable, which the body must not resolve through an
// outer binding of the same name. Helpers a rewrite mints are inserted just
// before the rewritten binding, in the same scope.
func optimizeBodyEC(body []ir.ANFBinding, outer map[string]*ir.ANFValue, hidden string, used map[string]bool, rebound map[string]bool, referrers func() map[string]int, outerFrame map[string]bool) ([]ir.ANFBinding, bool) {
	// N-460: an if arm sees its enclosing frame, a loop body starts a new one.
	scope := &fusionScope{referrers: referrers, local: make(map[string]bool, len(body)), frame: make(map[string]bool, len(outerFrame)+len(body))}
	for k := range outerFrame {
		scope.frame[k] = true
	}
	for i := range body {
		scope.local[body[i].Name] = true
		scope.frame[body[i].Name] = true
	}
	lookup := make(map[string]*ir.ANFValue, len(outer)+len(body))
	for k, v := range outer {
		lookup[k] = v
	}
	if hidden != "" {
		delete(lookup, hidden)
	}
	changed := false
	out := make([]ir.ANFBinding, 0, len(body))
	for i := range body {
		b := body[i]
		switch b.Value.Kind {
		case "if":
			thenB, thenChanged := optimizeBodyEC(b.Value.Then, lookup, "", used, rebound, referrers, scope.frame)
			elseB, elseChanged := optimizeBodyEC(b.Value.Else, lookup, "", used, rebound, referrers, scope.frame)
			if thenChanged || elseChanged {
				b.Value.Then = thenB
				b.Value.Else = elseB
				changed = true
			}
		case "loop":
			bodyB, bodyChanged := optimizeBodyEC(b.Value.Body, lookup, b.Value.IterVar, used, rebound, referrers, map[string]bool{})
			if bodyChanged {
				b.Value.Body = bodyB
				changed = true
			}
		default:
			// The binding's own (pre-rewrite) value is visible to its rule,
			// as in TS, where it is registered before tryRewrite.
			cur := b.Value
			lookup[b.Name] = &cur
			extra, ok := optimizeBindingECWithInserts(&b, lookup, used, rebound, scope)
			if ok {
				changed = true
				// N-218: every helper a rewrite mints (the N-104/N-251
				// gate bindings, the fused-scalar helper) takes the
				// rewritten binding's own SourceLoc, mirroring F-343 in
				// the TS reference (anf-ec.ts optimizeBodyOnce) — it
				// exists only because of that source expression, and
				// stack lowering maps opcodes through binding.SourceLoc.
				for j := range extra {
					extra[j].SourceLoc = b.SourceLoc
					hv := extra[j].Value
					lookup[extra[j].Name] = &hv
				}
				out = append(out, extra...)
			}
		}
		final := b.Value
		lookup[b.Name] = &final
		out = append(out, b)
	}
	if !changed {
		return body, false
	}
	return out, true
}

// optimizeBindingECWithInserts is like optimizeBindingEC but also returns
// any new bindings that should be inserted before the current binding.
//
// The actual rule set is loaded from optimizer/ec-rules.json (embedded via
// go:embed in ec_rules_engine.go); this function simply delegates to the
// generic rule engine. Adding a new rule to the JSON file makes it active
// without any changes here, provided it's tagged "go" (or untagged) and
// fits the engine's match/replace grammar.
//
// N-460: scope is the fusion guard's context; nil (a single binding tried
// outside any method sweep) applies no guard.
func optimizeBindingECWithInserts(b *ir.ANFBinding, lookup map[string]*ir.ANFValue, used map[string]bool, rebound map[string]bool, scope *fusionScope) ([]ir.ANFBinding, bool) {
	v := &b.Value
	if v.Kind != "call" {
		return nil, false
	}
	return applyECRules(b, lookup, used, rebound, scope)
}

func optimizeBindingEC(b *ir.ANFBinding, lookup map[string]*ir.ANFValue, used map[string]bool, rebound map[string]bool) bool {
	_, ok := optimizeBindingECWithInserts(b, lookup, used, rebound, nil)
	return ok
}

// collectUsedNames returns every name the method already uses — binding names
// at any depth (if/loop arms included), loop iteration variables, params, and
// the contract's properties (F-086). A scalar-fusing rewrite mints a new
// binding; ANF is single-assignment and stack lowering resolves a name to its
// shallowest slot, so a minted name that is already in use silently aliases
// the two values. `--ir` input chooses these names freely.
func collectUsedNames(method *ir.ANFMethod, properties []ir.ANFProperty) map[string]bool {
	used := make(map[string]bool)
	for _, p := range properties {
		used[p.Name] = true
	}
	for _, p := range method.Params {
		used[p.Name] = true
	}
	var walk func(bindings []ir.ANFBinding)
	walk = func(bindings []ir.ANFBinding) {
		for i := range bindings {
			b := &bindings[i]
			used[b.Name] = true
			switch b.Value.Kind {
			case "load_param", "load_prop":
				used[b.Value.Name] = true
			case "if":
				walk(b.Value.Then)
				walk(b.Value.Else)
			case "loop":
				used[b.Value.IterVar] = true
				walk(b.Value.Body)
			}
		}
	}
	walk(method.Body)
	return used
}

// collectReboundNames returns every name bound more than once in the method —
// binding names at any depth (if/loop arms included) and loop iteration
// variables (F-269, the TS anf-ec.ts collectReboundNames). ANF is not
// single-assignment for source locals: a reassignment re-emits the local's
// name, so an alias chain through such a name can land on a value the alias
// never held. canonicalName never resolves through one.
func collectReboundNames(method *ir.ANFMethod) map[string]bool {
	seen := make(map[string]bool)
	rebound := make(map[string]bool)
	bind := func(name string) {
		if seen[name] {
			rebound[name] = true
		} else {
			seen[name] = true
		}
	}
	var walk func(bindings []ir.ANFBinding)
	walk = func(bindings []ir.ANFBinding) {
		for i := range bindings {
			b := &bindings[i]
			bind(b.Name)
			switch b.Value.Kind {
			case "if":
				walk(b.Value.Then)
				walk(b.Value.Else)
			case "loop":
				bind(b.Value.IterVar)
				walk(b.Value.Body)
			}
		}
	}
	walk(method.Body)
	return rebound
}

// nextTempName generates a unique temp binding name not already in lookup nor
// in used (F-086), and reserves it in used. Used by the rule engine when
// emitting synthetic helper bindings. N-112: same scheme as TS anf-ec.ts
// freshName — `base`, else the first unused `base_<i>` from i = 1.
func nextTempName(base string, lookup map[string]*ir.ANFValue, used map[string]bool) string {
	taken := func(name string) bool {
		_, exists := lookup[name]
		return exists || used[name]
	}
	name := base
	for i := 1; taken(name); i++ {
		name = fmt.Sprintf("%s_%d", base, i)
	}
	used[name] = true
	return name
}

// ---------------------------------------------------------------------------
// Helpers — shared between anf_optimize.go (driver/DCE) and
// ec_rules_engine.go (matcher/replacer). The engine uses these to resolve
// bound variables and emit rewritten bindings.
// ---------------------------------------------------------------------------

// resolveConstBigInt returns the big.Int value if the named binding is a
// load_const bigint, through @ref: aliases (F-269). Used by the rule engine for compile-time folding of
// scalar arithmetic in replace templates.
func resolveConstBigInt(name string, lookup map[string]*ir.ANFValue, rebound map[string]bool) *big.Int {
	v := resolveValue(name, lookup, rebound)
	if v == nil || v.Kind != "load_const" {
		return nil
	}
	return v.ConstBigInt
}

// makeAlias rewrites a binding to be a load_const referencing another binding via @ref:.
func makeAlias(b *ir.ANFBinding, target string) {
	refStr := "@ref:" + target
	raw, _ := json.Marshal(refStr)
	b.Value = ir.ANFValue{
		Kind:        "load_const",
		RawValue:    raw,
		ConstString: &refStr,
	}
}

// makeInfinityConst rewrites a binding to be a load_const with the INFINITY point value.
func makeInfinityConst(b *ir.ANFBinding) {
	infHex := infinityHex
	raw, _ := json.Marshal(infHex)
	infBytes, _ := hex.DecodeString(infHex)
	b.Value = ir.ANFValue{
		Kind:        "load_const",
		RawValue:    raw,
		ConstString: &infHex,
		ConstBigInt: nil,
		ConstBool:   nil,
	}
	_ = infBytes
}

// makeGConst rewrites a binding to be a load_const with the generator point G value.
func makeGConst(b *ir.ANFBinding) {
	g := gHex
	raw, _ := json.Marshal(g)
	b.Value = ir.ANFValue{
		Kind:        "load_const",
		RawValue:    raw,
		ConstString: &g,
	}
}

// ---------------------------------------------------------------------------
// Dead binding elimination
// ---------------------------------------------------------------------------
//
// The DCE pass lives in its own discrete module now (frontend/dce.go).
// Lowercase aliases below keep the legacy intra-package symbols compiling
// (existing tests reference these names directly).

func eliminateDeadBindings(method *ir.ANFMethod) { EliminateDeadBindings(method) }

func hasSideEffect(v *ir.ANFValue) bool { return HasSideEffect(v) }
