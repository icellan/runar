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
func OptimizeEC(program *ir.ANFProgram) *ir.ANFProgram {
	for mi := range program.Methods {
		optimizeMethodEC(&program.Methods[mi])
	}
	return program
}

func optimizeMethodEC(method *ir.ANFMethod) {
	// Build a lookup map from binding name to its value.
	lookup := make(map[string]*ir.ANFValue)
	for i := range method.Body {
		lookup[method.Body[i].Name] = &method.Body[i].Value
	}

	anyChanged := false
	changed := true
	for changed {
		changed = false
		var newBindings []ir.ANFBinding // new bindings to insert before a given binding
		insertBefore := make(map[string][]ir.ANFBinding)

		for i := range method.Body {
			b := &method.Body[i]
			extra, ok := optimizeBindingECWithInserts(b, lookup)
			if ok {
				changed = true
				anyChanged = true
				if len(extra) > 0 {
					insertBefore[b.Name] = extra
					// Register new bindings in lookup map
					for j := range extra {
						lookup[extra[j].Name] = &extra[j].Value
					}
				}
			}
		}
		_ = newBindings

		if len(insertBefore) > 0 {
			var rebuilt []ir.ANFBinding
			for _, b := range method.Body {
				if pre, ok := insertBefore[b.Name]; ok {
					rebuilt = append(rebuilt, pre...)
				}
				rebuilt = append(rebuilt, b)
			}
			method.Body = rebuilt
			// Rebuild lookup from scratch since slice was reallocated
			lookup = make(map[string]*ir.ANFValue)
			for i := range method.Body {
				lookup[method.Body[i].Name] = &method.Body[i].Value
			}
		}
	}

	// Only run dead binding elimination if we actually rewrote something,
	// to avoid incorrectly pruning bindings in non-EC methods.
	if anyChanged {
		eliminateDeadBindings(method)
	}
}

// optimizeBindingECWithInserts is like optimizeBindingEC but also returns
// any new bindings that should be inserted before the current binding.
//
// The actual rule set is loaded from optimizer/ec-rules.json (embedded via
// go:embed in ec_rules_engine.go); this function simply delegates to the
// generic rule engine. Adding a new rule to the JSON file makes it active
// without any changes here, provided it's tagged "go" (or untagged) and
// fits the engine's match/replace grammar.
func optimizeBindingECWithInserts(b *ir.ANFBinding, lookup map[string]*ir.ANFValue) ([]ir.ANFBinding, bool) {
	v := &b.Value
	if v.Kind != "call" {
		return nil, false
	}
	return applyECRules(b, lookup)
}

func optimizeBindingEC(b *ir.ANFBinding, lookup map[string]*ir.ANFValue) bool {
	_, ok := optimizeBindingECWithInserts(b, lookup)
	return ok
}

// nextTempName generates a unique temp binding name not already in lookup.
// Used by the rule engine when emitting synthetic helper bindings.
func nextTempName(base string, lookup map[string]*ir.ANFValue) string {
	if _, exists := lookup[base]; !exists {
		return base
	}
	for i := 0; ; i++ {
		candidate := fmt.Sprintf("%s_r10_%d", base, i)
		if _, exists := lookup[candidate]; !exists {
			return candidate
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers — shared between anf_optimize.go (driver/DCE) and
// ec_rules_engine.go (matcher/replacer). The engine uses these to resolve
// bound variables and emit rewritten bindings.
// ---------------------------------------------------------------------------

// resolveConstBigInt returns the big.Int value if the named binding is a
// load_const bigint. Used by the rule engine for compile-time folding of
// scalar arithmetic in replace templates.
func resolveConstBigInt(name string, lookup map[string]*ir.ANFValue) *big.Int {
	v := lookup[name]
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

// eliminateDeadBindings removes bindings that are not referenced by any other
// binding, iteratively until no more can be removed.
func eliminateDeadBindings(method *ir.ANFMethod) {
	for {
		refs := collectAllRefs(method.Body)
		var kept []ir.ANFBinding
		removed := false
		for _, b := range method.Body {
			if _, used := refs[b.Name]; used || hasSideEffect(&b.Value) {
				kept = append(kept, b)
			} else {
				removed = true
			}
		}
		method.Body = kept
		if !removed {
			break
		}
	}
}

// collectAllRefs collects all binding names referenced in a list of bindings.
func collectAllRefs(bindings []ir.ANFBinding) map[string]bool {
	refs := make(map[string]bool)
	for _, b := range bindings {
		collectValueRefs(&b.Value, refs)
	}
	return refs
}

// collectValueRefs collects all name references from an ANFValue.
func collectValueRefs(v *ir.ANFValue, refs map[string]bool) {
	switch v.Kind {
	case "load_param":
		// Do NOT track @ref: targets here — matches TS collectRefsFromValue
		// which breaks on load_param without collecting refs.
	case "load_prop":
		// references the property by name, not a binding
	case "load_const":
		// Track @ref: aliases as references to prevent DCE
		if v.ConstString != nil && strings.HasPrefix(*v.ConstString, "@ref:") {
			refs[strings.TrimPrefix(*v.ConstString, "@ref:")] = true
		}
	case "bin_op":
		refs[v.Left] = true
		refs[v.Right] = true
	case "unary_op":
		refs[v.Operand] = true
	case "call":
		for _, arg := range v.Args {
			refs[arg] = true
		}
	case "method_call":
		refs[v.Object] = true
		for _, arg := range v.Args {
			refs[arg] = true
		}
	case "if":
		refs[v.Cond] = true
		for _, tb := range v.Then {
			collectValueRefs(&tb.Value, refs)
		}
		for _, eb := range v.Else {
			collectValueRefs(&eb.Value, refs)
		}
	case "loop":
		for _, lb := range v.Body {
			collectValueRefs(&lb.Value, refs)
		}
	case "assert":
		if v.ValueRef != "" {
			refs[v.ValueRef] = true
		}
	case "update_prop":
		if v.ValueRef != "" {
			refs[v.ValueRef] = true
		}
	case "check_preimage":
		if v.Preimage != "" {
			refs[v.Preimage] = true
		}
	case "add_output":
		if v.Satoshis != "" {
			refs[v.Satoshis] = true
		}
		for _, sv := range v.StateValues {
			refs[sv] = true
		}
	}
}

// hasSideEffect returns true if the binding has side effects and should not be eliminated.
func hasSideEffect(v *ir.ANFValue) bool {
	switch v.Kind {
	case "assert", "update_prop", "check_preimage", "add_output", "deserialize_state":
		return true
	case "if":
		// If any branch has side effects, keep it
		for _, tb := range v.Then {
			if hasSideEffect(&tb.Value) {
				return true
			}
		}
		for _, eb := range v.Else {
			if hasSideEffect(&eb.Value) {
				return true
			}
		}
	case "loop":
		for _, lb := range v.Body {
			if hasSideEffect(&lb.Value) {
				return true
			}
		}
	}
	return false
}
