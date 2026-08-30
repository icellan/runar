// Package frontend - EC rule engine driven by the canonical JSON rule file.
//
// The EC optimizer's algebraic rules are defined in optimizer/ec-rules.json
// (checked into the project root as the single source of truth shared with the
// TypeScript compiler). A copy is embedded here so Go tooling can run without
// a project-root checkout; a test verifies byte-identity with the canonical
// file.
//
// Each rule has a match pattern and a replace template:
//
//   match forms:
//     "$name"                    pattern variable (binds on first use,
//                                must equal on repeat use)
//     0, 1, ...                  integer literal (matches load_const bigint)
//     { "func": F, "args": [...] }   nested call; resolves the arg through
//                                the ANF value map
//     { "const": "INFINITY" | "G" }  named constant (matches load_const
//                                with the corresponding hex payload)
//
//   replace forms:
//     "$name"                    alias to the binding bound at match time
//                                (emitted as load_const "@ref:<name>")
//     { "const": "INFINITY" | "G" }  INFINITY or generator constant
//     { "func": F, "args": [...] }   new call binding; args may be "$name"
//                                or { "op": "+"|"*", "args": [A, B] }
//                                which emits a helper binding for the
//                                scalar sum/product (compile-time folded
//                                when both operands are constants, modulo
//                                the curve order; otherwise emitted as a
//                                runtime bin_op).
//
// A rule may carry an optional "supported" list of compiler targets. If
// present and it does not contain "go", the rule is skipped by this engine.
// This lets the JSON list rules that only some compilers implement (rules
// 9 and 11 were historically only implemented in TS); adding a rule without
// a "supported" tag makes it active in every compiler.
package frontend

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/icellan/runar/compilers/go/ir"
)

//go:embed ec-rules.json
var embeddedECRulesJSON []byte

// ecRules holds the parsed rule set used by the optimizer. Initialised at
// package init from the embedded JSON. Tests can override with
// SetECRulesForTesting.
var ecRules []ecRule

// ---------------------------------------------------------------------------
// Rule AST
// ---------------------------------------------------------------------------

type ecRule struct {
	Name      string
	Match     ecPattern
	Replace   ecReplace
	Supported []string // empty = supported by all compilers
}

// ecPattern represents a single match pattern element.
type ecPattern struct {
	// Exactly one of these is non-zero:
	Var       string     // "$x"
	IntLit    *big.Int   // integer literal
	Call      *ecCallPat // nested function call
	ConstName string     // "INFINITY" or "G"
}

type ecCallPat struct {
	Func string
	Args []ecPattern
}

// ecReplace represents the RHS of a rule.
type ecReplace struct {
	// Exactly one of these is non-zero:
	Var       string         // alias to bound var "$x"
	ConstName string         // "INFINITY" or "G"
	Call      *ecCallReplace // call with arg templates
}

type ecCallReplace struct {
	Func string
	Args []ecReplaceArg
}

// ecReplaceArg is an argument inside a replace call — either a bound var or
// an op expression that creates a helper binding.
type ecReplaceArg struct {
	// Exactly one of these is non-zero:
	Var string   // "$x"
	Op  *ecOpArg // {op, args: [A, B]}
}

type ecOpArg struct {
	Op  string // "+" or "*"
	Lhs string // "$name" — must be a bound var
	Rhs string
}

// ---------------------------------------------------------------------------
// JSON parsing
// ---------------------------------------------------------------------------

func init() {
	rules, err := parseECRulesJSON(embeddedECRulesJSON)
	if err != nil {
		panic(fmt.Sprintf("ec-rules.json: %v", err))
	}
	ecRules = rules
}

// SetECRulesForTesting replaces the rule set with a JSON payload. Returns
// the previous rule set so tests can restore it.
func SetECRulesForTesting(jsonBytes []byte) ([]ecRule, error) {
	rules, err := parseECRulesJSON(jsonBytes)
	if err != nil {
		return nil, err
	}
	prev := ecRules
	ecRules = rules
	return prev, nil
}

// RestoreECRulesForTesting restores a previously saved rule set.
func RestoreECRulesForTesting(prev []ecRule) {
	ecRules = prev
}

// ECRuleNames returns the names of all rules currently active for the Go
// compiler (i.e. loaded + with "go" in their supported list).
func ECRuleNames() []string {
	out := make([]string, 0, len(ecRules))
	for _, r := range ecRules {
		if ruleAppliesToGo(r) {
			out = append(out, r.Name)
		}
	}
	return out
}

func ruleAppliesToGo(r ecRule) bool {
	if len(r.Supported) == 0 {
		return true
	}
	for _, c := range r.Supported {
		if c == "go" {
			return true
		}
	}
	return false
}

func parseECRulesJSON(data []byte) ([]ecRule, error) {
	var raw []map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	out := make([]ecRule, 0, len(raw))
	for i, rr := range raw {
		name, _ := rr["name"].(string)
		if name == "" {
			return nil, fmt.Errorf("rule %d: missing name", i)
		}
		matchRaw, ok := rr["match"]
		if !ok {
			return nil, fmt.Errorf("rule %q: missing match", name)
		}
		match, err := parsePattern(matchRaw)
		if err != nil {
			return nil, fmt.Errorf("rule %q: match: %w", name, err)
		}
		replaceRaw, ok := rr["replace"]
		if !ok {
			return nil, fmt.Errorf("rule %q: missing replace", name)
		}
		replace, err := parseReplace(replaceRaw)
		if err != nil {
			return nil, fmt.Errorf("rule %q: replace: %w", name, err)
		}
		var supported []string
		if supRaw, ok := rr["supported"]; ok {
			sl, ok := supRaw.([]interface{})
			if !ok {
				return nil, fmt.Errorf("rule %q: supported must be an array", name)
			}
			for _, s := range sl {
				ss, _ := s.(string)
				if ss != "" {
					supported = append(supported, ss)
				}
			}
		}
		out = append(out, ecRule{
			Name:      name,
			Match:     match,
			Replace:   replace,
			Supported: supported,
		})
	}
	return out, nil
}

func parsePattern(v interface{}) (ecPattern, error) {
	switch x := v.(type) {
	case string:
		if len(x) < 2 || x[0] != '$' {
			return ecPattern{}, fmt.Errorf("pattern string %q: must start with $", x)
		}
		return ecPattern{Var: x[1:]}, nil
	case float64:
		n := big.NewInt(int64(x))
		return ecPattern{IntLit: n}, nil
	case json.Number:
		bi, ok := new(big.Int).SetString(string(x), 10)
		if !ok {
			return ecPattern{}, fmt.Errorf("pattern number %q: not integer", x)
		}
		return ecPattern{IntLit: bi}, nil
	case map[string]interface{}:
		if c, ok := x["const"].(string); ok {
			if c != "INFINITY" && c != "G" {
				return ecPattern{}, fmt.Errorf("const must be INFINITY or G, got %q", c)
			}
			return ecPattern{ConstName: c}, nil
		}
		if fn, ok := x["func"].(string); ok {
			argsRaw, _ := x["args"].([]interface{})
			var args []ecPattern
			for i, a := range argsRaw {
				ap, err := parsePattern(a)
				if err != nil {
					return ecPattern{}, fmt.Errorf("arg %d: %w", i, err)
				}
				args = append(args, ap)
			}
			return ecPattern{Call: &ecCallPat{Func: fn, Args: args}}, nil
		}
		return ecPattern{}, fmt.Errorf("pattern object: expected {const} or {func}")
	default:
		return ecPattern{}, fmt.Errorf("pattern: unexpected type %T", v)
	}
}

func parseReplace(v interface{}) (ecReplace, error) {
	switch x := v.(type) {
	case string:
		if len(x) < 2 || x[0] != '$' {
			return ecReplace{}, fmt.Errorf("replace string %q: must start with $", x)
		}
		return ecReplace{Var: x[1:]}, nil
	case map[string]interface{}:
		if c, ok := x["const"].(string); ok {
			return ecReplace{ConstName: c}, nil
		}
		if fn, ok := x["func"].(string); ok {
			argsRaw, _ := x["args"].([]interface{})
			var args []ecReplaceArg
			for i, a := range argsRaw {
				ra, err := parseReplaceArg(a)
				if err != nil {
					return ecReplace{}, fmt.Errorf("arg %d: %w", i, err)
				}
				args = append(args, ra)
			}
			return ecReplace{Call: &ecCallReplace{Func: fn, Args: args}}, nil
		}
		return ecReplace{}, fmt.Errorf("replace object: expected {const} or {func}")
	default:
		return ecReplace{}, fmt.Errorf("replace: unexpected type %T", v)
	}
}

func parseReplaceArg(v interface{}) (ecReplaceArg, error) {
	switch x := v.(type) {
	case string:
		if len(x) < 2 || x[0] != '$' {
			return ecReplaceArg{}, fmt.Errorf("replace arg string %q: must start with $", x)
		}
		return ecReplaceArg{Var: x[1:]}, nil
	case map[string]interface{}:
		if op, ok := x["op"].(string); ok {
			if op != "+" && op != "*" {
				return ecReplaceArg{}, fmt.Errorf("op must be + or *, got %q", op)
			}
			argsRaw, _ := x["args"].([]interface{})
			if len(argsRaw) != 2 {
				return ecReplaceArg{}, fmt.Errorf("op %q: expected 2 args, got %d", op, len(argsRaw))
			}
			lhs, _ := argsRaw[0].(string)
			rhs, _ := argsRaw[1].(string)
			if lhs == "" || lhs[0] != '$' || rhs == "" || rhs[0] != '$' {
				return ecReplaceArg{}, fmt.Errorf("op %q: args must be $vars", op)
			}
			return ecReplaceArg{Op: &ecOpArg{Op: op, Lhs: lhs[1:], Rhs: rhs[1:]}}, nil
		}
		return ecReplaceArg{}, fmt.Errorf("replace arg object: expected {op}")
	default:
		return ecReplaceArg{}, fmt.Errorf("replace arg: unexpected type %T", v)
	}
}

// ---------------------------------------------------------------------------
// Matcher
// ---------------------------------------------------------------------------

// ecBindings maps pattern variable names to ANF binding names they matched.
type ecBindings map[string]string

// matchRule attempts to match rule against binding b. Returns bindings on
// success.
func matchRule(rule ecRule, b *ir.ANFBinding, lookup map[string]*ir.ANFValue) (ecBindings, bool) {
	if rule.Match.Call == nil {
		// Top-level must be a call pattern — rules cannot match a bare
		// variable or constant at the root.
		return nil, false
	}
	v := &b.Value
	if v.Kind != "call" {
		return nil, false
	}
	if v.Func != rule.Match.Call.Func {
		return nil, false
	}
	if len(v.Args) != len(rule.Match.Call.Args) {
		return nil, false
	}
	binds := ecBindings{}
	for i, pat := range rule.Match.Call.Args {
		if !matchPatternArg(pat, v.Args[i], lookup, binds) {
			return nil, false
		}
	}
	return binds, true
}

// matchPatternArg matches a pattern against the value referenced by argName.
// For nested-call patterns, resolves argName through lookup and matches the
// resulting value.
func matchPatternArg(pat ecPattern, argName string, lookup map[string]*ir.ANFValue, binds ecBindings) bool {
	switch {
	case pat.Var != "":
		if prev, ok := binds[pat.Var]; ok {
			// Same-var must bind to the same underlying argument. We check
			// both the literal arg name and, failing that, whether both
			// arguments resolve to the same constant value — this matters
			// for rule 11 ($p appears twice).
			if prev == argName {
				return true
			}
			return sameResolvedValue(prev, argName, lookup)
		}
		binds[pat.Var] = argName
		return true

	case pat.IntLit != nil:
		v := lookup[argName]
		if v == nil || v.Kind != "load_const" || v.ConstBigInt == nil {
			return false
		}
		return v.ConstBigInt.Cmp(pat.IntLit) == 0

	case pat.ConstName == "INFINITY":
		return isInfinityOrZeroMulGen(argName, lookup)

	case pat.ConstName == "G":
		return isGOrOneMulGen(argName, lookup)

	case pat.Call != nil:
		v := lookup[argName]
		if v == nil || v.Kind != "call" || v.Func != pat.Call.Func {
			return false
		}
		if len(v.Args) != len(pat.Call.Args) {
			return false
		}
		for i, sub := range pat.Call.Args {
			if !matchPatternArg(sub, v.Args[i], lookup, binds) {
				return false
			}
		}
		return true
	}
	return false
}

// sameResolvedValue reports whether two arg names refer to the same value —
// either by name, or both being load_const with the same payload.
func sameResolvedValue(a, b string, lookup map[string]*ir.ANFValue) bool {
	if a == b {
		return true
	}
	va := lookup[a]
	vb := lookup[b]
	if va == nil || vb == nil {
		return false
	}
	if va.Kind != "load_const" || vb.Kind != "load_const" {
		return false
	}
	if va.ConstString != nil && vb.ConstString != nil {
		return *va.ConstString == *vb.ConstString
	}
	if va.ConstBigInt != nil && vb.ConstBigInt != nil {
		return va.ConstBigInt.Cmp(vb.ConstBigInt) == 0
	}
	return false
}

// isInfinityOrZeroMulGen matches either a load_const INFINITY or an
// ecMulGen(0) call — both are representations of the point at infinity.
func isInfinityOrZeroMulGen(name string, lookup map[string]*ir.ANFValue) bool {
	v := lookup[name]
	if v == nil {
		return false
	}
	if v.Kind == "load_const" && v.ConstString != nil && *v.ConstString == infinityHex {
		return true
	}
	if v.Kind == "call" && v.Func == "ecMulGen" && len(v.Args) == 1 {
		inner := lookup[v.Args[0]]
		if inner != nil && inner.Kind == "load_const" && inner.ConstBigInt != nil && inner.ConstBigInt.Sign() == 0 {
			return true
		}
	}
	return false
}

// isGOrOneMulGen matches either a load_const G or an ecMulGen(1) call.
func isGOrOneMulGen(name string, lookup map[string]*ir.ANFValue) bool {
	v := lookup[name]
	if v == nil {
		return false
	}
	if v.Kind == "load_const" && v.ConstString != nil && *v.ConstString == gHex {
		return true
	}
	if v.Kind == "call" && v.Func == "ecMulGen" && len(v.Args) == 1 {
		inner := lookup[v.Args[0]]
		if inner != nil && inner.Kind == "load_const" && inner.ConstBigInt != nil && inner.ConstBigInt.Cmp(big.NewInt(1)) == 0 {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Replace
// ---------------------------------------------------------------------------

// applyReplace mutates b.Value according to the rule's replace template.
// Returns any extra bindings to insert before b.
func applyReplace(rule ecRule, b *ir.ANFBinding, binds ecBindings, lookup map[string]*ir.ANFValue) []ir.ANFBinding {
	r := rule.Replace
	switch {
	case r.Var != "":
		target := binds[r.Var]
		makeAlias(b, target)
		return nil

	case r.ConstName == "INFINITY":
		makeInfinityConst(b)
		return nil

	case r.ConstName == "G":
		makeGConst(b)
		return nil

	case r.Call != nil:
		var extra []ir.ANFBinding
		callArgs := make([]string, 0, len(r.Call.Args))
		for _, a := range r.Call.Args {
			switch {
			case a.Var != "":
				callArgs = append(callArgs, binds[a.Var])
			case a.Op != nil:
				helperName, helperBinding := buildOpHelper(b, rule, a.Op, binds, lookup)
				extra = append(extra, helperBinding)
				callArgs = append(callArgs, helperName)
				// Register immediately so subsequent helpers (if any) see it
				lookup[helperName] = &extra[len(extra)-1].Value
			}
		}
		b.Value = ir.ANFValue{
			Kind: "call",
			Func: r.Call.Func,
			Args: callArgs,
		}
		return extra
	}
	return nil
}

// buildOpHelper emits a helper binding implementing a scalar +/* (modulo the
// curve order for +; plain multiplication for * — matching the existing Go
// behavior where Rule 10 mods by N).
//
// Compile-time folding is used when both operands are load_const bigints.
// Otherwise a runtime bin_op binding is emitted.
func buildOpHelper(b *ir.ANFBinding, rule ecRule, op *ecOpArg, binds ecBindings, lookup map[string]*ir.ANFValue) (string, ir.ANFBinding) {
	lhsName := binds[op.Lhs]
	rhsName := binds[op.Rhs]
	helperName := nextTempName(b.Name+"_sum", lookup)

	lhsVal := resolveConstBigInt(lhsName, lookup)
	rhsVal := resolveConstBigInt(rhsName, lookup)

	if lhsVal != nil && rhsVal != nil {
		var folded *big.Int
		switch op.Op {
		case "+":
			folded = new(big.Int).Add(lhsVal, rhsVal)
			folded.Mod(folded, curveN)
		case "*":
			folded = new(big.Int).Mul(lhsVal, rhsVal)
			folded.Mod(folded, curveN)
		}
		raw, _ := json.Marshal(folded.String())
		binding := ir.ANFBinding{
			Name: helperName,
			Value: ir.ANFValue{
				Kind:        "load_const",
				RawValue:    raw,
				ConstBigInt: folded,
			},
		}
		return helperName, binding
	}

	// Runtime case: bin_op binding. Use the JSON op ("+" or "*") directly —
	// matches the ANF bin_op convention.
	binding := ir.ANFBinding{
		Name: helperName,
		Value: ir.ANFValue{
			Kind:  "bin_op",
			Op:    op.Op,
			Left:  lhsName,
			Right: rhsName,
		},
	}
	return helperName, binding
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

// applyECRules tries each rule in order on binding b. Returns any extra
// bindings and whether a rewrite occurred.
func applyECRules(b *ir.ANFBinding, lookup map[string]*ir.ANFValue) ([]ir.ANFBinding, bool) {
	for _, rule := range ecRules {
		if !ruleAppliesToGo(rule) {
			continue
		}
		binds, ok := matchRule(rule, b, lookup)
		if !ok {
			continue
		}
		extra := applyReplace(rule, b, binds, lookup)
		return extra, true
	}
	return nil, false
}
