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
//                                must equal on repeat use — the same
//                                binding through @ref: aliases, F-269)
//     0, 1, ...                  integer literal (matches load_const bigint)
//     { "func": F, "args": [...] }   nested call; resolves the arg through
//                                the ANF value map, following @ref:
//                                aliases (F-269, canonicalName)
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
//   gate (optional): { "of": "ecAdd" | "ecMul" | "ecAddNegCancel", "operand": "$name" }
//                                N-104: the rewrite replaces a builtin that
//                                validates the bound operand first; emit that
//                                validation (as plain ANF, before the
//                                rewritten binding) so the rewrite cannot
//                                accept an operand the builtin would reject.
//                                See emitOperandGate.
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
	Gate      *ecGate  // N-104: operand validation the rewrite must keep, or nil
	Fuses     []int    // N-460: operand positions holding the inner calls a fusion subsumes, or nil
	Supported []string // empty = supported by all compilers
}

// ecGate names the builtin whose operand validation a rewrite keeps, and the
// pattern variable bound to that operand.
type ecGate struct {
	Of      string // "ecAdd", "ecMul" or "ecAddNegCancel"
	Operand string // pattern variable name, without the '$'
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
		var gate *ecGate
		if gateRaw, ok := rr["gate"]; ok {
			gm, ok := gateRaw.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("rule %q: gate must be an object", name)
			}
			of, _ := gm["of"].(string)
			if of != "ecAdd" && of != "ecMul" && of != "ecAddNegCancel" {
				return nil, fmt.Errorf("rule %q: gate.of must be ecAdd, ecMul or ecAddNegCancel, got %q", name, of)
			}
			operand, _ := gm["operand"].(string)
			if len(operand) < 2 || operand[0] != '$' {
				return nil, fmt.Errorf("rule %q: gate.operand must be a $var", name)
			}
			gate = &ecGate{Of: of, Operand: operand[1:]}
		}
		var fuses []int
		if fRaw, ok := rr["fuses"]; ok {
			fl, ok := fRaw.([]interface{})
			if !ok {
				return nil, fmt.Errorf("rule %q: fuses must be an array", name)
			}
			for _, f := range fl {
				n, ok := f.(float64)
				if !ok || n < 0 || n != float64(int(n)) {
					return nil, fmt.Errorf("rule %q: fuses must hold operand positions", name)
				}
				fuses = append(fuses, int(n))
			}
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
			Gate:      gate,
			Fuses:     fuses,
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
func matchRule(rule ecRule, b *ir.ANFBinding, lookup map[string]*ir.ANFValue, rebound map[string]bool) (ecBindings, bool) {
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
		if !matchPatternArg(pat, v.Args[i], false, lookup, rebound, binds) {
			return nil, false
		}
	}
	return binds, true
}

// matchPatternArg matches a pattern against the value referenced by argName.
// For nested-call patterns, resolves argName through lookup and matches the
// resulting value. Every lookup follows @ref: aliases (F-269, canonicalName);
// a pattern variable still binds the LITERAL argument name, so a rewrite
// emits the names it matched.
//
// F-269 attempt 2: a name without a fixed identity (rebound, or an alias
// cycle; see canonicalName) never satisfies a repeated $var, and a $var bound
// INSIDE a nested call pattern must have one — that name is lifted out of an
// earlier binding and the replace template or gate may emit it at this later
// site, where a rebound name already holds a different value (R7's $x, R9's
// $p, R8r's $x; R9/R10's nested scalars only need a constant, which an
// unstable name never resolves to anyway).
func matchPatternArg(pat ecPattern, argName string, nested bool, lookup map[string]*ir.ANFValue, rebound map[string]bool, binds ecBindings) bool {
	switch {
	case pat.Var != "":
		if prev, ok := binds[pat.Var]; ok {
			// Same-var must bind to the same underlying binding, through
			// aliases (the TS sameBinding rule). Two distinct bindings that
			// merely hold equal constants are NOT the same $x (N-353): every
			// tier decides operand identity by name.
			cp, okP := canonicalName(prev, lookup, rebound)
			ca, okA := canonicalName(argName, lookup, rebound)
			return okP && okA && cp == ca
		}
		if nested {
			if _, ok := canonicalName(argName, lookup, rebound); !ok {
				return false
			}
		}
		binds[pat.Var] = argName
		return true

	case pat.IntLit != nil:
		v := resolveValue(argName, lookup, rebound)
		if v == nil || v.Kind != "load_const" || v.ConstBigInt == nil {
			return false
		}
		return v.ConstBigInt.Cmp(pat.IntLit) == 0

	case pat.ConstName == "INFINITY":
		return isInfinityOrZeroMulGen(argName, lookup, rebound)

	case pat.ConstName == "G":
		return isGOrOneMulGen(argName, lookup, rebound)

	case pat.Call != nil:
		v := resolveValue(argName, lookup, rebound)
		if v == nil || v.Kind != "call" || v.Func != pat.Call.Func {
			return false
		}
		if len(v.Args) != len(pat.Call.Args) {
			return false
		}
		for i, sub := range pat.Call.Args {
			if !matchPatternArg(sub, v.Args[i], true, lookup, rebound, binds) {
				return false
			}
		}
		return true
	}
	return false
}

// canonicalName returns the binding argName ultimately names, following
// load_const "@ref:<x>" aliases — pass 04's `const y = <expr>` and the ones
// alias-producing rules leave behind (F-269, user decision R77; the TS
// anf-ec.ts canonicalName).
//
// ok is false when argName has no position-independent identity: ANF re-emits
// a local's name when the source reassigns it (top level or in an if/loop
// arm), so a REBOUND name means different values at different sites, and the
// lookup (last-wins over the whole body) holds only one of them. Two uses of
// a rebound name are not "the same $x", and nothing lifted out of an earlier
// binding may name one. An alias cycle (only hand-written --ir) is not ok
// either. A hop is never taken INTO a rebound name: the chain stops at the
// last name bound once, which is itself a fixed value (`const y = a` captured
// the `a` of its own position), and its value is the opaque alias.
func canonicalName(argName string, lookup map[string]*ir.ANFValue, rebound map[string]bool) (string, bool) {
	if rebound[argName] {
		return "", false
	}
	seen := map[string]bool{argName: true}
	cur := argName
	for {
		v := lookup[cur]
		if v == nil || v.Kind != "load_const" || v.ConstString == nil || len(*v.ConstString) <= 5 || (*v.ConstString)[:5] != "@ref:" {
			return cur, true
		}
		next := (*v.ConstString)[5:]
		if rebound[next] {
			return cur, true
		}
		if seen[next] {
			return "", false
		}
		seen[next] = true
		cur = next
	}
}

// resolveValue is the value argName resolves to through aliases, or nil when
// it has no fixed identity (canonicalName's ok == false).
func resolveValue(argName string, lookup map[string]*ir.ANFValue, rebound map[string]bool) *ir.ANFValue {
	c, ok := canonicalName(argName, lookup, rebound)
	if !ok {
		return nil
	}
	return lookup[c]
}

// isInfinityOrZeroMulGen matches either a load_const INFINITY or an
// ecMulGen(0) call — both are representations of the point at infinity.
func isInfinityOrZeroMulGen(name string, lookup map[string]*ir.ANFValue, rebound map[string]bool) bool {
	v := resolveValue(name, lookup, rebound)
	if v == nil {
		return false
	}
	if v.Kind == "load_const" && v.ConstString != nil && *v.ConstString == infinityHex {
		return true
	}
	if v.Kind == "call" && v.Func == "ecMulGen" && len(v.Args) == 1 {
		inner := resolveValue(v.Args[0], lookup, rebound)
		if inner != nil && inner.Kind == "load_const" && inner.ConstBigInt != nil && inner.ConstBigInt.Sign() == 0 {
			return true
		}
	}
	return false
}

// isGOrOneMulGen matches either a load_const G or an ecMulGen(1) call.
func isGOrOneMulGen(name string, lookup map[string]*ir.ANFValue, rebound map[string]bool) bool {
	v := resolveValue(name, lookup, rebound)
	if v == nil {
		return false
	}
	if v.Kind == "load_const" && v.ConstString != nil && *v.ConstString == gHex {
		return true
	}
	if v.Kind == "call" && v.Func == "ecMulGen" && len(v.Args) == 1 {
		inner := resolveValue(v.Args[0], lookup, rebound)
		if inner != nil && inner.Kind == "load_const" && inner.ConstBigInt != nil && inner.ConstBigInt.Cmp(big.NewInt(1)) == 0 {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Replace
// ---------------------------------------------------------------------------

// opOperandsAreConst reports whether every {"op": ...} argument in the rule's
// replace template has BOTH operands resolving to a compile-time load_const
// bigint — i.e. whether the scalar arithmetic the rewrite introduces can be
// folded away entirely rather than emitted as a runtime bin_op.
//
// This is the guard that keeps the Go engine in step with the other six
// tiers. TS, Rust, Python, Zig, Ruby and Java all implement the scalar-fusing
// rules (ec-mulgen-linear, ec-mul-associative, ec-mul-distributive) with a
// constant-operand precondition; the Go engine, being data-driven, used to
// fire them on runtime scalars as well. The resulting script was valid — the
// unreduced sum is put back into [0, n-1] by emitEcMulGen's scalar reduce
// before the ladder sees it — but it was a DIFFERENT script from every other
// tier for the same source, which conformance invariant 2 forbids. Rather
// than let a byte-level divergence hide behind "both are correct", the
// engine now declines the rewrite exactly where the other tiers decline it.
func opOperandsAreConst(rule ecRule, binds ecBindings, lookup map[string]*ir.ANFValue, rebound map[string]bool) bool {
	if rule.Replace.Call == nil {
		return true
	}
	for _, a := range rule.Replace.Call.Args {
		if a.Op == nil {
			continue
		}
		if resolveConstBigInt(binds[a.Op.Lhs], lookup, rebound) == nil {
			return false
		}
		if resolveConstBigInt(binds[a.Op.Rhs], lookup, rebound) == nil {
			return false
		}
	}
	return true
}

// applyReplace mutates b.Value according to the rule's replace template.
// Returns any extra bindings to insert before b.
func applyReplace(rule ecRule, b *ir.ANFBinding, binds ecBindings, lookup map[string]*ir.ANFValue, used map[string]bool, rebound map[string]bool) []ir.ANFBinding {
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
				helperName, helperBinding := buildOpHelper(b, rule, a.Op, binds, lookup, used, rebound)
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

// buildOpHelper emits a helper binding holding a scalar +/*, folded at compile
// time modulo the curve order.
//
// Both operands are guaranteed to be load_const bigints: applyECRules refuses
// the rule outright when they are not (opOperandsAreConst). That is what keeps
// the fold — and therefore the mod-n reduction — unconditional here, and what
// keeps this engine byte-compatible with the six hand-written tiers, none of
// which fires a scalar-fusing rule on runtime operands.
func buildOpHelper(b *ir.ANFBinding, rule ecRule, op *ecOpArg, binds ecBindings, lookup map[string]*ir.ANFValue, used map[string]bool, rebound map[string]bool) (string, ir.ANFBinding) {
	lhsName := binds[op.Lhs]
	rhsName := binds[op.Rhs]
	// N-112: `<binding>_k`, the TS anf-ec.ts freshName(`${binding.name}_k`, usedNames).
	helperName := nextTempName(b.Name+"_k", lookup, used)

	lhsVal := resolveConstBigInt(lhsName, lookup, rebound)
	rhsVal := resolveConstBigInt(rhsName, lookup, rebound)
	if lhsVal == nil || rhsVal == nil {
		panic(fmt.Sprintf("ec rule %q: buildOpHelper reached with non-constant operands (%q, %q) — opOperandsAreConst should have declined the rule", rule.Name, lhsName, rhsName))
	}

	var folded *big.Int
	switch op.Op {
	case "+":
		folded = new(big.Int).Add(lhsVal, rhsVal)
		folded.Mod(folded, curveN)
	case "*":
		folded = new(big.Int).Mul(lhsVal, rhsVal)
		folded.Mod(folded, curveN)
	}
	// N-112: the canonical bigint encoding (a JSON number, or "<n>n" when
	// wider than 2^53) every other load_const uses. It used to be a bare "5"
	// string in --emit-ir, unlike TS and the other tiers.
	return helperName, ir.ANFBinding{
		Name:  helperName,
		Value: makeLoadConstInt(folded),
	}
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

// applyECRules tries each rule in order on binding b. Returns any extra
// bindings and whether a rewrite occurred.
func applyECRules(b *ir.ANFBinding, lookup map[string]*ir.ANFValue, used map[string]bool, rebound map[string]bool, scope *fusionScope) ([]ir.ANFBinding, bool) {
	for _, rule := range ecRules {
		if !ruleAppliesToGo(rule) {
			continue
		}
		binds, ok := matchRule(rule, b, lookup, rebound)
		if !ok {
			continue
		}
		// Checked BEFORE applyReplace: applyReplace mutates b.Value and
		// registers helper bindings in lookup, so there is no way to back out
		// of it once started.
		if !opOperandsAreConst(rule, binds, lookup, rebound) {
			continue
		}
		// N-460: a fusing rule fires only when it lets an inner call go.
		if len(rule.Fuses) > 0 && scope != nil && !fusionEliminates(rule.Fuses, b, lookup, rebound, scope) {
			continue
		}
		var gate []ir.ANFBinding
		if rule.Gate != nil {
			gate = emitOperandGate(rule.Gate.Of, b.Name, binds[rule.Gate.Operand], lookup, used)
		}
		extra := applyReplace(rule, b, binds, lookup, used, rebound)
		return append(gate, extra...), true
	}
	return nil, false
}

// ---------------------------------------------------------------------------
// N-460 fusion guard
// ---------------------------------------------------------------------------

// fusionScope is what a fusing rule (a rule with "fuses": R9, R10, R11)
// needs to know at its fire site — the TS reference's FusionScope
// (packages/runar-compiler/src/optimizer/anf-ec.ts).
//
// A fusion replaces the outer call with ONE new scalar multiplication, so it
// shrinks the script only if removeGateSubsumedEcCalls then drops an inner
// call it read. Each fusing rule therefore fires only when at least one of its
// inner operands is ELIMINABLE (fusionEliminates):
//
//   - every name on its alias chain (the operand, each @ref: hop, the call
//     binding itself — canonicalName's walk) has exactly one referrer: the
//     rewritten binding for the operand, the previous hop for the rest. Any
//     other reader keeps the inner call alive after the fusion;
//   - the call is an ecMulGen bound in the current scope or an enclosing one
//     inside the same loop body (frame). It needs no witness, but one bound
//     outside a loop the fusion sits in would trade one multiplication for one
//     per iteration;
//   - or the call is an ecMul bound in the current scope itself (local): the
//     fused ecMul on the same point is then its witness. One bound in an
//     enclosing scope has no witness (the fused call is nested) and stays.
//
// referrers is computed once per sweep, from the body the sweep starts with
// (countReferrers), and not updated as the sweep rewrites. A rewrite only adds
// a reference to a name its own binding, or the inner binding it lifts from,
// already read, so a stale count is never too low. Every tier computes it the
// same way, because which rules fire decides the bytes.
type fusionScope struct {
	referrers func() map[string]int
	local     map[string]bool
	frame     map[string]bool
}

// countReferrers is the N-460 referrer count per name: the bindings, at any
// depth, whose value reads it (once per binding, however many operands name
// it; an if reads its Cond, its arms' bindings are counted themselves), plus
// one for each name in an if's Results and one for a private method's return
// binding (F-108): the two things removeGateSubsumedEcCalls protects.
func countReferrers(body []ir.ANFBinding, method *ir.ANFMethod) map[string]int {
	counts := make(map[string]int)
	var walk func(bindings []ir.ANFBinding)
	walk = func(bindings []ir.ANFBinding) {
		for i := range bindings {
			v := &bindings[i].Value
			reads := make(map[string]bool)
			switch v.Kind {
			case "if":
				reads[v.Cond] = true
				for _, r := range v.Results {
					reads[r] = true
				}
			case "loop":
			default:
				collectValueRefs(v, reads)
			}
			for name := range reads {
				counts[name]++
			}
			switch v.Kind {
			case "if":
				walk(v.Then)
				walk(v.Else)
			case "loop":
				walk(v.Body)
			}
		}
	}
	walk(body)
	if returnsLastBinding(method) && len(body) > 0 {
		counts[body[len(body)-1].Name]++
	}
	return counts
}

// fusionEliminates reports whether fusing the inner operands at positions
// `fuses` of b's call lets at least one inner call go (N-460).
func fusionEliminates(fuses []int, b *ir.ANFBinding, lookup map[string]*ir.ANFValue, rebound map[string]bool, scope *fusionScope) bool {
	for _, pos := range fuses {
		if pos >= len(b.Value.Args) {
			continue
		}
		operand := b.Value.Args[pos]
		c, ok := canonicalName(operand, lookup, rebound)
		if !ok {
			continue
		}
		// canonicalName already walked this chain, so every hop is an @ref:.
		single := true
		for cur := operand; ; {
			if scope.referrers()[cur] != 1 {
				single = false
				break
			}
			if cur == c {
				break
			}
			cur = (*lookup[cur].ConstString)[5:]
		}
		if !single {
			continue
		}
		v := lookup[c]
		if v == nil || v.Kind != "call" {
			continue
		}
		if (v.Func == "ecMulGen" && scope.frame[c]) || (v.Func == "ecMul" && scope.local[c]) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// N-104 operand gate
// ---------------------------------------------------------------------------

// fieldP is the secp256k1 field prime.
var fieldP, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)

// emitOperandGate returns the bindings that re-check, at runtime, what the
// builtin `of` would have checked about operand q before computing anything.
// Byte-for-byte the TS reference (emitAddOperandGate / emitMulOperandGate in
// packages/runar-compiler/src/optimizer/anf-ec.ts):
//
//	ecAdd: assert(ecPointX(q) < p && ecPointY(q) < p)   width (CL-BUG-095) + canonicity (R-117)
//	ecMul: assert(q === O || ecOnCurve(q))               on-curve-or-O (R-157)
//	ecAddNegCancel: assert(ecPointX(q) === 0 || ecPointY(q) !== 0)
//	       the adder's y = 0 doubling abort (N-110), kept by R8/R8r (N-251,
//	       emitNegCancelGate); the px == 0 term keeps O + O = O
//
// Built only from forms no rule matches, because this engine runs to a fixed
// point and TS makes one pass: a gate a later pass could rewrite would split
// the tiers. Each gate ends in an assert, which DCE keeps along with what it
// reads.
func emitOperandGate(of, base, q string, lookup map[string]*ir.ANFValue, used map[string]bool) []ir.ANFBinding {
	var out []ir.ANFBinding
	add := func(suffix string, v ir.ANFValue) string {
		name := nextTempName(base+suffix, lookup, used)
		out = append(out, ir.ANFBinding{Name: name, Value: v})
		return name
	}
	if of == "ecAdd" {
		px := add("_px", ir.ANFValue{Kind: "call", Func: "ecPointX", Args: []string{q}})
		py := add("_py", ir.ANFValue{Kind: "call", Func: "ecPointY", Args: []string{q}})
		fp := add("_fp", ir.ANFValue{Kind: "load_const", RawValue: ir.BigIntToRawJSON(fieldP), ConstBigInt: new(big.Int).Set(fieldP)})
		xOk := add("_pxok", ir.ANFValue{Kind: "bin_op", Op: "<", Left: px, Right: fp})
		yOk := add("_pyok", ir.ANFValue{Kind: "bin_op", Op: "<", Left: py, Right: fp})
		ok := add("_ok", ir.ANFValue{Kind: "bin_op", Op: "&&", Left: xOk, Right: yOk})
		add("_gate", makeAssert(ok))
		return out
	}
	if of == "ecAddNegCancel" {
		px := add("_px", ir.ANFValue{Kind: "call", Func: "ecPointX", Args: []string{q}})
		py := add("_py", ir.ANFValue{Kind: "call", Func: "ecPointY", Args: []string{q}})
		zero := add("_zero", makeLoadConstInt(big.NewInt(0)))
		xZero := add("_pxz", ir.ANFValue{Kind: "bin_op", Op: "===", Left: px, Right: zero})
		yNonZero := add("_pynz", ir.ANFValue{Kind: "bin_op", Op: "!==", Left: py, Right: zero})
		ok := add("_ok", ir.ANFValue{Kind: "bin_op", Op: "||", Left: xZero, Right: yNonZero})
		add("_gate", makeAssert(ok))
		return out
	}
	infHex := infinityHex
	rawInf, _ := json.Marshal(infHex)
	inf := add("_inf", ir.ANFValue{Kind: "load_const", RawValue: rawInf, ConstString: &infHex})
	isInf := add("_isinf", ir.ANFValue{Kind: "bin_op", Op: "===", Left: q, Right: inf, ResultType: "bytes"})
	onCurve := add("_oncurve", ir.ANFValue{Kind: "call", Func: "ecOnCurve", Args: []string{q}})
	ok := add("_ok", ir.ANFValue{Kind: "bin_op", Op: "||", Left: isInf, Right: onCurve})
	add("_gate", makeAssert(ok))
	return out
}
