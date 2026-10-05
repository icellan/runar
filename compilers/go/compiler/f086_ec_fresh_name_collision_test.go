package compiler

// F-086 — a name minted by the EC optimizer must never collide with a name the
// method already uses.
//
// The scalar-fusing rules bind the folded scalar under a generated name
// (`<binding>_k` since N-112, `<binding>_sum` before; disambiguated by nextTempName) just before the rewritten
// binding. nextTempName only consulted the top-level body bindings, so a method
// PARAM named `<binding>_sum` was shadowed: stack lowering resolves a name to
// its shallowest slot, and a later `load_param` of that param read the folded
// scalar. Reachable from `--ir`, where names are attacker-chosen. Pre-fix,
// param `s_sum` + `s = ecAdd(ecMulGen(2), ecMulGen(3))` + `assert(s_sum == 999)`
// compiled to a script that accepts s_sum = 5 and rejects the honest 999
// (@bsv/sdk Spend.validate, strict v1 — F-086 remediation log).
//
// Proves: the minted name is fresh w.r.t. every binding (at any depth), param
// and property; colliding programs compile to exactly the script of their
// renamed twins; the no-collision name is unchanged.
// Does not prove: anything about names minted by stack lowering
// (`_codePart`, `__param_*`, `__merge$*`).

import (
	"encoding/json"
	"testing"

	"github.com/icellan/runar/compilers/go/frontend"
	"github.com/icellan/runar/compilers/go/ir"
)

func f086ProgramJSON(t *testing.T, bodyName, kParam string) []byte {
	t.Helper()
	type m = map[string]any
	var body []any
	if bodyName != "" {
		body = append(body, m{"name": bodyName, "value": m{"kind": "load_const", "value": 999}})
	}
	body = append(body,
		m{"name": "t1", "value": m{"kind": "load_const", "value": 2}},
		m{"name": "t2", "value": m{"kind": "call", "func": "ecMulGen", "args": []string{"t1"}}},
		m{"name": "t3", "value": m{"kind": "load_const", "value": 3}},
		m{"name": "t4", "value": m{"kind": "call", "func": "ecMulGen", "args": []string{"t3"}}},
		m{"name": "s", "value": m{"kind": "call", "func": "ecAdd", "args": []string{"t2", "t4"}}},
		m{"name": "t5", "value": m{"kind": "load_param", "name": "p"}},
		m{"name": "t6", "value": m{"kind": "bin_op", "op": "===", "left": "s", "right": "t5"}},
		m{"name": "t7", "value": m{"kind": "assert", "value": "t6"}},
		m{"name": "t8", "value": m{"kind": "load_param", "name": kParam}},
	)
	rhs := bodyName
	if bodyName == "" {
		body = append(body, m{"name": "t9c", "value": m{"kind": "load_const", "value": 999}})
		rhs = "t9c"
	}
	body = append(body,
		m{"name": "t9", "value": m{"kind": "bin_op", "op": "===", "left": "t8", "right": rhs}},
		m{"name": "t10", "value": m{"kind": "assert", "value": "t9"}},
	)
	prog := m{
		"contractName": "EcOptCollide",
		"properties":   []any{},
		"methods": []any{
			m{"name": "constructor", "isPublic": false, "params": []any{},
				"body": []any{m{"name": "t0", "value": m{"kind": "call", "func": "super", "args": []string{}}}}},
			m{"name": "unlock", "isPublic": true,
				"params": []any{m{"name": "p", "type": "Point"}, m{"name": kParam, "type": "bigint"}},
				"body":   body},
		},
	}
	data, err := json.Marshal(prog)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func f086OptimizedUnlock(t *testing.T, data []byte) ir.ANFMethod {
	t.Helper()
	program, err := ir.LoadIRFromBytes(data)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, method := range frontend.OptimizeEC(program).Methods {
		if method.Name == "unlock" {
			return method
		}
	}
	t.Fatal("no unlock method")
	return ir.ANFMethod{}
}

// f086FusedScalar returns the constant the rewritten `s` consumes — the unique
// prior binding of its arg.
func f086FusedScalar(t *testing.T, method ir.ANFMethod) string {
	t.Helper()
	idx := -1
	for i, b := range method.Body {
		if b.Name == "s" {
			idx = i
		}
	}
	s := method.Body[idx].Value
	if s.Kind != "call" || s.Func != "ecMulGen" {
		t.Fatalf("s not rewritten to ecMulGen: %+v", s)
	}
	arg := s.Args[0]
	for _, p := range method.Params {
		if p.Name == arg {
			t.Fatalf("fused scalar %q is a param name", arg)
		}
	}
	var prior []ir.ANFBinding
	for _, b := range method.Body[:idx] {
		if b.Name == arg {
			prior = append(prior, b)
		}
	}
	if len(prior) != 1 || prior[0].Value.ConstBigInt == nil {
		t.Fatalf("fused scalar %q bound %d times / not a bigint const", arg, len(prior))
	}
	return prior[0].Value.ConstBigInt.String()
}

func f086AssertSingleAssignment(t *testing.T, method ir.ANFMethod) {
	t.Helper()
	seen := map[string]bool{}
	for _, p := range method.Params {
		seen[p.Name] = true
	}
	for _, b := range method.Body {
		if seen[b.Name] {
			t.Errorf("binding %q reuses a param or binding name", b.Name)
		}
		seen[b.Name] = true
	}
}

func TestF086_EcOptimizer_NoCollisionKeepsHistoricalName(t *testing.T) {
	method := f086OptimizedUnlock(t, f086ProgramJSON(t, "", "k"))
	found := false
	for _, b := range method.Body {
		found = found || b.Name == "s_k"
	}
	if !found {
		t.Errorf("expected helper binding s_k, got %+v", method.Body)
	}
	if got := f086FusedScalar(t, method); got != "5" {
		t.Errorf("fused scalar = %s, want 5", got)
	}
}

func TestF086_EcOptimizer_BodyBindingNotShadowed(t *testing.T) {
	method := f086OptimizedUnlock(t, f086ProgramJSON(t, "s_k", "k"))
	f086AssertSingleAssignment(t, method)
	if got := f086FusedScalar(t, method); got != "5" {
		t.Errorf("fused scalar = %s, want 5", got)
	}
}

func TestF086_EcOptimizer_ParamNotShadowed(t *testing.T) {
	method := f086OptimizedUnlock(t, f086ProgramJSON(t, "", "s_k"))
	f086AssertSingleAssignment(t, method)
	if got := f086FusedScalar(t, method); got != "5" {
		t.Errorf("fused scalar = %s, want 5", got)
	}
}

func TestF086_EcOptimizer_CollidingProgramsCompileLikeRenamedTwins(t *testing.T) {
	hex := func(data []byte) string {
		art, err := CompileFromIRBytes(data, CompileOptions{DisableConstantFolding: true})
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		return art.Script
	}
	if hex(f086ProgramJSON(t, "s_k", "k")) != hex(f086ProgramJSON(t, "zz_unused", "k")) {
		t.Error("body-binding collision changed the script")
	}
	if hex(f086ProgramJSON(t, "", "s_k")) != hex(f086ProgramJSON(t, "", "zz")) {
		t.Error("param collision changed the script")
	}
}
