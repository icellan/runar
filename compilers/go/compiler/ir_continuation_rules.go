package compiler

import (
	"errors"

	"github.com/icellan/runar/compilers/go/frontend"
	"github.com/icellan/runar/compilers/go/ir"
)

// D18 on the --ir path. CompileFromIR* skips typecheck, where the source path
// refuses a public stateful method that declares its own outputs and has a
// path that writes state but reaches no addOutput (that write would be dropped
// and the contract's satoshis would leave with the spend). The rule is
// re-derived from the ANF, per path, through if arms, loop bodies and
// method_calls to private methods. Mirrors assertIrNoDroppedContinuation in
// packages/runar-compiler/src/passes/continuation-rules.ts. Called for
// StatefulSmartContract programs after the N-101 scaffolding check.
func checkIRNoDroppedContinuation(program *ir.ANFProgram) error {
	privates := make(map[string]*ir.ANFMethod)
	for i := range program.Methods {
		m := &program.Methods[i]
		if !m.IsPublic && m.Name != "constructor" {
			privates[m.Name] = m
		}
	}
	for i := range program.Methods {
		m := &program.Methods[i]
		if !m.IsPublic || m.Name == "constructor" {
			continue
		}
		if irDropsContinuation(m, privates) {
			return errors.New(frontend.DroppedContinuationMessage(m.Name))
		}
	}
	return nil
}

// irDropsContinuation is the per-path rule on ANF: update_prop = state write,
// add_output = addOutput, add_raw_output / add_output = a declared output
// (suppresses the auto-continuation). `if` unions its arms, a loop body unions
// with skipping it, a method_call to a private method composes with that
// method's exits.
func irDropsContinuation(method *ir.ANFMethod, privates map[string]*ir.ANFMethod) bool {
	var declares func(bindings []ir.ANFBinding, seen map[string]bool) bool
	declares = func(bindings []ir.ANFBinding, seen map[string]bool) bool {
		for i := range bindings {
			v := &bindings[i].Value
			if v.Kind == "add_output" || v.Kind == "add_raw_output" {
				return true
			}
			if v.Kind == "method_call" {
				if t, ok := privates[v.Method]; ok && !seen[t.Name] {
					seen[t.Name] = true
					if declares(t.Body, seen) {
						return true
					}
				}
			}
			if declares(v.Then, seen) || declares(v.Else, seen) || declares(v.Body, seen) {
				return true
			}
		}
		return false
	}
	if !declares(method.Body, map[string]bool{}) {
		return false
	}

	exitsOf := map[string]map[int]bool{}
	inProgress := map[string]bool{}
	orAll := func(s map[int]bool, bits int) map[int]bool {
		out := map[int]bool{}
		for x := range s {
			out[x|bits] = true
		}
		return out
	}
	union := func(a, b map[int]bool) map[int]bool {
		out := map[int]bool{}
		for x := range a {
			out[x] = true
		}
		for x := range b {
			out[x] = true
		}
		return out
	}
	var run func(bindings []ir.ANFBinding, states map[int]bool) map[int]bool
	run = func(bindings []ir.ANFBinding, states map[int]bool) map[int]bool {
		s := states
		for i := range bindings {
			v := &bindings[i].Value
			switch {
			case v.Kind == "update_prop":
				s = orAll(s, irPathW)
			case v.Kind == "add_output":
				s = orAll(s, irPathA)
			case v.Kind == "method_call":
				t, ok := privates[v.Method]
				if !ok {
					continue
				}
				ex, cached := exitsOf[t.Name]
				if !cached {
					if inProgress[t.Name] {
						ex = map[int]bool{0: true}
					} else {
						inProgress[t.Name] = true
						ex = run(t.Body, map[int]bool{0: true})
						delete(inProgress, t.Name)
						exitsOf[t.Name] = ex
					}
				}
				out := map[int]bool{}
				for x := range s {
					for y := range ex {
						out[x|y] = true
					}
				}
				s = out
			case v.Then != nil || v.Else != nil:
				t, e := s, s
				if v.Then != nil {
					t = run(v.Then, s)
				}
				if v.Else != nil {
					e = run(v.Else, s)
				}
				s = union(t, e)
			case v.Body != nil:
				s = union(s, run(v.Body, s))
			}
		}
		return s
	}
	for x := range run(method.Body, map[int]bool{0: true}) {
		if x&irPathW != 0 && x&irPathA == 0 {
			return true
		}
	}
	return false
}

const (
	irPathW = 1
	irPathA = 2
)
