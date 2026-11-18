package compiler

import (
	"errors"

	"github.com/icellan/runar/compilers/go/frontend"
	"github.com/icellan/runar/compilers/go/ir"
)

// D18 on the --ir path. CompileFromIR* skips typecheck, where the source path
// refuses a public stateful method that writes state and declares raw outputs
// but no addOutput (its state write would be dropped and the contract's
// satoshis would leave with the spend). The rule is re-derived from the ANF:
// update_prop = state write, add_output / add_raw_output = declared outputs,
// at any depth (if then/else, loop body) and through method_calls to private
// methods. Mirrors assertIrNoDroppedContinuation in
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

func irDropsContinuation(method *ir.ANFMethod, privates map[string]*ir.ANFMethod) bool {
	var writes, raw, add bool
	visited := make(map[string]bool)
	var walk func(bindings []ir.ANFBinding)
	walk = func(bindings []ir.ANFBinding) {
		for i := range bindings {
			v := &bindings[i].Value
			switch v.Kind {
			case "update_prop":
				writes = true
			case "add_raw_output":
				raw = true
			case "add_output":
				add = true
			case "method_call":
				if target, ok := privates[v.Method]; ok && !visited[target.Name] {
					visited[target.Name] = true
					walk(target.Body)
				}
			}
			walk(v.Then)
			walk(v.Else)
			walk(v.Body)
		}
	}
	walk(method.Body)
	return writes && raw && !add
}
