package compiler

import (
	"fmt"

	"github.com/icellan/runar/compilers/go/ir"
)

// F-004 (CL-BUG-084 / CL-BUG-216 / CL-GAP-005) — frontend.Validate runs only on
// the CompileFromSource* paths. CompileFromIR / CompileFromIRBytes /
// CompileFromProgram go from ANF straight to stack lowering, and
// ir.ValidateIR is a structural check only. Two validator rules decide whether
// the emitted script is a covenant or anyone-can-spend, and both are fully
// observable in the ANF, so they are re-asserted here for every program that
// reaches CompileFromProgram:
//
//   - A public method must END with an assert (frontend/validator.go,
//     "public method '%s' must end with an assert() call"). Stack lowering
//     leaves the value of the method's last top-level binding as the script's
//     result and marks the last `assert` it finds as terminal (no OP_VERIFY),
//     so a body with no assert, or with bindings after its last assert,
//     yields a spender-influenced truthy value: `0093` for `x + 0`.
//     Accepted terminals mirror the source rule: `assert`; an `if` whose then
//     AND else arms both end in an accepted terminal; and a `raw_script` with
//     out_arity 1 (the UnsafeSmartContract terminal asm()).
//
//   - A readonly property may only be written in the constructor
//     ("cannot assign to readonly property"). An update_prop on a readonly
//     property in a spending method pushes the new value under the property's
//     name, so every later load_prop reads it instead of the value baked into
//     the locking script. An update_prop naming no declared property is
//     refused for the same reason.
//
// Every checked-in golden expected-ir.json satisfies both rules, so this
// changes no golden bytes; the source path already enforces them on the AST.
func checkIRFrontendRules(program *ir.ANFProgram) error {
	if program == nil {
		return nil
	}
	readonly := make(map[string]bool, len(program.Properties))
	for _, p := range program.Properties {
		readonly[p.Name] = p.Readonly
	}

	if err := checkIRNoRecursion(program); err != nil {
		return err
	}

	for i := range program.Methods {
		m := &program.Methods[i]
		if m.Name == "constructor" {
			continue
		}
		if m.IsPublic && !endsWithTerminalAssert(m.Body) {
			return fmt.Errorf(
				"IR validation: public method '%s' must end with an assert() call (or an if/else whose arms both do, or a terminal raw_script with out_arity 1); otherwise the value its last binding leaves on the stack decides the spend",
				m.Name)
		}
		if err := checkNoReadonlyWrites(m.Body, m.Name, readonly); err != nil {
			return err
		}
	}
	return nil
}

func endsWithTerminalAssert(bindings []ir.ANFBinding) bool {
	if len(bindings) == 0 {
		return false
	}
	last := bindings[len(bindings)-1].Value
	switch last.Kind {
	case "assert":
		return true
	case "if":
		return endsWithTerminalAssert(last.Then) && endsWithTerminalAssert(last.Else)
	case "raw_script":
		return last.OutArity == 1
	}
	return false
}

func checkNoReadonlyWrites(bindings []ir.ANFBinding, methodName string, readonly map[string]bool) error {
	for _, b := range bindings {
		v := &b.Value
		if v.Kind == "update_prop" {
			ro, declared := readonly[v.Name]
			if !declared {
				return fmt.Errorf(
					"IR validation: method '%s' assigns to undeclared property '%s'",
					methodName, v.Name)
			}
			if ro {
				return fmt.Errorf(
					"IR validation: cannot assign to readonly property '%s' in method '%s'. readonly properties may only be assigned in the constructor; a later load_prop would read the assigned value instead of the one baked into the locking script",
					v.Name, methodName)
			}
		}
		for _, nested := range [][]ir.ANFBinding{v.Then, v.Else, v.Body} {
			if err := checkNoReadonlyWrites(nested, methodName, readonly); err != nil {
				return err
			}
		}
	}
	return nil
}

// F-071 (CL-BUG-009): frontend.checkNoRecursion is source-only. Stack
// lowering inlines every method_call to a private method by lowering its body
// in place (codegen/stack.go inlineMethodCall) with no cycle or depth guard,
// so a self- or mutually-recursive method in externally supplied IR recursed
// until the goroutine stack limit — `fatal error: stack overflow`, which no
// recover() catches. Refuse any cycle in the method_call graph here, with the
// frontend's wording. The method named is one that lies ON the cycle.
func checkIRNoRecursion(program *ir.ANFProgram) error {
	callees := make(map[string][]string, len(program.Methods))
	for i := range program.Methods {
		m := &program.Methods[i]
		if m.Name == "constructor" {
			continue
		}
		callees[m.Name] = collectIRMethodCalls(m.Body, nil)
	}

	const (
		unvisited = iota
		onStack
		done
	)
	state := make(map[string]int, len(callees))
	var visit func(name string) string
	visit = func(name string) string {
		state[name] = onStack
		for _, callee := range callees[name] {
			if _, declared := callees[callee]; !declared {
				continue
			}
			switch state[callee] {
			case onStack:
				return callee
			case unvisited:
				if hit := visit(callee); hit != "" {
					return hit
				}
			}
		}
		state[name] = done
		return ""
	}

	for i := range program.Methods {
		name := program.Methods[i].Name
		if name == "constructor" || state[name] != unvisited {
			continue
		}
		if hit := visit(name); hit != "" {
			return fmt.Errorf(
				"IR validation: recursion detected: method '%s' calls itself directly or indirectly. Private methods are inlined at every call site, so a cyclic call graph has no finite lowering",
				hit)
		}
	}
	return nil
}

func collectIRMethodCalls(bindings []ir.ANFBinding, out []string) []string {
	for i := range bindings {
		v := &bindings[i].Value
		if v.Kind == "method_call" {
			out = append(out, v.Method)
		}
		out = collectIRMethodCalls(v.Then, out)
		out = collectIRMethodCalls(v.Else, out)
		out = collectIRMethodCalls(v.Body, out)
	}
	return out
}
