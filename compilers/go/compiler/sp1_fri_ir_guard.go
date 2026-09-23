package compiler

import (
	"errors"

	"github.com/icellan/runar/compilers/go/frontend"
	"github.com/icellan/runar/compilers/go/ir"
)

// R-012 / CL-BUG-093 — the `--ir` entry point bypassed the entire frontend.
//
// `frontend.Validate` runs only on the `CompileFromSource*` paths.
// `CompileFromIR`, `CompileFromIRBytes` and `CompileFromProgram` never call it,
// so the `verifySP1FRI` refusal — a validator diagnostic — never fired on ANF
// IR input, and IR reaching the verifier compiled clean through `--ir`.
//
// Why the guard keys on the call:
//
//	What the IR carries is the OBSERVABLE — a `call` binding naming
//	`verifySP1FRI`. That is exactly what `codegen/stack.go`'s lowering
//	dispatches on to emit the verifier body, so its presence is a faithful
//	answer to "does this program reach the verifier?" independent of which
//	source (if any) produced the IR.
//
// F-007: the verifier is not implemented for v1, so this refusal is
// unconditional. The invoker-side `CompileOptions.AcknowledgeUnsoundSP1Fri` /
// `--acknowledge-unsound-sp1-fri` override, and the source-path stand-down,
// were removed; on the source path frontend.Validate has already refused the
// same program before this is reached.

// guardUnsoundSP1FriIR refuses any program that reaches the SP1 FRI verifier.
// Returns nil only when the program does not reach it.
func guardUnsoundSP1FriIR(program *ir.ANFProgram) error {
	if !programCallsSP1FriVerifier(program) {
		return nil
	}
	return errors.New(frontend.SP1FriNotImplementedError)
}

// programCallsSP1FriVerifier reports whether any method body of the ANF program
// contains a `call` binding naming `verifySP1FRI`, at any nesting depth.
func programCallsSP1FriVerifier(program *ir.ANFProgram) bool {
	if program == nil {
		return false
	}
	for i := range program.Methods {
		if walkBindingsForSP1Fri(program.Methods[i].Body) {
			return true
		}
	}
	return false
}

// walkBindingsForSP1Fri descends every nested binding list an `ir.ANFValue` can
// hold. `if` hides bindings in Then/Else and `loop` in Body; a scan of only the
// top-level list of each method walks straight past a call placed in any of
// them.
//
// TestSP1FriIRWalker_WalksEveryNestedBindingList reflects over `ir.ANFValue` and
// fails the build if a future ANF kind introduces a nested `[]ANFBinding` field
// this function does not descend into — such a field would silently reopen the
// bypass.
func walkBindingsForSP1Fri(bindings []ir.ANFBinding) bool {
	for i := range bindings {
		v := &bindings[i].Value
		if v.Kind == "call" && v.Func == "verifySP1FRI" {
			return true
		}
		if walkBindingsForSP1Fri(v.Then) ||
			walkBindingsForSP1Fri(v.Else) ||
			walkBindingsForSP1Fri(v.Body) {
			return true
		}
	}
	return false
}
