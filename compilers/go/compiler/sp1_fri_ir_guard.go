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
// so the `verifySP1FRI` soundness refusal — a validator diagnostic — never
// fired on ANF IR input. IR emitted from an acknowledged contract compiled
// clean through `--ir`: exit 0, no error, no warning, and byte-for-byte the
// same locking script the source path refuses to emit unacknowledged.
//
// Why the guard keys on the call and not on an acknowledgement flag:
//
//	The ANF IR carries no representation of `@acknowledgeUnsoundSP1FriVerifier`.
//	It is a frontend-AST field (`ContractNode.AckUnsoundSP1Fri`) stripped by
//	lowering, and it cannot be added: `ir.ANFProgram`'s JSON is compared
//	byte-for-byte across all seven tiers by the conformance suite, which is why
//	the tier-local metadata that does exist (`ParentClass`,
//	`ANFMethod.SigHashType`) is tagged `json:"-"` and never reaches the wire.
//	Even setting parity aside, a flag inside the IR would be worthless as a
//	security control: `--ir` input is untrusted, so the same party that wrote
//	the verifier call would write the flag authorising it.
//
//	What the IR does carry is the OBSERVABLE — a `call` binding naming
//	`verifySP1FRI`. That is exactly what `codegen/stack.go`'s lowering
//	dispatches on to emit the unsound verifier, so its presence is a faithful
//	answer to "does this program reach the unsound verifier?" independent of
//	which source (if any) produced the IR.
//
//	The acknowledgement therefore comes from the INVOKER, via
//	`CompileOptions.AcknowledgeUnsoundSP1Fri` / the CLI's
//	`--acknowledge-unsound-sp1-fri`. On the source path the frontend has already
//	adjudicated the directive, so `CompileFromSource` marks the options
//	accordingly and this guard stands down rather than second-guessing Validate.

// guardUnsoundSP1FriIR refuses a program that reaches the known-unsound SP1 FRI
// verifier unless the compile was authorised for it. Returns nil when the
// program does not reach the verifier, when the frontend already adjudicated
// the source directive, or when the invoker acknowledged the gap.
func guardUnsoundSP1FriIR(program *ir.ANFProgram, o CompileOptions) error {
	if o.sp1FriAdjudicatedByFrontend || o.AcknowledgeUnsoundSP1Fri {
		return nil
	}
	if !programCallsSP1FriVerifier(program) {
		return nil
	}
	return errors.New(frontend.SP1FriSoundnessIRError)
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
