package contract

import runar "github.com/icellan/runar/packages/runar-go"

// PrivateHelperOutputs — Audit regression: private (unexported)
// helpers must propagate their side effects to the public method's
// continuation hash.
//
// # Background
//
// The 2026-04-30 TypeScript compiler audit
// (docs/ts-compiler-audit-2026-04-30.md) found that the compiler's
// auto-injection of stateful continuation parameters (_changePKH,
// _changeAmount, _newAmount, txPreimage) used a shallow scan of the
// public method body. A public method that delegated its side
// effect to a private helper — mutating state, emitting state
// outputs via AddOutput / AddRawOutput, or emitting data outputs
// via AddDataOutput — was silently classified as terminal: the ABI
// omitted the change params, and the deployed locking script
// carried no hashOutputs continuation. Findings F1 (Critical) and
// F3 (High) of the audit.
//
// This contract is the regression artifact: every public method
// below delegates its side effect to a private helper. A correct
// compiler must recognise the side effect and produce the same
// continuation shape as if the public method called the intrinsic
// directly.
//
// # Behavior
//
//   - Commit() calls private bump() which mutates Counter. The
//     compiler must auto-inject the continuation params and emit
//     a single-output state continuation that hashes the new
//     state script + change.
//
//   - Log(payload) calls private record(payload) which emits an
//     AddDataOutput. The compiler must inline the helper at ANF
//     time so the data output's bytes ref bubbles into the public
//     method's addDataOutputRefs. The continuation hash then
//     concatenates state-output || data-output || change before
//     hashing.
//
//   - Partition(amount, leftover) calls private forkOutput which
//     emits AddOutput. ANF inlining lifts the helper's add_output
//     ANF node into the public's binding stream, registering on
//     addOutputRefs. The continuation hash then takes the
//     multi-output path.
//
// # Compiler behavior
//
// ANF lowering uses a recursive side-effect summary (computed once
// per contract, shared with the ABI assembler) that walks the
// private-method call graph. When a public stateful method calls
// a private helper with output side effects, ANF lowering inlines
// the helper's body directly into the public's binding stream so
// its AddOutput / AddDataOutput / state-mutation ANF nodes
// register on the public's tracking lists. The continuation hash
// construction then sees the correct output set and matches the
// runtime transaction's hashOutputs.
//
// # Method ordering
//
// Method declaration order matches the TypeScript canonical
// fixture (privates before publics) so the seven-compiler ANF IR
// stays byte-identical against `conformance/tests/private-helper-
// outputs/expected-ir.json`. The Go parser emits methods in source
// order; reordering here keeps the conformance test green without
// any compiler-side ordering rules.
//
// # Cross-compiler scope
//
// All seven Rúnar compilers (TypeScript, Go, Rust, Python, Zig,
// Ruby, Java) must produce identical Bitcoin Script for this
// contract.
type PrivateHelperOutputs struct {
	runar.StatefulSmartContract
	Counter runar.Bigint
}

// bump — pure state mutation, exposed through a private helper.
// The public caller's continuation hash must commit to the new
// counter value via the single-output continuation path.
func (c *PrivateHelperOutputs) bump() {
	c.Counter = c.Counter + 1
}

// record — AddDataOutput called from a private helper. The public
// caller's continuation hash must include the data output bytes
// between the state output and the change output.
func (c *PrivateHelperOutputs) record(payload runar.ByteString) {
	c.AddDataOutput(0, payload)
}

// forkOutput — AddOutput called from a private helper. The public
// caller's continuation hash must commit to the explicit state
// output via the multi-output path.
func (c *PrivateHelperOutputs) forkOutput(amount runar.Bigint, leftover runar.Bigint) {
	c.AddOutput(amount, leftover)
}

// Commit invokes a private state-mutating helper. The compiler must
// auto-inject _changePKH, _changeAmount, _newAmount, txPreimage and
// emit the single-output state continuation.
func (c *PrivateHelperOutputs) Commit() {
	c.bump()
	runar.Assert(true)
}

// Log routes a data output through a private helper. The compiler
// must inline `record` so its AddDataOutput ref participates in the
// caller's continuation hash.
func (c *PrivateHelperOutputs) Log(payload runar.ByteString) {
	c.record(payload)
	runar.Assert(true)
}

// Partition routes a state output through a private helper. The
// compiler must inline `forkOutput` so its AddOutput ref
// participates in the caller's multi-output continuation hash.
func (c *PrivateHelperOutputs) Partition(amount runar.Bigint, leftover runar.Bigint) {
	c.forkOutput(amount, leftover)
	runar.Assert(true)
}
