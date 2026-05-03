// PrivateHelperOutputs -- Audit regression: private helpers must
// propagate their side effects to the public method's continuation
// hash.
//
// # Background
//
// The 2026-04-30 TypeScript compiler audit
// (docs/ts-compiler-audit-2026-04-30.md) found that the compiler's
// auto-injection of stateful continuation parameters (_changePKH,
// _changeAmount, _newAmount, txPreimage) used a shallow scan of the
// public method body. A public method that delegated its side
// effect to a private helper -- mutating state, emitting state
// outputs via add_output / add_raw_output, or emitting data
// outputs via add_data_output -- was silently classified as
// terminal: the ABI omitted the change params, and the deployed
// locking script carried no hashOutputs continuation. Findings F1
// (Critical) and F3 (High) of the audit.
//
// This contract is the regression artifact: every public function
// below delegates its side effect to a private helper. A correct
// compiler must recognise the side effect and produce the same
// continuation shape as if the public function called the
// intrinsic directly.
//
// # Behavior
//
//   - commit() calls private bump() which mutates counter. The
//     compiler must auto-inject _changePKH, _changeAmount,
//     _newAmount, and txPreimage and emit a single-output state
//     continuation that hashes the new state script + change.
//
//   - log(payload) calls private record(payload) which emits an
//     add_data_output. The compiler must inline the helper at ANF
//     time so the data output's bytes ref bubbles into the public
//     function's addDataOutputRefs. The continuation hash then
//     concatenates state-output || data-output || change before
//     hashing.
//
//   - partition(amount, leftover) calls private fork_output which
//     emits add_output. ANF inlining lifts the helper's add_output
//     ANF node into the public's binding stream, registering on
//     addOutputRefs. The continuation hash then takes the
//     multi-output path.
//
// # Compiler behavior
//
// ANF lowering uses a recursive side-effect summary (computed once
// per contract, shared with the ABI assembler) that walks the
// private-function call graph. When a public stateful function
// calls a private helper with output side effects, ANF lowering
// inlines the helper's body directly into the public's binding
// stream. The continuation hash construction then sees the
// correct output set and matches the runtime transaction's
// hashOutputs.
//
// # Cross-compiler scope
//
// All seven Rúnar compilers (TypeScript, Go, Rust, Python, Zig,
// Ruby, Java) must produce identical Bitcoin Script for this
// contract.
module PrivateHelperOutputs {
    use runar::StatefulSmartContract;
    use runar::types::{Int, ByteString};

    resource struct PrivateHelperOutputs {
        counter: &mut Int,
    }

    // Pure state mutation, exposed through a private helper. The
    // public caller's continuation hash must commit to the new
    // counter value via the single-output continuation path.
    fun bump() {
        self.counter = self.counter + 1;
    }

    // add_data_output called from a private helper. The public
    // caller's continuation hash must include the data output
    // bytes between the state output and the change output.
    fun record(payload: ByteString) {
        self.add_data_output(0, payload);
    }

    // add_output called from a private helper. The public caller's
    // continuation hash must commit to the explicit state output
    // via the multi-output path.
    fun fork_output(amount: Int, leftover: Int) {
        self.add_output(amount, leftover);
    }

    // Public spending entry: state mutation via private helper.
    public fun commit(contract: &mut PrivateHelperOutputs) {
        self.bump();
        assert!(true, 0);
    }

    // Public spending entry: data output via private helper.
    public fun log(contract: &mut PrivateHelperOutputs, payload: ByteString) {
        self.record(payload);
        assert!(true, 0);
    }

    // Public spending entry: state output via private helper.
    public fun partition(contract: &mut PrivateHelperOutputs, amount: Int, leftover: Int) {
        self.fork_output(amount, leftover);
        assert!(true, 0);
    }
}
