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
// outputs via addOutput / addRawOutput, or emitting data outputs
// via addDataOutput -- was silently classified as terminal: the
// ABI omitted the change params, and the deployed locking script
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
//   - commit() calls private bump() which mutates counter. The
//     compiler must auto-inject the continuation params and emit a
//     single-output state continuation that hashes the new state
//     script + change.
//
//   - log(payload) calls private record(payload) which emits an
//     addDataOutput. The compiler must inline the helper at ANF
//     time so the data output's bytes ref bubbles into the public
//     method's addDataOutputRefs. The continuation hash then
//     concatenates state-output || data-output || change before
//     hashing.
//
//   - partition(amount, leftover) calls private forkOutput which
//     emits addOutput. ANF inlining lifts the helper's add_output
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
// its add_output / add_data_output ANF nodes register on the
// public's tracking lists. The continuation hash construction
// then sees the correct output set and matches the runtime
// transaction's hashOutputs.
//
// # Cross-compiler scope
//
// All seven Rúnar compilers (TypeScript, Go, Rust, Python, Zig,
// Ruby, Java) must produce identical Bitcoin Script for this
// contract.
const runar = @import("runar");

pub const PrivateHelperOutputs = struct {
    pub const Contract = runar.StatefulSmartContract;

    counter: i64 = 0,

    pub fn init(counter: i64) PrivateHelperOutputs {
        return .{ .counter = counter };
    }

    // Method declaration order matches the TypeScript canonical
    // fixture (privates before publics) so the seven-compiler ANF
    // IR stays byte-identical against
    // conformance/tests/private-helper-outputs/expected-ir.json.

    /// Pure state mutation, exposed through a private helper. The
    /// public caller's continuation hash must commit to the new
    /// counter value via the single-output continuation path.
    fn bump(self: *PrivateHelperOutputs) void {
        self.counter = self.counter + 1;
    }

    /// addDataOutput called from a private helper. The public
    /// caller's continuation hash must include the data output
    /// bytes between the state output and the change output.
    fn record(self: *PrivateHelperOutputs, payload: runar.ByteString) void {
        self.addDataOutput(0, payload);
    }

    /// addOutput called from a private helper. The public caller's
    /// continuation hash must commit to the explicit state output
    /// via the multi-output path.
    fn forkOutput(self: *PrivateHelperOutputs, amount: i64, leftover: i64) void {
        self.addOutput(amount, leftover);
    }

    /// Public spending entry: state mutation via private helper.
    pub fn commit(self: *PrivateHelperOutputs) void {
        self.bump();
        runar.assert(true);
    }

    /// Public spending entry: data output via private helper.
    pub fn log(self: *PrivateHelperOutputs, payload: runar.ByteString) void {
        self.record(payload);
        runar.assert(true);
    }

    /// Public spending entry: state output via private helper.
    pub fn partition(self: *PrivateHelperOutputs, amount: i64, leftover: i64) void {
        self.forkOutput(amount, leftover);
        runar.assert(true);
    }
};
