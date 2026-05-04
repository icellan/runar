// ConditionalDataOutput -- Audit regression: a stateful method that
// emits a data output on a conditional branch must keep the canonical
// single-output `computeStateOutput` state continuation on every path.
//
// # Background
//
// The pre-fix lowering registered ANY branch output as
// `addOutputRef`, regardless of whether the branch's outputs were
// state outputs (`addOutput` / `addRawOutput`) or data outputs
// (`addDataOutput`). That forced the parent method onto the
// multi-output continuation path, which OMITS the canonical
// single-output `computeStateOutput` call. The continuation hash for
// the stateful contract was therefore wrong on the branch where
// `addDataOutput` ran, and the spend would fail on chain.
//
// # Behavior
//
//   - `pay(flag, payload)` mutates `amount` unconditionally and emits
//     a data output (the receipt) only when `flag` is true. The
//     continuation must commit to the new state on both branches; the
//     data output bytes splice in BETWEEN the state output and the
//     change output when `flag` is true.
//
// # Cross-compiler scope
//
// All seven Rúnar compilers must produce identical Bitcoin Script for
// this contract. The conformance fixture lives at
// `conformance/tests/conditional-data-output-stateful/`.
const runar = @import("runar");

pub const ConditionalDataOutput = struct {
    pub const Contract = runar.StatefulSmartContract;

    amount: i64 = 0,

    pub fn init(amount: i64) ConditionalDataOutput {
        return .{ .amount = amount };
    }

    /// The canonical bug: `addDataOutput` is wrapped in a branch.
    /// The compiler must register the if's value as a DATA output
    /// ref (not a state output ref) so that the parent method's
    /// continuation hash keeps `computeStateOutput`.
    pub fn pay(self: *ConditionalDataOutput, flag: bool, payload: runar.ByteString) void {
        self.amount = self.amount + 1;
        if (flag) {
            self.addDataOutput(0, payload);
        }
        runar.assert(true);
    }
};
