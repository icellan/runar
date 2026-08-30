//! Script-byte cost model for Stack IR.
//!
//! Port of `packages/runar-compiler/src/metrics/cost-model.ts`. Optimizer passes
//! need to compare two candidate lowerings by the metric that actually matters —
//! serialized locking-script bytes — before either one is emitted. `OP_DUP` and
//! a 33-byte constant push are one instruction each and 1 vs 34 bytes; an
//! instruction count cannot tell them apart.
//!
//! The implementation lives in `ec_emitters.zig` because the tracker's constant
//! pool needs it to price a call site before emitting anything, and a separate
//! copy here would be a second implementation free to drift from the one the
//! pool actually consults. This module is the named entry point the other tiers
//! have, re-exporting the single implementation.
//!
//! It is deliberately NOT an approximation: pushes route through the same
//! `opcodes.zig` encoders `emit.zig` uses, so
//!
//!     estimateScriptBytes(ops) == emitted hex length / 2
//!
//! holds exactly. `ec_cost_model_test.zig` asserts that over every EC emitter.

const ec = @import("ec_emitters.zig");

pub const scriptNumberCost = ec.scriptNumberCost;
pub const pushDataCost = ec.pushDataCost;
pub const sizeOfPushValue = ec.sizeOfPushValue;
pub const sizeOfStackOp = ec.sizeOfStackOp;
pub const estimateScriptBytes = ec.estimateScriptBytes;
