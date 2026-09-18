//! R-028 sibling: a local that shadows a mutable property must not be counted
//! as a state mutation when the continuation shape is decided.
//!
//! `methodMutatesState` -> `stmtMutatesStateRec` in `passes/anf_lower.zig`
//! answers "does this assignment write a contract property?" by comparing
//! `Assign.target` (a bare name — the parsers strip `this.`) against the
//! contract's non-readonly property names. A LOCAL that happens to shadow a
//! property name carries the identical string, so it was counted as a state
//! mutation.
//!
//! `tests/local_shadowing_property.zig` already fixed the LOWERING path for
//! exactly this AST shape by keying on `Assign.target_is_property` — the flag
//! every surface parser populates and `expand_fixed_arrays` propagates. The
//! continuation-shape decision was left on the bare-name comparison, so the
//! two disagree within the tier: the rebind lowers as a local (no
//! `update_prop`), yet the method is still declared as mutating.
//!
//! The reference tiers key on the AST node kind
//! (`stmt.target.kind === 'property_access'` in
//! `packages/runar-compiler/src/passes/side-effect-summary.ts`), so this is a
//! 6-vs-1 divergence with Zig as the outlier. Measured on `SHADOW_SRC` below,
//! fold-ON, via each tier's CLI:
//!
//!     ts / go / rust / python / ruby / java   471 bytes  params=[amount, txPreimage]
//!     zig (before)                            685 bytes  params=[amount, _changePKH,
//!                                                                 _changeAmount,
//!                                                                 _newAmount, txPreimage]
//!
//! Not a funds bug in the R-028 direction — it over-declares rather than
//! skipping a covenant — but it is a hard interop break: the deployed locking
//! script differs from every other tier, so the contract has a different
//! address, and an unlocking script built against the six-tier ABI pushes two
//! arguments where the Zig-compiled script expects five.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

/// A stateful contract whose public method mutates NO state: `a` inside
/// `settle` names a local that shadows the mutable property `a`.
const SHADOW_SRC =
    \\class P11 extends StatefulSmartContract {
    \\  a: bigint;
    \\
    \\  constructor(a: bigint) {
    \\    super(a);
    \\    this.a = a;
    \\  }
    \\
    \\  public settle(amount: bigint) {
    \\    let a: bigint = amount;
    \\    a = a + 1n;
    \\    assert(a > 0n);
    \\  }
    \\}
;

/// The ABI the six reference tiers declare for `settle`: terminal, so no
/// continuation parameters.
const settle_terminal =
    "\"name\":\"settle\",\"params\":[" ++
    "{\"name\":\"amount\",\"type\":\"bigint\"}," ++
    "{\"name\":\"txPreimage\",\"type\":\"SigHashPreimage\"}]";

/// Byte-for-byte what ts / go / rust / python / ruby / java emit for
/// `SHADOW_SRC` with constant folding ON (the `compileSource` default).
const CROSS_TIER_HEX =
    "76ab76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f" ++
    "517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e" ++
    "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e93214141" ++
    "36d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d949593" ++
    "7776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f" ++
    "76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76" ++
    "927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e" ++
    "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce" ++
    "28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d13" ++
    "82a2bf66a71ae74a1e83b0ad69768254947f7701007e8101419d01687f7782012c947f758258947f758258947f77817c51" ++
    "787c9300a07777";

test "R-028 sibling: a shadowing local rebind leaves the method terminal" {
    const allocator = std.testing.allocator;
    const result = try compiler_api.compileSource(allocator, SHADOW_SRC, "P11.runar.ts");
    defer result.deinit(allocator);
    const json = result.artifact_json orelse return error.TestExpectedJson;
    if (std.mem.indexOf(u8, json, settle_terminal) == null) {
        std.debug.print("expected terminal ABI fragment not found:\n  {s}\n", .{settle_terminal});
        return error.TestUnexpectedResult;
    }
}

test "R-028 sibling: the shadowing contract matches the six-tier script bytes" {
    const allocator = std.testing.allocator;
    const result = try compiler_api.compileSource(allocator, SHADOW_SRC, "P11.runar.ts");
    defer result.deinit(allocator);
    try std.testing.expectEqualStrings(CROSS_TIER_HEX, result.script_hex);
}
