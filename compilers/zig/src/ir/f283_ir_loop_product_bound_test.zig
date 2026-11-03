//! F-283 / CL-GAP-164 — the `--ir` loader bounds each loop's iteration count
//! individually (`types.MAX_LOOP_COUNT` = 10_000, N-115) but, before this
//! fix, never the PRODUCT across nested loops. Two loop bindings of 10_000
//! each, one nested inside the other, each independently pass the
//! per-binding check even though the real unrolled iteration count is
//! 10_000 x 10_000 = 100_000_000 -- a count that, if this IR ever reached
//! stack lowering, drives the unroller into multi-GB memory growth (measured
//! upstream, Ruby tier, same shape: a 1,175-byte payload loaded in 0.0s and
//! then drove compile_from_ir to 5m07s / 3.7GB RSS and climbing).
//!
//! Zig's IR loader is an error-enum channel with no message payload, so
//! this reuses `error.LoopCountExceedsMaximum` (N-115's own error) rather
//! than inventing a second name for the same family of rejection.

const std = @import("std");
const testing = std.testing;
const json = @import("json.zig");
const types = @import("types.zig");

/// A one-method contract with two nested `loop` bindings, parameterised on
/// both counts, so every case below differs from a control in exactly the
/// counts. N-071: the body closes with `_ok = true; assert(_ok)`.
fn nestedLoopIrJson(allocator: std.mem.Allocator, outer_count: i64, inner_count: i64) ![]const u8 {
    return std.fmt.allocPrint(allocator,
        \\{{"contractName":"Bounded","properties":[],"methods":[{{"name":"unlock","params":[],"isPublic":true,"body":[{{"name":"outer","value":{{"kind":"loop","count":{d},"iterVar":"i","body":[{{"name":"inner","value":{{"kind":"loop","count":{d},"iterVar":"j","body":[{{"name":"t0","value":{{"kind":"load_const","value":0}}}}]}}}}]}}}},{{"name":"_ok","value":{{"kind":"load_const","value":true}}}},{{"name":"_ok_assert","value":{{"kind":"assert","value":"_ok"}}}}]}}]}}
    , .{ outer_count, inner_count });
}

// Control: nested loops whose product stays within MAX_LOOP_COUNT must
// still load -- the new check must not be a disguised depth limit.
test "control: nested loop product within MAX_LOOP_COUNT still loads" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const src = try nestedLoopIrJson(allocator, 10, 10);
    const program = try json.parseANFProgram(allocator, src);
    try testing.expectEqualStrings("Bounded", program.contract_name);
}

// The hostile case: 10_000 x 10_000, each individually within
// MAX_LOOP_COUNT, product 100_000_000 far over it.
test "rejects nested loops whose product exceeds MAX_LOOP_COUNT" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const src = try nestedLoopIrJson(allocator, types.MAX_LOOP_COUNT, types.MAX_LOOP_COUNT);
    try testing.expectError(
        error.LoopCountExceedsMaximum,
        json.parseANFProgram(allocator, src),
    );
}

// Neither 101 nor 100 alone trips the per-binding ceiling (both are far
// below MAX_LOOP_COUNT), but their product (10_100) does. Proves the rule
// is the product, not a disguised re-check of the single bound.
test "rejects small nested counts whose product exceeds MAX_LOOP_COUNT" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const src = try nestedLoopIrJson(allocator, 101, 100);
    try testing.expectError(
        error.LoopCountExceedsMaximum,
        json.parseANFProgram(allocator, src),
    );
}
