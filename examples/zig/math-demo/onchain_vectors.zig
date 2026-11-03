//! F-033: MathDemo vectors whose expectations are the on-chain verdict (see
//! onchain-vectors.json `_doc`). Shared by MathDemo_test.zig (value cases, run
//! in-process) and assert_probe.zig (abort cases, run out-of-process because a
//! native abort is a panic).

const std = @import("std");
const MathDemo = @import("MathDemo.runar.zig").MathDemo;

pub const json = @embedFile("onchain-vectors.json");

/// Run one vector's method on `demo`, natively.
pub fn apply(demo: *MathDemo, method: []const u8, a: []const i64) void {
    const eq = std.mem.eql;
    if (eq(u8, method, "divideBy")) return demo.divideBy(a[0]);
    if (eq(u8, method, "withdrawWithFee")) return demo.withdrawWithFee(a[0], a[1]);
    if (eq(u8, method, "clampValue")) return demo.clampValue(a[0], a[1]);
    if (eq(u8, method, "normalize")) return demo.normalize();
    if (eq(u8, method, "exponentiate")) return demo.exponentiate(a[0]);
    if (eq(u8, method, "squareRoot")) return demo.squareRoot();
    if (eq(u8, method, "reduceGcd")) return demo.reduceGcd(a[0]);
    if (eq(u8, method, "scaleByRatio")) return demo.scaleByRatio(a[0], a[1]);
    if (eq(u8, method, "computeLog2")) return demo.computeLog2();
    if (eq(u8, method, "makeAbs")) return demo.makeAbs();
    if (eq(u8, method, "takeMin")) return demo.takeMin(a[0]);
    if (eq(u8, method, "takeMax")) return demo.takeMax(a[0]);
    if (eq(u8, method, "assertWithin")) return demo.assertWithin(a[0], a[1]);
    if (eq(u8, method, "moduloBy")) return demo.moduloBy(a[0]);
    if (eq(u8, method, "divmodBy")) return demo.divmodBy(a[0]);
    if (eq(u8, method, "assertNonZero")) return demo.assertNonZero();
    std.debug.panic("math-demo onchain-vectors: unknown method {s}", .{method});
}

/// Run vector `index` from its `init` state; returns the new value.
/// `announce` prints `F033_VECTOR_CALL` to stderr right before the contract
/// call (assert_probe uses it to prove the abort came from the call itself).
pub fn run(allocator: std.mem.Allocator, index: usize, announce: bool) !i64 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    const cases = parsed.value.object.get("cases").?.array.items;
    if (index >= cases.len) return error.NoSuchVector;
    const obj = cases[index].object;

    var args: [4]i64 = undefined;
    const arr = obj.get("args").?.array.items;
    for (arr, 0..) |v, i| args[i] = v.integer;

    var demo = MathDemo.init(obj.get("init").?.integer);
    if (announce) std.debug.print("F033_VECTOR_CALL\n", .{});
    apply(&demo, obj.get("method").?.string, args[0..arr.len]);
    return demo.value;
}
