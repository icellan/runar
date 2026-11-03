//! F-033: FunctionPatterns vectors whose expectations are the on-chain verdict
//! (see onchain-vectors.json `_doc`). Shared by FunctionPatterns_test.zig
//! (value cases, in-process) and assert_probe.zig (abort cases,
//! out-of-process). Every call is signed by the owner, ALICE.

const std = @import("std");
const runar = @import("runar");
const FunctionPatterns = @import("FunctionPatterns.runar.zig").FunctionPatterns;

pub const json = @embedFile("onchain-vectors.json");

/// Run one vector's method on `contract`, natively, signed by ALICE.
pub fn apply(contract: *FunctionPatterns, method: []const u8, a: []const i64) void {
    const eq = std.mem.eql;
    const sig = runar.signTestMessage(runar.ALICE);
    if (eq(u8, method, "deposit")) return contract.deposit(sig, a[0]);
    if (eq(u8, method, "withdraw")) return contract.withdraw(sig, a[0], a[1]);
    if (eq(u8, method, "scale")) return contract.scale(sig, a[0], a[1]);
    if (eq(u8, method, "normalize")) return contract.normalize(sig, a[0], a[1], a[2]);
    std.debug.panic("function-patterns onchain-vectors: unknown method {s}", .{method});
}

/// Run vector `index` from its `init` balance; returns the new balance.
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

    var contract = FunctionPatterns.init(runar.ALICE.pubKey, obj.get("init").?.integer);
    if (announce) std.debug.print("F033_VECTOR_CALL\n", .{});
    apply(&contract, obj.get("method").?.string, args[0..arr.len]);
    return contract.balance;
}
