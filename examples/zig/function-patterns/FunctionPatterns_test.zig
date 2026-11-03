const std = @import("std");

const root = @import("../examples_test.zig");
const runar = @import("runar");
const FunctionPatterns = @import("FunctionPatterns.runar.zig").FunctionPatterns;
const onchain_vectors = @import("onchain_vectors.zig");

const contract_source = @embedFile("FunctionPatterns.runar.zig");

test "compile-check FunctionPatterns.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "FunctionPatterns.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "FunctionPatterns.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "FunctionPatterns.runar.zig");
}

test "function patterns init stores owner and balance" {
    const contract = FunctionPatterns.init(runar.ALICE.pubKey, 1000);

    try std.testing.expectEqualSlices(u8, runar.ALICE.pubKey[0..], contract.owner[0..]);
    try std.testing.expectEqual(@as(i64, 1000), contract.balance);
}

test "function patterns executes deposit and withdraw through the real contract" {
    var contract = FunctionPatterns.init(runar.ALICE.pubKey, 1000);

    contract.deposit(runar.signTestMessage(runar.ALICE), 250);
    try std.testing.expectEqual(@as(i64, 1250), contract.balance);

    // F-033: feeBps is basis points — 400 * 25 / 10000 = 1 on-chain, so the
    // total is 401 (this used to expect 750, the native /100 result).
    contract.withdraw(runar.signTestMessage(runar.ALICE), 400, 25);
    try std.testing.expectEqual(@as(i64, 849), contract.balance);
}

test "function patterns executes scale and normalize through the real contract" {
    var contract = FunctionPatterns.init(runar.ALICE.pubKey, 137);

    contract.scale(runar.signTestMessage(runar.ALICE), 3, 2);
    try std.testing.expectEqual(@as(i64, 205), contract.balance);

    contract.normalize(runar.signTestMessage(runar.ALICE), 0, 200, 16);
    try std.testing.expectEqual(@as(i64, 192), contract.balance);
}

test "function patterns rejects non-owner actions" {
    try root.expectAssertFailure("function-patterns-wrong-owner");
}

test "function patterns rejects overdraw" {
    try root.expectAssertFailure("function-patterns-overdraw");
}

// F-033: every vector in onchain-vectors.json carries the verdict of the
// COMPILED script on @bsv/sdk Spend.validate, asserted by
// packages/runar-testing/src/__tests__/f033-zig-native-math-onchain.test.ts.
// Proves: the native FunctionPatterns lands on the on-chain balance for each
// value vector and aborts for each abort vector (out-of-process).
// Does not prove: anything outside i64, or that the vectors are exhaustive.
test "F-033: FunctionPatterns native run matches the on-chain verdict for every vector" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, onchain_vectors.json, .{});
    defer parsed.deinit();
    const cases = parsed.value.object.get("cases").?.array.items;
    try std.testing.expect(cases.len > 0);

    var aborts: usize = 0;
    for (cases, 0..) |c, i| {
        const expect = c.object.get("expect").?;
        if (expect == .string) {
            try std.testing.expectEqualStrings("abort", expect.string);
            var buf: [64]u8 = undefined;
            try root.expectVectorAbort(try std.fmt.bufPrint(&buf, "function-patterns-vector:{d}", .{i}));
            aborts += 1;
            continue;
        }
        const got = try onchain_vectors.run(allocator, i, false);
        if (got != expect.integer) {
            std.debug.print("function-patterns vector {d} ({s}): native={d} on-chain={d}\n", .{
                i, c.object.get("method").?.string, got, expect.integer,
            });
            return error.TestExpectedEqual;
        }
    }
    try std.testing.expect(aborts > 0);
}
