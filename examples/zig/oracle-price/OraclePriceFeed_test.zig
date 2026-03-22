const std = @import("std");

const root = @import("../examples_test.zig");
const runar = @import("runar");
const OraclePriceFeed = @import("OraclePriceFeed.runar.zig").OraclePriceFeed;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "oracle-price/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check OraclePriceFeed.runar.zig" {
    try runCompileChecks("OraclePriceFeed.runar.zig");
}

test "OraclePriceFeed init stores oracle and receiver" {
    const contract = OraclePriceFeed.init(&runar.testing.rabin_test_key_n, runar.ALICE.pubKey);
    try std.testing.expectEqualSlices(u8, &runar.testing.rabin_test_key_n, contract.oraclePubKey);
    try std.testing.expectEqualSlices(u8, runar.ALICE.pubKey, contract.receiver);
}

test "OraclePriceFeed settle accepts a real oracle proof above the threshold" {
    const contract = OraclePriceFeed.init(&runar.testing.rabin_test_key_n, runar.ALICE.pubKey);
    const price: i64 = 60_000;
    const proof = runar.testing.oraclePriceProof(price).?;

    contract.settle(price, proof.sig, proof.padding, runar.signTestMessage(runar.ALICE));
}

test "OraclePriceFeed rejects invalid oracle proofs, thresholds, and receiver signatures" {
    try root.expectAssertFailure("oracle-price-wrong-rabin-proof");
    try root.expectAssertFailure("oracle-price-below-threshold");
    try root.expectAssertFailure("oracle-price-wrong-receiver-sig");
}
