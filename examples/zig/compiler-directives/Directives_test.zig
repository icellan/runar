const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const Directives = @import("Directives.runar.zig").Directives;

// N-093: the native Zig spellings of the two compiler directives,
// runar.EmbedAlways(T) and the runar.Sighash("FLAGS") return type, are
// ordinary Zig natively (`T` and `void`) and compile through the Rúnar
// frontend.

fn contractPath(comptime basename: []const u8) []const u8 {
    return "compiler-directives/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check Directives.runar.zig" {
    try runCompileChecks("Directives.runar.zig");
}

test "Directives natively: EmbedAlways(T) is T and Sighash(...) is void" {
    try std.testing.expect(@FieldType(Directives, "deployTag") == runar.ByteString);
    const ret = @typeInfo(@TypeOf(Directives.spendSingle)).@"fn".return_type.?;
    try std.testing.expect(ret == void);
}

test "Directives init stores pubKeyHash and deployTag" {
    const pkh = runar.hash160(runar.ALICE.pubKey);
    const contract = Directives.init(pkh, "\xde\xad\xbe\xef");
    try std.testing.expectEqualSlices(u8, pkh, contract.pubKeyHash);
    try std.testing.expectEqualSlices(u8, "\xde\xad\xbe\xef", contract.deployTag);
}

test "Directives spendAll and spendSingle succeed with the matching key and signature" {
    const contract = Directives.init(runar.hash160(runar.ALICE.pubKey), "\x01");
    contract.spendAll(runar.signTestMessage(runar.ALICE), runar.ALICE.pubKey);
    contract.spendSingle(runar.signTestMessage(runar.ALICE), runar.ALICE.pubKey);
}
