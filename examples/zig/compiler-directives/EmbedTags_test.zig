const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const EmbedTags = @import("EmbedTags.runar.zig").EmbedTags;

// N-093: runar.EmbedAlways on a fixed-array field is the wrapped array type
// natively (its default initializer still applies) and compiles through the
// Rúnar frontend.

fn contractPath(comptime basename: []const u8) []const u8 {
    return "compiler-directives/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check EmbedTags.runar.zig" {
    try runCompileChecks("EmbedTags.runar.zig");
}

test "EmbedTags init keeps the default tags" {
    try std.testing.expect(@FieldType(EmbedTags, "tags") == [3]i64);
    const contract = EmbedTags.init(runar.hash160(runar.ALICE.pubKey));
    try std.testing.expectEqualSlices(i64, &.{ 7, 9, 11 }, &contract.tags);
}

test "EmbedTags unlock succeeds when amount reaches tags[1]" {
    const contract = EmbedTags.init(runar.hash160(runar.ALICE.pubKey));
    contract.unlock(runar.signTestMessage(runar.ALICE), runar.ALICE.pubKey, 9);
    contract.unlock(runar.signTestMessage(runar.ALICE), runar.ALICE.pubKey, 100);
}
