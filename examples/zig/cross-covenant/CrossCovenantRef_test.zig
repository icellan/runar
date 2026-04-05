const std = @import("std");

const root = @import("../examples_test.zig");
const runar = @import("runar");
const CrossCovenantRef = @import("CrossCovenantRef.runar.zig").CrossCovenantRef;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "cross-covenant/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check CrossCovenantRef.runar.zig" {
    try runCompileChecks("CrossCovenantRef.runar.zig");
}

test "CrossCovenantRef verifyAndExtract accepts valid output with correct state root" {
    // Layout: 16 bytes prefix + 32 bytes state root + 8 bytes suffix
    const prefix = runar.hexToBytes("aabbccddee0011223344556677889900");
    const state_root = runar.hexToBytes("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    const suffix = runar.hexToBytes("0102030405060708");
    const referenced_output = runar.bytesConcat(runar.bytesConcat(prefix, state_root), suffix);

    // Hash of the referenced output
    const output_hash = runar.hash256(referenced_output);

    const contract = CrossCovenantRef.init(output_hash);
    contract.verifyAndExtract(referenced_output, state_root, 16);
}
