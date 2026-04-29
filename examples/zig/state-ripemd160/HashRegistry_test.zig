const std = @import("std");
const root = @import("../examples_test.zig");
const HashRegistry = @import("HashRegistry.runar.zig").HashRegistry;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "state-ripemd160/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check HashRegistry.runar.zig" {
    try runCompileChecks("HashRegistry.runar.zig");
}

test "HashRegistry.update overwrites the stored hash" {
    const initial: []const u8 = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14";
    const next: []const u8 = "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4";
    var c = HashRegistry.init(initial);
    c.update(next);
    try std.testing.expectEqualSlices(u8, next, c.currentHash);
}
