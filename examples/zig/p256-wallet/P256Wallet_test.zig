const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "p256-wallet/" ++ basename;
}

test "compile-check P256Wallet.runar.zig (source)" {
    try root.runar.compileCheckSource(
        std.testing.allocator,
        @embedFile("P256Wallet.runar.zig"),
        "P256Wallet.runar.zig",
    );
}

test "compile-check P256Wallet.runar.zig (file)" {
    try root.runar.compileCheckFile(
        std.testing.allocator,
        contractPath("P256Wallet.runar.zig"),
    );
}
