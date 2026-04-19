const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "p384-wallet/" ++ basename;
}

test "compile-check P384Wallet.runar.zig (source)" {
    try root.runar.compileCheckSource(
        std.testing.allocator,
        @embedFile("P384Wallet.runar.zig"),
        "P384Wallet.runar.zig",
    );
}

test "compile-check P384Wallet.runar.zig (file)" {
    try root.runar.compileCheckFile(
        std.testing.allocator,
        contractPath("P384Wallet.runar.zig"),
    );
}
