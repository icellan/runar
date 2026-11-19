//! D12 SECP-F1: the native `ecModReduce` mock must match the compiled script,
//! which computes `((v tmod m) + m) tmod m` with TRUNCATED mod
//! (ec-codegen.ts emitEcModReduce) and aborts on m == 0 (OP_MOD by zero).
//! The mock used `@mod` (floored; illegal for a negative divisor) and returned
//! 0 for m == 0, so a native test passed where the script aborts.
//!
//! Proves: the script's value for negative / positive moduli and operands
//! (vectors executed on @bsv/sdk Spend in the D12 secp256k1 battery), and that
//! m == 0 aborts the process (out-of-process probe, like N-173).
//! Does NOT prove: anything about moduli other than these vectors.

const std = @import("std");
const builtins = @import("builtins.zig");

test "D12 SECP-F1: ecModReduce matches the script's truncated-mod formula" {
    try std.testing.expectEqual(@as(i64, -2), builtins.ecModReduce(7, -3));
    try std.testing.expectEqual(@as(i64, -1), builtins.ecModReduce(-7, -3));
    try std.testing.expectEqual(@as(i64, 1), builtins.ecModReduce(-5, 3));
    try std.testing.expectEqual(@as(i64, 1), builtins.ecModReduce(7, 3));
    try std.testing.expectEqual(@as(i64, 0), builtins.ecModReduce(-6, 3));
}

test "D12 SECP-F1: ecModReduce with modulus 0 aborts" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ "zig-out/bin/runar-n173-panic-probe", "ecModReduce-zero" },
        .stderr_limit = .limited(1024 * 1024),
        .stdout_limit = .limited(64 * 1024),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| {
            std.debug.print("ecModReduce(5, 0) exited cleanly (code {d}); stderr: {s}\n", .{ code, result.stderr });
            return error.ProbeDidNotPanic;
        },
        else => {},
    }
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "ecModReduce") != null);
}
