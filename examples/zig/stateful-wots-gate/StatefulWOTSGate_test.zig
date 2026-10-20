const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const StatefulWOTSGate = @import("StatefulWOTSGate.runar.zig").StatefulWOTSGate;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "stateful-wots-gate/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check StatefulWOTSGate.runar.zig" {
    try runCompileChecks("StatefulWOTSGate.runar.zig");
}

// Proves: advance() runs the real WOTS+ verifier natively, increments count on a valid signature and aborts on a tampered one.
// Does not prove: the stateful continuation (GAP-407 is about the compiled script's state handling alongside a large PQ verifier).

test "StatefulWOTSGate advance accepts a valid WOTS signature and increments count" {
    const seed = [_]u8{0x42} ** 32;
    const pub_seed = [_]u8{0x13} ** 32;
    const wots_pub_key = runar.testing.wotsPublicKeyFromSeed(&seed, &pub_seed);
    const wots_sig = runar.testing.wotsSignDeterministic("gate-message", &seed, &pub_seed);
    var c = StatefulWOTSGate.init(4);
    c.advance("gate-message", &wots_sig, &wots_pub_key);
    try std.testing.expectEqual(@as(i64, 5), c.count);
}

test "StatefulWOTSGate advance rejects a tampered WOTS signature" {
    try root.expectAssertFailure("stateful-wots-gate-tampered-sig");
}
