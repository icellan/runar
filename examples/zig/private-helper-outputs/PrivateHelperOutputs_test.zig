const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const PrivateHelperOutputs = @import("PrivateHelperOutputs.runar.zig").PrivateHelperOutputs;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "private-helper-outputs/" ++ basename;
}

test "compile-check PrivateHelperOutputs.runar.zig (source)" {
    try root.runar.compileCheckSource(
        std.testing.allocator,
        @embedFile("PrivateHelperOutputs.runar.zig"),
        "PrivateHelperOutputs.runar.zig",
    );
}

test "compile-check PrivateHelperOutputs.runar.zig (file)" {
    try root.runar.compileCheckFile(
        std.testing.allocator,
        contractPath("PrivateHelperOutputs.runar.zig"),
    );
}

// Proves: the real contract struct runs natively for the one public method that
// needs no output intrinsic. commit() really reaches its private helper bump()
// (counter 3 -> 4) and records nothing; a helper that is not called, or a second
// call, fails this.
// Does not prove: log() and partition(). Their private helpers call
// self.addDataOutput / self.addOutput, which have no native method, and the
// ctx.addDataOutput(...) style cannot be used here: threading a StatefulContext
// parameter through the private helpers changes the compiled script and the ANF
// IR (the compiler counts ctx as a real helper parameter and refuses with
// SilentOpZeroRefused). The compile checks above stay the only coverage for those two
// methods; the compiled behaviour is the conformance fixture private-helper-outputs.
test "commit bumps counter through the private helper and records no output" {
    var runtime = runar.StatefulSmartContract.init(std.testing.allocator);
    defer runtime.deinit();
    var c = PrivateHelperOutputs.init(3);
    const ctx = try runar.StatefulContext.init(&runtime, runar.mockPreimage(.{}));

    c.commit();

    try std.testing.expectEqual(@as(i64, 4), c.counter);
    try std.testing.expectEqual(@as(usize, 0), ctx.outputs().len);

    c.commit();
    try std.testing.expectEqual(@as(i64, 5), c.counter);
    try std.testing.expectEqual(@as(usize, 0), ctx.outputs().len);
}
