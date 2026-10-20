const std = @import("std");
const root = @import("../examples_test.zig");
const TerminalVarlenRead = @import("TerminalVarlenRead.runar.zig").TerminalVarlenRead;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "terminal-varlen-read/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check TerminalVarlenRead.runar.zig" {
    try runCompileChecks("TerminalVarlenRead.runar.zig");
}

// Proves: post() replaces the variable-length message and reveal() requires its length to exceed minLen.
// Does not prove: terminal variable-length state reads in the compiled script (a conformance property).

test "TerminalVarlenRead post replaces the message and reveal accepts a shorter minLen" {
    var c = TerminalVarlenRead.init("");
    c.post("hello");
    try std.testing.expectEqualSlices(u8, "hello", c.message);
    c.reveal(4);
}

test "TerminalVarlenRead reveal rejects a message no longer than minLen" {
    try root.expectAssertFailure("terminal-varlen-read-too-short");
}
