const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "intent-prev-output-script/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check IntentPrevOutputScript.runar.zig" {
    try runCompileChecks("IntentPrevOutputScript.runar.zig");
}

// Proves: the contract parses, validates and typechecks in the Rúnar frontend.
// Does not prove: any business logic. The native extractPrevOutputScript stub returns an empty ByteString (it cannot see other inputs), so bind()'s `len(s) > 0` assertion can never hold natively; on-chain the witness supplies the script. Frontend compile check only.
