const std = @import("std");
const root = @import("../examples_test.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "asm-raw-script/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check Anyone.runar.zig" {
    try runCompileChecks("Anyone.runar.zig");
}

// Proves: the contract parses, validates and typechecks in the Rúnar frontend.
// Does not prove: any business logic. Anyone calls `runar.asm(...)`; `asm` is a Zig keyword, so the file is not importable as Zig at all and can only be fed to the Runar frontend (parse -> validate -> typecheck) as source text. Frontend compile check only.
