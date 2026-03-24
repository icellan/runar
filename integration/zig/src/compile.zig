const std = @import("std");
const runar = @import("runar");
const runar_frontend = @import("runar_frontend");

/// Compile a .runar.zig contract source file and return a parsed RunarArtifact.
/// Uses the native Zig compiler frontend (parse -> validate -> typecheck -> ANF -> stack -> emit).
pub fn compileContract(allocator: std.mem.Allocator, source_path: []const u8) !runar.RunarArtifact {
    const project_root = projectRoot();

    const abs_path = try std.fs.path.join(allocator, &.{ project_root, source_path });
    defer allocator.free(abs_path);

    const source = try std.fs.cwd().readFileAlloc(allocator, abs_path, 10 * 1024 * 1024);
    defer allocator.free(source);

    const file_name = std.fs.path.basename(source_path);

    const result = try runar_frontend.compileSource(allocator, source, file_name);
    defer allocator.free(result.script_hex);

    if (result.artifact_json) |json| {
        defer allocator.free(json);
        return runar.RunarArtifact.fromJson(allocator, json);
    }

    return error.OutOfMemory;
}

/// Get the project root directory (relative from integration/zig/).
fn projectRoot() []const u8 {
    return "../..";
}

test "compileContract placeholder" {
    // This test just verifies the module compiles.
    // Actual compilation requires contract files on disk.
    try std.testing.expect(true);
}
