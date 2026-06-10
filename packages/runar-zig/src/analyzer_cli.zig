// CLI entry: read hex from argv[1] (file path), write JSON to stdout.
// Used by tools/analyzer-runner/zig.sh for cross-tier conformance.

const std = @import("std");
const analyzer = @import("analyzer.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer args_list.deinit(allocator);
    var args_iter = std.process.Args.Iterator.init(init.minimal.args);
    while (args_iter.next()) |arg| try args_list.append(allocator, arg);
    const args = args_list.items;

    if (args.len < 2) {
        try writeStderr(io, "usage: runar-analyzer <hex-file>\n");
        std.process.exit(2);
    }
    const path = args[1];

    const hex = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1024 * 1024 * 1024)) catch |err| {
        var buf: [512]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "error: cannot open {s}: {s}\n", .{ path, @errorName(err) }) catch "error: cannot open file\n";
        try writeStderr(io, msg);
        std.process.exit(2);
    };
    defer allocator.free(hex);

    var end = hex.len;
    while (end > 0) : (end -= 1) {
        const c = hex[end - 1];
        if (c != ' ' and c != '\t' and c != '\n' and c != '\r') break;
    }

    const result = try analyzer.analyzeScript(allocator, hex[0..end], .{});
    defer result.deinit(allocator);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try analyzer.writeReportJson(allocator, &out, result);

    try writeStdout(io, out.items);
}

fn writeStdout(io: std.Io, data: []const u8) !void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    try w.interface.writeAll(data);
    try w.interface.flush();
}

fn writeStderr(io: std.Io, data: []const u8) !void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stderr().writer(io, &buf);
    try w.interface.writeAll(data);
    try w.interface.flush();
}
