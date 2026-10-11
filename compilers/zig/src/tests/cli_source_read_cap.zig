//! The `runar-zig` CLI must read every source the MAX_SOURCE_BYTES cap admits.
//!
//! `compileFromSource` (main.zig) read the file with `.limited(1 MiB)`, so any
//! source between 1 MiB and the 4 MiB MAX_SOURCE_BYTES cap failed with a bare
//! `error: StreamTooLong` before a parser saw it — while the library entry
//! point (`compiler_api.compileSourceToHex`) and the other six tiers compile
//! it. And a source over the cap was refused with that same `StreamTooLong`
//! instead of the size guard's `MAX_SOURCE_BYTES` diagnostic.
//!
//! What this proves: a ~2 MiB source (a small contract padded with comment
//! lines) compiles through the CLI to the same script the library emits, a
//! source of exactly MAX_SOURCE_BYTES compiles, and a source one byte over the
//! cap is refused with the library size guard's exact text (actual size
//! included) through the CLI's normal error path. What it does NOT prove:
//! anything about the library path (unchanged) or other tiers' CLIs.

const std = @import("std");
const testing = std.testing;
const compiler_api = @import("../compiler_api.zig");
const input_limits = @import("../frontend/input_limits.zig");

const CONTRACT =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\class Padded extends SmartContract {
    \\  readonly limit: bigint;
    \\  constructor(limit: bigint) { super(limit); this.limit = limit; }
    \\  public check(value: bigint): void {
    \\    assert(value > this.limit);
    \\  }
    \\}
    \\
;

const PAD_LINE = "// padding line to push the source past the old 1 MiB read limit\n";

fn resolveZigBinary() []const u8 {
    if (std.testing.environ.getPosix("RUNAR_ZIG_BIN")) |bin| return bin;
    return "zig-out/bin/runar-zig";
}

/// CONTRACT followed by comment lines until the source is at least `size` bytes.
fn padded(allocator: std.mem.Allocator, size: usize) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    try buf.appendSlice(allocator, CONTRACT);
    while (buf.items.len < size) try buf.appendSlice(allocator, PAD_LINE);
    return buf.toOwnedSlice(allocator);
}

const Run = struct { code: ?u8, stdout: []u8, stderr: []u8 };

fn runCli(allocator: std.mem.Allocator, io: std.Io, source: []const u8, name: []const u8) !Run {
    const dir_path = "zig-out/read-cap-tmp";
    std.Io.Dir.cwd().createDirPath(io, dir_path) catch {};
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_path, name });
    defer allocator.free(path);
    {
        var file = try std.Io.Dir.cwd().createFile(io, path, .{});
        defer file.close(io);
        var wbuf: [65536]u8 = undefined;
        var w = file.writer(io, &wbuf);
        try w.interface.writeAll(source);
        try w.interface.flush();
    }
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};
    const result = std.process.run(allocator, io, .{
        .argv = &.{ resolveZigBinary(), "compile", path, "--hex" },
        .stdout_limit = .limited(10 * 1024 * 1024),
    }) catch |err| {
        // A missing binary is not a pass: `zig build test` installs it first.
        std.debug.print("could not run runar-zig: {s}\n", .{@errorName(err)});
        return error.CompilerBinaryMissing;
    };
    const code: ?u8 = switch (result.term) {
        .exited => |c| c,
        else => null,
    };
    return .{ .code = code, .stdout = result.stdout, .stderr = result.stderr };
}

test "CLI compiles a 2 MiB source (under MAX_SOURCE_BYTES) to the library's script" {
    const allocator = testing.allocator;
    const src = try padded(allocator, 2 * 1024 * 1024);
    defer allocator.free(src);
    try testing.expect(src.len > 1024 * 1024 and src.len <= input_limits.MAX_SOURCE_BYTES);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const want = try compiler_api.compileSourceToHex(arena.allocator(), src, "Padded.runar.ts");

    const r = try runCli(allocator, testing.io, src, "Padded.runar.ts");
    defer allocator.free(r.stdout);
    defer allocator.free(r.stderr);
    if (r.code == null or r.code.? != 0) {
        std.debug.print("runar-zig refused a {d}-byte source: {s}\n", .{ src.len, r.stderr[0..@min(r.stderr.len, 400)] });
        return error.CliRefusedSourceUnderCap;
    }
    try testing.expectEqualStrings(want, std.mem.trim(u8, r.stdout, " \r\n"));
}

test "CLI compiles a source of exactly MAX_SOURCE_BYTES" {
    const allocator = testing.allocator;
    const full = try padded(allocator, input_limits.MAX_SOURCE_BYTES);
    defer allocator.free(full);
    const src = full[0..input_limits.MAX_SOURCE_BYTES];
    const r = try runCli(allocator, testing.io, src, "AtCap.runar.ts");
    defer allocator.free(r.stdout);
    defer allocator.free(r.stderr);
    if (r.code == null or r.code.? != 0) {
        std.debug.print("runar-zig refused a source at the cap: {s}\n", .{r.stderr[0..@min(r.stderr.len, 400)]});
        return error.CliRefusedSourceAtCap;
    }
}

test "CLI refuses a source one byte over MAX_SOURCE_BYTES with the size-guard diagnostic" {
    const allocator = testing.allocator;
    const full = try padded(allocator, input_limits.MAX_SOURCE_BYTES + 1);
    defer allocator.free(full);
    const src = full[0 .. input_limits.MAX_SOURCE_BYTES + 1];

    const r = try runCli(allocator, testing.io, src, "Oversize.runar.ts");
    defer allocator.free(r.stdout);
    defer allocator.free(r.stderr);
    try testing.expect(r.code != null and r.code.? != 0);
    // The library guard's exact text (actual size included) and the CLI's
    // normal error line, not an ad-hoc message.
    const want = try input_limits.sourceSizeExceededMessage(allocator, src.len);
    defer allocator.free(want);
    if (std.mem.indexOf(u8, r.stderr, want) == null or
        std.mem.indexOf(u8, r.stderr, "error: SourceSizeExceeded") == null)
    {
        std.debug.print("expected \"{s}\" + \"error: SourceSizeExceeded\", got: {s}\n", .{ want, r.stderr[0..@min(r.stderr.len, 400)] });
        return error.WrongRefusal;
    }
}
