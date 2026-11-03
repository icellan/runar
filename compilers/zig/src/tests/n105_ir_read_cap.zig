//! N-105 — the `runar-zig` CLI must read every `--ir` / `compile-ir` input the
//! loader's own `json.MAX_IR_BYTES` (16 MiB) guard admits.
//!
//! `compileFromIR` (main.zig) read the file with `.limited(10 MiB)`, so any
//! IR JSON between 10 MiB and the 16 MiB `MAX_IR_BYTES` cap failed with a
//! bare `error: StreamTooLong` before `json_parser.parseANFProgram`'s own
//! size guard — the thing documented as enforcing the 16 MiB limit — ever
//! saw the bytes. TS (and the loader's own unit test,
//! `ir/json_size_guard_test.zig`, calling `parseANFProgram` directly) accept
//! exactly that range, so the CLI disagreed with its own loader and with the
//! other tiers over a range of valid input sizes.
//!
//! What this proves: a 12 MiB IR file (inside the dead zone the old 10 MiB
//! cap refused) and a file of exactly MAX_IR_BYTES both compile through the
//! CLI to the SAME script as the un-padded fixture, and a file one byte over
//! MAX_IR_BYTES is refused through the CLI's normal error path with the
//! loader's typed `IRSizeExceeded` diagnostic — not a raw `StreamTooLong`.
//! What it does NOT prove: anything about the library entry point (this bug
//! was CLI-only — `compileFromIR` is reached only through `main.zig`) or
//! other tiers' CLIs.

const std = @import("std");
const testing = std.testing;
const json = @import("../ir/json.zig");

/// The checked-in golden fixture the CLI already compiles successfully
/// (pinned by `tests/n119_ir_cli_clean_stderr.zig`). Padding is inserted
/// after its opening `{` — JSON permits insignificant whitespace there —
/// so every padded variant below must compile to the exact same script.
const FIXTURE = "../../conformance/tests/bounded-loop/expected-ir.json";
const EXPECTED_HEX =
    "000052797b7c937c935152797b7c937c935252797b7c937c935352797b7c937c93547b7b7c937c93009c";

const PAD_LINE = "                                                                \n";

fn resolveZigBinary() []const u8 {
    if (std.testing.environ.getPosix("RUNAR_ZIG_BIN")) |bin| return bin;
    return "zig-out/bin/runar-zig";
}

/// The fixture's bytes with whitespace padding inserted right after the
/// opening `{`, so the total length is exactly `target_size` (which must be
/// >= the fixture's own length).
fn paddedFixture(allocator: std.mem.Allocator, io: std.Io, target_size: usize) ![]u8 {
    const raw = try std.Io.Dir.cwd().readFileAlloc(io, FIXTURE, allocator, .limited(1024 * 1024));
    defer allocator.free(raw);
    try testing.expect(raw.len > 0 and raw[0] == '{');
    try testing.expect(target_size >= raw.len);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);
    try buf.appendSlice(allocator, raw[0..1]);

    var remaining = target_size - raw.len;
    while (remaining > 0) {
        const chunk = @min(remaining, PAD_LINE.len);
        try buf.appendSlice(allocator, PAD_LINE[0..chunk]);
        remaining -= chunk;
    }

    try buf.appendSlice(allocator, raw[1..]);
    return buf.toOwnedSlice(allocator);
}

const Run = struct { code: ?u8, stdout: []u8, stderr: []u8 };

fn runCompileIr(allocator: std.mem.Allocator, io: std.Io, source: []const u8, name: []const u8) !Run {
    const dir_path = "zig-out/ir-read-cap-tmp";
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
        .argv = &.{ resolveZigBinary(), "compile-ir", path, "--hex" },
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

test "CLI compiles a 12 MiB IR file (inside the old dead zone, under MAX_IR_BYTES)" {
    const allocator = testing.allocator;
    const io = testing.io;
    const target: usize = 12 * 1024 * 1024;

    const src = try paddedFixture(allocator, io, target);
    defer allocator.free(src);
    // Inside the range the old 10 MiB read cap refused outright.
    try testing.expect(src.len > 10 * 1024 * 1024 and src.len <= json.MAX_IR_BYTES);

    const r = try runCompileIr(allocator, io, src, "Padded12MiB.anf.json");
    defer allocator.free(r.stdout);
    defer allocator.free(r.stderr);
    if (r.code == null or r.code.? != 0) {
        std.debug.print(
            "runar-zig refused a {d}-byte IR file: {s}\n",
            .{ src.len, r.stderr[0..@min(r.stderr.len, 400)] },
        );
        return error.CliRefusedIrUnderCap;
    }
    try testing.expectEqualStrings(EXPECTED_HEX, std.mem.trim(u8, r.stdout, " \r\n\t"));
}

test "CLI compiles an IR file of exactly MAX_IR_BYTES" {
    const allocator = testing.allocator;
    const io = testing.io;

    const src = try paddedFixture(allocator, io, json.MAX_IR_BYTES);
    defer allocator.free(src);
    try testing.expectEqual(json.MAX_IR_BYTES, src.len);

    const r = try runCompileIr(allocator, io, src, "AtCap.anf.json");
    defer allocator.free(r.stdout);
    defer allocator.free(r.stderr);
    if (r.code == null or r.code.? != 0) {
        std.debug.print(
            "runar-zig refused an IR file at MAX_IR_BYTES: {s}\n",
            .{r.stderr[0..@min(r.stderr.len, 400)]},
        );
        return error.CliRefusedIrAtCap;
    }
    try testing.expectEqualStrings(EXPECTED_HEX, std.mem.trim(u8, r.stdout, " \r\n\t"));
}

test "CLI refuses an IR file one byte over MAX_IR_BYTES with the IRSizeExceeded diagnostic" {
    const allocator = testing.allocator;
    const io = testing.io;

    const src = try paddedFixture(allocator, io, json.MAX_IR_BYTES + 1);
    defer allocator.free(src);
    try testing.expectEqual(json.MAX_IR_BYTES + 1, src.len);

    const r = try runCompileIr(allocator, io, src, "Oversize.anf.json");
    defer allocator.free(r.stdout);
    defer allocator.free(r.stderr);
    try testing.expect(r.code != null and r.code.? != 0);
    // Must be the loader's typed diagnostic, not a raw StreamTooLong from the
    // CLI's own read step.
    if (std.mem.indexOf(u8, r.stderr, "error: IRSizeExceeded") == null) {
        std.debug.print(
            "expected \"error: IRSizeExceeded\", got: {s}\n",
            .{r.stderr[0..@min(r.stderr.len, 400)]},
        );
        return error.WrongRefusal;
    }
}
