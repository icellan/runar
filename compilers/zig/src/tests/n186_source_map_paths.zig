//! N-186: `--emit-source-map` was silently dropped on three Zig CLI paths,
//! each exiting 0 having written nothing and printed no diagnostic:
//!
//!   * `--source X --hex --emit-source-map Y`   (compileFromSource returned
//!     right after printing the hex, before the source-map block)
//!   * `--source IR.json --emit-source-map Y`   (compileFromIR never looked
//!     at the flag; also with `--hex`)
//!   * `--source IR.json --emit-ir --emit-source-map Y` (returned after the IR)
//!
//! Go, Rust, Python, Ruby and Java all write the map for these combinations;
//! for an IR input there are no source locations, so the map they write is
//! the empty `{"mappings":[]}` wrapper. The Zig CLI now does the same.
//!
//! What this test proves: the built `runar-zig` binary writes a
//! `{"mappings": ...}` file for each combination, keeps stdout as the
//! requested output (hex only, or IR only), and that a real source compile
//! yields a non-empty mapping list under `--hex`.
//! What it does not prove: any other tier's CLI (covered by their own tests);
//! `--parse-only --emit-source-map`, which no tier honours.
//!
//! The binary is resolved via `RUNAR_ZIG_BIN`, falling back to
//! `zig-out/bin/runar-zig` relative to CWD (`compilers/zig`).

const std = @import("std");
const testing = std.testing;

fn resolveZigBinary() []const u8 {
    if (std.testing.environ.getPosix("RUNAR_ZIG_BIN")) |bin| return bin;
    return "zig-out/bin/runar-zig";
}

const source_path = "../../examples/zig/p2pkh/P2PKH.runar.zig";
const ir_path = "../../conformance/tests/basic-p2pkh/expected-ir.json";
const tmp_dir = "zig-out/n186-tmp";

/// Runs the binary with `argv_tail` followed by `--emit-source-map <sm_name>`,
/// asserts exit 0 and that the map file exists with a "mappings" key, and
/// returns the stdout and the map contents (caller frees both).
fn runWithSourceMap(
    allocator: std.mem.Allocator,
    argv_tail: []const []const u8,
    sm_name: []const u8,
    out_stdout: *[]u8,
    out_map: *[]u8,
) !void {
    const io = testing.io;
    std.Io.Dir.cwd().createDirPath(io, tmp_dir) catch {};
    const sm_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ tmp_dir, sm_name });
    defer allocator.free(sm_path);
    std.Io.Dir.cwd().deleteFile(io, sm_path) catch {};

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.append(allocator, resolveZigBinary());
    for (argv_tail) |a| try argv.append(allocator, a);
    try argv.append(allocator, "--emit-source-map");
    try argv.append(allocator, sm_path);

    const result = std.process.run(allocator, io, .{
        .argv = argv.items,
        .stdout_limit = .limited(10 * 1024 * 1024),
    }) catch |err| {
        std.debug.print("could not run runar-zig: {s}\n", .{@errorName(err)});
        return error.CompilerBinaryMissing;
    };
    defer allocator.free(result.stderr);
    errdefer allocator.free(result.stdout);

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                std.debug.print("must exit 0, got {d}\nstdout: {s}\nstderr: {s}\n", .{ code, result.stdout, result.stderr });
                return error.CompilerExitNonZero;
            }
        },
        else => return error.CompilerAbnormalExit,
    }

    var sm_file = std.Io.Dir.cwd().openFile(io, sm_path, .{}) catch {
        std.debug.print("--emit-source-map file was never written (N-186); stderr: {s}\n", .{result.stderr});
        return error.SourceMapNotWritten;
    };
    defer sm_file.close(io);
    var read_buf: [8192]u8 = undefined;
    var reader = sm_file.reader(io, &read_buf);
    const sm_contents = try reader.interface.allocRemaining(allocator, .unlimited);
    errdefer allocator.free(sm_contents);
    if (std.mem.indexOf(u8, sm_contents, "\"mappings\"") == null) {
        std.debug.print("source map must carry a \"mappings\" key, got: {s}\n", .{sm_contents});
        return error.MissingMappingsKey;
    }
    out_stdout.* = result.stdout;
    out_map.* = sm_contents;
}

fn isHexLine(s: []const u8) bool {
    const t = std.mem.trim(u8, s, " \r\n");
    if (t.len == 0) return false;
    for (t) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

test "--hex with --emit-source-map writes the source map and prints only the hex" {
    const allocator = testing.allocator;
    var out: []u8 = undefined;
    var map: []u8 = undefined;
    try runWithSourceMap(allocator, &.{ "--source", source_path, "--hex" }, "src-hex.json", &out, &map);
    defer allocator.free(out);
    defer allocator.free(map);
    try testing.expect(isHexLine(out));
    // A real source compile carries real mappings, not the empty wrapper.
    try testing.expect(std.mem.indexOf(u8, map, "\"opcodeIndex\"") != null);
}

test "--source <ir.json> with --emit-source-map writes the (empty) source map" {
    const allocator = testing.allocator;
    var out: []u8 = undefined;
    var map: []u8 = undefined;
    try runWithSourceMap(allocator, &.{ "--source", ir_path }, "ir-plain.json", &out, &map);
    defer allocator.free(out);
    defer allocator.free(map);
    try testing.expect(std.mem.indexOf(u8, out, "\"script\"") != null);
    // An ANF IR carries no source locations: same {"mappings":[]} as the
    // Go/Rust/Python/Ruby/Java CLIs write on this path.
    try testing.expect(std.mem.indexOf(u8, map, "\"opcodeIndex\"") == null);
}

test "--source <ir.json> --hex with --emit-source-map writes the source map and prints only the hex" {
    const allocator = testing.allocator;
    var out: []u8 = undefined;
    var map: []u8 = undefined;
    try runWithSourceMap(allocator, &.{ "--source", ir_path, "--hex" }, "ir-hex.json", &out, &map);
    defer allocator.free(out);
    defer allocator.free(map);
    try testing.expect(isHexLine(out));
}

test "--source <ir.json> --emit-ir with --emit-source-map writes the source map and prints only IR" {
    const allocator = testing.allocator;
    var out: []u8 = undefined;
    var map: []u8 = undefined;
    try runWithSourceMap(allocator, &.{ "--source", ir_path, "--emit-ir" }, "ir-emit-ir.json", &out, &map);
    defer allocator.free(out);
    defer allocator.free(map);
    try testing.expect(std.mem.indexOf(u8, out, "\"contractName\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"script\"") == null);
}
