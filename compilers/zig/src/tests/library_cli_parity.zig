//! R-027: the library entry point and the CLI must be ONE compiler.
//!
//! `compiler_api.compileSourceWithOptions` and `main.zig`'s `compileFromSource`
//! were two hand-maintained copies of the same pass sequence, and they had
//! drifted: the library ran no `expand_fixed_arrays` pass at all, so a contract
//! with a `FixedArray<T, N>` property lowered as though the property were
//! something else. Because the library path is what every unit test uses, the
//! Zig tier's own tests were validating a pipeline that is not the one shipped.
//!
//! These tests pin the real invariant — not "the pass runs", but "the library
//! and the binary emit the same bytes for the same source and the same
//! options" — by compiling in-process AND shelling out to the built
//! `runar-zig` binary, in both fold modes. Two things are asserted, because
//! the two copies had drifted in two places:
//!
//!   A. the library's artifact `script` must equal the CLI's `--hex`. This is
//!      the assertion the missing `expand_fixed_arrays` pass broke.
//!   B. `CompileResult.script_hex` (what `compileSourceToHex` returns) must
//!      equal the CLI's `--hex` too. It was a newline-joined concatenation of
//!      per-method fragments, which is not a locking script.
//!
//! The FixedArray case is the R-027 regression; the plain scalar contract is
//! the control. The control passes assertion A both before and after the fix,
//! so these tests prove convergence rather than mere movement.
//!
//! The fix is structural: both entry points now run `compiler_api.runPipeline`
//! and nothing else, so there is one pass sequence rather than two. These
//! tests stay because "one pipeline" is a property that has to keep holding.
//!
//! The binary is resolved via `RUNAR_ZIG_BIN`, falling back to
//! `zig-out/bin/runar-zig` relative to CWD (`compilers/zig`). `build.zig` makes
//! the `test` step depend on the install step so the binary is always present
//! and always current — a stale binary would compare the library against a
//! different compiler than the one in the tree.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

/// A contract whose state is a `FixedArray<bigint, 3>` — the shape that
/// requires pass 3b. It exercises both halves of the pass: literal-index reads
/// (rewritten to direct `slots__K` access) and a runtime-index write (lowered
/// to an if/else dispatch chain). Access shapes mirror
/// `examples/ts/tic-tac-toe/TicTacToe.v2.runar.ts`.
const FIXED_ARRAY_SOURCE =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class HasArray extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  slots: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public set(idx: bigint, value: bigint): void {
    \\    assert(this.owner == 1n);
    \\    this.slots[idx] = value;
    \\  }
    \\  public check(): void {
    \\    assert(this.slots[0] == 0n);
    \\    assert(this.slots[1] != 0n);
    \\    assert(this.slots[2] == 0n);
    \\  }
    \\}
;

/// Control: the same contract with the array written out by hand as three
/// scalar properties and an explicit dispatch chain — i.e. what pass 3b is
/// supposed to produce. Pass 3b is a no-op here, so library and CLI already
/// agreed before the fix and must still agree after it.
const SCALAR_CONTROL_SOURCE =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class NoArray extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  s0: bigint = 0n;
    \\  s1: bigint = 0n;
    \\  s2: bigint = 0n;
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public set(idx: bigint, value: bigint): void {
    \\    assert(this.owner == 1n);
    \\    if (idx == 0n) { this.s0 = value; }
    \\    else if (idx == 1n) { this.s1 = value; }
    \\    else { this.s2 = value; }
    \\  }
    \\  public check(): void {
    \\    assert(this.s0 == 0n);
    \\    assert(this.s1 != 0n);
    \\    assert(this.s2 == 0n);
    \\  }
    \\}
;

fn resolveZigBinary() []const u8 {
    if (std.testing.environ.getPosix("RUNAR_ZIG_BIN")) |bin| return bin;
    return "zig-out/bin/runar-zig";
}

/// Write `source` to a scratch file and run the built compiler binary over it
/// with `--hex`, returning the emitted locking-script hex (caller frees).
fn cliHex(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: []const u8,
    file_name: []const u8,
    disable_constant_folding: bool,
) ![]u8 {
    const dir_path = "zig-out/parity-tmp";
    std.Io.Dir.cwd().createDirPath(io, dir_path) catch {};
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_path, file_name });
    defer allocator.free(path);
    {
        var file = try std.Io.Dir.cwd().createFile(io, path, .{});
        defer file.close(io);
        var buf: [4096]u8 = undefined;
        var w = file.writer(io, &buf);
        try w.interface.writeAll(source);
        try w.interface.flush();
    }
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    var argv: std.ArrayListUnmanaged([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.append(allocator, resolveZigBinary());
    try argv.append(allocator, "--source");
    try argv.append(allocator, path);
    try argv.append(allocator, "--hex");
    if (disable_constant_folding) try argv.append(allocator, "--disable-constant-folding");

    const result = try std.process.run(allocator, io, .{
        .argv = argv.items,
        .stdout_limit = .limited(10 * 1024 * 1024),
    });
    defer allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code != 0) {
            defer allocator.free(result.stdout);
            std.debug.print("  runar-zig exit {d}: {s}\n", .{ code, result.stderr });
            return error.CompilerExitNonZero;
        },
        else => {
            defer allocator.free(result.stdout);
            return error.CompilerAbnormalExit;
        },
    }
    // --hex writes a single trailing newline.
    const trimmed = std.mem.trim(u8, result.stdout, " \r\n");
    const hex = try allocator.dupe(u8, trimmed);
    allocator.free(result.stdout);
    return hex;
}

/// Pull the `"script":"…"` field out of an emitted artifact JSON — the same
/// extraction the CLI's `--hex` flag performs.
fn artifactScript(artifact: []const u8) ![]const u8 {
    const marker = "\"script\":\"";
    const idx = std.mem.indexOf(u8, artifact, marker) orelse return error.MissingHex;
    const after = idx + marker.len;
    const end = std.mem.indexOfPos(u8, artifact, after, "\"") orelse return error.MissingHex;
    return artifact[after..end];
}

/// Assertion A — the artifact the library hands back must be the artifact the
/// binary would have written. This is the assertion the missing pass 3b breaks.
fn expectArtifactMatchesCli(
    source: []const u8,
    file_name: []const u8,
    disable_constant_folding: bool,
) !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const expected = try cliHex(allocator, io, source, file_name, disable_constant_folding);
    defer allocator.free(expected);

    const lib = try compiler_api.compileSourceWithOptions(
        allocator,
        source,
        file_name,
        disable_constant_folding,
    );
    defer lib.deinit(allocator);

    try std.testing.expectEqualStrings(expected, try artifactScript(lib.artifact_json.?));
}

/// Assertion B — `compileSourceToHex` is what a library consumer treats as
/// "the script", so it must be the same bytes the binary prints for `--hex`.
/// It was a newline-joined concatenation of per-method fragments, which is not
/// a valid locking script for a multi-method contract; the CLI already carries
/// that note in `compileFromIR` and the library never got the memo.
fn expectHexMatchesCli(
    source: []const u8,
    file_name: []const u8,
    disable_constant_folding: bool,
) !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const expected = try cliHex(allocator, io, source, file_name, disable_constant_folding);
    defer allocator.free(expected);

    const lib = try compiler_api.compileSourceWithOptions(
        allocator,
        source,
        file_name,
        disable_constant_folding,
    );
    defer lib.deinit(allocator);

    try std.testing.expectEqualStrings(expected, lib.script_hex);
}

test "R-027 control: scalar contract — library artifact matches CLI --hex (fold ON)" {
    try expectArtifactMatchesCli(SCALAR_CONTROL_SOURCE, "NoArray.runar.ts", false);
}

test "R-027 control: scalar contract — library artifact matches CLI --hex (fold OFF)" {
    try expectArtifactMatchesCli(SCALAR_CONTROL_SOURCE, "NoArray.runar.ts", true);
}

test "R-027: FixedArray contract — library artifact matches CLI --hex (fold ON)" {
    try expectArtifactMatchesCli(FIXED_ARRAY_SOURCE, "HasArray.runar.ts", false);
}

test "R-027: FixedArray contract — library artifact matches CLI --hex (fold OFF)" {
    try expectArtifactMatchesCli(FIXED_ARRAY_SOURCE, "HasArray.runar.ts", true);
}

test "R-027 control: scalar contract — library script_hex matches CLI --hex (fold ON)" {
    try expectHexMatchesCli(SCALAR_CONTROL_SOURCE, "NoArray.runar.ts", false);
}

test "R-027 control: scalar contract — library script_hex matches CLI --hex (fold OFF)" {
    try expectHexMatchesCli(SCALAR_CONTROL_SOURCE, "NoArray.runar.ts", true);
}

test "R-027: FixedArray contract — library script_hex matches CLI --hex (fold ON)" {
    try expectHexMatchesCli(FIXED_ARRAY_SOURCE, "HasArray.runar.ts", false);
}

test "R-027: FixedArray contract — library script_hex matches CLI --hex (fold OFF)" {
    try expectHexMatchesCli(FIXED_ARRAY_SOURCE, "HasArray.runar.ts", true);
}
