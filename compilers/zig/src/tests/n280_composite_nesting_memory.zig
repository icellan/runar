//! N-280 — compile memory must not grow quadratically in if-nesting depth.
//!
//! Stack lowering flattens each `if` arm into its own instruction list, runs
//! the peephole over it (N-100), and copies the result into the parent. Every
//! enclosing `if` therefore held its own copy of everything nested inside it,
//! and the lists lived on the compile arena, which frees nothing: retention
//! grew with the SQUARE of the nesting depth. On remediation-logs/N-180/
//! compgen.py's shape (D helpers, each calling the next under 120 nested ifs)
//! the ReleaseSafe CLI peaked at 1.65 GB RSS for D=8 (Go: 80 MB), passed 8 GB
//! for D=32, and D=127 — the deepest chain the call-depth and nesting limits
//! admit — was OOM-killed.
//!
//! The test runs the built CLI (`zig-out/bin/runar-zig`, or `RUNAR_ZIG_BIN`;
//! `build.zig` installs it before the test step runs) on D=8 x 120 and reads
//! the child's peak resident set size from wait4's rusage, so it bounds what
//! the process actually held, whichever allocator the memory came from.
//!
//! Proves: the CLI compiles D=8 x 120 (960 nested ifs after inlining) at a
//! peak RSS below `rss_bound`, and the script is byte-identical to the one
//! the Go compiler prints for the same source (sha256 of
//! remediation-logs/N-264/go-oracle-8.hex, which all seven tiers agreed on).
//! Does not prove: D=127. The fixed ReleaseSafe CLI compiles it to Go's bytes
//! (conformance/negatives/n264-composite-nesting-parity.test.ts pins the
//! digest), but the Debug CLI this suite usually builds is too slow for it.
//! Nor compile TIME, which was also quadratic in nesting depth (each level
//! re-ran the peephole over, and copied, its already-optimized subtree);
//! tests/n343_composite_nesting_work.zig bounds that. Nor the other tiers. Fails, rather than passes, where the platform reports no
//! rusage.

const std = @import("std");
const n264 = @import("n264_composite_nesting.zig");

/// Peak RSS the D=8 compile may reach. Measured on macOS, Debug and
/// ReleaseSafe alike: 1.66 GB before the fix, 70-74 MB after (Go: 80 MB).
const rss_bound: usize = 512 * 1024 * 1024;

fn resolveZigBinary() []const u8 {
    if (std.testing.environ.getPosix("RUNAR_ZIG_BIN")) |bin| return bin;
    return "zig-out/bin/runar-zig";
}

test "N-280: D=8 x 120 compiles to Go's bytes within a bounded peak RSS" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const w = arena.allocator();

    const dir_path = "zig-out/n280-tmp";
    std.Io.Dir.cwd().createDirPath(io, dir_path) catch {};
    const src_path = dir_path ++ "/comp8k120.runar.ts";
    const hex_path = dir_path ++ "/comp8k120.hex";
    {
        var file = try std.Io.Dir.cwd().createFile(io, src_path, .{});
        defer file.close(io);
        var buf: [4096]u8 = undefined;
        var fw = file.writer(io, &buf);
        try fw.interface.writeAll(try n264.comp(w, 8, 120));
        try fw.interface.flush();
    }
    defer std.Io.Dir.cwd().deleteFile(io, src_path) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, hex_path) catch {};

    var child = blk: {
        var out = try std.Io.Dir.cwd().createFile(io, hex_path, .{});
        defer out.close(io);
        break :blk try std.process.spawn(io, .{
            .argv = &.{ resolveZigBinary(), "--source", src_path, "--hex" },
            .stdin = .ignore,
            .stdout = .{ .file = out },
            .stderr = .inherit,
            .request_resource_usage_statistics = true,
        });
    };
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) {
            std.debug.print("N-280: runar-zig exited {d}\n", .{code});
            return error.CompilerExitNonZero;
        },
        else => return error.CompilerAbnormalExit,
    }

    const rss = child.resource_usage_statistics.getMaxRss() orelse {
        std.debug.print("N-280: this platform reports no child rusage; cannot bound RSS\n", .{});
        return error.NoResourceUsage;
    };

    const hex = try std.Io.Dir.cwd().readFileAlloc(io, hex_path, w, .limited(16 * 1024 * 1024));
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std.mem.trimEnd(u8, hex, "\r\n"), &digest, .{});
    const got = std.fmt.bytesToHex(digest, .lower);
    try std.testing.expectEqualStrings("579eeccfa4389f180849590c9857e7520a284bc3e5fb6d367a3291ee9c8a5052", &got);

    if (rss > rss_bound) {
        std.debug.print("N-280: D=8 x 120 peaked at {d} bytes RSS (bound {d})\n", .{ rss, rss_bound });
        return error.PeakRssTooLarge;
    }
}
