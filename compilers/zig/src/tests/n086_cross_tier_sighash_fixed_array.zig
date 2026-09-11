//! N-086 cross-tier — all seven tiers must compile the SAME locking script for
//! a `@sighash SINGLE|FORKID` method on a FixedArray contract.
//!
//! This test was NOT buildable before N-086: the Zig tier dropped
//! `MethodNode.sighash_type` in `passes/expand_fixed_arrays.zig`, so Zig emitted
//! the default ALL|FORKID binding (0x41) where the other six emitted the
//! declared SINGLE|FORKID (0x43). A cross-tier agreement assertion would have
//! been red for a reason unrelated to the tier under comparison.
//!
//! Why it lives here and not in `conformance/`: `conformance/negatives/` is a
//! REJECTION-parity suite (sources every tier must refuse), and this is an
//! ACCEPTANCE-parity claim; adding a `conformance/tests/` fixture would mint new
//! checked-in goldens. Shelling out from the Zig tier keeps the claim in one
//! place and touches no other tier's tree.
//!
//! Availability: each peer tier is invoked through the SAME uniform CLI the
//! conformance runner uses (`--source <file> --hex --disable-constant-folding`)
//! and is SKIPPED when its binary is absent, so `zig build test` stays green in
//! a checkout where only Zig is built. That makes the test as strong as the
//! environment allows and no stronger — which is why it PRINTS the tier list it
//! actually compared, and why `RUNAR_CROSS_TIER_MIN` (default 1) lets CI demand
//! a floor: set it to 6 in a job that builds every tier and the test fails
//! rather than silently degrading to a self-comparison.
//!
//! Measured here with go/rust unbuilt: zig, python, ruby, java agreed
//! byte-for-byte (sha256 45865d64815ad777…), with 0x43 at byte offsets 394 and
//! 519 — the auto-injected `extractSigHashType` assert const and the OP_PUSH_TX
//! binding blob's appended DER sighash byte.

const std = @import("std");

/// Stateful + FixedArray + a non-default `@sighash`. The method binds exactly
/// one output because `sighash_validate` refuses a mutate-only SINGLE
/// continuation as a value-skim vector.
const SRC =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class Boardy extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  /** @sighash SINGLE|FORKID */
    \\  public bump(v: bigint): void {
    \\    assert(this.owner > 0n);
    \\    this.addOutput(1000n, this.cells[0], this.cells[1], this.cells[2]);
    \\  }
    \\}
;

/// Byte offsets carrying the BIP-143 binding flag in the emitted script, and
/// the value the declared mode must put there. Pinned rather than "contains
/// 0143" so an unrelated 0x43 push cannot satisfy the assertion.
const FLAG_OFFSETS = [_]usize{ 394, 519 };
const FLAG_BYTE = "43";

/// One peer tier: a display name, the repo-relative working directory its CLI
/// expects, the argv prefix, and the file that must exist for the tier to be
/// considered built. Paths are relative to `compilers/zig`, which is the CWD
/// `zig build test` runs in.
const Tier = struct {
    name: []const u8,
    cwd: []const u8,
    argv: []const []const u8,
    /// Existence probe, relative to `cwd`.
    probe: []const u8,
};

const PEERS = [_]Tier{
    .{
        .name = "go",
        .cwd = "../go",
        .argv = &.{"./runar-go-compiler"},
        .probe = "runar-go-compiler",
    },
    .{
        .name = "rust",
        .cwd = "../rust",
        .argv = &.{"./target/release/runar-rust"},
        .probe = "target/release/runar-rust",
    },
    .{
        .name = "python",
        .cwd = "../python",
        .argv = &.{ "python3", "-m", "runar_compiler" },
        .probe = "runar_compiler/__main__.py",
    },
    .{
        .name = "ruby",
        .cwd = "../ruby",
        .argv = &.{ "ruby", "bin/runar-compiler-ruby" },
        .probe = "bin/runar-compiler-ruby",
    },
};

/// The Java jar carries a version in its filename, so it is resolved at run
/// time rather than pinned in `PEERS`.
fn findJavaJar(allocator: std.mem.Allocator, io: std.Io) !?[]u8 {
    const libs = "../java/build/libs";
    var dir = std.Io.Dir.cwd().openDir(io, libs, .{ .iterate = true }) catch return null;
    defer dir.close(io);
    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.startsWith(u8, entry.name, "runar-java")) continue;
        if (!std.mem.endsWith(u8, entry.name, ".jar")) continue;
        return try std.fmt.allocPrint(allocator, "{s}/{s}", .{ libs, entry.name });
    }
    return null;
}

/// Run one tier's CLI over `abs_source` and return the trimmed hex it printed.
/// Returns null when the tier refuses or prints nothing, which is reported as a
/// failure by the caller rather than swallowed.
fn tierHex(
    allocator: std.mem.Allocator,
    io: std.Io,
    cwd: std.process.Child.Cwd,
    prefix: []const []const u8,
    abs_source: []const u8,
) !?[]u8 {
    var argv: std.ArrayListUnmanaged([]const u8) = .empty;
    defer argv.deinit(allocator);
    for (prefix) |p| try argv.append(allocator, p);
    try argv.append(allocator, "--source");
    try argv.append(allocator, abs_source);
    try argv.append(allocator, "--hex");
    try argv.append(allocator, "--disable-constant-folding");

    const result = std.process.run(allocator, io, .{
        .argv = argv.items,
        .cwd = cwd,
        .stdout_limit = .limited(10 * 1024 * 1024),
    }) catch return null;
    defer allocator.free(result.stderr);
    defer allocator.free(result.stdout);

    switch (result.term) {
        .exited => |code| if (code != 0) {
            std.debug.print("  tier exit {d}: {s}\n", .{ code, result.stderr });
            return null;
        },
        else => return null,
    }
    // Every tier prints warnings before the hex; the hex is the last line.
    var last: []const u8 = "";
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        const t = std.mem.trim(u8, line, " \r\t");
        if (t.len > 0) last = t;
    }
    if (last.len == 0) return null;
    return try allocator.dupe(u8, last);
}

fn expectFlagAt(hex: []const u8, tier: []const u8) !void {
    for (FLAG_OFFSETS) |off| {
        const i = off * 2;
        try std.testing.expect(i + 2 <= hex.len);
        if (!std.mem.eql(u8, hex[i .. i + 2], FLAG_BYTE)) {
            std.debug.print(
                "  tier {s}: byte {d} is {s}, expected {s} (declared SINGLE|FORKID)\n",
                .{ tier, off, hex[i .. i + 2], FLAG_BYTE },
            );
            return error.WrongSighashFlagByte;
        }
    }
}

test "N-086 every available tier compiles the same FixedArray @sighash script" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Peers run with their own CWD, so the source path handed to them must be
    // absolute.
    const dir_path = "zig-out/n086-cross-tier";
    std.Io.Dir.cwd().createDirPath(io, dir_path) catch {};
    const rel = dir_path ++ "/Boardy.runar.ts";
    {
        var file = try std.Io.Dir.cwd().createFile(io, rel, .{});
        defer file.close(io);
        var buf: [4096]u8 = undefined;
        var w = file.writer(io, &buf);
        try w.interface.writeAll(SRC);
        try w.interface.flush();
    }
    defer std.Io.Dir.cwd().deleteFile(io, rel) catch {};
    const abs = try std.Io.Dir.cwd().realPathFileAlloc(io, rel, allocator);
    defer allocator.free(abs);

    // Reference: this tier's own binary, which `build.zig` guarantees is fresh.
    const zig_bin = std.testing.environ.getPosix("RUNAR_ZIG_BIN") orelse "zig-out/bin/runar-zig";
    const reference = (try tierHex(allocator, io, .inherit, &.{zig_bin}, abs)) orelse
        return error.ZigCompilerProducedNoHex;
    defer allocator.free(reference);
    try expectFlagAt(reference, "zig");

    var compared: std.ArrayListUnmanaged(u8) = .empty;
    defer compared.deinit(allocator);
    try compared.appendSlice(allocator, "zig");
    var peers_found: usize = 0;

    for (PEERS) |tier| {
        const probe = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ tier.cwd, tier.probe });
        defer allocator.free(probe);
        _ = std.Io.Dir.cwd().statFile(io, probe, .{}) catch continue;

        const hex = (try tierHex(allocator, io, .{ .path = tier.cwd }, tier.argv, abs)) orelse {
            std.debug.print("  tier {s} is present but produced no hex\n", .{tier.name});
            return error.PeerTierProducedNoHex;
        };
        defer allocator.free(hex);
        peers_found += 1;
        try compared.append(allocator, ' ');
        try compared.appendSlice(allocator, tier.name);
        try expectFlagAt(hex, tier.name);
        try std.testing.expectEqualStrings(reference, hex);
    }

    if (try findJavaJar(allocator, io)) |jar| {
        defer allocator.free(jar);
        // `cwd` stays inherited: the jar path above is relative to this CWD.
        const hex = (try tierHex(allocator, io, .inherit, &.{ "java", "-jar", jar }, abs)) orelse {
            std.debug.print("  tier java jar is present but produced no hex\n", .{});
            return error.PeerTierProducedNoHex;
        };
        defer allocator.free(hex);
        peers_found += 1;
        try compared.appendSlice(allocator, " java");
        try expectFlagAt(hex, "java");
        try std.testing.expectEqualStrings(reference, hex);
    }

    std.debug.print("  N-086 cross-tier: compared [{s}]\n", .{compared.items});

    // A self-comparison proves nothing. CI that builds every tier sets
    // RUNAR_CROSS_TIER_MIN=6 so a silently-degraded run fails instead of
    // reporting green off one tier.
    const min_env = std.testing.environ.getPosix("RUNAR_CROSS_TIER_MIN") orelse "1";
    const min_peers = std.fmt.parseInt(usize, std.mem.trim(u8, min_env, " \r\n"), 10) catch 1;
    if (peers_found < min_peers) {
        std.debug.print(
            "  N-086 cross-tier: {d} peer tiers found, RUNAR_CROSS_TIER_MIN demands {d}\n",
            .{ peers_found, min_peers },
        );
        return error.TooFewPeerTiersBuilt;
    }
}
