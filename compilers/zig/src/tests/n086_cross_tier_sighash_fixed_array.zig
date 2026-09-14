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
//! Availability policy — peers are NOT required, and their absence is reported
//! as a SKIP, never as a pass:
//!
//!   * Every peer is invoked through the SAME uniform CLI the conformance
//!     runner uses (`--source <file> --hex --disable-constant-folding`).
//!   * A peer counts as unavailable for exactly two environment reasons: its
//!     artifact is not built, or its interpreter is not installed. Both are
//!     facts about the machine, not about the code under test, so the peer is
//!     dropped from the comparison and named in the diagnostic together with
//!     the exact command that would build it.
//!   * Anything past those two — a CLI that launches and then refuses, or
//!     prints no hex, or prints a DIFFERENT script — is a real cross-tier
//!     disagreement and still fails hard. Availability is never an excuse.
//!   * When NO peer is available the cross-tier claim was not checked, so the
//!     test returns `error.SkipZigTest`. `zig build test --summary all` then
//!     reports it under "skipped" rather than folding it into the pass count:
//!     a cross-tier test that quietly becomes a no-op would certify agreement
//!     it never verified. The zig-tier sighash-byte assertions run either way.
//!   * `RUNAR_CROSS_TIER_MIN` (default 0) turns the floor back on: a job that
//!     builds every tier sets it to 6 and a silently-degraded run then FAILS
//!     instead of skipping. The default used to be 1, which made one peer
//!     mandatory and broke `zig build test` in a checkout where only Zig was
//!     built — the opposite of the stated policy.
//!
//! Measured with all six peers built: zig, go, rust, python, ruby and java
//! agree byte-for-byte, with 0x43 at byte offsets 394 and 519 — the
//! auto-injected `extractSigHashType` assert const and the OP_PUSH_TX binding
//! blob's appended DER sighash byte.

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
/// expects, the argv prefix, the file that must exist for the tier to be
/// considered built, the interpreter that must be installed for `argv` to run
/// at all, and the command that produces the artifact. Paths are relative to
/// `compilers/zig`, which is the CWD `zig build test` runs in.
const Tier = struct {
    name: []const u8,
    cwd: []const u8,
    argv: []const []const u8,
    /// Existence probe, relative to `cwd`.
    probe: []const u8,
    /// Interpreter that must be launchable. Empty when `argv[0]` IS the probed
    /// binary, which the probe already covers.
    interpreter: []const u8,
    /// Quoted verbatim in the skip / floor diagnostic, so a developer who hits
    /// either does not have to go hunting for the build line.
    build_cmd: []const u8,
};

/// Binary names are the ones the conformance runner and CI actually produce
/// (`conformance/runner/runner.ts`, `.github/workflows/ci.yml`). They were
/// previously spelled `runar-go-compiler` and `runar-rust`, which no build step
/// in this repo ever emits — so the go and rust tiers could never be found, and
/// the comparison silently ran four-wide even in a fully built checkout.
const PEERS = [_]Tier{
    .{
        .name = "go",
        .cwd = "../go",
        .argv = &.{"./runar-go"},
        .probe = "runar-go",
        .interpreter = "",
        .build_cmd = "cd compilers/go && go build -o runar-go .",
    },
    .{
        .name = "rust",
        .cwd = "../rust",
        .argv = &.{"./target/release/runar-compiler-rust"},
        .probe = "target/release/runar-compiler-rust",
        .interpreter = "",
        .build_cmd = "cd compilers/rust && cargo build --release",
    },
    .{
        .name = "python",
        .cwd = "../python",
        .argv = &.{ "python3", "-m", "runar_compiler" },
        .probe = "runar_compiler/__main__.py",
        .interpreter = "python3",
        // The compiler itself is checked in and has no dependencies
        // (`compilers/python/pyproject.toml` declares `dependencies = []`), so
        // the only thing that can be missing is the interpreter.
        .build_cmd = "install python3 (the compiler source is already checked in)",
    },
    .{
        .name = "ruby",
        .cwd = "../ruby",
        .argv = &.{ "ruby", "bin/runar-compiler-ruby" },
        .probe = "bin/runar-compiler-ruby",
        .interpreter = "ruby",
        .build_cmd = "install ruby (the compiler source is already checked in)",
    },
};

const JAVA_BUILD_CMD = "cd compilers/java && ./gradlew jar";

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

/// Whether `exe --version` can be launched and exits 0. Mirrors the conformance
/// runner's `python3 --version` / `ruby --version` gate, which exists for the
/// same reason: a missing interpreter is a missing tier, not a broken one.
fn interpreterAvailable(allocator: std.mem.Allocator, io: std.Io, exe: []const u8) bool {
    const r = std.process.run(allocator, io, .{
        .argv = &.{ exe, "--version" },
        .stdout_limit = .limited(64 * 1024),
    }) catch return false;
    defer allocator.free(r.stdout);
    defer allocator.free(r.stderr);
    return switch (r.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

/// Why `tier` cannot be exercised on this machine, or null when it can be.
/// Caller owns the returned slice.
///
/// Deliberately limited to the two environment facts above. It must never
/// absorb a tier that runs and then disagrees — that is the bug this whole
/// file exists to catch.
fn unavailableReason(allocator: std.mem.Allocator, io: std.Io, tier: Tier) !?[]u8 {
    const probe = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ tier.cwd, tier.probe });
    defer allocator.free(probe);
    _ = std.Io.Dir.cwd().statFile(io, probe, .{}) catch {
        return try std.fmt.allocPrint(allocator, "not built ({s} is absent)", .{probe});
    };
    if (tier.interpreter.len > 0 and !interpreterAvailable(allocator, io, tier.interpreter)) {
        return try std.fmt.allocPrint(allocator, "`{s}` is not on PATH", .{tier.interpreter});
    }
    return null;
}

/// Append one "why this peer was not compared, and how to fix it" entry.
fn noteUnavailable(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    name: []const u8,
    reason: []const u8,
    build_cmd: []const u8,
) !void {
    const line = try std.fmt.allocPrint(
        allocator,
        "    - {s}: {s}\n        build with: {s}\n",
        .{ name, reason, build_cmd },
    );
    defer allocator.free(line);
    try out.appendSlice(allocator, line);
}

/// Run one tier's CLI over `abs_source` and return the trimmed hex it printed.
/// Returns null when the tier refuses or prints nothing.
///
/// Availability is settled by `unavailableReason` BEFORE this is called, so a
/// null here means a tier that should have worked did not — the caller treats
/// it as a failure and must keep doing so.
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
    // This half runs unconditionally — it is the regression guard for the N-086
    // bug itself and does not depend on any peer being present.
    const zig_bin = std.testing.environ.getPosix("RUNAR_ZIG_BIN") orelse "zig-out/bin/runar-zig";
    const reference = (try tierHex(allocator, io, .inherit, &.{zig_bin}, abs)) orelse
        return error.ZigCompilerProducedNoHex;
    defer allocator.free(reference);
    try expectFlagAt(reference, "zig");

    var compared: std.ArrayListUnmanaged(u8) = .empty;
    defer compared.deinit(allocator);
    try compared.appendSlice(allocator, "zig");

    // Peers that could not be exercised, each with its reason and build command.
    var unavailable: std.ArrayListUnmanaged(u8) = .empty;
    defer unavailable.deinit(allocator);
    var peers_found: usize = 0;

    for (PEERS) |tier| {
        if (try unavailableReason(allocator, io, tier)) |reason| {
            defer allocator.free(reason);
            try noteUnavailable(allocator, &unavailable, tier.name, reason, tier.build_cmd);
            continue;
        }

        const hex = (try tierHex(allocator, io, .{ .path = tier.cwd }, tier.argv, abs)) orelse {
            std.debug.print("  tier {s} is available but produced no hex\n", .{tier.name});
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
        if (interpreterAvailable(allocator, io, "java")) {
            // `cwd` stays inherited: the jar path above is relative to this CWD.
            const hex = (try tierHex(allocator, io, .inherit, &.{ "java", "-jar", jar }, abs)) orelse {
                std.debug.print("  tier java is available but produced no hex\n", .{});
                return error.PeerTierProducedNoHex;
            };
            defer allocator.free(hex);
            peers_found += 1;
            try compared.appendSlice(allocator, " java");
            try expectFlagAt(hex, "java");
            try std.testing.expectEqualStrings(reference, hex);
        } else {
            try noteUnavailable(allocator, &unavailable, "java", "`java` is not on PATH", JAVA_BUILD_CMD);
        }
    } else {
        try noteUnavailable(
            allocator,
            &unavailable,
            "java",
            "not built (../java/build/libs/runar-java*.jar is absent)",
            JAVA_BUILD_CMD,
        );
    }

    std.debug.print("  N-086 cross-tier: compared [{s}]\n", .{compared.items});

    // An explicit floor outranks the skip: a job that claims to build N peers
    // must go red, not quietly skip, when it did not.
    const min_env = std.testing.environ.getPosix("RUNAR_CROSS_TIER_MIN") orelse "0";
    const min_peers = std.fmt.parseInt(usize, std.mem.trim(u8, min_env, " \r\n"), 10) catch 0;
    if (peers_found < min_peers) {
        std.debug.print(
            "  N-086 cross-tier: RUNAR_CROSS_TIER_MIN demands {d} peer tier(s), only {d} available.\n" ++
                "  Peers not compared:\n{s}",
            .{ min_peers, peers_found, unavailable.items },
        );
        return error.TooFewPeerTiersBuilt;
    }

    if (peers_found == 0) {
        std.debug.print(
            "  N-086 cross-tier: SKIPPED — no peer tier is available, so the cross-tier\n" ++
                "  agreement claim was NOT checked. (The zig-tier sighash-byte assertions\n" ++
                "  above DID run.) Build any peer to turn the comparison on:\n{s}" ++
                "  Set RUNAR_CROSS_TIER_MIN=<n> to require n peers and fail instead of skip.\n",
            .{unavailable.items},
        );
        return error.SkipZigTest;
    }
}
