//! F-230 (CX-BUG-128): the library API silently fell back to the Zig-format
//! parser for an unrecognized file extension, while the CLI's `compile`
//! subcommand fails closed with `UnsupportedFormat`.
//!
//! `compiler_api.parseSource`'s `.unknown` branch read:
//!
//!     // Fall back to Zig parser for unknown extensions
//!     const r = parse_zig.parseZig(work, source, file_name);
//!
//! while `main.zig`'s `compileFromSource` explicitly refuses the same case
//! before ever reaching `runPipeline`:
//!
//!     switch (detectFormat(path)) {
//!         .unknown, .anf_json => {
//!             std.debug.print("error: unsupported format for {s}\n", .{path});
//!             return error.UnsupportedFormat;
//!         },
//!         else => {},
//!     }
//!
//! So a file named e.g. `contract.txt` is refused by one public entry point
//! and silently compiled under unintended (Zig) grammar by the other — the
//! two are no longer "one compiler" (R-027) for this input class.
//!
//! What this proves: for a syntactically-valid `.runar.zig` contract saved
//! under an unrecognized extension, both the CLI `compile` subcommand and
//! `compiler_api.compileSource` now refuse it with the same `UnsupportedFormat`
//! error class, rather than one refusing and the other quietly accepting it
//! as Zig-format source. The control test (same bytes, named `Vault.runar.zig`)
//! pins the refusal to the EXTENSION, not the contract body — without it, a
//! test asserting only "returns some error" would also pass if the fix
//! accidentally broke Zig-format parsing generally.
//!
//! What this does NOT prove: that every OTHER library entry point
//! (`parseSource` called directly, `validateForFile`, etc.) agrees with the
//! CLI for every unrecognized extension beyond this one case, nor anything
//! about the other six tiers' own library/CLI pairs (verified separately,
//! read-only, to be CONSISTENT already — see notes for dispatcher).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

/// A syntactically-valid `.runar.zig` contract — the grammar an unrecognized
/// extension gets silently parsed as before the fix. Mirrors the `zig()`
/// fixture shape in `n050_static_methods.zig`.
const VAULT_ZIG_SOURCE =
    \\const runar = @import("runar");
    \\
    \\pub const Vault = struct {
    \\    pub const Contract = runar.SmartContract;
    \\
    \\    owner: runar.PubKey,
    \\
    \\    pub fn init(owner: runar.PubKey) Vault {
    \\        return .{ .owner = owner };
    \\    }
    \\
    \\    pub fn withdraw(self: *const Vault, sig: runar.Sig) void {
    \\        runar.assert(runar.checkSig(sig, self.owner));
    \\    }
    \\};
;

/// An extension no surface parser claims — not `.json` either, so the CLI's
/// `.unknown, .anf_json` guard takes the `.unknown` arm specifically.
const UNKNOWN_FILE_NAME = "contract.txt";

fn resolveZigBinary() []const u8 {
    if (std.testing.environ.getPosix("RUNAR_ZIG_BIN")) |bin| return bin;
    return "zig-out/bin/runar-zig";
}

test "F-230: CLI `compile` refuses a valid .runar.zig contract saved as contract.txt" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const dir_path = "zig-out/f230-tmp";
    std.Io.Dir.cwd().createDirPath(io, dir_path) catch {};
    const path = dir_path ++ "/" ++ UNKNOWN_FILE_NAME;
    {
        var file = try std.Io.Dir.cwd().createFile(io, path, .{});
        defer file.close(io);
        var buf: [4096]u8 = undefined;
        var w = file.writer(io, &buf);
        try w.interface.writeAll(VAULT_ZIG_SOURCE);
        try w.interface.flush();
    }
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    const result = std.process.run(allocator, io, .{
        .argv = &.{ resolveZigBinary(), "compile", path },
        .stdout_limit = .limited(10 * 1024 * 1024),
    }) catch |err| {
        std.debug.print("could not run runar-zig: {s}\n", .{@errorName(err)});
        return error.CompilerBinaryMissing;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| try std.testing.expect(code != 0),
        else => return error.CompilerAbnormalExit,
    }
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "unsupported format") != null);
    // `main.zig`'s `compile` subcommand catch block prints `error: {s}` with
    // `@errorName(err)` on top of `compileFromSource`'s own prose line, so
    // the error NAME (not just the prose) is in stderr too. Pinning this is
    // what makes the two tests in this file assert the same error CLASS.
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "UnsupportedFormat") != null);
}

test "F-230: library compileSource must refuse the same unknown extension the CLI refuses" {
    const allocator = std.testing.allocator;

    // Before the fix: this SUCCEEDS (the `.unknown` branch falls back to
    // `parseZig`, which happily accepts VAULT_ZIG_SOURCE), diverging from the
    // CLI assertion above. After the fix: it must return exactly
    // `error.UnsupportedFormat` — the same class the CLI's `compile`
    // subcommand returns for its own `.unknown` case — not merely "some
    // error" (which `ParseFailed` would also satisfy, despite telling a
    // caller the wrong thing: that the source itself was invalid Rúnar,
    // which was never evaluated).
    try std.testing.expectError(
        error.UnsupportedFormat,
        compiler_api.compileSource(allocator, VAULT_ZIG_SOURCE, UNKNOWN_FILE_NAME),
    );
}

test "F-230 control: the SAME bytes, named Vault.runar.zig, compile successfully" {
    // Pins the refusal above to the file name's extension, not to
    // VAULT_ZIG_SOURCE's content — without this control, the first test
    // would also pass if the fix had instead broken Zig-format parsing in
    // general (e.g. by making `.unknown` accidentally shadow `.runar_zig`).
    const allocator = std.testing.allocator;
    const result = try compiler_api.compileSource(allocator, VAULT_ZIG_SOURCE, "Vault.runar.zig");
    defer result.deinit(allocator);
    try std.testing.expect(result.script_hex.len > 0);
}
