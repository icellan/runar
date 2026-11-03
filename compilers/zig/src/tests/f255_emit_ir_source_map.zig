//! F-255: `--emit-ir` silently dropped `--emit-source-map`, exiting 0
//! having written nothing.
//!
//! The `--emit-ir` branch in `main.zig` wrote the canonical IR JSON to
//! stdout and `return`ed unconditionally — and `stop_after` was hardcoded to
//! `.anf` whenever `--emit-ir` was set, so the pipeline never ran stack
//! lowering at all, leaving `pipeline.stack_program` null. Either way,
//! `--source X --emit-ir --emit-source-map Y` exited 0 and Y was never
//! created — the request was silently dropped, not refused. Go had the
//! identical bug (F-183) and Java was always correct ("GAP-002:
//! --emit-source-map ... runs INDEPENDENTLY of --emit-ir"); this ports Go's
//! fix (run the full pipeline when a source map was also requested, write
//! the source map, THEN stop before the hex/artifact output) to the Zig
//! tier.
//!
//! What this test proves: the built `runar-zig` binary, given `--emit-ir`
//! together with `--emit-source-map <path>`, exits 0, writes a
//! `{"mappings": [...]}` file to `<path>`, and prints ONLY the IR JSON on
//! stdout (no `"script"` field — `--emit-ir`'s contract is "stdout carries
//! only the IR").
//! What it does not prove: the two flags combined with `--hex` (a separate,
//! pre-existing gap: `--hex` returns before the source-map block runs at
//! all — out of scope for F-255); any other tier's CLI; the `compile-ir`
//! subcommand form.
//!
//! The binary is resolved via `RUNAR_ZIG_BIN`, falling back to
//! `zig-out/bin/runar-zig` relative to CWD (`compilers/zig`), matching
//! `library_cli_parity.zig` / `n119_ir_cli_clean_stderr.zig`.

const std = @import("std");
const testing = std.testing;

fn resolveZigBinary() []const u8 {
    if (std.testing.environ.getPosix("RUNAR_ZIG_BIN")) |bin| return bin;
    return "zig-out/bin/runar-zig";
}

test "--emit-ir with --emit-source-map writes the source map and prints only IR" {
    const allocator = testing.allocator;
    const io = testing.io;

    const source_path = "../../examples/zig/p2pkh/P2PKH.runar.zig";
    const sm_dir = "zig-out/f255-tmp";
    std.Io.Dir.cwd().createDirPath(io, sm_dir) catch {};
    const sm_path = sm_dir ++ "/source-map.json";
    // Sanity: must not pre-exist from a previous run.
    std.Io.Dir.cwd().deleteFile(io, sm_path) catch {};

    const result = std.process.run(allocator, io, .{
        .argv = &.{
            resolveZigBinary(),
            "--source",
            source_path,
            "--emit-ir",
            "--emit-source-map",
            sm_path,
        },
        .stdout_limit = .limited(10 * 1024 * 1024),
    }) catch |err| {
        std.debug.print("could not run runar-zig: {s}\n", .{@errorName(err)});
        return error.CompilerBinaryMissing;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                std.debug.print(
                    "--emit-ir --emit-source-map must exit 0, got {d}\nstdout: {s}\nstderr: {s}\n",
                    .{ code, result.stdout, result.stderr },
                );
                return error.CompilerExitNonZero;
            }
        },
        else => return error.CompilerAbnormalExit,
    }

    // The finding itself: the file must actually be written.
    var sm_file = std.Io.Dir.cwd().openFile(io, sm_path, .{}) catch {
        std.debug.print(
            "--emit-source-map file was never written (F-255 regression); stderr: {s}\n",
            .{result.stderr},
        );
        return error.SourceMapNotWritten;
    };
    defer sm_file.close(io);
    var read_buf: [8192]u8 = undefined;
    var reader = sm_file.reader(io, &read_buf);
    const sm_contents = try reader.interface.allocRemaining(allocator, .unlimited);
    defer allocator.free(sm_contents);

    if (std.mem.indexOf(u8, sm_contents, "\"mappings\"") == null) {
        std.debug.print("source map JSON must carry a \"mappings\" key, got: {s}\n", .{sm_contents});
        return error.MissingMappingsKey;
    }

    // --emit-ir's contract: stdout carries only the IR, never the full
    // artifact (which would carry a "script" field).
    if (std.mem.indexOf(u8, result.stdout, "\"contractName\"") == null) {
        std.debug.print("stdout must be ANF IR (expected a contractName field), got: {s}\n", .{result.stdout});
        return error.MissingContractName;
    }
    if (std.mem.indexOf(u8, result.stdout, "\"script\"") != null) {
        std.debug.print("stdout must carry ONLY the IR, not the compiled artifact; got: {s}\n", .{result.stdout});
        return error.StdoutLeakedArtifact;
    }
}
