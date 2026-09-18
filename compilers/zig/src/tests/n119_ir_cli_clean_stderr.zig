//! N-119 — a successful `compile-ir` run must write nothing to stderr.
//!
//! `compileFromIR` allocated the whole parsed ANF graph from the process
//! allocator and relied on `ANFProgram.deinit` to give it back.
//! `deinit`/`freeBindings` (ir/types.zig) free the `if` / `loop` heap nodes and
//! recurse into their bodies — and nothing else. The 43 `allocator.dupe` sites
//! in `ir/json.zig` (every binding name, param name, operator, iterVar, const
//! byte string) and every binding ARRAY were never returned, so in a Debug
//! build the DebugAllocator reported them all at exit.
//!
//! Measured on `conformance/tests/bounded-loop/expected-ir.json` — a
//! 3.2 KB fixture with four bindings:
//!
//!     exit 0, stdout correct, stderr 55 leak reports / 1145 lines
//!
//! Exit status and emitted bytes were always right, so this is hygiene, not a
//! correctness bug — LOW. What makes it worth fixing is that the noise is on
//! the SAME channel a caller reads results from, and it is 1145 lines deep: a
//! `tail -1` over combined output reads the tail of a leak trace instead of the
//! script, which is exactly how one measurement in this audit was recorded
//! wrong before its control caught it. A tool whose success output is buried
//! under a kilo-line of its own diagnostics is a tool that gets misread.
//!
//! Why an arena rather than completing `deinit`: the parser has no ownership
//! discipline to complete. It mixes owned dupes with borrowed slices of the
//! still-live `std.json` document, across a ~25-variant union, at 43 sites — a
//! uniform free would double-free or free borrowed memory, turning stderr noise
//! into a crash. And the arena is already this codebase's answer to the same
//! question: `compileFromSource` runs its entire pipeline in one
//! (`main.zig`), and every in-tree caller of `parseANFProgram` wraps one.
//! `compileFromIR` was the single outlier. See Rule 6 — pick the established
//! pattern, do not average.
//!
//! The assertion is on the CLI, not on the allocator, because the CLI is where
//! the contract lives: a caller reads stdout and stderr, not a leak checker.

const std = @import("std");
const testing = std.testing;

/// The checked-in golden used as the control: all six IR-capable tiers accept
/// it and emit these exact bytes. Pinned so this test cannot pass by the CLI
/// silently producing nothing at all.
const FIXTURE = "../../conformance/tests/bounded-loop/expected-ir.json";
const EXPECTED_HEX =
    "000052797b7c937c935152797b7c937c935252797b7c937c935352797b7c937c93547b7b7c937c93009c";

fn runCompileIr(allocator: std.mem.Allocator, io: std.Io) !std.process.RunResult {
    const bin = std.testing.environ.getPosix("RUNAR_ZIG_BIN") orelse "zig-out/bin/runar-zig";
    return std.process.run(allocator, io, .{
        .argv = &.{ bin, "compile-ir", FIXTURE, "--hex" },
        .stdout_limit = .limited(10 * 1024 * 1024),
    });
}

test "compile-ir emits the script on stdout and NOTHING on stderr" {
    const allocator = testing.allocator;
    const io = testing.io;

    const result = runCompileIr(allocator, io) catch |err| {
        // A missing binary is not a pass. `zig build test` depends on the
        // install step precisely so this cannot happen silently.
        std.debug.print("could not run runar-zig: {s}\n", .{@errorName(err)});
        return error.CompilerBinaryMissing;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // Control first: the run must have SUCCEEDED and produced the golden
    // bytes. A test that only asserted "stderr is empty" would pass for a
    // binary that refused the input outright.
    try testing.expectEqual(@as(u8, 0), result.term.exited);
    try testing.expectEqualStrings(EXPECTED_HEX, std.mem.trim(u8, result.stdout, " \r\n\t"));

    // The finding itself.
    if (result.stderr.len != 0) {
        std.debug.print(
            "compile-ir wrote {d} bytes to stderr on a SUCCESSFUL run:\n{s}\n",
            .{ result.stderr.len, result.stderr[0..@min(result.stderr.len, 800)] },
        );
        return error.UnexpectedStderrOutput;
    }
}
