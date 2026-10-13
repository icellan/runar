//! N-173: pins the exact panic text of the length-gated runtime builtins in
//! builtins.zig (sha256Compress, sha256Finalize, blake3Compress, blake3Hash,
//! ecPointX, ecPointY) against the shared "<prefix>, got <N>" diagnostic
//! convention every other tier's mock-crypto implementation uses for the
//! same checks: packages/runar-testing/src/interpreter/interpreter.ts,
//! packages/runar-py/runar/builtins.py, and
//! packages/runar-java/.../runtime/MockCrypto.java for the sha256/blake3
//! texts; packages/runar-lang/src/runtime/builtins.ts's `ecDecode` for the
//! "EC point must be 64 bytes" text ecPointX/ecPointY share.
//!
//! A Zig `@panic` aborts the whole process, so it cannot be caught
//! in-process (same documented limitation as builtins_n111_ec_gates_test.zig
//! and builtins_n171_substr_onchain_test.zig's abort vectors). This test
//! instead spawns `zig-out/bin/runar-n173-panic-probe` (built by build.zig;
//! source in builtins_n173_panic_probe.zig) with a case name as argv[1] and
//! checks its stderr and termination.
//!
//! Proves: for the 7 length-mismatch panics named above, a bad-length operand
//! aborts the process and the printed text contains the exact shared
//! diagnostic, independently hardcoded here (not derived from builtins.zig),
//! plus a control case proving the probe itself does not panic on a
//! valid-length call.
//! Does NOT prove: that these are the only call sites needing the suffix —
//! sha256Finalize's "total bit length must be non-negative" check has no
//! shared counterpart in any other tier and is deliberately left unchanged;
//! the on-chain script's behavior (the conformance suite's job, untouched by
//! this item); any tier other than Zig.

const std = @import("std");

const Case = struct {
    arg: []const u8,
    expected: []const u8,
};

const cases = [_]Case{
    .{ .arg = "sha256Compress-state", .expected = "sha256Compress: state must be 32 bytes, got 31" },
    .{ .arg = "sha256Compress-block", .expected = "sha256Compress: block must be 64 bytes, got 63" },
    .{ .arg = "sha256Finalize-state", .expected = "sha256Finalize: state must be 32 bytes, got 31" },
    .{ .arg = "sha256Finalize-remaining", .expected = "sha256Finalize: remaining must be 0-119 bytes, got 120" },
    .{ .arg = "blake3Compress-chaining", .expected = "blake3Compress: chaining value must be 32 bytes, got 31" },
    .{ .arg = "blake3Compress-block", .expected = "blake3Compress: block must be 64 bytes, got 63" },
    .{ .arg = "blake3Hash-message", .expected = "blake3Hash: message must be <= 64 bytes, got 65" },
    .{ .arg = "ecPointX", .expected = "ecPointX: EC point must be 64 bytes, got 63" },
    .{ .arg = "ecPointY", .expected = "ecPointY: EC point must be 64 bytes, got 63" },
};

test "N-173: Zig runtime builtin panics carry the shared 'prefix, got N' diagnostic text" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    for (cases) |case| {
        const result = try std.process.run(allocator, io, .{
            .argv = &.{ "zig-out/bin/runar-n173-panic-probe", case.arg },
            .stderr_limit = .limited(1024 * 1024),
            .stdout_limit = .limited(64 * 1024),
        });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        // A panic aborts the process; it must never reach a clean `.exited`.
        switch (result.term) {
            .exited => |code| {
                std.debug.print(
                    "case {s}: probe exited cleanly (code {d}) instead of panicking; stderr: {s}\n",
                    .{ case.arg, code, result.stderr },
                );
                return error.ProbeDidNotPanic;
            },
            else => {},
        }

        if (std.mem.indexOf(u8, result.stderr, case.expected) == null) {
            std.debug.print(
                "case {s}: expected stderr to contain \"{s}\", got: {s}\n",
                .{ case.arg, case.expected, result.stderr },
            );
            return error.PanicTextMismatch;
        }
    }
}

test "N-173: control -- valid-length operands do not panic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const result = try std.process.run(allocator, io, .{
        .argv = &.{ "zig-out/bin/runar-n173-panic-probe", "ok" },
        .stderr_limit = .limited(1024 * 1024),
        .stdout_limit = .limited(64 * 1024),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        else => {
            std.debug.print("control case aborted unexpectedly; stderr: {s}\n", .{result.stderr});
            return error.ProbeControlCaseAborted;
        },
    }
}
