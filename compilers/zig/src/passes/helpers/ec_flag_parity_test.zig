//! Cross-tier parity for the EXPERIMENTAL EC size flags.
//!
//! The flags default off, so the ordinary conformance suite — which compiles
//! with defaults — cannot see them at all. Seven tiers could each ship a
//! DIFFERENT `--ec-constant-pool` and the suite would stay green.
//!
//! That matters because the flags are not cosmetic: they change which reduction
//! form is emitted and which addition formula each ladder round uses. A tier
//! that ports the constant pool but not the sign lattice's `.reduced`
//! precondition produces a script that is smaller, passes its own tests, and is
//! wrong on `ecAdd((0,1), (2^256-1,1))`. Byte-identical output against a single
//! reference is the only cheap check that catches that.
//!
//! WHAT THIS TIER COMPARES, AND WHY IT IS NOT THE HASH. The other six tiers
//! reproduce the reference's RAW emitter output op for op, so they assert its
//! SHA-256. This tier cannot, in exactly one place: `emitEcMul` emits `k + 3n`
//! pre-folded, because this peephole reassociates only i64 `push_int` chains
//! (peephole.zig rule 27) and a 256-bit constant is a `push_data` blob here.
//! The reference emits three `+n` steps that its own peephole collapses to the
//! same thing. Same shipped bytes, different pre-peephole spelling.
//!
//! So the gate here is the raw BYTE COUNT against the fixture, with that one
//! divergence asserted EXACTLY rather than waved through — if it ever widens,
//! or appears anywhere else, this test fails. The whole-script byte identity is
//! then covered end to end by compiling the same contract through this CLI and
//! the TypeScript one and diffing the hex.

const std = @import("std");
const testing = std.testing;
const ec = @import("ec_emitters.zig");
const cost_model = @import("ec_cost_model.zig");
const registry = @import("crypto_builtins.zig");

const Variant = struct { name: []const u8, opts: ec.EcCodegenOptions };

const VARIANTS = [_]Variant{
    .{ .name = "off", .opts = .{} },
    .{ .name = "pool", .opts = .{ .constant_pool = true } },
    .{ .name = "sink", .opts = .{ .constant_pool = true, .reduction_sinking = true } },
    .{ .name = "comb", .opts = .{
        .constant_pool = true,
        .reduction_sinking = true,
        .fixed_base_comb = true,
    } },
};

const Case = struct { name: []const u8, builtin: registry.CryptoBuiltin };

const CASES = [_]Case{
    .{ .name = "EcAdd", .builtin = .ec_add },
    .{ .name = "EcMul", .builtin = .ec_mul },
    .{ .name = "EcMulGen", .builtin = .ec_mul_gen },
    .{ .name = "EcNegate", .builtin = .ec_negate },
    .{ .name = "EcOnCurve", .builtin = .ec_on_curve },
};

/// The single documented divergence: `EcMul` / `EcMulGen` under `off` are 70
/// bytes shorter than the reference's raw output, because `k + 3n` is emitted
/// pre-folded here (see the module doc). Anything else must match exactly.
fn allowedDelta(name: []const u8, variant: []const u8) i64 {
    if (!std.mem.eql(u8, variant, "off")) return 0;
    if (std.mem.eql(u8, name, "EcMul") or std.mem.eql(u8, name, "EcMulGen")) return -70;
    return 0;
}

fn fixtureBytes(json: []const u8, emitter: []const u8, variant: []const u8) !i64 {
    // Anchored on the emitter's key so `EcMul` cannot match inside `EcMulGen`.
    var key_buf: [64]u8 = undefined;
    const ekey = try std.fmt.bufPrint(&key_buf, "\"{s}\": {{", .{emitter});
    const at = std.mem.indexOf(u8, json, ekey) orelse return error.EmitterMissing;
    var vbuf: [32]u8 = undefined;
    const vkey = try std.fmt.bufPrint(&vbuf, "\"{s}\": {{", .{variant});
    const vat = (std.mem.indexOf(u8, json[at..], vkey) orelse return error.VariantMissing) + at;
    const bat = (std.mem.indexOf(u8, json[vat..], "\"bytes\":") orelse
        return error.BytesMissing) + vat + "\"bytes\":".len;
    var end = bat;
    while (end < json.len and json[end] != ',') : (end += 1) {}
    return std.fmt.parseInt(i64, std.mem.trim(u8, json[bat..end], " \n\r\t"), 10);
}

fn readFixture(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(
        io,
        "../../conformance/ec-flag-parity/expected.json",
        allocator,
        .limited(1 << 20),
    );
}

test "EC flag parity against the TypeScript reference" {
    const allocator = testing.allocator;
    const json = try readFixture(allocator, std.testing.io);
    defer allocator.free(json);

    for (CASES) |c| {
        for (VARIANTS) |v| {
            var bundle = try ec.buildBuiltinOpsOpts(allocator, c.builtin, v.opts);
            defer bundle.deinit();
            const got: i64 = @intCast(cost_model.estimateScriptBytes(bundle.ops));
            const want = try fixtureBytes(json, c.name, v.name);
            const expected = want + allowedDelta(c.name, v.name);
            if (got != expected) {
                std.debug.print(
                    "{s} under {s}: Zig emits {d} bytes, expected {d} (reference {d})\n",
                    .{ c.name, v.name, got, expected, want },
                );
                return error.ParityMismatch;
            }
        }
    }
}

test "the flags default off byte-identically" {
    const allocator = testing.allocator;
    const json = try readFixture(allocator, std.testing.io);
    defer allocator.free(json);

    // An all-false options value must reproduce what the tier ships today. This
    // is what keeps the existing goldens, the size baseline and every cross-tier
    // hex comparison from moving while the flags are experimental.
    for (CASES) |c| {
        var a = try ec.buildBuiltinOps(allocator, c.builtin);
        defer a.deinit();
        var b = try ec.buildBuiltinOpsOpts(allocator, c.builtin, .{});
        defer b.deinit();
        try testing.expectEqual(
            cost_model.estimateScriptBytes(a.ops),
            cost_model.estimateScriptBytes(b.ops),
        );
    }
}

test "the fixture is non-vacuous" {
    const allocator = testing.allocator;
    const json = try readFixture(allocator, std.testing.io);
    defer allocator.free(json);

    // A fixture where every variant had the same size would pass in a tier that
    // ignored the flags entirely.
    try testing.expect(
        try fixtureBytes(json, "EcMul", "pool") < try fixtureBytes(json, "EcMul", "off"),
    );
    try testing.expect(
        try fixtureBytes(json, "EcMul", "sink") < try fixtureBytes(json, "EcMul", "pool"),
    );
    try testing.expect(
        try fixtureBytes(json, "EcMulGen", "comb") < try fixtureBytes(json, "EcMulGen", "sink"),
    );
    // `ecMul` takes its base at run time, so the comb cannot apply there.
    try testing.expectEqual(
        try fixtureBytes(json, "EcMul", "sink"),
        try fixtureBytes(json, "EcMul", "comb"),
    );
}

test "the comb agrees with the reference on the chosen window width" {
    // w is not hardcoded: the emitter renders w in {2,3,4} and keeps the
    // smallest. If this tier's cost model scored a different winner than the
    // reference's, `EcMulGen/comb` above would already differ — this pins the
    // reason, so a future change to the candidate set fails here with a clear
    // message rather than as an opaque byte count.
    const allocator = testing.allocator;
    var best_w: usize = 0;
    var best: usize = std.math.maxInt(usize);
    for ([_]usize{ 2, 3, 4 }) |w| {
        var probe = try ec.buildCombProbeForTest(allocator, w);
        defer probe.deinit();
        const bytes = cost_model.estimateScriptBytes(probe.ops);
        if (bytes < best) {
            best = bytes;
            best_w = w;
        }
    }
    try testing.expectEqual(@as(usize, 3), best_w);
}
