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
//! SHA-256. This tier cannot, in two places, both of them differences in
//! SPELLING that its own peephole normalises away before the script ships:
//!
//!   1. `k + 3n`. Every binary ladder emits it pre-folded, because this
//!      peephole reassociates only i64 `push_int` chains (peephole.zig rule 27)
//!      and a 256/384-bit constant is a `push_data` blob here. The reference
//!      emits three `+n` steps that its own peephole collapses to the same
//!      thing. On secp256k1 the reference pools those pushes, so this tier
//!      matches raw-for-raw whenever the pool is on; on the NIST curves it uses
//!      raw literals under every variant, so the divergence is constant there.
//!   2. `push [0x02]` / `push [0x03]`. The reference applies MINIMALDATA and
//!      writes `OP_2` / `OP_3`; this tier's push encoder always writes the
//!      length-prefixed blob. Pre-existing and flag-independent — it is there
//!      with every flag off, on emitters no flag reaches.
//!
//! So the gate here is the raw BYTE COUNT against the fixture, with both
//! divergences priced EXACTLY rather than waved through — if either widens, or
//! appears on an emitter it does not name, this test fails. The whole-script
//! byte identity is then covered end to end by compiling the same contract
//! through this CLI and the TypeScript one and diffing the hex.

const std = @import("std");
const testing = std.testing;
const ec = @import("ec_emitters.zig");
const nist = @import("nist_ec_emitters.zig");
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

const NIST_CASES = [_]Case{
    .{ .name = "P256Add", .builtin = .p256_add },
    .{ .name = "P256Mul", .builtin = .p256_mul },
    .{ .name = "P256MulGen", .builtin = .p256_mul_gen },
    .{ .name = "P256Negate", .builtin = .p256_negate },
    .{ .name = "P256OnCurve", .builtin = .p256_on_curve },
    .{ .name = "P256EncodeCompressed", .builtin = .p256_encode_compressed },
    .{ .name = "VerifyECDSA_P256", .builtin = .verify_ecdsa_p256 },
    .{ .name = "P384Add", .builtin = .p384_add },
    .{ .name = "P384Mul", .builtin = .p384_mul },
    .{ .name = "P384MulGen", .builtin = .p384_mul_gen },
    .{ .name = "P384Negate", .builtin = .p384_negate },
    .{ .name = "P384OnCurve", .builtin = .p384_on_curve },
    .{ .name = "P384EncodeCompressed", .builtin = .p384_encode_compressed },
    .{ .name = "VerifyECDSA_P384", .builtin = .verify_ecdsa_p384 },
};

// ---------------------------------------------------------------------------
// The documented divergences, priced exactly.
//
// Each is a difference in SPELLING, not in what the script computes: both are
// normalised away by this tier's peephole, so the shipped hex still matches the
// reference byte for byte. They are stated as exact per-emitter numbers rather
// than a tolerance so that a divergence which widens, or appears on an emitter
// that had none, fails here.
// ---------------------------------------------------------------------------

/// Bytes the reference's raw output carries that this tier's does not, per
/// BINARY LADDER, from `k + 3n`.
///
/// The reference pushes `n` three times and adds three times, and lets its
/// peephole reassociate that to `push 3n; OP_ADD`. This tier's peephole folds
/// only i64 `push_int` chains (peephole.zig rule 27) and a 256/384-bit constant
/// is a `push_data` blob here, so it pre-folds instead. secp256k1's `n` and
/// P-256's both encode to 33 bytes, so the arithmetic is the same there:
/// 3*(1 + 33) + 3 == 105 against (1 + 33) + 1 == 35.
const P256_THREE_N: i64 = -70;
/// P-384's `n` encodes to 49 bytes: 3*(1 + 49) + 3 == 153 against 51.
const P384_THREE_N: i64 = -102;

/// A `push` of a one-byte blob whose value is 1..16.
///
/// The reference applies MINIMALDATA and spells `push [0x02]` as `OP_2`, one
/// byte; this tier's push encoder always writes the length-prefixed form, two.
/// Two such pushes per site — the `0x02` / `0x03` prefix pair — so `+2`.
///
/// PRE-EXISTING and flag-independent: it is already there with every flag off,
/// on emitters (`p256EncodeCompressed`) that no flag reaches at all.
const MINIMAL_PUSH_PAIR: i64 = 2;

/// How many binary ladders this emitter runs under this variant.
///
/// `p256Mul` / `p384Mul` take their base at run time, so no flag can turn their
/// ladder into a comb. `verifyECDSA` runs two — `u1*G`, whose base IS a
/// constant, and `u2*Q`, whose is not — so the comb removes exactly one.
fn ladderCount(name: []const u8, variant: []const u8) i64 {
    const combing = std.mem.eql(u8, variant, "comb");
    if (std.mem.eql(u8, name, "EcMul") or
        std.mem.eql(u8, name, "P256Mul") or
        std.mem.eql(u8, name, "P384Mul")) return 1;
    if (std.mem.eql(u8, name, "EcMulGen") or
        std.mem.eql(u8, name, "P256MulGen") or
        std.mem.eql(u8, name, "P384MulGen")) return if (combing) 0 else 1;
    if (std.mem.eql(u8, name, "VerifyECDSA_P256") or
        std.mem.eql(u8, name, "VerifyECDSA_P384")) return if (combing) 1 else 2;
    return 0;
}

/// The exact expected difference from the reference, and ZERO for anything the
/// two divergences above do not name.
fn allowedDelta(name: []const u8, variant: []const u8) i64 {
    var delta: i64 = 0;

    // secp256k1 spells its `3n` with POOLED pushes in the reference, so this
    // tier matches it raw-for-raw as soon as the pool is on and diverges only
    // under `off`. The NIST reference uses raw literals under every variant, so
    // its divergence is constant. Do not merge these two cases.
    if (std.mem.eql(u8, name, "EcMul") or std.mem.eql(u8, name, "EcMulGen")) {
        if (std.mem.eql(u8, variant, "off")) delta += ladderCount(name, variant) * P256_THREE_N;
    } else if (std.mem.startsWith(u8, name, "P256") or
        std.mem.eql(u8, name, "VerifyECDSA_P256"))
    {
        delta += ladderCount(name, variant) * P256_THREE_N;
    } else if (std.mem.startsWith(u8, name, "P384") or
        std.mem.eql(u8, name, "VerifyECDSA_P384"))
    {
        delta += ladderCount(name, variant) * P384_THREE_N;
    }

    // The `0x02` / `0x03` prefix pair: `decompressPubKey`'s SEC1 check, and the
    // parity select in `pNNNEncodeCompressed`.
    if (std.mem.eql(u8, name, "P256EncodeCompressed") or
        std.mem.eql(u8, name, "P384EncodeCompressed") or
        std.mem.eql(u8, name, "VerifyECDSA_P256") or
        std.mem.eql(u8, name, "VerifyECDSA_P384")) delta += MINIMAL_PUSH_PAIR;

    return delta;
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

fn checkParity(json: []const u8, c: Case, v: Variant, bundle_ops: []const ec.StackOp) !void {
    const got: i64 = @intCast(cost_model.estimateScriptBytes(bundle_ops));
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

test "EC flag parity against the TypeScript reference" {
    const allocator = testing.allocator;
    const json = try readFixture(allocator, std.testing.io);
    defer allocator.free(json);

    for (CASES) |c| {
        for (VARIANTS) |v| {
            var bundle = try ec.buildBuiltinOpsOpts(allocator, c.builtin, v.opts);
            defer bundle.deinit();
            try checkParity(json, c, v, bundle.ops);
        }
    }
}

test "NIST curve flag parity against the TypeScript reference" {
    const allocator = testing.allocator;
    const json = try readFixture(allocator, std.testing.io);
    defer allocator.free(json);

    // An arena, not `testing.allocator`. `verifyECDSA_P384` under `off` is a
    // 2 MB script — nearly four million tracked ops — and 56 of these are built
    // here; the leak-checking allocator's per-allocation bookkeeping is what
    // dominates the runtime, not the emitters. Allocation discipline for these
    // same builtins is covered by the op-count goldens next door, which do run
    // on `testing.allocator`.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    for (NIST_CASES) |c| {
        for (VARIANTS) |v| {
            defer _ = arena.reset(.retain_capacity);
            var bundle = try nist.buildBuiltinOpsOpts(arena.allocator(), c.builtin, v.opts);
            defer bundle.deinit();
            try checkParity(json, c, v, bundle.ops);
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
    // Arena for the NIST half, for the reason the parity test above gives.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    for (NIST_CASES) |c| {
        defer _ = arena.reset(.retain_capacity);
        var a = try nist.buildBuiltinOps(arena.allocator(), c.builtin);
        defer a.deinit();
        var b = try nist.buildBuiltinOpsOpts(arena.allocator(), c.builtin, .{});
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

    for ([_][]const u8{ "P256", "P384" }) |curve| {
        var buf: [32]u8 = undefined;
        const mul = try std.fmt.bufPrint(&buf, "{s}Mul", .{curve});
        try testing.expect(try fixtureBytes(json, mul, "pool") < try fixtureBytes(json, mul, "off"));
        try testing.expect(try fixtureBytes(json, mul, "sink") < try fixtureBytes(json, mul, "pool"));
        // Same reason as `ecMul`: the base is an argument, not a constant.
        try testing.expectEqual(
            try fixtureBytes(json, mul, "sink"),
            try fixtureBytes(json, mul, "comb"),
        );
    }
    try testing.expect(
        try fixtureBytes(json, "P256MulGen", "comb") < try fixtureBytes(json, "P256MulGen", "sink"),
    );
    try testing.expect(
        try fixtureBytes(json, "P384MulGen", "comb") < try fixtureBytes(json, "P384MulGen", "sink"),
    );
    // Only the `u1*G` half combs, so the verifier shrinks but by much less than
    // a whole ladder — a tier that combed `u2*Q` too would be combing an
    // attacker-supplied base, which comb.zig's interval argument does not cover.
    try testing.expect(
        try fixtureBytes(json, "VerifyECDSA_P256", "comb") <
            try fixtureBytes(json, "VerifyECDSA_P256", "sink"),
    );
    try testing.expect(
        try fixtureBytes(json, "VerifyECDSA_P384", "comb") <
            try fixtureBytes(json, "VerifyECDSA_P384", "sink"),
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

test "the NIST comb paths do not leak" {
    // The parity tests above run on an arena, which cannot see a leak, and the
    // op-count goldens next door only exercise the DEFAULT path — so nothing
    // else runs the comb, the pooled slots or the verifier's transferred bundle
    // under a leak-checking allocator. The two cheapest emitters that reach all
    // three do it here.
    const allocator = testing.allocator;
    const opts = ec.EcCodegenOptions{
        .constant_pool = true,
        .reduction_sinking = true,
        .fixed_base_comb = true,
    };
    for ([_]registry.CryptoBuiltin{ .p256_mul_gen, .verify_ecdsa_p256 }) |b| {
        var bundle = try nist.buildBuiltinOpsOpts(allocator, b, opts);
        bundle.deinit();
    }
}

test "the NIST combs agree with the reference on the chosen window width" {
    // Same argument as the secp256k1 case above. Stated per curve because the
    // geometry search is per curve: P-256 at w=3 lands on the ladder's own +3n
    // offset, P-384 at w=3 needs +5n, and a tier that hardcoded the ladder's
    // offset would still pick w=3 while emitting a comb whose leading digit can
    // vanish.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    for ([_]bool{ false, true }) |p384| {
        var best_w: usize = 0;
        var best: usize = std.math.maxInt(usize);
        for ([_]usize{ 2, 3, 4 }) |w| {
            defer _ = arena.reset(.retain_capacity);
            var probe = try nist.buildCombProbeForTest(arena.allocator(), p384, w);
            defer probe.deinit();
            const bytes = cost_model.estimateScriptBytes(probe.ops);
            if (bytes < best) {
                best = bytes;
                best_w = w;
            }
        }
        try testing.expectEqual(@as(usize, 3), best_w);
    }
}
