//! N-034 — the Zig EC optimizer's constant-fusing rules (9, 10, 11).
//!
//! Two defects in the same function family, both externally visible:
//!
//!   A  `freshConstName` registered the folded scalar in the optimizer's value
//!      map and NOWHERE else. The rewritten call then referenced a name that
//!      had no binding in the method body, and stack lowering died with
//!      `VariableNotFound` / `error.StackLowerFailed`. Zig could not compile a
//!      contract that the other six tiers compile — an availability defect,
//!      reproducible with scalars as small as 5n and 7n.
//!
//!   B  `freshConstName` took an `i128`, and `isConstInt` / `getConstInt`
//!      matched only `ConstValue.integer`. A real secp256k1 scalar exceeds
//!      `i128` and therefore arrives as `ConstValue.big_integer`
//!      (ir/types.zig), so every rule keyed on a constant scalar silently
//!      declined and Zig emitted the unfused script — a MISCOMPILE, not an
//!      availability bug: a different locking script from the other six tiers,
//!      with no diagnostic.
//!
//! The expectations below are cross-tier parity pins, not self-attested Zig
//! goldens: every length/sha256 was measured by replaying the same source
//! through the shipping ts / go / rust / java / python / ruby CLIs, all six of
//! which agree byte-for-byte.
//!
//! The operands MUST be written inline. `const a = ecMulGen(k)` lowers to an
//! `@ref:` alias binding that no tier's matcher resolves through, so the rule
//! declines in EVERY tier and a probe in that shape proves nothing. Likewise a
//! probe with no EC call at all makes `optimize()` return early, so every
//! assertion in it passes against a broken compiler — hence the two controls
//! at the bottom, which pin the untouched paths, and the ANF-level tests,
//! which prove the fusing rule actually fired.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const types = @import("../ir/types.zig");

// ---------------------------------------------------------------------------
// Probe sources
// ---------------------------------------------------------------------------

/// Rule 10: ecAdd(ecMulGen(5), ecMulGen(7)) -> ecMulGen(12).
/// Small scalars: both fit `i128`, so this isolates defect A.
const SRC_SMALL =
    \\import { SmartContract, assert, ecAdd, ecMulGen, ecOnCurve } from 'runar-lang';
    \\
    \\class ECLinear extends SmartContract {
    \\    constructor() {
    \\        super();
    \\    }
    \\
    \\    public spend(a: bigint, b: bigint) {
    \\        assert(ecOnCurve(ecAdd(ecMulGen(5n), ecMulGen(7n))));
    \\    }
    \\}
;

/// Rule 10 with scalars just below the group order: (n-7) + (n-6) mod n = n-13.
/// Both operands and the fold result exceed `i128`, so this isolates defect B.
const SRC_BIG =
    \\import { SmartContract, assert, ecAdd, ecMulGen, ecOnCurve } from 'runar-lang';
    \\
    \\class ECBig extends SmartContract {
    \\    constructor() {
    \\        super();
    \\    }
    \\
    \\    public spend(a: bigint, b: bigint) {
    \\        assert(ecOnCurve(ecAdd(ecMulGen(115792089237316195423570985008687907852837564279074904382605163141518161494330n), ecMulGen(115792089237316195423570985008687907852837564279074904382605163141518161494331n))));
    \\    }
    \\}
;

/// Control: an EC contract that ARMS the optimizer (so it does not return
/// early) but where no fusing rule fires. Its bytes must not move.
const SRC_EC_NO_FUSION =
    \\import { SmartContract, assert, ecMulGen, ecOnCurve } from 'runar-lang';
    \\
    \\class ECCtl extends SmartContract {
    \\    constructor() {
    \\        super();
    \\    }
    \\
    \\    public spend(a: bigint, b: bigint) {
    \\        assert(ecOnCurve(ecMulGen(5n)));
    \\    }
    \\}
;

/// Control: no EC calls at all — `optimize()` returns the program unchanged.
const SRC_NO_EC =
    \\import { SmartContract, ByteString, PubKey, Sig, assert, hash160, checkSig } from 'runar-lang';
    \\
    \\class NoEc extends SmartContract {
    \\    readonly pubKeyHash: ByteString;
    \\
    \\    constructor(pubKeyHash: ByteString) {
    \\        super(pubKeyHash);
    \\        this.pubKeyHash = pubKeyHash;
    \\    }
    \\
    \\    public unlock(sig: Sig, pubkey: PubKey) {
    \\        assert(hash160(pubkey) == this.pubKeyHash);
    \\        assert(checkSig(sig, pubkey));
    \\    }
    \\}
;

/// (n-7) + (n-6) mod n, in canonical decimal — what rule 10 must fold to.
const FOLDED_BIG_DECIMAL =
    "115792089237316195423570985008687907852837564279074904382605163141518161494324";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    var out: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{x}", .{&digest}) catch unreachable;
    return out;
}

/// Compile to locking-script hex and assert length + sha256 against the
/// six-tier reference.
fn expectHexDigest(
    comptime source: []const u8,
    comptime file_name: []const u8,
    expected_len: usize,
    expected_sha256: []const u8,
) !void {
    const hex = try compiler_api.compileSourceToHex(std.testing.allocator, source, file_name);
    defer std.testing.allocator.free(hex);
    try std.testing.expectEqual(expected_len, hex.len);
    try std.testing.expectEqualStrings(expected_sha256, &sha256Hex(hex));
}

/// Run the pipeline as far as the optimized ANF and hand the caller the
/// public method's body.
fn withOptimizedBody(
    comptime source: []const u8,
    comptime file_name: []const u8,
    check: *const fn (body: []const types.ANFBinding) anyerror!void,
) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diag: compiler_api.Diagnostics = .{};
    const pipeline = try compiler_api.runPipeline(
        arena.allocator(),
        source,
        file_name,
        .{ .stop_after = .anf },
        &diag,
    );
    const program = pipeline.program orelse return error.NoProgram;
    for (program.methods) |method| {
        if (std.mem.eql(u8, method.name, "spend")) return check(method.body);
    }
    return error.MethodNotFound;
}

/// Find the sole argument of the (single) `ecMulGen` call that a fusing rule
/// rewrote — i.e. the one whose argument is NOT one of the original literals.
fn foldedScalarBinding(body: []const types.ANFBinding) ?types.ANFBinding {
    // The rewritten binding is the last ecMulGen in the body: rules 9-11
    // rewrite in place and leave the (now side-effecting, hence DCE-immune)
    // operand calls ahead of it.
    var scalar_name: ?[]const u8 = null;
    for (body) |binding| {
        switch (binding.value) {
            .call => |c| {
                if (std.mem.eql(u8, c.func, "ecMulGen") and c.args.len == 1) {
                    scalar_name = c.args[0];
                }
            },
            else => {},
        }
    }
    const name = scalar_name orelse return null;
    for (body) |binding| {
        if (std.mem.eql(u8, binding.name, name)) return binding;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Defect A — the folded constant must be bound in the method body
// ---------------------------------------------------------------------------

test "N-034 A: a contract where an EC fusing rule fires compiles at all" {
    // Before the fix: error.StackLowerFailed, diagnostic
    // "stack lowering error: VariableNotFound" — the rewritten ecMulGen
    // referenced `__ec_opt_1`, which was never bound.
    const hex = try compiler_api.compileSourceToHex(
        std.testing.allocator,
        SRC_SMALL,
        "ECLinear.runar.ts",
    );
    defer std.testing.allocator.free(hex);
    try std.testing.expect(hex.len > 0);
}

test "N-034 A: rule 10 binds the folded scalar into the method body" {
    const check = struct {
        fn f(body: []const types.ANFBinding) anyerror!void {
            const binding = foldedScalarBinding(body) orelse return error.NoEcMulGenFound;
            switch (binding.value) {
                .load_const => |lc| switch (lc.value) {
                    .integer => |i| try std.testing.expectEqual(@as(i128, 12), i),
                    else => return error.FoldedScalarNotAnInteger,
                },
                // Before the fix the fresh name resolved to nothing at all, so
                // the lookup above returns null and the test errors out with
                // NoEcMulGenFound / a stale operand binding.
                else => return error.FoldedScalarNotBound,
            }
        }
    }.f;
    try withOptimizedBody(SRC_SMALL, "ECLinear.runar.ts", check);
}

test "N-034 A: fused small-scalar hex matches the six-tier reference" {
    // ts / go / rust / java / python / ruby, byte-identical.
    try expectHexDigest(
        SRC_SMALL,
        "ECLinear.runar.ts",
        2548856,
        "efcff80d2f183358a0a9803fff7766a65c36de6d4db22e72a68db46d2efefcf7",
    );
}

// ---------------------------------------------------------------------------
// Defect B — a folded scalar past i128 must still fold
// ---------------------------------------------------------------------------

test "N-034 B: rule 10 folds scalars that exceed i128" {
    const check = struct {
        fn f(body: []const types.ANFBinding) anyerror!void {
            const binding = foldedScalarBinding(body) orelse return error.NoEcMulGenFound;
            switch (binding.value) {
                .load_const => |lc| switch (lc.value) {
                    .big_integer => |s| try std.testing.expectEqualStrings(FOLDED_BIG_DECIMAL, s),
                    // Before the fix `getConstInt` saw `.big_integer` and
                    // returned null, so rule 10 declined and the ecMulGen
                    // argument is still one of the two source literals.
                    else => return error.FoldedScalarNotABigInteger,
                },
                else => return error.FoldedScalarNotBound,
            }
        }
    }.f;
    try withOptimizedBody(SRC_BIG, "ECBig.runar.ts", check);
}

test "N-034 B: fused oversize-scalar hex matches the six-tier reference" {
    // ts / go / rust / java / python / ruby, byte-identical. Before the fix
    // Zig emitted 1748648 chars (sha 9391969994f3b865…) — the unfused script.
    try expectHexDigest(
        SRC_BIG,
        "ECBig.runar.ts",
        2549054,
        "463305e40283e6097253d609296c0e42d0a634d2e5ef0dcde7874d0d3a2a2339",
    );
}

// ---------------------------------------------------------------------------
// Controls — the fix must not be satisfiable by disabling the optimizer
// ---------------------------------------------------------------------------

test "N-034 control: EC contract with no fusible pair is byte-unchanged" {
    // Arms the optimizer (an EC call is present, so `optimize` does not return
    // early) but no rule fires. Six-tier reference.
    try expectHexDigest(
        SRC_EC_NO_FUSION,
        "ECCtl.runar.ts",
        850588,
        "9219589a0856da1bdaaf128317cae254da084995e4d2f58459f274b8b277c317",
    );
}

test "N-034 control: contract with no EC calls is byte-unchanged" {
    const hex = try compiler_api.compileSourceToHex(
        std.testing.allocator,
        SRC_NO_EC,
        "NoEc.runar.ts",
    );
    defer std.testing.allocator.free(hex);
    try std.testing.expectEqualStrings("76a90088ac", hex);
}
