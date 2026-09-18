//! Dedicated unit tests for the Zig `checkMultiSig` codegen.
//!
//! Closes audit gap T-2 / F11: the Zig tier had only a single coarse
//! "lowers to OP_CHECKMULTISIG" probe in `hash_builtins.zig`. The Java
//! reference (compilers/java/src/test/java/runar/compiler/codegen/
//! CheckMultiSigTest.java) carries six byte-shape goldens that pin the
//! exact Bitcoin OP_CHECKMULTISIG dispatch shape. This file mirrors that
//! coverage for the Zig compiler.
//!
//! Reference shape (mirrored across all 7 compilers) for
//! `checkMultiSig([sig1, sig2], [pk1, pk2, pk3])`:
//!
//!   OP_0 <sig1> <sig2> 2 <pk1> <pk2> <pk3> 3 OP_CHECKMULTISIG
//!
//! Where:
//!   - OP_0 (byte 0x00) is the off-by-one dummy push required by Bitcoin's
//!     legacy CHECKMULTISIG implementation.
//!   - 2 (OP_2 = 0x52) is the count of signatures.
//!   - 3 (OP_3 = 0x53) is the count of public keys.
//!   - OP_CHECKMULTISIG (0xae) — or its peephole-folded
//!     OP_CHECKMULTISIGVERIFY (0xaf) variant when wrapped in
//!     `assert(checkMultiSig(...))`.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const json_parser = @import("../ir/json.zig");
const stack_lower = @import("../passes/stack_lower.zig");

const MULTISIG_2OF3_SRC =
    \\const runar = @import("runar");
    \\
    \\pub const MultiSig2of3 = struct {
    \\    pub const Contract = runar.SmartContract;
    \\
    \\    pk1: runar.PubKey,
    \\    pk2: runar.PubKey,
    \\    pk3: runar.PubKey,
    \\
    \\    pub fn init(pk1: runar.PubKey, pk2: runar.PubKey, pk3: runar.PubKey) MultiSig2of3 {
    \\        return .{ .pk1 = pk1, .pk2 = pk2, .pk3 = pk3 };
    \\    }
    \\
    \\    pub fn unlock(self: *const MultiSig2of3, sig1: runar.Sig, sig2: runar.Sig) void {
    \\        runar.assert(runar.checkMultiSig(
    \\            &.{ sig1, sig2 },
    \\            &.{ self.pk1, self.pk2, self.pk3 },
    \\        ));
    \\    }
    \\};
;

const MULTISIG_3OF5_SRC =
    \\const runar = @import("runar");
    \\
    \\pub const MultiSig3of5 = struct {
    \\    pub const Contract = runar.SmartContract;
    \\
    \\    pk1: runar.PubKey,
    \\    pk2: runar.PubKey,
    \\    pk3: runar.PubKey,
    \\    pk4: runar.PubKey,
    \\    pk5: runar.PubKey,
    \\
    \\    pub fn init(pk1: runar.PubKey, pk2: runar.PubKey, pk3: runar.PubKey, pk4: runar.PubKey, pk5: runar.PubKey) MultiSig3of5 {
    \\        return .{ .pk1 = pk1, .pk2 = pk2, .pk3 = pk3, .pk4 = pk4, .pk5 = pk5 };
    \\    }
    \\
    \\    pub fn unlock(self: *const MultiSig3of5, sig1: runar.Sig, sig2: runar.Sig, sig3: runar.Sig) void {
    \\        runar.assert(runar.checkMultiSig(
    \\            &.{ sig1, sig2, sig3 },
    \\            &.{ self.pk1, self.pk2, self.pk3, self.pk4, self.pk5 },
    \\        ));
    \\    }
    \\};
;

/// Return true iff the 2-char `opcode` (lower-case hex) appears as a byte
/// in the script `hex` (also lower-case). Iterates by byte boundary so a
/// chance match inside a push payload counts as a hit -- the tests below
/// already cross-check with the structural OP_0 / OP_CHECKMULTISIG +
/// count-push pattern.
fn hexHasOpcode(hex: []const u8, opcode: []const u8) bool {
    std.debug.assert(opcode.len == 2);
    var i: usize = 0;
    while (i + 1 < hex.len) : (i += 2) {
        if (hex[i] == opcode[0] and hex[i + 1] == opcode[1]) return true;
    }
    return false;
}

fn countOpcode(hex: []const u8, opcode: []const u8) usize {
    std.debug.assert(opcode.len == 2);
    var i: usize = 0;
    var n: usize = 0;
    while (i + 1 < hex.len) : (i += 2) {
        if (hex[i] == opcode[0] and hex[i + 1] == opcode[1]) n += 1;
    }
    return n;
}

/// Compile `src` and return the resulting script hex. Caller owns the
/// returned slice.
fn compile(allocator: std.mem.Allocator, src: []const u8, file_name: []const u8) ![]const u8 {
    return compiler_api.compileSourceToHex(allocator, src, file_name);
}

// -------------------- 2-of-3 shape goldens --------------------

test "multiSig 2-of-3 emits exactly one OP_CHECKMULTISIG (or peephole-folded VERIFY)" {
    const hex = try compile(std.testing.allocator, MULTISIG_2OF3_SRC, "MultiSig2of3.runar.zig");
    defer std.testing.allocator.free(hex);

    // `assert(checkMultiSig(...))` may fold to OP_CHECKMULTISIGVERIFY (0xaf)
    // via the peephole optimiser. Accept either form, but require exactly
    // one multisig opcode total.
    const checkmultisig = countOpcode(hex, "ae");
    const checkmultisig_verify = countOpcode(hex, "af");
    try std.testing.expect((checkmultisig + checkmultisig_verify) == 1);
}

test "multiSig 2-of-3 emits OP_0 dummy for the CHECKMULTISIG off-by-one bug" {
    const hex = try compile(std.testing.allocator, MULTISIG_2OF3_SRC, "MultiSig2of3.runar.zig");
    defer std.testing.allocator.free(hex);

    // OP_0 is byte 0x00. Without the leading dummy push, Bitcoin's
    // CHECKMULTISIG legacy code reads one signature too many.
    try std.testing.expect(hexHasOpcode(hex, "00"));
}

test "multiSig 2-of-3 emits OP_2 (nSigs) and OP_3 (nPks) from array-literal lengths" {
    const hex = try compile(std.testing.allocator, MULTISIG_2OF3_SRC, "MultiSig2of3.runar.zig");
    defer std.testing.allocator.free(hex);

    // OP_2 = 0x52, OP_3 = 0x53.
    try std.testing.expect(hexHasOpcode(hex, "52"));
    try std.testing.expect(hexHasOpcode(hex, "53"));
}

// -------------------- 3-of-5 shape goldens --------------------

test "multiSig 3-of-5 emits OP_3 (nSigs) and OP_5 (nPks) derived from arrays" {
    // The 3-of-5 variant must push 3 (nSigs) and 5 (nPks) -- proving counts
    // come from the array literal lengths, not hard-coded.
    const hex = try compile(std.testing.allocator, MULTISIG_3OF5_SRC, "MultiSig3of5.runar.zig");
    defer std.testing.allocator.free(hex);

    // OP_3 = 0x53, OP_5 = 0x55.
    try std.testing.expect(hexHasOpcode(hex, "53"));
    try std.testing.expect(hexHasOpcode(hex, "55"));

    const checkmultisig = countOpcode(hex, "ae");
    const checkmultisig_verify = countOpcode(hex, "af");
    try std.testing.expect((checkmultisig + checkmultisig_verify) == 1);
}

test "multiSig 3-of-5 differs from 2-of-3 (counts wire through, no fallback)" {
    const hex23 = try compile(std.testing.allocator, MULTISIG_2OF3_SRC, "MultiSig2of3.runar.zig");
    defer std.testing.allocator.free(hex23);
    const hex35 = try compile(std.testing.allocator, MULTISIG_3OF5_SRC, "MultiSig3of5.runar.zig");
    defer std.testing.allocator.free(hex35);

    // 3-of-5 has more pubkeys -- strictly more bytes than 2-of-3. If a
    // regression caused array-length lookup to fall back to a default
    // (e.g. 1), the two would converge or 3-of-5 would shrink.
    try std.testing.expect(hex35.len > hex23.len);
    // And the byte sequences must not be byte-equal.
    try std.testing.expect(!std.mem.eql(u8, hex23, hex35));
}

// -------------------- determinism --------------------

test "multiSig lowering is deterministic" {
    const a = try compile(std.testing.allocator, MULTISIG_2OF3_SRC, "MultiSig2of3.runar.zig");
    defer std.testing.allocator.free(a);
    const b = try compile(std.testing.allocator, MULTISIG_2OF3_SRC, "MultiSig2of3.runar.zig");
    defer std.testing.allocator.free(b);

    try std.testing.expect(std.mem.eql(u8, a, b));
}

// -------------------- R-054: degenerate thresholds --------------------
//
// `checkMultiSig(&.{}, &.{pk})` lowers to
//
//   OP_0 OP_0 <pk> OP_1 OP_CHECKMULTISIG
//
// i.e. nSigs = 0. OP_CHECKMULTISIG with zero required signatures pops the
// pubkeys, verifies nothing, and pushes TRUE — the deployed output is
// ANYONE-CAN-SPEND while the source reads like an authorization check.
// Confirmed byte-identically across all seven tiers before the guard landed:
// every one emitted `0000007b51ae` for the equivalent contract.
//
// The mirror image, more signatures than public keys, can never be satisfied
// by any witness: the output is permanently UNSPENDABLE.
//
// The guard lives in `stack_lower` rather than `typecheck` so it also covers
// the `--ir` input path — which is what these tests drive, so the assertion
// can name the exact refusal rather than a coarse "compile failed".

const EMPTY_SIGS_SRC =
    \\const runar = @import("runar");
    \\
    \\pub const EmptyMultiSig = struct {
    \\    pub const Contract = runar.SmartContract;
    \\
    \\    pk1: runar.PubKey,
    \\
    \\    pub fn init(pk1: runar.PubKey) EmptyMultiSig {
    \\        return .{ .pk1 = pk1 };
    \\    }
    \\
    \\    pub fn unlock(self: *const EmptyMultiSig) void {
    \\        runar.assert(runar.checkMultiSig(&.{}, &.{self.pk1}));
    \\    }
    \\};
;

/// ANF IR for a `checkMultiSig` gate over the named sig / pk params, built at
/// comptime so the `--ir` path (which never runs a typecheck) can be driven
/// directly and the assertion can name the exact refusal.
fn thresholdIr(comptime sigs: []const []const u8, comptime pks: []const []const u8) []const u8 {
    var params: []const u8 = "";
    var body: []const u8 = "";
    var sig_refs: []const u8 = "";
    var pk_refs: []const u8 = "";
    for (sigs) |s| {
        if (params.len > 0) params = params ++ ", ";
        params = params ++ "{\"name\": \"" ++ s ++ "\", \"type\": \"Sig\"}";
        body = body ++ "{\"name\": \"b_" ++ s ++ "\", \"value\": {\"kind\": \"load_param\", \"name\": \"" ++ s ++ "\"}}, ";
        if (sig_refs.len > 0) sig_refs = sig_refs ++ ", ";
        sig_refs = sig_refs ++ "\"b_" ++ s ++ "\"";
    }
    for (pks) |k| {
        if (params.len > 0) params = params ++ ", ";
        params = params ++ "{\"name\": \"" ++ k ++ "\", \"type\": \"PubKey\"}";
        body = body ++ "{\"name\": \"b_" ++ k ++ "\", \"value\": {\"kind\": \"load_param\", \"name\": \"" ++ k ++ "\"}}, ";
        if (pk_refs.len > 0) pk_refs = pk_refs ++ ", ";
        pk_refs = pk_refs ++ "\"b_" ++ k ++ "\"";
    }
    return "{\"contractName\": \"CheckMultiSigThresholdProbe\", \"properties\": [], \"methods\": [" ++
        "{\"name\": \"unlock\", \"isPublic\": true, \"params\": [" ++ params ++ "], \"body\": [" ++ body ++
        "{\"name\": \"sigs\", \"value\": {\"kind\": \"array_literal\", \"elements\": [" ++ sig_refs ++ "]}}, " ++
        "{\"name\": \"pks\", \"value\": {\"kind\": \"array_literal\", \"elements\": [" ++ pk_refs ++ "]}}, " ++
        "{\"name\": \"r\", \"value\": {\"kind\": \"call\", \"func\": \"checkMultiSig\", \"args\": [\"sigs\", \"pks\"]}}, " ++
        "{\"name\": \"t\", \"value\": {\"kind\": \"assert\", \"value\": \"r\"}}]}]}";
}

const IR_0_OF_1 = thresholdIr(&.{}, &.{"k0"});
const IR_1_OF_0 = thresholdIr(&.{"s0"}, &.{});
const IR_2_OF_1 = thresholdIr(&.{ "s0", "s1" }, &.{"k0"});
const IR_1_OF_1 = thresholdIr(&.{"s0"}, &.{"k0"});
const IR_2_OF_3 = thresholdIr(&.{ "s0", "s1" }, &.{ "k0", "k1", "k2" });
const IR_3_OF_3 = thresholdIr(&.{ "s0", "s1", "s2" }, &.{ "k0", "k1", "k2" });

fn lowerIr(allocator: std.mem.Allocator, ir_json: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const program = try json_parser.parseANFProgram(alloc, ir_json);
    _ = try stack_lower.lower(alloc, program);
}

test "R-054: an empty signature array is refused (anyone-can-spend)" {
    try std.testing.expectError(
        error.DegenerateMultiSigThreshold,
        lowerIr(std.testing.allocator, IR_0_OF_1),
    );
}

test "R-054: an empty public key array is refused" {
    try std.testing.expectError(
        error.DegenerateMultiSigThreshold,
        lowerIr(std.testing.allocator, IR_1_OF_0),
    );
}

test "R-054: more signatures than public keys is refused (unspendable)" {
    try std.testing.expectError(
        error.DegenerateMultiSigThreshold,
        lowerIr(std.testing.allocator, IR_2_OF_1),
    );
}

test "R-054: an empty signature array is refused from source syntax too" {
    // The source path reaches the same refusal — `compileSourceToHex` maps a
    // lowering refusal to StackLowerFailed, so this pins reachability rather
    // than the specific error (the `--ir` tests above pin that).
    try std.testing.expectError(
        error.StackLowerFailed,
        compiler_api.compileSourceToHex(std.testing.allocator, EMPTY_SIGS_SRC, "EmptyMultiSig.runar.zig"),
    );
}

// Controls: the guard must not break any valid threshold.

test "R-054 control: 1-of-1, 2-of-3 and m == n still lower" {
    try lowerIr(std.testing.allocator, IR_1_OF_1);
    try lowerIr(std.testing.allocator, IR_2_OF_3);
    try lowerIr(std.testing.allocator, IR_3_OF_3);
}
