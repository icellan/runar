//! Rabin signature verification codegen for Bitcoin Script.
//!
//! Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg)
//! AND padding is in [0, 65536) — the bound is enforced on-chain (BUG-010).
//! The emission is a fixed 18-opcode sequence:
//!
//!   OP_SWAP
//!   OP_DUP OP_0 <push 65536> OP_WITHIN OP_VERIFY   // 0 <= padding < 65536 (BUG-010)
//!   OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
//!
//! The caller must bring the 4 arguments to the top of the stack in argument
//! order (msg sig padding pubKey, pubKey on top) before emitting this sequence.
//!
//! Mirror of `packages/runar-compiler/src/passes/rabin-codegen.ts` and the
//! standalone Rabin modules in the Go / Rust / Python / Java tiers.

const std = @import("std");

/// A codegen instruction. Aliased from `crypto_emitters.CryptoInstruction` so
/// Rabin instruction lists are interoperable with the shared crypto emitter.
pub const Instruction = @import("crypto_emitters.zig").CryptoInstruction;

/// Exclusive upper bound on the Rabin `padding` parameter, enforced on-chain.
/// The legitimate signer (`packages/runar-go/rabin.go::RabinSign`) produces
/// `padding < 1000`; the on-chain bound is 65536 (16-bit) for slack.
/// See `_review/BUG-010-rfc.md`.
pub const rabin_padding_limit: i64 = 65536;

/// Append the Rabin verification opcode sequence to `list`.
pub fn append(
    list: *std.ArrayListUnmanaged(Instruction),
    allocator: std.mem.Allocator,
) !void {
    try list.append(allocator, .{ .op_name = "OP_SWAP" });
    // BUG-010 padding range check: assert 0 <= padding < 65536.
    try list.append(allocator, .{ .op_name = "OP_DUP" });
    try list.append(allocator, .{ .op_name = "OP_0" });
    try list.append(allocator, .{ .push_int = rabin_padding_limit });
    try list.append(allocator, .{ .op_name = "OP_WITHIN" });
    try list.append(allocator, .{ .op_name = "OP_VERIFY" });
    try list.append(allocator, .{ .op_name = "OP_ROT" });
    try list.append(allocator, .{ .op_name = "OP_DUP" });
    try list.append(allocator, .{ .op_name = "OP_MUL" });
    try list.append(allocator, .{ .op_name = "OP_ADD" });
    try list.append(allocator, .{ .op_name = "OP_SWAP" });
    try list.append(allocator, .{ .op_name = "OP_MOD" });
    try list.append(allocator, .{ .op_name = "OP_SWAP" });
    try list.append(allocator, .{ .op_name = "OP_SHA256" });
    // BUG-011 digest-encoding normalization: OP_MOD leaves a MINIMAL Script
    // number, which carries a trailing 0x00 sign byte whenever the digest's
    // most-significant byte has its high bit set (~50% of messages), while
    // OP_SHA256 pushes exactly 32 raw bytes. A bare OP_EQUAL is a BYTE compare
    // and refused about half of all honest signatures on a real consensus VM.
    // Give the digest an explicit 0x00 sign byte, collapse to minimal form,
    // and compare NUMERICALLY. OP_NUMEQUAL never aborts, so the any-of-N
    // pattern still yields false rather than killing the script.
    try list.append(allocator, .{ .push_data = &.{0x00} });
    try list.append(allocator, .{ .op_name = "OP_CAT" });
    try list.append(allocator, .{ .op_name = "OP_BIN2NUM" });
    try list.append(allocator, .{ .op_name = "OP_NUMEQUAL" });
}

test "rabin emitter appends the 18-opcode byte-frozen golden sequence (BUG-010, BUG-011)" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(Instruction) = .empty;
    defer list.deinit(allocator);

    try append(&list, allocator);

    try std.testing.expectEqual(@as(usize, 18), list.items.len);

    const expected_opcodes = [_]?[]const u8{
        "OP_SWAP", "OP_DUP", "OP_0",
        null, // index 3 is push_int(65536), checked separately
        "OP_WITHIN", "OP_VERIFY",
        "OP_ROT", "OP_DUP", "OP_MUL", "OP_ADD", "OP_SWAP",
        "OP_MOD", "OP_SWAP", "OP_SHA256",
        null, // index 14 is push_data(0x00), checked separately
        "OP_CAT", "OP_BIN2NUM", "OP_NUMEQUAL",
    };

    for (list.items, expected_opcodes, 0..) |inst, expected, i| {
        if (expected) |op_name| {
            try std.testing.expectEqualStrings(op_name, inst.op_name);
        } else if (i == 3) {
            // BUG-010 padding bound.
            switch (inst) {
                .push_int => |v| try std.testing.expectEqual(rabin_padding_limit, v),
                else => return error.TestExpectedPushInt,
            }
        } else {
            // BUG-011 digest sign byte: the 0x00 that makes the raw digest read
            // as a NON-NEGATIVE Script number before the numeric compare.
            try std.testing.expect(i == 14);
            switch (inst) {
                .push_data => |b| try std.testing.expectEqualSlices(u8, &.{0x00}, b),
                else => return error.TestExpectedPushData,
            }
        }
    }
}
