//! Rabin signature verification codegen for Bitcoin Script.
//!
//! Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg) mod pubKey
//! AND padding is in [0, 65536) — the bound is enforced on-chain (BUG-010)
//! AND sig is in [0, pubKey) — also enforced on-chain (F-368; sig >= 0 holds
//! after F-144, so only sig < pubKey costs opcodes).
//! The emission is a fixed 34-opcode sequence:
//!
//!   <push 0x00> OP_CAT OP_BIN2NUM                   // pubKey as unsigned (F-144)
//!   OP_SWAP
//!   <push 0x00> OP_CAT OP_BIN2NUM                   // padding as unsigned (F-144)
//!   OP_DUP OP_0 <push 65536> OP_WITHIN OP_VERIFY   // 0 <= padding < 65536 (BUG-010)
//!   OP_ROT
//!   <push 0x00> OP_CAT OP_BIN2NUM                   // sig as unsigned (F-144)
//!   OP_DUP OP_3 OP_PICK OP_LESSTHAN OP_VERIFY      // sig < pubKey (F-368)
//!   OP_DUP OP_MUL OP_ADD OP_OVER OP_MOD
//!   OP_ROT OP_SHA256 <push 0x00> OP_CAT OP_BIN2NUM
//!   OP_ROT OP_MOD OP_NUMEQUAL                       // digest mod pubKey (F-047)
//!
//! OPERAND SIGN (F-144): off-chain verifiers read padding (and the native
//! Go/Rust/Python/Ruby/Zig layers also sig and pubKey) as UNSIGNED
//! little-endian bytes; OP_WITHIN / OP_MUL / OP_MOD read a Script number,
//! whose last byte's high bit is the sign. Each operand gets an explicit
//! 0x00 sign byte and OP_BIN2NUM, so a raw unsigned push keeps its unsigned
//! value and a non-negative Script number is unchanged.
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
    try list.append(allocator, .{ .push_data = &.{0x00} }); // F-144: pubKey as unsigned
    try list.append(allocator, .{ .op_name = "OP_CAT" });
    try list.append(allocator, .{ .op_name = "OP_BIN2NUM" });
    try list.append(allocator, .{ .op_name = "OP_SWAP" });
    try list.append(allocator, .{ .push_data = &.{0x00} }); // F-144: padding as unsigned
    try list.append(allocator, .{ .op_name = "OP_CAT" });
    try list.append(allocator, .{ .op_name = "OP_BIN2NUM" });
    // BUG-010 padding range check: assert 0 <= padding < 65536.
    try list.append(allocator, .{ .op_name = "OP_DUP" });
    try list.append(allocator, .{ .op_name = "OP_0" });
    try list.append(allocator, .{ .push_int = rabin_padding_limit });
    try list.append(allocator, .{ .op_name = "OP_WITHIN" });
    try list.append(allocator, .{ .op_name = "OP_VERIFY" });
    try list.append(allocator, .{ .op_name = "OP_ROT" });
    try list.append(allocator, .{ .push_data = &.{0x00} }); // F-144: sig as unsigned
    try list.append(allocator, .{ .op_name = "OP_CAT" });
    try list.append(allocator, .{ .op_name = "OP_BIN2NUM" });
    // F-368: assert sig < pubKey (sig >= 0 already holds after F-144), so the
    // sig + k*pubKey re-encodings of one signature are refused.
    try list.append(allocator, .{ .op_name = "OP_DUP" });
    try list.append(allocator, .{ .push_int = 3 });
    try list.append(allocator, .{ .op_name = "OP_PICK" });
    try list.append(allocator, .{ .op_name = "OP_LESSTHAN" });
    try list.append(allocator, .{ .op_name = "OP_VERIFY" });
    try list.append(allocator, .{ .op_name = "OP_DUP" });
    try list.append(allocator, .{ .op_name = "OP_MUL" });
    try list.append(allocator, .{ .op_name = "OP_ADD" });
    try list.append(allocator, .{ .op_name = "OP_OVER" }); // F-047: keep pubKey for the digest reduction
    try list.append(allocator, .{ .op_name = "OP_MOD" });
    try list.append(allocator, .{ .op_name = "OP_ROT" });
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
    // F-047: reduce the digest mod pubKey, matching every off-chain verifier.
    try list.append(allocator, .{ .op_name = "OP_ROT" });
    try list.append(allocator, .{ .op_name = "OP_MOD" });
    try list.append(allocator, .{ .op_name = "OP_NUMEQUAL" });
}

test "rabin emitter appends the 34-opcode byte-frozen golden sequence (BUG-010, BUG-011, F-047, F-144, F-368)" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(Instruction) = .empty;
    defer list.deinit(allocator);

    try append(&list, allocator);

    try std.testing.expectEqual(@as(usize, 34), list.items.len);

    const expected_opcodes = [_]?[]const u8{
        null, "OP_CAT", "OP_BIN2NUM", // F-144: pubKey as unsigned (push_data 0x00 at 0)
        "OP_SWAP",
        null, "OP_CAT", "OP_BIN2NUM", // F-144: padding as unsigned (push_data 0x00 at 4)
        "OP_DUP", "OP_0",
        null, // index 9 is push_int(65536), checked separately
        "OP_WITHIN", "OP_VERIFY",
        "OP_ROT",
        null, "OP_CAT", "OP_BIN2NUM", // F-144: sig as unsigned (push_data 0x00 at 13)
        "OP_DUP", null, "OP_PICK", "OP_LESSTHAN", "OP_VERIFY", // F-368: sig < pubKey (push_int 3 at 17)
        "OP_DUP", "OP_MUL", "OP_ADD", "OP_OVER",
        "OP_MOD", "OP_ROT", "OP_SHA256",
        null, // index 28 is push_data(0x00), checked separately
        "OP_CAT", "OP_BIN2NUM",
        "OP_ROT", "OP_MOD", // F-047: SHA256(msg) mod pubKey
        "OP_NUMEQUAL",
    };

    for (list.items, expected_opcodes, 0..) |inst, expected, i| {
        if (expected) |op_name| {
            try std.testing.expectEqualStrings(op_name, inst.op_name);
        } else if (i == 9) {
            // BUG-010 padding bound.
            switch (inst) {
                .push_int => |v| try std.testing.expectEqual(rabin_padding_limit, v),
                else => return error.TestExpectedPushInt,
            }
        } else if (i == 17) {
            // F-368 pick depth.
            switch (inst) {
                .push_int => |v| try std.testing.expectEqual(@as(i64, 3), v),
                else => return error.TestExpectedPushInt,
            }
        } else {
            // F-144 operand sign bytes (0, 4, 13) and the BUG-011 digest sign
            // byte (28): each 0x00 makes the item below it read as a
            // NON-NEGATIVE Script number.
            try std.testing.expect(i == 0 or i == 4 or i == 13 or i == 28);
            switch (inst) {
                .push_data => |b| try std.testing.expectEqualSlices(u8, &.{0x00}, b),
                else => return error.TestExpectedPushData,
            }
        }
    }
}
