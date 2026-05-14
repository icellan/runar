//! Rabin signature verification codegen for Bitcoin Script.
//!
//! Rabin verification checks: (sig^2 + padding) mod pubKey == SHA256(msg).
//! The emission is a fixed 10-opcode sequence:
//!
//!   OP_SWAP OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
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

/// The fixed 10-opcode Rabin verification sequence.
pub const opcode_sequence = [_][]const u8{
    "OP_SWAP", // msg sig pubKey padding
    "OP_ROT", // msg pubKey padding sig
    "OP_DUP", // msg pubKey padding sig sig
    "OP_MUL", // msg pubKey padding sig^2
    "OP_ADD", // msg pubKey (sig^2+padding)
    "OP_SWAP", // msg (sig^2+padding) pubKey
    "OP_MOD", // msg ((sig^2+padding) mod pubKey)
    "OP_SWAP", // ((sig^2+padding) mod pubKey) msg
    "OP_SHA256", // ((sig^2+padding) mod pubKey) SHA256(msg)
    "OP_EQUAL", // bool
};

/// Append the Rabin verification opcode sequence to `list`.
pub fn append(
    list: *std.ArrayListUnmanaged(Instruction),
    allocator: std.mem.Allocator,
) !void {
    for (opcode_sequence) |op| {
        try list.append(allocator, .{ .op_name = op });
    }
}

test "rabin emitter appends the 10-opcode byte-frozen golden sequence" {
    const allocator = std.testing.allocator;
    var list: std.ArrayListUnmanaged(Instruction) = .empty;
    defer list.deinit(allocator);

    try append(&list, allocator);

    try std.testing.expectEqual(@as(usize, 10), list.items.len);
    for (list.items, opcode_sequence) |inst, expected| {
        try std.testing.expectEqualStrings(expected, inst.op_name);
    }
}
