//! Reusable stack-lowering templates for stateful/output helpers.
//!
//! The exported routines append exact `StackInstruction` sequences that mirror
//! the canonical lowering structure in
//! `packages/runar-compiler/src/passes/05-stack-lower.ts`.
//!
//! These helpers only emit linear instruction templates. They do not mutate a
//! stack map and they do not perform named-value shuffling. The caller is
//! responsible for arranging values on the virtual stack according to each
//! function's documented preconditions.

const std = @import("std");
const types = @import("../../ir/types.zig");
const Opcode = types.Opcode;
const Allocator = std.mem.Allocator;

pub const p2pkh_prefix_with_len = [_]u8{ 0x19, 0x76, 0xa9, 0x14 };
pub const p2pkh_suffix = [_]u8{ 0x88, 0xac };
pub const op_return_byte = [_]u8{0x6a};
pub const varint_fd_prefix = [_]u8{0xfd};

fn appendOpcode(
    allocator: Allocator,
    instructions: *std.ArrayListUnmanaged(types.StackInstruction),
    op: Opcode,
) !void {
    try instructions.append(allocator, .{ .op = op });
}

fn appendPushInt(
    allocator: Allocator,
    instructions: *std.ArrayListUnmanaged(types.StackInstruction),
    value: i64,
) !void {
    try instructions.append(allocator, .{ .push_int = value });
}

fn appendPushData(
    allocator: Allocator,
    instructions: *std.ArrayListUnmanaged(types.StackInstruction),
    data: []const u8,
) !void {
    try instructions.append(allocator, .{ .push_data = data });
}

/// Append the Bitcoin varint encoding template used by stateful output
/// construction.
///
/// Preconditions:
/// - Virtual stack shape is `[..., script_bytes, len]`.
///
/// Postconditions:
/// - The emitted program leaves the virtual stack as `[..., script_bytes,
///   varint_bytes]`.
///
/// Notes:
/// - This mirrors the TypeScript implementation's sign-magnitude handling:
///   values under 253 use `NUM2BIN 2` plus `SPLIT 1`; larger values use
///   `NUM2BIN 4`, `SPLIT 2`, and a `0xfd` prefix.
pub fn emitVarintEncodingForTopLength(
    allocator: Allocator,
    instructions: *std.ArrayListUnmanaged(types.StackInstruction),
) !void {
    try appendOpcode(allocator, instructions, .op_dup);
    try appendPushInt(allocator, instructions, 253);
    try appendOpcode(allocator, instructions, .op_lessthan);
    try appendOpcode(allocator, instructions, .op_if);

    try appendPushInt(allocator, instructions, 2);
    try appendOpcode(allocator, instructions, .op_num2bin);
    try appendPushInt(allocator, instructions, 1);
    try appendOpcode(allocator, instructions, .op_split);
    try appendOpcode(allocator, instructions, .op_drop);

    try appendOpcode(allocator, instructions, .op_else);

    try appendPushInt(allocator, instructions, 4);
    try appendOpcode(allocator, instructions, .op_num2bin);
    try appendPushInt(allocator, instructions, 2);
    try appendOpcode(allocator, instructions, .op_split);
    try appendOpcode(allocator, instructions, .op_drop);
    try appendPushData(allocator, instructions, &varint_fd_prefix);
    try appendOpcode(allocator, instructions, .op_swap);
    try appendOpcode(allocator, instructions, .op_cat);

    try appendOpcode(allocator, instructions, .op_endif);
}

/// Append the template for building a length-prefixed P2PKH locking script.
///
/// Preconditions:
/// - Top of virtual stack is a 20-byte pubkey hash (`pkh`).
///
/// Postconditions:
/// - Top of virtual stack is `0x19 76 a9 14 <pkh> 88 ac`.
///
pub fn emitBuildP2pkhScriptFromTopPkh(
    allocator: Allocator,
    instructions: *std.ArrayListUnmanaged(types.StackInstruction),
) !void {
    try appendPushData(allocator, instructions, &p2pkh_prefix_with_len);
    try appendOpcode(allocator, instructions, .op_swap);
    try appendOpcode(allocator, instructions, .op_cat);
    try appendPushData(allocator, instructions, &p2pkh_suffix);
    try appendOpcode(allocator, instructions, .op_cat);
}

/// Append the template that prepends an 8-byte LE amount to the current script.
///
/// Preconditions:
/// - Virtual stack shape is `[..., script_bytes, amount]`.
///
/// Postconditions:
/// - Top of virtual stack is `amount_8le || script_bytes`.
pub fn emitPrependAmount8LeToTopScript(
    allocator: Allocator,
    instructions: *std.ArrayListUnmanaged(types.StackInstruction),
) !void {
    try appendPushInt(allocator, instructions, 8);
    try appendOpcode(allocator, instructions, .op_num2bin);
    try appendOpcode(allocator, instructions, .op_swap);
    try appendOpcode(allocator, instructions, .op_cat);
}

/// Append `OP_RETURN` to an already-positioned code part.
///
/// Preconditions:
/// - Top of virtual stack is `code_part`.
///
/// Postconditions:
/// - Top of virtual stack is `code_part || 0x6a`.
pub fn emitAppendOpReturnToTopCodePart(
    allocator: Allocator,
    instructions: *std.ArrayListUnmanaged(types.StackInstruction),
) !void {
    try appendPushData(allocator, instructions, &op_return_byte);
    try appendOpcode(allocator, instructions, .op_cat);
}

/// Prepend the varint of the current script length.
///
/// Preconditions:
/// - Virtual stack shape is `[..., script_bytes]`.
///
/// Postconditions:
/// - Top of virtual stack is `varint(script_len) || script_bytes`.
pub fn emitPrependVarintToTopScript(
    allocator: Allocator,
    instructions: *std.ArrayListUnmanaged(types.StackInstruction),
) !void {
    try appendOpcode(allocator, instructions, .op_size);
    try emitVarintEncodingForTopLength(allocator, instructions);
    try appendOpcode(allocator, instructions, .op_swap);
    try appendOpcode(allocator, instructions, .op_cat);
}

/// Emit the generic end-relative extractor template used for fields near the
/// tail of a preimage.
///
/// Preconditions:
/// - Top of virtual stack is the preimage bytes.
///
/// Parameters:
/// - `skip_from_end`: number of bytes to skip from the end before the desired
///   slice starts.
/// - `slice_len`: length of the desired slice in bytes.
/// - `decode_bin2num`: whether to decode the slice with `OP_BIN2NUM`.
///
/// Examples:
/// - `extractLocktime`: `skip_from_end = 8`, `slice_len = 4`,
///   `decode_bin2num = true`
/// - `extractOutputHash`: `skip_from_end = 40`, `slice_len = 32`,
///   `decode_bin2num = false`
pub fn emitExtractEndRelativeSlice(
    allocator: Allocator,
    instructions: *std.ArrayListUnmanaged(types.StackInstruction),
    skip_from_end: i64,
    slice_len: i64,
    decode_bin2num: bool,
) !void {
    try appendOpcode(allocator, instructions, .op_size);
    try appendPushInt(allocator, instructions, skip_from_end);
    try appendOpcode(allocator, instructions, .op_sub);
    try appendOpcode(allocator, instructions, .op_split);
    try appendOpcode(allocator, instructions, .op_nip);
    try appendPushInt(allocator, instructions, slice_len);
    try appendOpcode(allocator, instructions, .op_split);
    try appendOpcode(allocator, instructions, .op_drop);
    if (decode_bin2num) {
        try appendOpcode(allocator, instructions, .op_bin2num);
    }
}

/// Extract the locktime field from the preimage tail.
pub fn emitExtractLocktime(
    allocator: Allocator,
    instructions: *std.ArrayListUnmanaged(types.StackInstruction),
) !void {
    try emitExtractEndRelativeSlice(allocator, instructions, 8, 4, true);
}

/// Extract the serialized `hashOutputs` field from the preimage tail.
pub fn emitExtractOutputHash(
    allocator: Allocator,
    instructions: *std.ArrayListUnmanaged(types.StackInstruction),
) !void {
    try emitExtractEndRelativeSlice(allocator, instructions, 40, 32, false);
}

test "emit varint encoding template includes both small and large branches" {
    const allocator = std.testing.allocator;
    var instructions: std.ArrayListUnmanaged(types.StackInstruction) = .empty;
    defer instructions.deinit(allocator);

    try emitVarintEncodingForTopLength(allocator, &instructions);

    try std.testing.expectEqual(@as(usize, 19), instructions.items.len);
    try std.testing.expectEqualDeep(types.StackInstruction{ .op = .op_dup }, instructions.items[0]);
    try std.testing.expectEqualDeep(types.StackInstruction{ .op = .op_if }, instructions.items[3]);
    try std.testing.expectEqualDeep(types.StackInstruction{ .op = .op_else }, instructions.items[9]);
    try std.testing.expectEqualDeep(types.StackInstruction{ .push_data = &varint_fd_prefix }, instructions.items[15]);
    try std.testing.expectEqualDeep(types.StackInstruction{ .op = .op_endif }, instructions.items[18]);
}

test "emit build p2pkh script template anchors prefix and suffix" {
    const allocator = std.testing.allocator;
    var instructions: std.ArrayListUnmanaged(types.StackInstruction) = .empty;
    defer instructions.deinit(allocator);

    try emitBuildP2pkhScriptFromTopPkh(allocator, &instructions);

    try std.testing.expectEqual(@as(usize, 5), instructions.items.len);
    try std.testing.expectEqualDeep(types.StackInstruction{ .push_data = &p2pkh_prefix_with_len }, instructions.items[0]);
    try std.testing.expectEqualDeep(types.StackInstruction{ .op = .op_swap }, instructions.items[1]);
    try std.testing.expectEqualDeep(types.StackInstruction{ .op = .op_cat }, instructions.items[2]);
    try std.testing.expectEqualDeep(types.StackInstruction{ .push_data = &p2pkh_suffix }, instructions.items[3]);
    try std.testing.expectEqualDeep(types.StackInstruction{ .op = .op_cat }, instructions.items[4]);
}

test "emit locktime extractor matches end-relative split pattern" {
    const allocator = std.testing.allocator;
    var instructions: std.ArrayListUnmanaged(types.StackInstruction) = .empty;
    defer instructions.deinit(allocator);

    try emitExtractLocktime(allocator, &instructions);

    try std.testing.expectEqual(@as(usize, 9), instructions.items.len);
    try std.testing.expectEqualDeep(types.StackInstruction{ .op = .op_size }, instructions.items[0]);
    try std.testing.expectEqualDeep(types.StackInstruction{ .push_int = 8 }, instructions.items[1]);
    try std.testing.expectEqualDeep(types.StackInstruction{ .op = .op_sub }, instructions.items[2]);
    try std.testing.expectEqualDeep(types.StackInstruction{ .op = .op_nip }, instructions.items[4]);
    try std.testing.expectEqualDeep(types.StackInstruction{ .push_int = 4 }, instructions.items[5]);
    try std.testing.expectEqualDeep(types.StackInstruction{ .op = .op_bin2num }, instructions.items[8]);
}

test "emit output hash extractor omits bin2num decode" {
    const allocator = std.testing.allocator;
    var instructions: std.ArrayListUnmanaged(types.StackInstruction) = .empty;
    defer instructions.deinit(allocator);

    try emitExtractOutputHash(allocator, &instructions);

    try std.testing.expectEqual(@as(usize, 8), instructions.items.len);
    try std.testing.expectEqualDeep(types.StackInstruction{ .push_int = 40 }, instructions.items[1]);
    try std.testing.expectEqualDeep(types.StackInstruction{ .push_int = 32 }, instructions.items[5]);
    try std.testing.expectEqualDeep(types.StackInstruction{ .op = .op_drop }, instructions.items[7]);
}
