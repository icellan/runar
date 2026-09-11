//! N-070 (extract half) — `interpretScriptElement` must know every ABI type
//! spelling the compiler can emit.
//!
//! Two holes, identical in shape across all seven SDK tiers:
//!
//!   RabinSig / RabinPubKey — `bigint` ALIASES (runar-lang/src/types.ts:68-71)
//!     that `verifyRabinSig` consumes with OP_MOD, i.e. as a Script NUMBER.
//!     Absent from the comparison chain, so a restored contract's modulus came
//!     back as the little-endian hex blob "1581e97df4102211" instead of the
//!     number. Feed that back into a call and the rebuilt locking script no
//!     longer matches what is on chain.
//!
//!   boolean — the CANONICAL Rúnar primitive name; only the alias `bool` was
//!     compared. A boolean slot fell through to the byte branch, so `true` came
//!     back as the string "01" and `false` as "". Java's ContractScript was the
//!     only tier of seven that tested both spellings.
//!
//! NOTE ON WIDTH: `decodeScriptNumber` returns i64, so this test uses a modulus
//! that fits. A real 128-byte Rabin modulus does not — a pre-existing,
//! type-INDEPENDENT limit of this tier's script-number decoder (it bites a
//! plain `bigint` ctor arg of the same size identically), out of scope here.

const std = @import("std");
const types = @import("sdk_types.zig");
const script_utils = @import("sdk_script_utils.zig");

const MODULUS: i64 = 1234567890123456789;
const RABIN_PUSH = "081581e97df4102211"; // minimal LE sign-magnitude, 8 bytes
const BLOB = "04deadbeef";

/// Template: `<modulus@0> 7c <flag@2> 7c <blob@4> ac`
fn makeArtifact(
    allocator: std.mem.Allocator,
    params: *[3]types.ABIParam,
    slots: *[3]types.ConstructorSlot,
    rabin_type: []const u8,
    bool_type: []const u8,
) types.RunarArtifact {
    params.* = .{
        .{ .name = "modulus", .type_name = rabin_type },
        .{ .name = "flag", .type_name = bool_type },
        .{ .name = "blob", .type_name = "ByteString" },
    };
    slots.* = .{
        .{ .param_index = 0, .byte_offset = 0 },
        .{ .param_index = 1, .byte_offset = 2 },
        .{ .param_index = 2, .byte_offset = 4 },
    };
    return .{
        .allocator = allocator,
        .script = "007c007c00ac",
        .abi = .{ .constructor = .{ .params = params } },
        .constructor_slots = slots,
    };
}

fn scriptFor(buf: []u8, flag_opcode: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, RABIN_PUSH ++ "7c{s}7c" ++ BLOB ++ "ac", .{flag_opcode}) catch unreachable;
}

/// Run the extractor and hand back the owned map (caller frees).
fn extract(
    allocator: std.mem.Allocator,
    rabin_type: []const u8,
    bool_type: []const u8,
    script_hex: []const u8,
) !std.StringHashMap(types.StateValue) {
    var params: [3]types.ABIParam = undefined;
    var slots: [3]types.ConstructorSlot = undefined;
    const artifact = makeArtifact(allocator, &params, &slots, rabin_type, bool_type);
    return script_utils.extractConstructorArgs(&artifact, script_hex, allocator);
}

fn freeArgs(allocator: std.mem.Allocator, args: *std.StringHashMap(types.StateValue)) void {
    var it = args.iterator();
    while (it.next()) |e| {
        allocator.free(e.key_ptr.*);
        e.value_ptr.deinit(allocator);
    }
    args.deinit();
}

test "N-070: a Rabin-typed slot extracts as a script number, not a hex blob" {
    const allocator = std.testing.allocator;
    var buf: [64]u8 = undefined;
    const script = scriptFor(&buf, "51");

    for ([_][]const u8{ "RabinPubKey", "RabinSig" }) |type_name| {
        var args = try extract(allocator, type_name, "boolean", script);
        defer freeArgs(allocator, &args);
        const v = args.get("modulus").?;
        try std.testing.expect(v == .int);
        try std.testing.expectEqual(MODULUS, v.int);
    }
}

test "N-070: a canonical `boolean` slot extracts as a boolean in both polarities" {
    const allocator = std.testing.allocator;
    const cases = [_]struct { opcode: []const u8, want: bool }{
        .{ .opcode = "51", .want = true },
        .{ .opcode = "00", .want = false },
    };
    for (cases) |c| {
        var buf: [64]u8 = undefined;
        const script = scriptFor(&buf, c.opcode);
        var args = try extract(allocator, "RabinPubKey", "boolean", script);
        defer freeArgs(allocator, &args);
        const v = args.get("flag").?;
        try std.testing.expect(v == .boolean);
        try std.testing.expectEqual(c.want, v.boolean);
    }
}

test "N-070: the `boolean` and `bool` spellings extract identically" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "51", "00" }) |opcode| {
        var buf: [64]u8 = undefined;
        const script = scriptFor(&buf, opcode);

        var canonical = try extract(allocator, "RabinPubKey", "boolean", script);
        defer freeArgs(allocator, &canonical);
        var alias = try extract(allocator, "RabinPubKey", "bool", script);
        defer freeArgs(allocator, &alias);

        const a = canonical.get("flag").?;
        const b = alias.get("flag").?;
        try std.testing.expect(a == .boolean and b == .boolean);
        try std.testing.expectEqual(b.boolean, a.boolean);
    }
}

test "N-070 CONTROL: bigint / int / ByteString slots are unchanged" {
    const allocator = std.testing.allocator;
    var buf: [64]u8 = undefined;
    const script = scriptFor(&buf, "51");

    for ([_][]const u8{ "bigint", "int" }) |type_name| {
        var args = try extract(allocator, type_name, "bool", script);
        defer freeArgs(allocator, &args);
        try std.testing.expectEqual(MODULUS, args.get("modulus").?.int);
    }

    // A ByteString slot still comes back as its hex payload, NOT a number, and
    // the offset walk past the wide Rabin push still lands on it.
    var args = try extract(allocator, "RabinPubKey", "boolean", script);
    defer freeArgs(allocator, &args);
    try std.testing.expectEqualStrings("deadbeef", args.get("blob").?.bytes);
}

test "N-070 CONTROL: S1 single-opcode byte reconstruction still applies" {
    const allocator = std.testing.allocator;
    var args = try extract(allocator, "RabinPubKey", "boolean", RABIN_PUSH ++ "7c517c55ac");
    defer freeArgs(allocator, &args);
    try std.testing.expectEqualStrings("05", args.get("blob").?.bytes);
}
