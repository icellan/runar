//! N-074 — a Bitcoin Script number is ARBITRARY PRECISION.
//!
//! Rúnar contracts routinely carry 256-bit EC scalars and 1024-bit+ Rabin
//! moduli as plain `bigint` constructor args. `decodeScriptNumber` accumulated
//! into an `i64` through a fixed `[8]u8` staging buffer, so anything wider than
//! 8 data bytes (`|v| >= 2^63`) indexed past the end of that buffer and
//! PANICKED — `index out of bounds` — instead of decoding.
//!
//! This is type-INDEPENDENT: `bigint`, `int`, `RabinSig` and `RabinPubKey` all
//! bite identically. Nothing about it is Rabin-specific.
//!
//! The ENCODE direction was already arbitrary-precision
//! (`sdk_state.encodeBigScriptNumber`, which takes a decimal string and is what
//! the `.big_int` StateValue variant encodes through). The asymmetry WAS the
//! bug, so every case below is a real encode -> decode round trip.

const std = @import("std");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");
const script_utils = @import("sdk_script_utils.zig");

/// secp256k1 group order — a real 256-bit EC scalar.
const SECP_N = "115792089237316195423570985008687907852837564279074904382605163141518161494337";
/// A deterministic 1024-bit odd modulus with the top bit set: the shape of a
/// real Rabin public key (128 bytes).
const RABIN_1024 = "99068719171432002146137311586819387646033673282442268174774782671999562801264502320230697368056122056037887996485526845789822730341467216601217971743412906058452632946239858722327898748234874221141359423697249054724716242045815478148675575955849558861539174810221469540865911313499616042524201320198581026695";

const MAGNITUDES = [_][]const u8{
    "1234567890123456789", // small — fits i64
    "9223372036854775807", // 2^63-1
    "9223372036854775808", // 2^63 — first value past i64
    "18446744073709551616", // 2^64
    SECP_N,
    RABIN_1024,
};

/// Single-slot template: `<value@0> ac`
fn makeArtifact(
    allocator: std.mem.Allocator,
    params: *[1]types.ABIParam,
    slots: *[1]types.ConstructorSlot,
    type_name: []const u8,
) types.RunarArtifact {
    params.* = .{.{ .name = "value", .type_name = type_name }};
    slots.* = .{.{ .param_index = 0, .byte_offset = 0 }};
    return .{
        .allocator = allocator,
        .script = "00ac",
        .abi = .{ .constructor = .{ .params = params } },
        .constructor_slots = slots,
    };
}

fn freeArgs(allocator: std.mem.Allocator, args: *std.StringHashMap(types.StateValue)) void {
    var it = args.iterator();
    while (it.next()) |e| {
        allocator.free(e.key_ptr.*);
        e.value_ptr.deinit(allocator);
    }
    args.deinit();
}

/// Encode `decimal` through the production encoder, extract it back, and
/// normalise whatever `StateValue` variant comes back into a decimal string.
/// Caller frees the returned slice.
fn roundTrip(allocator: std.mem.Allocator, type_name: []const u8, decimal: []const u8) ![]u8 {
    const push = try state_mod.encodeBigScriptNumber(allocator, decimal);
    defer allocator.free(push);
    const script = try std.mem.concat(allocator, u8, &[_][]const u8{ push, "ac" });
    defer allocator.free(script);

    var params: [1]types.ABIParam = undefined;
    var slots: [1]types.ConstructorSlot = undefined;
    const artifact = makeArtifact(allocator, &params, &slots, type_name);

    var args = try script_utils.extractConstructorArgs(&artifact, script, allocator);
    defer freeArgs(allocator, &args);

    return switch (args.get("value").?) {
        .int => |n| std.fmt.allocPrint(allocator, "{d}", .{n}),
        .big_int => |s| allocator.dupe(u8, s),
        else => |v| {
            std.debug.print("{s}: value extracted as {any}, want a script number\n", .{ type_name, v });
            return error.NotAScriptNumber;
        },
    };
}

test "N-074: a positive script number round-trips at every magnitude" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "bigint", "int", "RabinPubKey", "RabinSig" }) |type_name| {
        for (MAGNITUDES) |decimal| {
            const got = try roundTrip(allocator, type_name, decimal);
            defer allocator.free(got);
            try std.testing.expectEqualStrings(decimal, got);
        }
    }
}

// Bitcoin script numbers are SIGN-MAGNITUDE, not two's complement: the sign
// lives in the high bit of the most-significant byte. This is where a naive
// bignum port breaks.
//
// `-9223372036854775808` (exactly -2^63) is decoded below but NOT round-tripped
// here: `sdk_state.encodeScriptNumber` computes `@intCast(-n)` on an i64, which
// panics with `integer overflow` on i64::MIN. That is a SEPARATE, pre-existing
// defect on the ENCODE side of another module (Go widens through uint64 and
// Rust through i128 at the same spot, so neither tier has it). Reported, not
// fixed here.
test "N-074: a negative script number round-trips at every magnitude" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "bigint", "RabinPubKey" }) |type_name| {
        for (MAGNITUDES) |decimal| {
            const neg = try std.fmt.allocPrint(allocator, "-{s}", .{decimal});
            defer allocator.free(neg);
            if (std.mem.eql(u8, neg, "-9223372036854775808")) continue;
            const got = try roundTrip(allocator, type_name, neg);
            defer allocator.free(got);
            try std.testing.expectEqualStrings(neg, got);
        }
    }
}

// Decode-side coverage for the two boundary values the encoder cannot currently
// produce, fed as raw push data. `-2^63` is the pre-existing encoder overflow
// noted above; `+2^63` is the first magnitude the OLD decoder panicked on.
test "N-074: the i64 boundary decodes correctly from raw push data" {
    const allocator = std.testing.allocator;
    const cases = [_]struct { push: []const u8, want: []const u8 }{
        .{ .push = "09000000000000008000", .want = "9223372036854775808" },
        .{ .push = "09000000000000008080", .want = "-9223372036854775808" },
    };
    for (cases) |c| {
        const script = try std.mem.concat(allocator, u8, &[_][]const u8{ c.push, "ac" });
        defer allocator.free(script);
        var params: [1]types.ABIParam = undefined;
        var slots: [1]types.ConstructorSlot = undefined;
        const artifact = makeArtifact(allocator, &params, &slots, "bigint");
        var args = try script_utils.extractConstructorArgs(&artifact, script, allocator);
        defer freeArgs(allocator, &args);

        const got = switch (args.get("value").?) {
            .int => |n| try std.fmt.allocPrint(allocator, "{d}", .{n}),
            .big_int => |s| try allocator.dupe(u8, s),
            else => return error.NotAScriptNumber,
        };
        defer allocator.free(got);
        try std.testing.expectEqualStrings(c.want, got);
    }
}

// CONTROL: small values stay byte-identical on the wire AND keep the `.int`
// StateValue variant, so no caller that switches on it breaks.
test "N-074 CONTROL: small values keep their bytes and their `.int` variant" {
    const allocator = std.testing.allocator;
    const cases = [_]struct { decimal: []const u8, push: []const u8, value: i64 }{
        .{ .decimal = "0", .push = "00", .value = 0 },
        .{ .decimal = "1", .push = "51", .value = 1 },
        .{ .decimal = "16", .push = "60", .value = 16 },
        .{ .decimal = "-1", .push = "4f", .value = -1 },
        .{ .decimal = "17", .push = "0111", .value = 17 },
        .{ .decimal = "127", .push = "017f", .value = 127 },
        .{ .decimal = "128", .push = "028000", .value = 128 },
        .{ .decimal = "-128", .push = "028080", .value = -128 },
        .{ .decimal = "1234567890123456789", .push = "081581e97df4102211", .value = 1234567890123456789 },
        .{ .decimal = "-1234567890123456789", .push = "081581e97df4102291", .value = -1234567890123456789 },
    };
    for (cases) |c| {
        const push = try state_mod.encodeBigScriptNumber(allocator, c.decimal);
        defer allocator.free(push);
        try std.testing.expectEqualStrings(c.push, push);

        const script = try std.mem.concat(allocator, u8, &[_][]const u8{ c.push, "ac" });
        defer allocator.free(script);
        var params: [1]types.ABIParam = undefined;
        var slots: [1]types.ConstructorSlot = undefined;
        const artifact = makeArtifact(allocator, &params, &slots, "bigint");
        var args = try script_utils.extractConstructorArgs(&artifact, script, allocator);
        defer freeArgs(allocator, &args);

        const v = args.get("value").?;
        try std.testing.expect(v == .int);
        try std.testing.expectEqual(c.value, v.int);
    }
}
