//! N-084: the num2bin state encode path fails closed.
//!
//! `encodeStateValue` encoded a `.bytes` value in an int / bigint / RabinSig /
//! RabinPubKey field as 0, a `.empty_sig` marker as 0 and a `.boolean` as 0/1;
//! `encodeBigNum2Bin` computed `c - '0'` on whatever characters a `.big_int`
//! string held. Every one of those is now `error.NotAnInteger`.
//!
//! Proves: `serializeState` returns `error.NotAnInteger` for `.bytes` (hex /
//! empty / non-decimal), `.boolean`, `.empty_sig` and a non-decimal `.big_int`
//! in each of the four num2bin types, and valid `.int` / `.big_int` values keep
//! their exact bytes. Does not prove anything on chain, nor the other six SDKs.

const std = @import("std");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");

const TYPES = [_][]const u8{ "int", "bigint", "RabinSig", "RabinPubKey" };

test "N-084: num2bin state fields refuse a non-integer value" {
    const allocator = std.testing.allocator;
    const bad = [_]types.StateValue{
        .{ .bytes = "deadbeef" },
        .{ .bytes = "" },
        .{ .bytes = "0x10" },
        .{ .bytes = "5" },
        .{ .boolean = true },
        .{ .boolean = false },
        .empty_sig,
        .{ .big_int = "abc" },
        .{ .big_int = "" },
        .{ .big_int = "-" },
        .{ .big_int = "1 2" },
        .{ .big_int = "+5" },
    };
    for (TYPES) |t| {
        const fields = [_]types.StateField{.{ .name = "k", .type_name = t, .index = 0 }};
        for (bad) |v| {
            const vals = [_]types.StateValue{v};
            try std.testing.expectError(error.NotAnInteger, state_mod.serializeState(allocator, &fields, &vals));
        }
    }
}

test "N-084: valid integers keep their bytes" {
    const allocator = std.testing.allocator;
    const Case = struct { v: types.StateValue, want: []const u8 };
    const cases = [_]Case{
        .{ .v = .{ .int = 0 }, .want = "0000000000000000" },
        .{ .v = .{ .int = 5 }, .want = "0500000000000000" },
        .{ .v = .{ .int = -5 }, .want = "0500000000000080" },
        .{ .v = .{ .big_int = "5" }, .want = "0500000000000000" },
        .{ .v = .{ .big_int = "-5" }, .want = "0500000000000080" },
    };
    for (TYPES) |t| {
        const fields = [_]types.StateField{.{ .name = "k", .type_name = t, .index = 0 }};
        for (cases) |c| {
            const vals = [_]types.StateValue{c.v};
            const out = try state_mod.serializeState(allocator, &fields, &vals);
            defer allocator.free(out);
            try std.testing.expectEqualStrings(c.want, out);
        }
    }
}
