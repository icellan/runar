//! F-035: `RabinPubKey` / `RabinSig` state fields are a bare 8-byte OP_NUM2BIN
//! word, exactly like `bigint`. Both are bigint aliases and every compiler
//! writes and reads them that way in the state section (the compiler is
//! canonical, user decision D2). The SDK width table omitted both, so they fell
//! to the variable-length branch, where an `.int` value is not `.bytes` and
//! became "" — OP_0, the value silently lost.
//!
//! `RABIN_STATE_GOLDEN` is hand-derived and byte-identical across all seven
//! SDKs (the same three values are the `state-rabin` sdk-output fixture):
//!
//!     RabinPubKey 0x1234567890ABCDEF -> efcdab9078563412
//!     RabinSig    -1000000007        -> 07ca9a3b00000080
//!     bigint      3                  -> 0300000000000000
//!
//! Proves: the Zig codec writes and reads that layout. Does not prove the
//! script accepts it (packages/runar-testing f035-rabin-state-spend.test.ts).

const std = @import("std");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");

const RABIN_STATE_GOLDEN = "efcdab9078563412" ++ "07ca9a3b00000080" ++ "0300000000000000";

const RABIN_FIELDS = [_]types.StateField{
    .{ .name = "oracleKey", .type_name = "RabinPubKey", .index = 0 },
    .{ .name = "lastSig", .type_name = "RabinSig", .index = 1 },
    .{ .name = "count", .type_name = "bigint", .index = 2 },
};

test "F-035: RabinPubKey / RabinSig serialize as NUM2BIN 8" {
    const allocator = std.testing.allocator;
    const values = [_]types.StateValue{
        .{ .int = 0x1234567890ABCDEF },
        .{ .int = -1000000007 },
        .{ .int = 3 },
    };
    const got = try state_mod.serializeState(allocator, &RABIN_FIELDS, &values);
    defer allocator.free(got);
    try std.testing.expectEqualStrings(RABIN_STATE_GOLDEN, got);
}

test "F-035: RabinPubKey / RabinSig deserialize back" {
    const allocator = std.testing.allocator;
    const back = try state_mod.deserializeState(allocator, &RABIN_FIELDS, RABIN_STATE_GOLDEN);
    defer {
        for (back) |v| switch (v) {
            .bytes => |b| allocator.free(b),
            .big_int => |b| allocator.free(b),
            else => {},
        };
        allocator.free(back);
    }
    try std.testing.expectEqual(@as(i64, 0x1234567890ABCDEF), back[0].int);
    try std.testing.expectEqual(@as(i64, -1000000007), back[1].int);
    try std.testing.expectEqual(@as(i64, 3), back[2].int);
}

test "F-035: a Rabin value that does not fit the 8-byte word is refused" {
    const allocator = std.testing.allocator;
    const fields = [_]types.StateField{.{ .name = "k", .type_name = "RabinPubKey", .index = 0 }};
    const values = [_]types.StateValue{.{ .big_int = "9223372036854775808" }};
    try std.testing.expectError(
        error.StateValueOutOfRange,
        state_mod.serializeState(allocator, &fields, &values),
    );
}
