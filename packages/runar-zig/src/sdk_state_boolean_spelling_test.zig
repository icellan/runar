//! A mutable `boolean` state field is ONE raw byte — 01 or 00.
//!
//! The compiler spells the type `boolean`. `bool` appears nowhere in any of the
//! seven frontends, so an artifact's stateFields never carries it; the SDKs that
//! matched on "bool" alone were matching a spelling no compiler emits, and every
//! real boolean field fell through to their push-data default:
//!
//!   typescript  01           correct
//!   ruby        01           correct
//!   go          02 74727565  push-framed ASCII "true" — 3 bytes too long
//!   java        02 74727565  same
//!   python      00           right width, ALWAYS false
//!   zig         00           same
//!   rust        panic        as_bytes() on a Bool variant
//!
//! All five are fund-affecting. Go and Java deploy a state tail longer than the
//! one the script's own reader rebuilds, so hash256(outputs) can never match and
//! the first spend is impossible. Zig and Python deploy a well-formed tail that
//! says false whatever the caller passed, so the first call that sets the flag
//! builds a continuation the covenant rejects — a silent wrong answer, the worst
//! of the three.
//!
//! BOOLEAN_SPELLING_GOLDEN is byte-identical across all seven SDKs; every tier
//! carries the same literal and the same field list. The trailing bigint is
//! load-bearing: a boolean of the wrong WIDTH shifts it, so the record catches a
//! length error that a lone boolean field would hide.

const std = @import("std");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");

const BOOLEAN_SPELLING_FIELDS = [_]types.StateField{
    .{ .name = "count", .type_name = "bigint", .index = 0 },
    // The canonical spelling — the only one any compiler emits.
    .{ .name = "flag", .type_name = "boolean", .index = 1 },
    // The alias. Several tiers accepted only this one; it must keep working.
    .{ .name = "alias", .type_name = "bool", .index = 2 },
    .{ .name = "tail", .type_name = "bigint", .index = 3 },
};

/// The one wire record every tier must reproduce byte for byte.
const BOOLEAN_SPELLING_GOLDEN =
    "0700000000000000" ++ //  bigint 7, NUM2BIN 8
    "01" ++ //                boolean true  — 1 raw byte
    "00" ++ //                bool    false — 1 raw byte
    "0100000000000000"; //    bigint 1, NUM2BIN 8

const FLIPPED_GOLDEN = "0700000000000000" ++ "00" ++ "01" ++ "0100000000000000";

fn valuesFor(flag: bool, alias: bool) [4]types.StateValue {
    return [_]types.StateValue{
        .{ .int = 7 },
        .{ .boolean = flag },
        .{ .boolean = alias },
        .{ .int = 1 },
    };
}

test "boolean spelling: cross-SDK golden state record serializes byte for byte" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 18), BOOLEAN_SPELLING_GOLDEN.len / 2);

    const values = valuesFor(true, false);
    const got = try state_mod.serializeState(allocator, &BOOLEAN_SPELLING_FIELDS, &values);
    defer allocator.free(got);
    try std.testing.expectEqualStrings(BOOLEAN_SPELLING_GOLDEN, got);
}

test "boolean spelling: the opposite polarity is a different record" {
    const allocator = std.testing.allocator;
    const values = valuesFor(false, true);
    const got = try state_mod.serializeState(allocator, &BOOLEAN_SPELLING_FIELDS, &values);
    defer allocator.free(got);
    try std.testing.expectEqualStrings(FLIPPED_GOLDEN, got);
}

test "boolean spelling: the golden record deserializes back to every value" {
    const allocator = std.testing.allocator;
    const back = try state_mod.deserializeState(allocator, &BOOLEAN_SPELLING_FIELDS, BOOLEAN_SPELLING_GOLDEN);
    defer {
        for (back) |v| switch (v) {
            .bytes => |b| allocator.free(b),
            .big_int => |b| allocator.free(b),
            else => {},
        };
        allocator.free(back);
    }
    try std.testing.expectEqual(@as(i64, 7), back[0].int);
    try std.testing.expect(back[1].boolean);
    try std.testing.expect(!back[2].boolean);
    try std.testing.expectEqual(@as(i64, 1), back[3].int);
}

test "boolean spelling: the flipped record deserializes too" {
    const allocator = std.testing.allocator;
    const back = try state_mod.deserializeState(allocator, &BOOLEAN_SPELLING_FIELDS, FLIPPED_GOLDEN);
    defer {
        for (back) |v| switch (v) {
            .bytes => |b| allocator.free(b),
            .big_int => |b| allocator.free(b),
            else => {},
        };
        allocator.free(back);
    }
    try std.testing.expect(!back[1].boolean);
    try std.testing.expect(back[2].boolean);
}

test "boolean spelling: a lone boolean field is exactly one byte" {
    const allocator = std.testing.allocator;
    const fields = [_]types.StateField{
        .{ .name = "v", .type_name = "boolean", .index = 0 },
    };
    const cases = [_]struct { value: bool, want: []const u8 }{
        .{ .value = true, .want = "01" },
        .{ .value = false, .want = "00" },
    };
    for (cases) |c| {
        const values = [_]types.StateValue{.{ .boolean = c.value }};
        const got = try state_mod.serializeState(allocator, &fields, &values);
        defer allocator.free(got);
        try std.testing.expectEqualStrings(c.want, got);

        const back = try state_mod.deserializeState(allocator, &fields, c.want);
        defer allocator.free(back);
        try std.testing.expectEqual(c.value, back[0].boolean);
    }
}
