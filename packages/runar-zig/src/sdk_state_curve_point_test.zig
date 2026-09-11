//! `P256Point` (64) and `P384Point` (96) are FIXED-WIDTH RAW state fields.
//!
//! All seven compilers emit them as fixed raw slices in the state tail, and
//! runar-lang's cast constructors hard-assert exactly those widths. The seven
//! SDKs used to omit both from their width tables, so they fell through to the
//! push-data default and deployed a state section 1 byte (0x40 direct push) or
//! 2 bytes (OP_PUSHDATA1 0x60) longer than the script's own on-chain reader
//! expects. The deploy succeeded and the FIRST spend failed with
//! "OP_NUMEQUALVERIFY requires the top stack item to be truthy" — funds locked.
//!
//! `crossSdkGolden` is byte-identical across all seven SDKs; every tier carries
//! the same literal and the same field list.

const std = @import("std");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");

/// Repeat `unit` `n` times into an owned buffer.
fn rep(allocator: std.mem.Allocator, unit: []const u8, n: usize) ![]u8 {
    const out = try allocator.alloc(u8, unit.len * n);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        @memcpy(out[i * unit.len ..][0..unit.len], unit);
    }
    return out;
}

const CURVE_POINT_FIELDS = [_]types.StateField{
    .{ .name = "n", .type_name = "bigint", .index = 0 },
    .{ .name = "flag", .type_name = "bool", .index = 1 },
    .{ .name = "pk", .type_name = "PubKey", .index = 2 },
    .{ .name = "h", .type_name = "Sha256", .index = 3 },
    .{ .name = "ad", .type_name = "Addr", .index = 4 },
    .{ .name = "pt", .type_name = "Point", .index = 5 },
    .{ .name = "p256", .type_name = "P256Point", .index = 6 },
    .{ .name = "p384", .type_name = "P384Point", .index = 7 },
    .{ .name = "sig", .type_name = "Sig", .index = 8 },
    .{ .name = "rab", .type_name = "RabinSig", .index = 9 },
    .{ .name = "bs", .type_name = "ByteString", .index = 10 },
};

/// The one wire record every tier must reproduce byte for byte.
fn crossSdkGolden(allocator: std.mem.Allocator) ![]u8 {
    const aa = try rep(allocator, "aa", 32); //  PubKey    33 raw (after the 02 prefix)
    defer allocator.free(aa);
    const bb = try rep(allocator, "bb", 32); //  Sha256    32 raw
    defer allocator.free(bb);
    const cc = try rep(allocator, "cc", 20); //  Addr      20 raw
    defer allocator.free(cc);
    const dd = try rep(allocator, "dd", 64); //  Point     64 raw
    defer allocator.free(dd);
    const p1 = try rep(allocator, "11", 64); //  P256Point 64 raw  <- was framed "40" + 64
    defer allocator.free(p1);
    const p2 = try rep(allocator, "22", 96); //  P384Point 96 raw  <- was framed "4c60" + 96
    defer allocator.free(p2);
    const ee = try rep(allocator, "ee", 66); //  Sig        framed <len><data>
    defer allocator.free(ee);
    const ff = try rep(allocator, "ff", 8); //   RabinSig   framed <len><data>
    defer allocator.free(ff);
    return std.fmt.allocPrint(
        allocator,
        "0100000000000000" ++ "01" ++ "02{s}{s}{s}{s}{s}{s}" ++ "443044{s}" ++ "08{s}" ++ "020011",
        .{ aa, bb, cc, dd, p1, p2, ee, ff },
    );
}

test "curve point: cross-SDK golden state record serializes byte for byte" {
    const allocator = std.testing.allocator;

    const pk = try rep(allocator, "aa", 32);
    defer allocator.free(pk);
    const pk_full = try std.fmt.allocPrint(allocator, "02{s}", .{pk});
    defer allocator.free(pk_full);
    const h = try rep(allocator, "bb", 32);
    defer allocator.free(h);
    const ad = try rep(allocator, "cc", 20);
    defer allocator.free(ad);
    const pt = try rep(allocator, "dd", 64);
    defer allocator.free(pt);
    const p256 = try rep(allocator, "11", 64);
    defer allocator.free(p256);
    const p384 = try rep(allocator, "22", 96);
    defer allocator.free(p384);
    const ee = try rep(allocator, "ee", 66);
    defer allocator.free(ee);
    const sig = try std.fmt.allocPrint(allocator, "3044{s}", .{ee});
    defer allocator.free(sig);
    const rab = try rep(allocator, "ff", 8);
    defer allocator.free(rab);

    const values = [_]types.StateValue{
        .{ .int = 1 },
        .{ .boolean = true },
        .{ .bytes = pk_full },
        .{ .bytes = h },
        .{ .bytes = ad },
        .{ .bytes = pt },
        .{ .bytes = p256 },
        .{ .bytes = p384 },
        .{ .bytes = sig },
        .{ .bytes = rab },
        .{ .bytes = "0011" },
    };

    const want = try crossSdkGolden(allocator);
    defer allocator.free(want);
    try std.testing.expectEqual(@as(usize, 399), want.len / 2);

    const got = try state_mod.serializeState(allocator, &CURVE_POINT_FIELDS, &values);
    defer allocator.free(got);
    try std.testing.expectEqualStrings(want, got);

    // ... and back, unchanged.
    const back = try state_mod.deserializeState(allocator, &CURVE_POINT_FIELDS, want);
    defer {
        for (back) |v| switch (v) {
            .bytes => |b| allocator.free(b),
            .big_int => |b| allocator.free(b),
            else => {},
        };
        allocator.free(back);
    }
    try std.testing.expectEqual(@as(i64, 1), back[0].int);
    try std.testing.expect(back[1].boolean);
    try std.testing.expectEqualStrings(pk_full, back[2].bytes);
    try std.testing.expectEqualStrings(h, back[3].bytes);
    try std.testing.expectEqualStrings(ad, back[4].bytes);
    try std.testing.expectEqualStrings(pt, back[5].bytes);
    try std.testing.expectEqualStrings(p256, back[6].bytes);
    try std.testing.expectEqualStrings(p384, back[7].bytes);
    try std.testing.expectEqualStrings(sig, back[8].bytes);
    try std.testing.expectEqualStrings(rab, back[9].bytes);
    try std.testing.expectEqualStrings("0011", back[10].bytes);
}

test "curve point: a lone P256Point / P384Point field round-trips raw" {
    const allocator = std.testing.allocator;
    const cases = [_]struct { type_name: []const u8, size: usize, fill: []const u8 }{
        .{ .type_name = "P256Point", .size = 64, .fill = "11" },
        .{ .type_name = "P384Point", .size = 96, .fill = "22" },
    };
    for (cases) |c| {
        const fields = [_]types.StateField{.{ .name = "v", .type_name = c.type_name, .index = 0 }};
        const v = try rep(allocator, c.fill, c.size);
        defer allocator.free(v);
        const values = [_]types.StateValue{.{ .bytes = v }};

        const hex = try state_mod.serializeState(allocator, &fields, &values);
        defer allocator.free(hex);
        try std.testing.expectEqualStrings(v, hex);
        try std.testing.expectEqual(c.size, hex.len / 2);

        const back = try state_mod.deserializeState(allocator, &fields, hex);
        defer {
            allocator.free(back[0].bytes);
            allocator.free(back);
        }
        try std.testing.expectEqualStrings(v, back[0].bytes);
    }
}

test "curve point: raw and framed controls stay byte-unchanged" {
    const allocator = std.testing.allocator;

    const raw = [_]struct { type_name: []const u8, size: usize }{
        .{ .type_name = "Point", .size = 64 },
        .{ .type_name = "PubKey", .size = 33 },
        .{ .type_name = "Sha256", .size = 32 },
    };
    for (raw) |c| {
        const fields = [_]types.StateField{.{ .name = "v", .type_name = c.type_name, .index = 0 }};
        const v = try rep(allocator, "ab", c.size);
        defer allocator.free(v);
        const values = [_]types.StateValue{.{ .bytes = v }};
        const got = try state_mod.serializeState(allocator, &fields, &values);
        defer allocator.free(got);
        try std.testing.expectEqualStrings(v, got);
    }

    for ([_][]const u8{ "ByteString", "Sig", "RabinSig" }) |type_name| {
        const fields = [_]types.StateField{.{ .name = "v", .type_name = type_name, .index = 0 }};
        const v = try rep(allocator, "ab", 64);
        defer allocator.free(v);
        const values = [_]types.StateValue{.{ .bytes = v }};
        const want = try std.fmt.allocPrint(allocator, "40{s}", .{v});
        defer allocator.free(want);
        const got = try state_mod.serializeState(allocator, &fields, &values);
        defer allocator.free(got);
        try std.testing.expectEqualStrings(want, got);
    }
}
