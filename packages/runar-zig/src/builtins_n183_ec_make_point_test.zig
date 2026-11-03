//! N-183 -- native Zig ecMakePoint must apply the compiled script's R-156
//! gate: each coordinate must satisfy 0 <= v < p, or the script aborts.
//! BigintBig is u256, so a negative or over-wide coordinate is not
//! representable; the reachable defect is x or y in [p, 2^256), which the old
//! code wrote out verbatim. A panic cannot be caught in-process, so the abort
//! rows run the `ecMakePointChecked` variant (the plain builtin is that
//! variant plus `catch @panic`, as for ecAdd).
//!
//! Proves: x = p, x = p + 1, y = p, y = p + 1 and 2^256 - 1 on either half
//! return an error, and p - 1 / 0 / a real curve point still build.
//! Does NOT prove: negative / >= 2^256 inputs (unrepresentable in u256), or
//! the script itself (the runar-testing r156 test pins that).

const std = @import("std");
const builtins = @import("builtins.zig");

const P: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
const GY: u256 = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
const MAX: u256 = std.math.maxInt(u256);

test "N-183: ecMakePointChecked refuses coordinates outside [0, p)" {
    const bad = [_][2]u256{
        .{ P, GY },
        .{ P + 1, GY },
        .{ 1, P },
        .{ 1, P + 1 },
        .{ MAX, GY },
        .{ 1, MAX },
    };
    for (bad) |c| {
        if (builtins.ecMakePointChecked(c[0], c[1])) |pt| {
            builtins.freeIfOwned(pt);
            return error.TestExpectedError;
        } else |err| {
            try std.testing.expectEqual(builtins.EcBuiltinError.NonCanonicalCoordinate, err);
        }
    }
}

test "N-183: ecMakePointChecked still builds field elements" {
    const good = [_][2]u256{ .{ P - 1, P - 1 }, .{ 0, 0 }, .{ 1, GY } };
    for (good) |c| {
        const pt = try builtins.ecMakePointChecked(c[0], c[1]);
        defer builtins.freeIfOwned(pt);
        try std.testing.expectEqual(@as(usize, 64), pt.len);
        try std.testing.expectEqual(c[0], std.mem.readInt(u256, pt[0..32], .big));
        try std.testing.expectEqual(c[1], std.mem.readInt(u256, pt[32..64], .big));
    }
}
