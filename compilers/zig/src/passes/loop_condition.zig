//! N-115 — normalise a reversed loop comparison to the canonical spelling.
//!
//! Every later check reads a loop's iterator off the LEFT-hand side of its
//! condition (W4, `cond_tests_iter`) and its bound off the right. `10 > i`
//! says the same thing as `i < 10`, so each surface parser rewrites it once,
//! right after parsing the condition, before digesting it into a `ForStmt`:
//!
//!   N >  i  ->  i <  N        N <  i  ->  i >  N
//!   N >= i  ->  i <= N        N <= i  ->  i >= N
//!
//! The rule, identical in all seven tiers: the condition is a `<`/`<=`/`>`/`>=`
//! comparison, its RIGHT operand is the loop variable, and its LEFT operand is
//! not -> swap the operands and mirror the operator. Nothing else is touched,
//! so the W4 refusals (N40, N41) and the direction rule (N42) keep firing.

const std = @import("std");
const types = @import("../ir/types.zig");

fn mirrored(op: types.BinOperator) ?types.BinOperator {
    return switch (op) {
        .lt => .gt,
        .lte => .gte,
        .gt => .lt,
        .gte => .lte,
        else => null,
    };
}

fn isIdent(e: types.Expression, name: []const u8) bool {
    return e == .identifier and std.mem.eql(u8, e.identifier, name);
}

/// Rewrite `cond` in place to the canonical form for a loop over `iter`.
///
/// `iter` is null where the parser has not learned the loop variable yet (a
/// Zig `while` or Move `while`, whose variable is read off the condition and
/// matched to the preceding declaration afterwards). The loop variable is then
/// taken to be the right-hand identifier when the left-hand side is not an
/// identifier at all. That differs from the rule above only for
/// identifier-vs-identifier conditions, which every tier refuses either way:
/// an identifier is never an unrollable bound.
pub fn normalize(cond: types.Expression, iter: ?[]const u8) void {
    if (cond != .binary_op) return;
    const bop = cond.binary_op;
    const m = mirrored(bop.op) orelse return;
    const swap = if (iter) |name|
        isIdent(bop.right, name) and !isIdent(bop.left, name)
    else
        bop.right == .identifier and bop.left != .identifier;
    if (!swap) return;
    // Through temporaries: a struct literal assigned to `bop.*` writes in
    // place, so `.right = bop.left` would read the already-overwritten field.
    const left = bop.left;
    const right = bop.right;
    bop.* = .{ .op = m, .left = right, .right = left };
}

test "reversed comparisons are mirrored, everything else is left alone" {
    var b1 = types.BinaryOp{ .op = .gt, .left = .{ .literal_int = 10 }, .right = .{ .identifier = "i" } };
    normalize(.{ .binary_op = &b1 }, "i");
    try std.testing.expectEqual(types.BinOperator.lt, b1.op);
    try std.testing.expectEqualStrings("i", b1.left.identifier);
    try std.testing.expectEqual(@as(i64, 10), b1.right.literal_int);

    var b2 = types.BinaryOp{ .op = .lte, .left = .{ .literal_int = 1 }, .right = .{ .identifier = "i" } };
    normalize(.{ .binary_op = &b2 }, null);
    try std.testing.expectEqual(types.BinOperator.gte, b2.op);
    try std.testing.expectEqualStrings("i", b2.left.identifier);

    // N41's shape: a different variable on the left, a literal on the right.
    var b3 = types.BinaryOp{ .op = .lt, .left = .{ .identifier = "j" }, .right = .{ .literal_int = 3 } };
    normalize(.{ .binary_op = &b3 }, "i");
    try std.testing.expectEqual(types.BinOperator.lt, b3.op);
    try std.testing.expectEqualStrings("j", b3.left.identifier);

    // `!=` carries no direction and is not mirrored.
    var b4 = types.BinaryOp{ .op = .neq, .left = .{ .literal_int = 3 }, .right = .{ .identifier = "i" } };
    normalize(.{ .binary_op = &b4 }, "i");
    try std.testing.expectEqual(types.BinOperator.neq, b4.op);
}
