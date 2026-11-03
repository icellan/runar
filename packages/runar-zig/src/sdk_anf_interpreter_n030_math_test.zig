//! N-030 (CL-BUG-104) — the SDK ANF interpreter's math builtins must return
//! what the compiled script returns, for every vector in the shared on-chain
//! file fixtures/f033-math-builtins-onchain.json.
//!
//! That file is the oracle: every row is executed on @bsv/sdk Spend.validate by
//! packages/runar-testing/src/__tests__/f033-zig-native-math-onchain.test.ts
//! (accept at `expect`, reject at `expect + 1`; an `abort` row rejects both
//! `== 0` and `!= 0`). builtins_math_onchain_test.zig replays the same file
//! through the native runtime; every other tier replays it too.
//!
//! Proves: for every `cases` row the interpreter returns the on-chain value
//! (booleans compared as script numbers), or returns its abort error where the
//! script aborts — never a value — including clamp with lo > hi
//! (min(max(v, lo), hi)).
//! Does NOT prove: the `wideCases` rows (operands beyond i64: log2 past
//! 2^64, gcd's 256-step partial remainder, sqrt's 2^495 guard) — this
//! interpreter's integer value is i64, so those inputs cannot be expressed; the
//! bigint-capable tiers replay them. Nor inputs outside the file.

const std = @import("std");
const interp = @import("sdk_anf_interpreter.zig");

const ANFProgram = interp.ANFProgram;
const ANFProperty = interp.ANFProperty;
const ANFMethod = interp.ANFMethod;
const ANFBinding = interp.ANFBinding;
const ANFValue = interp.ANFValue;

const vectors_json = @embedFile("fixtures/f033-math-builtins-onchain.json");

/// Run `result = func(args...)` through the interpreter; booleans become 0/1.
fn runCall(a: std.mem.Allocator, func: []const u8, args: []const i64) !i64 {
    const names = [_][]const u8{ "a", "b", "c" };
    var body: [5]ANFBinding = undefined;
    for (args, 0..) |arg, i| {
        body[i] = .{ .name = names[i], .value = .{ .load_const = .{ .value = .{ .int = arg } } } };
    }
    const n = args.len;
    body[n] = .{ .name = "r", .value = .{ .call = .{ .func = func, .args = names[0..n] } } };
    body[n + 1] = .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "r" } } };

    var props = [_]ANFProperty{
        .{ .name = "result", .type_name = "int", .readonly = false },
    };
    var methods = [_]ANFMethod{
        .{ .name = "run", .params = &.{}, .body = body[0 .. n + 2], .is_public = true },
    };
    const anf = ANFProgram{ .contract_name = "MathProbe", .properties = &props, .methods = &methods };
    var cs = std.StringHashMap(ANFValue).init(a);
    defer cs.deinit();
    try cs.put("result", .{ .int = 0 });
    var call_args = std.StringHashMap(ANFValue).init(a);
    defer call_args.deinit();
    var ns = try interp.computeNewState(a, &anf, "run", cs, call_args, &.{});
    defer ns.deinit();
    return switch (ns.get("result").?) {
        .int => |v| v,
        .boolean => |b| @intFromBool(b),
        else => error.UnexpectedResultKind,
    };
}

test "N-030: SDK ANF interpreter math builtins return the on-chain value for every shared vector" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, vectors_json, .{});
    defer parsed.deinit();

    const cases = parsed.value.object.get("cases").?.array.items;
    try std.testing.expect(cases.len > 0);

    var mismatches: usize = 0;
    for (cases) |c| {
        const obj = c.object;
        const name = obj.get("fn").?.string;
        const expect = obj.get("expect").?;

        var args: [3]i64 = undefined;
        const arr = obj.get("args").?.array.items;
        for (arr, 0..) |v, i| args[i] = v.integer;

        const got = runCall(allocator, name, args[0..arr.len]);
        const ok = switch (expect) {
            .string => |s| std.mem.eql(u8, s, "abort") and std.meta.isError(got),
            .integer => |w| if (got) |g| g == w else |_| false,
            .bool => |w| if (got) |g| g == @intFromBool(w) else |_| false,
            else => false,
        };
        if (!ok) {
            mismatches += 1;
            std.debug.print("N-030 interpreter/on-chain mismatch: {s}({any}) interpreter={any} on-chain={any}\n", .{
                name, args[0..arr.len], got, expect,
            });
        }
    }
    try std.testing.expectEqual(@as(usize, 0), mismatches);
}

// N-163: the `wideCases` rows (operands or results beyond i64). This
// interpreter's integer is i64, so it cannot compute them — but it must fail
// closed: every row whose operands fit i64 (`pow(10, 32)`) yields an error, or
// exactly the on-chain value; never a wrapped value. It used to wrap
// `pow` / `mulDiv` / `percentOf` / `*` past i64 (`*%`).
//
// Proves: no i64-expressible `wideCases` row returns a value other than the
// on-chain one. Does NOT prove: the rows whose operands are beyond i64 — they
// cannot be expressed as an `ANFValue.int`; they enter the Zig SDK as
// `StateValue.big_int` through `stateValueToAnf` (sdk_contract.zig), which
// this test does not reach. Nor that the interpreter computes these rows.
test "N-163: SDK ANF interpreter fails closed on every i64-expressible wideCases row" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, vectors_json, .{});
    defer parsed.deinit();

    const wide = parsed.value.object.get("wideCases").?.array.items;
    var replayed: usize = 0;
    var mismatches: usize = 0;
    rows: for (wide) |c| {
        const obj = c.object;
        const name = obj.get("fn").?.string;
        const arr = obj.get("args").?.array.items;
        var args: [3]i64 = undefined;
        for (arr, 0..) |v, i| {
            args[i] = std.fmt.parseInt(i64, v.string, 10) catch continue :rows;
        }
        replayed += 1;
        const got = runCall(allocator, name, args[0..arr.len]);
        const ok = if (got) |g| switch (obj.get("expect").?) {
            .string => |s| blk: {
                var buf: [24]u8 = undefined;
                break :blk std.mem.eql(u8, s, try std.fmt.bufPrint(&buf, "{d}", .{g}));
            },
            .bool => |w| g == @intFromBool(w),
            else => false,
        } else |_| true;
        if (!ok) {
            mismatches += 1;
            std.debug.print("N-163 wide row returned a value the script does not: {s}({any}) interpreter={any}\n", .{
                name, args[0..arr.len], got,
            });
        }
    }
    try std.testing.expect(replayed > 0);
    try std.testing.expectEqual(@as(usize, 0), mismatches);
}

// N-163: `a * b` past i64 must be refused, not wrapped (`*%`).
// Proves: the binop `*` fails closed on i64 overflow and still multiplies in
// range. Does NOT prove: `+` / `-` overflow (not covered by this item).
test "N-163: SDK ANF interpreter refuses an i64-overflowing binop *" {
    const H = struct {
        fn mul(a: std.mem.Allocator, x: i64, y: i64) !i64 {
            var body = [_]ANFBinding{
                .{ .name = "a", .value = .{ .load_const = .{ .value = .{ .int = x } } } },
                .{ .name = "b", .value = .{ .load_const = .{ .value = .{ .int = y } } } },
                .{ .name = "r", .value = .{ .bin_op = .{ .op = "*", .left = "a", .right = "b" } } },
                .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "r" } } },
            };
            var props = [_]ANFProperty{.{ .name = "result", .type_name = "int", .readonly = false }};
            var methods = [_]ANFMethod{.{ .name = "run", .params = &.{}, .body = &body, .is_public = true }};
            const anf = ANFProgram{ .contract_name = "MulProbe", .properties = &props, .methods = &methods };
            var cs = std.StringHashMap(ANFValue).init(a);
            defer cs.deinit();
            try cs.put("result", .{ .int = 0 });
            var call_args = std.StringHashMap(ANFValue).init(a);
            defer call_args.deinit();
            var ns = try interp.computeNewState(a, &anf, "run", cs, call_args, &.{});
            defer ns.deinit();
            return ns.get("result").?.int;
        }
    };
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(@as(i64, -42), try H.mul(allocator, 6, -7));
    const got = H.mul(allocator, std.math.maxInt(i64), 2);
    if (got) |v| {
        std.debug.print("N-163: maxInt(i64) * 2 returned {d}\n", .{v});
        return error.TestUnexpectedResult;
    } else |_| {}
}

// N-281 (sibling of N-163): shared plumbing for the four checks below. Each
// runs a tiny single-binding method through the full interpreter (same path
// `computeNewState` uses in production) and reads back `result`.
fn n281Run(a: std.mem.Allocator, body: []ANFBinding) !i64 {
    var props = [_]ANFProperty{.{ .name = "result", .type_name = "int", .readonly = false }};
    var methods = [_]ANFMethod{.{ .name = "run", .params = &.{}, .body = body, .is_public = true }};
    const anf = ANFProgram{ .contract_name = "AddSubAbsProbe", .properties = &props, .methods = &methods };
    var cs = std.StringHashMap(ANFValue).init(a);
    defer cs.deinit();
    try cs.put("result", .{ .int = 0 });
    var call_args = std.StringHashMap(ANFValue).init(a);
    defer call_args.deinit();
    var ns = try interp.computeNewState(a, &anf, "run", cs, call_args, &.{});
    defer ns.deinit();
    return ns.get("result").?.int;
}

fn n281BinOp(a: std.mem.Allocator, op: []const u8, x: i64, y: i64) !i64 {
    var body = [_]ANFBinding{
        .{ .name = "a", .value = .{ .load_const = .{ .value = .{ .int = x } } } },
        .{ .name = "b", .value = .{ .load_const = .{ .value = .{ .int = y } } } },
        .{ .name = "r", .value = .{ .bin_op = .{ .op = op, .left = "a", .right = "b" } } },
        .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "r" } } },
    };
    return n281Run(a, &body);
}

fn n281UnaryNegate(a: std.mem.Allocator, x: i64) !i64 {
    var body = [_]ANFBinding{
        .{ .name = "a", .value = .{ .load_const = .{ .value = .{ .int = x } } } },
        .{ .name = "r", .value = .{ .unary_op = .{ .op = "-", .operand = "a" } } },
        .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "r" } } },
    };
    return n281Run(a, &body);
}

fn n281Abs(a: std.mem.Allocator, x: i64) !i64 {
    const args = [_][]const u8{"a"};
    var body = [_]ANFBinding{
        .{ .name = "a", .value = .{ .load_const = .{ .value = .{ .int = x } } } },
        .{ .name = "r", .value = .{ .call = .{ .func = "abs", .args = args[0..] } } },
        .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "r" } } },
    };
    return n281Run(a, &body);
}

fn n281ExpectRefused(what: []const u8, got: anyerror!i64) !void {
    if (got) |v| {
        std.debug.print("N-281: {s} must be refused, returned {d}\n", .{ what, v });
        return error.TestUnexpectedResult;
    } else |_| {}
}

// N-281: `a + b` past i64 must be refused, not wrapped (`+%`).
// Proves: the binop `+` fails closed on i64 overflow and still adds in
// range. Does NOT prove: `-` / unary `-` / `abs` overflow (separate tests
// below) or the compiled script itself.
test "N-281: SDK ANF interpreter refuses an i64-overflowing binop +" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(@as(i64, 13), try n281BinOp(allocator, "+", 6, 7));
    try n281ExpectRefused("maxInt(i64) + 1", n281BinOp(allocator, "+", std.math.maxInt(i64), 1));
}

// N-281: `a - b` past i64 must be refused, not wrapped (`-%`).
// Proves: the binop `-` fails closed on i64 underflow and still subtracts
// in range. Does NOT prove: `+` / unary `-` / `abs` overflow or the script.
test "N-281: SDK ANF interpreter refuses an i64-overflowing binop -" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(@as(i64, -1), try n281BinOp(allocator, "-", 6, 7));
    try n281ExpectRefused("minInt(i64) - 1", n281BinOp(allocator, "-", std.math.minInt(i64), 1));
}

// N-281: unary `-` on `minInt(i64)` (`-minInt(i64) == maxInt(i64) + 1`) must
// be refused, not wrapped (`-%`).
// Proves: `unary_op -` fails closed at `minInt(i64)` and still negates in
// range. Does NOT prove: `+` / `-` / `abs` overflow or the compiled script.
test "N-281: SDK ANF interpreter refuses an i64-overflowing unary -" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(@as(i64, -6), try n281UnaryNegate(allocator, 6));
    try n281ExpectRefused("-minInt(i64)", n281UnaryNegate(allocator, std.math.minInt(i64)));
}

// N-281: `abs(minInt(i64))` (`== maxInt(i64) + 1`) must be refused, not
// wrapped or crashed by a native `-v` overflow.
// Proves: `call abs` fails closed at `minInt(i64)` and still computes the
// right absolute value either side of it. Does NOT prove: `+` / `-` / unary
// `-` overflow or the compiled script itself.
test "N-281: SDK ANF interpreter refuses abs(minInt(i64))" {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(@as(i64, 6), try n281Abs(allocator, -6));
    try n281ExpectRefused("abs(minInt(i64))", n281Abs(allocator, std.math.minInt(i64)));
}
