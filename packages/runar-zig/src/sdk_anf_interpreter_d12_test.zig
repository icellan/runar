//! D12 BM-F1 / BM-F5 / BM-F7 / reverseBytes / D2: the SDK ANF interpreter
//! must return what the compiled script returns, or refuse -- never invent a
//! value or abort the process.
//!
//! - BM-F1: `bin2num` stripped trailing 0x00 sign padding and read the sign off
//!   the previous byte (`ff00` -> -127, script 255), and wrapped > 8 bytes.
//! - BM-F5: `num2bin` / `int2str` truncated a value too wide for the field and
//!   returned "" for a negative width; OP_NUM2BIN aborts. `int2str` returned none.
//! - BM-F7: `gcd(minInt(i64), x)` panicked on `-a` (integer overflow).
//! - reverseBytes: the compiled script reverses only the first 520 bytes, so a
//!   longer input is refused.
//! - D2: `extractOutpoint` returned none; it now answers MockEnv.outpoint_hex.
//!
//! Proves: the values / refusals above through `computeNewState`.
//! Does NOT prove: script execution (vectors are the documented opcode semantics,
//! cross-checked on @bsv/sdk Spend in the D12 review repros).

const std = @import("std");
const interp = @import("sdk_anf_interpreter.zig");

const ANFProgram = interp.ANFProgram;
const ANFProperty = interp.ANFProperty;
const ANFMethod = interp.ANFMethod;
const ANFBinding = interp.ANFBinding;
const ANFValue = interp.ANFValue;

const Arg = union(enum) { int: i64, bytes: []const u8 };

const Out = union(enum) { int: i64, bytes: []const u8, abort };

fn run(a: std.mem.Allocator, func: []const u8, args: []const Arg, mock_env: ?*interp.MockEnv) !ANFValue {
    const names = [_][]const u8{ "a", "b", "c" };
    var body: [5]ANFBinding = undefined;
    for (args, 0..) |arg, i| {
        const v: ANFValue = switch (arg) {
            .int => |n| .{ .int = n },
            .bytes => |h| .{ .bytes = h },
        };
        body[i] = .{ .name = names[i], .value = .{ .load_const = .{ .value = v } } };
    }
    const n = args.len;
    body[n] = .{ .name = "r", .value = .{ .call = .{ .func = func, .args = names[0..n] } } };
    body[n + 1] = .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "r" } } };
    var props = [_]ANFProperty{.{ .name = "result", .type_name = "int", .readonly = false }};
    var methods = [_]ANFMethod{.{ .name = "run", .params = &.{}, .body = body[0 .. n + 2], .is_public = true }};
    const anf = ANFProgram{ .contract_name = "D12Probe", .properties = &props, .methods = &methods };
    var cs = std.StringHashMap(ANFValue).init(a);
    defer cs.deinit();
    try cs.put("result", .{ .int = 0 });
    var call_args = std.StringHashMap(ANFValue).init(a);
    defer call_args.deinit();
    var ns = if (mock_env) |me|
        (try interp.computeNewStateWithMockEnv(a, &anf, "run", cs, call_args, &.{}, me)).state
    else
        try interp.computeNewState(a, &anf, "run", cs, call_args, &.{});
    defer ns.deinit();
    return ns.get("result").?;
}

fn expectOut(func: []const u8, args: []const Arg, want: Out) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    switch (want) {
        .abort => {
            const r = run(a, func, args, null);
            if (r) |v| {
                std.debug.print("{s}: expected an abort, got {any}\n", .{ func, v });
                return error.TestExpectedAbort;
            } else |e| try std.testing.expectEqual(error.ScriptNumberError, e);
        },
        .int => |w| {
            const v = try run(a, func, args, null);
            try std.testing.expect(v == .int);
            try std.testing.expectEqual(w, v.int);
        },
        .bytes => |w| {
            const v = try run(a, func, args, null);
            try std.testing.expect(v == .bytes);
            try std.testing.expectEqualStrings(w, v.bytes);
        },
    }
}

test "D12 BM-F1: bin2num reads the sign off the last byte and refuses > i64" {
    try expectOut("bin2num", &.{.{ .bytes = "ff00" }}, .{ .int = 255 });
    try expectOut("bin2num", &.{.{ .bytes = "8000" }}, .{ .int = 128 });
    try expectOut("bin2num", &.{.{ .bytes = "ffff00" }}, .{ .int = 65535 });
    try expectOut("bin2num", &.{.{ .bytes = "ff80" }}, .{ .int = -255 });
    try expectOut("bin2num", &.{.{ .bytes = "81" }}, .{ .int = -1 });
    try expectOut("bin2num", &.{.{ .bytes = "0080" }}, .{ .int = 0 });
    try expectOut("bin2num", &.{.{ .bytes = "0100000000000000" }}, .{ .int = 1 });
    try expectOut("bin2num", &.{.{ .bytes = "ffffffffffffff7f" }}, .{ .int = std.math.maxInt(i64) });
    try expectOut("bin2num", &.{.{ .bytes = "ffffffffffffffff" }}, .{ .int = -std.math.maxInt(i64) });
    try expectOut("bin2num", &.{.{ .bytes = "000000000000008000" }}, .abort);
    try expectOut("bin2num", &.{.{ .bytes = "0102030405060708090a" }}, .abort);
    try expectOut("bin2num", &.{.{ .bytes = "ff" ** 32 }}, .abort);
}

test "D12 BM-F5: num2bin / int2str refuse a too-narrow or negative width" {
    try expectOut("num2bin", &.{ .{ .int = 40000 }, .{ .int = 2 } }, .abort);
    try expectOut("num2bin", &.{ .{ .int = 128 }, .{ .int = 1 } }, .abort);
    try expectOut("num2bin", &.{ .{ .int = 1 }, .{ .int = 0 } }, .abort);
    try expectOut("num2bin", &.{ .{ .int = 5 }, .{ .int = -1 } }, .abort);
    try expectOut("num2bin", &.{ .{ .int = 0 }, .{ .int = -1 } }, .abort);
    try expectOut("int2str", &.{ .{ .int = 40000 }, .{ .int = 2 } }, .abort);
    try expectOut("num2bin", &.{ .{ .int = 0 }, .{ .int = 0 } }, .{ .bytes = "" });
    try expectOut("num2bin", &.{ .{ .int = 255 }, .{ .int = 2 } }, .{ .bytes = "ff00" });
    try expectOut("int2str", &.{ .{ .int = 5 }, .{ .int = 2 } }, .{ .bytes = "0500" });
    try expectOut("int2str", &.{ .{ .int = -1 }, .{ .int = 2 } }, .{ .bytes = "0180" });
}

test "D12 BM-F7: gcd(minInt(i64), x) does not abort the process" {
    try expectOut("gcd", &.{ .{ .int = std.math.minInt(i64) }, .{ .int = 6 } }, .{ .int = 2 });
    try expectOut("gcd", &.{ .{ .int = 6 }, .{ .int = std.math.minInt(i64) } }, .{ .int = 2 });
    // 2^63 is outside i64: refuse rather than wrap.
    try expectOut("gcd", &.{ .{ .int = std.math.minInt(i64) }, .{ .int = 0 } }, .abort);
    try expectOut("gcd", &.{ .{ .int = std.math.minInt(i64) }, .{ .int = std.math.minInt(i64) } }, .abort);
}

test "D12: reverseBytes refuses inputs over 520 bytes" {
    try expectOut("reverseBytes", &.{.{ .bytes = "01" ++ "00" ** 519 }}, .{ .bytes = "00" ** 519 ++ "01" });
    try expectOut("reverseBytes", &.{.{ .bytes = "00" ** 521 }}, .abort);
}

test "D12 D2: extractOutpoint answers the MockEnv outpoint" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var me = interp.MockEnv.init(a);
    defer me.deinit();
    const op = "11" ** 32 ++ "02000000";
    me.outpoint_hex = op;
    me.locktime = 500;
    me.sequence = 0xffffffff;
    const v = try run(a, "extractOutpoint", &.{.{ .int = 0 }}, &me);
    try std.testing.expect(v == .bytes);
    try std.testing.expectEqualStrings(op, v.bytes);
    try std.testing.expectEqual(@as(i64, 500), (try run(a, "extractLocktime", &.{.{ .int = 0 }}, &me)).int);
    try std.testing.expectEqual(@as(i64, 0xffffffff), (try run(a, "extractSequence", &.{.{ .int = 0 }}, &me)).int);
}
