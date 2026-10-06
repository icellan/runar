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
//! Does NOT prove: the `wideCases` rows (operands beyond i64: log2 saturating
//! at 64, gcd's 256-step partial remainder, sqrt's 2^495 guard) — this
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
