//! F-274 (CL-BUG-163) — the SDK ANF interpreter's `left`/`right` must return
//! what the compiled script returns, for every vector in the shared on-chain
//! file fixtures/f274-split-builtins-onchain.json.
//!
//! That file is the oracle: every row is executed on @bsv/sdk Spend.validate by
//! packages/runar-testing/src/__tests__/f274-split-builtins-onchain.test.ts.
//!
//! `right(data, 0)` used to compile to a clamp (`hex_len >= hex.len -> return
//! the whole hex`) for a LENGTH PAST THE END too, instead of the abort
//! OP_SPLIT actually produces; `left`/`right` also silently treated a
//! negative `length` as zero. Both now abort through `splitBuiltinAborts`.
//!
//! Proves: for every `cases` row the interpreter returns the on-chain value,
//! or returns its abort error where the script aborts — never a value —
//! covering n=0, n=len(data), n>len(data), n<0, and an empty `data` input.
//! Does NOT prove: inputs outside the file, or the script itself (the oracle).

const std = @import("std");
const interp = @import("sdk_anf_interpreter.zig");

const ANFProgram = interp.ANFProgram;
const ANFProperty = interp.ANFProperty;
const ANFMethod = interp.ANFMethod;
const ANFBinding = interp.ANFBinding;
const ANFValue = interp.ANFValue;

const vectors_json = @embedFile("fixtures/f274-split-builtins-onchain.json");

/// Run `result = func(data, n)` through the interpreter.
fn runCall(a: std.mem.Allocator, func: []const u8, data: []const u8, n: i64) ![]const u8 {
    const names = [_][]const u8{ "a", "b" };
    var body = [_]ANFBinding{
        .{ .name = names[0], .value = .{ .load_const = .{ .value = .{ .bytes = data } } } },
        .{ .name = names[1], .value = .{ .load_const = .{ .value = .{ .int = n } } } },
        .{ .name = "r", .value = .{ .call = .{ .func = func, .args = &names } } },
        .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "r" } } },
    };

    var props = [_]ANFProperty{
        .{ .name = "result", .type_name = "ByteString", .readonly = false },
    };
    var methods = [_]ANFMethod{
        .{ .name = "run", .params = &.{}, .body = &body, .is_public = true },
    };
    const anf = ANFProgram{ .contract_name = "SplitProbe", .properties = &props, .methods = &methods };
    var cs = std.StringHashMap(ANFValue).init(a);
    defer cs.deinit();
    try cs.put("result", .{ .bytes = "" });
    var call_args = std.StringHashMap(ANFValue).init(a);
    defer call_args.deinit();
    var ns = try interp.computeNewState(a, &anf, "run", cs, call_args, &.{});
    defer ns.deinit();
    return switch (ns.get("result").?) {
        .bytes => |v| v,
        else => error.UnexpectedResultKind,
    };
}

test "F-274: SDK ANF interpreter left/right return the on-chain value for every shared vector" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, vectors_json, .{});
    defer parsed.deinit();

    const cases = parsed.value.object.get("cases").?.array.items;
    try std.testing.expect(cases.len > 0);

    var mismatches: usize = 0;
    for (cases) |c| {
        const obj = c.object;
        const name = obj.get("fn").?.string;
        const data = obj.get("data").?.string;
        const n: i64 = @intCast(obj.get("n").?.integer);
        const expect = obj.get("expect").?;

        const got = runCall(allocator, name, data, n);
        const ok = switch (expect) {
            .string => |s| if (std.mem.eql(u8, s, "abort"))
                std.meta.isError(got)
            else if (got) |g| std.mem.eql(u8, g, s) else |_| false,
            else => false,
        };
        if (!ok) {
            mismatches += 1;
            std.debug.print("F-274 interpreter/on-chain mismatch: {s}({s}, {d}) interpreter={any} on-chain={any}\n", .{
                name, data, n, got, expect,
            });
        }
        if (got) |g| allocator.free(g) else |_| {}
    }
    try std.testing.expectEqual(@as(usize, 0), mismatches);
}
