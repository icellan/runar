//! N-171 (sibling of F-274) — the SDK ANF interpreter's `split`/`substr`
//! must return what the compiled script returns, for every vector in the
//! shared on-chain file fixtures/n171-split-substr-builtins-onchain.json.
//!
//! That file is the oracle: every row is executed on @bsv/sdk Spend.validate
//! by packages/runar-testing/src/__tests__/n171-split-substr-builtins-onchain.test.ts.
//!
//! `split(data, index)` used to clamp `index` into `[0, size(data)]` instead
//! of aborting (`@max(0, idx)` / `@min(idx * 2, hex.len)`), the same bug
//! shape F-274 fixed for `left`/`right`. `substr` used to clamp the same way.
//! Both now abort through `splitBuiltinAborts`.
//!
//! R67: `substr` is now fully abort-faithful. Its one caller via
//! `extractScriptCode` (`FungibleToken#merge`) used to get an empty dummy
//! scriptCode, turning a realistic `substr(sc, ...)` call into a POSITIVE
//! overflow the old clamp had to swallow to avoid breaking `prepareCall`.
//! `extractScriptCode` now returns the contract's own REAL codePart
//! (`sdk_contract.zig`'s call path, via `MockEnv.script_code_hex`), so
//! `substr` can be fully abort-faithful without starving `merge` of a
//! realistic scriptCode.
//!
//! Proves: for every row the interpreter returns the on-chain value, or
//! returns its abort error where the script aborts — never a value — for
//! BOTH `split` and `substr`, covering n=0, interior, n=len(data),
//! n>len(data), n<0, and an empty `data` input.
//! Does NOT prove: inputs outside the file, or the script itself (the
//! oracle).

const std = @import("std");
const interp = @import("sdk_anf_interpreter.zig");

const ANFProgram = interp.ANFProgram;
const ANFProperty = interp.ANFProperty;
const ANFMethod = interp.ANFMethod;
const ANFBinding = interp.ANFBinding;
const ANFValue = interp.ANFValue;

const vectors_json = @embedFile("fixtures/n171-split-substr-builtins-onchain.json");

/// Run `result = split(data, a)` or `result = substr(data, a, b)` through
/// the interpreter, depending on `func`.
fn runCall(allocator: std.mem.Allocator, func: []const u8, data: []const u8, a: i64, b: i64) ![]const u8 {
    const names = [_][]const u8{ "a", "b", "c" };
    const call_args: []const []const u8 = if (std.mem.eql(u8, func, "substr")) names[0..3] else names[0..2];
    var body = [_]ANFBinding{
        .{ .name = names[0], .value = .{ .load_const = .{ .value = .{ .bytes = data } } } },
        .{ .name = names[1], .value = .{ .load_const = .{ .value = .{ .int = a } } } },
        .{ .name = names[2], .value = .{ .load_const = .{ .value = .{ .int = b } } } },
        .{ .name = "r", .value = .{ .call = .{ .func = func, .args = call_args } } },
        .{ .name = "u", .value = .{ .update_prop = .{ .name = "result", .value = "r" } } },
    };

    var props = [_]ANFProperty{
        .{ .name = "result", .type_name = "ByteString", .readonly = false },
    };
    var methods = [_]ANFMethod{
        .{ .name = "run", .params = &.{}, .body = &body, .is_public = true },
    };
    const anf = ANFProgram{ .contract_name = "SplitSubstrProbe", .properties = &props, .methods = &methods };
    var cs = std.StringHashMap(ANFValue).init(allocator);
    defer cs.deinit();
    try cs.put("result", .{ .bytes = "" });
    var call_env = std.StringHashMap(ANFValue).init(allocator);
    defer call_env.deinit();
    var ns = try interp.computeNewState(allocator, &anf, "run", cs, call_env, &.{});
    defer ns.deinit();
    return switch (ns.get("result").?) {
        .bytes => |v| v,
        else => error.UnexpectedResultKind,
    };
}

test "N-171: SDK ANF interpreter split/substr return the on-chain value for every shared vector" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, vectors_json, .{});
    defer parsed.deinit();

    const cases = parsed.value.object.get("cases").?.array.items;
    try std.testing.expect(cases.len > 0);

    var mismatches: usize = 0;
    for (cases) |c| {
        const obj = c.object;
        const func = obj.get("fn").?.string;
        const data = obj.get("data").?.string;
        const a: i64 = @intCast(obj.get("a").?.integer);
        const b: i64 = @intCast(obj.get("b").?.integer);
        const expect = obj.get("expect").?;

        const got = runCall(allocator, func, data, a, b);
        const ok = switch (expect) {
            .string => |s| if (std.mem.eql(u8, s, "abort"))
                std.meta.isError(got)
            else if (got) |g| std.mem.eql(u8, g, s) else |_| false,
            else => false,
        };
        if (!ok) {
            mismatches += 1;
            std.debug.print("N-171 interpreter/on-chain mismatch: {s}({s}, {d}, {d}) interpreter={any} on-chain={any}\n", .{
                func, data, a, b, got, expect,
            });
        }
        if (got) |g| allocator.free(g) else |_| {}
    }
    try std.testing.expectEqual(@as(usize, 0), mismatches);
}
