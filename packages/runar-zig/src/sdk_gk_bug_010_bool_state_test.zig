//! GK-BUG-010: a boolean state field accepts only `.boolean`.
//!
//! `encodeStateValue` encoded `.int` as `i != 0` and `.bytes` / `.big_int` /
//! `.empty_sig` as false, while each peer tier had its own coercion rule (Ruby
//! wrote 01 for 0, Java 00 for 1): one input, different on-chain bytes per
//! tier. Every tier now refuses a non-boolean, as the num2bin arm (N-084)
//! refuses a non-integer.
//!
//! Proves: `serializeState` returns `error.NotABoolean` for `.int` 0 / 1,
//! `.bytes` ("true" / "01" / ""), `.big_int` and `.empty_sig` in both
//! spellings of the type, and `.boolean` true / false keep 01 / 00. Does not
//! prove anything on chain, nor the other six SDKs.

const std = @import("std");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");

const TYPES = [_][]const u8{ "bool", "boolean" };

test "GK-BUG-010: boolean state fields refuse a non-boolean value" {
    const allocator = std.testing.allocator;
    const bad = [_]types.StateValue{
        .{ .int = 0 },
        .{ .int = 1 },
        .{ .bytes = "true" },
        .{ .bytes = "01" },
        .{ .bytes = "" },
        .{ .big_int = "1" },
        .empty_sig,
    };
    for (TYPES) |t| {
        const fields = [_]types.StateField{.{ .name = "flag", .type_name = t, .index = 0 }};
        for (bad) |v| {
            const vals = [_]types.StateValue{v};
            try std.testing.expectError(error.NotABoolean, state_mod.serializeState(allocator, &fields, &vals));
        }
    }
}

test "GK-BUG-010: true / false keep their bytes" {
    const allocator = std.testing.allocator;
    for (TYPES) |t| {
        const fields = [_]types.StateField{.{ .name = "flag", .type_name = t, .index = 0 }};
        for ([_]bool{ true, false }) |b| {
            const vals = [_]types.StateValue{.{ .boolean = b }};
            const out = try state_mod.serializeState(allocator, &fields, &vals);
            defer allocator.free(out);
            try std.testing.expectEqualStrings(if (b) "01" else "00", out);
        }
    }
}

// The refusal above must not reject a boolean the SDK computed itself. The
// language declares `bool(x): boolean`, but the ANF interpreter returned
// `.int = 1` / `.int = 0`, so a contract doing `this.flag = bool(this.count)`
// produced a post-state `anfToStateValue` maps to `.int`, which
// `serializeState` now refuses with error.NotABoolean.
const interp = @import("sdk_anf_interpreter.zig");

test "GK-BUG-010: an interpreter-computed boolean state field is a .boolean" {
    const allocator = std.testing.allocator;
    const call_args = [_][]const u8{"c"};
    var body = [_]interp.ANFBinding{
        .{ .name = "c", .value = .{ .load_prop = .{ .name = "count" } } },
        .{ .name = "b", .value = .{ .call = .{ .func = "bool", .args = &call_args } } },
        .{ .name = "u", .value = .{ .update_prop = .{ .name = "flag", .value = "b" } } },
    };
    var props = [_]interp.ANFProperty{
        .{ .name = "count", .type_name = "bigint", .readonly = false },
        .{ .name = "flag", .type_name = "bool", .readonly = false },
    };
    var methods = [_]interp.ANFMethod{
        .{ .name = "step", .params = &.{}, .body = &body, .is_public = true },
    };
    const anf = interp.ANFProgram{ .contract_name = "BoolProbe", .properties = &props, .methods = &methods };
    for ([_]i64{ 5, 0 }) |count| {
        var cs = std.StringHashMap(interp.ANFValue).init(allocator);
        defer cs.deinit();
        try cs.put("count", .{ .int = count });
        try cs.put("flag", .{ .boolean = count == 0 });
        var call_env = std.StringHashMap(interp.ANFValue).init(allocator);
        defer call_env.deinit();
        var ns = try interp.computeNewState(allocator, &anf, "step", cs, call_env, &.{});
        defer ns.deinit();
        const flag = ns.get("flag").?;
        try std.testing.expect(flag == .boolean);
        try std.testing.expectEqual(count != 0, flag.boolean);
        const fields = [_]types.StateField{.{ .name = "flag", .type_name = "bool", .index = 0 }};
        const vals = [_]types.StateValue{.{ .boolean = flag.boolean }};
        const out = try state_mod.serializeState(allocator, &fields, &vals);
        defer allocator.free(out);
        try std.testing.expectEqualStrings(if (count != 0) "01" else "00", out);
    }
}
