//! `split` in the Zig ANF interpreter must bind the RIGHT half.
//!
//! `split(data, index)` is single-valued and binds the bytes from `index`
//! onwards — the RIGHT half. That is what `spec/grammar.md` specifies, what all
//! seven typecheckers return, what `05-stack-lower.ts` and its six peers emit
//! (`OP_SPLIT OP_NIP`), and what the TypeScript interpreter
//! (`packages/runar-testing/src/interpreter/interpreter.ts`) computes.
//!
//! This interpreter returned the LEFT half, under a comment claiming "in ANF
//! the second result is in a separate binding" — there is no such binding, and
//! no surface can name one. So an artifact run off-chain through this
//! interpreter and then spent on-chain would take two different branches for
//! any contract that splits: the quiet, expensive kind of divergence, because
//! nothing errors.
//!
//! The pair below is the guard: `split` and `left` cut at the same index and
//! must return the two DIFFERENT halves. A single-sided assertion would pass
//! on an interpreter that returned `data` unchanged.

const std = @import("std");
const interp = @import("sdk_anf_interpreter.zig");

const ANFProgram = interp.ANFProgram;
const ANFProperty = interp.ANFProperty;
const ANFParam = interp.ANFParam;
const ANFMethod = interp.ANFMethod;
const ANFBinding = interp.ANFBinding;
const ANFValue = interp.ANFValue;

/// A stateful contract whose only method writes `<builtin>(data, 2)` into the
/// `tag` property, so the result is observable in the returned state.
///
/// ANF body:
///   t_data = load_param data
///   t_idx  = load_const 2
///   t_out  = call <builtin>(t_data, t_idx)
///   _      = update_prop tag = t_out
fn buildCutAnf(comptime builtin: []const u8) ANFProgram {
    const props = struct {
        var p = [_]ANFProperty{
            .{ .name = "tag", .type_name = "bytes", .readonly = false },
        };
    };
    const params = struct {
        var p = [_]ANFParam{
            .{ .name = "data", .type_name = "bytes" },
        };
    };
    const call_args = struct {
        var a = [_][]const u8{ "t_data", "t_idx" };
    };
    const body = struct {
        var b = [_]ANFBinding{
            .{ .name = "t_data", .value = .{ .load_param = .{ .name = "data" } } },
            .{ .name = "t_idx", .value = .{ .load_const = .{ .value = .{ .int = 2 } } } },
            .{ .name = "t_out", .value = .{ .call = .{ .func = builtin, .args = &call_args.a } } },
            .{ .name = "updTag", .value = .{ .update_prop = .{ .name = "tag", .value = "t_out" } } },
        };
    };
    const methods = struct {
        var m = [_]ANFMethod{
            .{ .name = "cut", .params = &params.p, .body = &body.b, .is_public = true },
        };
    };
    return .{
        .contract_name = "Cut",
        .properties = &props.p,
        .methods = &methods.m,
    };
}

/// Runs `cut("aabbccdd")` through the interpreter and returns the hex the
/// builtin produced. Caller frees.
fn runCut(allocator: std.mem.Allocator, comptime builtin: []const u8) ![]u8 {
    const anf = buildCutAnf(builtin);

    var current_state = std.StringHashMap(ANFValue).init(allocator);
    defer current_state.deinit();
    try current_state.put("tag", .{ .bytes = "" });

    var args = std.StringHashMap(ANFValue).init(allocator);
    defer args.deinit();
    try args.put("data", .{ .bytes = "aabbccdd" });

    var result = try interp.executeStrict(allocator, &anf, "cut", current_state, args, &.{});
    defer {
        result.state.deinit();
        for (result.data_outputs) |d| allocator.free(d.script);
        allocator.free(result.data_outputs);
        for (result.raw_outputs) |d| allocator.free(d.script);
        allocator.free(result.raw_outputs);
        for (result.outputs) |o| if (o.kind == .raw and o.script.len > 0) allocator.free(@constCast(o.script));
        allocator.free(result.outputs);
    }

    // `result.state` is mixed-ownership: `runMethod` dupes the bytes a method's
    // state delta produced into the caller allocator, so `tag` is ours to free
    // once its contents have been copied out.
    const produced = result.state.get("tag").?.bytes;
    const copy = try allocator.dupe(u8, produced);
    allocator.free(@constCast(produced));
    return copy;
}

test "split(data, 2) binds the RIGHT half, matching OP_SPLIT OP_NIP" {
    const allocator = std.testing.allocator;
    const got = try runCut(allocator, "split");
    defer allocator.free(got);
    try std.testing.expectEqualStrings("ccdd", got);
}

test "left(data, 2) binds the LEFT half — the other side of the same cut" {
    const allocator = std.testing.allocator;
    const got = try runCut(allocator, "left");
    defer allocator.free(got);
    try std.testing.expectEqualStrings("aabb", got);
}
