//! Dead Code Elimination pass for ANF IR.
//!
//! Removes bindings whose results are never referenced by other bindings,
//! preserving bindings with observable side effects (assert, update_prop,
//! check_preimage, add_output, etc.).
//!
//! Runs as a standalone pass after constant folding (pass 4.25) and before
//! EC optimization (pass 4.5). Also used internally by the EC optimizer
//! to clean up temporaries created during algebraic simplification.

const std = @import("std");
const types = @import("../ir/types.zig");
const Allocator = std.mem.Allocator;

// ============================================================================
// Public API
// ============================================================================

/// Eliminate dead bindings across all methods in the program.
/// Returns a new program with unreferenced bindings removed.
/// When no dead code is found, returns the input program unchanged (no allocation).
pub fn eliminateDeadCode(allocator: Allocator, program: types.ANFProgram) !types.ANFProgram {
    var any_changed = false;
    const new_methods = try allocator.alloc(types.ANFMethod, program.methods.len);
    errdefer allocator.free(new_methods);

    for (program.methods, 0..) |method, i| {
        const optimized_body = try eliminateDeadBindings(allocator, method.body);
        const changed = optimized_body.ptr != method.body.ptr;
        if (changed) any_changed = true;
        new_methods[i] = .{
            .name = method.name,
            .is_public = method.is_public,
            .params = method.params,
            .bindings = method.bindings,
            .body = optimized_body,
        };
    }

    if (!any_changed) {
        allocator.free(new_methods);
        return program;
    }

    return .{
        .contract_name = program.contract_name,
        .parent_class = program.parent_class,
        .properties = program.properties,
        .constructor = program.constructor,
        .methods = new_methods,
    };
}

// ============================================================================
// Core algorithm
// ============================================================================

/// Remove bindings whose results are never referenced.
/// Iterates until stable, handling transitive dead code.
/// Caller must free the returned slice. The input `body` is NOT freed by this function.
pub fn eliminateDeadBindings(allocator: Allocator, body: []types.ANFBinding) ![]types.ANFBinding {
    var current = body;
    var owns_current = false;
    var changed = true;

    while (changed) {
        changed = false;
        var used = std.StringHashMap(void).init(allocator);
        defer used.deinit();

        for (current) |binding| try collectRefs(binding.value, &used);

        var filtered = std.ArrayListUnmanaged(types.ANFBinding).empty;
        defer filtered.deinit(allocator);

        for (current) |binding| {
            if (used.contains(binding.name) or hasSideEffect(binding.value)) {
                try filtered.append(allocator, binding);
            } else {
                changed = true;
            }
        }

        const new_slice = try filtered.toOwnedSlice(allocator);
        if (owns_current) allocator.free(current);
        current = new_slice;
        owns_current = true;
    }

    return current;
}

/// Walk an ANFValue and collect all binding name references.
fn collectRefs(v: types.ANFValue, used: *std.StringHashMap(void)) !void {
    switch (v) {
        .load_param => return,
        .load_const => |lc| {
            switch (lc.value) {
                .string => |s| {
                    if (std.mem.startsWith(u8, s, "@ref:"))
                        try used.put(s[5..], {});
                },
                else => {},
            }
            return;
        },
        .load_prop, .get_state_script => return,
        .bin_op => |bo| {
            try used.put(bo.left, {});
            try used.put(bo.right, {});
        },
        .unary_op => |uo| try used.put(uo.operand, {}),
        .call => |c| {
            for (c.args) |arg| try used.put(arg, {});
        },
        .method_call => |mc| {
            try used.put(mc.object, {});
            for (mc.args) |arg| try used.put(arg, {});
        },
        .@"if" => |if_val| {
            try used.put(if_val.cond, {});
            for (if_val.then) |b| try collectRefs(b.value, used);
            for (if_val.@"else") |b| try collectRefs(b.value, used);
        },
        .loop => |loop_val| {
            for (loop_val.body) |b| try collectRefs(b.value, used);
        },
        .assert => |a| try used.put(a.value, {}),
        .update_prop => |up| try used.put(up.value, {}),
        .check_preimage => |cp| try used.put(cp.preimage, {}),
        .deserialize_state => |ds| try used.put(ds.preimage, {}),
        .add_output => |ao| {
            try used.put(ao.satoshis, {});
            for (ao.state_values) |sv| try used.put(sv, {});
            if (ao.preimage.len > 0) try used.put(ao.preimage, {});
        },
        .add_raw_output => |aro| {
            try used.put(aro.satoshis, {});
            if (aro.script_bytes.len > 0) try used.put(aro.script_bytes, {});
        },
        .add_data_output => |ado| {
            try used.put(ado.satoshis, {});
            if (ado.script_bytes.len > 0) try used.put(ado.script_bytes, {});
        },
        .array_literal => |al| {
            for (al.elements) |e| try used.put(e, {});
        },
    }
}

/// Return true if this value kind has observable side effects.
pub fn hasSideEffect(v: types.ANFValue) bool {
    return switch (v) {
        .assert, .update_prop, .check_preimage, .deserialize_state,
        .add_output, .add_raw_output, .add_data_output, .@"if", .loop, .call, .method_call,
        => true,
        else => false,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "eliminateDeadBindings removes unreferenced pure bindings" {
    const alloc = std.testing.allocator;

    var body_arr = [_]types.ANFBinding{
        .{ .name = "t0", .value = .{ .load_const = .{ .value = .{ .string = "dead" } } }, .source_loc = null },
        .{ .name = "t1", .value = .{ .load_const = .{ .value = .{ .integer = 42 } } }, .source_loc = null },
        .{ .name = "t2", .value = .{ .assert = .{ .value = "t1" } }, .source_loc = null },
    };

    const result = try eliminateDeadBindings(alloc, &body_arr);
    defer alloc.free(result);

    // t0 is dead (not referenced), t1 is kept (referenced by t2), t2 is kept (side effect)
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("t1", result[0].name);
    try std.testing.expectEqualStrings("t2", result[1].name);
}

test "eliminateDeadBindings handles transitive dead code" {
    const alloc = std.testing.allocator;

    var body_arr = [_]types.ANFBinding{
        .{ .name = "t0", .value = .{ .load_const = .{ .value = .{ .string = "dead_base" } } }, .source_loc = null },
        .{ .name = "t1", .value = .{ .load_const = .{ .value = .{ .string = "@ref:t0" } } }, .source_loc = null },
        .{ .name = "t2", .value = .{ .load_const = .{ .value = .{ .integer = 1 } } }, .source_loc = null },
        .{ .name = "t3", .value = .{ .assert = .{ .value = "t2" } }, .source_loc = null },
    };

    const result = try eliminateDeadBindings(alloc, &body_arr);
    defer alloc.free(result);

    // t0 referenced by t1, but t1 itself is dead → both eliminated transitively
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("t2", result[0].name);
    try std.testing.expectEqualStrings("t3", result[1].name);
}

test "eliminateDeadBindings preserves side-effecting bindings" {
    const alloc = std.testing.allocator;

    var body_arr = [_]types.ANFBinding{
        .{ .name = "t0", .value = .{ .load_const = .{ .value = .{ .integer = 5 } } }, .source_loc = null },
        .{ .name = "t1", .value = .{ .update_prop = .{ .name = "count", .value = "t0" } }, .source_loc = null },
    };

    const result = try eliminateDeadBindings(alloc, &body_arr);
    defer alloc.free(result);

    // Both kept: t0 is referenced by t1, t1 has side effect
    try std.testing.expectEqual(@as(usize, 2), result.len);
}
