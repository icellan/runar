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
        .raw_script => {
            // Opaque byte span — no SSA operand refs. Stack effect is declared
            // via in_arity / out_arity and consumed by the stack lowerer.
        },
    }
}

/// Return true if this value kind has observable side effects.
/// F-003: every ANFValue variant is enumerated explicitly (no `else`) so
/// adding a new variant fails at Zig compile time here instead of silently
/// defaulting to "pure" — which would let DCE delete an effectful binding.
pub fn hasSideEffect(v: types.ANFValue) bool {
    return switch (v) {
        .assert, .update_prop, .check_preimage, .deserialize_state,
        .add_output, .add_raw_output, .add_data_output, .call, .method_call,
        // raw_script bytes are opaque — DCE must never eliminate them, even
        // when the binding is unreferenced.
        .raw_script,
        => true,
        // R-140: `if` / `loop` are effectful IFF some NESTED binding is.
        //
        // They used to sit in the unconditional list above, so an unreferenced
        // branch or loop whose bodies are entirely pure was kept here and
        // deleted by the Go, Java, Rust and TypeScript tiers — three tiers
        // against four on the same predicate. Measured on the predicate
        // itself, since no shipped path reaches DCE with that shape today and
        // the conformance suite therefore cannot see it:
        //
        //     go  HasSideEffect(pure if)   = false   zig (before) = true
        //     go  HasSideEffect(pure loop) = false   zig (before) = true
        //
        // Recursion is what makes retention both safe and precise: nested
        // bindings live inside the parent node rather than flattened into the
        // method body, so dropping an effectful `if` would take every nested
        // assert / check_preimage / add_output with it — retention is
        // all-or-nothing. Mirrors packages/runar-compiler/src/optimizer/dce.ts
        // and compilers/go/frontend/dce.go.
        .@"if" => |iv| blk: {
            for (iv.then) |b| {
                if (hasSideEffect(b.value)) break :blk true;
            }
            for (iv.@"else") |b| {
                if (hasSideEffect(b.value)) break :blk true;
            }
            break :blk false;
        },
        .loop => |lv| blk: {
            for (lv.body) |b| {
                if (hasSideEffect(b.value)) break :blk true;
            }
            break :blk false;
        },
        // Issue #109 (@embedAlways): a load_prop injected to force a readonly
        // field into the deployed locking script carries `preserve = true`, so
        // DCE must keep it even though nothing references it. Ordinary
        // load_props (preserve = false) remain freely eliminable.
        .load_prop => |lp| lp.preserve,
        .load_param,
        .load_const,
        .bin_op,
        .unary_op,
        .get_state_script,
        .array_literal,
        => false,
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

// R-140: the predicate itself, pinned. No shipped path reaches DCE with an
// unreferenced pure branch today, so an end-to-end hex test cannot see this
// divergence — the predicate is the only place it is observable, and it is
// where the three tiers disagreed with the other four.
test "R-140 hasSideEffect recurses into if / loop bodies" {
    var then_b = [_]types.ANFBinding{.{ .name = "t1", .value = .{ .load_const = .{ .value = .{ .integer = 1 } } }, .source_loc = null }};
    var else_b = [_]types.ANFBinding{.{ .name = "t2", .value = .{ .load_const = .{ .value = .{ .integer = 2 } } }, .source_loc = null }};
    var pure_if = types.ANFIf{ .cond = "c", .then = then_b[0..], .@"else" = else_b[0..] };
    try std.testing.expect(!hasSideEffect(.{ .@"if" = &pure_if }));

    var body_b = [_]types.ANFBinding{.{ .name = "t3", .value = .{ .load_const = .{ .value = .{ .integer = 3 } } }, .source_loc = null }};
    var pure_loop = types.ANFLoop{ .count = 2, .body = body_b[0..], .iter_var = "i" };
    try std.testing.expect(!hasSideEffect(.{ .loop = &pure_loop }));

    // An effect in EITHER arm keeps the node.
    var eff_b = [_]types.ANFBinding{.{ .name = "t4", .value = .{ .assert = .{ .value = "c" } }, .source_loc = null }};
    var eff_then = types.ANFIf{ .cond = "c", .then = eff_b[0..], .@"else" = else_b[0..] };
    try std.testing.expect(hasSideEffect(.{ .@"if" = &eff_then }));
    var eff_else = types.ANFIf{ .cond = "c", .then = then_b[0..], .@"else" = eff_b[0..] };
    try std.testing.expect(hasSideEffect(.{ .@"if" = &eff_else }));

    var eff_loop = types.ANFLoop{ .count = 2, .body = eff_b[0..], .iter_var = "i" };
    try std.testing.expect(hasSideEffect(.{ .loop = &eff_loop }));

    // And an effect two levels down — the case a top-level-only scan misses.
    var inner_holder = [_]types.ANFBinding{.{ .name = "t5", .value = .{ .@"if" = &eff_then }, .source_loc = null }};
    var outer = types.ANFIf{ .cond = "c", .then = inner_holder[0..], .@"else" = else_b[0..] };
    try std.testing.expect(hasSideEffect(.{ .@"if" = &outer }));

    // An empty `if` carries nothing, so it carries no effect.
    var empty = types.ANFIf{ .cond = "c", .then = &.{}, .@"else" = &.{} };
    try std.testing.expect(!hasSideEffect(.{ .@"if" = &empty }));
}
