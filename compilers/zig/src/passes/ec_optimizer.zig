//! Pass 4.5: EC (Elliptic Curve) algebraic optimizer for ANF IR.
//!
//! Applies 12 algebraic simplification rules to secp256k1 EC intrinsic calls,
//! mirroring the Python implementation in `runar_compiler/frontend/anf_optimize.py`
//! and the TypeScript implementation in `optimizer/ec-optimize.ts`.
//!
//! Runs between ANF lowering (pass 4) and stack lowering (pass 5).
//! Includes dead binding elimination to clean up unreferenced temporaries.

const std = @import("std");
const types = @import("../ir/types.zig");
const Allocator = std.mem.Allocator;

// ============================================================================
// secp256k1 constants
// ============================================================================

/// Curve order N for secp256k1.
const CURVE_N: u256 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

/// Generator point X coordinate (hex).
const GEN_X_HEX = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// Generator point Y coordinate (hex).
const GEN_Y_HEX = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

/// INFINITY = 64 zero bytes as 128-char hex string.
const INFINITY_HEX = "0" ** 128;

/// G = GEN_X || GEN_Y as 128-char hex string.
const G_HEX = GEN_X_HEX ++ GEN_Y_HEX;

/// EC intrinsic function names that trigger optimization.
const ec_funcs = std.StaticStringMap(void).initComptime(.{
    .{ "ecAdd", {} },     .{ "ecMul", {} },     .{ "ecMulGen", {} },
    .{ "ecNegate", {} },  .{ "ecOnCurve", {} },  .{ "ecModReduce", {} },
    .{ "ecEncodeCompressed", {} }, .{ "ecMakePoint", {} },
    .{ "ecPointX", {} },  .{ "ecPointY", {} },
});

// ============================================================================
// Public API
// ============================================================================

/// Optimize all EC operations in the program. Returns a new program with
/// algebraically simplified bindings and dead code eliminated.
/// When no EC calls are present, returns the input program unchanged (no allocation).
pub fn optimize(allocator: Allocator, program: types.ANFProgram) !types.ANFProgram {
    var any_ec = false;
    for (program.methods) |method| {
        if (hasEcCalls(method.body)) {
            any_ec = true;
            break;
        }
    }
    if (!any_ec) return program;

    const new_methods = try allocator.alloc(types.ANFMethod, program.methods.len);
    for (program.methods, 0..) |method, i| {
        new_methods[i] = try optimizeMethod(allocator, method);
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
// Per-method optimization
// ============================================================================

fn optimizeMethod(allocator: Allocator, method: types.ANFMethod) !types.ANFMethod {
    var body = try allocator.alloc(types.ANFBinding, method.body.len);
    @memcpy(body, method.body);

    // Fresh name counter, local to this method optimization.
    var fresh_counter: u32 = 0;

    // Fixed-point iteration: keep applying rules until nothing changes.
    var changed = true;
    while (changed) {
        changed = false;
        var value_map = std.StringHashMap(types.ANFValue).init(allocator);
        defer value_map.deinit();

        var new_body = std.ArrayListUnmanaged(types.ANFBinding).empty;
        defer new_body.deinit(allocator);

        for (body) |binding| {
            var current = binding;
            if (tryOptimize(allocator, current.value, &value_map, &fresh_counter)) |optimized| {
                current = .{ .name = binding.name, .value = optimized, .source_loc = binding.source_loc };
                changed = true;
            }
            try value_map.put(current.name, current.value);
            try new_body.append(allocator, current);
        }

        if (changed) {
            allocator.free(body);
            body = try new_body.toOwnedSlice(allocator);
        }
    }

    const optimized_body = try eliminateDeadBindings(allocator, body);
    allocator.free(body);
    body = optimized_body;

    return .{
        .name = method.name,
        .is_public = method.is_public,
        .params = method.params,
        .bindings = method.bindings,
        .body = body,
    };
}

fn hasEcCalls(body: []const types.ANFBinding) bool {
    for (body) |binding| {
        switch (binding.value) {
            .call => |c| if (ec_funcs.has(c.func)) return true,
            else => {},
        }
    }
    return false;
}

// ============================================================================
// Optimization rules
// ============================================================================

fn tryOptimize(
    allocator: Allocator,
    v: types.ANFValue,
    vm: *std.StringHashMap(types.ANFValue),
    counter: *u32,
) ?types.ANFValue {
    const c = switch (v) {
        .call => |call| call,
        else => return null,
    };

    const func = c.func;
    const args = c.args;

    // Rule 1: ecAdd(x, INFINITY) -> x
    if (eql(func, "ecAdd") and args.len == 2 and isInfinity(args[1], vm))
        return makeRef(allocator, args[0]);

    // Rule 2: ecAdd(INFINITY, x) -> x
    if (eql(func, "ecAdd") and args.len == 2 and isInfinity(args[0], vm))
        return makeRef(allocator, args[1]);

    // Rule 3: ecMul(x, 1) -> x
    if (eql(func, "ecMul") and args.len == 2 and isConstInt(args[1], 1, vm))
        return makeRef(allocator, args[0]);

    // Rule 4: ecMul(x, 0) -> INFINITY
    if (eql(func, "ecMul") and args.len == 2 and isConstInt(args[1], 0, vm))
        return makeConstHex(INFINITY_HEX);

    // Rule 5: ecMulGen(0) -> INFINITY
    if (eql(func, "ecMulGen") and args.len == 1 and isConstInt(args[0], 0, vm))
        return makeConstHex(INFINITY_HEX);

    // Rule 6: ecMulGen(1) -> G
    if (eql(func, "ecMulGen") and args.len == 1 and isConstInt(args[0], 1, vm))
        return makeConstHex(G_HEX);

    // Rule 7: ecNegate(ecNegate(x)) -> x
    if (eql(func, "ecNegate") and args.len == 1) {
        if (resolveCall(args[0], vm)) |ic| {
            if (eql(ic.func, "ecNegate") and ic.args.len == 1)
                return makeRef(allocator, ic.args[0]);
        }
    }

    // Rule 8: ecAdd(x, ecNegate(x)) -> INFINITY
    if (eql(func, "ecAdd") and args.len == 2) {
        if (resolveCall(args[1], vm)) |nc| {
            if (eql(nc.func, "ecNegate") and nc.args.len == 1 and sameBinding(args[0], nc.args[0], vm))
                return makeConstHex(INFINITY_HEX);
        }
    }

    // Rule 9: ecMul(ecMul(p, k1), k2) -> ecMul(p, k1*k2 mod N)
    if (eql(func, "ecMul") and args.len == 2) {
        if (getConstInt(args[1], vm)) |k2| {
            if (resolveCall(args[0], vm)) |ic| {
                if (eql(ic.func, "ecMul") and ic.args.len == 2) {
                    if (getConstInt(ic.args[1], vm)) |k1| {
                        const combined = mulModN(k1, k2);
                        const fresh = freshConstName(allocator, combined, vm, counter);
                        return makeCall(allocator, "ecMul", &.{ ic.args[0], fresh });
                    }
                }
            }
        }
    }

    // Rule 10: ecAdd(ecMulGen(k1), ecMulGen(k2)) -> ecMulGen((k1+k2) mod N)
    if (eql(func, "ecAdd") and args.len == 2) {
        const lc = resolveCall(args[0], vm);
        const rc = resolveCall(args[1], vm);
        if (lc != null and rc != null) {
            if (eql(lc.?.func, "ecMulGen") and lc.?.args.len == 1 and
                eql(rc.?.func, "ecMulGen") and rc.?.args.len == 1)
            {
                const k1 = getConstInt(lc.?.args[0], vm);
                const k2 = getConstInt(rc.?.args[0], vm);
                if (k1 != null and k2 != null) {
                    const combined = addModN(k1.?, k2.?);
                    const fresh = freshConstName(allocator, combined, vm, counter);
                    return makeCall(allocator, "ecMulGen", &.{fresh});
                }
            }
        }
    }

    // Rule 11: ecAdd(ecMul(k1,p), ecMul(k2,p)) -> ecMul((k1+k2) mod N, p) when same p
    if (eql(func, "ecAdd") and args.len == 2) {
        const lc = resolveCall(args[0], vm);
        const rc = resolveCall(args[1], vm);
        if (lc != null and rc != null) {
            if (eql(lc.?.func, "ecMul") and lc.?.args.len == 2 and
                eql(rc.?.func, "ecMul") and rc.?.args.len == 2)
            {
                if (sameBinding(lc.?.args[0], rc.?.args[0], vm)) {
                    const k1 = getConstInt(lc.?.args[1], vm);
                    const k2 = getConstInt(rc.?.args[1], vm);
                    if (k1 != null and k2 != null) {
                        const combined = addModN(k1.?, k2.?);
                        const fresh = freshConstName(allocator, combined, vm, counter);
                        return makeCall(allocator, "ecMul", &.{ lc.?.args[0], fresh });
                    }
                }
            }
        }
    }

    // Rule 12: ecMul(G, k) -> ecMulGen(k)
    if (eql(func, "ecMul") and args.len == 2 and isGenerator(args[0], vm))
        return makeCall(allocator, "ecMulGen", &.{args[1]});

    return null;
}

// ============================================================================
// Helpers -- value inspection
// ============================================================================

fn resolve(name: []const u8, vm: *std.StringHashMap(types.ANFValue)) ?types.ANFValue {
    return vm.get(name);
}

/// Resolve a binding name and return the inner ANFCall if it is a call, else null.
fn resolveCall(name: []const u8, vm: *std.StringHashMap(types.ANFValue)) ?types.ANFCall {
    const val = resolve(name, vm) orelse return null;
    return switch (val) {
        .call => |call| call,
        else => null,
    };
}

fn isInfinity(name: []const u8, vm: *std.StringHashMap(types.ANFValue)) bool {
    const val = resolve(name, vm) orelse return false;
    return switch (val) {
        .load_const => |lc| switch (lc.value) {
            .string => |s| eql(s, INFINITY_HEX),
            else => false,
        },
        else => false,
    };
}

fn isGenerator(name: []const u8, vm: *std.StringHashMap(types.ANFValue)) bool {
    const val = resolve(name, vm) orelse return false;
    return switch (val) {
        .load_const => |lc| switch (lc.value) {
            .string => |s| eql(s, G_HEX),
            else => false,
        },
        else => false,
    };
}

fn isConstInt(name: []const u8, n: i128, vm: *std.StringHashMap(types.ANFValue)) bool {
    const val = resolve(name, vm) orelse return false;
    return switch (val) {
        .load_const => |lc| switch (lc.value) {
            .integer => |v| v == n,
            else => false,
        },
        else => false,
    };
}

fn getConstInt(name: []const u8, vm: *std.StringHashMap(types.ANFValue)) ?i128 {
    const val = resolve(name, vm) orelse return null;
    return switch (val) {
        .load_const => |lc| switch (lc.value) {
            .integer => |v| v,
            else => null,
        },
        else => null,
    };
}

fn sameBinding(a: []const u8, b: []const u8, vm: *std.StringHashMap(types.ANFValue)) bool {
    _ = vm;
    return eql(a, b);
}

// ============================================================================
// Helpers -- value construction
// ============================================================================

/// Create a load_const @ref: alias to another binding.
fn makeRef(allocator: Allocator, name: []const u8) ?types.ANFValue {
    const ref_str = makeRefStr(allocator, name) orelse return null;
    return .{ .load_const = .{ .value = .{ .string = ref_str } } };
}

fn makeRefStr(allocator: Allocator, name: []const u8) ?[]const u8 {
    const buf = allocator.alloc(u8, 5 + name.len) catch return null;
    @memcpy(buf[0..5], "@ref:");
    @memcpy(buf[5..], name);
    return buf;
}

fn makeConstHex(hex: []const u8) types.ANFValue {
    return .{ .load_const = .{ .value = .{ .string = hex } } };
}

fn makeConstInt(n: i128) types.ANFValue {
    return .{ .load_const = .{ .value = .{ .integer = n } } };
}

fn makeCall(allocator: Allocator, func: []const u8, args: []const []const u8) ?types.ANFValue {
    const owned = allocator.alloc([]const u8, args.len) catch return null;
    @memcpy(owned, args);
    return .{ .call = .{ .func = func, .args = owned } };
}

/// Insert a fresh constant binding into the value map and return its name.
fn freshConstName(allocator: Allocator, value: i128, vm: *std.StringHashMap(types.ANFValue), counter: *u32) []const u8 {
    counter.* += 1;
    const buf = allocator.alloc(u8, 24) catch return "";
    const name = std.fmt.bufPrint(buf, "__ec_opt_{d}", .{counter.*}) catch return "";
    vm.put(name, makeConstInt(value)) catch return "";
    return name;
}

// ============================================================================
// Modular arithmetic on u256
// ============================================================================

fn addModN(a_signed: i128, b_signed: i128) i128 {
    const a = toU256(a_signed);
    const b = toU256(b_signed);
    const sum: u256 = (a +% b) % CURVE_N;
    return @intCast(sum);
}

fn mulModN(a_signed: i128, b_signed: i128) i128 {
    const a = toU256(a_signed);
    const b = toU256(b_signed);
    const product: u256 = (a *% b) % CURVE_N;
    return @intCast(product);
}

fn toU256(v: i128) u256 {
    if (v >= 0) return @intCast(v);
    const abs: u256 = @intCast(-v);
    return CURVE_N - (abs % CURVE_N);
}

// ============================================================================
// Dead binding elimination
// ============================================================================

/// Remove bindings whose results are never referenced.
/// Iterates until stable, handling transitive dead code.
/// Caller must free the returned slice. The input `body` is NOT freed by this function.
fn eliminateDeadBindings(allocator: Allocator, body: []types.ANFBinding) ![]types.ANFBinding {
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
            if (aro.script_ref.len > 0) try used.put(aro.script_ref, {});
        },
        .array_literal => |al| {
            for (al.elements) |e| try used.put(e, {});
        },
        // Legacy variants
        .binary_op => |bo| {
            try used.put(bo.left, {});
            try used.put(bo.right, {});
        },
        .builtin_call => |bc| {
            for (bc.args) |arg| try used.put(arg, {});
        },
        .property_write => |pw| try used.put(pw.value_ref, {}),
        .if_expr => |ie| {
            try used.put(ie.condition, {});
            for (ie.then_bindings) |b| try collectRefs(b.value, used);
            if (ie.else_bindings) |eb| for (eb) |b| try collectRefs(b.value, used);
        },
        .for_loop => |fl| {
            for (fl.body_bindings) |b| try collectRefs(b.value, used);
        },
        .assert_op => |a| try used.put(a.condition, {}),
        .ref => |r| try used.put(r, {}),
        .literal_int, .literal_bigint, .literal_bool, .literal_bytes, .property_read, .nop => {},
    }
}

/// Return true if this value kind has observable side effects.
fn hasSideEffect(v: types.ANFValue) bool {
    return switch (v) {
        .assert, .update_prop, .check_preimage, .deserialize_state,
        .add_output, .add_raw_output, .@"if", .loop, .call, .method_call,
        => true,
        .assert_op, .if_expr, .for_loop, .builtin_call => true,
        else => false,
    };
}

// ============================================================================
// Utility
// ============================================================================

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

fn makeBinding(name: []const u8, value: types.ANFValue) types.ANFBinding {
    return .{ .name = name, .value = value, .source_loc = null };
}

fn testMethod(body: []const types.ANFBinding) types.ANFMethod {
    return .{ .name = "test", .is_public = true, .params = &.{}, .bindings = &.{}, .body = @constCast(body) };
}

fn testProgram(methods: []const types.ANFMethod) types.ANFProgram {
    return .{ .contract_name = "Test", .properties = &.{}, .methods = @constCast(methods) };
}

/// Free allocations from an optimize() result (methods array + per-method bodies + @ref strings).
/// Note: does not free call args since we cannot distinguish heap-allocated args from
/// stack-allocated args passed in through the original input.
fn freeOptimizeResult(alloc: Allocator, result: types.ANFProgram) void {
    for (result.methods) |method| {
        for (method.body) |binding| {
            switch (binding.value) {
                .load_const => |lc| switch (lc.value) {
                    .string => |s| {
                        // Free @ref: strings (allocated by makeRefStr)
                        if (std.mem.startsWith(u8, s, "@ref:"))
                            alloc.free(s);
                    },
                    else => {},
                },
                else => {},
            }
        }
        alloc.free(method.body);
    }
    alloc.free(result.methods);
}

fn expectRefTo(val: types.ANFValue, target: []const u8) !void {
    switch (val) {
        .load_const => |lc| switch (lc.value) {
            .string => |s| {
                try testing.expect(std.mem.startsWith(u8, s, "@ref:"));
                try testing.expectEqualStrings(target, s[5..]);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

fn expectConstStr(val: types.ANFValue, expected: []const u8) !void {
    switch (val) {
        .load_const => |lc| switch (lc.value) {
            .string => |s| try testing.expectEqualStrings(expected, s),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

// --- Rule 1: ecAdd(x, INFINITY) -> x ---
test "rule 1: ecAdd(x, INFINITY) -> x" {
    const alloc = testing.allocator;
    var body = [_]types.ANFBinding{
        makeBinding("t0", .{ .load_const = .{ .value = .{ .integer = 42 } } }),
        makeBinding("inf", .{ .load_const = .{ .value = .{ .string = INFINITY_HEX } } }),
        makeBinding("t2", .{ .call = .{ .func = "ecAdd", .args = &.{ "t0", "inf" } } }),
        makeBinding("t3", .{ .assert = .{ .value = "t2" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    defer freeOptimizeResult(alloc, result);
    // After optimization t2 = @ref:t0, dead binding elimination removes unused "inf".
    // Body: [t0, t2, t3] — t2 is at index 1.
    try expectRefTo(result.methods[0].body[1].value, "t0");
}

// --- Rule 2: ecAdd(INFINITY, x) -> x ---
test "rule 2: ecAdd(INFINITY, x) -> x" {
    const alloc = testing.allocator;
    var body = [_]types.ANFBinding{
        makeBinding("inf", .{ .load_const = .{ .value = .{ .string = INFINITY_HEX } } }),
        makeBinding("t1", .{ .load_const = .{ .value = .{ .integer = 42 } } }),
        makeBinding("t2", .{ .call = .{ .func = "ecAdd", .args = &.{ "inf", "t1" } } }),
        makeBinding("t3", .{ .assert = .{ .value = "t2" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    defer freeOptimizeResult(alloc, result);
    // After optimization t2 = @ref:t1, dead binding elimination removes unused "inf".
    // Body: [t1, t2, t3] — t2 is at index 1.
    try expectRefTo(result.methods[0].body[1].value, "t1");
}

// --- Rule 3: ecMul(x, 1) -> x ---
test "rule 3: ecMul(x, 1) -> x" {
    const alloc = testing.allocator;
    var body = [_]types.ANFBinding{
        makeBinding("p", .{ .load_const = .{ .value = .{ .string = G_HEX } } }),
        makeBinding("k", .{ .load_const = .{ .value = .{ .integer = 1 } } }),
        makeBinding("t0", .{ .call = .{ .func = "ecMul", .args = &.{ "p", "k" } } }),
        makeBinding("t1", .{ .assert = .{ .value = "t0" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    defer freeOptimizeResult(alloc, result);
    // After optimization t0 = @ref:p, dead binding elimination removes unused "k".
    // Body: [p, t0, t1] — t0 is at index 1.
    try expectRefTo(result.methods[0].body[1].value, "p");
}

// --- Rule 4: ecMul(x, 0) -> INFINITY ---
test "rule 4: ecMul(x, 0) -> INFINITY" {
    const alloc = testing.allocator;
    var body = [_]types.ANFBinding{
        makeBinding("p", .{ .load_const = .{ .value = .{ .string = G_HEX } } }),
        makeBinding("k", .{ .load_const = .{ .value = .{ .integer = 0 } } }),
        makeBinding("t0", .{ .call = .{ .func = "ecMul", .args = &.{ "p", "k" } } }),
        makeBinding("t1", .{ .assert = .{ .value = "t0" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    defer freeOptimizeResult(alloc, result);
    // After optimization t0 = INFINITY_HEX, dead binding elimination removes unused "p" and "k".
    // Body: [t0, t1] — t0 is at index 0.
    try expectConstStr(result.methods[0].body[0].value, INFINITY_HEX);
}

// --- Rule 5: ecMulGen(0) -> INFINITY ---
test "rule 5: ecMulGen(0) -> INFINITY" {
    const alloc = testing.allocator;
    var body = [_]types.ANFBinding{
        makeBinding("k", .{ .load_const = .{ .value = .{ .integer = 0 } } }),
        makeBinding("t0", .{ .call = .{ .func = "ecMulGen", .args = &.{"k"} } }),
        makeBinding("t1", .{ .assert = .{ .value = "t0" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    defer freeOptimizeResult(alloc, result);
    // After optimization t0 = INFINITY_HEX, dead binding elimination removes unused "k".
    // Body: [t0, t1] — t0 is at index 0.
    try expectConstStr(result.methods[0].body[0].value, INFINITY_HEX);
}

// --- Rule 6: ecMulGen(1) -> G ---
test "rule 6: ecMulGen(1) -> G" {
    const alloc = testing.allocator;
    var body = [_]types.ANFBinding{
        makeBinding("k", .{ .load_const = .{ .value = .{ .integer = 1 } } }),
        makeBinding("t0", .{ .call = .{ .func = "ecMulGen", .args = &.{"k"} } }),
        makeBinding("t1", .{ .assert = .{ .value = "t0" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    defer freeOptimizeResult(alloc, result);
    // After optimization t0 = G_HEX, dead binding elimination removes unused "k".
    // Body: [t0, t1] — t0 is at index 0.
    try expectConstStr(result.methods[0].body[0].value, G_HEX);
}

// --- Rule 7: ecNegate(ecNegate(x)) -> x ---
test "rule 7: ecNegate(ecNegate(x)) -> x" {
    const alloc = testing.allocator;
    var body = [_]types.ANFBinding{
        makeBinding("p", .{ .load_const = .{ .value = .{ .string = G_HEX } } }),
        makeBinding("t0", .{ .call = .{ .func = "ecNegate", .args = &.{"p"} } }),
        makeBinding("t1", .{ .call = .{ .func = "ecNegate", .args = &.{"t0"} } }),
        makeBinding("t2", .{ .assert = .{ .value = "t1" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    defer freeOptimizeResult(alloc, result);
    try expectRefTo(result.methods[0].body[2].value, "p");
}

// --- Rule 8: ecAdd(x, ecNegate(x)) -> INFINITY ---
test "rule 8: ecAdd(x, ecNegate(x)) -> INFINITY" {
    const alloc = testing.allocator;
    var body = [_]types.ANFBinding{
        makeBinding("p", .{ .load_const = .{ .value = .{ .string = G_HEX } } }),
        makeBinding("neg", .{ .call = .{ .func = "ecNegate", .args = &.{"p"} } }),
        makeBinding("t0", .{ .call = .{ .func = "ecAdd", .args = &.{ "p", "neg" } } }),
        makeBinding("t1", .{ .assert = .{ .value = "t0" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    defer freeOptimizeResult(alloc, result);
    try expectConstStr(result.methods[0].body[2].value, INFINITY_HEX);
}

// --- Rule 12: ecMul(G, k) -> ecMulGen(k) ---
test "rule 12: ecMul(G, k) -> ecMulGen(k)" {
    const alloc = testing.allocator;
    var body = [_]types.ANFBinding{
        makeBinding("g", .{ .load_const = .{ .value = .{ .string = G_HEX } } }),
        makeBinding("k", .{ .load_const = .{ .value = .{ .integer = 7 } } }),
        makeBinding("t0", .{ .call = .{ .func = "ecMul", .args = &.{ "g", "k" } } }),
        makeBinding("t1", .{ .assert = .{ .value = "t0" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    defer freeOptimizeResult(alloc, result);
    // After optimization t0 = ecMulGen(k), dead binding elimination removes unused "g".
    // Body: [k, t0, t1] — t0 is at index 1.
    const t0 = result.methods[0].body[1].value;
    switch (t0) {
        .call => |c| {
            defer alloc.free(c.args); // Allocated by makeCall
            try testing.expectEqualStrings("ecMulGen", c.func);
            try testing.expectEqual(@as(usize, 1), c.args.len);
            try testing.expectEqualStrings("k", c.args[0]);
        },
        else => return error.TestUnexpectedResult,
    }
}

// --- No EC calls: program returned unchanged ---
test "no EC calls: program returned unchanged" {
    const alloc = testing.allocator;
    var body = [_]types.ANFBinding{
        makeBinding("t0", .{ .load_const = .{ .value = .{ .integer = 1 } } }),
        makeBinding("t1", .{ .assert = .{ .value = "t0" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    try testing.expectEqual(body[0].name.ptr, result.methods[0].body[0].name.ptr);
}

// --- Dead binding elimination ---
test "dead binding elimination removes unused bindings" {
    const alloc = testing.allocator;
    var body_arr = [_]types.ANFBinding{
        makeBinding("t0", .{ .load_const = .{ .value = .{ .integer = 42 } } }),
        makeBinding("t1", .{ .load_const = .{ .value = .{ .integer = 99 } } }),
        makeBinding("t2", .{ .assert = .{ .value = "t0" } }),
    };
    const result = try eliminateDeadBindings(alloc, &body_arr);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 2), result.len);
    try testing.expectEqualStrings("t0", result[0].name);
    try testing.expectEqualStrings("t2", result[1].name);
}

test "dead binding elimination preserves side effects" {
    const alloc = testing.allocator;
    var body_arr = [_]types.ANFBinding{
        makeBinding("t0", .{ .load_const = .{ .value = .{ .integer = 1 } } }),
        makeBinding("t1", .{ .call = .{ .func = "ecMulGen", .args = &.{"t0"} } }),
    };
    const result = try eliminateDeadBindings(alloc, &body_arr);
    defer alloc.free(result);
    try testing.expectEqual(@as(usize, 2), result.len);
}

// --- Constants ---
test "constants: CURVE_N matches secp256k1" {
    try testing.expectEqual(
        @as(u256, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141),
        CURVE_N,
    );
}

test "constants: G_HEX and INFINITY_HEX are 128 chars" {
    try testing.expectEqual(@as(usize, 128), G_HEX.len);
    try testing.expectEqual(@as(usize, 128), INFINITY_HEX.len);
}

// --- Modular arithmetic ---
test "addModN: basic addition" {
    try testing.expectEqual(@as(i128, 5), addModN(2, 3));
    try testing.expectEqual(@as(i128, 0), addModN(0, 0));
}

test "mulModN: basic multiplication" {
    try testing.expectEqual(@as(i128, 6), mulModN(2, 3));
    try testing.expectEqual(@as(i128, 0), mulModN(0, 42));
}
