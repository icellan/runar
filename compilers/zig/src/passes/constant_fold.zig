//! Pass 4.25: Constant Folding — evaluates compile-time-known expressions in ANF IR.
//!
//! Walks ANF bindings and replaces operations on known constants with `load_const`
//! bindings.  Constants are propagated through the binding chain so downstream
//! operations can be folded transitively.
//!
//! Handles:
//!   1. Binary ops on known constants (+, -, *, /, %, ===, !==, <, >, <=, >=, &&, ||, &, |, ^, <<, >>)
//!   2. Unary ops (!, -, ~)
//!   3. Pure builtin calls (abs, min, max, safediv, safemod, clamp, sign, pow, mulDiv, percentOf, sqrt, gcd, divmod, log2, bool)
//!   4. If-expressions with known conditions (dead branch elimination)
//!   5. Loop body folding
//!
//! Does NOT run dead binding elimination — that is handled by a separate DCE pass.
//! Direct port of `compilers/python/runar_compiler/frontend/constant_fold.py`.

const std = @import("std");
const types = @import("../ir/types.zig");

const Allocator = std.mem.Allocator;
const ConstValue = types.ConstValue;
const ANFValue = types.ANFValue;
const ANFBinding = types.ANFBinding;
const ANFMethod = types.ANFMethod;
const ANFProgram = types.ANFProgram;

const ConstEnv = std.StringHashMap(ConstValue);

// ============================================================================
// Binary operation dispatch via StaticStringMap
// ============================================================================

const BinOpTag = enum {
    op_add,
    op_sub,
    op_mul,
    op_div,
    op_mod,
    op_strict_eq,
    op_strict_neq,
    op_lt,
    op_gt,
    op_lte,
    op_gte,
    op_bit_and,
    op_bit_or,
    op_bit_xor,
    op_shl,
    op_shr,
    op_logical_and,
    op_logical_or,
};

const bin_op_map = std.StaticStringMap(BinOpTag).initComptime(.{
    .{ "+", .op_add },
    .{ "-", .op_sub },
    .{ "*", .op_mul },
    .{ "/", .op_div },
    .{ "%", .op_mod },
    .{ "===", .op_strict_eq },
    .{ "!==", .op_strict_neq },
    .{ "<", .op_lt },
    .{ ">", .op_gt },
    .{ "<=", .op_lte },
    .{ ">=", .op_gte },
    .{ "&", .op_bit_and },
    .{ "|", .op_bit_or },
    .{ "^", .op_bit_xor },
    .{ "<<", .op_shl },
    .{ ">>", .op_shr },
    .{ "&&", .op_logical_and },
    .{ "||", .op_logical_or },
});

fn evalBinOp(op: []const u8, left: ConstValue, right: ConstValue) ?ConstValue {
    const tag = bin_op_map.get(op) orelse return null;

    // Integer arithmetic / bitwise / comparison
    if (left == .integer and right == .integer) {
        const a = left.integer;
        const b = right.integer;

        return switch (tag) {
            .op_add => .{ .integer = a +% b },
            .op_sub => .{ .integer = a -% b },
            .op_mul => .{ .integer = a *% b },
            .op_div => if (b == 0) null else .{ .integer = @divTrunc(a, b) },
            .op_mod => if (b == 0) null else .{ .integer = a - @divTrunc(a, b) * b },
            .op_strict_eq => .{ .boolean = a == b },
            .op_strict_neq => .{ .boolean = a != b },
            .op_lt => .{ .boolean = a < b },
            .op_gt => .{ .boolean = a > b },
            .op_lte => .{ .boolean = a <= b },
            .op_gte => .{ .boolean = a >= b },
            .op_bit_and => .{ .integer = a & b },
            .op_bit_or => .{ .integer = a | b },
            .op_bit_xor => .{ .integer = a ^ b },
            .op_shl => blk: {
                if (a < 0) break :blk null; // BSV shifts are logical
                if (b < 0 or b > 128) break :blk null;
                const shift: u7 = @intCast(@as(i128, @min(b, 127)));
                break :blk .{ .integer = a << shift };
            },
            .op_shr => blk: {
                if (a < 0) break :blk null; // BSV shifts are logical
                if (b < 0 or b > 128) break :blk null;
                const shift: u7 = @intCast(@as(i128, @min(b, 127)));
                break :blk .{ .integer = a >> shift };
            },
            .op_logical_and, .op_logical_or => null,
        };
    }

    // Boolean operations
    if (left == .boolean and right == .boolean) {
        const a = left.boolean;
        const b = right.boolean;

        return switch (tag) {
            .op_logical_and => .{ .boolean = a and b },
            .op_logical_or => .{ .boolean = a or b },
            .op_strict_eq => .{ .boolean = a == b },
            .op_strict_neq => .{ .boolean = a != b },
            else => null,
        };
    }

    // String (ByteString) operations
    if (left == .string and right == .string) {
        return switch (tag) {
            .op_strict_eq => .{ .boolean = std.mem.eql(u8, left.string, right.string) },
            .op_strict_neq => .{ .boolean = !std.mem.eql(u8, left.string, right.string) },
            // String concatenation: we cannot allocate in a pure evaluator, skip
            else => null,
        };
    }

    // Cross-type equality
    return switch (tag) {
        .op_strict_eq => .{ .boolean = false },
        .op_strict_neq => .{ .boolean = true },
        else => null,
    };
}

// ============================================================================
// Unary operation dispatch via StaticStringMap
// ============================================================================

const UnaryOpTag = enum { op_negate, op_bitwise_not, op_logical_not };

const unary_op_map = std.StaticStringMap(UnaryOpTag).initComptime(.{
    .{ "-", .op_negate },
    .{ "~", .op_bitwise_not },
    .{ "!", .op_logical_not },
});

fn evalUnaryOp(op: []const u8, operand: ConstValue) ?ConstValue {
    const tag = unary_op_map.get(op) orelse return null;

    if (operand == .boolean) {
        return switch (tag) {
            .op_logical_not => .{ .boolean = !operand.boolean },
            else => null,
        };
    }
    if (operand == .integer) {
        const n = operand.integer;
        return switch (tag) {
            .op_negate => .{ .integer = -%n },
            .op_bitwise_not => .{ .integer = ~n },
            .op_logical_not => .{ .boolean = n == 0 },
        };
    }
    return null;
}

// ============================================================================
// Builtin call dispatch via StaticStringMap
// ============================================================================

const BuiltinTag = enum {
    builtin_abs,
    builtin_min,
    builtin_max,
    builtin_safediv,
    builtin_safemod,
    builtin_clamp,
    builtin_sign,
    builtin_pow,
    builtin_mulDiv,
    builtin_percentOf,
    builtin_sqrt,
    builtin_gcd,
    builtin_divmod,
    builtin_log2,
    builtin_bool,
};

const builtin_map = std.StaticStringMap(BuiltinTag).initComptime(.{
    .{ "abs", .builtin_abs },
    .{ "min", .builtin_min },
    .{ "max", .builtin_max },
    .{ "safediv", .builtin_safediv },
    .{ "safemod", .builtin_safemod },
    .{ "clamp", .builtin_clamp },
    .{ "sign", .builtin_sign },
    .{ "pow", .builtin_pow },
    .{ "mulDiv", .builtin_mulDiv },
    .{ "percentOf", .builtin_percentOf },
    .{ "sqrt", .builtin_sqrt },
    .{ "gcd", .builtin_gcd },
    .{ "divmod", .builtin_divmod },
    .{ "log2", .builtin_log2 },
    .{ "bool", .builtin_bool },
});

fn evalBuiltinCall(func_name: []const u8, args: []const []const u8, env: *const ConstEnv) ?ConstValue {
    const tag = builtin_map.get(func_name) orelse return null;

    // Resolve all args to integer constants
    var int_args: [8]i128 = undefined;
    var count: usize = 0;
    for (args) |arg| {
        const cv = env.get(arg) orelse return null;
        if (cv != .integer) return null;
        if (count >= 8) return null;
        int_args[count] = cv.integer;
        count += 1;
    }

    return switch (tag) {
        .builtin_abs => {
            if (count != 1) return null;
            const n = int_args[0];
            return .{ .integer = if (n < 0) -n else n };
        },
        .builtin_min => {
            if (count != 2) return null;
            return .{ .integer = @min(int_args[0], int_args[1]) };
        },
        .builtin_max => {
            if (count != 2) return null;
            return .{ .integer = @max(int_args[0], int_args[1]) };
        },
        .builtin_safediv => {
            if (count != 2 or int_args[1] == 0) return null;
            return .{ .integer = @divTrunc(int_args[0], int_args[1]) };
        },
        .builtin_safemod => {
            if (count != 2 or int_args[1] == 0) return null;
            const a = int_args[0];
            const b = int_args[1];
            return .{ .integer = a - @divTrunc(a, b) * b };
        },
        .builtin_clamp => {
            if (count != 3) return null;
            const val = int_args[0];
            const lo = int_args[1];
            const hi = int_args[2];
            return .{ .integer = @max(lo, @min(val, hi)) };
        },
        .builtin_sign => {
            if (count != 1) return null;
            const n = int_args[0];
            if (n > 0) return .{ .integer = 1 };
            if (n < 0) return .{ .integer = -1 };
            return .{ .integer = 0 };
        },
        .builtin_pow => {
            if (count != 2) return null;
            const base = int_args[0];
            const exp = int_args[1];
            if (exp < 0 or exp > 256) return null;
            var result: i128 = 1;
            var i: i128 = 0;
            while (i < exp) : (i += 1) {
                result *%= base;
            }
            return .{ .integer = result };
        },
        .builtin_mulDiv => {
            if (count != 3 or int_args[2] == 0) return null;
            const tmp = int_args[0] *% int_args[1];
            return .{ .integer = @divTrunc(tmp, int_args[2]) };
        },
        .builtin_percentOf => {
            if (count != 2) return null;
            const tmp = int_args[0] *% int_args[1];
            return .{ .integer = @divTrunc(tmp, 10000) };
        },
        .builtin_sqrt => {
            if (count != 1) return null;
            const n = int_args[0];
            if (n < 0) return null;
            if (n == 0) return .{ .integer = 0 };
            // Integer square root via Newton's method
            var x = n;
            var y = @divTrunc(x + 1, 2);
            while (y < x) {
                x = y;
                y = @divTrunc(x + @divTrunc(n, x), 2);
            }
            return .{ .integer = x };
        },
        .builtin_gcd => {
            if (count != 2) return null;
            var a: i128 = if (int_args[0] < 0) -int_args[0] else int_args[0];
            var b: i128 = if (int_args[1] < 0) -int_args[1] else int_args[1];
            while (b != 0) {
                const t = @mod(a, b);
                a = b;
                b = t;
            }
            return .{ .integer = a };
        },
        .builtin_divmod => {
            if (count != 2 or int_args[1] == 0) return null;
            return .{ .integer = @divTrunc(int_args[0], int_args[1]) };
        },
        .builtin_log2 => {
            if (count != 1) return null;
            const n = int_args[0];
            if (n <= 0) return .{ .integer = 0 };
            // Bit length - 1
            var bits: i128 = 0;
            var v = n;
            while (v > 1) : (v = @divTrunc(v, 2)) {
                bits += 1;
            }
            return .{ .integer = bits };
        },
        .builtin_bool => {
            if (count != 1) return null;
            return .{ .boolean = int_args[0] != 0 };
        },
    };
}

// ============================================================================
// Conversion: ConstValue -> ANFValue
// ============================================================================

fn constToAnfValue(cv: ConstValue) ANFValue {
    return .{ .load_const = .{ .value = cv } };
}

/// Extract a ConstValue from an ANFValue if it is a load_const.
fn anfValueToConst(value: ANFValue) ?ConstValue {
    return switch (value) {
        .load_const => |lc| lc.value,
        else => null,
    };
}

// ============================================================================
// Fold bindings
// ============================================================================

fn foldBindings(allocator: Allocator, bindings: []const ANFBinding, env: *ConstEnv) anyerror![]ANFBinding {
    var result: std.ArrayListUnmanaged(ANFBinding) = .empty;
    errdefer result.deinit(allocator);

    for (bindings) |binding| {
        const folded = try foldBinding(allocator, binding, env);
        try result.append(allocator, folded);
    }

    return result.toOwnedSlice(allocator);
}

fn foldBinding(allocator: Allocator, binding: ANFBinding, env: *ConstEnv) anyerror!ANFBinding {
    const folded_value = try foldValue(allocator, binding.value, env);

    // If the folded value is a load_const, register in the environment
    if (anfValueToConst(folded_value)) |cv| {
        try env.put(binding.name, cv);
    }

    return .{ .name = binding.name, .value = folded_value, .source_loc = binding.source_loc };
}

// ============================================================================
// Fold a single value
// ============================================================================

fn foldValue(allocator: Allocator, value: ANFValue, env: *ConstEnv) anyerror!ANFValue {
    switch (value) {
        .load_const, .load_param, .load_prop => return value,

        .bin_op => |bo| {
            const left_const = env.get(bo.left);
            const right_const = env.get(bo.right);
            if (left_const != null and right_const != null) {
                if (evalBinOp(bo.op, left_const.?, right_const.?)) |result| {
                    return constToAnfValue(result);
                }
            }
            return value;
        },

        .unary_op => |uo| {
            const operand_const = env.get(uo.operand);
            if (operand_const) |oc| {
                if (evalUnaryOp(uo.op, oc)) |result| {
                    return constToAnfValue(result);
                }
            }
            return value;
        },

        .call => |c| {
            if (evalBuiltinCall(c.func, c.args, env)) |result| {
                return constToAnfValue(result);
            }
            return value;
        },

        .method_call => return value,

        .@"if" => |if_node| {
            const cond_const = env.get(if_node.cond);
            if (cond_const != null and cond_const.? == .boolean) {
                const cond_val = cond_const.?.boolean;
                if (cond_val) {
                    // Condition is true -- fold the then-branch, eliminate else
                    var branch_env = try cloneEnv(allocator, env);
                    defer branch_env.deinit();
                    const folded_then = try foldBindings(allocator, if_node.then, &branch_env);
                    // Merge constants from taken branch back
                    mergeEnv(env, &branch_env);

                    const new_if = try allocator.create(types.ANFIf);
                    new_if.* = .{
                        .cond = if_node.cond,
                        .then = folded_then,
                        .@"else" = &.{},
                    };
                    return .{ .@"if" = new_if };
                } else {
                    // Condition is false -- fold the else-branch, eliminate then
                    var branch_env = try cloneEnv(allocator, env);
                    defer branch_env.deinit();
                    const folded_else = try foldBindings(allocator, if_node.@"else", &branch_env);
                    mergeEnv(env, &branch_env);

                    const new_if = try allocator.create(types.ANFIf);
                    new_if.* = .{
                        .cond = if_node.cond,
                        .then = &.{},
                        .@"else" = folded_else,
                    };
                    return .{ .@"if" = new_if };
                }
            } else {
                // Condition not known -- fold both branches independently
                var then_env = try cloneEnv(allocator, env);
                defer then_env.deinit();
                var else_env = try cloneEnv(allocator, env);
                defer else_env.deinit();
                const folded_then = try foldBindings(allocator, if_node.then, &then_env);
                const folded_else = try foldBindings(allocator, if_node.@"else", &else_env);

                const new_if = try allocator.create(types.ANFIf);
                new_if.* = .{
                    .cond = if_node.cond,
                    .then = folded_then,
                    .@"else" = folded_else,
                };
                return .{ .@"if" = new_if };
            }
        },

        .loop => |loop_node| {
            var body_env = try cloneEnv(allocator, env);
            defer body_env.deinit();
            const folded_body = try foldBindings(allocator, loop_node.body, &body_env);

            const new_loop = try allocator.create(types.ANFLoop);
            new_loop.* = .{
                .count = loop_node.count,
                .body = folded_body,
                .iter_var = loop_node.iter_var,
            };
            return .{ .loop = new_loop };
        },

        // All other kinds (assert, update_prop, get_state_script, check_preimage,
        // deserialize_state, add_output, add_raw_output, array_literal, legacy variants)
        // pass through unchanged.
        else => return value,
    }
}

// ============================================================================
// Environment helpers
// ============================================================================

fn cloneEnv(allocator: Allocator, env: *const ConstEnv) !ConstEnv {
    var new_env = ConstEnv.init(allocator);
    errdefer new_env.deinit();
    var it = env.iterator();
    while (it.next()) |entry| {
        try new_env.put(entry.key_ptr.*, entry.value_ptr.*);
    }
    return new_env;
}

/// Merge constants from a branch environment into the parent. Only adds new entries.
fn mergeEnv(parent: *ConstEnv, branch: *const ConstEnv) void {
    var it = branch.iterator();
    while (it.next()) |entry| {
        if (!parent.contains(entry.key_ptr.*)) {
            parent.put(entry.key_ptr.*, entry.value_ptr.*) catch {};
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Apply constant folding to a single method.
pub fn foldMethod(allocator: Allocator, method: ANFMethod) !ANFMethod {
    var env = ConstEnv.init(allocator);
    defer env.deinit();
    const folded_body = try foldBindings(allocator, method.body, &env);
    return .{
        .name = method.name,
        .is_public = method.is_public,
        .params = method.params,
        .bindings = method.bindings,
        .body = folded_body,
    };
}

/// Apply constant folding to an entire ANF program.
pub fn foldConstants(allocator: Allocator, program: ANFProgram) !ANFProgram {
    var methods: std.ArrayListUnmanaged(ANFMethod) = .empty;
    errdefer methods.deinit(allocator);

    for (program.methods) |method| {
        const folded = try foldMethod(allocator, method);
        try methods.append(allocator, folded);
    }

    return .{
        .contract_name = program.contract_name,
        .parent_class = program.parent_class,
        .properties = program.properties,
        .constructor = program.constructor,
        .methods = try methods.toOwnedSlice(allocator),
    };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

fn makeBinding(name: []const u8, value: ANFValue) ANFBinding {
    return .{ .name = name, .value = value };
}

fn makeLoadConst(cv: ConstValue) ANFValue {
    return .{ .load_const = .{ .value = cv } };
}

fn expectConst(expected: ConstValue, binding: ANFBinding) !void {
    const cv = anfValueToConst(binding.value) orelse return error.TestExpectedEqual;
    if (!expected.eql(cv)) {
        std.debug.print("Expected {any}, got {any}\n", .{ expected, cv });
        return error.TestExpectedEqual;
    }
}

// --- Binary operations: integer arithmetic ---

test "fold add: 3 + 7 = 10" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 3 })),
        makeBinding("b", makeLoadConst(.{ .integer = 7 })),
        makeBinding("c", .{ .bin_op = .{ .op = "+", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 10 }, result[2]);
}

test "fold sub: 10 - 3 = 7" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 10 })),
        makeBinding("b", makeLoadConst(.{ .integer = 3 })),
        makeBinding("c", .{ .bin_op = .{ .op = "-", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 7 }, result[2]);
}

test "fold mul: 4 * 5 = 20" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 4 })),
        makeBinding("b", makeLoadConst(.{ .integer = 5 })),
        makeBinding("c", .{ .bin_op = .{ .op = "*", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 20 }, result[2]);
}

test "fold div: 10 / 3 = 3 (truncated)" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 10 })),
        makeBinding("b", makeLoadConst(.{ .integer = 3 })),
        makeBinding("c", .{ .bin_op = .{ .op = "/", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 3 }, result[2]);
}

test "fold div by zero: returns original" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 10 })),
        makeBinding("b", makeLoadConst(.{ .integer = 0 })),
        makeBinding("c", .{ .bin_op = .{ .op = "/", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    // Should NOT be folded — division by zero is not evaluable
    try testing.expect(anfValueToConst(result[2].value) == null);
}

test "fold mod: 10 % 3 = 1" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 10 })),
        makeBinding("b", makeLoadConst(.{ .integer = 3 })),
        makeBinding("c", .{ .bin_op = .{ .op = "%", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 1 }, result[2]);
}

// --- Binary operations: comparison ---

test "fold equality: 5 === 5 = true" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 5 })),
        makeBinding("b", makeLoadConst(.{ .integer = 5 })),
        makeBinding("c", .{ .bin_op = .{ .op = "===", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .boolean = true }, result[2]);
}

test "fold inequality: 5 !== 3 = true" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 5 })),
        makeBinding("b", makeLoadConst(.{ .integer = 3 })),
        makeBinding("c", .{ .bin_op = .{ .op = "!==", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .boolean = true }, result[2]);
}

test "fold less-than: 3 < 5 = true" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 3 })),
        makeBinding("b", makeLoadConst(.{ .integer = 5 })),
        makeBinding("c", .{ .bin_op = .{ .op = "<", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .boolean = true }, result[2]);
}

// --- Binary operations: bitwise ---

test "fold bitwise and: 0xff & 0x0f = 0x0f" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 0xff })),
        makeBinding("b", makeLoadConst(.{ .integer = 0x0f })),
        makeBinding("c", .{ .bin_op = .{ .op = "&", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 0x0f }, result[2]);
}

test "fold left shift: 1 << 8 = 256" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 1 })),
        makeBinding("b", makeLoadConst(.{ .integer = 8 })),
        makeBinding("c", .{ .bin_op = .{ .op = "<<", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 256 }, result[2]);
}

test "fold shift with negative left operand: skipped" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = -1 })),
        makeBinding("b", makeLoadConst(.{ .integer = 8 })),
        makeBinding("c", .{ .bin_op = .{ .op = "<<", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try testing.expect(anfValueToConst(result[2].value) == null);
}

// --- Binary operations: boolean ---

test "fold boolean and: true && false = false" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .boolean = true })),
        makeBinding("b", makeLoadConst(.{ .boolean = false })),
        makeBinding("c", .{ .bin_op = .{ .op = "&&", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .boolean = false }, result[2]);
}

test "fold boolean or: false || true = true" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .boolean = false })),
        makeBinding("b", makeLoadConst(.{ .boolean = true })),
        makeBinding("c", .{ .bin_op = .{ .op = "||", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .boolean = true }, result[2]);
}

// --- Cross-type equality ---

test "fold cross-type equality: int === bool = false" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 1 })),
        makeBinding("b", makeLoadConst(.{ .boolean = true })),
        makeBinding("c", .{ .bin_op = .{ .op = "===", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .boolean = false }, result[2]);
}

// --- Unary operations ---

test "fold unary negate: -42 = -42" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 42 })),
        makeBinding("b", .{ .unary_op = .{ .op = "-", .operand = "a" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = -42 }, result[1]);
}

test "fold unary not on bool: !true = false" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .boolean = true })),
        makeBinding("b", .{ .unary_op = .{ .op = "!", .operand = "a" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .boolean = false }, result[1]);
}

test "fold unary not on int: !0 = true" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 0 })),
        makeBinding("b", .{ .unary_op = .{ .op = "!", .operand = "a" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .boolean = true }, result[1]);
}

test "fold unary bitnot: ~0 = -1" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 0 })),
        makeBinding("b", .{ .unary_op = .{ .op = "~", .operand = "a" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = -1 }, result[1]);
}

// --- Builtin calls ---

test "fold builtin abs(-5) = 5" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{"a"};
    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = -5 })),
        makeBinding("b", .{ .call = .{ .func = "abs", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 5 }, result[1]);
}

test "fold builtin min(3, 7) = 3" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{ "a", "b" };
    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 3 })),
        makeBinding("b", makeLoadConst(.{ .integer = 7 })),
        makeBinding("c", .{ .call = .{ .func = "min", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 3 }, result[2]);
}

test "fold builtin max(3, 7) = 7" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{ "a", "b" };
    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 3 })),
        makeBinding("b", makeLoadConst(.{ .integer = 7 })),
        makeBinding("c", .{ .call = .{ .func = "max", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 7 }, result[2]);
}

test "fold builtin clamp(10, 0, 5) = 5" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{ "v", "lo", "hi" };
    const bindings = [_]ANFBinding{
        makeBinding("v", makeLoadConst(.{ .integer = 10 })),
        makeBinding("lo", makeLoadConst(.{ .integer = 0 })),
        makeBinding("hi", makeLoadConst(.{ .integer = 5 })),
        makeBinding("c", .{ .call = .{ .func = "clamp", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 5 }, result[3]);
}

test "fold builtin sign(-7) = -1" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{"a"};
    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = -7 })),
        makeBinding("b", .{ .call = .{ .func = "sign", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = -1 }, result[1]);
}

test "fold builtin pow(2, 10) = 1024" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{ "base", "exp" };
    const bindings = [_]ANFBinding{
        makeBinding("base", makeLoadConst(.{ .integer = 2 })),
        makeBinding("exp", makeLoadConst(.{ .integer = 10 })),
        makeBinding("c", .{ .call = .{ .func = "pow", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 1024 }, result[2]);
}

test "fold builtin sqrt(144) = 12" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{"a"};
    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 144 })),
        makeBinding("b", .{ .call = .{ .func = "sqrt", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 12 }, result[1]);
}

test "fold builtin gcd(12, 8) = 4" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{ "a", "b" };
    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 12 })),
        makeBinding("b", makeLoadConst(.{ .integer = 8 })),
        makeBinding("c", .{ .call = .{ .func = "gcd", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 4 }, result[2]);
}

test "fold builtin log2(1024) = 10" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{"a"};
    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 1024 })),
        makeBinding("b", .{ .call = .{ .func = "log2", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 10 }, result[1]);
}

test "fold builtin bool(0) = false" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{"a"};
    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 0 })),
        makeBinding("b", .{ .call = .{ .func = "bool", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .boolean = false }, result[1]);
}

test "fold builtin mulDiv(10, 20, 5) = 40" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{ "a", "b", "c" };
    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 10 })),
        makeBinding("b", makeLoadConst(.{ .integer = 20 })),
        makeBinding("c", makeLoadConst(.{ .integer = 5 })),
        makeBinding("d", .{ .call = .{ .func = "mulDiv", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 40 }, result[3]);
}

test "fold builtin percentOf(5000, 200) = 100" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{ "a", "b" };
    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 5000 })),
        makeBinding("b", makeLoadConst(.{ .integer = 200 })),
        makeBinding("c", .{ .call = .{ .func = "percentOf", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 100 }, result[2]);
}

// --- If-expression folding ---

test "fold if with known true condition: dead branch elimination" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    var then_bindings = [_]ANFBinding{
        makeBinding("x", makeLoadConst(.{ .integer = 42 })),
    };
    var else_bindings = [_]ANFBinding{
        makeBinding("x", makeLoadConst(.{ .integer = 99 })),
    };

    const if_node = try allocator.create(types.ANFIf);
    defer allocator.destroy(if_node);
    if_node.* = .{ .cond = "cond", .then = &then_bindings, .@"else" = &else_bindings };

    const bindings = [_]ANFBinding{
        makeBinding("cond", makeLoadConst(.{ .boolean = true })),
        makeBinding("result", .{ .@"if" = if_node }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer {
        // Free the newly allocated if-node from folding
        switch (result[1].value) {
            .@"if" => |new_if| {
                allocator.free(new_if.then);
                allocator.destroy(new_if);
            },
            else => {},
        }
        allocator.free(result);
    }

    // The if should have then-branch populated and else-branch empty
    switch (result[1].value) {
        .@"if" => |folded_if| {
            try testing.expectEqual(@as(usize, 1), folded_if.then.len);
            try testing.expectEqual(@as(usize, 0), folded_if.@"else".len);
        },
        else => return error.TestExpectedEqual,
    }
}

test "fold if with known false condition: dead branch elimination" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    var then_bindings = [_]ANFBinding{
        makeBinding("x", makeLoadConst(.{ .integer = 42 })),
    };
    var else_bindings = [_]ANFBinding{
        makeBinding("x", makeLoadConst(.{ .integer = 99 })),
    };

    const if_node = try allocator.create(types.ANFIf);
    defer allocator.destroy(if_node);
    if_node.* = .{ .cond = "cond", .then = &then_bindings, .@"else" = &else_bindings };

    const bindings = [_]ANFBinding{
        makeBinding("cond", makeLoadConst(.{ .boolean = false })),
        makeBinding("result", .{ .@"if" = if_node }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer {
        switch (result[1].value) {
            .@"if" => |new_if| {
                allocator.free(new_if.@"else");
                allocator.destroy(new_if);
            },
            else => {},
        }
        allocator.free(result);
    }

    switch (result[1].value) {
        .@"if" => |folded_if| {
            try testing.expectEqual(@as(usize, 0), folded_if.then.len);
            try testing.expectEqual(@as(usize, 1), folded_if.@"else".len);
        },
        else => return error.TestExpectedEqual,
    }
}

// --- Constant propagation ---

test "transitive constant propagation: a=3, b=a+4=7, c=b*2=14" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 3 })),
        makeBinding("four", makeLoadConst(.{ .integer = 4 })),
        makeBinding("b", .{ .bin_op = .{ .op = "+", .left = "a", .right = "four" } }),
        makeBinding("two", makeLoadConst(.{ .integer = 2 })),
        makeBinding("c", .{ .bin_op = .{ .op = "*", .left = "b", .right = "two" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 7 }, result[2]);
    try expectConst(.{ .integer = 14 }, result[4]);
}

// --- Non-foldable cases ---

test "non-const operand: bin_op not folded" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 3 })),
        makeBinding("b", .{ .load_param = .{ .name = "x" } }),
        makeBinding("c", .{ .bin_op = .{ .op = "+", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    // b is a param, so c cannot be folded
    try testing.expect(anfValueToConst(result[2].value) == null);
}

test "non-pure call: not folded" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{"a"};
    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 5 })),
        makeBinding("b", .{ .call = .{ .func = "hash160", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    // hash160 is not a pure math builtin
    try testing.expect(anfValueToConst(result[1].value) == null);
}

// --- Method-level folding ---

test "foldMethod: folds body bindings" {
    const allocator = testing.allocator;

    var body = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 10 })),
        makeBinding("b", makeLoadConst(.{ .integer = 20 })),
        makeBinding("c", .{ .bin_op = .{ .op = "+", .left = "a", .right = "b" } }),
    };
    const method = ANFMethod{
        .name = "test",
        .is_public = true,
        .body = &body,
    };
    const folded = try foldMethod(allocator, method);
    defer allocator.free(folded.body);

    try expectConst(.{ .integer = 30 }, folded.body[2]);
}

// --- Program-level folding ---

test "foldConstants: folds all methods" {
    const allocator = testing.allocator;

    var body1 = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 2 })),
        makeBinding("b", makeLoadConst(.{ .integer = 3 })),
        makeBinding("c", .{ .bin_op = .{ .op = "*", .left = "a", .right = "b" } }),
    };
    var body2 = [_]ANFBinding{
        makeBinding("x", makeLoadConst(.{ .boolean = true })),
        makeBinding("y", .{ .unary_op = .{ .op = "!", .operand = "x" } }),
    };
    var methods = [_]ANFMethod{
        .{ .name = "m1", .is_public = true, .body = &body1 },
        .{ .name = "m2", .is_public = false, .body = &body2 },
    };
    const program = ANFProgram{
        .contract_name = "TestContract",
        .properties = &.{},
        .methods = &methods,
    };
    const folded = try foldConstants(allocator, program);
    defer {
        for (folded.methods) |m| allocator.free(m.body);
        allocator.free(folded.methods);
    }

    try testing.expectEqual(@as(usize, 2), folded.methods.len);
    try expectConst(.{ .integer = 6 }, folded.methods[0].body[2]);
    try expectConst(.{ .boolean = false }, folded.methods[1].body[1]);
}

// --- String equality ---

test "fold string equality: same strings" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .string = "deadbeef" })),
        makeBinding("b", makeLoadConst(.{ .string = "deadbeef" })),
        makeBinding("c", .{ .bin_op = .{ .op = "===", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .boolean = true }, result[2]);
}

test "fold string inequality: different strings" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .string = "dead" })),
        makeBinding("b", makeLoadConst(.{ .string = "beef" })),
        makeBinding("c", .{ .bin_op = .{ .op = "!==", .left = "a", .right = "b" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .boolean = true }, result[2]);
}

// --- Loop body folding ---

test "fold constants inside loop body" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    var loop_body = [_]ANFBinding{
        makeBinding("x", makeLoadConst(.{ .integer = 5 })),
        makeBinding("y", makeLoadConst(.{ .integer = 10 })),
        makeBinding("z", .{ .bin_op = .{ .op = "+", .left = "x", .right = "y" } }),
    };
    const loop_node = try allocator.create(types.ANFLoop);
    defer allocator.destroy(loop_node);
    loop_node.* = .{ .count = 3, .body = &loop_body, .iter_var = "i" };

    const bindings = [_]ANFBinding{
        makeBinding("result", .{ .loop = loop_node }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer {
        switch (result[0].value) {
            .loop => |new_loop| {
                allocator.free(new_loop.body);
                allocator.destroy(new_loop);
            },
            else => {},
        }
        allocator.free(result);
    }

    switch (result[0].value) {
        .loop => |folded_loop| {
            try testing.expectEqual(@as(usize, 3), folded_loop.body.len);
            try expectConst(.{ .integer = 15 }, folded_loop.body[2]);
        },
        else => return error.TestExpectedEqual,
    }
}

// --- Passthrough: assert, load_param, load_prop, method_call ---

test "passthrough: load_param unchanged" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("x", .{ .load_param = .{ .name = "x" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try testing.expect(result[0].value == .load_param);
}

test "passthrough: method_call unchanged" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("x", .{ .method_call = .{ .object = "obj", .method = "m", .args = &.{} } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try testing.expect(result[0].value == .method_call);
}

test "passthrough: assert unchanged" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("x", .{ .assert = .{ .value = "cond" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try testing.expect(result[0].value == .assert);
}

// --- Safediv and safemod ---

test "fold builtin safediv(10, 3) = 3" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{ "a", "b" };
    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 10 })),
        makeBinding("b", makeLoadConst(.{ .integer = 3 })),
        makeBinding("c", .{ .call = .{ .func = "safediv", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 3 }, result[2]);
}

test "fold builtin safediv by zero: not folded" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{ "a", "b" };
    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 10 })),
        makeBinding("b", makeLoadConst(.{ .integer = 0 })),
        makeBinding("c", .{ .call = .{ .func = "safediv", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try testing.expect(anfValueToConst(result[2].value) == null);
}

test "fold builtin safemod(10, 3) = 1" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{ "a", "b" };
    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 10 })),
        makeBinding("b", makeLoadConst(.{ .integer = 3 })),
        makeBinding("c", .{ .call = .{ .func = "safemod", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 1 }, result[2]);
}

// --- Divmod ---

test "fold builtin divmod(10, 3) = 3" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const args = [_][]const u8{ "a", "b" };
    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 10 })),
        makeBinding("b", makeLoadConst(.{ .integer = 3 })),
        makeBinding("c", .{ .call = .{ .func = "divmod", .args = &args } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try expectConst(.{ .integer = 3 }, result[2]);
}
