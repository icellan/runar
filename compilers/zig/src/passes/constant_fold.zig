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
const const_arith = @import("const_arith.zig");

const Allocator = std.mem.Allocator;

/// Upper end of the domain `pow` is exact on, shared with the emitted script
/// (`passes/stack_lower.zig#lowerPow` unrolls exactly this many conditional
/// multiplies and enforces the bound with `OP_DUP <0> <33> OP_WITHIN
/// OP_VERIFY`) and with the reference interpreter.
const pow_fold_exponent_limit: u32 = 32;

/// Unroll counts of the emitted `log2` and `gcd` loops (`passes/stack_lower.zig`).
/// Past them the script returns a saturated / partial value, not the
/// mathematical one, so the folder declines there (N-029).
const log2_fold_iterations: usize = 64;
const gcd_fold_iterations: usize = 256;
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

fn evalBinOp(allocator: Allocator, op: []const u8, left: ConstValue, right: ConstValue) !?ConstValue {
    const tag = bin_op_map.get(op) orelse return null;

    // Integer arithmetic / bitwise / comparison.
    //
    // Evaluated at ARBITRARY precision (issue #162). The operands may arrive
    // in either `ConstValue` integer representation, and a result may need
    // more room than either — `(2^63-1)^2` needs 126 bits, `pow(2n, 200n)`
    // needs 201. Folding these in a fixed width either aborted the process on
    // the way to the emitter or, for `pow`, wrapped silently and emitted a
    // different locking script from the other six tiers.
    if (const_arith.isInteger(left) and const_arith.isInteger(right)) {
        var a = (try const_arith.load(allocator, left)) orelse return null;
        defer a.deinit();
        var b = (try const_arith.load(allocator, right)) orelse return null;
        defer b.deinit();

        switch (tag) {
            .op_add, .op_sub, .op_mul => {
                var r = try const_arith.Big.init(allocator);
                defer r.deinit();
                switch (tag) {
                    .op_add => try r.add(&a, &b),
                    .op_sub => try r.sub(&a, &b),
                    else => try r.mul(&a, &b),
                }
                return try const_arith.store(allocator, r);
            },
            .op_div => {
                if (const_arith.isZero(b)) return null;
                var q = try const_arith.divTrunc(allocator, a, b);
                defer q.deinit();
                return try const_arith.store(allocator, q);
            },
            .op_mod => {
                if (const_arith.isZero(b)) return null;
                var r = try const_arith.remTrunc(allocator, a, b);
                defer r.deinit();
                return try const_arith.store(allocator, r);
            },
            .op_strict_eq => return .{ .boolean = const_arith.order(a, b) == .eq },
            .op_strict_neq => return .{ .boolean = const_arith.order(a, b) != .eq },
            .op_lt => return .{ .boolean = const_arith.order(a, b) == .lt },
            .op_gt => return .{ .boolean = const_arith.order(a, b) == .gt },
            .op_lte => return .{ .boolean = const_arith.order(a, b) != .gt },
            .op_gte => return .{ .boolean = const_arith.order(a, b) != .lt },
            // OP_AND/OP_OR/OP_XOR/OP_LSHIFT/OP_RSHIFT operate on the operands'
            // raw script-number BYTES, not their numeric value — native
            // folding diverges from the deployed script (e.g. 255 << 1 is 254
            // on-chain, not 510; 255 & 1 aborts). Never fold; emit the opcode
            // so the interpreter's byte-array semantics govern. Matches TS
            // constant-fold + vm/utils scriptNumber*.
            .op_bit_and, .op_bit_or, .op_bit_xor, .op_shl, .op_shr => return null,
            .op_logical_and, .op_logical_or => return null,
        }
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
            // F-160: OP_EQUAL compares the DECODED bytes and hex decoding
            // ignores case, so 'aa' === 'AA' is true on-chain.
            .op_strict_eq => .{ .boolean = hexEqual(left.string, right.string) },
            .op_strict_neq => .{ .boolean = !hexEqual(left.string, right.string) },
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

/// Compares two ByteString literals as bytes: case-insensitively when both
/// are hex, by exact text otherwise.
fn hexEqual(a: []const u8, b: []const u8) bool {
    if (isHex(a) and isHex(b)) return std.ascii.eqlIgnoreCase(a, b);
    return std.mem.eql(u8, a, b);
}

fn isHex(s: []const u8) bool {
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
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

fn evalUnaryOp(allocator: Allocator, op: []const u8, operand: ConstValue) !?ConstValue {
    const tag = unary_op_map.get(op) orelse return null;

    if (operand == .boolean) {
        return switch (tag) {
            .op_logical_not => .{ .boolean = !operand.boolean },
            else => null,
        };
    }
    if (const_arith.isInteger(operand)) {
        var n = (try const_arith.load(allocator, operand)) orelse return null;
        defer n.deinit();
        switch (tag) {
            .op_negate => {
                var zero = try const_arith.fromI128(allocator, 0);
                defer zero.deinit();
                var r = try const_arith.Big.init(allocator);
                defer r.deinit();
                try r.sub(&zero, &n);
                return try const_arith.store(allocator, r);
            },
            // OP_INVERT flips the operand's script-number bytes, not native
            // ~n (~5 == -122, ~0 == 0). Never fold; emit the opcode so the
            // interpreter's byte-array semantics govern. Matches TS.
            .op_bitwise_not => return null,
            .op_logical_not => return .{ .boolean = const_arith.isZero(n) },
        }
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

/// Evaluate a pure math builtin over constant arguments at ARBITRARY
/// precision (issue #162).
///
/// Mirrors `foldBuiltin` in packages/runar-compiler/src/optimizer/
/// constant-fold.ts operation for operation, including the guards that
/// decline to fold (division by zero, negative or >256 exponents, negative
/// sqrt) — those must stay identical or the tiers disagree about which
/// programs fold at all, not merely about the folded value.
///
/// The previous fixed-width version wrapped: `pow`'s accumulator, `mulDiv`
/// and `percentOf` all used `*%` on `i128`, so `pow(2n, 200n)` silently
/// folded to `2^200 mod 2^128` == 0.
fn evalBuiltinCall(
    allocator: Allocator,
    func_name: []const u8,
    args: []const []const u8,
    env: *const ConstEnv,
) !?ConstValue {
    const tag = builtin_map.get(func_name) orelse return null;

    // Resolve all args to integer constants, in either representation.
    var big_args: [8]const_arith.Big = undefined;
    var count: usize = 0;
    errdefer for (big_args[0..count]) |*m| m.deinit();
    for (args) |arg| {
        const cv = env.get(arg) orelse break;
        if (count >= 8) break;
        big_args[count] = (try const_arith.load(allocator, cv)) orelse break;
        count += 1;
    }
    defer for (big_args[0..count]) |*m| m.deinit();
    // A non-constant / non-integer argument means the call is not foldable.
    if (count != args.len) return null;

    const Big = const_arith.Big;

    switch (tag) {
        .builtin_abs => {
            if (count != 1) return null;
            var r = try Big.init(allocator);
            defer r.deinit();
            try r.copy(big_args[0].toConst());
            r.abs();
            return try const_arith.store(allocator, r);
        },
        .builtin_min, .builtin_max => {
            if (count != 2) return null;
            const ord = const_arith.order(big_args[0], big_args[1]);
            const pick: usize = switch (tag) {
                .builtin_min => if (ord == .gt) 1 else 0,
                else => if (ord == .lt) 1 else 0,
            };
            return try const_arith.store(allocator, big_args[pick]);
        },
        .builtin_safediv, .builtin_divmod => {
            if (count != 2 or const_arith.isZero(big_args[1])) return null;
            var q = try const_arith.divTrunc(allocator, big_args[0], big_args[1]);
            defer q.deinit();
            return try const_arith.store(allocator, q);
        },
        .builtin_safemod => {
            if (count != 2 or const_arith.isZero(big_args[1])) return null;
            var r = try const_arith.remTrunc(allocator, big_args[0], big_args[1]);
            defer r.deinit();
            return try const_arith.store(allocator, r);
        },
        .builtin_clamp => {
            // The script is `<val> <lo> OP_MAX <hi> OP_MIN`: min(max(val, lo), hi).
            // That differs from max(lo, min(val, hi)) once lo > hi (N-029).
            if (count != 3) return null;
            const val = big_args[0];
            const lo = big_args[1];
            const hi = big_args[2];
            const m = if (const_arith.order(val, lo) == .gt) val else lo;
            const clamped = if (const_arith.order(m, hi) == .lt) m else hi;
            return try const_arith.store(allocator, clamped);
        },
        .builtin_sign => {
            if (count != 1) return null;
            const n = big_args[0];
            if (const_arith.isZero(n)) return .{ .integer = 0 };
            return .{ .integer = if (const_arith.isNegative(n)) -1 else 1 };
        },
        .builtin_pow => {
            if (count != 2) return null;
            // Decline outside the domain the emitted script GUARANTEES and
            // ENFORCES (`passes/stack_lower.zig#lowerPow`: 0 <= exp <= 32, the
            // number of unrolled conditional multiplies). The old bound was
            // 256, which folded exponents the script CLAMPED to 32 — so for
            // 33 <= exp <= 256 the fold-ON and fold-OFF scripts accepted
            // mutually exclusive inputs (R-169, the `pow` half). A negative
            // exponent fails `toInt(u32)` and is declined the same way.
            const exp = big_args[1].toConst().toInt(u32) catch return null;
            if (exp > pow_fold_exponent_limit) return null;
            var r = try Big.init(allocator);
            defer r.deinit();
            try r.pow(&big_args[0], exp);
            return try const_arith.store(allocator, r);
        },
        .builtin_mulDiv, .builtin_percentOf => {
            const want: usize = if (tag == .builtin_mulDiv) 3 else 2;
            if (count != want) return null;

            var divisor = if (tag == .builtin_mulDiv)
                try Big.init(allocator)
            else
                try const_arith.fromI128(allocator, 10000);
            defer divisor.deinit();
            if (tag == .builtin_mulDiv) try divisor.copy(big_args[2].toConst());
            if (const_arith.isZero(divisor)) return null;

            var prod = try Big.init(allocator);
            defer prod.deinit();
            try prod.mul(&big_args[0], &big_args[1]);

            var q = try const_arith.divTrunc(allocator, prod, divisor);
            defer q.deinit();
            return try const_arith.store(allocator, q);
        },
        .builtin_sqrt => {
            if (count != 1) return null;
            const n = big_args[0];
            if (const_arith.isNegative(n)) return null;
            // Decline outside the domain the emitted script GUARANTEES and
            // ENFORCES (passes/stack_lower.zig lowerSqrt): n >= 0 and n encodable in
            // <= 62 script bytes, i.e. n < 2^495. Outside it the compiled
            // script aborts, so folding to a value here would make sqrt(k) mean
            // one thing folded and another executed — R-169 at the other end of
            // the domain.
            if (n.toConst().bitCountAbs() > 495) return null;
            if (const_arith.isZero(n)) return .{ .integer = 0 };

            // Newton's method, capped at 256 iterations and terminating when
            // the next guess stops decreasing — the TS reference's exact
            // loop, so both converge on the same value for every input.
            var guess = try Big.init(allocator);
            defer guess.deinit();
            try guess.copy(n.toConst());

            var two = try const_arith.fromI128(allocator, 2);
            defer two.deinit();

            var i: usize = 0;
            while (i < 256) : (i += 1) {
                var div = try const_arith.divTrunc(allocator, n, guess);
                defer div.deinit();
                var sum = try Big.init(allocator);
                defer sum.deinit();
                try sum.add(&guess, &div);
                var next = try const_arith.divTrunc(allocator, sum, two);
                defer next.deinit();
                if (const_arith.order(next, guess) != .lt) break;
                try guess.copy(next.toConst());
            }
            return try const_arith.store(allocator, guess);
        },
        .builtin_gcd => {
            if (count != 2) return null;
            var a = try Big.init(allocator);
            defer a.deinit();
            try a.copy(big_args[0].toConst());
            a.abs();
            var b = try Big.init(allocator);
            defer b.deinit();
            try b.copy(big_args[1].toConst());
            b.abs();

            // The script runs at most gcd_fold_iterations Euclid steps; if
            // that is not enough it returns a partial remainder, not the gcd.
            // Decline there (N-029).
            var step: usize = 0;
            while (step < gcd_fold_iterations and !const_arith.isZero(b)) : (step += 1) {
                var r = try const_arith.remTrunc(allocator, a, b);
                defer r.deinit();
                try a.copy(b.toConst());
                try b.copy(r.toConst());
            }
            if (!const_arith.isZero(b)) return null;
            return try const_arith.store(allocator, a);
        },
        .builtin_log2 => {
            if (count != 1) return null;
            const n = big_args[0];
            // n <= 0 folds to 0, matching the TS reference.
            if (const_arith.isZero(n) or const_arith.isNegative(n)) return .{ .integer = 0 };
            // Bit length - 1. `bitCountAbs` is exact for a positive value.
            const bits = n.toConst().bitCountAbs();
            // The script halves at most log2_fold_iterations times, so it
            // saturates at 64 for n >= 2^65. Decline there (N-029).
            if (bits - 1 > log2_fold_iterations) return null;
            return .{ .integer = @as(i128, @intCast(bits - 1)) };
        },
        .builtin_bool => {
            if (count != 1) return null;
            return .{ .boolean = !const_arith.isZero(big_args[0]) };
        },
    }
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

    // If the folded value is a load_const, register in the environment.
    // Skip @ref: values — they are symbolic references to runtime bindings, not foldable constants.
    //
    // A name may be bound more than once (reassignment, or a user local that
    // shares a compiler temp's name). The env must track the LATEST binding:
    // a rebinding to a non-constant drops the old constant, or later uses
    // would fold with a value the name no longer holds (N-064).
    var registered = false;
    if (anfValueToConst(folded_value)) |cv| {
        const skip = switch (cv) {
            .string => |s| std.mem.startsWith(u8, s, "@ref:"),
            else => false,
        };
        if (!skip) {
            try env.put(binding.name, cv);
            registered = true;
        }
    }
    if (!registered) _ = env.remove(binding.name);

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
                if (try evalBinOp(allocator, bo.op, left_const.?, right_const.?)) |result| {
                    return constToAnfValue(result);
                }
            }
            return value;
        },

        .unary_op => |uo| {
            const operand_const = env.get(uo.operand);
            if (operand_const) |oc| {
                if (try evalUnaryOp(allocator, uo.op, oc)) |result| {
                    return constToAnfValue(result);
                }
            }
            return value;
        },

        .call => |c| {
            if (try evalBuiltinCall(allocator, c.func, c.args, env)) |result| {
                return constToAnfValue(result);
            }
            return value;
        },

        .method_call => return value,

        .@"if" => |if_node| {
            // Fold both arms independently, ALWAYS -- including when the
            // condition is a compile-time constant.
            //
            // This pass used to "optimise" a statically-known condition by
            // blanking the untaken arm (.@"else" = &.{}) while LEAVING the
            // `if` node itself in place, and by propagating the taken arm's
            // constants into the enclosing env. Both halves were unsound:
            //
            //   * An arm is not a free-floating binding list -- it carries a
            //     STACK-SHAPE CONTRACT that ANF lowering establishes and stack
            //     lowering depends on. For two or more branch-merged locals
            //     both arms end with the identical __merge$<i> result block,
            //     which is how lowerIf learns K and adopts the K results by
            //     name. Blanking one arm makes the merged-result count 0, the
            //     N>=2 name-matched reconcile cannot fire, and ONE stack slot
            //     is registered for K physical results -- every post-branch
            //     operand then resolves one or more slots off. At K=2 that
            //     miscompiled SILENTLY: the deployed script accepted spends
            //     the source rejects and rejected spends the source accepts.
            //     At K=1 it surfaced as "value not found on stack", a
            //     compile-time rejection of source that compiles with folding
            //     disabled.
            //   * Propagating the taken arm's constants outward is only sound
            //     if the other arm is really gone. The `if` node survives this
            //     pass, so both arms are still emitted and either can run.
            //
            // Correct dead-arm elimination would have to delete the `if` and
            // splice the live arm into the parent, re-establishing the
            // parent's shape. That is a lowering-level rewrite, not a fold, so
            // it does not live here. The bytes given up are the
            // statically-dead arm's ops, which never execute.
            var then_env = try cloneEnv(allocator, env);
            defer then_env.deinit();
            var else_env = try cloneEnv(allocator, env);
            defer else_env.deinit();
            const folded_then = try foldBindings(allocator, if_node.then, &then_env);
            const folded_else = try foldBindings(allocator, if_node.@"else", &else_env);
            // N-064: a name either arm rebinds may hold the arm's value after
            // the if (that is how a branch reassigns a local), so the enclosing
            // env's constant for it is stale past this point.
            removeBoundNames(env, if_node.then);
            removeBoundNames(env, if_node.@"else");

            const new_if = try allocator.create(types.ANFIf);
            new_if.* = .{
                .cond = if_node.cond,
                .then = folded_then,
                .@"else" = folded_else,
                // The declared result list survives folding untouched: folding
                // an arm's bindings cannot change WHICH slots the arm leaves,
                // and dropping the list would silently return the `if` to the
                // single-result reconcile it was migrated off.
                .results = if_node.results,
            };
            return .{ .@"if" = new_if };
        },

        .loop => |loop_node| {
            // N-064: the body runs once per iteration, so a name it rebinds
            // holds the entry constant only in iteration 0 -- it is not a
            // constant inside the body, nor after the loop.
            var body_env = try cloneEnv(allocator, env);
            defer body_env.deinit();
            removeBoundNames(&body_env, loop_node.body);
            const folded_body = try foldBindings(allocator, loop_node.body, &body_env);
            removeBoundNames(env, loop_node.body);

            const new_loop = try allocator.create(types.ANFLoop);
            new_loop.* = .{
                .count = loop_node.count,
                .body = folded_body,
                .iter_var = loop_node.iter_var,
                // Issue #121: preserve the iterator start value / step direction.
                .start = loop_node.start,
                .step = loop_node.step,
            };
            return .{ .loop = new_loop };
        },

        // F-003: every remaining variant is enumerated explicitly (no `else`
        // arm) so that adding a new ANFValue variant becomes a Zig compile
        // error here instead of silently passing through and corrupting fold
        // output. Mirrors the `UnknownANFKindError` default in TS
        // `optimizer/constant-fold.ts#foldValue`.
        .assert,
        .update_prop,
        .get_state_script,
        .check_preimage,
        .deserialize_state,
        .add_output,
        .add_raw_output,
        .add_data_output,
        .array_literal,
        .raw_script,
        => return value,
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

/// Drop from `env` every name bound in `bindings`, including inside nested if
/// arms and loop bodies.
fn removeBoundNames(env: *ConstEnv, bindings: []const ANFBinding) void {
    for (bindings) |b| {
        _ = env.remove(b.name);
        switch (b.value) {
            .@"if" => |n| {
                removeBoundNames(env, n.then);
                removeBoundNames(env, n.@"else");
            },
            .loop => |n| removeBoundNames(env, n.body),
            else => {},
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
        // #123: preserve the in-memory @sighash carrier across the rebuild.
        .sighash_type = method.sighash_type,
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

// Bitwise/shift ops are NEVER folded: they operate on the operands' minimal
// script-number bytes at runtime, not their numeric value. Folding is skipped
// so codegen emits OP_AND/OP_LSHIFT etc. (Previously these tests asserted the
// native-integer fold results 0x0f and 256, which disagreed with the deployed
// script — see the byte-array truth table in sdk_anf_interpreter.zig.)
test "no-fold bitwise and: & left for the opcode (byte semantics)" {
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
    try testing.expect(anfValueToConst(result[2].value) == null);
}

test "no-fold left shift: << left for the opcode (byte semantics)" {
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
    try testing.expect(anfValueToConst(result[2].value) == null);
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

// OP_INVERT flips the operand's minimal script-number bytes, so ~0 is 0
// (encode(0) is empty; inverting nothing yields 0), NOT native -1. Never fold;
// leave the node so codegen emits OP_INVERT. (Previously asserted -1.)
test "no-fold unary bitnot: ~ left for the opcode (byte semantics)" {
    const allocator = testing.allocator;
    var env = ConstEnv.init(allocator);
    defer env.deinit();

    const bindings = [_]ANFBinding{
        makeBinding("a", makeLoadConst(.{ .integer = 0 })),
        makeBinding("b", .{ .unary_op = .{ .op = "~", .operand = "a" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer allocator.free(result);
    try testing.expect(anfValueToConst(result[1].value) == null);
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

// N-029: every folded value must be what the emitted script computes.
// clamp lowers to `<v> <lo> OP_MAX <hi> OP_MIN` = min(max(v, lo), hi), which
// differs from max(lo, min(v, hi)) once lo > hi; log2 unrolls 64 halvings and
// gcd 256 Euclid steps, so past those the script returns a saturated / partial
// value and the folder must decline. Expected values were executed on @bsv/sdk
// Spend.validate by
// packages/runar-testing/src/__tests__/n029-fold-builtin-script-parity.test.ts.
// Proves the Zig folder's value/decline decisions; not the script itself.
const n029_fib257 = "229265413057075367692743352179590077832064383222590237";
const n029_fib258 = "370959230771131880927453318055001997489772178180790104";
const n029_fib259 = "600224643828207248620196670234592075321836561403380341";

/// Fold `func(args...)` over all-constant args; returns the folded value of
/// the call binding, or null when the folder declined.
fn n029Fold(arena: Allocator, func: []const u8, args: []const ConstValue) !?ConstValue {
    var env = ConstEnv.init(arena);
    const names = [_][]const u8{ "t0", "t1", "t2" };
    var bindings: [4]ANFBinding = undefined;
    for (args, 0..) |a, i| bindings[i] = makeBinding(names[i], makeLoadConst(a));
    bindings[args.len] = makeBinding("r", .{ .call = .{ .func = func, .args = names[0..args.len] } });
    const result = try foldBindings(arena, bindings[0 .. args.len + 1], &env);
    return anfValueToConst(result[args.len].value);
}

test "N-029 clamp with lo > hi folds to min(max(v, lo), hi), as the script computes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cases = [_]struct { args: [3]i128, want: i128 }{
        .{ .args = .{ 5, 10, 0 }, .want = 0 },
        .{ .args = .{ 0, 3, -3 }, .want = -3 },
        .{ .args = .{ -20, 10, 0 }, .want = 0 },
    };
    for (cases) |c| {
        const args = [_]ConstValue{ .{ .integer = c.args[0] }, .{ .integer = c.args[1] }, .{ .integer = c.args[2] } };
        const got = (try n029Fold(a, "clamp", &args)) orelse return error.TestExpectedEqual;
        try testing.expect(got.eql(.{ .integer = c.want }));
    }
}

test "N-029 log2 declines past the script's 64 halvings" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const one: i128 = 1;
    const got64 = (try n029Fold(a, "log2", &.{.{ .integer = one << 64 }})) orelse return error.TestExpectedEqual;
    try testing.expect(got64.eql(.{ .integer = 64 }));
    const got64b = (try n029Fold(a, "log2", &.{.{ .integer = (one << 65) - 1 }})) orelse return error.TestExpectedEqual;
    try testing.expect(got64b.eql(.{ .integer = 64 }));
    try testing.expect((try n029Fold(a, "log2", &.{.{ .integer = one << 65 }})) == null);
    try testing.expect((try n029Fold(a, "log2", &.{.{ .integer = one << 70 }})) == null);
}

test "N-029 gcd declines past the script's 256 Euclid steps" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const exact = (try n029Fold(a, "gcd", &.{ .{ .big_integer = n029_fib258 }, .{ .big_integer = n029_fib257 } })) orelse return error.TestExpectedEqual;
    try testing.expect(exact.eql(.{ .integer = 1 }));
    try testing.expect((try n029Fold(a, "gcd", &.{ .{ .big_integer = n029_fib259 }, .{ .big_integer = n029_fib258 } })) == null);
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

// A statically-known condition must NOT blank the untaken arm.
//
// The folder used to return an empty arm while leaving the `if` node itself in
// place. An arm is not a free-floating binding list -- it carries the
// stack-shape contract ANF lowering builds (the __merge$<i> result block for
// K>=2 merged locals) and stack lowering consumes. Erasing one arm made
// lowerIfExprImpl register ONE stack slot for K physical results, which at K=2
// silently miscompiled the guard (the deployed script accepted spends the
// source rejects) and at K=1 rejected source that compiles with folding
// disabled.

test "fold if with known true condition keeps BOTH arms" {
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
        switch (result[1].value) {
            .@"if" => |new_if| {
                allocator.free(new_if.then);
                allocator.free(new_if.@"else");
                allocator.destroy(new_if);
            },
            else => {},
        }
        allocator.free(result);
    }

    switch (result[1].value) {
        .@"if" => |folded_if| {
            try testing.expectEqual(@as(usize, 1), folded_if.then.len);
            try testing.expectEqual(@as(usize, 1), folded_if.@"else".len);
        },
        else => return error.TestExpectedEqual,
    }
}

test "fold if with known false condition keeps BOTH arms" {
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
                allocator.free(new_if.then);
                allocator.free(new_if.@"else");
                allocator.destroy(new_if);
            },
            else => {},
        }
        allocator.free(result);
    }

    switch (result[1].value) {
        .@"if" => |folded_if| {
            try testing.expectEqual(@as(usize, 1), folded_if.then.len);
            try testing.expectEqual(@as(usize, 1), folded_if.@"else".len);
        },
        else => return error.TestExpectedEqual,
    }
}

// A statically-known condition must not leak an arm's constants into the
// enclosing environment either: the `if` survives the pass, so both arms are
// still emitted and either can run.
test "fold if with known condition does not propagate the taken arm's constants" {
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
        makeBinding("after", .{ .bin_op = .{ .op = "+", .left = "x", .right = "x" } }),
    };
    const result = try foldBindings(allocator, &bindings, &env);
    defer {
        switch (result[1].value) {
            .@"if" => |new_if| {
                allocator.free(new_if.then);
                allocator.free(new_if.@"else");
                allocator.destroy(new_if);
            },
            else => {},
        }
        allocator.free(result);
    }

    try testing.expect(result[2].value == .bin_op);
}

// N-068: `mergeEnv` ("merge constants from a branch environment into the
// parent, only adding new entries") is the exact unsound add-only merge the
// test above pins the ABSENCE of -- it is never called by the live `if` case
// (which only ever removes names via `removeBoundNames`, never merges one
// branch's env into the parent). This test proves no such helper exists to be
// wired back in by a future edit. It does NOT prove the live if-fold path is
// sound on its own -- that is what "fold if with known condition does not
// propagate the taken arm's constants" above already covers.
test "no branch-env merge helper exists to be wired into the if fold" {
    try testing.expect(!@hasDecl(@This(), "mergeEnv"));
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

// F-160: 'aa' and 'AA' decode to the same byte, so OP_EQUAL is true on-chain
// and the fold must say so. Proves the Zig folder's verdict on mixed-case hex;
// not the emitted script (conformance/negatives/f160-bytestring-case-fold-parity
// pins every tier's bytes).
test "fold string equality ignores hex case (F-160)" {
    const allocator = testing.allocator;
    const cases = [_]struct { op: []const u8, want: bool }{
        .{ .op = "===", .want = true },
        .{ .op = "!==", .want = false },
    };
    for (cases) |tc| {
        var env = ConstEnv.init(allocator);
        defer env.deinit();
        const bindings = [_]ANFBinding{
            makeBinding("a", makeLoadConst(.{ .string = "aa" })),
            makeBinding("b", makeLoadConst(.{ .string = "AA" })),
            makeBinding("c", .{ .bin_op = .{ .op = tc.op, .left = "a", .right = "b" } }),
        };
        const result = try foldBindings(allocator, &bindings, &env);
        defer allocator.free(result);
        try expectConst(.{ .boolean = tc.want }, result[2]);
    }
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
