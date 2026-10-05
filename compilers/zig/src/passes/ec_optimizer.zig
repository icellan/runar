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
const dce = @import("dce.zig");
const const_arith = @import("const_arith.zig");
const Allocator = std.mem.Allocator;

// ============================================================================
// secp256k1 constants
// ============================================================================

/// Curve order N for secp256k1.
const CURVE_N: u256 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

/// The same value as canonical hex text, for `Big.setString`. A folded scalar
/// is a value mod N and routinely exceeds `i128`, so the reduction has to run
/// at arbitrary precision — `u256` arithmetic cannot even hold `a + b` for
/// two operands in [0, N).
const CURVE_N_HEX = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

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
        new_methods[i] = try optimizeMethod(allocator, method, program.properties);
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

/// F-086: every name the method already uses — binding names at any depth
/// (if/loop arms included), loop iteration variables, params, and the
/// contract's properties. A scalar-fusing rewrite mints a new binding; ANF is
/// single-assignment and stack lowering resolves a name to its shallowest
/// slot, so a minted name that is already in use silently aliases the two
/// values. `compile-ir` input chooses these names freely.
fn collectUsedNames(
    used: *std.StringHashMap(void),
    method: types.ANFMethod,
    properties: []const types.ANFProperty,
) !void {
    for (properties) |p| try used.put(p.name, {});
    for (method.params) |p| try used.put(p.name, {});
    try collectBindingNames(used, method.body);
}

fn collectBindingNames(used: *std.StringHashMap(void), bindings: []const types.ANFBinding) !void {
    for (bindings) |b| {
        try used.put(b.name, {});
        switch (b.value) {
            .load_param => |lp| try used.put(lp.name, {}),
            .load_prop => |lp| try used.put(lp.name, {}),
            .@"if" => |iv| {
                try collectBindingNames(used, iv.then);
                try collectBindingNames(used, iv.@"else");
            },
            .loop => |lv| {
                try used.put(lv.iter_var, {});
                try collectBindingNames(used, lv.body);
            },
            else => {},
        }
    }
}

fn optimizeMethod(allocator: Allocator, method: types.ANFMethod, properties: []const types.ANFProperty) !types.ANFMethod {
    var body = try allocator.alloc(types.ANFBinding, method.body.len);
    @memcpy(body, method.body);

    // F-086: names a minted binding must avoid; minted names are added too.
    var used_names = std.StringHashMap(void).init(allocator);
    defer used_names.deinit();
    try collectUsedNames(&used_names, method, properties);

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
            // `new_body` doubles as the prelude list: a rule that folds a new
            // constant appends its binding here, i.e. immediately BEFORE the
            // binding being rewritten (see `freshConstName`).
            if (tryOptimize(allocator, binding.name, current.value, &value_map, &used_names, &new_body)) |optimized| {
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

    var rooted = method;
    rooted.body = body;
    const optimized_body = try dce.eliminateDeadBindingsInMethod(allocator, rooted);
    allocator.free(body);
    body = optimized_body;

    return .{
        .name = method.name,
        .is_public = method.is_public,
        .params = method.params,
        .bindings = method.bindings,
        .body = body,
        // #123: preserve the in-memory @sighash carrier across the rebuild.
        .sighash_type = method.sighash_type,
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
    name: []const u8,
    v: types.ANFValue,
    vm: *std.StringHashMap(types.ANFValue),
    used: *std.StringHashMap(void),
    prelude: *std.ArrayListUnmanaged(types.ANFBinding),
) ?types.ANFValue {
    const c = switch (v) {
        .call => |call| call,
        else => return null,
    };

    const func = c.func;
    const args = c.args;

    // Rule 1: ecAdd(x, INFINITY) -> x, keeping ecAdd's operand gate (N-104)
    if (eql(func, "ecAdd") and args.len == 2 and isInfinity(args[1], vm)) {
        const ref = makeRef(allocator, args[0]) orelse return null;
        if (!emitOperandGate(allocator, .add, name, args[0], vm, used, prelude)) return null;
        return ref;
    }

    // Rule 2: ecAdd(INFINITY, x) -> x, keeping ecAdd's operand gate (N-104)
    if (eql(func, "ecAdd") and args.len == 2 and isInfinity(args[0], vm)) {
        const ref = makeRef(allocator, args[1]) orelse return null;
        if (!emitOperandGate(allocator, .add, name, args[1], vm, used, prelude)) return null;
        return ref;
    }

    // Rule 3: ecMul(x, 1) -> x, keeping ecMul's operand gate (N-104)
    if (eql(func, "ecMul") and args.len == 2 and isConstInt(allocator, args[1], 1, vm)) {
        const ref = makeRef(allocator, args[0]) orelse return null;
        if (!emitOperandGate(allocator, .mul, name, args[0], vm, used, prelude)) return null;
        return ref;
    }

    // Rule 4: ecMul(x, 0) -> INFINITY, keeping ecMul's operand gate (N-104)
    if (eql(func, "ecMul") and args.len == 2 and isConstInt(allocator, args[1], 0, vm)) {
        if (!emitOperandGate(allocator, .mul, name, args[0], vm, used, prelude)) return null;
        return makeConstHex(INFINITY_HEX);
    }

    // Rule 5: ecMulGen(0) -> INFINITY
    if (eql(func, "ecMulGen") and args.len == 1 and isConstInt(allocator, args[0], 0, vm))
        return makeConstHex(INFINITY_HEX);

    // Rule 6: ecMulGen(1) -> G
    if (eql(func, "ecMulGen") and args.len == 1 and isConstInt(allocator, args[0], 1, vm))
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

    // Rule 8r (`ec-add-negate-cancel-reversed`): ecAdd(ecNegate(x), x) -> INFINITY
    //
    // The mirror of Rule 8. It has always been in optimizer/ec-rules.json and the
    // Go tier -- whose rule engine executes that file directly -- performed it;
    // the six hand-ported tiers implemented only the forward direction, so the
    // same ANF compiled to a 1808-byte script in Go and a 26140-byte one
    // everywhere else (R-034 / CL-BUG-028).
    //
    // Placed after Rule 8 and before Rules 9/10/11 to match the JSON's rule
    // order, which is the order the Go engine tries them in.
    if (eql(func, "ecAdd") and args.len == 2) {
        if (resolveCall(args[0], vm)) |nc| {
            if (eql(nc.func, "ecNegate") and nc.args.len == 1 and sameBinding(args[1], nc.args[0], vm))
                return makeConstHex(INFINITY_HEX);
        }
    }

    // Rule 9: ecMul(ecMul(p, k1), k2) -> ecMul(p, k1*k2 mod N)
    if (eql(func, "ecMul") and args.len == 2) {
        if (getConstBig(allocator, args[1], vm)) |k2_loaded| {
            var k2 = k2_loaded;
            defer k2.deinit();
            if (resolveCall(args[0], vm)) |ic| {
                if (eql(ic.func, "ecMul") and ic.args.len == 2) {
                    if (getConstBig(allocator, ic.args[1], vm)) |k1_loaded| {
                        var k1 = k1_loaded;
                        defer k1.deinit();
                        const combined = combineModN(allocator, k1, k2, .mul) catch return null;
                        const fresh = freshConstName(allocator, name, combined, vm, used, prelude) orelse return null;
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
                var k1 = getConstBig(allocator, lc.?.args[0], vm);
                defer if (k1) |*m| m.deinit();
                var k2 = getConstBig(allocator, rc.?.args[0], vm);
                defer if (k2) |*m| m.deinit();
                if (k1 != null and k2 != null) {
                    const combined = combineModN(allocator, k1.?, k2.?, .add) catch return null;
                    const fresh = freshConstName(allocator, name, combined, vm, used, prelude) orelse return null;
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
                    var k1 = getConstBig(allocator, lc.?.args[1], vm);
                    defer if (k1) |*m| m.deinit();
                    var k2 = getConstBig(allocator, rc.?.args[1], vm);
                    defer if (k2) |*m| m.deinit();
                    if (k1 != null and k2 != null) {
                        const combined = combineModN(allocator, k1.?, k2.?, .add) catch return null;
                        const fresh = freshConstName(allocator, name, combined, vm, used, prelude) orelse return null;
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

fn isConstInt(allocator: Allocator, name: []const u8, n: i128, vm: *std.StringHashMap(types.ANFValue)) bool {
    var v = getConstBig(allocator, name, vm) orelse return false;
    defer v.deinit();
    const got = v.toConst().toInt(i128) catch return false;
    return got == n;
}

/// Read a constant scalar at full precision from EITHER integer
/// representation. `ConstValue` splits the one arbitrary-precision Rúnar
/// integer domain across `integer: i128` and `big_integer: []const u8`
/// (ir/types.zig), and a real secp256k1 scalar only ever lands in the latter —
/// so matching `.integer` alone made every rule keyed on a constant scalar
/// silently decline for exactly the operands that matter.
///
/// Caller owns the returned value and must `deinit` it.
fn getConstBig(allocator: Allocator, name: []const u8, vm: *std.StringHashMap(types.ANFValue)) ?const_arith.Big {
    const val = resolve(name, vm) orelse return null;
    const lc = switch (val) {
        .load_const => |c| c,
        else => return null,
    };
    return (const_arith.load(allocator, lc.value) catch return null) orelse null;
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

fn makeCall(allocator: Allocator, func: []const u8, args: []const []const u8) ?types.ANFValue {
    const owned = allocator.alloc([]const u8, args.len) catch return null;
    @memcpy(owned, args);
    return .{ .call = .{ .func = func, .args = owned } };
}

/// secp256k1 field prime, as the canonical decimal text `ConstValue.big_integer`
/// carries (it does not fit `i128`).
const FIELD_P_DEC = "115792089237316195423570985008687907853269984665640564039457584007908834671663";

const GateOf = enum { add, mul };

/// N-104 -- the operand gate a rewrite must leave behind. Byte-for-byte the TS
/// reference (`emitAddOperandGate` / `emitMulOperandGate` in
/// packages/runar-compiler/src/optimizer/anf-ec.ts) and the "gate" entries in
/// optimizer/ec-rules.json:
///
///   ecAdd: assert(ecPointX(q) < p && ecPointY(q) < p)   width (CL-BUG-095) + canonicity (R-117)
///   ecMul: assert(q === O || ecOnCurve(q))               on-curve-or-O (R-157)
///
/// R1-R4 replace a builtin whose first act is to validate q; without this a
/// malformed or off-curve q was accepted by the default compile and aborted
/// under disableEcOptimizer. Built only from forms no rule matches, so the
/// fixed-point loop cannot rewrite it on a later pass. Names follow the TS
/// `freshName`: `<base><suffix>`, else the first unused `..._<i>`.
///
/// Builds every binding first and appends them to `prelude` only once all
/// allocations succeeded, so a false return (the caller then declines the
/// rewrite) never leaves a half-built gate behind.
fn emitOperandGate(
    allocator: Allocator,
    of: GateOf,
    base: []const u8,
    q: []const u8,
    vm: *std.StringHashMap(types.ANFValue),
    used: *std.StringHashMap(void),
    prelude: *std.ArrayListUnmanaged(types.ANFBinding),
) bool {
    var out: [7]types.ANFBinding = undefined;
    var n: usize = 0;
    const Builder = struct {
        fn name(a: Allocator, u: *std.StringHashMap(void), b: []const u8, suffix: []const u8) ?[]const u8 {
            var nm = std.fmt.allocPrint(a, "{s}{s}", .{ b, suffix }) catch return null;
            var i: usize = 1;
            while (u.contains(nm)) : (i += 1) {
                nm = std.fmt.allocPrint(a, "{s}{s}_{d}", .{ b, suffix, i }) catch return null;
            }
            u.put(nm, {}) catch return null;
            return nm;
        }
    };
    const push = struct {
        fn f(o: *[7]types.ANFBinding, k: *usize, nm: []const u8, v: types.ANFValue) []const u8 {
            o[k.*] = .{ .name = nm, .value = v, .source_loc = null };
            k.* += 1;
            return nm;
        }
    }.f;
    var ok_name: []const u8 = undefined;
    switch (of) {
        .add => {
            const px = push(&out, &n, Builder.name(allocator, used, base, "_px") orelse return false, makeCall(allocator, "ecPointX", &.{q}) orelse return false);
            const py = push(&out, &n, Builder.name(allocator, used, base, "_py") orelse return false, makeCall(allocator, "ecPointY", &.{q}) orelse return false);
            const fp = push(&out, &n, Builder.name(allocator, used, base, "_fp") orelse return false, .{ .load_const = .{ .value = .{ .big_integer = FIELD_P_DEC } } });
            const x_ok = push(&out, &n, Builder.name(allocator, used, base, "_pxok") orelse return false, .{ .bin_op = .{ .op = "<", .left = px, .right = fp } });
            const y_ok = push(&out, &n, Builder.name(allocator, used, base, "_pyok") orelse return false, .{ .bin_op = .{ .op = "<", .left = py, .right = fp } });
            ok_name = push(&out, &n, Builder.name(allocator, used, base, "_ok") orelse return false, .{ .bin_op = .{ .op = "&&", .left = x_ok, .right = y_ok } });
        },
        .mul => {
            const inf = push(&out, &n, Builder.name(allocator, used, base, "_inf") orelse return false, makeConstHex(INFINITY_HEX));
            const is_inf = push(&out, &n, Builder.name(allocator, used, base, "_isinf") orelse return false, .{ .bin_op = .{ .op = "===", .left = q, .right = inf, .result_type = "bytes" } });
            const on_curve = push(&out, &n, Builder.name(allocator, used, base, "_oncurve") orelse return false, makeCall(allocator, "ecOnCurve", &.{q}) orelse return false);
            ok_name = push(&out, &n, Builder.name(allocator, used, base, "_ok") orelse return false, .{ .bin_op = .{ .op = "||", .left = is_inf, .right = on_curve } });
        },
    }
    _ = push(&out, &n, Builder.name(allocator, used, base, "_gate") orelse return false, .{ .assert = .{ .value = ok_name } });
    for (out[0..n]) |b| {
        vm.put(b.name, b.value) catch return false;
        prelude.append(allocator, b) catch return false;
    }
    return true;
}

/// Bind a freshly folded constant and return its name.
///
/// The binding is appended to `prelude` — the rebuilt method body, at the
/// point just before the binding currently being rewritten — as well as
/// registered in the value map. Registering it in the value map alone is NOT
/// enough: stack lowering walks the body, so a call referencing a name that
/// never got a binding dies with `VariableNotFound` and the contract does not
/// compile at all. Mirrors `AnfOptimize.freshConstName` (Java),
/// `insertBefore` (Go), the `newBindings` list in `anf-ec.ts` (TypeScript)
/// and `_fresh_const_name` / `fresh_const_name` (Python / Ruby).
///
/// Returns null when the binding could not be allocated, so the caller
/// declines the rewrite rather than emitting a dangling reference.
///
/// N-112: the name follows the TS `freshName(`${binding.name}_k`, usedNames)`
/// in anf-ec.ts: `<base>_k`, else the first unused `<base>_k_<i>` (F-086:
/// against every name the method already uses, see `collectUsedNames`), and
/// is reserved there.
fn freshConstName(
    allocator: Allocator,
    base: []const u8,
    value: types.ConstValue,
    vm: *std.StringHashMap(types.ANFValue),
    used: *std.StringHashMap(void),
    prelude: *std.ArrayListUnmanaged(types.ANFBinding),
) ?[]const u8 {
    var name = std.fmt.allocPrint(allocator, "{s}_k", .{base}) catch return null;
    var i: usize = 1;
    while (used.contains(name)) : (i += 1) {
        name = std.fmt.allocPrint(allocator, "{s}_k_{d}", .{ base, i }) catch return null;
    }
    used.put(name, {}) catch return null;
    const binding_value = types.ANFValue{ .load_const = .{ .value = value } };
    vm.put(name, binding_value) catch return null;
    prelude.append(allocator, .{ .name = name, .value = binding_value, .source_loc = null }) catch return null;
    return name;
}

// ============================================================================
// Modular arithmetic at arbitrary precision
// ============================================================================

const ModOp = enum { add, mul };

/// `(a + b) mod N` or `(a * b) mod N`, reduced into [0, N).
///
/// `divFloor` yields a remainder whose sign follows the (positive) divisor, so
/// this is the Euclidean reduction that `BigInteger.mod` (Java) and `%`
/// (Python / Ruby) produce — the tiers this port follows. The result is
/// normalised back through `const_arith.store`, which keeps a value that fits
/// `i128` in the `.integer` variant per the `ConstValue` contract and only
/// reaches for `.big_integer` on overflow.
fn combineModN(
    allocator: Allocator,
    a: const_arith.Big,
    b: const_arith.Big,
    comptime op: ModOp,
) !types.ConstValue {
    var n = try const_arith.Big.init(allocator);
    defer n.deinit();
    try n.setString(16, CURVE_N_HEX);

    var acc = try const_arith.Big.init(allocator);
    defer acc.deinit();
    switch (op) {
        .add => try acc.add(&a, &b),
        .mul => try acc.mul(&a, &b),
    }

    var q = try const_arith.Big.init(allocator);
    defer q.deinit();
    var r = try const_arith.Big.init(allocator);
    defer r.deinit();
    try q.divFloor(&r, &acc, &n);

    return const_arith.store(allocator, r);
}

// ============================================================================
// Dead binding elimination — delegates to the standalone dce.zig module
// ============================================================================

const eliminateDeadBindings = dce.eliminateDeadBindings;

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

fn findValue(body: []const types.ANFBinding, name: []const u8) !types.ANFValue {
    for (body) |b| if (std.mem.eql(u8, b.name, name)) return b.value;
    return error.TestUnexpectedResult;
}

// --- Rule 1: ecAdd(x, INFINITY) -> x ---
test "rule 1: ecAdd(x, INFINITY) -> x" {
    // N-104: the operand gate's names and call args are not individually
    // owned by the result, so freeOptimizeResult cannot release them.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var body = [_]types.ANFBinding{
        makeBinding("t0", .{ .load_const = .{ .value = .{ .integer = 42 } } }),
        makeBinding("inf", .{ .load_const = .{ .value = .{ .string = INFINITY_HEX } } }),
        makeBinding("t2", .{ .call = .{ .func = "ecAdd", .args = &.{ "t0", "inf" } } }),
        makeBinding("t3", .{ .assert = .{ .value = "t2" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    // After optimization t2 = @ref:t0, dead binding elimination removes unused
    // "inf". N-104: ecAdd's operand gate now precedes t2, so find it by name.
    try expectRefTo(try findValue(result.methods[0].body, "t2"), "t0");
}

// --- Rule 2: ecAdd(INFINITY, x) -> x ---
test "rule 2: ecAdd(INFINITY, x) -> x" {
    // N-104: the operand gate's names and call args are not individually
    // owned by the result, so freeOptimizeResult cannot release them.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var body = [_]types.ANFBinding{
        makeBinding("inf", .{ .load_const = .{ .value = .{ .string = INFINITY_HEX } } }),
        makeBinding("t1", .{ .load_const = .{ .value = .{ .integer = 42 } } }),
        makeBinding("t2", .{ .call = .{ .func = "ecAdd", .args = &.{ "inf", "t1" } } }),
        makeBinding("t3", .{ .assert = .{ .value = "t2" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    // After optimization t2 = @ref:t1, dead binding elimination removes unused
    // "inf". N-104: ecAdd's operand gate now precedes t2, so find it by name.
    try expectRefTo(try findValue(result.methods[0].body, "t2"), "t1");
}

// --- Rule 3: ecMul(x, 1) -> x ---
test "rule 3: ecMul(x, 1) -> x" {
    // N-104: the operand gate's names and call args are not individually
    // owned by the result, so freeOptimizeResult cannot release them.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var body = [_]types.ANFBinding{
        makeBinding("p", .{ .load_const = .{ .value = .{ .string = G_HEX } } }),
        makeBinding("k", .{ .load_const = .{ .value = .{ .integer = 1 } } }),
        makeBinding("t0", .{ .call = .{ .func = "ecMul", .args = &.{ "p", "k" } } }),
        makeBinding("t1", .{ .assert = .{ .value = "t0" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    // After optimization t0 = @ref:p, dead binding elimination removes unused
    // "k". N-104: ecMul's operand gate now precedes t0, so find it by name.
    try expectRefTo(try findValue(result.methods[0].body, "t0"), "p");
}

// --- Rule 4: ecMul(x, 0) -> INFINITY ---
test "rule 4: ecMul(x, 0) -> INFINITY" {
    // N-104: the operand gate's names and call args are not individually
    // owned by the result, so freeOptimizeResult cannot release them.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var body = [_]types.ANFBinding{
        makeBinding("p", .{ .load_const = .{ .value = .{ .string = G_HEX } } }),
        makeBinding("k", .{ .load_const = .{ .value = .{ .integer = 0 } } }),
        makeBinding("t0", .{ .call = .{ .func = "ecMul", .args = &.{ "p", "k" } } }),
        makeBinding("t1", .{ .assert = .{ .value = "t0" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    // After optimization t0 = INFINITY_HEX and "k" is dead. N-104: ecMul's
    // operand gate now reads "p" and precedes t0, so find it by name.
    try expectConstStr(try findValue(result.methods[0].body, "t0"), INFINITY_HEX);
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

// --- Rule 8r (ec-add-negate-cancel-reversed): ecAdd(ecNegate(x), x) -> INFINITY ---
// The operand order rule 8 above does NOT cover. optimizer/ec-rules.json declares
// both directions with no "supported" tag; only the Go tier implemented this one
// (R-034 / CL-BUG-028).
test "rule 8r: ecAdd(ecNegate(x), x) -> INFINITY" {
    const alloc = testing.allocator;
    var body = [_]types.ANFBinding{
        makeBinding("p", .{ .load_const = .{ .value = .{ .string = G_HEX } } }),
        makeBinding("neg", .{ .call = .{ .func = "ecNegate", .args = &.{"p"} } }),
        makeBinding("t0", .{ .call = .{ .func = "ecAdd", .args = &.{ "neg", "p" } } }),
        makeBinding("t1", .{ .assert = .{ .value = "t0" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    defer freeOptimizeResult(alloc, result);
    try expectConstStr(result.methods[0].body[2].value, INFINITY_HEX);
}

// --- CONTROL: ecAdd(ecNegate(y), x) with x != y must NOT fold ---
test "rule 8r control: ecAdd(ecNegate(y), x) over distinct points does not fold" {
    const alloc = testing.allocator;
    var body = [_]types.ANFBinding{
        makeBinding("p", .{ .load_param = .{ .name = "p" } }),
        makeBinding("q", .{ .load_param = .{ .name = "q" } }),
        makeBinding("neg", .{ .call = .{ .func = "ecNegate", .args = &.{"q"} } }),
        makeBinding("t0", .{ .call = .{ .func = "ecAdd", .args = &.{ "neg", "p" } } }),
        makeBinding("t1", .{ .assert = .{ .value = "t0" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    defer freeOptimizeResult(alloc, result);
    try testing.expect(result.methods[0].body[3].value == .call);
    try testing.expectEqualStrings("ecAdd", result.methods[0].body[3].value.call.func);
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

fn expectCombine(a_dec: []const u8, b_dec: []const u8, comptime op: ModOp, expected_dec: []const u8) !void {
    const alloc = testing.allocator;
    var a = try const_arith.Big.init(alloc);
    defer a.deinit();
    try a.setString(10, a_dec);
    var b = try const_arith.Big.init(alloc);
    defer b.deinit();
    try b.setString(10, b_dec);

    const got = try combineModN(alloc, a, b, op);
    switch (got) {
        .integer => |i| {
            const text = try std.fmt.allocPrint(alloc, "{d}", .{i});
            defer alloc.free(text);
            try testing.expectEqualStrings(expected_dec, text);
        },
        .big_integer => |s| {
            defer alloc.free(s);
            try testing.expectEqualStrings(expected_dec, s);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "combineModN: basic addition" {
    try expectCombine("2", "3", .add, "5");
    try expectCombine("0", "0", .add, "0");
}

test "combineModN: basic multiplication" {
    try expectCombine("2", "3", .mul, "6");
    try expectCombine("0", "42", .mul, "0");
}

test "combineModN: operands past i128 reduce into [0, N)" {
    // (N-7) + (N-6) mod N == N-13. Both operands and the result exceed i128,
    // so this is the path the `.big_integer` variant exists for; the old
    // `u256` implementation could not even hold the intermediate sum.
    const n_minus_7 = "115792089237316195423570985008687907852837564279074904382605163141518161494330";
    const n_minus_6 = "115792089237316195423570985008687907852837564279074904382605163141518161494331";
    const n_minus_13 = "115792089237316195423570985008687907852837564279074904382605163141518161494324";
    try expectCombine(n_minus_7, n_minus_6, .add, n_minus_13);
}

// --- N-104: the identity rewrites R1-R4 keep the replaced builtin's operand gate ---
//
// Pins the exact gate bindings -- names, kinds, operands, order -- every tier
// emits (the "gate" entries in optimizer/ec-rules.json), so the seven tiers
// stay ANF- and hex-identical. Proves this tier emits the gate; the gate's
// script semantics are executed on the real Spend engine by
// packages/runar-testing/src/__tests__/n104-ec-optimizer-operand-gate.test.ts.

fn n104Describe(a: Allocator, b: types.ANFBinding) ![]const u8 {
    const d: []const u8 = switch (b.value) {
        .load_param => |lp| try std.fmt.allocPrint(a, "load_param {s}", .{lp.name}),
        .load_const => |lc| switch (lc.value) {
            .string => |s| if (std.mem.eql(u8, s, INFINITY_HEX))
                "const INFINITY"
            else if (std.mem.startsWith(u8, s, "@ref:"))
                try std.fmt.allocPrint(a, "ref {s}", .{s[5..]})
            else
                try std.fmt.allocPrint(a, "const {s}", .{s}),
            .integer => |n| try std.fmt.allocPrint(a, "const {d}", .{n}),
            .big_integer => |s| try std.fmt.allocPrint(a, "const {s}", .{s}),
            else => "const ?",
        },
        .call => |c| blk: {
            var buf = std.ArrayListUnmanaged(u8).empty;
            try buf.appendSlice(a, "call ");
            try buf.appendSlice(a, c.func);
            for (c.args) |arg| {
                try buf.append(a, ' ');
                try buf.appendSlice(a, arg);
            }
            break :blk buf.items;
        },
        .bin_op => |bo| if (bo.result_type) |rt|
            try std.fmt.allocPrint(a, "bin_op {s} {s} {s} {s}", .{ bo.op, bo.left, bo.right, rt })
        else
            try std.fmt.allocPrint(a, "bin_op {s} {s} {s}", .{ bo.op, bo.left, bo.right }),
        .assert => |as| try std.fmt.allocPrint(a, "assert {s}", .{as.value}),
        else => "other",
    };
    return std.fmt.allocPrint(a, "{s} = {s}", .{ b.name, d });
}

const N104_ADD_GATE = [_][]const u8{
    "t_px = call ecPointX p",
    "t_py = call ecPointY p",
    "t_fp = const 115792089237316195423570985008687907853269984665640564039457584007908834671663",
    "t_pxok = bin_op < t_px t_fp",
    "t_pyok = bin_op < t_py t_fp",
    "t_ok = bin_op && t_pxok t_pyok",
    "t_gate = assert t_ok",
};

const N104_MUL_GATE = [_][]const u8{
    "t_inf = const INFINITY",
    "t_isinf = bin_op === p t_inf bytes",
    "t_oncurve = call ecOnCurve p",
    "t_ok = bin_op || t_isinf t_oncurve",
    "t_gate = assert t_ok",
};

fn n104Check(second: types.ANFBinding, call: types.ANFValue, gate: []const []const u8, result: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var body = [_]types.ANFBinding{
        makeBinding("p", .{ .load_param = .{ .name = "pt" } }),
        second,
        makeBinding("t", call),
        makeBinding("a", .{ .assert = .{ .value = "t" } }),
    };
    const out = try optimize(a, testProgram(&.{testMethod(&body)}));
    var want = std.ArrayListUnmanaged([]const u8).empty;
    try want.append(a, "p = load_param pt");
    try want.appendSlice(a, gate);
    try want.append(a, try std.fmt.allocPrint(a, "t = {s}", .{result}));
    try want.append(a, "a = assert t");
    const got_body = out.methods[0].body;
    var got = std.ArrayListUnmanaged([]const u8).empty;
    for (got_body) |b| try got.append(a, try n104Describe(a, b));
    if (got.items.len != want.items.len) {
        for (got.items) |g| std.debug.print("  got: {s}\n", .{g});
        return error.TestUnexpectedResult;
    }
    for (want.items, got.items) |w, g| try testing.expectEqualStrings(w, g);
}

test "N-104 ec-add-identity-right keeps ecAdd's operand gate" {
    try n104Check(
        makeBinding("inf", .{ .load_const = .{ .value = .{ .string = INFINITY_HEX } } }),
        .{ .call = .{ .func = "ecAdd", .args = &.{ "p", "inf" } } },
        &N104_ADD_GATE,
        "ref p",
    );
}

test "N-104 ec-add-identity-left keeps ecAdd's operand gate" {
    try n104Check(
        makeBinding("inf", .{ .load_const = .{ .value = .{ .string = INFINITY_HEX } } }),
        .{ .call = .{ .func = "ecAdd", .args = &.{ "inf", "p" } } },
        &N104_ADD_GATE,
        "ref p",
    );
}

test "N-104 ec-mul-one keeps ecMul's operand gate" {
    try n104Check(
        makeBinding("one", .{ .load_const = .{ .value = .{ .integer = 1 } } }),
        .{ .call = .{ .func = "ecMul", .args = &.{ "p", "one" } } },
        &N104_MUL_GATE,
        "ref p",
    );
}

test "N-104 ec-mul-zero keeps ecMul's operand gate" {
    try n104Check(
        makeBinding("zero", .{ .load_const = .{ .value = .{ .integer = 0 } } }),
        .{ .call = .{ .func = "ecMul", .args = &.{ "p", "zero" } } },
        &N104_MUL_GATE,
        "const INFINITY",
    );
}
