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
/// algebraically simplified bindings, and dead code eliminated when a rule fired.
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

    // N-097: the has-EC-call check above is only a fast path (a rule can only
    // fire on an EC call, at any depth since N-201). The DCE gate is the TS reference's
    // (anf-ec.ts optimizeEC): dead binding elimination runs over EVERY method
    // iff a rewrite fired in ANY method; otherwise the bodies are returned as
    // copies, dead bindings included.
    var fired = false;
    const new_methods = try allocator.alloc(types.ANFMethod, program.methods.len);
    for (program.methods, 0..) |method, i| {
        new_methods[i] = try optimizeMethod(allocator, method, program.properties, &fired);
    }
    if (fired) {
        for (new_methods, 0..) |*method, i| {
            const optimized_body = try dce.eliminateDeadBindingsInMethod(allocator, method.*);
            allocator.free(method.body);
            method.body = optimized_body;
            // N-201: a rewrite inside an if arm or a loop body orphans its
            // operands there, and the DCE above filters only the top level;
            // an orphan left in an arm unbalances the arms (the N-446
            // hazard). Same candidate rule as the constant folder's prune:
            // only names the method referenced before this pass ran.
            var candidates = std.StringHashMap(void).init(allocator);
            defer candidates.deinit();
            for (program.methods[i].body) |b| try dce.collectRefs(b.value, &candidates);
            const pruned = try dce.eliminateDeadBindingsAmongInMethod(allocator, method.*, &candidates);
            allocator.free(method.body);
            method.body = pruned;
            // N-113: drop the inner ecMul/ecMulGen calls a fusion orphaned
            // whose abort is still performed, then prune what that orphans.
            while (try removeGateSubsumedEcCalls(allocator, method, &candidates)) {
                const again = try dce.eliminateDeadBindingsAmongInMethod(allocator, method.*, &candidates);
                allocator.free(method.body);
                method.body = again;
            }
        }
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
// N-113: dead scalar multiplications whose abort is still performed
// ============================================================================

/// N-113 (the TS reference's anf-ec.ts `removeGateSubsumedEcCalls`): remove
/// dead scalar multiplications whose only effect, a possible abort, is
/// provably still performed. Replaces `method.body` and returns true when
/// anything went.
///
/// - `ecMulGen(<const k>)` cannot abort: its point is the fixed generator,
///   which passes ecMul's operand gate, and the ladder reduces any k.
/// - `ecMul(q, <const k>)` aborts exactly when its operand gate
///   `q === O || ecOnCurve(q)` fails (R-157). It may go when a WITNESS
///   performs the same gate: another `ecMul(q', _)`, q' the same binding as q
///   (F-269), not itself removable, in the same scope or an ENCLOSING one --
///   never a nested one, which runs only on some paths.
/// - `ecNegate` is never removed: R7, R8 and R8r rely on it as a gate.
///
/// Only a removal candidate goes (a name referenced before the EC pass ran --
/// the inner call a fusion orphaned), referenced nowhere in the method now,
/// not a private method's return value (F-108) and not one of its if's
/// `results`. A changed `if` / `loop` node is re-allocated, never edited in
/// place, and replaced nested slices are not freed (dce.pruneScope's rule).
fn removeGateSubsumedEcCalls(
    allocator: Allocator,
    method: *types.ANFMethod,
    candidates: *const std.StringHashMap(void),
) !bool {
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();
    var rebound = std.StringHashMap(void).init(allocator);
    defer rebound.deinit();
    try collectReboundNames(&seen, &rebound, method.body);
    var vm = ValueMap{ .map = std.StringHashMap(types.ANFValue).init(allocator), .rebound = &rebound };
    defer vm.map.deinit();
    var refs = std.StringHashMap(void).init(allocator);
    defer refs.deinit();
    try indexForRemoval(&vm, &refs, method.body);

    const ctx = RemovalCtx{
        .allocator = allocator,
        .vm = &vm,
        .refs = &refs,
        .candidates = candidates,
        .keep_last = !method.is_public and !std.mem.eql(u8, method.name, "constructor"),
    };
    var body = method.body;
    if (!try ctx.filter(&body, &.{}, &.{}, true)) return false;
    allocator.free(method.body);
    method.body = body;
    return true;
}

fn indexForRemoval(
    vm: *ValueMap,
    refs: *std.StringHashMap(void),
    bindings: []const types.ANFBinding,
) !void {
    for (bindings) |b| {
        try vm.put(b.name, b.value);
        try dce.collectRefs(b.value, refs);
        switch (b.value) {
            .@"if" => |iv| {
                try indexForRemoval(vm, refs, iv.then);
                try indexForRemoval(vm, refs, iv.@"else");
            },
            .loop => |lv| try indexForRemoval(vm, refs, lv.body),
            else => {},
        }
    }
}

const RemovalCtx = struct {
    allocator: Allocator,
    vm: *ValueMap,
    refs: *const std.StringHashMap(void),
    candidates: *const std.StringHashMap(void),
    keep_last: bool,

    fn isConstScalar(self: RemovalCtx, name: []const u8) bool {
        var v = getConstBig(self.allocator, name, self.vm) orelse return false;
        v.deinit();
        return true;
    }

    fn removable(self: RemovalCtx, b: types.ANFBinding, protect: []const []const u8, is_return: bool) bool {
        const call = switch (b.value) {
            .call => |c| c,
            else => return false,
        };
        if (is_return or !self.candidates.contains(b.name) or self.refs.contains(b.name)) return false;
        for (protect) |r| {
            if (eql(r, b.name)) return false;
        }
        if (eql(call.func, "ecMulGen")) {
            return call.args.len == 1 and self.isConstScalar(call.args[0]);
        }
        if (eql(call.func, "ecMul")) {
            return call.args.len == 2 and self.isConstScalar(call.args[1]) and self.vm.stable(call.args[0]);
        }
        return false;
    }

    /// Filters one scope in place (`scope.*` replaced by a fresh slice when
    /// anything changed, the old one left alone); true when it changed.
    fn filter(
        self: RemovalCtx,
        scope: *[]types.ANFBinding,
        outer: []const []const u8,
        protect: []const []const u8,
        top_level: bool,
    ) !bool {
        const bindings = scope.*;
        const n = bindings.len;
        const is_cand = try self.allocator.alloc(bool, n);
        defer self.allocator.free(is_cand);
        for (bindings, 0..) |b, i| {
            is_cand[i] = self.removable(b, protect, top_level and self.keep_last and i + 1 == n);
        }
        var witnesses = std.ArrayListUnmanaged([]const u8).empty;
        defer witnesses.deinit(self.allocator);
        try witnesses.appendSlice(self.allocator, outer);
        for (bindings, 0..) |b, i| {
            switch (b.value) {
                .call => |c| if (!is_cand[i] and eql(c.func, "ecMul") and c.args.len == 2) {
                    if (self.vm.canonical(c.args[0])) |w| try witnesses.append(self.allocator, w);
                },
                else => {},
            }
        }
        var changed = false;
        var out = std.ArrayListUnmanaged(types.ANFBinding).empty;
        errdefer out.deinit(self.allocator);
        for (bindings, 0..) |b, i| {
            switch (b.value) {
                .call => |c| if (is_cand[i]) {
                    var gated = eql(c.func, "ecMulGen");
                    if (!gated) {
                        const q = self.vm.canonical(c.args[0]).?;
                        for (witnesses.items) |w| {
                            if (eql(w, q)) gated = true;
                        }
                    }
                    if (gated) {
                        changed = true;
                        continue;
                    }
                },
                .@"if" => |if_val| {
                    var then_b = if_val.then;
                    var else_b = if_val.@"else";
                    const t = try self.filter(&then_b, witnesses.items, if_val.results, false);
                    const e = try self.filter(&else_b, witnesses.items, if_val.results, false);
                    if (t or e) {
                        const nv = try self.allocator.create(types.ANFIf);
                        nv.* = if_val.*;
                        nv.then = then_b;
                        nv.@"else" = else_b;
                        var nb = b;
                        nb.value = .{ .@"if" = nv };
                        try out.append(self.allocator, nb);
                        changed = true;
                        continue;
                    }
                },
                .loop => |loop_val| {
                    var body_b = loop_val.body;
                    if (try self.filter(&body_b, witnesses.items, &.{}, false)) {
                        const nv = try self.allocator.create(types.ANFLoop);
                        nv.* = loop_val.*;
                        nv.body = body_b;
                        var nb = b;
                        nb.value = .{ .loop = nv };
                        try out.append(self.allocator, nb);
                        changed = true;
                        continue;
                    }
                },
                else => {},
            }
            try out.append(self.allocator, b);
        }
        if (!changed) {
            out.deinit(self.allocator);
            return false;
        }
        scope.* = try out.toOwnedSlice(self.allocator);
        return true;
    }
};

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

/// F-269: every name bound more than once in the method -- binding names at
/// any depth (if/loop arms included) and loop iteration variables (the TS
/// `collectReboundNames`). `ValueMap.canonical` never resolves through one.
fn collectReboundNames(
    seen: *std.StringHashMap(void),
    rebound: *std.StringHashMap(void),
    bindings: []const types.ANFBinding,
) !void {
    for (bindings) |b| {
        try bindName(seen, rebound, b.name);
        switch (b.value) {
            .@"if" => |iv| {
                try collectReboundNames(seen, rebound, iv.then);
                try collectReboundNames(seen, rebound, iv.@"else");
            },
            .loop => |lv| {
                try bindName(seen, rebound, lv.iter_var);
                try collectReboundNames(seen, rebound, lv.body);
            },
            else => {},
        }
    }
}

fn bindName(seen: *std.StringHashMap(void), rebound: *std.StringHashMap(void), name: []const u8) !void {
    if (seen.contains(name)) {
        try rebound.put(name, {});
    } else {
        try seen.put(name, {});
    }
}

/// Binding name -> its value as already rewritten in the current sweep, plus
/// the method's rebound names. `get` follows `@ref:` aliases (F-269).
const ValueMap = struct {
    map: std.StringHashMap(types.ANFValue),
    rebound: *const std.StringHashMap(void),

    fn put(self: *ValueMap, name: []const u8, value: types.ANFValue) !void {
        try self.map.put(name, value);
    }

    /// N-201: the map an if arm or a loop body starts from (the TS
    /// `ValueMap.nestedScope`) -- every binding visible at the if/loop, and
    /// nothing the nested scope binds flows back out. `hidden` is a loop's
    /// iteration variable, never resolved through an outer binding. The
    /// caller deinits the returned map.
    fn nestedScope(self: *ValueMap, hidden: ?[]const u8) !ValueMap {
        var scope = ValueMap{ .map = try self.map.clone(), .rebound = self.rebound };
        if (hidden) |h| _ = scope.map.remove(h);
        return scope;
    }

    /// F-269 (user decision R77): the binding `name` ultimately names,
    /// following load_const "@ref:<x>" aliases -- pass 04's
    /// `const y = <expr>` and the ones R1/R2/R3/R7 leave behind (the TS
    /// `canonicalName` in anf-ec.ts).
    ///
    /// null when `name` has no position-independent identity: ANF re-emits a
    /// local's name when the source reassigns it (top level or in an if/loop
    /// arm), so a REBOUND name means different values at different sites. Two
    /// uses of one are not "the same $x", and nothing lifted out of an earlier
    /// binding may name one (F-269 attempt 2). An alias cycle (only
    /// hand-written `compile-ir` input) is null too: an acyclic chain visits
    /// each binding at most once, so more hops than the map holds IS a cycle
    /// -- the TS seen-set, without an allocation. A hop is never taken INTO a
    /// rebound name: the chain stops at the last name bound once, which is
    /// itself a fixed value, and its value is the opaque alias. Matching only:
    /// rewrites emit the literal names they matched.
    fn canonical(self: *ValueMap, name: []const u8) ?[]const u8 {
        if (self.rebound.contains(name)) return null;
        var cur = name;
        var hops: usize = 0;
        while (true) {
            const v = self.map.get(cur) orelse return cur;
            const s = switch (v) {
                .load_const => |lc| switch (lc.value) {
                    .string => |str| str,
                    else => return cur,
                },
                else => return cur,
            };
            if (s.len <= 5 or !std.mem.startsWith(u8, s, "@ref:")) return cur;
            const next = s[5..];
            hops += 1;
            if (self.rebound.contains(next)) return cur;
            if (eql(next, name) or hops > self.map.count()) return null;
            cur = next;
        }
    }

    /// The value `name` resolves to, through aliases; null for a name with
    /// no fixed identity.
    fn get(self: *ValueMap, name: []const u8) ?types.ANFValue {
        return self.map.get(self.canonical(name) orelse return null);
    }

    /// F-269 attempt 2: may a name lifted out of an earlier binding be
    /// emitted at the current site? Only when it denotes one value (R7, R9).
    fn stable(self: *ValueMap, name: []const u8) bool {
        return self.canonical(name) != null;
    }
};

/// Rewrite one method's EC calls -- top level, if arms and loop bodies
/// (N-201) -- to a fixed point. Sets `fired` when any rule fires; dead binding
/// elimination is the caller's (N-097).
fn optimizeMethod(allocator: Allocator, method: types.ANFMethod, properties: []const types.ANFProperty, fired: *bool) !types.ANFMethod {
    var body = try allocator.alloc(types.ANFBinding, method.body.len);
    @memcpy(body, method.body);

    // F-086: names a minted binding must avoid; minted names are added too.
    var used_names = std.StringHashMap(void).init(allocator);
    defer used_names.deinit();
    try collectUsedNames(&used_names, method, properties);

    // F-269: names bound more than once; alias resolution never passes one.
    var rebound_seen = std.StringHashMap(void).init(allocator);
    defer rebound_seen.deinit();
    var rebound = std.StringHashMap(void).init(allocator);
    defer rebound.deinit();
    try collectReboundNames(&rebound_seen, &rebound, method.body);

    // Fixed-point iteration: keep applying rules until nothing changes.
    while (true) {
        var top = ValueMap{ .map = std.StringHashMap(types.ANFValue).init(allocator), .rebound = &rebound };
        defer top.map.deinit();
        // N-460: the fusion guard's referrer counts, once per sweep.
        var referrers = std.StringHashMap(u32).init(allocator);
        defer referrers.deinit();
        try countReferrers(allocator, &referrers, body);
        if (!method.is_public and !std.mem.eql(u8, method.name, "constructor") and body.len > 0) {
            const gop = try referrers.getOrPut(body[body.len - 1].name);
            gop.value_ptr.* = if (gop.found_existing) gop.value_ptr.* + 1 else 1;
        }
        var no_frame = std.StringHashMap(void).init(allocator);
        defer no_frame.deinit();
        const next = (try optimizeBody(allocator, body, &top, null, &used_names, &referrers, &no_frame)) orelse break;
        allocator.free(body);
        body = next;
        fired.* = true;
    }

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

/// One left-to-right sweep over a scope (the TS `optimizeBodyOnce`): each
/// binding is tried once against the values of the bindings before it, as
/// already rewritten in this sweep. N-201: it descends into if arms (then
/// before else) and loop bodies at the position of their binding, each with
/// its own scope (`ValueMap.nestedScope`). Returns null when no rule fired;
/// otherwise a newly allocated body (the input is not freed).
fn optimizeBody(
    allocator: Allocator,
    body: []const types.ANFBinding,
    outer: *ValueMap,
    hidden: ?[]const u8,
    used_names: *std.StringHashMap(void),
    referrers: *const std.StringHashMap(u32),
    outer_frame: *const std.StringHashMap(void),
) !?[]types.ANFBinding {
    var value_map = try outer.nestedScope(hidden);
    defer value_map.map.deinit();

    // N-460: an if arm sees its enclosing frame, a loop body starts a new one.
    var local = std.StringHashMap(void).init(allocator);
    defer local.deinit();
    var frame = try outer_frame.clone();
    defer frame.deinit();
    for (body) |b| {
        try local.put(b.name, {});
        try frame.put(b.name, {});
    }
    var mul_readers = std.StringHashMap(u32).init(allocator);
    defer mul_readers.deinit();
    try countMulReaders(allocator, &mul_readers, body, outer, hidden);
    const scope = FusionScope{ .referrers = referrers, .local = &local, .frame = &frame, .mul_readers = &mul_readers };

    var new_body = std.ArrayListUnmanaged(types.ANFBinding).empty;
    defer new_body.deinit(allocator);
    var changed = false;

    for (body) |binding| {
        var current = binding;
        switch (binding.value) {
            .@"if" => |iv| {
                try value_map.put(binding.name, binding.value);
                const then_b = try optimizeBody(allocator, iv.then, &value_map, null, used_names, referrers, &frame);
                const else_b = try optimizeBody(allocator, iv.@"else", &value_map, null, used_names, referrers, &frame);
                if (then_b != null or else_b != null) {
                    const ni = try allocator.create(types.ANFIf);
                    ni.* = iv.*;
                    if (then_b) |t| ni.then = t;
                    if (else_b) |e| ni.@"else" = e;
                    current.value = .{ .@"if" = ni };
                    changed = true;
                }
            },
            .loop => |lv| {
                try value_map.put(binding.name, binding.value);
                var loop_frame = std.StringHashMap(void).init(allocator);
                defer loop_frame.deinit();
                if (try optimizeBody(allocator, lv.body, &value_map, lv.iter_var, used_names, referrers, &loop_frame)) |nb| {
                    const nl = try allocator.create(types.ANFLoop);
                    nl.* = lv.*;
                    nl.body = nb;
                    current.value = .{ .loop = nl };
                    changed = true;
                }
            },
            else => {
                // `new_body` doubles as the prelude list: a rule that folds a
                // new constant appends its binding here, i.e. immediately
                // BEFORE the binding being rewritten (see `freshConstName`).
                const prelude_start = new_body.items.len;
                try value_map.put(binding.name, binding.value);
                if (tryOptimize(allocator, binding.name, current.value, &value_map, used_names, &new_body, scope)) |optimized| {
                    // N-218: every helper a rewrite mints (the N-104/N-251
                    // gate bindings, the fused-scalar helper) takes the
                    // rewritten binding's own source_loc, mirroring F-343 in
                    // the TS reference (anf-ec.ts optimizeBodyOnce) -- it
                    // exists only because of that source expression, and
                    // stack lowering maps opcodes through binding.source_loc.
                    for (new_body.items[prelude_start..]) |*helper| helper.source_loc = binding.source_loc;
                    current = .{ .name = binding.name, .value = optimized, .source_loc = binding.source_loc };
                    changed = true;
                }
            },
        }
        try value_map.put(current.name, current.value);
        try new_body.append(allocator, current);
    }

    if (!changed) return null;
    return try new_body.toOwnedSlice(allocator);
}

fn hasEcCalls(body: []const types.ANFBinding) bool {
    for (body) |binding| {
        switch (binding.value) {
            .call => |c| if (ec_funcs.has(c.func)) return true,
            // N-201: if arms and loop bodies are rewritten too.
            .@"if" => |iv| if (hasEcCalls(iv.then) or hasEcCalls(iv.@"else")) return true,
            .loop => |lv| if (hasEcCalls(lv.body)) return true,
            else => {},
        }
    }
    return false;
}

// ============================================================================
// Optimization rules
// ============================================================================

/// N-460 -- what a fusing rule (R9, R10, R11) needs to know at its fire site
/// (the TS `FusionScope` in anf-ec.ts).
///
/// A fusion replaces the outer call with ONE new scalar multiplication, so it
/// shrinks the script only if `removeGateSubsumedEcCalls` then drops an inner
/// call it read. Each fusing rule therefore fires only when at least one of
/// its inner operands is ELIMINABLE (`fusionEliminates`):
///
///  - every name on its alias chain (the operand, each `@ref:` hop, the call
///    binding itself -- `canonical`'s walk) has exactly one referrer: the
///    rewritten binding for the operand, the previous hop for the rest. Any
///    other reader keeps the inner call alive after the fusion;
///  - the call is an `ecMulGen` bound in the current scope or an enclosing one
///    inside the same loop body (`frame`). It needs no witness, but one bound
///    outside a loop the fusion sits in would trade one multiplication for one
///    per iteration;
///  - or the call is an `ecMul` bound in the current scope itself (`local`):
///    the fused `ecMul` on the same point is then its witness. One bound in an
///    enclosing scope has no witness (the fused call is nested) and stays.
///
/// `referrers` is computed once per sweep, from the body the sweep starts with
/// (`countReferrers`), and not updated as the sweep rewrites. A rewrite only
/// adds a reference to a name its own binding, or the inner binding it lifts
/// from, already read, so a stale count is never too low. Every tier computes
/// it the same way, because which rules fire decides the bytes.
///
/// N-465: R9 alone (`shared`) also accepts a name whose every referrer is one
/// of `mul_readers`: a binding of the current scope `ecMul(<name>, k)` with k a
/// constant other than 0 and 1 (R3/R4 would rewrite it first and keep reading
/// the name). Each such reader fires R9 in this same sweep -- everything R9
/// checks besides k is a property of the shared inner, the same for all of
/// them -- so the inner loses every reader, and the fused calls, `ecMul`s on
/// its point in its own scope, are its witness. R10/R11 never use this: an
/// ecAdd reader beside R9 readers is not one of them, so the two would decide
/// differently and the inner would stay.
const FusionScope = struct {
    referrers: *const std.StringHashMap(u32),
    local: *const std.StringHashMap(void),
    frame: *const std.StringHashMap(void),
    mul_readers: *const std.StringHashMap(u32),
};

/// N-465: per name, the bindings of this scope (`body`, not its arms or loop
/// bodies) that are `ecMul(<name>, k)` with k resolving to a constant other
/// than 0 and 1 -- resolved as R9 will resolve it at that binding, against the
/// bindings before it. Taken from the body the sweep starts with: a rewrite
/// never turns a binding into an integer constant, so k resolves the same way
/// after the rewrites ahead of it.
fn countMulReaders(
    allocator: Allocator,
    counts: *std.StringHashMap(u32),
    body: []const types.ANFBinding,
    outer: *ValueMap,
    hidden: ?[]const u8,
) !void {
    var vm = try outer.nestedScope(hidden);
    defer vm.map.deinit();
    for (body) |b| {
        try vm.put(b.name, b.value);
        const call = switch (b.value) {
            .call => |c| c,
            else => continue,
        };
        if (!eql(call.func, "ecMul") or call.args.len != 2) continue;
        var k = getConstBig(allocator, call.args[1], &vm) orelse continue;
        k.deinit();
        if (isConstInt(allocator, call.args[1], 0, &vm) or isConstInt(allocator, call.args[1], 1, &vm)) continue;
        const gop = try counts.getOrPut(call.args[0]);
        gop.value_ptr.* = if (gop.found_existing) gop.value_ptr.* + 1 else 1;
    }
}

/// N-460: referrer count per name -- the bindings, at any depth, whose value
/// reads it (once per binding, however many operands name it; an if reads its
/// cond, its arms' bindings are counted themselves), plus one for each name in
/// an if's results. The caller adds one for a private method's return binding
/// (F-108): the two things `removeGateSubsumedEcCalls` protects.
fn countReferrers(allocator: Allocator, counts: *std.StringHashMap(u32), bindings: []const types.ANFBinding) !void {
    for (bindings) |b| {
        var reads = std.StringHashMap(void).init(allocator);
        defer reads.deinit();
        switch (b.value) {
            .@"if" => |iv| {
                try reads.put(iv.cond, {});
                for (iv.results) |r| try reads.put(r, {});
            },
            .loop => {},
            else => try dce.collectRefs(b.value, &reads),
        }
        var it = reads.keyIterator();
        while (it.next()) |k| {
            const gop = try counts.getOrPut(k.*);
            gop.value_ptr.* = if (gop.found_existing) gop.value_ptr.* + 1 else 1;
        }
        switch (b.value) {
            .@"if" => |iv| {
                try countReferrers(allocator, counts, iv.then);
                try countReferrers(allocator, counts, iv.@"else");
            },
            .loop => |lv| try countReferrers(allocator, counts, lv.body),
            else => {},
        }
    }
}

/// N-460: does fusing these inner operands let at least one inner call go?
fn fusionEliminates(operands: []const []const u8, vm: *ValueMap, scope: FusionScope, shared: bool) bool {
    for (operands) |operand| {
        const c = vm.canonical(operand) orelse continue;
        // `canonical` already walked this chain, so every hop is an `@ref:`.
        var cur = operand;
        const single = while (true) {
            const n = scope.referrers.get(cur) orelse 0;
            if (n != 1 and !(shared and n > 1 and n == (scope.mul_readers.get(cur) orelse 0))) break false;
            if (eql(cur, c)) break true;
            cur = vm.map.get(cur).?.load_const.value.string[5..];
        };
        if (!single) continue;
        switch (vm.map.get(c) orelse continue) {
            .call => |call| {
                if ((eql(call.func, "ecMulGen") and scope.frame.contains(c)) or
                    (eql(call.func, "ecMul") and scope.local.contains(c))) return true;
            },
            else => {},
        }
    }
    return false;
}

fn tryOptimize(
    allocator: Allocator,
    name: []const u8,
    v: types.ANFValue,
    vm: *ValueMap,
    used: *std.StringHashMap(void),
    prelude: *std.ArrayListUnmanaged(types.ANFBinding),
    scope: FusionScope,
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
            // F-269 attempt 2: x is lifted out of the inner binding and
            // re-emitted here, so it must denote one value at both sites.
            if (eql(ic.func, "ecNegate") and ic.args.len == 1 and vm.stable(ic.args[0]))
                return makeRef(allocator, ic.args[0]);
        }
    }

    // Rule 8: ecAdd(x, ecNegate(x)) -> INFINITY, keeping the adder's y = 0 abort (N-251)
    if (eql(func, "ecAdd") and args.len == 2) {
        if (resolveCall(args[1], vm)) |nc| {
            if (eql(nc.func, "ecNegate") and nc.args.len == 1 and sameBinding(args[0], nc.args[0], vm)) {
                if (!emitOperandGate(allocator, .neg_cancel, name, args[0], vm, used, prelude)) return null;
                return makeConstHex(INFINITY_HEX);
            }
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
            if (eql(nc.func, "ecNegate") and nc.args.len == 1 and sameBinding(args[1], nc.args[0], vm)) {
                // The gate reads the ecNegate operand: the name the JSON's `$x`
                // binds first, as the Go engine binds it (differs from args[1]
                // only through an alias, F-269).
                if (!emitOperandGate(allocator, .neg_cancel, name, nc.args[0], vm, used, prelude)) return null;
                return makeConstHex(INFINITY_HEX);
            }
        }
    }

    // Rule 9: ecMul(ecMul(p, k1), k2) -> ecMul(p, k1*k2 mod N)
    if (eql(func, "ecMul") and args.len == 2) {
        if (getConstBig(allocator, args[1], vm)) |k2_loaded| {
            var k2 = k2_loaded;
            defer k2.deinit();
            if (resolveCall(args[0], vm)) |ic| {
                if (eql(ic.func, "ecMul") and ic.args.len == 2 and vm.stable(ic.args[0])) {
                    if (getConstBig(allocator, ic.args[1], vm)) |k1_loaded| {
                        var k1 = k1_loaded;
                        defer k1.deinit();
                        if (!fusionEliminates(&.{args[0]}, vm, scope, true)) return null;
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
                if (k1 != null and k2 != null and fusionEliminates(args, vm, scope, false)) {
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
                    if (k1 != null and k2 != null and fusionEliminates(args, vm, scope, false)) {
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

fn resolve(name: []const u8, vm: *ValueMap) ?types.ANFValue {
    return vm.get(name);
}

/// Resolve a binding name and return the inner ANFCall if it is a call, else null.
fn resolveCall(name: []const u8, vm: *ValueMap) ?types.ANFCall {
    const val = resolve(name, vm) orelse return null;
    return switch (val) {
        .call => |call| call,
        else => null,
    };
}

fn isInfinity(name: []const u8, vm: *ValueMap) bool {
    const val = resolve(name, vm) orelse return false;
    return switch (val) {
        .load_const => |lc| switch (lc.value) {
            .string => |s| eql(s, INFINITY_HEX),
            else => false,
        },
        else => false,
    };
}

fn isGenerator(name: []const u8, vm: *ValueMap) bool {
    const val = resolve(name, vm) orelse return false;
    return switch (val) {
        .load_const => |lc| switch (lc.value) {
            .string => |s| eql(s, G_HEX),
            else => false,
        },
        else => false,
    };
}

fn isConstInt(allocator: Allocator, name: []const u8, n: i128, vm: *ValueMap) bool {
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
fn getConstBig(allocator: Allocator, name: []const u8, vm: *ValueMap) ?const_arith.Big {
    const val = resolve(name, vm) orelse return null;
    const lc = switch (val) {
        .load_const => |c| c,
        else => return null,
    };
    return (const_arith.load(allocator, lc.value) catch return null) orelse null;
}

/// F-269: do two arguments name the same binding, through aliases? (R8, R8r, R11.)
fn sameBinding(a: []const u8, b: []const u8, vm: *ValueMap) bool {
    const ca = vm.canonical(a) orelse return false;
    const cb = vm.canonical(b) orelse return false;
    return eql(ca, cb);
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

const GateOf = enum { add, mul, neg_cancel };

/// N-104 -- the operand gate a rewrite must leave behind. Byte-for-byte the TS
/// reference (`emitAddOperandGate` / `emitMulOperandGate` in
/// packages/runar-compiler/src/optimizer/anf-ec.ts) and the "gate" entries in
/// optimizer/ec-rules.json:
///
///   ecAdd: assert(ecPointX(q) < p && ecPointY(q) < p)   width (CL-BUG-095) + canonicity (R-117)
///   ecMul: assert(q === O || ecOnCurve(q))               on-curve-or-O (R-157)
///   neg_cancel: assert(ecPointX(q) === 0 || ecPointY(q) !== 0)
///
/// `neg_cancel` is N-251's gate for R8/R8r (`ecAdd(q, ecNegate(q)) -> O` and
/// its mirror; TS `emitNegCancelGate`, user decision R96): the replaced ecAdd
/// doubles exactly when y(q) = 0, and N-110 made the adder abort on a doubling
/// with px != 0 and py == 0; the px == 0 term keeps O + O = O. Width and
/// canonicity are checked by the inner ecNegate(q) call, which is never
/// dead-code-eliminated.
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
    vm: *ValueMap,
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
        .neg_cancel => {
            const px = push(&out, &n, Builder.name(allocator, used, base, "_px") orelse return false, makeCall(allocator, "ecPointX", &.{q}) orelse return false);
            const py = push(&out, &n, Builder.name(allocator, used, base, "_py") orelse return false, makeCall(allocator, "ecPointY", &.{q}) orelse return false);
            const zero = push(&out, &n, Builder.name(allocator, used, base, "_zero") orelse return false, .{ .load_const = .{ .value = .{ .integer = 0 } } });
            const x_zero = push(&out, &n, Builder.name(allocator, used, base, "_pxz") orelse return false, .{ .bin_op = .{ .op = "===", .left = px, .right = zero } });
            const y_non_zero = push(&out, &n, Builder.name(allocator, used, base, "_pynz") orelse return false, .{ .bin_op = .{ .op = "!==", .left = py, .right = zero } });
            ok_name = push(&out, &n, Builder.name(allocator, used, base, "_ok") orelse return false, .{ .bin_op = .{ .op = "||", .left = x_zero, .right = y_non_zero } });
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
    vm: *ValueMap,
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
    // N-251: the y = 0 gate's names and call args are not individually owned
    // by the result, so freeOptimizeResult cannot release them.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var body = [_]types.ANFBinding{
        makeBinding("p", .{ .load_const = .{ .value = .{ .string = G_HEX } } }),
        makeBinding("neg", .{ .call = .{ .func = "ecNegate", .args = &.{"p"} } }),
        makeBinding("t0", .{ .call = .{ .func = "ecAdd", .args = &.{ "p", "neg" } } }),
        makeBinding("t1", .{ .assert = .{ .value = "t0" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    // N-251: the y = 0 gate now precedes t0, so find it by name.
    try expectConstStr(try findValue(result.methods[0].body, "t0"), INFINITY_HEX);
}

// --- Rule 8r (ec-add-negate-cancel-reversed): ecAdd(ecNegate(x), x) -> INFINITY ---
// The operand order rule 8 above does NOT cover. optimizer/ec-rules.json declares
// both directions with no "supported" tag; only the Go tier implemented this one
// (R-034 / CL-BUG-028).
test "rule 8r: ecAdd(ecNegate(x), x) -> INFINITY" {
    // N-251: the y = 0 gate's names and call args are not individually owned
    // by the result, so freeOptimizeResult cannot release them.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var body = [_]types.ANFBinding{
        makeBinding("p", .{ .load_const = .{ .value = .{ .string = G_HEX } } }),
        makeBinding("neg", .{ .call = .{ .func = "ecNegate", .args = &.{"p"} } }),
        makeBinding("t0", .{ .call = .{ .func = "ecAdd", .args = &.{ "neg", "p" } } }),
        makeBinding("t1", .{ .assert = .{ .value = "t0" } }),
    };
    const result = try optimize(alloc, testProgram(&.{testMethod(&body)}));
    // N-251: the y = 0 gate now precedes t0, so find it by name.
    try expectConstStr(try findValue(result.methods[0].body, "t0"), INFINITY_HEX);
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

// --- N-251: R8/R8r keep the adder's y = 0 doubling abort (N-110) ---
//
// assert(ecPointX(q) === 0 || ecPointY(q) !== 0), ahead of the INFINITY binding
// (user decision R96). Pins the gate ANF only; its script semantics are
// executed on the real Spend engine, in both optimizer modes, by
// packages/runar-testing/src/__tests__/n251-ec-negate-cancel-y0.test.ts.
// The ecNegate binding stays (calls are never dead-code-eliminated), so it is
// part of the expected body ahead of the gate.

const N251_NEG_CANCEL_GATE = [_][]const u8{
    "n = call ecNegate p",
    "t_px = call ecPointX p",
    "t_py = call ecPointY p",
    "t_zero = const 0",
    "t_pxz = bin_op === t_px t_zero",
    "t_pynz = bin_op !== t_py t_zero",
    "t_ok = bin_op || t_pxz t_pynz",
    "t_gate = assert t_ok",
};

test "N-251 ec-add-negate-cancel keeps the adder's y = 0 abort" {
    try n104Check(
        makeBinding("n", .{ .call = .{ .func = "ecNegate", .args = &.{"p"} } }),
        .{ .call = .{ .func = "ecAdd", .args = &.{ "p", "n" } } },
        &N251_NEG_CANCEL_GATE,
        "const INFINITY",
    );
}

test "N-251 ec-add-negate-cancel-reversed keeps the adder's y = 0 abort" {
    try n104Check(
        makeBinding("n", .{ .call = .{ .func = "ecNegate", .args = &.{"p"} } }),
        .{ .call = .{ .func = "ecAdd", .args = &.{ "n", "p" } } },
        &N251_NEG_CANCEL_GATE,
        "const INFINITY",
    );
}

// --- N-218: port of F-343 to this tier ---
//
// The TS reference's optimizeBodyOnce
// (packages/runar-compiler/src/optimizer/anf-ec.ts) keeps the rewritten
// binding's source location on every helper binding a rule mints -- the
// N-104 operand gate, the N-251 neg-cancel gate, and the fused-scalar helper
// -- because stack lowering maps opcodes through binding.source_loc. Before
// this fix, optimizeMethod appended every helper binding with source_loc ==
// null regardless of the rewritten binding's own location, so none of a
// rewritten EC call's gate opcodes reached the source map.
//
// Proves: a located ecMul(p, 0) rewrite's mul gate (5 bindings), a located
// ecAdd(p, ecNegate(p)) rewrite's neg-cancel gate (7 bindings), and a located
// nested-ecMul fusion's `_k` helper all carry the rewritten binding's
// source_loc; an unlocated rewrite mints unlocated helpers (no source_loc
// invented from nothing).
//
// Does not prove: exact file/line/column assignment upstream in the ANF
// lowerer, or end-to-end script-map behavior -- that is covered by the TS
// test f343-ec-optimizer-source-loc.test.ts and by conformance, which strips
// sourceLoc as debug-only and so cannot regress from this change.

const N218_LOC = types.SourceLocation{ .file = "T.runar.ts", .line = 7, .column = 4 };

fn n218FindBinding(body: []const types.ANFBinding, name: []const u8) !types.ANFBinding {
    for (body) |b| {
        if (std.mem.eql(u8, b.name, name)) return b;
    }
    std.debug.print("  missing binding: {s}\n", .{name});
    return error.TestUnexpectedResult;
}

fn n218ExpectLoc(b: types.ANFBinding) !void {
    const loc = b.source_loc orelse {
        std.debug.print("  {s}: source_loc is null, want {s}:{d}:{d}\n", .{ b.name, N218_LOC.file, N218_LOC.line, N218_LOC.column });
        return error.TestUnexpectedResult;
    };
    try testing.expectEqualStrings(N218_LOC.file, loc.file);
    try testing.expectEqual(N218_LOC.line, loc.line);
    try testing.expectEqual(N218_LOC.column, loc.column);
}

test "N-218 rule 4 mul gate carries the rewritten binding's source_loc" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var body = [_]types.ANFBinding{
        makeBinding("p", .{ .load_param = .{ .name = "pt" } }),
        makeBinding("zero", .{ .load_const = .{ .value = .{ .integer = 0 } } }),
        .{ .name = "t", .value = .{ .call = .{ .func = "ecMul", .args = &.{ "p", "zero" } } }, .source_loc = N218_LOC },
        makeBinding("a", .{ .assert = .{ .value = "t" } }),
    };
    const out = try optimize(a, testProgram(&.{testMethod(&body)}));
    const got_body = out.methods[0].body;
    for ([_][]const u8{ "t_inf", "t_isinf", "t_oncurve", "t_ok", "t_gate" }) |name| {
        try n218ExpectLoc(try n218FindBinding(got_body, name));
    }
    try n218ExpectLoc(try n218FindBinding(got_body, "t"));
}

test "N-218 rule 8 neg-cancel gate carries the rewritten binding's source_loc" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var body = [_]types.ANFBinding{
        makeBinding("p", .{ .load_param = .{ .name = "pt" } }),
        makeBinding("n", .{ .call = .{ .func = "ecNegate", .args = &.{"p"} } }),
        .{ .name = "t", .value = .{ .call = .{ .func = "ecAdd", .args = &.{ "p", "n" } } }, .source_loc = N218_LOC },
        makeBinding("a", .{ .assert = .{ .value = "t" } }),
    };
    const out = try optimize(a, testProgram(&.{testMethod(&body)}));
    const got_body = out.methods[0].body;
    for ([_][]const u8{ "t_px", "t_py", "t_zero", "t_pxz", "t_pynz", "t_ok", "t_gate" }) |name| {
        try n218ExpectLoc(try n218FindBinding(got_body, name));
    }
}

test "N-218 rule 9 fused-scalar helper carries the rewritten binding's source_loc" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var body = [_]types.ANFBinding{
        makeBinding("p", .{ .load_param = .{ .name = "pt" } }),
        makeBinding("k1", .{ .load_const = .{ .value = .{ .integer = 3 } } }),
        makeBinding("k2", .{ .load_const = .{ .value = .{ .integer = 5 } } }),
        makeBinding("inner", .{ .call = .{ .func = "ecMul", .args = &.{ "p", "k1" } } }),
        .{ .name = "outer", .value = .{ .call = .{ .func = "ecMul", .args = &.{ "inner", "k2" } } }, .source_loc = N218_LOC },
        makeBinding("a", .{ .assert = .{ .value = "outer" } }),
    };
    const out = try optimize(a, testProgram(&.{testMethod(&body)}));
    const got_body = out.methods[0].body;
    try n218ExpectLoc(try n218FindBinding(got_body, "outer_k"));
    try n218ExpectLoc(try n218FindBinding(got_body, "outer"));
}

test "N-218 unlocated rewrite mints unlocated helpers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var body = [_]types.ANFBinding{
        makeBinding("p", .{ .load_param = .{ .name = "pt" } }),
        makeBinding("zero", .{ .load_const = .{ .value = .{ .integer = 0 } } }),
        makeBinding("t", .{ .call = .{ .func = "ecMul", .args = &.{ "p", "zero" } } }),
        makeBinding("a", .{ .assert = .{ .value = "t" } }),
    };
    const out = try optimize(a, testProgram(&.{testMethod(&body)}));
    for (out.methods[0].body) |b| {
        if (b.source_loc != null) {
            std.debug.print("  {s}: expected null source_loc, got non-null\n", .{b.name});
            return error.TestUnexpectedResult;
        }
    }
}
