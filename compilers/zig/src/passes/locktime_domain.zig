//! D26: a block-height locktime gate must pin the locktime domain. Port of
//! packages/runar-compiler/src/passes/locktime-domain.ts (see its header for
//! the full rationale and the exact GATE / PIN / DERIVED definitions).
//!
//! Consensus reads an nLockTime of 500000000 or more as a Unix timestamp, so
//! `extractLocktime(p) >= H` for a height H passes for any such locktime. Per
//! path (D18's path walk, two bits: gate seen G, pin seen P), every path
//! through a public method that carries a lower-bound gate on a locktime read
//! must also carry an asserted domain pin. This file holds the shared
//! classification and the source path (typecheck.zig reports it); the --ir
//! path lives in ir/locktime_domain.zig.

const std = @import("std");
const types = @import("../ir/types.zig");

const Allocator = std.mem.Allocator;
const ContractNode = types.ContractNode;
const MethodNode = types.MethodNode;
const Expression = types.Expression;
const Statement = types.Statement;

/// D26: the shared error text (method name).
pub const LOCKTIME_DOMAIN_FMT =
    "method '{s}' compares extractLocktime against a lower bound without pinning the locktime domain: " ++
    "consensus reads an nLockTime of 500000000 or more as a Unix timestamp, so on that path any such locktime " ++
    "passes a block-height gate at once. On every path that compares, assert(extractLocktime(preimage) < " ++
    "500000000n) for a block-height gate, or assert(extractLocktime(preimage) >= 500000000n) for a timestamp gate";

/// The first nLockTime value consensus reads as a Unix timestamp.
pub const LOCKTIME_THRESHOLD: i128 = 500000000;

// ---------------------------------------------------------------------------
// Path states: G (gate seen) and P (pin seen); a set of the four states is a
// u4 mask (bit x set iff state x is live).
// ---------------------------------------------------------------------------

pub const G: u2 = 1;
pub const P: u2 = 2;
/// The single fresh path {0}.
pub const ZERO: u4 = 1;

/// Every live state `x` becomes `x | bits`.
pub fn orAll(states: u4, bits: u2) u4 {
    var out: u4 = 0;
    for (0..4) |x| {
        if ((states >> @intCast(x)) & 1 != 0) out |= @as(u4, 1) << (@as(u2, @intCast(x)) | bits);
    }
    return out;
}

/// {x | y : x in a, y in b}.
pub fn compose(a: u4, b: u4) u4 {
    var out: u4 = 0;
    for (0..4) |y| {
        if ((b >> @intCast(y)) & 1 != 0) out |= orAll(a, @intCast(y));
    }
    return out;
}

/// Some live path carries a gate (G) and no pin (not P): state 1.
pub fn unpinned(states: u4) bool {
    return states & (@as(u4, 1) << G) != 0;
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

pub const Cmp = enum { lt, lte, gt, gte };
pub const Class = enum { none, gate, pin };

fn flip(op: Cmp) Cmp {
    return switch (op) {
        .lt => .gt,
        .lte => .gte,
        .gt => .lt,
        .gte => .lte,
    };
}

pub fn cmpFromTs(op: []const u8) ?Cmp {
    if (std.mem.eql(u8, op, "<")) return .lt;
    if (std.mem.eql(u8, op, "<=")) return .lte;
    if (std.mem.eql(u8, op, ">")) return .gt;
    if (std.mem.eql(u8, op, ">=")) return .gte;
    return null;
}

/// Decimal integer text as i128; a value past i128 clamps by sign (every
/// bound classify compares against is far inside the range).
pub fn parseBig(text: []const u8) i128 {
    return std.fmt.parseInt(i128, text, 10) catch
        if (text.len > 0 and text[0] == '-') std.math.minInt(i128) else std.math.maxInt(i128);
}

/// Classify `lt <op> other` (the locktime read on the left); `other` is the
/// literal's value, or null when it is not a bigint literal.
fn classify(op: Cmp, other: ?i128) Class {
    if (op == .gte or op == .gt) {
        // `>= 0` is vacuous (every locktime passes it): no gate. Only literal 0:
        // a negative bound is a negation in source but may be a literal in IR.
        if (other) |n| {
            if (op == .gte and n == 0) return .none;
            const ts = if (op == .gte) n >= LOCKTIME_THRESHOLD else n >= LOCKTIME_THRESHOLD - 1;
            return if (ts) .pin else .gate;
        }
        return .gate;
    }
    const n = other orelse return .none;
    const height = if (op == .lt) n > 0 and n <= LOCKTIME_THRESHOLD else n >= 0 and n < LOCKTIME_THRESHOLD;
    return if (height) .pin else .none;
}

/// Taint level: not a locktime read / a direct read / derived from one.
pub const NONE: u2 = 0;
pub const DIRECT: u2 = 1;
pub const DERIVED: u2 = 2;

fn side(lv: u2, op: Cmp, other: ?i128) Class {
    if (lv == DIRECT) return classify(op, other);
    if (lv == DERIVED) return if (op == .gte or op == .gt) .gate else .none;
    return .none;
}

/// Classify a compare given its operands' taint levels and literal values:
/// each tainted side is read as the left one; a gate on either side wins.
pub fn classifyCompare(op: Cmp, left_level: u2, left_lit: ?i128, right_level: u2, right_lit: ?i128) Class {
    const a = side(left_level, op, right_lit);
    const b = side(right_level, flip(op), left_lit);
    if (a == .gate or b == .gate) return .gate;
    return if (a == .pin or b == .pin) .pin else .none;
}

/// Taint of a set of names from their bindings, order-blind: least fixpoint
/// for the tainted set, then greatest fixpoint (within it) for the names all
/// of whose bindings are direct reads. `Ctx` supplies
/// `tainted(ctx, binding, *const Levels) bool` (names in the map are tainted)
/// and `direct(ctx, binding, *const Levels) bool` (names in the map are direct).
pub const Levels = std.StringHashMapUnmanaged(u2);

pub fn solveTaint(
    comptime B: type,
    a: Allocator,
    names: []const []const u8,
    binds: []const B,
    ctx: anytype,
) Allocator.Error!Levels {
    var t: Levels = .empty;
    var changed = true;
    while (changed) {
        changed = false;
        for (names, binds) |n, b| {
            if (!t.contains(n) and ctx.tainted(b, &t)) {
                try t.put(a, n, DIRECT);
                changed = true;
            }
        }
    }
    var d: Levels = .empty;
    var it = t.iterator();
    while (it.next()) |e| try d.put(a, e.key_ptr.*, DIRECT);
    changed = true;
    while (changed) {
        changed = false;
        for (names, binds) |n, b| {
            if (d.contains(n) and !ctx.direct(b, &d)) {
                _ = d.remove(n);
                changed = true;
            }
        }
    }
    var out: Levels = .empty;
    var it2 = t.iterator();
    while (it2.next()) |e| try out.put(a, e.key_ptr.*, if (d.contains(e.key_ptr.*)) DIRECT else DERIVED);
    return out;
}

// ---------------------------------------------------------------------------
// Source path
// ---------------------------------------------------------------------------

fn isCallTo(e: Expression, name: []const u8) bool {
    return e == .call and std.mem.eql(u8, e.call.callee, name);
}

/// A D26 locktime read. currentBlockHeight() is not one: it asserts its own
/// value < 500000000 at the call (anf_lower.zig), so it is a height by
/// construction. Mirrors locktime-domain.ts.
fn isLocktimeRead(e: Expression) bool {
    return isCallTo(e, "extractLocktime");
}

fn exprReads(e: Expression) bool {
    if (isLocktimeRead(e)) return true;
    return switch (e) {
        .call => |c| for (c.args) |x| {
            if (exprReads(x)) break true;
        } else false,
        .method_call => |mc| for (mc.args) |x| {
            if (exprReads(x)) break true;
        } else false,
        .binary_op => |b| exprReads(b.left) or exprReads(b.right),
        .unary_op => |u| exprReads(u.operand),
        .ternary => |t| exprReads(t.condition) or exprReads(t.then_expr) or exprReads(t.else_expr),
        .index_access => |ia| exprReads(ia.object) or exprReads(ia.index),
        .increment => |inc| exprReads(inc.operand),
        .decrement => |dec| exprReads(dec.operand),
        .array_literal => |els| for (els) |x| {
            if (exprReads(x)) break true;
        } else false,
        else => false,
    };
}

fn stmtsRead(list: []const Statement) bool {
    for (list) |st| {
        const hit = switch (st) {
            .expr_stmt => |e| exprReads(e.expr),
            .const_decl => |cd| exprReads(cd.value),
            .let_decl => |ld| if (ld.value) |v| exprReads(v) else false,
            .assign => |as_| exprReads(as_.value) or
                (if (as_.index_target) |it| exprReads(it.object) or exprReads(it.index) else false),
            .assert_stmt => |as_s| exprReads(as_s.condition),
            .return_stmt => |r| if (r.value) |v| exprReads(v) else false,
            .if_stmt => |if_s| exprReads(if_s.condition) or stmtsRead(if_s.then_body) or
                (if (if_s.else_body) |eb| stmtsRead(eb) else false),
            .for_stmt => |fs| stmtsRead(fs.body) or (if (fs.update) |u| stmtsRead(u[0..1]) else false),
        };
        if (hit) return true;
    }
    return false;
}

/// The shared error text for a currentBlockHeight() compare against a
/// timestamp-domain bound (method name).
pub const CBH_TIMESTAMP_FMT =
    "method '{s}' compares currentBlockHeight() against a Unix-timestamp bound: currentBlockHeight() asserts " ++
    "its value is below 500000000 (a block height), so this compare can never pass and an output gated on it " ++
    "could never be spent. Use extractLocktime(this.txPreimage) for a timestamp gate";

/// Locals every binding of which is a direct currentBlockHeight() call.
const CbhSet = std.StringHashMapUnmanaged(bool);

fn isCbh(e: Expression, cbh: *const CbhSet) bool {
    if (isCallTo(e, "currentBlockHeight")) return true;
    return e == .identifier and (cbh.get(e.identifier) orelse false);
}

fn cbhTimestampHit(e: Expression, cbh: *const CbhSet) bool {
    if (e != .binary_op) return false;
    const b = e.binary_op;
    const op: Cmp = switch (b.op) {
        .lt => .lt,
        .lte => .lte,
        .gt => .gt,
        .gte => .gte,
        else => return false,
    };
    if (isCbh(b.left, cbh) and (op == .gte or op == .gt) and classify(op, literalOf(b.right)) == .pin) return true;
    const f = flip(op);
    return isCbh(b.right, cbh) and (f == .gte or f == .gt) and classify(f, literalOf(b.left)) == .pin;
}

fn exprHasCbhTimestamp(e: Expression, cbh: *const CbhSet) bool {
    if (cbhTimestampHit(e, cbh)) return true;
    return switch (e) {
        .call => |c| for (c.args) |x| {
            if (exprHasCbhTimestamp(x, cbh)) break true;
        } else false,
        .method_call => |mc| for (mc.args) |x| {
            if (exprHasCbhTimestamp(x, cbh)) break true;
        } else false,
        .binary_op => |b| exprHasCbhTimestamp(b.left, cbh) or exprHasCbhTimestamp(b.right, cbh),
        .unary_op => |u| exprHasCbhTimestamp(u.operand, cbh),
        .ternary => |t| exprHasCbhTimestamp(t.condition, cbh) or exprHasCbhTimestamp(t.then_expr, cbh) or exprHasCbhTimestamp(t.else_expr, cbh),
        .index_access => |ia| exprHasCbhTimestamp(ia.object, cbh) or exprHasCbhTimestamp(ia.index, cbh),
        .increment => |inc| exprHasCbhTimestamp(inc.operand, cbh),
        .decrement => |dec| exprHasCbhTimestamp(dec.operand, cbh),
        .array_literal => |els| for (els) |x| {
            if (exprHasCbhTimestamp(x, cbh)) break true;
        } else false,
        else => false,
    };
}

fn stmtsHaveCbhTimestamp(list: []const Statement, cbh: *const CbhSet) bool {
    for (list) |st| {
        const hit = switch (st) {
            .expr_stmt => |e| exprHasCbhTimestamp(e.expr, cbh),
            .const_decl => |cd| exprHasCbhTimestamp(cd.value, cbh),
            .let_decl => |ld| if (ld.value) |v| exprHasCbhTimestamp(v, cbh) else false,
            .assign => |as_| exprHasCbhTimestamp(as_.value, cbh) or
                (if (as_.index_target) |it| exprHasCbhTimestamp(it.object, cbh) or exprHasCbhTimestamp(it.index, cbh) else false),
            .assert_stmt => |as_s| exprHasCbhTimestamp(as_s.condition, cbh),
            .return_stmt => |r| if (r.value) |v| exprHasCbhTimestamp(v, cbh) else false,
            .if_stmt => |if_s| exprHasCbhTimestamp(if_s.condition, cbh) or stmtsHaveCbhTimestamp(if_s.then_body, cbh) or
                (if (if_s.else_body) |eb| stmtsHaveCbhTimestamp(eb, cbh) else false),
            .for_stmt => |fs| stmtsHaveCbhTimestamp(fs.body, cbh) or
                (if (fs.update) |u| stmtsHaveCbhTimestamp(u[0..1], cbh) else false),
        };
        if (hit) return true;
    }
    return false;
}

fn cbhBind(a: Allocator, cbh: *CbhSet, name: []const u8, v: ?Expression) Allocator.Error!void {
    const ok = if (v) |e| isCallTo(e, "currentBlockHeight") else false;
    const prev = cbh.get(name) orelse true;
    try cbh.put(a, name, prev and ok);
}

fn cbhCollect(a: Allocator, list: []const Statement, cbh: *CbhSet) Allocator.Error!void {
    for (list) |st| switch (st) {
        .const_decl => |cd| try cbhBind(a, cbh, cd.name, cd.value),
        .let_decl => |ld| try cbhBind(a, cbh, ld.name, ld.value),
        .assign => |as_| if (!as_.target_is_property and as_.index_target == null) try cbhBind(a, cbh, as_.target, as_.value),
        .if_stmt => |if_s| {
            try cbhCollect(a, if_s.then_body, cbh);
            if (if_s.else_body) |eb| try cbhCollect(a, eb, cbh);
        },
        .for_stmt => |fs| try cbhCollect(a, fs.body, cbh),
        else => {},
    };
}

/// True iff `method` contains, anywhere, a lower-bound compare of a direct
/// currentBlockHeight() call (or a local every binding of which is one)
/// against a timestamp-domain bigint literal (`>= N`, N >= 500000000;
/// `> N`, N >= 499999999; or reversed). currentBlockHeight() asserts its
/// value is below 500000000, so such a compare can never pass. Mirrors
/// comparesCurrentBlockHeightToTimestamp in locktime-domain.ts.
pub fn comparesCurrentBlockHeightToTimestamp(method: MethodNode) bool {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var cbh: CbhSet = .empty;
    cbhCollect(arena.allocator(), method.body, &cbh) catch @panic("out of memory");
    return stmtsHaveCbhTimestamp(method.body, &cbh);
}

/// D26 prefilter: some method reads the locktime (extractLocktime) anywhere. Without one there is no gate to walk for.
pub fn contractReadsLocktime(contract: ContractNode) bool {
    for (contract.methods) |m| if (stmtsRead(m.body)) return true;
    return false;
}

const PROPAGATE_BIN = [_]types.BinOperator{ .add, .sub, .mul, .div, .mod, .bitand, .bitor, .bitxor, .lshift, .rshift };

fn propagates(op: types.BinOperator) bool {
    for (PROPAGATE_BIN) |p| if (p == op) return true;
    return false;
}

/// Taint level of a source expression, given the taint of the names in scope.
/// `g` (when given) resolves a private helper's return level.
fn exprLevel(e: Expression, names: *const Levels, g: ?*SourceGates) u2 {
    if (isLocktimeRead(e)) return DIRECT;
    switch (e) {
        .identifier => |n| return names.get(n) orelse NONE,
        .binary_op => |b| return if (propagates(b.op) and (exprLevel(b.left, names, g) != NONE or exprLevel(b.right, names, g) != NONE)) DERIVED else NONE,
        .unary_op => |u| return if ((u.op == .negate or u.op == .bitnot) and exprLevel(u.operand, names, g) != NONE) DERIVED else NONE,
        .ternary => |t| return if (exprLevel(t.then_expr, names, g) != NONE or exprLevel(t.else_expr, names, g) != NONE) DERIVED else NONE,
        // A builtin (bare callee) derives from its arguments.
        .call => |c| {
            for (c.args) |x| if (exprLevel(x, names, g) != NONE) return DERIVED;
            return NONE;
        },
        // A private helper's return carries the locktime taint into the caller
        // (inlined, `this.height()` IS its returned expression).
        .method_call => |mc| {
            const gg = g orelse return NONE;
            const h = gg.lookupPrivate(mc.method) orelse return NONE;
            const levels = gg.a.alloc(u2, mc.args.len) catch @panic("out of memory");
            for (mc.args, 0..) |x, i| levels[i] = exprLevel(x, names, g);
            return gg.helperReturn(h, levels) catch @panic("out of memory");
        },
        else => return NONE,
    }
}

/// Every `return` expression of a method body (if arms and loop bodies included).
fn returnExpressions(a: Allocator, body: []const Statement) Allocator.Error![]const Expression {
    var out: std.ArrayListUnmanaged(Expression) = .empty;
    var work: std.ArrayListUnmanaged([]const Statement) = .empty;
    try work.append(a, body);
    while (work.pop()) |list| {
        for (list) |st| switch (st) {
            .return_stmt => |r| if (r.value) |v| try out.append(a, v),
            .if_stmt => |if_s| {
                try work.append(a, if_s.then_body);
                if (if_s.else_body) |eb| try work.append(a, eb);
            },
            .for_stmt => |fs| try work.append(a, fs.body),
            else => {},
        };
    }
    return out.items;
}

fn literalOf(e: Expression) ?i128 {
    return switch (e) {
        .literal_int => |v| @as(i128, v),
        .literal_bigint => |s| parseBig(s),
        else => null,
    };
}

/// A binding of a local or parameter: an initializer, or a parameter's level.
const SourceBind = union(enum) { expr: Expression, level: u2 };

const SourceTaintCtx = struct {
    g: ?*SourceGates = null,
    fn tainted(c: SourceTaintCtx, b: SourceBind, t: *const Levels) bool {
        return switch (b) {
            .level => |lv| lv != NONE,
            .expr => |e| exprLevel(e, t, c.g) != NONE,
        };
    }
    fn direct(c: SourceTaintCtx, b: SourceBind, d: *const Levels) bool {
        return switch (b) {
            .level => |lv| lv == DIRECT,
            .expr => |e| isLocktimeRead(e) or (e == .identifier and d.contains(e.identifier)) or
                (e == .method_call and exprLevel(e, d, c.g) == DIRECT),
        };
    }
};

const Flow = struct { live: u4, returned: u4 };

const SourceGates = struct {
    a: Allocator,
    contract: ContractNode,
    /// Helper exits, by helper name and the taint level of each argument.
    helper_exits: std.StringHashMapUnmanaged(u4) = .empty,
    in_progress: std.StringHashMapUnmanaged(void) = .empty,
    /// Taint level of the locals and parameters of the method being walked.
    locals: Levels = .empty,
    /// Helper return levels, by helper key (name + argument levels).
    return_levels: std.StringHashMapUnmanaged(u2) = .empty,
    return_in_progress: std.StringHashMapUnmanaged(void) = .empty,

    /// Level of a private helper's return value: DIRECT when every `return`
    /// expression is a direct read, DERIVED when some is tainted, else NONE
    /// (the rule a local with several bindings follows). A call cycle
    /// contributes NONE. Mirrors SourceGates.helperReturn in locktime-domain.ts.
    fn helperReturn(g: *SourceGates, m: MethodNode, arg_levels: []const u2) Allocator.Error!u2 {
        var params: Levels = .empty;
        var key: std.ArrayListUnmanaged(u8) = .empty;
        try key.appendSlice(g.a, m.name);
        try key.append(g.a, '|');
        for (m.params, 0..) |p, i| {
            const lv = if (i < arg_levels.len) arg_levels[i] else NONE;
            if (lv != NONE) try params.put(g.a, p.name, lv);
            if (i > 0) try key.append(g.a, ',');
            try key.append(g.a, '0' + @as(u8, lv));
        }
        if (g.return_levels.get(key.items)) |lv| return lv;
        if (g.return_in_progress.contains(key.items)) return NONE;
        try g.return_in_progress.put(g.a, key.items, {});
        const locals = try collectLocals(g.a, m.body, params, g);
        var all_none = true;
        var all_direct = true;
        for (try returnExpressions(g.a, m.body)) |r| {
            const lv = exprLevel(r, &locals, g);
            if (lv != NONE) all_none = false;
            if (lv != DIRECT) all_direct = false;
        }
        _ = g.return_in_progress.remove(key.items);
        const lv: u2 = if (all_none) NONE else if (all_direct) DIRECT else DERIVED;
        try g.return_levels.put(g.a, key.items, lv);
        return lv;
    }

    fn lookupPrivate(g: *SourceGates, name: []const u8) ?MethodNode {
        for (g.contract.methods) |m| {
            if (!m.is_public and std.mem.eql(u8, m.name, name)) return m;
        }
        return null;
    }

    fn exits(g: *SourceGates, method: MethodNode, params: Levels) Allocator.Error!u4 {
        const saved = g.locals;
        g.locals = try collectLocals(g.a, method.body, params, g);
        const f = try g.stmts(method.body, ZERO);
        g.locals = saved;
        return f.live | f.returned;
    }

    fn level(g: *SourceGates, e: Expression) u2 {
        return exprLevel(e, &g.locals, g);
    }

    fn compare(g: *SourceGates, e: Expression) Class {
        if (e != .binary_op) return .none;
        const b = e.binary_op;
        const op: Cmp = switch (b.op) {
            .lt => .lt,
            .lte => .lte,
            .gt => .gt,
            .gte => .gte,
            else => return .none,
        };
        return classifyCompare(op, g.level(b.left), literalOf(b.left), g.level(b.right), literalOf(b.right));
    }

    fn assertedPin(g: *SourceGates, e: Expression) bool {
        if (g.compare(e) == .pin) return true;
        if (e == .binary_op and e.binary_op.op == .and_op) return g.assertedPin(e.binary_op.left) or g.assertedPin(e.binary_op.right);
        return false;
    }

    fn stmts(g: *SourceGates, list: []const Statement, states: u4) Allocator.Error!Flow {
        var live = states;
        var returned: u4 = 0;
        for (list) |st| {
            if (live == 0) break;
            const f = try g.stmt(st, live);
            returned |= f.returned;
            live = f.live;
        }
        return .{ .live = live, .returned = returned };
    }

    fn stmt(g: *SourceGates, st: Statement, states: u4) Allocator.Error!Flow {
        switch (st) {
            .assign => |as_| {
                var s = states;
                if (as_.index_target) |it| s = try g.expr(it.index, try g.expr(it.object, s));
                return .{ .live = try g.expr(as_.value, s), .returned = 0 };
            },
            .expr_stmt => |e| return .{ .live = try g.expr(e.expr, states), .returned = 0 },
            .const_decl => |cd| return .{ .live = try g.expr(cd.value, states), .returned = 0 },
            .let_decl => |ld| return .{ .live = if (ld.value) |v| try g.expr(v, states) else states, .returned = 0 },
            .assert_stmt => |as_s| {
                const s = try g.expr(as_s.condition, states);
                return .{ .live = if (g.assertedPin(as_s.condition)) orAll(s, P) else s, .returned = 0 };
            },
            .return_stmt => |r| return .{ .live = 0, .returned = if (r.value) |v| try g.expr(v, states) else states },
            .if_stmt => |if_s| {
                const c = try g.expr(if_s.condition, states);
                const t = try g.stmts(if_s.then_body, c);
                const e: Flow = if (if_s.else_body) |eb| try g.stmts(eb, c) else .{ .live = c, .returned = 0 };
                return .{ .live = t.live | e.live, .returned = t.returned | e.returned };
            },
            // The header's init / bound are integers: nothing to walk there.
            .for_stmt => |fs| {
                const b = try g.stmts(fs.body, states);
                const u: Flow = if (fs.update) |up| try g.stmt(up.*, b.live) else .{ .live = b.live, .returned = 0 };
                return .{ .live = states | u.live, .returned = b.returned | u.returned };
            },
        }
    }

    fn expr(g: *SourceGates, e: Expression, states: u4) Allocator.Error!u4 {
        switch (e) {
            .call => |c| {
                var s = states;
                for (c.args) |x| s = try g.expr(x, s);
                if (std.mem.eql(u8, c.callee, "assert") and c.args.len > 0 and g.assertedPin(c.args[0])) return orAll(s, P);
                return s;
            },
            .method_call => |mc| {
                var s = states;
                for (mc.args) |x| s = try g.expr(x, s);
                const h = g.lookupPrivate(mc.method) orelse return s;
                var levels = try g.a.alloc(u2, mc.args.len);
                for (mc.args, 0..) |x, i| levels[i] = g.level(x);
                return compose(s, try g.helper(h, levels));
            },
            .binary_op => |b| {
                const s = try g.expr(b.right, try g.expr(b.left, states));
                return if (g.compare(e) == .gate) orAll(s, G) else s;
            },
            .unary_op => |u| return g.expr(u.operand, states),
            .ternary => |t| {
                const c = try g.expr(t.condition, states);
                return (try g.expr(t.then_expr, c)) | (try g.expr(t.else_expr, c));
            },
            .index_access => |ia| return g.expr(ia.index, try g.expr(ia.object, states)),
            .increment => |inc| return g.expr(inc.operand, states),
            .decrement => |dec| return g.expr(dec.operand, states),
            .array_literal => |els| {
                var s = states;
                for (els) |x| s = try g.expr(x, s);
                return s;
            },
            else => return states,
        }
    }

    fn helper(g: *SourceGates, m: MethodNode, arg_levels: []const u2) Allocator.Error!u4 {
        var params: Levels = .empty;
        var key: std.ArrayListUnmanaged(u8) = .empty;
        try key.appendSlice(g.a, m.name);
        try key.append(g.a, '|');
        for (m.params, 0..) |p, i| {
            const lv = if (i < arg_levels.len) arg_levels[i] else NONE;
            if (lv != NONE) try params.put(g.a, p.name, lv);
            if (i > 0) try key.append(g.a, ',');
            try key.append(g.a, '0' + @as(u8, lv));
        }
        if (g.helper_exits.get(key.items)) |cached| return cached;
        // Recursion is refused by the validator; a cycle contributes nothing.
        if (g.in_progress.contains(m.name)) return ZERO;
        try g.in_progress.put(g.a, m.name, {});
        const ex = try g.exits(m, params);
        _ = g.in_progress.remove(m.name);
        try g.helper_exits.put(g.a, key.items, ex);
        return ex;
    }
};

/// Taint of the method's locals and parameters, from every binding in the
/// body (declaration or assignment, anywhere) plus one binding per tainted
/// parameter (the level its call passes it). Order-blind on purpose.
fn collectLocals(a: Allocator, body: []const Statement, params: Levels, g: ?*SourceGates) Allocator.Error!Levels {
    var names: std.ArrayListUnmanaged([]const u8) = .empty;
    var binds: std.ArrayListUnmanaged(SourceBind) = .empty;
    var it = params.iterator();
    while (it.next()) |e| {
        try names.append(a, e.key_ptr.*);
        try binds.append(a, .{ .level = e.value_ptr.* });
    }
    const Visit = struct {
        fn run(al: Allocator, list: []const Statement, ns: *std.ArrayListUnmanaged([]const u8), bs: *std.ArrayListUnmanaged(SourceBind)) Allocator.Error!void {
            for (list) |st| switch (st) {
                .const_decl => |cd| {
                    try ns.append(al, cd.name);
                    try bs.append(al, .{ .expr = cd.value });
                },
                .let_decl => |ld| if (ld.value) |v| {
                    try ns.append(al, ld.name);
                    try bs.append(al, .{ .expr = v });
                },
                .assign => |as_| if (!as_.target_is_property and as_.index_target == null) {
                    try ns.append(al, as_.target);
                    try bs.append(al, .{ .expr = as_.value });
                },
                .if_stmt => |if_s| {
                    try run(al, if_s.then_body, ns, bs);
                    if (if_s.else_body) |eb| try run(al, eb, ns, bs);
                },
                .for_stmt => |fs| try run(al, fs.body, ns, bs),
                else => {},
            };
        }
    };
    try Visit.run(a, body, &names, &binds);
    return solveTaint(SourceBind, a, names.items, binds.items, SourceTaintCtx{ .g = g });
}

/// D26 (source path): true iff some path through public `method` carries an
/// unpinned gate. Callers gate it on `contractReadsLocktime`.
pub fn hasUnpinnedLocktimeGate(contract: ContractNode, method: MethodNode) bool {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var g: SourceGates = .{ .a = arena.allocator(), .contract = contract };
    const ex = g.exits(method, .empty) catch @panic("out of memory");
    return unpinned(ex);
}
