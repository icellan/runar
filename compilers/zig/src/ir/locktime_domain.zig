//! D26 on --ir input. Port of assertIrLocktimeDomain in
//! packages/runar-compiler/src/passes/locktime-domain.ts: compile-ir skips the
//! frontend, so the rule is re-derived from the ANF of every public method
//! (stateless and stateful): a `bin_op` gate whose operand resolves (through
//! `load_const "@ref:"` aliases) to a `call extractLocktime`, and an `assert`
//! whose value resolves to a pin compare, or to the `&&` lowering (a value
//! `if` whose `else` arm is the single constant `false`) of a chain with a pin
//! conjunct. Per path: `if` unions its arms, a loop unions with skipping it, a
//! method_call to a private method composes with that method's exit states
//! (cached by name plus argument taint). Run after the D15 preimage rules.

const std = @import("std");
const types = @import("types.zig");
const required_fields = @import("required_fields.zig");
const ld = @import("../passes/locktime_domain.zig");

const Allocator = std.mem.Allocator;

pub const Error = error{ LocktimeDomain, OutOfMemory };

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn refOf(v: types.ANFValue) ?[]const u8 {
    if (v != .load_const) return null;
    return switch (v.load_const.value) {
        .string => |s| if (std.mem.startsWith(u8, s, "@ref:")) s[5..] else null,
        else => null,
    };
}

fn lastName(arm: []const types.ANFBinding) ?[]const u8 {
    return if (arm.len == 0) null else arm[arm.len - 1].name;
}

fn isPropagateBin(op: []const u8) bool {
    for ([_][]const u8{ "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>" }) |p| if (eql(op, p)) return true;
    return false;
}

fn isPropagateUnary(op: []const u8) bool {
    return eql(op, "-") or eql(op, "~");
}

/// Prefilter: some binding (if / loop arms included) is `call extractLocktime`.
fn reads(bs: []const types.ANFBinding) bool {
    for (bs) |b| switch (b.value) {
        .call => |c| if (eql(c.func, "extractLocktime")) return true,
        .@"if" => |iff| if (reads(iff.then) or reads(iff.@"else")) return true,
        .loop => |lp| if (reads(lp.body)) return true,
        else => {},
    };
    return false;
}

const Defs = std.StringHashMapUnmanaged(std.ArrayListUnmanaged(types.ANFValue));

const IrTaintCtx = struct {
    params: *const ld.Levels,
    pub fn tainted(c: IrTaintCtx, v: types.ANFValue, t: *const ld.Levels) bool {
        if (refOf(v)) |r| return t.contains(r);
        return switch (v) {
            .call => |call| blk: {
                if (eql(call.func, "extractLocktime")) break :blk true;
                for (call.args) |a| if (t.contains(a)) break :blk true;
                break :blk false;
            },
            .load_param => |lp| (c.params.get(lp.name) orelse ld.NONE) != ld.NONE,
            .bin_op => |b| isPropagateBin(b.op) and (t.contains(b.left) or t.contains(b.right)),
            .unary_op => |u| isPropagateUnary(u.op) and t.contains(u.operand),
            .@"if" => |iff| blk: {
                if (lastName(iff.then)) |n| if (t.contains(n)) break :blk true;
                if (lastName(iff.@"else")) |n| if (t.contains(n)) break :blk true;
                break :blk false;
            },
            else => false,
        };
    }
    pub fn direct(c: IrTaintCtx, v: types.ANFValue, d: *const ld.Levels) bool {
        if (refOf(v)) |r| return d.contains(r);
        return switch (v) {
            .call => |call| eql(call.func, "extractLocktime"),
            .load_param => |lp| (c.params.get(lp.name) orelse ld.NONE) == ld.DIRECT,
            else => false,
        };
    }
};

const Program = struct {
    a: Allocator,
    methods: []const types.ANFMethod,
    exits_of: std.StringHashMapUnmanaged(u4) = .empty,
    in_progress: std.StringHashMapUnmanaged(void) = .empty,

    fn private(p: *Program, name: []const u8) ?types.ANFMethod {
        for (p.methods) |m| {
            if (m.is_public or eql(m.name, "constructor") or !eql(m.name, name)) continue;
            return m;
        }
        return null;
    }

    fn exits(p: *Program, m: types.ANFMethod, arg_levels: []const u2) Allocator.Error!u4 {
        var params: ld.Levels = .empty;
        var key: std.ArrayListUnmanaged(u8) = .empty;
        try key.appendSlice(p.a, m.name);
        try key.append(p.a, '|');
        for (m.params, 0..) |prm, i| {
            const lv = if (i < arg_levels.len) arg_levels[i] else ld.NONE;
            if (lv != ld.NONE) try params.put(p.a, prm.name, lv);
            if (i > 0) try key.append(p.a, ',');
            try key.append(p.a, '0' + @as(u8, lv));
        }
        if (p.exits_of.get(key.items)) |cached| return cached;
        if (p.in_progress.contains(m.name)) return ld.ZERO;
        try p.in_progress.put(p.a, m.name, {});
        var g = try Gates.init(p, m, params);
        const ex = try g.run(m.body, ld.ZERO);
        _ = p.in_progress.remove(m.name);
        try p.exits_of.put(p.a, key.items, ex);
        return ex;
    }
};

const Gates = struct {
    prog: *Program,
    /// Every binding of the method, by name (a name bound more than once keeps all its values).
    defs: Defs,
    taint: ld.Levels,

    fn index(a: Allocator, defs: *Defs, names: *std.ArrayListUnmanaged([]const u8), vals: *std.ArrayListUnmanaged(types.ANFValue), bs: []const types.ANFBinding) Allocator.Error!void {
        for (bs) |b| {
            const gop = try defs.getOrPut(a, b.name);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.append(a, b.value);
            try names.append(a, b.name);
            try vals.append(a, b.value);
            switch (b.value) {
                .@"if" => |iff| {
                    try index(a, defs, names, vals, iff.then);
                    try index(a, defs, names, vals, iff.@"else");
                },
                .loop => |lp| try index(a, defs, names, vals, lp.body),
                else => {},
            }
        }
    }

    fn init(prog: *Program, m: types.ANFMethod, params: ld.Levels) Allocator.Error!Gates {
        const a = prog.a;
        var defs: Defs = .empty;
        var names: std.ArrayListUnmanaged([]const u8) = .empty;
        var vals: std.ArrayListUnmanaged(types.ANFValue) = .empty;
        try index(a, &defs, &names, &vals, m.body);
        const ps = try a.create(ld.Levels);
        ps.* = params;
        const taint = try ld.solveTaint(types.ANFValue, a, names.items, vals.items, IrTaintCtx{ .params = ps });
        return .{ .prog = prog, .defs = defs, .taint = taint };
    }

    fn level(g: *const Gates, name: []const u8) u2 {
        return g.taint.get(name) orelse ld.NONE;
    }

    fn single(g: *const Gates, name: []const u8) ?types.ANFValue {
        const list = g.defs.get(name) orelse return null;
        return if (list.items.len == 1) list.items[0] else null;
    }

    /// The bigint a name resolves to through `@ref:` aliases, or null.
    fn literal(g: *const Gates, start: []const u8) ?i128 {
        var name = start;
        var hops: usize = 0;
        while (hops <= g.defs.count()) : (hops += 1) {
            const v = g.single(name) orelse return null;
            if (v != .load_const) return null;
            switch (v.load_const.value) {
                .integer => |n| return n,
                .big_integer => |s| return ld.parseBig(s),
                .string => |s| {
                    if (!std.mem.startsWith(u8, s, "@ref:")) return null;
                    name = s[5..];
                },
                else => return null,
            }
        }
        return null; // an alias cycle
    }

    fn compare(g: *const Gates, v: types.ANFValue) ld.Class {
        if (v != .bin_op) return .none;
        const b = v.bin_op;
        const op = ld.cmpFromTs(b.op) orelse return .none;
        return ld.classifyCompare(op, g.level(b.left), g.literal(b.left), g.level(b.right), g.literal(b.right));
    }

    /// Does `assert(name)` imply a pin? Explicit work list with a seen set.
    fn assertedPin(g: *const Gates, start: []const u8) Allocator.Error!bool {
        const a = g.prog.a;
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        var work: std.ArrayListUnmanaged([]const u8) = .empty;
        try work.append(a, start);
        while (work.pop()) |name| {
            const gop = try seen.getOrPut(a, name);
            if (gop.found_existing) continue;
            const v = g.single(name) orelse continue;
            if (g.compare(v) == .pin) return true;
            if (refOf(v)) |r| {
                try work.append(a, r);
                continue;
            }
            // `a && b` lowers to `if a then [..., b] else [false]`.
            if (v == .@"if") {
                const iff = v.@"if";
                if (isConstFalseArm(iff.@"else") and iff.then.len > 0) {
                    try work.append(a, iff.cond);
                    try work.append(a, iff.then[iff.then.len - 1].name);
                }
            }
        }
        return false;
    }

    fn run(g: *Gates, bs: []const types.ANFBinding, states: u4) Allocator.Error!u4 {
        var s = states;
        for (bs) |b| {
            switch (b.value) {
                .bin_op => if (g.compare(b.value) == .gate) {
                    s = ld.orAll(s, ld.G);
                },
                .assert => |as_| if (try g.assertedPin(as_.value)) {
                    s = ld.orAll(s, ld.P);
                },
                .method_call => |mc| if (g.prog.private(mc.method)) |t| {
                    const levels = try g.prog.a.alloc(u2, mc.args.len);
                    for (mc.args, 0..) |x, i| levels[i] = g.level(x);
                    s = ld.compose(s, try g.prog.exits(t, levels));
                },
                .@"if" => |iff| s = (try g.run(iff.then, s)) | (try g.run(iff.@"else", s)),
                .loop => |lp| s |= try g.run(lp.body, s),
                else => {},
            }
        }
        return s;
    }
};

fn isConstFalseArm(arm: []const types.ANFBinding) bool {
    if (arm.len != 1) return false;
    const v = arm[0].value;
    if (v != .load_const) return false;
    return switch (v.load_const.value) {
        .boolean => |b| !b,
        else => false,
    };
}

/// Refuses the first public method with an unpinned locktime gate on some
/// path (error.LocktimeDomain, message in the required_fields diagnostic channel).
pub fn check(allocator: Allocator, methods: []const types.ANFMethod) Error!void {
    var any = false;
    for (methods) |m| {
        if (reads(m.body)) any = true;
    }
    if (!any) return;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var prog: Program = .{ .a = arena.allocator(), .methods = methods };
    for (methods) |m| {
        if (!m.is_public or eql(m.name, "constructor")) continue;
        if (ld.unpinned(try prog.exits(m, &.{}))) {
            required_fields.setDiag("IR validation: " ++ ld.LOCKTIME_DOMAIN_FMT, .{m.name});
            return error.LocktimeDomain;
        }
    }
}
