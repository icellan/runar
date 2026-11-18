//! D15: the preimage rules on `--ir` input. Port of
//! packages/runar-compiler/src/passes/ir-preimage-rules.ts (see its header for
//! the full rule and for what ANF cannot carry). `--ir` skips the frontend,
//! so D9 (no SigHashPreimage property), GK-GAP-010 (a public method's
//! SigHashPreimage parameter is asserted on every path) and D14 (an extractor
//! reads only a checked preimage) are re-derived here, failing closed. Zig
//! reports the first violation (the order the TS reference joins them in).

const std = @import("std");
const types = @import("types.zig");
const required_fields = @import("required_fields.zig");
const validate = @import("../passes/validate.zig");
const typecheck = @import("../passes/typecheck.zig");

pub const Error = error{ PreimageRuleViolation, OutOfMemory };

const Allocator = std.mem.Allocator;
const StringSet = std.StringHashMapUnmanaged(void);
const SHP = "SigHashPreimage";

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn isExtractor(name: []const u8) bool {
    for (typecheck.PREIMAGE_EXTRACTORS) |e| if (eql(e, name)) return true;
    return false;
}

fn refTarget(v: types.ANFValue) ?[]const u8 {
    return switch (v) {
        .load_const => |lc| switch (lc.value) {
            .string => |s| if (std.mem.startsWith(u8, s, "@ref:")) s[5..] else null,
            else => null,
        },
        else => null,
    };
}

/// A set where `all` stands for "everything" (what a constant-false arm implies).
const Checks = struct {
    all: bool = false,
    set: StringSet = .empty,
};

const THEN: i64 = -1;
const ELSE: i64 = -2;
const BODY: i64 = -3;
const Path = []const i64;

fn child(a: Allocator, p: Path, i: i64) Allocator.Error!Path {
    const out = try a.alloc(i64, p.len + 1);
    @memcpy(out[0..p.len], p);
    out[p.len] = i;
    return out;
}

/// Is the binding at `def` in scope at `from`? Only if it sits earlier in the
/// same list or in a list enclosing it: stack lowering resolves names by
/// position, so a binding after (or beside) a use never answers for it.
fn visible(def: Path, from: Path) bool {
    const n = def.len;
    if (n == 0 or from.len < n) return false;
    if (!std.mem.eql(i64, def[0 .. n - 1], from[0 .. n - 1])) return false;
    return def[n - 1] < from[n - 1];
}

const Def = struct { value: types.ANFValue, path: Path };

const View = struct {
    a: Allocator,
    defs: std.StringHashMapUnmanaged(Def) = .empty,
    /// Bound more than once, or under a parameter's name: never resolves.
    poisoned: StringSet = .empty,
    shp: StringSet = .empty,
    implicit: bool = false,

    fn init(a: Allocator, m: types.ANFMethod, implicit_tx: bool) Allocator.Error!View {
        var v: View = .{ .a = a };
        var own = false;
        for (m.params) |p| {
            try v.poisoned.put(a, p.name, {});
            if (eql(p.type_name, SHP)) try v.shp.put(a, p.name, {});
            if (eql(p.name, "txPreimage")) own = true;
        }
        try v.collect(m.body, &.{});
        v.implicit = !m.is_public and implicit_tx and !own;
        return v;
    }

    fn collect(self: *View, bs: []const types.ANFBinding, at: Path) Allocator.Error!void {
        for (bs, 0..) |b, i| {
            const path = try child(self.a, at, @intCast(i));
            if (self.defs.contains(b.name)) try self.poisoned.put(self.a, b.name, {});
            try self.defs.put(self.a, b.name, .{ .value = b.value, .path = path });
            switch (b.value) {
                .@"if" => |iff| {
                    try self.collect(iff.then, try child(self.a, path, THEN));
                    try self.collect(iff.@"else", try child(self.a, path, ELSE));
                },
                .loop => |lp| try self.collect(lp.body, try child(self.a, path, BODY)),
                else => {},
            }
        }
    }

    fn lookup(self: *const View, name: ?[]const u8, from: Path) ?Def {
        const n = name orelse return null;
        if (self.poisoned.contains(n)) return null;
        const d = self.defs.get(n) orelse return null;
        return if (visible(d.path, from)) d else null;
    }

    fn resolve(self: *const View, start: ?[]const u8, from_in: Path) ?[]const u8 {
        var name = start;
        var from = from_in;
        var hops: usize = 0;
        while (hops <= self.defs.count()) : (hops += 1) {
            const d = self.lookup(name, from) orelse return null;
            switch (d.value) {
                .load_param => |lp| {
                    if (self.shp.contains(lp.name)) return lp.name;
                    return if (self.implicit and eql(lp.name, "txPreimage")) lp.name else null;
                },
                .load_prop => |lp| return if (self.implicit and eql(lp.name, "txPreimage")) lp.name else null,
                else => {
                    name = refTarget(d.value) orelse return null;
                    from = d.path;
                },
            }
        }
        return null; // an alias cycle
    }

    fn truthOf(self: *const View, name: []const u8, from: Path, depth: usize) Allocator.Error!Checks {
        const d = self.lookup(name, from) orelse return .{};
        return self.truthValue(d.value, d.path, depth);
    }

    fn truthValue(self: *const View, v: types.ANFValue, path: Path, depth: usize) Allocator.Error!Checks {
        var out: Checks = .{};
        if (depth > self.defs.count()) return out;
        switch (v) {
            .check_preimage => |cp| if (self.resolve(cp.preimage, path)) |o| try out.set.put(self.a, o, {}),
            .load_const => |lc| {
                if (lc.value == .boolean and !lc.value.boolean) return .{ .all = true };
                if (refTarget(v)) |next| return self.truthOf(next, path, depth + 1);
            },
            .@"if" => |iff| {
                if (iff.results.len > 0 or iff.then.len == 0 or iff.@"else".len == 0) return out;
                const nt = iff.then.len - 1;
                const ne = iff.@"else".len - 1;
                const c = try self.truthOf(iff.cond, path, depth + 1);
                const t = try self.truthValue(iff.then[nt].value, try child(self.a, try child(self.a, path, THEN), @intCast(nt)), depth + 1);
                const e = try self.truthValue(iff.@"else"[ne].value, try child(self.a, try child(self.a, path, ELSE), @intCast(ne)), depth + 1);
                // (c ∪ t) ∩ e, with `all` as the top element.
                var ct: Checks = .{ .all = c.all or t.all };
                if (!ct.all) {
                    var it = c.set.keyIterator();
                    while (it.next()) |k| try ct.set.put(self.a, k.*, {});
                    var it2 = t.set.keyIterator();
                    while (it2.next()) |k| try ct.set.put(self.a, k.*, {});
                }
                if (ct.all) return e;
                if (e.all) return ct;
                var it = ct.set.keyIterator();
                while (it.next()) |k| if (e.set.contains(k.*)) try out.set.put(self.a, k.*, {});
            },
            else => {},
        }
        return out;
    }
};

const Rules = struct {
    a: Allocator,
    methods: []const types.ANFMethod,
    implicit_tx: bool,
    /// Keyed by method index, never by name.
    memo: std.AutoHashMapUnmanaged(usize, StringSet) = .empty,

    /// The method a `method_call` inlines, resolved exactly as stack lowering
    /// does (passes/stack_lower.zig findPrivateMethod: the FIRST non-public,
    /// non-constructor method of that name). The loader refuses duplicate
    /// names first; this never relies on that alone.
    fn findPrivate(self: *const Rules, name: []const u8) ?usize {
        for (self.methods, 0..) |m, i| {
            if (m.is_public or eql(m.name, "constructor")) continue;
            if (eql(m.name, name)) return i;
        }
        return null;
    }

    fn mustChecked(self: *Rules, idx: usize, stack: *std.AutoHashMapUnmanaged(usize, void)) Allocator.Error!StringSet {
        if (self.memo.get(idx)) |r| return r;
        if (stack.contains(idx)) return .empty;
        try stack.put(self.a, idx, {});
        defer _ = stack.remove(idx);
        const m = self.methods[idx];
        const mv = try View.init(self.a, m, self.implicit_tx);
        const result = try self.walk(&mv, m.body, &.{}, .empty, stack);
        try self.memo.put(self.a, idx, result);
        return result;
    }

    fn walk(self: *Rules, mv: *const View, bs: []const types.ANFBinding, at: Path, done_in: StringSet, stack: *std.AutoHashMapUnmanaged(usize, void)) Allocator.Error!StringSet {
        var done = try done_in.clone(self.a);
        for (bs, 0..) |b, bi| {
            const path = try child(self.a, at, @intCast(bi));
            switch (b.value) {
                .assert => |as| {
                    const c = try mv.truthOf(as.value, path, 0);
                    if (!c.all) {
                        var it = c.set.keyIterator();
                        while (it.next()) |k| try done.put(self.a, k.*, {});
                    }
                },
                .@"if" => |iff| {
                    const t = try self.walk(mv, iff.then, try child(self.a, path, THEN), done, stack);
                    const e = try self.walk(mv, iff.@"else", try child(self.a, path, ELSE), done, stack);
                    var next: StringSet = .empty;
                    var it = t.keyIterator();
                    while (it.next()) |k| if (e.contains(k.*)) try next.put(self.a, k.*, {});
                    done = next;
                },
                .method_call => |mc| {
                    const ti = self.findPrivate(mc.method) orelse continue;
                    const target = self.methods[ti];
                    const checked = try self.mustChecked(ti, stack);
                    for (target.params, 0..) |p, i| {
                        if (!checked.contains(p.name) or i >= mc.args.len) continue;
                        if (mv.resolve(mc.args[i], path)) |o| try done.put(self.a, o, {});
                    }
                },
                else => {},
            }
        }
        return done;
    }

    /// The first D14 violation in `bs`, recorded in the diagnostic channel.
    fn visit(self: *Rules, mv: *const View, bs: []const types.ANFBinding, at: Path) Allocator.Error!bool {
        for (bs, 0..) |b, bi| {
            const path = try child(self.a, at, @intCast(bi));
            switch (b.value) {
                .call => |c| if (isExtractor(c.func)) {
                    const arg: ?[]const u8 = if (c.args.len > 0) c.args[0] else null;
                    if (mv.resolve(arg, path) == null) {
                        required_fields.setDiag("IR validation: " ++ typecheck.UNCHECKED_PREIMAGE_ARG_FMT, .{c.func});
                        return true;
                    }
                },
                .method_call => |mc| {
                    const target = self.methods[self.findPrivate(mc.method) orelse continue];
                    for (target.params, 0..) |p, i| {
                        if (!eql(p.type_name, SHP)) continue;
                        const arg: ?[]const u8 = if (i < mc.args.len) mc.args[i] else null;
                        if (mv.resolve(arg, path) == null) {
                            required_fields.setDiag("IR validation: " ++ typecheck.UNCHECKED_PREIMAGE_ARG_FMT, .{target.name});
                            return true;
                        }
                    }
                },
                .@"if" => |iff| if ((try self.visit(mv, iff.then, try child(self.a, path, THEN))) or
                    (try self.visit(mv, iff.@"else", try child(self.a, path, ELSE)))) return true,
                .loop => |lp| if (try self.visit(mv, lp.body, try child(self.a, path, BODY))) return true,
                else => {},
            }
        }
        return false;
    }
};

/// Refuses the first D9 / GK-GAP-010 / D14 violation (error.PreimageRuleViolation,
/// message in the required_fields diagnostic channel).
pub fn check(allocator: Allocator, properties: []const types.ANFProperty, methods: []const types.ANFMethod) Error!void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (properties) |p| {
        if (eql(p.type_name, SHP)) {
            required_fields.setDiag("IR validation: " ++ validate.PREIMAGE_PROPERTY_FMT, .{p.name});
            return error.PreimageRuleViolation;
        }
    }
    var publics: usize = 0;
    var all_have_tx = true;
    for (methods) |m| {
        if (!m.is_public or eql(m.name, "constructor")) continue;
        publics += 1;
        var has = false;
        for (m.params) |p| has = has or (eql(p.name, "txPreimage") and eql(p.type_name, SHP));
        all_have_tx = all_have_tx and has;
    }
    var declared = false;
    for (properties) |p| declared = declared or eql(p.name, "txPreimage");
    var rules: Rules = .{ .a = a, .methods = methods, .implicit_tx = publics > 0 and all_have_tx and !declared };
    for (methods, 0..) |m, mi| {
        if (eql(m.name, "constructor")) continue;
        const mv = try View.init(a, m, rules.implicit_tx);
        if (try rules.visit(&mv, m.body, &.{})) return error.PreimageRuleViolation;
        if (!m.is_public) continue;
        var stack: std.AutoHashMapUnmanaged(usize, void) = .empty;
        const done = try rules.mustChecked(mi, &stack);
        for (m.params) |p| {
            if (eql(p.type_name, SHP) and !done.contains(p.name)) {
                required_fields.setDiag("IR validation: " ++ typecheck.PREIMAGE_NOT_CHECKED_FMT, .{ m.name, p.name });
                return error.PreimageRuleViolation;
            }
        }
    }
}

/// GK-BUG-015's shared text on the IR path: a repeated method name, refused
/// before anything looks a method up by name (the source validator refuses
/// it; --ir did not, so two bodies could share a name).
pub fn checkUniqueMethodNames(methods: []const types.ANFMethod) error{PreimageRuleViolation}!void {
    for (methods, 0..) |m, i| {
        for (methods[0..i]) |prev| {
            if (eql(prev.name, m.name)) {
                required_fields.setDiag("IR validation: method '{s}' is already declared in this contract and cannot be re-declared", .{m.name});
                return error.PreimageRuleViolation;
            }
        }
    }
}
