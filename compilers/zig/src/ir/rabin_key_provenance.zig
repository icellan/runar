//! N-205 (b) — F-286's verifyRabinSig key-provenance rule, and N-205 (a)'s
//! rule for writes to a key property, re-asserted on `--ir` input. Port of
//! `packages/runar-compiler/src/ir/rabin-key-provenance.ts`: same rule, same
//! order, same words (`conformance/negatives/ir-rabin-key-provenance.test.ts`).
//!
//! A ref is trusted when EVERY binding of that name in the method is:
//!   - `load_prop`;
//!   - `load_const` holding an integer;
//!   - `load_const "@ref:<x>"` with `<x>` trusted (a local alias);
//!   - `load_param` of a PRIVATE method whose every `method_call` site (at
//!     least one) passes a trusted ref in that position (least fixed point);
//!   - an `if` with no `results`, both arms non-empty and each arm's LAST
//!     binding trusted (the phi ANF lowering emits for an if/else write).
//! Bindings are resolved over the whole method, flattened in pre-order (a
//! binding, then its `then`, `else`, `body`). KEY properties are the
//! `load_prop` names a verifyRabinSig 4th argument can come from, closed under
//! "a trusted value written into a key property comes from it". Writes are,
//! outside the constructor only, `update_prop` and `add_output.stateValues[i]`
//! (the i-th non-readonly property). Method by method, the first refusal wins:
//!   1. every verifyRabinSig call whose 4th argument is untrusted;
//!   2. every write of a MUTABLE key property whose value is untrusted.
//! The message travels on required_fields' thread-local diagnostic channel.

const std = @import("std");
const types = @import("types.zig");
const required_fields = @import("required_fields.zig");
const validate = @import("../passes/validate.zig");

pub const Error = error{ RabinKeyProvenance, OutOfMemory };

const Allocator = std.mem.Allocator;
const ValueList = std.ArrayListUnmanaged(types.ANFValue);
const NameMap = std.StringHashMapUnmanaged(ValueList);
const StringSet = std.StringHashMapUnmanaged(void);

const CallSite = struct { args: []const []const u8, method: usize };
const Write = struct { prop: []const u8, value: []const u8, method: usize };

const Ctx = struct {
    a: Allocator,
    methods: []const types.ANFMethod,
    flat: []std.ArrayListUnmanaged(types.ANFBinding),
    by_name: []NameMap,
    /// Private method name -> index into `methods`.
    privates: std.StringHashMapUnmanaged(usize) = .empty,
    sites: std.StringHashMapUnmanaged(std.ArrayListUnmanaged(CallSite)) = .empty,
    trusted_params: std.StringHashMapUnmanaged([]bool) = .empty,

    fn isPrivate(self: *const Ctx, m: usize) bool {
        const method = self.methods[m];
        return !method.is_public and !std.mem.eql(u8, method.name, "constructor");
    }

    fn paramIndex(self: *const Ctx, m: usize, name: []const u8) ?usize {
        for (self.methods[m].params, 0..) |p, i| {
            if (std.mem.eql(u8, p.name, name)) return i;
        }
        return null;
    }

    fn isTrusted(self: *Ctx, ref: []const u8, m: usize, visiting: *StringSet) Allocator.Error!bool {
        const values = self.by_name[m].get(ref) orelse return false;
        if (visiting.get(ref) != null) return false;
        try visiting.put(self.a, ref, {});
        defer _ = visiting.remove(ref);
        for (values.items) |v| {
            const ok: bool = switch (v) {
                .load_prop => true,
                .load_const => |c| switch (c.value) {
                    .integer, .big_integer => true,
                    .string => |s| std.mem.startsWith(u8, s, "@ref:") and try self.isTrusted(s[5..], m, visiting),
                    .boolean => false,
                },
                .load_param => |p| blk: {
                    if (!self.isPrivate(m)) break :blk false;
                    const idx = self.paramIndex(m, p.name) orelse break :blk false;
                    const flags = self.trusted_params.get(self.methods[m].name) orelse break :blk false;
                    break :blk idx < flags.len and flags[idx];
                },
                .@"if" => |iff| blk: {
                    if (iff.results.len > 0) break :blk false;
                    if (iff.then.len == 0 or iff.@"else".len == 0) break :blk false;
                    break :blk (try self.isTrusted(iff.then[iff.then.len - 1].name, m, visiting)) and
                        (try self.isTrusted(iff.@"else"[iff.@"else".len - 1].name, m, visiting));
                },
                else => false,
            };
            if (!ok) return false;
        }
        return true;
    }

    fn trusted(self: *Ctx, ref: []const u8, m: usize) Allocator.Error!bool {
        var visiting: StringSet = .empty;
        return self.isTrusted(ref, m, &visiting);
    }

    fn sourcesOf(self: *Ctx, ref: []const u8, m: usize, out: *StringSet, visiting: *StringSet) Allocator.Error!void {
        const key = try std.fmt.allocPrint(self.a, "{d}\x00{s}", .{ m, ref });
        if (visiting.get(key) != null) return;
        try visiting.put(self.a, key, {});
        const values = self.by_name[m].get(ref) orelse return;
        for (values.items) |v| {
            switch (v) {
                .load_prop => |p| try out.put(self.a, p.name, {}),
                .load_const => |c| switch (c.value) {
                    .string => |s| if (std.mem.startsWith(u8, s, "@ref:")) try self.sourcesOf(s[5..], m, out, visiting),
                    else => {},
                },
                .@"if" => |iff| {
                    if (iff.then.len > 0) try self.sourcesOf(iff.then[iff.then.len - 1].name, m, out, visiting);
                    if (iff.@"else".len > 0) try self.sourcesOf(iff.@"else"[iff.@"else".len - 1].name, m, out, visiting);
                },
                .load_param => |p| {
                    if (!self.isPrivate(m)) continue;
                    const idx = self.paramIndex(m, p.name) orelse continue;
                    const list = self.sites.get(self.methods[m].name) orelse continue;
                    for (list.items) |site| {
                        if (idx < site.args.len) try self.sourcesOf(site.args[idx], site.method, out, visiting);
                    }
                },
                else => {},
            }
        }
    }
};

fn flatten(a: Allocator, bindings: []const types.ANFBinding, out: *std.ArrayListUnmanaged(types.ANFBinding)) Allocator.Error!void {
    for (bindings) |b| {
        try out.append(a, b);
        switch (b.value) {
            .@"if" => |iff| {
                try flatten(a, iff.then, out);
                try flatten(a, iff.@"else", out);
            },
            .loop => |l| try flatten(a, l.body, out),
            else => {},
        }
    }
}

fn isRabinCall(v: types.ANFValue) ?[]const u8 {
    if (v != .call) return null;
    const c = v.call;
    if (!std.mem.eql(u8, c.func, "verifyRabinSig") or c.args.len < 4) return null;
    return c.args[3];
}

pub fn check(allocator: Allocator, properties: []const types.ANFProperty, methods: []const types.ANFMethod) Error!void {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var ctx = Ctx{
        .a = a,
        .methods = methods,
        .flat = try a.alloc(std.ArrayListUnmanaged(types.ANFBinding), methods.len),
        .by_name = try a.alloc(NameMap, methods.len),
    };
    for (methods, 0..) |m, i| {
        ctx.flat[i] = .empty;
        try flatten(a, m.body, &ctx.flat[i]);
        ctx.by_name[i] = .empty;
        for (ctx.flat[i].items) |b| {
            const gop = try ctx.by_name[i].getOrPut(a, b.name);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.append(a, b.value);
        }
    }

    for (methods, 0..) |m, i| {
        if (!ctx.isPrivate(i)) continue;
        try ctx.privates.put(a, m.name, i);
        try ctx.sites.put(a, m.name, .empty);
        const flags = try a.alloc(bool, m.params.len);
        @memset(flags, false);
        try ctx.trusted_params.put(a, m.name, flags);
    }
    for (methods, 0..) |_, i| {
        for (ctx.flat[i].items) |b| {
            if (b.value != .method_call) continue;
            const mc = b.value.method_call;
            if (ctx.sites.getPtr(mc.method)) |list| try list.append(a, .{ .args = mc.args, .method = i });
        }
    }

    // Least fixed point: monotone, so it terminates.
    var changed = true;
    while (changed) {
        changed = false;
        var it = ctx.privates.iterator();
        while (it.next()) |entry| {
            const list = ctx.sites.get(entry.key_ptr.*).?;
            if (list.items.len == 0) continue;
            const flags = ctx.trusted_params.get(entry.key_ptr.*).?;
            for (flags, 0..) |*flag, p| {
                if (flag.*) continue;
                var all = true;
                for (list.items) |site| {
                    if (p >= site.args.len or !(try ctx.trusted(site.args[p], site.method))) {
                        all = false;
                        break;
                    }
                }
                if (all) {
                    flag.* = true;
                    changed = true;
                }
            }
        }
    }

    var key_props: StringSet = .empty;
    for (methods, 0..) |_, i| {
        for (ctx.flat[i].items) |b| {
            if (isRabinCall(b.value)) |ref| {
                var visiting: StringSet = .empty;
                try ctx.sourcesOf(ref, i, &key_props, &visiting);
            }
        }
    }

    var mutable_props: std.ArrayListUnmanaged([]const u8) = .empty;
    for (properties) |p| {
        if (!p.readonly) try mutable_props.append(a, p.name);
    }
    var writes: std.ArrayListUnmanaged(Write) = .empty;
    for (methods, 0..) |m, i| {
        if (std.mem.eql(u8, m.name, "constructor")) continue;
        for (ctx.flat[i].items) |b| {
            switch (b.value) {
                .update_prop => |up| try writes.append(a, .{ .prop = up.name, .value = up.value, .method = i }),
                .add_output => |ao| for (ao.state_values, 0..) |value, k| {
                    if (k < mutable_props.items.len) try writes.append(a, .{ .prop = mutable_props.items[k], .value = value, .method = i });
                },
                else => {},
            }
        }
    }

    var grew = true;
    while (grew) {
        const before = key_props.count();
        for (writes.items) |w| {
            if (key_props.get(w.prop) == null) continue;
            if (!(try ctx.trusted(w.value, w.method))) continue;
            var visiting: StringSet = .empty;
            try ctx.sourcesOf(w.value, w.method, &key_props, &visiting);
        }
        grew = key_props.count() != before;
    }

    for (methods, 0..) |m, i| {
        for (ctx.flat[i].items) |b| {
            if (isRabinCall(b.value)) |ref| {
                if (!(try ctx.trusted(ref, i))) {
                    required_fields.setDiag("IR validation: method '{s}': " ++ validate.RABIN_PUBKEY_PROVENANCE_MESSAGE, .{m.name});
                    return error.RabinKeyProvenance;
                }
            }
        }
        for (writes.items) |w| {
            if (w.method != i or key_props.get(w.prop) == null) continue;
            var is_mutable = false;
            for (mutable_props.items) |mp| {
                if (std.mem.eql(u8, mp, w.prop)) is_mutable = true;
            }
            if (!is_mutable) continue;
            if (!(try ctx.trusted(w.value, i))) {
                required_fields.setDiag("IR validation: method '{s}': " ++ validate.RABIN_KEY_WRITE_FMT, .{ m.name, w.prop });
                return error.RabinKeyProvenance;
            }
        }
    }
}
