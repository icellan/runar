//! N-101: the scaffolding StatefulSmartContract lowering injects, re-derived
//! for `compile-ir` input.
//!
//! `compile-ir` skips the frontend, so a program labelled (or, per N-087,
//! inferred) StatefulSmartContract could omit or fake the scaffolding ANF
//! lowering injects into every public method and compile to an
//! anyone-can-spend script: F-107's attack body compiled to `76767b8777`. For
//! each public method this re-derives what the frontend would inject (the
//! TypeScript reference is packages/runar-compiler/src/passes/stateful-scaffold.ts):
//!
//!   prologue      assert(checkPreimage(txPreimage)), the sighash-type assert
//!                 and, when the contract has mutable properties,
//!                 deserialize_state
//!   user code     free
//!   continuation  when the method mutates state or declares outputs: the
//!                 _newAmount floor (single-output form), the change output
//!                 and the hashOutputs comparison over every output in order
//!
//! and refuses the program, with the diagnostics all seven tiers share
//! (conformance/negatives/ir-stateful-scaffold-cases.json, message in
//! required_fields.lastDiagnostic()), when (1) the auto-injected parameters,
//! (2) the prologue or (3) the continuation differ, or (4) a scaffolding
//! binding, or an output the continuation commits to, is bound more than once
//! or shares a property or parameter name.

const std = @import("std");
const types = @import("types.zig");
const required_fields = @import("required_fields.zig");

pub const Error = error{ StatefulScaffoldMismatch, OutOfMemory };

const sighash_default: i32 = 0x41;

/// N-038: whether a method's continuation commits (and its ABI takes) the
/// change output. Under a SIGHASH_SINGLE base BIP-143 commits hashOutputs to
/// hash256(output[inputIndex]) only, so the change output is not part of the
/// committed set and the method takes no `_changePKH` / `_changeAmount`.
pub fn includesChange(needs_change: bool, sighash_type: ?i32) bool {
    return needs_change and ((sighash_type orelse sighash_default) & 0x1f) != 0x03;
}

/// Whether a public stateful method produces a continuation (mutates state or
/// declares outputs, at any depth and through private method_calls). The
/// artifact's `isTerminal` is its negation.
pub fn hasContinuation(alloc: std.mem.Allocator, methods: []const types.ANFMethod, bindings: []const types.ANFBinding) Error!bool {
    var fx: Effects = .{};
    var visited: std.ArrayListUnmanaged([]const u8) = .empty;
    defer visited.deinit(alloc);
    try walkEffects(alloc, methods, bindings, &fx, &visited);
    return fx.mutates or fx.state or fx.data;
}

const Ref = union(enum) { local: usize, outside: []const u8 };

const Kind = enum { load_param, load_const_int, load_const_str, check_preimage, assert, call, bin_op, deserialize_state, get_state_script, @"if" };

/// One expected scaffolding binding. Refs to other expected bindings are
/// indices into the builder's arena; refs to the user's output bindings are
/// their names.
const Exp = struct {
    kind: Kind,
    text: []const u8 = "",
    int: i128 = 0,
    refs: [3]Ref = undefined,
    nrefs: usize = 0,
    flag: i32 = sighash_default,
    bytes_result: bool = false,
    then_id: usize = 0,
    else_id: usize = 0,
};

const Builder = struct {
    alloc: std.mem.Allocator,
    arena: std.ArrayListUnmanaged(Exp) = .empty,

    fn add(self: *Builder, e: Exp) Error!usize {
        try self.arena.append(self.alloc, e);
        return self.arena.items.len - 1;
    }

    fn emit(self: *Builder, seq: *std.ArrayListUnmanaged(usize), e: Exp) Error!Ref {
        const id = try self.add(e);
        try seq.append(self.alloc, id);
        return .{ .local = id };
    }
};

fn refs1(a: Ref) [3]Ref {
    return .{ a, undefined, undefined };
}
fn refs2(a: Ref, b: Ref) [3]Ref {
    return .{ a, b, undefined };
}

fn param(name: []const u8) Exp {
    return .{ .kind = .load_param, .text = name };
}
fn call1(func: []const u8, a: Ref) Exp {
    return .{ .kind = .call, .text = func, .refs = refs1(a), .nrefs = 1 };
}
fn call2(func: []const u8, a: Ref, b: Ref) Exp {
    return .{ .kind = .call, .text = func, .refs = refs2(a, b), .nrefs = 2 };
}
fn binop(op: []const u8, l: Ref, r: Ref, bytes: bool) Exp {
    return .{ .kind = .bin_op, .text = op, .refs = refs2(l, r), .nrefs = 2, .bytes_result = bytes };
}
fn assertOf(r: Ref) Exp {
    return .{ .kind = .assert, .refs = refs1(r), .nrefs = 1 };
}

fn prologue(b: *Builder, seq: *std.ArrayListUnmanaged(usize), sighash_mode: i32, has_mutable_state: bool) Error!void {
    const pre = try b.emit(seq, param("txPreimage"));
    const checked_pre = try b.emit(seq, .{ .kind = .check_preimage, .refs = refs1(pre), .nrefs = 1, .flag = sighash_mode });
    _ = try b.emit(seq, assertOf(checked_pre));
    const p2 = try b.emit(seq, param("txPreimage"));
    const typ = try b.emit(seq, call1("extractSigHashType", p2));
    const want = try b.emit(seq, .{ .kind = .load_const_int, .int = sighash_mode });
    const ok = try b.emit(seq, binop("===", typ, want, false));
    _ = try b.emit(seq, assertOf(ok));
    if (has_mutable_state) {
        const p3 = try b.emit(seq, param("txPreimage"));
        _ = try b.emit(seq, .{ .kind = .deserialize_state, .refs = refs1(p3), .nrefs = 1 });
    }
}

fn continuation(b: *Builder, seq: *std.ArrayListUnmanaged(usize), needs_change: bool, includes_change: bool, state_out: []const *const types.ANFBinding, data_out: []const *const types.ANFBinding) Error!void {
    if (!needs_change) return;
    if (state_out.len == 0) {
        const p = try b.emit(seq, param("txPreimage"));
        const amount = try b.emit(seq, call1("extractAmount", p));
        const na = try b.emit(seq, param("_newAmount"));
        const ok = try b.emit(seq, binop(">=", na, amount, false));
        _ = try b.emit(seq, assertOf(ok));
    }
    // N-038: no change segment under a SIGHASH_SINGLE base.
    var change: ?Ref = null;
    if (includes_change) {
        const pkh = try b.emit(seq, param("_changePKH"));
        const amt = try b.emit(seq, param("_changeAmount"));
        const zero = try b.emit(seq, .{ .kind = .load_const_int, .int = 0 });
        const non_zero = try b.emit(seq, binop("!==", amt, zero, false));
        const then_id = try b.add(call2("buildChangeOutput", pkh, amt));
        const else_id = try b.add(.{ .kind = .load_const_str, .text = "" });
        change = try b.emit(seq, .{ .kind = .@"if", .refs = refs1(non_zero), .nrefs = 1, .then_id = then_id, .else_id = else_id });
    }

    var acc: Ref = undefined;
    if (state_out.len > 0) {
        acc = .{ .outside = state_out[0].name };
        for (state_out[1..]) |o| acc = try b.emit(seq, call2("cat", acc, .{ .outside = o.name }));
    } else {
        const script = try b.emit(seq, .{ .kind = .get_state_script });
        const p = try b.emit(seq, param("txPreimage"));
        const na = try b.emit(seq, param("_newAmount"));
        acc = try b.emit(seq, .{ .kind = .call, .text = "computeStateOutput", .refs = .{ p, script, na }, .nrefs = 3 });
    }
    for (data_out) |o| acc = try b.emit(seq, call2("cat", acc, .{ .outside = o.name }));
    if (change) |c| acc = try b.emit(seq, call2("cat", acc, c));
    const hash = try b.emit(seq, call1("hash256", acc));
    const p = try b.emit(seq, param("txPreimage"));
    const out_hash = try b.emit(seq, call1("extractOutputHash", p));
    const eq = try b.emit(seq, binop("===", hash, out_hash, true));
    _ = try b.emit(seq, assertOf(eq));
}

fn isStateOutput(v: types.ANFValue) bool {
    return v == .add_output or v == .add_raw_output;
}
fn isDataOutput(v: types.ANFValue) bool {
    return v == .add_data_output;
}

fn contains(bindings: []const types.ANFBinding, comptime pred: fn (types.ANFValue) bool) bool {
    for (bindings) |b| {
        if (pred(b.value)) return true;
        switch (b.value) {
            .@"if" => |v| if (contains(v.then, pred) or contains(v.@"else", pred)) return true,
            .loop => |v| if (contains(v.body, pred)) return true,
            else => {},
        }
    }
    return false;
}

const Effects = struct { mutates: bool = false, state: bool = false, data: bool = false };

/// The frontend's side-effect summary, read off the IR (update_prop is a state
/// mutation, add_output / add_raw_output a state output, add_data_output a
/// data output) at any depth and through method_calls to private methods.
fn walkEffects(alloc: std.mem.Allocator, methods: []const types.ANFMethod, bindings: []const types.ANFBinding, fx: *Effects, visited: *std.ArrayListUnmanaged([]const u8)) Error!void {
    for (bindings) |b| {
        switch (b.value) {
            .update_prop => fx.mutates = true,
            .add_output, .add_raw_output => fx.state = true,
            .add_data_output => fx.data = true,
            .method_call => |mc| {
                for (methods) |t| {
                    if (t.is_public or std.mem.eql(u8, t.name, "constructor") or !std.mem.eql(u8, t.name, mc.method)) continue;
                    const seen = for (visited.items) |n| {
                        if (std.mem.eql(u8, n, t.name)) break true;
                    } else false;
                    if (seen) break;
                    try visited.append(alloc, t.name);
                    try walkEffects(alloc, methods, t.body, fx, visited);
                    break;
                }
            },
            .@"if" => |v| {
                try walkEffects(alloc, methods, v.then, fx, visited);
                try walkEffects(alloc, methods, v.@"else", fx, visited);
            },
            .loop => |v| try walkEffects(alloc, methods, v.body, fx, visited),
            else => {},
        }
    }
}

fn hasResultType(rt: ?[]const u8) bool {
    return if (rt) |s| s.len > 0 else false;
}

const Matcher = struct {
    b: *const Builder,
    names: []?[]const u8,

    fn ref(self: *const Matcher, r: Ref, actual: []const u8) bool {
        return switch (r) {
            .local => |id| if (self.names[id]) |n| std.mem.eql(u8, n, actual) else false,
            .outside => |n| std.mem.eql(u8, n, actual),
        };
    }

    fn binding(self: *Matcher, id: usize, act: *const types.ANFBinding) bool {
        const e = self.b.arena.items[id];
        const ok = switch (e.kind) {
            .load_param => act.value == .load_param and std.mem.eql(u8, act.value.load_param.name, e.text),
            .load_const_int => act.value == .load_const and act.value.load_const.value == .integer and act.value.load_const.value.integer == e.int,
            .load_const_str => act.value == .load_const and act.value.load_const.value == .string and std.mem.eql(u8, act.value.load_const.value.string, e.text),
            .check_preimage => act.value == .check_preimage and self.ref(e.refs[0], act.value.check_preimage.preimage) and
                (if (act.value.check_preimage.sighash_flag == 0) sighash_default else act.value.check_preimage.sighash_flag) == e.flag,
            .assert => act.value == .assert and self.ref(e.refs[0], act.value.assert.value),
            .call => blk: {
                if (act.value != .call) break :blk false;
                const c = act.value.call;
                if (!std.mem.eql(u8, c.func, e.text) or c.args.len != e.nrefs) break :blk false;
                for (c.args, 0..) |a, i| {
                    if (!self.ref(e.refs[i], a)) break :blk false;
                }
                break :blk true;
            },
            .bin_op => act.value == .bin_op and std.mem.eql(u8, act.value.bin_op.op, e.text) and
                self.ref(e.refs[0], act.value.bin_op.left) and self.ref(e.refs[1], act.value.bin_op.right) and
                (if (e.bytes_result) hasResultType(act.value.bin_op.result_type) and std.mem.eql(u8, act.value.bin_op.result_type.?, "bytes") else !hasResultType(act.value.bin_op.result_type)),
            .deserialize_state => act.value == .deserialize_state and self.ref(e.refs[0], act.value.deserialize_state.preimage),
            .get_state_script => act.value == .get_state_script,
            .@"if" => blk: {
                if (act.value != .@"if") break :blk false;
                const v = act.value.@"if";
                break :blk self.ref(e.refs[0], v.cond) and v.results.len == 0 and
                    v.then.len == 1 and self.binding(e.then_id, &v.then[0]) and
                    v.@"else".len == 1 and self.binding(e.else_id, &v.@"else"[0]);
            },
        };
        if (!ok) return false;
        for (self.names) |n| {
            if (n) |name| {
                if (std.mem.eql(u8, name, act.name)) return false;
            }
        }
        self.names[id] = act.name;
        return true;
    }
};

fn describe(e: Exp) []const u8 {
    return switch (e.kind) {
        .load_param, .call, .bin_op => blk: {
            const prefix = switch (e.kind) {
                .load_param => "load_param",
                .call => "call",
                else => "bin_op",
            };
            break :blk std.fmt.bufPrint(&describe_buf, "{s} {s}", .{ prefix, e.text }) catch "";
        },
        .load_const_int => std.fmt.bufPrint(&describe_buf, "load_const {d}", .{e.int}) catch "",
        .load_const_str => std.fmt.bufPrint(&describe_buf, "load_const \"{s}\"", .{e.text}) catch "",
        .check_preimage => "check_preimage",
        .assert => "assert",
        .deserialize_state => "deserialize_state",
        .get_state_script => "get_state_script",
        .@"if" => "if",
    };
}
var describe_buf: [128]u8 = undefined;

fn countName(bindings: []const types.ANFBinding, name: []const u8) usize {
    var n: usize = 0;
    for (bindings) |b| {
        if (std.mem.eql(u8, b.name, name)) n += 1;
        switch (b.value) {
            .@"if" => |v| {
                for (v.results) |r| {
                    if (std.mem.eql(u8, r, name)) n += 1;
                }
                n += countName(v.then, name) + countName(v.@"else", name);
            },
            .loop => |v| {
                if (std.mem.eql(u8, v.iter_var, name)) n += 1;
                n += countName(v.body, name);
            },
            else => {},
        }
    }
    return n;
}

fn countInside(b: *const types.ANFBinding, name: []const u8) usize {
    return switch (b.value) {
        .@"if" => |v| countName(v.then, name) + countName(v.@"else", name),
        .loop => |v| countName(v.body, name),
        else => 0,
    };
}

fn appendPreorder(alloc: std.mem.Allocator, out: *std.ArrayListUnmanaged(*const types.ANFBinding), bindings: []const types.ANFBinding) Error!void {
    for (bindings) |*b| {
        try out.append(alloc, b);
        switch (b.value) {
            .@"if" => |v| {
                try appendPreorder(alloc, out, v.then);
                try appendPreorder(alloc, out, v.@"else");
            },
            .loop => |v| try appendPreorder(alloc, out, v.body),
            else => {},
        }
    }
}

fn mismatch(method: []const u8, section: []const u8, index: usize, e: Exp) Error {
    required_fields.setDiag(
        "IR validation: stateful method '{s}' does not carry the scaffolding StatefulSmartContract lowering injects: {s} binding {d} must be {s}",
        .{ method, section, index, describe(e) },
    );
    return Error.StatefulScaffoldMismatch;
}

pub fn check(alloc: std.mem.Allocator, properties: []const types.ANFProperty, methods: []const types.ANFMethod) Error!void {
    var has_mutable = false;
    for (properties) |p| {
        if (!p.readonly) has_mutable = true;
    }
    for (methods) |m| {
        if (!m.is_public or std.mem.eql(u8, m.name, "constructor")) continue;

        var fx: Effects = .{};
        var visited: std.ArrayListUnmanaged([]const u8) = .empty;
        defer visited.deinit(alloc);
        try walkEffects(alloc, methods, m.body, &fx, &visited);
        const needs_change = fx.mutates or fx.state or fx.data;
        const needs_new_amount = (fx.mutates or fx.data) and !fx.state;
        const includes_change = includesChange(needs_change, m.sighash_type);

        // (1) the parameters, contiguous and once each.
        var req_names: [4][]const u8 = undefined;
        var req_types: [4][]const u8 = undefined;
        var nreq: usize = 0;
        if (includes_change) {
            req_names[0] = "_changePKH";
            req_types[0] = "Ripemd160";
            req_names[1] = "_changeAmount";
            req_types[1] = "bigint";
            nreq = 2;
        }
        if (needs_new_amount) {
            req_names[nreq] = "_newAmount";
            req_types[nreq] = "bigint";
            nreq += 1;
        }
        req_names[nreq] = "txPreimage";
        req_types[nreq] = "SigHashPreimage";
        nreq += 1;
        const start: ?usize = for (m.params, 0..) |p, i| {
            if (std.mem.eql(u8, p.name, req_names[0])) break i;
        } else null;
        var params_ok = start != null;
        if (start) |s| {
            for (0..nreq) |i| {
                if (s + i >= m.params.len or !std.mem.eql(u8, m.params[s + i].name, req_names[i]) or !std.mem.eql(u8, m.params[s + i].type_name, req_types[i])) params_ok = false;
                var count: usize = 0;
                for (m.params) |p| {
                    if (std.mem.eql(u8, p.name, req_names[i])) count += 1;
                }
                if (count != 1) params_ok = false;
            }
        }
        if (!params_ok) {
            var list_buf: [160]u8 = undefined;
            var w: usize = 0;
            for (0..nreq) |i| {
                const piece = std.fmt.bufPrint(list_buf[w..], "{s}{s}: {s}", .{ if (i == 0) "" else ", ", req_names[i], req_types[i] }) catch "";
                w += piece.len;
            }
            required_fields.setDiag(
                "IR validation: stateful method '{s}' must declare the auto-injected parameters ({s}) contiguously and once each, as StatefulSmartContract lowering does",
                .{ m.name, list_buf[0..w] },
            );
            return Error.StatefulScaffoldMismatch;
        }

        var builder: Builder = .{ .alloc = alloc };
        defer builder.arena.deinit(alloc);
        var pro: std.ArrayListUnmanaged(usize) = .empty;
        defer pro.deinit(alloc);
        var tail: std.ArrayListUnmanaged(usize) = .empty;
        defer tail.deinit(alloc);

        // (2) the prologue.
        try prologue(&builder, &pro, m.sighash_type orelse sighash_default, has_mutable);
        const pro_len = pro.items.len;

        // (3) the continuation's outputs, read off the method's own top-level
        // bindings after the prologue (an `if` counts once, as a state output
        // when either arm holds one, else as a data output), in order.
        const rest: []const types.ANFBinding = if (m.body.len >= pro_len) m.body[pro_len..] else &.{};
        var state_out: std.ArrayListUnmanaged(*const types.ANFBinding) = .empty;
        defer state_out.deinit(alloc);
        var data_out: std.ArrayListUnmanaged(*const types.ANFBinding) = .empty;
        defer data_out.deinit(alloc);
        for (rest) |*b| {
            switch (b.value) {
                .add_output, .add_raw_output => try state_out.append(alloc, b),
                .add_data_output => try data_out.append(alloc, b),
                .@"if" => |v| {
                    if (contains(v.then, isStateOutput) or contains(v.@"else", isStateOutput)) {
                        try state_out.append(alloc, b);
                    } else if (contains(v.then, isDataOutput) or contains(v.@"else", isDataOutput)) {
                        try data_out.append(alloc, b);
                    }
                },
                else => {},
            }
        }
        try continuation(&builder, &tail, needs_change, includes_change, state_out.items, data_out.items);

        const names = try alloc.alloc(?[]const u8, builder.arena.items.len);
        defer alloc.free(names);
        @memset(names, null);
        var matcher: Matcher = .{ .b = &builder, .names = names };

        for (pro.items, 0..) |id, i| {
            if (i >= m.body.len or !matcher.binding(id, &m.body[i])) return mismatch(m.name, "prologue", i, builder.arena.items[id]);
        }

        const offset: isize = @as(isize, @intCast(rest.len)) - @as(isize, @intCast(tail.items.len));
        for (tail.items, 0..) |id, i| {
            const idx = offset + @as(isize, @intCast(i));
            if (idx < 0 or !matcher.binding(id, &rest[@intCast(idx)])) return mismatch(m.name, "continuation", i, builder.arena.items[id]);
        }

        // (4) unique, unshadowed names for what the scaffolding binds or
        // commits to. A binding's own arms may reuse its name (an
        // output-carrying `if` is named after its arm's last binding).
        var checked: std.ArrayListUnmanaged(*const types.ANFBinding) = .empty;
        defer checked.deinit(alloc);
        try appendPreorder(alloc, &checked, m.body[0..pro_len]);
        if (offset >= 0) try appendPreorder(alloc, &checked, rest[@intCast(offset)..]);
        try checked.appendSlice(alloc, state_out.items);
        try checked.appendSlice(alloc, data_out.items);
        for (checked.items) |b| {
            var clash = countName(m.body, b.name) - countInside(b, b.name) != 1;
            for (properties) |p| {
                if (std.mem.eql(u8, p.name, b.name)) clash = true;
            }
            for (m.params) |p| {
                if (std.mem.eql(u8, p.name, b.name)) clash = true;
            }
            if (clash) {
                required_fields.setDiag(
                    "IR validation: stateful method '{s}' must bind '{s}' exactly once, under a name no property or parameter uses: the injected scaffolding binds it or the continuation commits to it",
                    .{ m.name, b.name },
                );
                return Error.StatefulScaffoldMismatch;
            }
        }
    }
}
