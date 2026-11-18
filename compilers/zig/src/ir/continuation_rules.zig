//! D18 on --ir input. Port of assertIrNoDroppedContinuation in
//! packages/runar-compiler/src/passes/continuation-rules.ts: compile-ir skips
//! typecheck, so the rule is re-derived from the ANF, per path. A public
//! method of a StatefulSmartContract program that declares an output
//! (add_output / add_raw_output, at any depth and through method_calls to
//! private methods) and has a path that reaches an update_prop but no
//! add_output is refused with the source path's text. Path states are the
//! bits {W = update_prop reached, A = add_output reached} as a u4 mask (see
//! passes/continuation_rules.zig): `if` unions its arms, a loop unions with
//! skipping it, a method_call to a private method composes with that method's
//! exit states. Run after the N-101 stateful-scaffolding check.

const std = @import("std");
const types = @import("types.zig");
const required_fields = @import("required_fields.zig");
const continuation_rules = @import("../passes/continuation_rules.zig");

const Allocator = std.mem.Allocator;

pub const Error = error{ DroppedContinuation, OutOfMemory };

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn privateNamed(methods: []const types.ANFMethod, name: []const u8) ?types.ANFMethod {
    for (methods) |t| {
        if (t.is_public or eql(t.name, "constructor") or !eql(t.name, name)) continue;
        return t;
    }
    return null;
}

/// Any add_output / add_raw_output at any depth, through method_calls.
/// Explicit work list: no host recursion on deep nesting.
fn declaresOutput(a: Allocator, method: types.ANFMethod, methods: []const types.ANFMethod) Allocator.Error!bool {
    var visited: std.StringHashMapUnmanaged(void) = .empty;
    var work: std.ArrayListUnmanaged([]const types.ANFBinding) = .empty;
    try work.append(a, method.body);
    while (work.pop()) |bindings| {
        for (bindings) |b| {
            switch (b.value) {
                .add_output, .add_raw_output => return true,
                .method_call => |mc| if (privateNamed(methods, mc.method)) |t| {
                    const gop = try visited.getOrPut(a, t.name);
                    if (!gop.found_existing) try work.append(a, t.body);
                },
                .@"if" => |iff| {
                    try work.append(a, iff.then);
                    try work.append(a, iff.@"else");
                },
                .loop => |lp| try work.append(a, lp.body),
                else => {},
            }
        }
    }
    return false;
}

/// The private methods a binding list calls, at any depth.
fn callees(a: Allocator, body: []const types.ANFBinding, methods: []const types.ANFMethod) Allocator.Error![]const types.ANFMethod {
    var out: std.ArrayListUnmanaged(types.ANFMethod) = .empty;
    var work: std.ArrayListUnmanaged([]const types.ANFBinding) = .empty;
    try work.append(a, body);
    while (work.pop()) |bindings| {
        for (bindings) |b| {
            switch (b.value) {
                .method_call => |mc| if (privateNamed(methods, mc.method)) |t| try out.append(a, t),
                .@"if" => |iff| {
                    try work.append(a, iff.then);
                    try work.append(a, iff.@"else");
                },
                .loop => |lp| try work.append(a, lp.body),
                else => {},
            }
        }
    }
    return out.items;
}

const Exits = std.StringHashMapUnmanaged(u4);

fn run(bindings: []const types.ANFBinding, states: u4, methods: []const types.ANFMethod, exits: *const Exits) u4 {
    var s = states;
    for (bindings) |b| {
        switch (b.value) {
            .update_prop => s = continuation_rules.orAll(s, continuation_rules.W),
            .add_output => s = continuation_rules.orAll(s, continuation_rules.A),
            .method_call => |mc| if (privateNamed(methods, mc.method)) |t| {
                s = continuation_rules.compose(s, exits.get(t.name) orelse continuation_rules.ZERO);
            },
            .@"if" => |iff| s = run(iff.then, s, methods, exits) | run(iff.@"else", s, methods, exits),
            .loop => |lp| s |= run(lp.body, s, methods, exits),
            else => {},
        }
    }
    return s;
}

/// Exit states of every private method reachable from `method`, bottom-up by
/// an explicit post-order (N-264: no host recursion across helper chains). A
/// helper on the open path (a cycle) stays unresolved and contributes {0}.
fn helperExits(a: Allocator, method: types.ANFMethod, methods: []const types.ANFMethod) Allocator.Error!Exits {
    const Frame = struct { helper: ?types.ANFMethod, todo: []const types.ANFMethod };
    var exits: Exits = .empty;
    var open: std.StringHashMapUnmanaged(void) = .empty;
    var stack: std.ArrayListUnmanaged(Frame) = .empty;
    try stack.append(a, .{ .helper = null, .todo = try callees(a, method.body, methods) });
    while (stack.items.len > 0) {
        const top = stack.items[stack.items.len - 1];
        var next: ?types.ANFMethod = null;
        for (top.todo) |t| {
            if (!exits.contains(t.name) and !open.contains(t.name)) {
                next = t;
                break;
            }
        }
        if (next) |t| {
            try open.put(a, t.name, {});
            try stack.append(a, .{ .helper = t, .todo = try callees(a, t.body, methods) });
        } else {
            _ = stack.pop();
            if (top.helper) |h| {
                try exits.put(a, h.name, run(h.body, continuation_rules.ZERO, methods, &exits));
                _ = open.remove(h.name);
            }
        }
    }
    return exits;
}

fn dropsContinuation(a: Allocator, method: types.ANFMethod, methods: []const types.ANFMethod) Allocator.Error!bool {
    if (!try declaresOutput(a, method, methods)) return false;
    var exits = try helperExits(a, method, methods);
    return continuation_rules.droppedState(run(method.body, continuation_rules.ZERO, methods, &exits));
}

/// Refuses the first public method that drops its state write
/// (error.DroppedContinuation, message in the required_fields diagnostic channel).
pub fn check(allocator: Allocator, methods: []const types.ANFMethod) Error!void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    for (methods) |m| {
        if (!m.is_public or eql(m.name, "constructor")) continue;
        if (try dropsContinuation(arena.allocator(), m, methods)) {
            required_fields.setDiag("IR validation: " ++ continuation_rules.DROPPED_CONTINUATION_FMT, .{m.name});
            return error.DroppedContinuation;
        }
    }
}
