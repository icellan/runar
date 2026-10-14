//! N-265: the method_call graph's recursion + N-180 call-depth bound,
//! re-derived for `compile-ir` input.
//!
//! `compile-ir` skips the frontend entirely, so it never runs
//! `frontend/validate.zig`'s recursion + MAX_CALL_DEPTH check (this tier had
//! no such check anywhere on the `--ir` path, unlike Go's F-071, which was
//! cycle-only). Stack lowering (`passes/stack_lower.zig`'s method_call
//! inlining) inlines every method_call to a private method by lowering its
//! body in place, with no cycle or depth guard, so a self/mutually-recursive
//! method recurses the host call stack until it overflows, and an acyclic
//! chain past the bound recurses it just as deep.
//!
//! Two passes, cycles checked before depth (a cyclic graph has no finite
//! depth to measure), both iterative (explicit stack, no host recursion):
//!   1. `findCycle` -- the exact "hit" a recursive depth-first search would
//!      report the moment it finds a back edge: a method strictly ON the
//!      cycle, not every caller that merely reaches it.
//!   2. `checkDepth` -- once known acyclic, a plain longest-path walk,
//!      refusing the first method (declaration order) whose inlining depth
//!      exceeds MAX_CALL_DEPTH.
//!
//! Message in required_fields.lastDiagnostic() -- Zig's IR loader carries no
//! payload on its own error enum.

const std = @import("std");
const types = @import("types.zig");
const required_fields = @import("required_fields.zig");
const input_limits = @import("../frontend/input_limits.zig");

pub const Error = error{ IRRecursionDetected, IRCallDepthExceeded, OutOfMemory };

const Frame = struct { name: []const u8, next: usize = 0, depth: usize = 0 };
const CallGraph = std.StringHashMapUnmanaged([]const []const u8);

fn collectCalls(allocator: std.mem.Allocator, bindings: []const types.ANFBinding, out: *std.ArrayListUnmanaged([]const u8)) !void {
    for (bindings) |b| {
        switch (b.value) {
            .method_call => |mc| try out.append(allocator, mc.method),
            .@"if" => |v| {
                try collectCalls(allocator, v.then, out);
                try collectCalls(allocator, v.@"else", out);
            },
            .loop => |v| try collectCalls(allocator, v.body, out),
            else => {},
        }
    }
}

/// Refuses a cycle in the method_call graph, then an acyclic chain past
/// MAX_CALL_DEPTH. `allocator` should be an arena (the caller's `parseANFProgram`
/// arena) -- this leaks its working sets like every other IR-frontend-rules
/// check in this file.
pub fn check(allocator: std.mem.Allocator, methods: []const types.ANFMethod) Error!void {
    var callees: CallGraph = .empty;
    for (methods) |m| {
        if (std.mem.eql(u8, m.name, "constructor")) continue;
        var calls: std.ArrayListUnmanaged([]const u8) = .empty;
        try collectCalls(allocator, m.body, &calls);
        try callees.put(allocator, m.name, try calls.toOwnedSlice(allocator));
    }

    if (try findCycle(allocator, methods, &callees)) |name| {
        required_fields.setDiag(
            "IR validation: recursion detected: method '{s}' calls itself directly or indirectly. Private methods are inlined at every call site, so a cyclic call graph has no finite lowering",
            .{name},
        );
        return Error.IRRecursionDetected;
    }
    try checkDepth(allocator, methods, &callees);
}

/// Iterative (explicit-stack), three-state DFS over the IR method_call
/// graph. Declaration order only decides which root the search starts from;
/// the name returned is whichever back edge is found first.
fn findCycle(allocator: std.mem.Allocator, methods: []const types.ANFMethod, callees: *const CallGraph) !?[]const u8 {
    const unvisited: u8 = 0;
    const on_stack: u8 = 1;
    const done: u8 = 2;
    var state: std.StringHashMapUnmanaged(u8) = .empty;

    for (methods) |root_m| {
        const root = root_m.name;
        if (std.mem.eql(u8, root, "constructor")) continue;
        if ((state.get(root) orelse unvisited) != unvisited) continue;

        var stack: std.ArrayListUnmanaged(Frame) = .empty;
        try state.put(allocator, root, on_stack);
        try stack.append(allocator, .{ .name = root });

        while (stack.items.len > 0) {
            const idx = stack.items.len - 1;
            const name = stack.items[idx].name;
            const calls = callees.get(name) orelse &[_][]const u8{};
            if (stack.items[idx].next >= calls.len) {
                try state.put(allocator, name, done);
                _ = stack.pop();
                continue;
            }
            const callee = calls[stack.items[idx].next];
            stack.items[idx].next += 1;
            if (!callees.contains(callee)) continue;
            const callee_state = state.get(callee) orelse unvisited;
            if (callee_state == on_stack) return callee;
            if (callee_state == unvisited) {
                try state.put(allocator, callee, on_stack);
                try stack.append(allocator, .{ .name = callee });
            }
        }
    }
    return null;
}

/// Iterative longest-path walk over the (by this point known-acyclic) IR
/// call graph, no host recursion. Refuses the first method (declaration
/// order) past MAX_CALL_DEPTH, with the diagnostic every tier shares.
fn checkDepth(allocator: std.mem.Allocator, methods: []const types.ANFMethod, callees: *const CallGraph) Error!void {
    var depth: std.StringHashMapUnmanaged(usize) = .empty;
    var done: std.StringHashMapUnmanaged(void) = .empty;

    for (methods) |root_m| {
        const root = root_m.name;
        if (std.mem.eql(u8, root, "constructor")) continue;
        if (done.contains(root)) continue;

        var stack: std.ArrayListUnmanaged(Frame) = .empty;
        try stack.append(allocator, .{ .name = root });

        while (stack.items.len > 0) {
            const idx = stack.items.len - 1;
            const name = stack.items[idx].name;
            const calls = callees.get(name) orelse &[_][]const u8{};
            if (stack.items[idx].next < calls.len) {
                const callee = calls[stack.items[idx].next];
                stack.items[idx].next += 1;
                if (!callees.contains(callee)) continue;
                if (done.contains(callee)) {
                    const d = 1 + (depth.get(callee) orelse 0);
                    if (d > stack.items[idx].depth) stack.items[idx].depth = d;
                } else {
                    try stack.append(allocator, .{ .name = callee });
                }
                continue;
            }
            const finished = stack.pop().?;
            try done.put(allocator, finished.name, {});
            try depth.put(allocator, finished.name, finished.depth);
            if (stack.items.len > 0) {
                const top = &stack.items[stack.items.len - 1];
                const d = 1 + finished.depth;
                if (d > top.depth) top.depth = d;
            }
        }
    }

    for (methods) |m| {
        if (std.mem.eql(u8, m.name, "constructor")) continue;
        const d = depth.get(m.name) orelse 0;
        if (d > input_limits.MAX_CALL_DEPTH) {
            required_fields.setDiag("IR validation: " ++ input_limits.CALL_DEPTH_MESSAGE_FMT, .{m.name});
            return Error.IRCallDepthExceeded;
        }
    }
}
