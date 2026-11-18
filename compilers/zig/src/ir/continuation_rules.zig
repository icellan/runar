//! D18 on --ir input. Port of assertIrNoDroppedContinuation in
//! packages/runar-compiler/src/passes/continuation-rules.ts: compile-ir skips
//! typecheck, so the rule is re-derived from the ANF. A public method of a
//! StatefulSmartContract program whose bindings reach an update_prop and an
//! add_raw_output but no add_output -- at any depth (if arms, loop body) and
//! through method_calls to private methods -- is refused with the source
//! path's text. Run after the N-101 stateful-scaffolding check.

const std = @import("std");
const types = @import("types.zig");
const required_fields = @import("required_fields.zig");
const continuation_rules = @import("../passes/continuation_rules.zig");

const Allocator = std.mem.Allocator;

pub const Error = error{ DroppedContinuation, OutOfMemory };

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn dropsContinuation(a: Allocator, method: types.ANFMethod, methods: []const types.ANFMethod) Allocator.Error!bool {
    var writes = false;
    var raw = false;
    var add = false;
    var visited: std.StringHashMapUnmanaged(void) = .empty;
    // Explicit work list: no host recursion on deep nesting.
    var work: std.ArrayListUnmanaged([]const types.ANFBinding) = .empty;
    try work.append(a, method.body);
    while (work.pop()) |bindings| {
        for (bindings) |b| {
            switch (b.value) {
                .update_prop => writes = true,
                .add_raw_output => raw = true,
                .add_output => add = true,
                .method_call => |mc| {
                    for (methods) |t| {
                        if (t.is_public or eql(t.name, "constructor") or !eql(t.name, mc.method)) continue;
                        const gop = try visited.getOrPut(a, t.name);
                        if (!gop.found_existing) try work.append(a, t.body);
                        break;
                    }
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
    return writes and raw and !add;
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
