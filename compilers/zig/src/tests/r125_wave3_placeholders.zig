//! R-125 / CL-BUG-163 — `ecPairing` and `schnorrVerify` lowered to a literal 0.
//!
//! Both names sat in this tier's builtin map, reached `lowerBuiltinCall`, and
//! were served by an arm commented "Wave 3 placeholders — consume args and push
//! placeholder": the arguments were popped and `emitPushInt(0)` was pushed in
//! the call's place.
//!
//! `schnorrVerify` returning false is at least fail-closed. `ecPairing`
//! returning 0 is arbitrarily wrong — a pairing check that the contract then
//! asserts on becomes an unconditionally false spend, and one used as a value
//! becomes a zero nobody chose.
//!
//! Neither name exists anywhere else in the repository: no other tier's
//! typechecker, lowering or builtin table knows them, so a contract using one
//! could only ever have compiled HERE. They are not Rúnar builtins, and the
//! honest lowering of an unknown name is the one every other family uses —
//! `error.InvalidBuiltin`.
//!
//! This file pins the refusal by name so the placeholder cannot come back
//! quietly.

const std = @import("std");
const stack_lower = @import("../passes/stack_lower.zig");
const types = @import("../ir/types.zig");

fn programCalling(allocator: std.mem.Allocator, func: []const u8) !types.ANFProgram {
    const args = try allocator.alloc([]const u8, 1);
    args[0] = "t0";

    const bindings = try allocator.alloc(types.ANFBinding, 3);
    bindings[0] = .{ .name = "t0", .value = .{ .load_param = .{ .name = "x" } } };
    bindings[1] = .{ .name = "t1", .value = .{ .call = .{ .func = func, .args = args } } };
    bindings[2] = .{ .name = "t2", .value = .{ .assert = .{ .value = "t1" } } };

    const params = try allocator.alloc(types.ANFParam, 1);
    params[0] = .{ .name = "x", .type_info = .bigint };

    const methods = try allocator.alloc(types.ANFMethod, 1);
    methods[0] = .{ .name = "go", .params = params, .body = bindings, .is_public = true };

    return .{ .contract_name = "Wave3", .properties = &.{}, .methods = methods };
}

test "R-125: ecPairing is refused, not lowered to a literal 0" {
    const a = std.testing.allocator;
    const program = try programCalling(a, "ecPairing");
    defer {
        a.free(program.methods[0].body[1].value.call.args);
        a.free(program.methods[0].body);
        a.free(program.methods[0].params);
        a.free(program.methods);
    }
    try std.testing.expectError(
        error.InvalidBuiltin,
        stack_lower.lower(a, program),
    );
}

test "R-125: schnorrVerify is refused too" {
    const a = std.testing.allocator;
    const program = try programCalling(a, "schnorrVerify");
    defer {
        a.free(program.methods[0].body[1].value.call.args);
        a.free(program.methods[0].body);
        a.free(program.methods[0].params);
        a.free(program.methods);
    }
    try std.testing.expectError(
        error.InvalidBuiltin,
        stack_lower.lower(a, program),
    );
}
