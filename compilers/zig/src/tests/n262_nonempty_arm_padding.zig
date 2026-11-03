//! N-262 -- `lowerIf` phase 3 must refuse to pad a NON-EMPTY arm.
//!
//! Phase 3 balances the two arms of an OP_IF by pushing an OP_0 on the
//! shallower one. Padding an arm with NO bindings is the legitimate #99
//! fallback; padding an arm that DID compute something writes a placeholder the
//! post-ENDIF code reads as a value (the OP_0-in-the-taken-arm shape). Go has
//! refused it since R-161; the other six tiers padded silently.
//!
//! The program is hand-built `--ir` input: an arm ending in a non-terminal
//! `assert` is one slot shallower than a sibling arm that leaves a value.
//!
//! Proves: both padding directions are refused with `BranchStackMismatch` (the
//! diagnostic carries the shared sentence, same words as
//! compilers/go/codegen/stack.go -- logged, so this test pins the error kind,
//! not the text), and padding an EMPTY arm still compiles. Layer B's own
//! `BranchStackMismatch` cannot fire after phase 3 (the loops end at equality),
//! so the error here is unambiguous. Does not prove that no source program
//! reaches the guard (golden conformance covers the corpus).

const std = @import("std");
const json = @import("../ir/json.zig");
const stack_lower = @import("../passes/stack_lower.zig");

const VALUE_ARM =
    \\[{"name":"a","value":{"kind":"load_const","value":1}}]
;
const ASSERT_ARM =
    \\[{"name":"k","value":{"kind":"load_const","value":1}},
    \\ {"name":"k2","value":{"kind":"assert","value":"k"}}]
;

fn irFor(a: std.mem.Allocator, then_arm: []const u8, else_arm: []const u8) ![]u8 {
    return std.fmt.allocPrint(a,
        \\{{"contractName":"P","properties":[],"methods":[{{"name":"m","isPublic":true,
        \\ "params":[{{"name":"x","type":"bigint"}}],"body":[
        \\ {{"name":"t0","value":{{"kind":"load_param","name":"x"}}}},
        \\ {{"name":"t1","value":{{"kind":"load_const","value":0}}}},
        \\ {{"name":"t2","value":{{"kind":"bin_op","op":">","left":"t0","right":"t1"}}}},
        \\ {{"name":"t3","value":{{"kind":"if","cond":"t2","then":{s},"else":{s}}}}},
        \\ {{"name":"t4","value":{{"kind":"assert","value":"t3"}}}}]}}]}}
    , .{ then_arm, else_arm });
}

fn lowerIr(a: std.mem.Allocator, src: []const u8) !void {
    const program = try json.parseANFProgram(a, src);
    _ = try stack_lower.lower(a, program);
}

test "N-262: a non-empty else arm is never padded" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectError(error.BranchStackMismatch, lowerIr(a, try irFor(a, VALUE_ARM, ASSERT_ARM)));
}

test "N-262: a non-empty then arm is never padded" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectError(error.BranchStackMismatch, lowerIr(a, try irFor(a, ASSERT_ARM, VALUE_ARM)));
}

test "N-262: an empty else arm is still padded" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try lowerIr(a, try irFor(a, VALUE_ARM, "[]"));
}
