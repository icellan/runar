//! F-072 — lowerCall's `exit` branch recorded a stack slot no opcode produces.
//!
//! `exit(cond)` lowers as `call exit` (no dedicated ANF node); every tier ran
//! `cond OP_VERIFY` and then pushed a slot for the void result. OP_VERIFY
//! leaves nothing behind, so every later PICK/ROLL addressed the item one
//! below the one it meant. For
//! `check(b, a, x, y) { exit(x > 0n); assert(y === 1n); assert(a > 5n); assert(b === 0n); }`
//! every tier emitted 7c00a0697c519d7c55a0697c9177, which the five-push
//! witness (0, b=6, a=1, x=1, y=999) spends. This tier's `call assert` lowering
//! (reachable only through compile-ir) was already phantom-free; the `super`
//! branch is dead (constructors are never stack-lowered and the loader refuses
//! `super` elsewhere) and had its push removed for consistency.
//!
//! Proves: the Zig tier emits the hand-derived 7c00a069519d55a06991 on the
//! source path (both fold modes) and on the compile-ir path for `call exit`
//! and `call assert`.
//! Does not prove: that the script spends correctly — executed on the
//! @bsv/sdk engine for all seven tiers in
//! packages/runar-testing/src/__tests__/f072-exit-phantom-slot-spend.test.ts.

const std = @import("std");
const types = @import("../ir/types.zig");
const json_parser = @import("../ir/json.zig");
const ec_optimizer = @import("../passes/ec_optimizer.zig");
const stack_lower = @import("../passes/stack_lower.zig");
const peephole = @import("../passes/peephole.zig");
const emit = @import("../codegen/emit.zig");
const compiler_api = @import("../compiler_api.zig");

const EXPECTED = "7c00a069519d55a06991";

const SOURCE =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\class ExitAssert4 extends SmartContract {
    \\  constructor() {
    \\    super();
    \\  }
    \\
    \\  public check(b: bigint, a: bigint, x: bigint, y: bigint) {
    \\    exit(x > 0n);
    \\    assert(y === 1n);
    \\    assert(a > 5n);
    \\    assert(b === 0n);
    \\  }
    \\}
;

fn ir(alloc: std.mem.Allocator, guard: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc,
        \\{{"contractName": "ExitAssert4", "properties": [], "methods": [
        \\  {{"name": "constructor", "isPublic": false, "params": [], "body": [
        \\    {{"name": "t0", "value": {{"kind": "call", "func": "super", "args": []}}}}]}},
        \\  {{"name": "check", "isPublic": true, "params": [
        \\    {{"name": "b", "type": "bigint"}}, {{"name": "a", "type": "bigint"}},
        \\    {{"name": "x", "type": "bigint"}}, {{"name": "y", "type": "bigint"}}], "body": [
        \\    {{"name": "t0", "value": {{"kind": "load_param", "name": "x"}}}},
        \\    {{"name": "t1", "value": {{"kind": "load_const", "value": 0}}}},
        \\    {{"name": "t2", "value": {{"kind": "bin_op", "op": ">", "left": "t0", "right": "t1"}}}},
        \\    {{"name": "t3", "value": {{"kind": "call", "func": "{s}", "args": ["t2"]}}}},
        \\    {{"name": "t4", "value": {{"kind": "load_param", "name": "y"}}}},
        \\    {{"name": "t5", "value": {{"kind": "load_const", "value": 1}}}},
        \\    {{"name": "t6", "value": {{"kind": "bin_op", "op": "===", "left": "t4", "right": "t5"}}}},
        \\    {{"name": "t7", "value": {{"kind": "assert", "value": "t6"}}}},
        \\    {{"name": "t8", "value": {{"kind": "load_param", "name": "a"}}}},
        \\    {{"name": "t9", "value": {{"kind": "load_const", "value": 5}}}},
        \\    {{"name": "t10", "value": {{"kind": "bin_op", "op": ">", "left": "t8", "right": "t9"}}}},
        \\    {{"name": "t11", "value": {{"kind": "assert", "value": "t10"}}}},
        \\    {{"name": "t12", "value": {{"kind": "load_param", "name": "b"}}}},
        \\    {{"name": "t13", "value": {{"kind": "load_const", "value": 0}}}},
        \\    {{"name": "t14", "value": {{"kind": "bin_op", "op": "===", "left": "t12", "right": "t13"}}}},
        \\    {{"name": "t15", "value": {{"kind": "assert", "value": "t14"}}}}]}}]}}
    , .{guard});
}

fn irScriptHex(alloc: std.mem.Allocator, src: []const u8) ![]const u8 {
    const program = try ec_optimizer.optimize(alloc, try json_parser.parseANFProgram(alloc, src));
    const stack_program = try stack_lower.lower(alloc, program);
    const methods = try peephole.optimize(alloc, stack_program.methods);
    const optimized = types.StackProgram{
        .methods = methods,
        .contract_name = stack_program.contract_name,
        .properties = stack_program.properties,
        .constructor_params = stack_program.constructor_params,
    };
    return compiler_api.extractArtifactScript(try emit.emitArtifact(alloc, optimized, program));
}

test "F-072: exit() followed by more code reads the right stack slots (source, both fold modes)" {
    for ([_]bool{ true, false }) |disable_fold| {
        const r = try compiler_api.compileSourceWithOptions(std.testing.allocator, SOURCE, "ExitAssert4.runar.ts", disable_fold);
        defer r.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings(EXPECTED, r.script_hex);
    }
}

test "F-072: `call exit` and `call assert` via compile-ir read the right stack slots" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    for ([_][]const u8{ "exit", "assert" }) |guard| {
        try std.testing.expectEqualStrings(EXPECTED, try irScriptHex(alloc, try ir(alloc, guard)));
    }
}
