//! C27: `methodUsesCheckPreimage`'s entry point used to hard-code `null` for
//! the private-method map, so the `method_call` recursion inside
//! `methodUsesCheckPreimageRec` was dead code.
//!
//! `methodUsesCodePartFull` = usesCheckPreimage AND (usesCodePart OR
//! readsVarLenState). With the map nulled out, a `checkPreimage` reachable
//! ONLY through a private helper made the first conjunct false, so the public
//! method silently dropped its implicit `_codePart` stack parameter,
//! `lowerDeserializeState` took its "terminal method" shortcut, and the later
//! `load_prop` fell back to the deploy-time constructor placeholder instead of
//! the live on-chain state — the same funds-safety class as C18.
//!
//! The TypeScript reference threads a real map
//! (`methodUsesCheckPreimage(method.body, privateMethods)`,
//! packages/runar-compiler/src/passes/05-stack-lower.ts), as do Go, Rust,
//! Python, Ruby and Java. Zig was the only dormant tier.
//!
//! Unreachable from the SOURCE frontend today: `addOutput`/`addRawOutput`/
//! `addDataOutput` are typecheck-gated to StatefulSmartContract, mutable
//! (non-readonly) properties likewise, and ANF lowering auto-injects
//! `check_preimage` into EVERY public stateful method — so the second conjunct
//! can only be true where the public body already carries its own
//! `check_preimage`. It IS reachable through the `compile-ir` / `--ir` input
//! mode, which every tier ships and the conformance runner exercises; before
//! the fix Zig emitted 786 bytes for the program below where all six other
//! tiers emitted 872.

const std = @import("std");
const json_parser = @import("../ir/json.zig");
const types = @import("../ir/types.zig");
const stack_lower = @import("../passes/stack_lower.zig");
const peephole = @import("../passes/peephole.zig");
const emit = @import("../codegen/emit.zig");

/// `check_preimage` lives ONLY inside the private helper `ck`; the public
/// `check` reads the mutable var-length `tag` directly.
const helper_ir =
    \\{
    \\  "contractName": "VarLenPrivateRead",
    \\  "properties": [{"name": "tag", "type": "ByteString", "readonly": false}],
    \\  "methods": [
    \\    {
    \\      "name": "constructor",
    \\      "isPublic": false,
    \\      "params": [{"name": "tag", "type": "ByteString"}],
    \\      "body": [
    \\        {"name": "t0", "value": {"kind": "load_prop", "name": "tag"}},
    \\        {"name": "t1", "value": {"kind": "call", "func": "super", "args": ["t0"]}},
    \\        {"name": "t2", "value": {"kind": "load_prop", "name": "tag"}},
    \\        {"name": "t3", "value": {"kind": "update_prop", "name": "tag", "value": "t2"}}
    \\      ]
    \\    },
    \\    {
    \\      "name": "ck",
    \\      "isPublic": false,
    \\      "params": [{"name": "p", "type": "SigHashPreimage"}],
    \\      "body": [
    \\        {"name": "t0", "value": {"kind": "load_param", "name": "p"}},
    \\        {"name": "t1", "value": {"kind": "check_preimage", "preimage": "t0"}}
    \\      ]
    \\    },
    \\    {
    \\      "name": "check",
    \\      "isPublic": true,
    \\      "params": [{"name": "expected", "type": "bigint"}, {"name": "txPreimage", "type": "SigHashPreimage"}],
    \\      "body": [
    \\        {"name": "t0", "value": {"kind": "load_const", "value": "@this"}},
    \\        {"name": "t1", "value": {"kind": "load_param", "name": "txPreimage"}},
    \\        {"name": "t2", "value": {"kind": "method_call", "method": "ck", "object": "t0", "args": ["t1"]}},
    \\        {"name": "t3", "value": {"kind": "assert", "value": "t2"}},
    \\        {"name": "t4", "value": {"kind": "load_param", "name": "txPreimage"}},
    \\        {"name": "t5", "value": {"kind": "deserialize_state", "preimage": "t4"}},
    \\        {"name": "t6", "value": {"kind": "load_prop", "name": "tag"}},
    \\        {"name": "t7", "value": {"kind": "call", "func": "len", "args": ["t6"]}},
    \\        {"name": "t8", "value": {"kind": "load_param", "name": "expected"}},
    \\        {"name": "t9", "value": {"kind": "bin_op", "left": "t7", "op": "===", "right": "t8"}},
    \\        {"name": "t10", "value": {"kind": "assert", "value": "t9"}}
    \\      ]
    \\    }
    \\  ]
    \\}
;

/// Same program with NO `check_preimage` anywhere. The `_codePart` gate must
/// stay gated — the recursion must not make `usesCodePart` unconditionally
/// true just because a private helper is called.
const no_preimage_ir =
    \\{
    \\  "contractName": "VarLenPrivateRead",
    \\  "properties": [{"name": "tag", "type": "ByteString", "readonly": false}],
    \\  "methods": [
    \\    {
    \\      "name": "ck",
    \\      "isPublic": false,
    \\      "params": [{"name": "p", "type": "SigHashPreimage"}],
    \\      "body": [
    \\        {"name": "t0", "value": {"kind": "load_param", "name": "p"}}
    \\      ]
    \\    },
    \\    {
    \\      "name": "check",
    \\      "isPublic": true,
    \\      "params": [{"name": "expected", "type": "bigint"}, {"name": "txPreimage", "type": "SigHashPreimage"}],
    \\      "body": [
    \\        {"name": "t0", "value": {"kind": "load_const", "value": "@this"}},
    \\        {"name": "t1", "value": {"kind": "load_param", "name": "txPreimage"}},
    \\        {"name": "t2", "value": {"kind": "method_call", "method": "ck", "object": "t0", "args": ["t1"]}},
    \\        {"name": "t3", "value": {"kind": "load_prop", "name": "tag"}},
    \\        {"name": "t4", "value": {"kind": "call", "func": "len", "args": ["t3"]}},
    \\        {"name": "t5", "value": {"kind": "load_param", "name": "expected"}},
    \\        {"name": "t6", "value": {"kind": "bin_op", "left": "t4", "op": "===", "right": "t5"}},
    \\        {"name": "t7", "value": {"kind": "assert", "value": "t6"}}
    \\      ]
    \\    }
    \\  ]
    \\}
;

/// Mirror main.zig's compileFromIR pipeline: parse ANF JSON -> stack lower ->
/// peephole -> emitArtifact.
fn compileIrToArtifact(allocator: std.mem.Allocator, json: []const u8) ![]const u8 {
    const program = try json_parser.parseANFProgram(allocator, json);
    const stack_program = try stack_lower.lower(allocator, program);
    const optimized_methods = try peephole.optimize(allocator, stack_program.methods);
    const optimized_stack_program = types.StackProgram{
        .methods = optimized_methods,
        .contract_name = stack_program.contract_name,
        .properties = stack_program.properties,
        .constructor_params = stack_program.constructor_params,
    };
    return emit.emitArtifact(allocator, optimized_stack_program, program);
}

fn scriptHex(artifact: []const u8) ![]const u8 {
    const marker = "\"script\":\"";
    const idx = std.mem.indexOf(u8, artifact, marker) orelse return error.MissingHex;
    const after = idx + marker.len;
    const end = std.mem.indexOfPos(u8, artifact, after, "\"") orelse return error.MissingHex;
    return artifact[after..end];
}

fn usesCodePartFor(allocator: std.mem.Allocator, json: []const u8, method_name: []const u8) !bool {
    const program = try json_parser.parseANFProgram(allocator, json);
    for (program.methods) |method| {
        if (std.mem.eql(u8, method.name, method_name)) {
            return stack_lower.methodUsesCodePartFull(
                stack_lower.methodBindings(method),
                program.properties,
                program.methods,
            );
        }
    }
    return error.MethodNotFound;
}

test "C27: checkPreimage reachable only through a private helper still emits _codePart" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try std.testing.expect(try usesCodePartFor(a, helper_ir, "check"));

    // End-to-end: the ABI must advertise the implicit _codePart parameter so
    // the SDK provisions it in the unlocking script.
    const artifact = try compileIrToArtifact(a, helper_ir);
    try std.testing.expect(std.mem.indexOf(u8, artifact, "\"usesCodePart\":true") != null);

    // Cross-tier lock: TS, Go, Rust, Python, Ruby and Java all emit 540 bytes
    // for this program (872 with the legacy 760-byte binding blob; the Any-S
    // blob is 332 bytes smaller). Zig under-emitted while the private-method
    // map was null.
    const hex = try scriptHex(artifact);
    try std.testing.expectEqual(@as(usize, 540 * 2), hex.len);
}

test "C27: the _codePart gate stays gated when no checkPreimage is reachable" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try std.testing.expect(!try usesCodePartFor(a, no_preimage_ir, "check"));

    const artifact = try compileIrToArtifact(a, no_preimage_ir);
    try std.testing.expect(std.mem.indexOf(u8, artifact, "\"usesCodePart\":true") == null);
}
