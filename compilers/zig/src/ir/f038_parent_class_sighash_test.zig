//! F-038 / F-065 / F-066 / F-070 / F-088 — `parentClass` and a method's
//! `sigHashType` are ANF wire data, so `--emit-ir` -> `compile-ir` keeps them.
//!
//! Before: the emitted IR carried neither key, and `compile-ir` built the
//! artifact from `ANFProgram.parent_class`'s DEFAULT, labelling every IR input
//! "SmartContract" — including a StatefulSmartContract, whose SDK then skips
//! the issue-#44 OP_CODESEPARATOR subscript trim — and dropped the ABI
//! `sigHashType`, so the SDK built an ALL|FORKID preimage for a covenant that
//! asserts another mode.
//!
//! Proves: the IR a source compile emits carries both keys; the artifact
//! compiled from that IR has the same parentClass and abi sigHashType as the
//! source artifact; IR without parentClass yields an artifact without one (not
//! an invented "SmartContract"); the loader refuses the four malformed shapes
//! with the diagnostics shared by all seven tiers. Does not prove: the other
//! six tiers (conformance/ir-roundtrip does that) or script equality (the
//! conformance --ir-parity gate does that).

const std = @import("std");
const testing = std.testing;
const json = @import("json.zig");
const required_fields = @import("required_fields.zig");
const compiler_api = @import("../compiler_api.zig");
const ec_optimizer = @import("../passes/ec_optimizer.zig");
const stack_lower = @import("../passes/stack_lower.zig");
const peephole = @import("../passes/peephole.zig");
const emit = @import("../codegen/emit.zig");
const types = @import("types.zig");

const counter_src =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\class SighashCounter extends StatefulSmartContract {
    \\  count: bigint;
    \\
    \\  constructor(count: bigint) {
    \\    super(count);
    \\    this.count = count;
    \\  }
    \\
    \\  /** @sighash ALL|ANYONECANPAY|FORKID */
    \\  public increment(): void {
    \\    this.count = this.count + 1n;
    \\    assert(true);
    \\  }
    \\}
;

/// Mirror of main.zig `compileFromIR`: parse -> EC optimize -> stack -> emit.
fn artifactFromIr(work: std.mem.Allocator, ir: []const u8) ![]const u8 {
    const program = try json.parseANFProgram(work, ir);
    const optimized = try ec_optimizer.optimize(work, program);
    const stack_program = try stack_lower.lower(work, optimized);
    const methods = try peephole.optimize(work, stack_program.methods);
    return emit.emitArtifact(work, .{
        .methods = methods,
        .contract_name = stack_program.contract_name,
        .properties = stack_program.properties,
        .constructor_params = stack_program.constructor_params,
    }, optimized);
}

test "F-038 source IR carries parentClass + sigHashType and compile-ir keeps both" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const work = arena.allocator();

    var diag: compiler_api.Diagnostics = .{};
    const pipeline = try compiler_api.runPipeline(work, counter_src, "SighashCounter.runar.ts", .{
        .disable_constant_folding = true,
    }, &diag);
    const program = pipeline.program.?;

    const ir = try json.serializeCanonicalJSON(work, program);
    try testing.expect(std.mem.indexOf(u8, ir, "\"parentClass\": \"StatefulSmartContract\"") != null);
    try testing.expect(std.mem.indexOf(u8, ir, "\"sigHashType\": 193") != null);

    const direct = try emit.emitArtifact(work, pipeline.stack_program.?, program);
    const via_ir = try artifactFromIr(work, ir);
    for ([_][]const u8{ direct, via_ir }) |art| {
        try testing.expect(std.mem.indexOf(u8, art, "\"parentClass\":\"StatefulSmartContract\"") != null);
        try testing.expect(std.mem.indexOf(u8, art, "\"sigHashType\":193") != null);
    }
    try testing.expectEqualStrings(
        try compiler_api.extractArtifactScript(direct),
        try compiler_api.extractArtifactScript(via_ir),
    );
}

const control =
    \\{"contractName":"X","properties":[{"name":"pk","type":"PubKey","readonly":true}],"methods":[{"name":"unlock","isPublic":true,"params":[{"name":"sig","type":"Sig"}],"body":[{"name":"t0","value":{"kind":"load_param","name":"sig"}},{"name":"t1","value":{"kind":"load_prop","name":"pk"}},{"name":"t2","value":{"kind":"call","func":"checkSig","args":["t0","t1"]}},{"name":"t3","value":{"kind":"assert","value":"t2"}}]}]}
;

test "F-038 IR without parentClass yields an artifact without one" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const art = try artifactFromIr(arena.allocator(), control);
    try testing.expect(std.mem.indexOf(u8, art, "parentClass") == null);
}

fn withField(comptime where: []const u8, comptime field: []const u8) []const u8 {
    @setEvalBranchQuota(100_000);
    const i = std.mem.indexOf(u8, control, where) orelse @compileError("pattern not in control: " ++ where);
    return control[0..i] ++ field ++ control[i..];
}

fn expectRefused(src: []const u8, want_msg: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.IRFieldWrongType, json.parseANFProgram(arena.allocator(), src));
    try testing.expectEqualStrings(want_msg, required_fields.lastDiagnostic() orelse "<none>");
}

test "F-038 loader refuses a malformed parentClass / sigHashType" {
    try expectRefused(
        comptime withField(",\"properties\"", ",\"parentClass\":7"),
        "IR validation: parentClass must be a string, got number",
    );
    try expectRefused(
        comptime withField(",\"properties\"", ",\"parentClass\":\"Contract\""),
        "IR validation: parentClass must be one of SmartContract, StatefulSmartContract, UnsafeSmartContract, got Contract",
    );
    try expectRefused(
        comptime withField(",\"params\"", ",\"sigHashType\":\"0x43\""),
        "IR validation: methods[0].sigHashType must be an integer, got string",
    );
    try expectRefused(
        comptime withField(",\"params\"", ",\"sigHashType\":3"),
        "IR validation: methods[0].sigHashType must be one of 65, 66, 67, 193, 194, 195, got 3",
    );
}

test "F-038 loader accepts the legal values and reads them" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const p = try json.parseANFProgram(
        arena.allocator(),
        comptime withField(",\"params\"", ",\"sigHashType\":67"),
    );
    try testing.expectEqual(@as(?i32, 67), p.methods[0].sighash_type);
    const q = try json.parseANFProgram(
        arena.allocator(),
        comptime withField(",\"properties\"", ",\"parentClass\":\"UnsafeSmartContract\""),
    );
    try testing.expectEqual(@as(?types.ParentClass, .unsafe_smart_contract), @as(?types.ParentClass, q.parent_class));
}
