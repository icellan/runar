//! N-095 — the synthetic-array chain on `ANFProperty` is wire data.
//!
//! The expand-fixed-arrays pass desugars a `FixedArray` property into scalar
//! siblings and hangs a chain of `{base, index, length}` levels off each leaf.
//! `regroupStateFields` in `codegen/emit.zig` collapses those siblings back
//! into a single FixedArray state entry by reading that chain off the ANF
//! PROGRAM, not off the AST. So the field is load-bearing on the wire, and it
//! is load-bearing in a way nothing in this repo was watching: drop it and the
//! script hex is byte-identical, only the artifact's `stateFields` degrades
//! from one `grid` entry into four raw `grid__i__j` scalars, which is what the
//! SDK's `state.grid` accessor is built on.
//!
//! Zig's defect was the quietest of the three shapes:
//!   * it threaded the chain correctly through the AST, `expand_fixed_arrays`
//!     and `anf_lower`, so SOURCE mode regrouped fine; but
//!   * `ir/json.zig` neither wrote it in `writePropertiesArray` nor read it in
//!     `parseProperties`, so `--emit-ir` dropped it on the floor and
//!     `compile-ir` could not recover it from anyone's ANF, its own included.
//!
//! Three tiers spelled the key three different ways (`syntheticArrayChain`,
//! `__syntheticArrayChain`, `synthetic_array_chain`) and three emitted nothing.
//! The settled spelling is Go's `syntheticArrayChain`, which is also what
//! `$defs.ANFProperty` in the shared JSON Schema now declares.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const json_ir = @import("../ir/json.zig");
const types = @import("../ir/types.zig");
const emit = @import("../codegen/emit.zig");
const stack_lower = @import("../passes/stack_lower.zig");
const peephole = @import("../passes/peephole.zig");

/// Nested 2x2 FixedArray: four leaves, each with a two-level chain.
const GRID_SRC =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class Grid2x2 extends StatefulSmartContract {
    \\  grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];
    \\  constructor() {
    \\    super();
    \\  }
    \\  public set00(v: bigint) {
    \\    this.grid[0][0] = v;
    \\    assert(true);
    \\  }
    \\  public set11(v: bigint) {
    \\    this.grid[1][1] = v;
    \\    assert(true);
    \\  }
    \\}
;

/// Control: no FixedArray anywhere, so no property may grow the key.
const SCALAR_SRC =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class Counter extends StatefulSmartContract {
    \\  count: bigint = 0n;
    \\  constructor() {
    \\    super();
    \\  }
    \\  public increment() {
    \\    this.count = this.count + 1n;
    \\    assert(true);
    \\  }
    \\}
;

/// Run passes 1-4 and hand back the canonical ANF JSON `--emit-ir` prints.
/// Caller owns the returned bytes.
/// `work` must be an ARENA: `runPipeline` allocates every node from it and
/// the ANF types carry no recursive `deinit`, so the arena is the only
/// correct owner. Every test below follows `ir/json.zig`'s own convention.
fn emitIr(work: std.mem.Allocator, source: []const u8) ![]const u8 {
    var diag = compiler_api.Diagnostics{};
    const pipeline = try compiler_api.runPipeline(work, source, "Contract.runar.ts", .{
        .stop_after = .anf,
        .disable_constant_folding = true,
    }, &diag);
    const program = pipeline.program orelse return error.NoProgram;
    return json_ir.serializeCanonicalJSON(work, program);
}

/// Compile a parsed ANF program the way `compile-ir` does, returning the
/// artifact JSON. Caller owns the returned bytes.
fn artifactFromProgram(allocator: std.mem.Allocator, program: types.ANFProgram) ![]const u8 {
    const stack_program = try stack_lower.lower(allocator, program);
    const optimized = try peephole.optimize(allocator, stack_program.methods);
    return emit.emitArtifact(allocator, .{
        .methods = optimized,
        .contract_name = stack_program.contract_name,
        .properties = stack_program.properties,
        .constructor_params = stack_program.constructor_params,
    }, program);
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

test "N-095: --emit-ir writes syntheticArrayChain on every expanded leaf" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const ir = try emitIr(allocator, GRID_SRC);

    // The settled spelling, and only it.
    try std.testing.expect(std.mem.indexOf(u8, ir, "\"syntheticArrayChain\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, ir, "\"__syntheticArrayChain\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, ir, "\"synthetic_array_chain\"") == null);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, ir, .{});
    defer parsed.deinit();
    const props = parsed.value.object.get("properties").?.array;
    try std.testing.expectEqual(@as(usize, 4), props.items.len);

    const want = [_][2]i64{ .{ 0, 0 }, .{ 0, 1 }, .{ 1, 0 }, .{ 1, 1 } };
    for (props.items, 0..) |prop, i| {
        const chain = prop.object.get("syntheticArrayChain").?.array;
        try std.testing.expectEqual(@as(usize, 2), chain.items.len);
        try std.testing.expectEqualStrings("grid", chain.items[0].object.get("base").?.string);
        try std.testing.expectEqual(want[i][0], chain.items[0].object.get("index").?.integer);
        try std.testing.expectEqual(@as(i64, 2), chain.items[0].object.get("length").?.integer);
        try std.testing.expectEqual(want[i][1], chain.items[1].object.get("index").?.integer);
        try std.testing.expectEqual(@as(i64, 2), chain.items[1].object.get("length").?.integer);
    }
}

test "N-095: every emitted ANFProperty key is one the shared schema declares" {
    // Hand-mirrored from `$defs.ANFProperty` in
    // packages/runar-ir-schema/src/schemas/anf-ir.schema.json, which is
    // `additionalProperties: false` — any key outside this set makes Zig's own
    // ANF fail `validateANF`.
    const allowed = [_][]const u8{ "name", "type", "readonly", "initialValue", "syntheticArrayChain" };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const ir = try emitIr(allocator, GRID_SRC);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, ir, .{});
    defer parsed.deinit();
    for (parsed.value.object.get("properties").?.array.items) |prop| {
        var it = prop.object.iterator();
        while (it.next()) |entry| {
            var ok = false;
            for (allowed) |a| {
                if (std.mem.eql(u8, a, entry.key_ptr.*)) ok = true;
            }
            try std.testing.expect(ok);
        }
    }
}

test "N-095: a FixedArray-free contract's ANF does not grow the key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const ir = try emitIr(allocator, SCALAR_SRC);
    try std.testing.expect(std.mem.indexOf(u8, ir, "ynthetic") == null);
}

// ---------------------------------------------------------------------------
// The harm: the ABI, not the hex
// ---------------------------------------------------------------------------

test "N-095: Zig's own ANF replayed through compile-ir still regroups" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const ir = try emitIr(allocator, GRID_SRC);
    const program = try json_ir.parseANFProgram(allocator, ir);

    // The loader must recover the chain, not silently drop it.
    try std.testing.expectEqual(@as(usize, 4), program.properties.len);
    for (program.properties) |p| {
        const chain = p.synthetic_array_chain orelse return error.ChainLostOnLoad;
        try std.testing.expectEqual(@as(usize, 2), chain.len);
        try std.testing.expectEqualStrings("grid", chain[0].base);
    }

    const artifact = try artifactFromProgram(allocator, program);

    // One regrouped `grid`, not four raw scalars.
    try std.testing.expect(std.mem.indexOf(u8, artifact, "\"stateFields\":[{\"name\":\"grid\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, artifact, "\"syntheticNames\":[\"grid__0__0\",\"grid__0__1\",\"grid__1__0\",\"grid__1__1\"]") != null);
}

test "N-095: the chain is ABI-only — the round trip must not move a script byte" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const direct = try compiler_api.compileSourceWithOptions(allocator, GRID_SRC, "Grid2x2.runar.ts", true);

    const ir = try emitIr(allocator, GRID_SRC);
    const program = try json_ir.parseANFProgram(allocator, ir);
    const artifact = try artifactFromProgram(allocator, program);

    const round_hex = try compiler_api.extractArtifactScript(artifact);
    try std.testing.expectEqualStrings(direct.script_hex, round_hex);
}
