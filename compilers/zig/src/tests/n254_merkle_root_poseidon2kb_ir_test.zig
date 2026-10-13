//! N-254: `merkleRootPoseidon2KB` through the Zig `--ir` entry point.
//!
//! `stack_lower.zig`'s `builtin_map` keyed the Poseidon2 KoalaBear Merkle
//! lowering as `"poseidon2MerkleRoot"` -- a name no IR this project emits
//! ever calls. Every tier's `--emit-ir` (and the real conformance fixture,
//! conformance/go-only-parity/GoOnlyPoseidon2Merkle.runar.ts) names the
//! builtin `merkleRootPoseidon2KB`, so the dispatch always fell through to
//! `else => return LowerError.InvalidBuiltin`, and the port behind it
//! (`lowerPoseidon2MerkleBuiltin` / `poseidon2_merkle.zig`) was dead code
//! that nothing ever reached.
//!
//! The dead code was also stale: it carried the OLD 4-argument
//! `poseidon2MerkleRoot(leaf, proof, index, depth)` shape (a loose
//! `args.len < 3` guard, no depth-vs-arity cross-check), not the variadic
//! `8*depth + 10` shape `merkleRootPoseidon2KB` actually has, and it
//! reconciled the emitter's 8-element result with nothing at all -- the
//! physical stack and the logical binding disagreed. This also carried
//! CL-BUG-099's limb-truncation hole (fixed in Go via `EmitPoseidon2RootPack`,
//! ported here the same way the Rust (N-237) and Ruby (N-248) tiers did):
//! reconciling via OP_NIP keeps only the top root limb, so
//! `assert(merkleRootPoseidon2KB(...) === expected)` would authenticate
//! against a SINGLE ~31-bit field element instead of the whole root.
//!
//! Under the Go-only-parity policy (conformance/go-only-parity/, R-037) a
//! non-Go port must match Go byte for byte or refuse. This tier now matches
//! Go: the lowering mirrors Go's `lowerMerkleRootPoseidon2KB` (depth 1..=32
//! per Go R-172, exact `8*depth+10` arity) and packs the eight root limbs
//! base-2^32 like Go's `EmitPoseidon2RootPack`.
//!
//! What this proves: Zig's `--ir` path now LOWERS Go's own IR shape for the
//! depth-1 probe (conformance/go-only-parity's own fixture, reduced to its
//! `--emit-ir` bindings) instead of refusing with a bare `InvalidBuiltin`;
//! the emitted script contains the 7x base-2^32 Horner fold that packs all
//! eight root limbs, not the old 7x OP_NIP truncation; and an out-of-range
//! or mis-sized call is refused with a distinct, named diagnostic rather
//! than "no such builtin".
//!
//! What it does not prove: byte-identity with Go (that is the F-092 `--ir`
//! leg of conformance/go-only-parity/go-only-parity.test.ts, which compares
//! this tier's hex against Go's on Go's own `--emit-ir` output), nor
//! execution semantics -- the script is not run here. Depths other than 1
//! are not exercised.

const std = @import("std");
const types = @import("../ir/types.zig");
const json_parser = @import("../ir/json.zig");
const stack_lower = @import("../passes/stack_lower.zig");
const peephole = @import("../passes/peephole.zig");
const ec_optimizer = @import("../passes/ec_optimizer.zig");
const emit = @import("../codegen/emit.zig");
const compiler_api = @import("../compiler_api.zig");

/// ANF IR for `assert(merkleRootPoseidon2KB(l0..l7, s0..s7, idx, <depth>n) === expected)`,
/// the shape conformance/go-only-parity's Go tier emits for
/// GoOnlyPoseidon2Merkle.runar.ts via `--emit-ir` (reduced: `sourceLoc` is
/// optional and omitted here).
fn probeIR(allocator: std.mem.Allocator, depth: i64) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\{{
        \\  "contractName": "GoOnlyPoseidon2Merkle",
        \\  "parentClass": "SmartContract",
        \\  "properties": [],
        \\  "methods": [
        \\    {{
        \\      "name": "constructor",
        \\      "isPublic": false,
        \\      "params": [],
        \\      "body": [
        \\        {{ "name": "t0", "value": {{ "kind": "call", "func": "super", "args": [] }} }}
        \\      ]
        \\    }},
        \\    {{
        \\      "name": "verify",
        \\      "isPublic": true,
        \\      "params": [
        \\        {{ "name": "l0", "type": "bigint" }}, {{ "name": "l1", "type": "bigint" }},
        \\        {{ "name": "l2", "type": "bigint" }}, {{ "name": "l3", "type": "bigint" }},
        \\        {{ "name": "l4", "type": "bigint" }}, {{ "name": "l5", "type": "bigint" }},
        \\        {{ "name": "l6", "type": "bigint" }}, {{ "name": "l7", "type": "bigint" }},
        \\        {{ "name": "s0", "type": "bigint" }}, {{ "name": "s1", "type": "bigint" }},
        \\        {{ "name": "s2", "type": "bigint" }}, {{ "name": "s3", "type": "bigint" }},
        \\        {{ "name": "s4", "type": "bigint" }}, {{ "name": "s5", "type": "bigint" }},
        \\        {{ "name": "s6", "type": "bigint" }}, {{ "name": "s7", "type": "bigint" }},
        \\        {{ "name": "idx", "type": "bigint" }}, {{ "name": "expected", "type": "bigint" }}
        \\      ],
        \\      "body": [
        \\        {{ "name": "t0", "value": {{ "kind": "load_param", "name": "l0" }} }},
        \\        {{ "name": "t1", "value": {{ "kind": "load_param", "name": "l1" }} }},
        \\        {{ "name": "t2", "value": {{ "kind": "load_param", "name": "l2" }} }},
        \\        {{ "name": "t3", "value": {{ "kind": "load_param", "name": "l3" }} }},
        \\        {{ "name": "t4", "value": {{ "kind": "load_param", "name": "l4" }} }},
        \\        {{ "name": "t5", "value": {{ "kind": "load_param", "name": "l5" }} }},
        \\        {{ "name": "t6", "value": {{ "kind": "load_param", "name": "l6" }} }},
        \\        {{ "name": "t7", "value": {{ "kind": "load_param", "name": "l7" }} }},
        \\        {{ "name": "t8", "value": {{ "kind": "load_param", "name": "s0" }} }},
        \\        {{ "name": "t9", "value": {{ "kind": "load_param", "name": "s1" }} }},
        \\        {{ "name": "t10", "value": {{ "kind": "load_param", "name": "s2" }} }},
        \\        {{ "name": "t11", "value": {{ "kind": "load_param", "name": "s3" }} }},
        \\        {{ "name": "t12", "value": {{ "kind": "load_param", "name": "s4" }} }},
        \\        {{ "name": "t13", "value": {{ "kind": "load_param", "name": "s5" }} }},
        \\        {{ "name": "t14", "value": {{ "kind": "load_param", "name": "s6" }} }},
        \\        {{ "name": "t15", "value": {{ "kind": "load_param", "name": "s7" }} }},
        \\        {{ "name": "t16", "value": {{ "kind": "load_param", "name": "idx" }} }},
        \\        {{ "name": "t17", "value": {{ "kind": "load_const", "value": {d} }} }},
        \\        {{ "name": "t18", "value": {{ "kind": "call", "func": "merkleRootPoseidon2KB",
        \\             "args": ["t0","t1","t2","t3","t4","t5","t6","t7","t8","t9","t10","t11","t12","t13","t14","t15","t16","t17"] }} }},
        \\        {{ "name": "t19", "value": {{ "kind": "load_param", "name": "expected" }} }},
        \\        {{ "name": "t20", "value": {{ "kind": "bin_op", "op": "===", "left": "t18", "right": "t19" }} }},
        \\        {{ "name": "t21", "value": {{ "kind": "assert", "value": "t20" }} }}
        \\      ]
        \\    }}
        \\  ]
        \\}}
    , .{depth});
}

fn lowerAtDepth(allocator: std.mem.Allocator, depth: i64) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const ir = try probeIR(alloc, depth);
    const program = try json_parser.parseANFProgram(alloc, ir);
    _ = try stack_lower.lower(alloc, program);
}

/// Runs the same pass sequence `main.zig`'s `--ir` CLI path runs (EC optimize
/// -> stack lower -> peephole -> emit) and returns the locking script hex,
/// owned by `allocator`.
fn compileIRToHex(allocator: std.mem.Allocator, depth: i64) ![]const u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const work_allocator = arena.allocator();

    const ir = try probeIR(work_allocator, depth);
    const program = try json_parser.parseANFProgram(work_allocator, ir);
    const optimized_program = try ec_optimizer.optimize(work_allocator, program);
    const stack_program = try stack_lower.lower(work_allocator, optimized_program);
    const optimized_methods = try peephole.optimize(work_allocator, stack_program.methods);
    const optimized_stack_program = types.StackProgram{
        .methods = optimized_methods,
        .contract_name = stack_program.contract_name,
        .properties = stack_program.properties,
        .constructor_params = stack_program.constructor_params,
    };
    const artifact = try emit.emitArtifact(work_allocator, optimized_stack_program, optimized_program);
    const script = try compiler_api.extractArtifactScript(artifact);
    return allocator.dupe(u8, script);
}

test "N-254: Go's merkleRootPoseidon2KB depth-1 IR lowers (was InvalidBuiltin)" {
    try lowerAtDepth(std.testing.allocator, 1);
}

test "N-254: the compiled script packs all eight root limbs, not just the top one" {
    const allocator = std.testing.allocator;
    const hex = try compileIRToHex(allocator, 1);
    defer allocator.free(hex);

    // Go's `EmitPoseidon2RootPack`: 7 x (push 2^32 = `05 0000000001` LE, OP_MUL,
    // OP_ADD) -- a fixed Bitcoin Script encoding, the same bytes Rust's N-237
    // and Ruby's N-248 ports pin against Go.
    const root_pack_hex = "0500000000019593";
    var packed_tail: [root_pack_hex.len * 7]u8 = undefined;
    inline for (0..7) |i| @memcpy(packed_tail[i * root_pack_hex.len ..][0..root_pack_hex.len], root_pack_hex);
    try std.testing.expect(std.mem.indexOf(u8, hex, &packed_tail) != null);

    // The pre-fix truncation shape -- seven consecutive OP_NIPs (0x77) -- must
    // be absent: that would mean root_0..root_6 got discarded again.
    const seven_nips = "77" ** 7;
    try std.testing.expect(std.mem.indexOf(u8, hex, seven_nips) == null);
}

test "N-254: depth 33 is refused as a DEPTH problem, not an unknown builtin" {
    try std.testing.expectError(
        error.MerkleDepthOutOfRange,
        lowerAtDepth(std.testing.allocator, 33),
    );
}

test "N-254: an arg count that does not match the depth is refused" {
    // probeIR always emits exactly 18 call args (8 leaf + 8 sibling + index +
    // depth). At a legal depth > 1 the expected count is 8 + depth*8 + 2,
    // which 18 no longer satisfies once depth != 1 -- this exercises the
    // depth-vs-arity cross-check the old 4-arg port never had.
    try std.testing.expectError(
        error.InvalidBuiltin,
        lowerAtDepth(std.testing.allocator, 2),
    );
}
