//! R-238 (CL-GAP-014): an out-of-range `merkleRootSha256` depth was refused as
//! `InvalidBuiltin` — a "no such builtin" error for a builtin this tier
//! supports and compiles correctly at a legal depth.
//!
//! `lowerMerkleBuiltin` folded three unrelated refusals into one tag:
//!
//!     if (args.len != 4) return LowerError.InvalidBuiltin;
//!     const depth_value = self.findConstantInt(depth_arg) orelse return LowerError.InvalidBuiltin;
//!     if (depth_value < 1 or depth_value > 64) return LowerError.InvalidBuiltin;
//!
//! Measured across the tiers on `merkleRootSha256(leaf, proof, idx, 65n)`:
//!
//!     go / rust / ruby / ts / python
//!             merkleRootSha256: depth must be between 1 and 64, got 65
//!     java    refuses the whole family by policy, and says which policy
//!     zig     stack lowering error: InvalidBuiltin
//!
//! Zig compiles depth 4 to the same bytes as those five peers, so the builtin is
//! not invalid — the DEPTH is. An author reading "InvalidBuiltin" goes looking
//! for a misspelled name or a missing port, which is the one thing that is not
//! wrong.
//!
//! The finding's framing is "three different placements of the same check across
//! tiers". Placement is style. What a reader can act on is the message, and that
//! is what these pin: a distinct error tag per cause, the way this file already
//! distinguishes SilentOpZeroRefused and DegenerateMultiSigThreshold, plus the
//! peers' wording on the log line.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const stack_lower = @import("../passes/stack_lower.zig");
const json_parser = @import("../ir/json.zig");

// A minimal ANF program whose only call is merkleRootSha256 at `depth`. The
// shape is what the compiler itself emits for
// `assert(merkleRootSha256(leaf, proof, idx, <depth>n) === this.expected)`,
// taken from `--emit-ir` and reduced to the bindings that matter.
fn irAtDepth(allocator: std.mem.Allocator, depth: u32) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\{{
        \\  "contractName": "M",
        \\  "parentClass": "SmartContract",
        \\  "properties": [{{ "name": "expected", "type": "ByteString", "readonly": true }}],
        \\  "methods": [{{
        \\    "name": "verify",
        \\    "isPublic": true,
        \\    "params": [
        \\      {{ "name": "leaf", "type": "ByteString" }},
        \\      {{ "name": "proof", "type": "ByteString" }},
        \\      {{ "name": "idx", "type": "bigint" }}
        \\    ],
        \\    "body": [
        \\      {{ "name": "t0", "value": {{ "kind": "load_param", "name": "leaf" }} }},
        \\      {{ "name": "t1", "value": {{ "kind": "load_param", "name": "proof" }} }},
        \\      {{ "name": "t2", "value": {{ "kind": "load_param", "name": "idx" }} }},
        \\      {{ "name": "t3", "value": {{ "kind": "load_const", "value": {d} }} }},
        \\      {{ "name": "t4", "value": {{ "kind": "call", "func": "merkleRootSha256", "args": ["t0", "t1", "t2", "t3"] }} }},
        \\      {{ "name": "t5", "value": {{ "kind": "load_prop", "name": "expected" }} }},
        \\      {{ "name": "t6", "value": {{ "kind": "bin_op", "op": "===", "left": "t4", "right": "t5" }} }},
        \\      {{ "name": "t7", "value": {{ "kind": "assert", "value": "t6" }} }}
        \\    ]
        \\  }}]
        \\}}
    , .{depth});
}

fn lowerAtDepth(allocator: std.mem.Allocator, depth: u32) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const ir = try irAtDepth(alloc, depth);
    const program = try json_parser.parseANFProgram(alloc, ir);
    _ = try stack_lower.lower(alloc, program);
}

fn sourceAtDepth(allocator: std.mem.Allocator, depth: u32) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\import {{ SmartContract, assert, merkleRootSha256 }} from 'runar-lang';
        \\
        \\class M extends SmartContract {{
        \\  readonly expected: ByteString;
        \\
        \\  constructor(expected: ByteString) {{
        \\    super(expected);
        \\    this.expected = expected;
        \\  }}
        \\
        \\  public verify(leaf: ByteString, proof: ByteString, idx: bigint) {{
        \\    assert(merkleRootSha256(leaf, proof, idx, {d}n) === this.expected);
        \\  }}
        \\}}
    , .{depth});
}

fn hexAtDepth(allocator: std.mem.Allocator, depth: u32) ![]const u8 {
    const src = try sourceAtDepth(allocator, depth);
    defer allocator.free(src);
    return compiler_api.compileSourceToHex(allocator, src, "M.runar.ts");
}

test "R-238: a legal merkle depth still compiles from source" {
    const allocator = std.testing.allocator;
    const hex = try hexAtDepth(allocator, 4);
    defer allocator.free(hex);
    try std.testing.expect(hex.len > 0);
}

test "R-238: the boundaries of the supported range still compile" {
    const allocator = std.testing.allocator;
    const one = try hexAtDepth(allocator, 1);
    defer allocator.free(one);
    try std.testing.expect(one.len > 0);

    const sixty_four = try hexAtDepth(allocator, 64);
    defer allocator.free(sixty_four);
    try std.testing.expect(sixty_four.len > 0);
}

// The specific refusal is pinned at the lowering entry point. `compileSourceToHex`
// maps every LowerError to StackLowerFailed at the API boundary, so the source
// tests below pin REACHABILITY and these pin WHICH refusal — the split
// check_multisig.zig already uses for the same reason.

test "R-238: depth 0 is refused as a DEPTH problem, not an unknown builtin" {
    try std.testing.expectError(
        error.MerkleDepthOutOfRange,
        lowerAtDepth(std.testing.allocator, 0),
    );
}

test "R-238: depth 65 is refused as a DEPTH problem, not an unknown builtin" {
    try std.testing.expectError(
        error.MerkleDepthOutOfRange,
        lowerAtDepth(std.testing.allocator, 65),
    );
}

test "R-238: a legal depth lowers through the same IR path" {
    try lowerAtDepth(std.testing.allocator, 4);
}

test "R-238: an out-of-range depth is reachable from source too" {
    try std.testing.expectError(
        error.StackLowerFailed,
        hexAtDepth(std.testing.allocator, 65),
    );
}
