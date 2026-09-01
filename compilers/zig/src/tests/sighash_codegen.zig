//! Issue #123 — mode-aware @sighash codegen parity (Zig tier).
//!
//! The declared @sighash mode changes the compiled locking script in EXACTLY
//! two ways relative to the default ALL|FORKID (0x41):
//!   1. the auto-injected `extractSigHashType(pre) === <mode>` assert push, and
//!   2. the OP_PUSH_TX binding blob's appended DER sighash flag byte.
//! Both are a single flag byte (0x41 -> declared mode). This is byte-for-byte
//! the same transformation the TypeScript reference applies (411525a8), so a
//! @sighash SINGLE|FORKID method emits 0x43 in both positions and ANYONECANPAY
//! emits 0xC1 — identical to the TS output.
//!
//! Two layers of assertion: (1) DELTA tests prove the sighash output equals the
//! default output with only the flag byte(s) changed; (2) fold-OFF golden tests
//! (below) assert byte-for-byte equality with the TypeScript reference output
//! (the Go tier's pinned goldens: default / SINGLE 0x43 / ANYONECANPAY 0xC1).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

fn counterSrc(comptime directive: []const u8) []const u8 {
    return "import { StatefulSmartContract } from 'runar-lang';\n" ++
        "class Counter extends StatefulSmartContract {\n" ++
        "  n: bigint;\n" ++
        "  constructor(n: bigint) { super(n); this.n = n; }\n" ++
        "  " ++ directive ++ "\n" ++
        "  public bump(): void { this.addOutput(1000n, this.n); }\n" ++
        "}\n";
}

fn fundSrc(comptime directive: []const u8) []const u8 {
    return "import { StatefulSmartContract } from 'runar-lang';\n" ++
        "class Fund extends StatefulSmartContract {\n" ++
        "  raised: bigint;\n" ++
        "  constructor(raised: bigint) { super(raised); this.raised = raised; }\n" ++
        "  " ++ directive ++ "\n" ++
        "  public pledge(amount: bigint): void { this.raised = this.raised + amount; }\n" ++
        "}\n";
}

/// Assert `single` equals `base` except at positions where the byte differs,
/// where `base` MUST read `expect_from` and `single` MUST read `expect_to`.
/// Returns the number of differing bytes. Both hex strings must be equal length.
fn assertFlagSwapOnly(base: []const u8, mode: []const u8, expect_from: []const u8, expect_to: []const u8) !usize {
    try std.testing.expectEqual(base.len, mode.len);
    var i: usize = 0;
    var diffs: usize = 0;
    while (i + 1 < base.len) : (i += 2) {
        const b = base[i .. i + 2];
        const m = mode[i .. i + 2];
        if (!std.mem.eql(u8, b, m)) {
            diffs += 1;
            try std.testing.expectEqualStrings(expect_from, b);
            try std.testing.expectEqualStrings(expect_to, m);
        }
    }
    return diffs;
}

fn abiSigHash(json: []const u8) ?i64 {
    const marker = "\"sigHashType\":";
    const p = std.mem.indexOf(u8, json, marker) orelse return null;
    const rest = json[p + marker.len ..];
    var end: usize = 0;
    while (end < rest.len and (std.ascii.isDigit(rest[end]))) end += 1;
    return std.fmt.parseInt(i64, rest[0..end], 10) catch null;
}

test "sighash: default == explicit ALL|FORKID (byte-identical, no ABI mode)" {
    const a = std.testing.allocator;
    const dflt = try compiler_api.compileSource(a, counterSrc(""), "Counter.runar.ts");
    defer dflt.deinit(a);
    const all = try compiler_api.compileSource(a, counterSrc("/** @sighash ALL|FORKID */"), "Counter.runar.ts");
    defer all.deinit(a);
    try std.testing.expectEqualStrings(dflt.script_hex, all.script_hex);
    // Neither carries an ABI sigHashType (default is omitted).
    try std.testing.expect(abiSigHash(dflt.artifact_json.?) == null);
    try std.testing.expect(abiSigHash(all.artifact_json.?) == null);
}

test "sighash: SINGLE|FORKID swaps the flag byte 0x41 -> 0x43 (two positions) + ABI mode 67" {
    const a = std.testing.allocator;
    const dflt = try compiler_api.compileSource(a, counterSrc(""), "Counter.runar.ts");
    defer dflt.deinit(a);
    const single = try compiler_api.compileSource(a, counterSrc("/** @sighash SINGLE|FORKID */"), "Counter.runar.ts");
    defer single.deinit(a);

    const diffs = try assertFlagSwapOnly(dflt.script_hex, single.script_hex, "41", "43");
    // Exactly two flag bytes change: the extractSigHashType assert push and the
    // OP_PUSH_TX binding blob's appended DER sighash byte.
    try std.testing.expectEqual(@as(usize, 2), diffs);
    try std.testing.expectEqual(@as(i64, 0x43), abiSigHash(single.artifact_json.?).?);
}

test "sighash: ALL|ANYONECANPAY|FORKID swaps binding-blob flag to 0xC1 + ABI mode 193" {
    const a = std.testing.allocator;
    const dflt = try compiler_api.compileSource(a, fundSrc(""), "Fund.runar.ts");
    defer dflt.deinit(a);
    const acp = try compiler_api.compileSource(a, fundSrc("/** @sighash ALL|ANYONECANPAY|FORKID */"), "Fund.runar.ts");
    defer acp.deinit(a);

    // The OP_PUSH_TX binding blob appends `01<flag>` immediately before OP_CAT
    // (7e) + the fixed G-pubkey push (210279be667ef9...). 0xc1 is a raw byte in
    // that position (not script-number encoded), so it stays a clean 1-byte
    // swap: default `0141` -> ACP `01c1`. (The `extractSigHashType === 0xc1`
    // assert push, by contrast, script-number-encodes 0xc1 as 02c100 with a
    // sign byte, so the full script length changes by one byte — matching TS.)
    const blob_all = "01417e2102b405d7f032";
    const blob_acp = "01c17e2102b405d7f032";
    try std.testing.expect(std.mem.indexOf(u8, dflt.script_hex, blob_all) != null);
    try std.testing.expect(std.mem.indexOf(u8, dflt.script_hex, blob_acp) == null);
    try std.testing.expect(std.mem.indexOf(u8, acp.script_hex, blob_acp) != null);
    // The 0xc1 preimage-type assert push carries the sign byte (02c100).
    try std.testing.expect(std.mem.indexOf(u8, acp.script_hex, "02c100") != null);
    try std.testing.expect(!std.mem.eql(u8, dflt.script_hex, acp.script_hex));
    try std.testing.expectEqual(@as(i64, 0xc1), abiSigHash(acp.artifact_json.?).?);
}

test "sighash: default method has no ABI sigHashType" {
    const a = std.testing.allocator;
    const dflt = try compiler_api.compileSource(a, fundSrc(""), "Fund.runar.ts");
    defer dflt.deinit(a);
    try std.testing.expect(abiSigHash(dflt.artifact_json.?) == null);
}

// ---------------------------------------------------------------------------
// Definitive byte==TS golden parity (fold-OFF, matching the Go tier's
// sighash_codegen_test.go goldens which are the TypeScript reference output).
// Runs the pipeline WITHOUT constant folding (the goldens were stamped fold-OFF)
// and asserts byte-for-byte equality with TS.
// ---------------------------------------------------------------------------

const parse_ts = @import("../passes/parse_ts.zig");
const validate = @import("../passes/validate.zig");
const typecheck = @import("../passes/typecheck.zig");
const expand_fixed_arrays = @import("../passes/expand_fixed_arrays.zig");
const anf_lower = @import("../passes/anf_lower.zig");
const ec_optimizer = @import("../passes/ec_optimizer.zig");
const stack_lower = @import("../passes/stack_lower.zig");
const peephole = @import("../passes/peephole.zig");
const emit = @import("../codegen/emit.zig");
const types = @import("../ir/types.zig");

/// Compile a .runar.ts source through the full pipeline with constant folding
/// DISABLED (matching the checked-in fold-OFF goldens), returning the locking
/// script hex extracted from the artifact JSON.
fn compileFoldOff(alloc: std.mem.Allocator, source: []const u8, path: []const u8) ![]const u8 {
    const parsed = parse_ts.parseTs(alloc, source, path);
    if (parsed.errors.len > 0) return error.ParseFailed;
    const contract = parsed.contract orelse return error.ParseFailed;
    const val = try validate.validate(alloc, contract);
    if (val.errors.len > 0) return error.ValidateFailed;
    const tc = try typecheck.typeCheck(alloc, contract);
    if (tc.errors.len > 0) return error.TypeCheckFailed;
    const expanded = try expand_fixed_arrays.expand(alloc, contract);
    if (expanded.errors.len > 0) return error.ExpandFailed;
    var program = try anf_lower.lowerToANF(alloc, expanded.contract);
    // NOTE: constant_fold intentionally skipped (fold-OFF goldens).
    program = try ec_optimizer.optimize(alloc, program);
    const stack_program = try stack_lower.lower(alloc, program);
    const optimized_methods = try peephole.optimize(alloc, stack_program.methods);
    const optimized = types.StackProgram{
        .methods = optimized_methods,
        .contract_name = stack_program.contract_name,
        .properties = stack_program.properties,
        .constructor_params = stack_program.constructor_params,
    };
    const artifact_json = try emit.emitArtifact(alloc, optimized, program);
    const marker = "\"script\":\"";
    const p = std.mem.indexOf(u8, artifact_json, marker) orelse return error.NoScript;
    const rest = artifact_json[p + marker.len ..];
    const end = std.mem.indexOfScalar(u8, rest, '"') orelse return error.NoScript;
    return rest[0..end];
}

// TS-reference goldens (fold-OFF) — byte-identical to the Go tier's constants.
const counter_default_golden = "76ab76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad69768254947f778101419d7601687f7782012c947f758258947f758258947f778102e803785679016a7e7c58807e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687eaa7b820128947f7701207f75877777";
const counter_single_golden = "76ab76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01437e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad69768254947f778101439d7601687f7782012c947f758258947f758258947f778102e803785679016a7e7c58807e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687eaa7b820128947f7701207f75877777";
const fund_acp_golden = "76ab76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01c17e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad69768254947f778102c1009d7601687f7782012c947f758258947f758258947f778176567a9377547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777";

test "sighash golden: default counter == TS reference (fold-OFF)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const hex = try compileFoldOff(arena.allocator(), counterSrc(""), "Counter.runar.ts");
    try std.testing.expectEqualStrings(counter_default_golden, hex);
}

test "sighash golden: SINGLE|FORKID counter == TS reference (0x43, fold-OFF)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const hex = try compileFoldOff(arena.allocator(), counterSrc("/** @sighash SINGLE|FORKID */"), "Counter.runar.ts");
    try std.testing.expectEqualStrings(counter_single_golden, hex);
}

test "sighash golden: ALL|ANYONECANPAY|FORKID fund == TS reference (0xC1, fold-OFF)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const hex = try compileFoldOff(arena.allocator(), fundSrc("/** @sighash ALL|ANYONECANPAY|FORKID */"), "Fund.runar.ts");
    try std.testing.expectEqualStrings(fund_acp_golden, hex);
}
