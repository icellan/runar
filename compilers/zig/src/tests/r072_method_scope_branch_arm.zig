//! R-072 -- the per-method INTRINSIC SCOPE must survive into a nested block.
//!
//! `subContext()` in `passes/anf_lower.zig` builds a FRESH `LowerCtx` for every
//! `if` arm, `for` body and ternary arm, and re-plumbs the parent's state field
//! by field. Three fields form one logical unit -- the per-method scope the
//! intent intrinsics (`extractPrevOutputScript`, `requireOutputP2PKH`) write to:
//!
//!   auto_injected_params        the witness params appended to the method ABI
//!   auto_injected_set           their dedup set
//!   did_emit_hash_outputs_check the once-per-method hashOutputs guard
//!
//! None of the three was carried, and the sub-context's copies were discarded
//! when the arm's bindings were moved to the parent. Two distinct defects fell
//! out, one loud and one silent:
//!
//!   1. An intrinsic called ONLY inside a nested block registered its witness
//!      param on a context nobody read. The ABI never grew the param, so stack
//!      lowering met a `load_param` for a name the method does not declare and
//!      REFUSED. Six tiers compile these programs; Zig alone rejected them.
//!
//!   2. `requireOutputP2PKH` at statement level followed by another inside an
//!      arm emitted the hashOutputs check TWICE -- the arm's context started
//!      with `did_emit_hash_outputs_check = false`. Zig accepted and produced
//!      573 bytes where the other six produce 556. A silent byte divergence.
//!
//! Go had this right from the start: `methodScopeT` is a per-method struct
//! shared into sub-contexts by POINTER (`compilers/go/frontend/anf_lower.go`,
//! "shared pointer -- auto-injection registers propagate up"). This is the same
//! NEW-014 / NEW-018 arm contract that already cost `scriptLevelCodeSeparator`
//! (R-010), `renamedParams` (#130) and `privateMethods` (N-051, 4fcffcc5).
//!
//! Every hex below is the SIX-TIER agreed output (go / rust / python / ruby /
//! java / ts, all byte-identical at the sha this test landed on), captured with
//! and without constant folding -- the cases are fold-invariant.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

// ============================================================================
// Sources (TypeScript surface). Kept byte-identical across all seven tiers.
// ============================================================================

const PRELUDE =
    \\import { SmartContract, ByteString, extractPrevOutputScript, assert, len } from "runar-lang";
    \\
    \\class C extends SmartContract {
    \\  readonly h: ByteString;
    \\
    \\  constructor(h: ByteString) { super(h); this.h = h; }
    \\
;

/// Control: the intrinsic in ordinary statement position, outside any nested
/// block. This is the byte-unchanged baseline -- the method context IS the
/// scope owner here, so no plumbing is involved.
const STMT = PRELUDE ++
    \\  public m(flag: bigint): void {
    \\    const s: ByteString = extractPrevOutputScript(0n, this.h);
    \\    assert(len(s) > 0n);
    \\    assert(flag >= 0n);
    \\  }
    \\}
;

/// The intrinsic inside an `if` THEN arm.
const IF_ARM = PRELUDE ++
    \\  public m(flag: bigint): void {
    \\    if (flag > 0n) {
    \\      const s: ByteString = extractPrevOutputScript(0n, this.h);
    \\      assert(len(s) > 0n);
    \\    }
    \\    assert(flag >= 0n);
    \\  }
    \\}
;

/// Same shape, the 3-arg prefix form. The body-independence probe: it differs
/// from IF_ARM ONLY inside the nested block, so a compiler that drops what the
/// arm computed would emit the same bytes for both.
const IF_ARM_PREFIX = PRELUDE ++
    \\  public m(flag: bigint): void {
    \\    if (flag > 0n) {
    \\      const s: ByteString = extractPrevOutputScript(0n, this.h, 32n);
    \\      assert(len(s) > 0n);
    \\    }
    \\    assert(flag >= 0n);
    \\  }
    \\}
;

/// The intrinsic inside an `if` ELSE arm.
const ELSE_ARM = PRELUDE ++
    \\  public m(flag: bigint): void {
    \\    if (flag > 0n) {
    \\      assert(flag > 0n);
    \\    } else {
    \\      const s: ByteString = extractPrevOutputScript(0n, this.h);
    \\      assert(len(s) > 0n);
    \\    }
    \\    assert(flag >= 0n);
    \\  }
    \\}
;

/// The intrinsic inside a `for` body.
const LOOP_BODY = PRELUDE ++
    \\  public m(flag: bigint): void {
    \\    for (let i = 0n; i < 1n; i++) {
    \\      const s: ByteString = extractPrevOutputScript(0n, this.h);
    \\      assert(len(s) > 0n);
    \\    }
    \\    assert(flag >= 0n);
    \\  }
    \\}
;

/// Two levels deep -- the scope must survive a sub-context OF a sub-context.
const NESTED_IF = PRELUDE ++
    \\  public m(flag: bigint): void {
    \\    if (flag > 0n) {
    \\      if (flag > 1n) {
    \\        const s: ByteString = extractPrevOutputScript(0n, this.h);
    \\        assert(len(s) > 0n);
    \\      }
    \\    }
    \\    assert(flag >= 0n);
    \\  }
    \\}
;

/// `requireOutputP2PKH` at statement level AND inside an arm. The hashOutputs
/// check is contracted to be emitted at most ONCE per method body; an arm that
/// starts with a fresh `did_emit_hash_outputs_check` emits a second one.
const DOUBLE_REQUIRE_OUTPUT =
    \\import { StatefulSmartContract, ByteString, requireOutputP2PKH, assert } from "runar-lang";
    \\
    \\class C extends StatefulSmartContract {
    \\  readonly pkh: ByteString;
    \\  readonly amt: bigint;
    \\  count: bigint;
    \\
    \\  constructor(pkh: ByteString, amt: bigint, count: bigint) { super(pkh, amt, count); this.pkh = pkh; this.amt = amt; this.count = count; }
    \\
    \\  public m(flag: bigint): void {
    \\    requireOutputP2PKH(0n, this.pkh, this.amt);
    \\    if (flag > 0n) {
    \\      requireOutputP2PKH(1n, this.pkh, this.amt);
    \\    }
    \\    assert(flag >= 0n);
    \\  }
    \\}
;

const DOUBLE_REQUIRE_OUTPUT_HEX =
    "78ab76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f" ++
    "517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e" ++
    "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaeba" ++
    "feffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76" ++
    "927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7692" ++
    "7f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e" ++
    "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce87" ++
    "0b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a" ++
    "8d1382a2bf66a71ae74a1e83b0ad69788254947f778101419d7801687f7782012c947f758258947f758258947f778178aa537a82" ++
    "0128947f7701207f758800005880041976a9140288ac7b7b7e7b7e7c7e52790001227b7b7f777c7f757c88527900a06300005880" ++
    "041976a9140288ac7b7b7e7b7e7c7e7b012201227b7b7f777c7f757c886777687c00a277";

const Case = struct {
    label: []const u8,
    source: []const u8,
    want: []const u8,
};

const CASES = [_]Case{
    .{ .label = "statement-position (control)", .source = STMT, .want = "0078aa7c88827700a06900a2" },
    .{ .label = "if-then-arm", .source = IF_ARM, .want = "7800a0630078aa7c88827700a06967756800a2" },
    .{ .label = "if-then-arm/prefix-form", .source = IF_ARM_PREFIX, .want = "7800a0630000012053797b7f777c7f75aa7c88827700a06967756800a2" },
    .{ .label = "if-else-arm", .source = ELSE_ARM, .want = "7800a0637800a06975670078aa7c88827700a0696800a2" },
    .{ .label = "for-body", .source = LOOP_BODY, .want = "007c0078aa7c88827700a0697500a2" },
    .{ .label = "nested-if", .source = NESTED_IF, .want = "7800a0637851a0630078aa7c88827700a06967756867756800a2" },
    .{ .label = "double-requireOutputP2PKH", .source = DOUBLE_REQUIRE_OUTPUT, .want = DOUBLE_REQUIRE_OUTPUT_HEX },
};

fn compileScriptHex(
    allocator: std.mem.Allocator,
    source: []const u8,
    disable_constant_folding: bool,
) ![]const u8 {
    const result = try compiler_api.compileSourceWithOptions(
        allocator,
        source,
        "C.runar.ts",
        disable_constant_folding,
    );
    if (result.artifact_json) |json| allocator.free(json);
    return result.script_hex;
}

fn compileArtifact(
    allocator: std.mem.Allocator,
    source: []const u8,
) ![]const u8 {
    const result = try compiler_api.compileSourceWithOptions(allocator, source, "C.runar.ts", true);
    allocator.free(result.script_hex);
    return result.artifact_json orelse error.NoArtifact;
}

test "an intent intrinsic inside a nested block compiles to the six-tier agreed script" {
    const allocator = std.testing.allocator;
    for (CASES) |tc| {
        for ([_]bool{ true, false }) |disable| {
            const got = compileScriptHex(allocator, tc.source, disable) catch |err| {
                std.debug.print(
                    "{s} (disable_constant_folding={}): REFUSED with {s} -- six tiers compile this\n",
                    .{ tc.label, disable, @errorName(err) },
                );
                return err;
            };
            defer allocator.free(got);
            std.testing.expectEqualStrings(tc.want, got) catch |err| {
                std.debug.print(
                    "{s} (disable_constant_folding={}): script hex diverged from the six-tier agreed output\n",
                    .{ tc.label, disable },
                );
                return err;
            };
        }
    }
}

// The witness param is the thing the intrinsic registers. If the arm's
// registration is discarded, the method ABI never grows it -- so assert on the
// ABI directly, not only on the bytes it happens to produce.
test "the witness param an arm-scoped intrinsic registers reaches the method ABI" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ IF_ARM, ELSE_ARM, LOOP_BODY, NESTED_IF }) |source| {
        const artifact = try compileArtifact(allocator, source);
        defer allocator.free(artifact);
        try std.testing.expect(std.mem.indexOf(u8, artifact, "_prevOutScript_0") != null);
    }
}

// The tier-independent oracle (N-051, 4fcffcc5). No reference tier is
// consulted: two programs that differ ONLY inside the nested block must not
// compile to the same script. A compiler that drops what the arm computed
// emits identical bytes for both, and a covenant built that way pins a
// different script than its source says.
test "two sources differing only inside the nested block do not compile alike" {
    const allocator = std.testing.allocator;
    for ([_]bool{ true, false }) |disable| {
        const full = try compileScriptHex(allocator, IF_ARM, disable);
        defer allocator.free(full);
        const prefix = try compileScriptHex(allocator, IF_ARM_PREFIX, disable);
        defer allocator.free(prefix);
        try std.testing.expect(!std.mem.eql(u8, full, prefix));
    }
}

// The hashOutputs guard is per-METHOD, not per-block. A second emission is not
// a refusal -- it is 17 extra bytes in a deployed locking script that six other
// tiers do not have.
test "the hashOutputs check is emitted once per method, not once per block" {
    const allocator = std.testing.allocator;
    const got = try compileScriptHex(allocator, DOUBLE_REQUIRE_OUTPUT, true);
    defer allocator.free(got);
    try std.testing.expectEqual(DOUBLE_REQUIRE_OUTPUT_HEX.len, got.len);
    try std.testing.expectEqualStrings(DOUBLE_REQUIRE_OUTPUT_HEX, got);
}
