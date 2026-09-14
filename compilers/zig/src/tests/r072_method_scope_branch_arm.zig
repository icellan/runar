//! R-072 -- what an `if` arm inherits from its parent, and what it must not.
//!
//! `subContext()` in `passes/anf_lower.zig` builds a FRESH `LowerCtx` for every
//! `if` arm, `for` body and ternary arm, and re-plumbs the parent's state field
//! by field. Two kinds of state cross that boundary, and they cross it in
//! OPPOSITE directions:
//!
//!   auto_injected_params / auto_injected_set   BORROWED (shared `MethodScope`)
//!   did_emit_hash_outputs_check                COPIED IN, never copied back
//!
//! The first pair is per-METHOD. A witness param an intrinsic registers inside
//! an arm has to land on the list the method's ABI augmentation reads, whichever
//! block the call sits in. Neither was carried once: an intrinsic called ONLY
//! inside a nested block registered its param on a context nobody read, the ABI
//! never grew it, and stack lowering met a `load_param` for a name the method
//! does not declare and REFUSED. Six tiers compiled those programs; Zig alone
//! rejected them.
//!
//! The second is per-PATH, and the reason is a covenant bypass, not a byte
//! count. `requireOutputP2PKH(i, pkh, sats)` compiles to two separate
//! assertions:
//!
//!   (1) hash256(_serialisedOutputs) === extractOutputHash(txPreimage)
//!   (2) substr(_serialisedOutputs, i*34, 34) === <the expected P2PKH bytes>
//!
//! `_serialisedOutputs` is a SPENDER-SUPPLIED witness, so (2) on its own is a
//! statement about bytes the attacker chose -- it says nothing about the
//! transaction. Only (1) ties the witness to the tx's real output set, and only
//! on the path where (1) actually executes. While the guard lived on the shared
//! `MethodScope`, an `if` whose two arms each call the intrinsic got (1) in the
//! arm lowered first and none in the other: the compiler counted "already
//! emitted" against a path that does not run when the other arm does. Exactly
//! one arm runs on chain, so a spend taking the uncommitted arm reached (2) with
//! `_serialisedOutputs` unconstrained and could hand the covenant a fabricated
//! output set -- bond not paid, script still verifies. Proven on `@bsv/sdk`'s
//! Spend engine in
//! `packages/runar-testing/src/__tests__/r072-branch-arm-covenant-bypass.test.ts`.
//! Python was the only tier that had this right; the other six now match it.
//!
//! So an arm INHERITS a commitment its parent already established (that one
//! dominates it), and its own commitment stays local (a sibling arm cannot
//! inherit code that never runs on its path). This is the same NEW-014 /
//! NEW-018 arm contract that already cost `scriptLevelCodeSeparator` (R-010),
//! `renamedParams` (#130) and `privateMethods` (N-051, 4fcffcc5) -- except here
//! the right answer is not "share it", it is "share one, copy the other".
//!
//! Every hex below is the SEVEN-TIER agreed output (go / rust / python / ruby /
//! java / ts / zig, all byte-identical at the sha this test landed on), captured
//! with and without constant folding -- the cases are fold-invariant.

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

/// `requireOutputP2PKH` at statement level AND inside an arm. The statement-level
/// call DOMINATES the arm, so its commitment is in force there and the arm must
/// NOT emit a second one -- an arm that starts with a fresh
/// `did_emit_hash_outputs_check` would.
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

/// `requireOutputP2PKH` in BOTH arms of an `if`, and in NEITHER a dominating
/// position. This is the covenant-bypass shape: neither arm dominates the other,
/// so each has to carry its own hashOutputs commitment. Under the old
/// once-per-method guard the else arm carried none, and a spend taking it could
/// satisfy the bond assertion against bytes it invented.
const BOTH_ARMS =
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
    \\    if (flag > 0n) {
    \\      requireOutputP2PKH(0n, this.pkh, this.amt);
    \\    } else {
    \\      requireOutputP2PKH(1n, this.pkh, this.amt);
    \\    }
    \\    assert(flag >= 0n);
    \\  }
    \\}
;

const BOTH_ARMS_HEX =
    "78ab76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f" ++
    "517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e" ++
    "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaeba" ++
    "feffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76" ++
    "927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7692" ++
    "7f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e" ++
    "7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce87" ++
    "0b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a" ++
    "8d1382a2bf66a71ae74a1e83b0ad69788254947f778101419d7801687f7782012c947f758258947f758258947f7781537900a063" ++
    "78aa537a820128947f7701207f758800005880041976a9140288ac7b7b7e7b7e7c7e7b0001227b7b7f777c7f757c886778aa537a" ++
    "820128947f7701207f758800005880041976a9140288ac7b7b7e7b7e7c7e7b012201227b7b7f777c7f757c88687c00a277";

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
    .{ .label = "requireOutputP2PKH-in-both-arms", .source = BOTH_ARMS, .want = BOTH_ARMS_HEX },
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

test "an intent intrinsic inside a nested block compiles to the seven-tier agreed script" {
    const allocator = std.testing.allocator;
    for (CASES) |tc| {
        for ([_]bool{ true, false }) |disable| {
            const got = compileScriptHex(allocator, tc.source, disable) catch |err| {
                std.debug.print(
                    "{s} (disable_constant_folding={}): REFUSED with {s} -- the other six tiers compile this\n",
                    .{ tc.label, disable, @errorName(err) },
                );
                return err;
            };
            defer allocator.free(got);
            std.testing.expectEqualStrings(tc.want, got) catch |err| {
                std.debug.print(
                    "{s} (disable_constant_folding={}): script hex diverged from the seven-tier agreed output\n",
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

// The hashOutputs guard is per-PATH. A commitment already established on a
// DOMINATING path is in force inside the block, so repeating it there is 17
// wasted bytes in a deployed locking script that no other tier has.
test "a commitment on a dominating path is not repeated inside the block" {
    const allocator = std.testing.allocator;
    const got = try compileScriptHex(allocator, DOUBLE_REQUIRE_OUTPUT, true);
    defer allocator.free(got);
    try std.testing.expectEqual(DOUBLE_REQUIRE_OUTPUT_HEX.len, got.len);
    try std.testing.expectEqualStrings(DOUBLE_REQUIRE_OUTPUT_HEX, got);
}

// The other direction, and the one with funds attached: neither arm dominates
// the other, so each MUST carry its own commitment. Asserted on the opcode
// stream rather than only on the pinned bytes, because "the hex matches" would
// still pass if the pin itself were ever restamped from a bypassing compiler.
// `OP_HASH256 OP_3 OP_ROLL` (aa 53 7a) is the head of the commitment sequence:
// hash the witness, then reach past it for the preimage.
test "each arm of an if carries its own hashOutputs commitment" {
    const allocator = std.testing.allocator;
    for ([_]bool{ true, false }) |disable| {
        const got = try compileScriptHex(allocator, BOTH_ARMS, disable);
        defer allocator.free(got);
        var count: usize = 0;
        var i: usize = 0;
        while (std.mem.indexOfPos(u8, got, i, "aa537a")) |at| {
            count += 1;
            i = at + 1;
        }
        if (count != 2) {
            std.debug.print(
                "BOTH_ARMS (disable_constant_folding={}): {d} hashOutputs commitment(s), want 2 -- " ++
                    "an arm without one lets a spender satisfy the bond against a witness it invented\n",
                .{ disable, count },
            );
            return error.MissingPerArmCommitment;
        }
    }
}
