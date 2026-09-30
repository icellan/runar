//! N-005 — an assert that is not the method's last binding must be lowered
//! with OP_VERIFY. Port of the reference tier's case in
//! packages/runar-compiler/src/__tests__/asm-surface.test.ts.
//!
//! Stack lowering treated the LAST assert of a public method as terminal (its
//! value left as the script result) even when a terminal asm() followed it.
//! The asm pushed OP_1, the end-of-method cleanup NIPped the comparison away,
//! and the method compiled to 012a9c5177 (<42> OP_NUMEQUAL OP_1 OP_NIP):
//! spendable with ANY x. The hand-derived fixed script is 012a9d51
//! (<42> OP_NUMEQUALVERIFY OP_1).
//!
//! Proves: this tier's bytes for the shape in both fold modes, and that a
//! truly final assert still stays the method result. Does NOT prove on-chain
//! behaviour — the Spend-engine proof for all seven tiers is
//! packages/runar-testing/src/__tests__/n005-assert-then-asm-spend.test.ts.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const ASSERT_THEN_ASM =
    \\import { UnsafeSmartContract, assert, asm } from 'runar-lang';
    \\
    \\class AssertThenAsm extends UnsafeSmartContract {
    \\  constructor() {
    \\    super();
    \\  }
    \\
    \\  public unlock(x: bigint) {
    \\    assert(x === 42n);
    \\    asm({ body: '51', in_arity: 0, out_arity: 1 });
    \\  }
    \\}
    \\
;

const ASM_THEN_ASSERT =
    \\import { UnsafeSmartContract, assert, asm } from 'runar-lang';
    \\
    \\class AsmThenAssert extends UnsafeSmartContract {
    \\  constructor() {
    \\    super();
    \\  }
    \\
    \\  public unlock(x: bigint) {
    \\    asm({ body: '51', in_arity: 0, out_arity: 1 });
    \\    assert(x === 42n);
    \\  }
    \\}
    \\
;

fn hexOf(allocator: std.mem.Allocator, source: []const u8, disable_fold: bool) ![]const u8 {
    const result = try compiler_api.compileSourceWithOptions(allocator, source, "AssertThenAsm.runar.ts", disable_fold);
    if (result.artifact_json) |json| allocator.free(json);
    return result.script_hex;
}

test "N-005: an assert before a terminal asm() is lowered with OP_VERIFY (both fold modes)" {
    const allocator = std.testing.allocator;
    for ([_]bool{ true, false }) |disable_fold| {
        const hex = try hexOf(allocator, ASSERT_THEN_ASM, disable_fold);
        defer allocator.free(hex);
        try std.testing.expect(!std.mem.eql(u8, hex, "012a9c5177"));
        try std.testing.expectEqualStrings("012a9d51", hex);
    }
}

test "N-005: a truly final assert stays the method result" {
    const allocator = std.testing.allocator;
    // OP_1 OP_SWAP <42> OP_NUMEQUAL (terminal, no OP_VERIFY) OP_NIP
    const hex = try hexOf(allocator, ASM_THEN_ASSERT, true);
    defer allocator.free(hex);
    try std.testing.expectEqualStrings("517c012a9c77", hex);
}
