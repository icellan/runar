//! N-051 -- a private-helper call inside a BRANCH ARM must inline the callee.
//! Port of the TypeScript reference test
//! packages/runar-compiler/src/__tests__/n051-branch-arm-private-helper.test.ts.
//!
//! spec/semantics.md §6.3 defines a private method as source-level substitution
//! at every call site, and its canonical example is a helper call in EXPRESSION
//! position:
//!
//!   private square(x: bigint): bigint { return x * x; }
//!   public verify(n: bigint): void { assert(this.square(n) < 100n); }
//!   // After inlining:
//!   public verify(n: bigint): void { assert(n * n < 100n); }
//!
//! spec/ir-format.md §4.7 keeps `method_call` in the canonical ANF ("Inlining
//! happens in a later compiler phase"), so the substitution is stack lowering's
//! job -- and stack lowering lowers an `if`'s arms in a FRESH context.
//!
//! Zig was already correct: its arm contexts carry `self.program`, so the
//! callee is reachable from inside an arm. Go, Rust and Python built the arm
//! context with an EMPTY private-method map and each improvised a different
//! answer for the same source:
//!
//!   const v: bigint = p > 0n ? this.bump(p) : 0n;   // bump(x) = x + 1n
//!
//!   ts / zig / ruby / java   7600a0638b6700776800a2         (correct)
//!   go                       7600a063006700776800a2         (silently wrong)
//!   python                   7600a063007c00776700776800a2   (silently wrong)
//!   rust                     rejected: "unknown function 'bump'"
//!
//! This test exists in Zig to hold that line: the tier that was right must fail
//! loudly if it ever drifts.
//!
//! The hexes are the SEVEN-TIER agreed output. Every tier pins the same
//! strings, which is what makes this a parity gate.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

// ============================================================================
// Sources (TypeScript surface). Kept byte-identical across all seven tiers.
// ============================================================================

const PRELUDE =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\class C extends SmartContract {
    \\  readonly s: bigint;
    \\
    \\  constructor(s: bigint) { super(s); this.s = s; }
    \\
;

/// Helper called from a ternary arm.
const TERNARY_ARM_PLUS_1 = PRELUDE ++
    \\  private bump(x: bigint): bigint { return x + 1n; }
    \\
    \\  public m(p: bigint): void {
    \\    const v: bigint = p > 0n ? this.bump(p) : 0n;
    \\    assert(v >= this.s);
    \\  }
    \\}
;

/// Same shape, different callee body -- the body-independence probe.
const TERNARY_ARM_PLUS_2 = PRELUDE ++
    \\  private bump(x: bigint): bigint { return x + 2n; }
    \\
    \\  public m(p: bigint): void {
    \\    const v: bigint = p > 0n ? this.bump(p) : 0n;
    \\    assert(v >= this.s);
    \\  }
    \\}
;

/// Control: the same program with the helper inlined by hand.
const TERNARY_ARM_MANUAL_INLINE = PRELUDE ++
    \\  public m(p: bigint): void {
    \\    const v: bigint = p > 0n ? p + 1n : 0n;
    \\    assert(v >= this.s);
    \\  }
    \\}
;

/// Helper called from an `if` STATEMENT arm.
const IF_STATEMENT_ARM = PRELUDE ++
    \\  private bump(x: bigint): bigint { return x + 1n; }
    \\
    \\  public m(p: bigint): void {
    \\    let v: bigint = 0n;
    \\    if (p > 0n) {
    \\      v = this.bump(p);
    \\    } else {
    \\      v = 0n;
    \\    }
    \\    assert(v >= this.s);
    \\  }
    \\}
;

/// Control: the same `if` with no helper call in either arm.
const IF_STATEMENT_ARM_NO_HELPER = PRELUDE ++
    \\  public m(p: bigint): void {
    \\    let v: bigint = 0n;
    \\    if (p > 0n) {
    \\      v = p + 1n;
    \\    } else {
    \\      v = 0n;
    \\    }
    \\    assert(v >= this.s);
    \\  }
    \\}
;

/// Control: a helper call in ordinary statement position, outside any arm.
const STATEMENT_POSITION = PRELUDE ++
    \\  private bump(x: bigint): bigint { return x + 1n; }
    \\
    \\  public m(p: bigint): void {
    \\    const v: bigint = this.bump(p);
    \\    assert(v >= this.s);
    \\  }
    \\}
;

const Case = struct {
    label: []const u8,
    source: []const u8,
    want: []const u8,
};

const CASES = [_]Case{
    .{ .label = "ternary-arm/+1", .source = TERNARY_ARM_PLUS_1, .want = "7600a0638b6700776800a2" },
    .{ .label = "ternary-arm/+2", .source = TERNARY_ARM_PLUS_2, .want = "7600a06352936700776800a2" },
    .{ .label = "ternary-arm-manual-inline", .source = TERNARY_ARM_MANUAL_INLINE, .want = "7600a0638b6700776800a2" },
    .{ .label = "if-statement-arm", .source = IF_STATEMENT_ARM, .want = "007800a0637c8b767676537a757777670076537a7577687c7500a2" },
    .{ .label = "if-statement-arm-no-helper", .source = IF_STATEMENT_ARM_NO_HELPER, .want = "007800a0637c8b7677670076537a7577687c7500a2" },
    .{ .label = "statement-position", .source = STATEMENT_POSITION, .want = "8b00a2" },
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

test "a private-helper call in a branch arm compiles to the seven-tier agreed script" {
    const allocator = std.testing.allocator;
    for (CASES) |tc| {
        for ([_]bool{ true, false }) |disable| {
            const got = try compileScriptHex(allocator, tc.source, disable);
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

// spec/semantics.md §6.3: inlining IS substitution, so a helper call in a
// ternary arm and the hand-substituted program are the same program.
test "a helper call in a ternary arm compiles exactly like the hand-inlined source" {
    const allocator = std.testing.allocator;
    for ([_]bool{ true, false }) |disable| {
        const with_helper = try compileScriptHex(allocator, TERNARY_ARM_PLUS_1, disable);
        defer allocator.free(with_helper);
        const manual = try compileScriptHex(allocator, TERNARY_ARM_MANUAL_INLINE, disable);
        defer allocator.free(manual);
        try std.testing.expectEqualStrings(manual, with_helper);
    }
}

// The tier-independent oracle. No reference tier is consulted: a compiler that
// emits the same bytes for `x + 1n` and `x + 2n` has dropped the callee body,
// whatever its peers do.
test "the callee body reaches the arm -- a different helper body changes the script" {
    const allocator = std.testing.allocator;
    for ([_]bool{ true, false }) |disable| {
        const plus1 = try compileScriptHex(allocator, TERNARY_ARM_PLUS_1, disable);
        defer allocator.free(plus1);
        const plus2 = try compileScriptHex(allocator, TERNARY_ARM_PLUS_2, disable);
        defer allocator.free(plus2);
        try std.testing.expect(!std.mem.eql(u8, plus1, plus2));
    }
}
