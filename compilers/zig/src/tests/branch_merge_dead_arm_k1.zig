//! Three branch-merge defects fixed 2026-08-06, pinned to the seven-tier script.
//! Port of the TypeScript reference test
//! packages/runar-compiler/src/__tests__/branch-merge-k1-and-dead-arm.test.ts.
//!
//! All three reproduced in ALL SEVEN TIERS, and all are the PALMER-1 family
//! ("one stack carrier asked to hold N live values") at the k=1 / k=2 arities
//! the 2026-08-05 branch-merged-locals fix did not cover:
//!
//!   1. FUND SAFETY, silent, fold-ON only. An `if` whose condition folds to a
//!      compile-time constant, whose STATICALLY DEAD arm rebinds exactly TWO
//!      locals both read after the branch, resolved every post-branch operand
//!      to the WRONG stack slot. Wrong in both directions: with s = -60267 the
//!      source REJECTS and the deployed script ACCEPTED (a covenant guard
//!      bypassed); with s = 1000 the source ACCEPTS and the deployed script
//!      REJECTED (an unspendable UTXO). Every tier emitted the same wrong
//!      script, so cross-tier agreement held perfectly while all seven were
//!      wrong together.
//!   2. A single local rebound FROM ITSELF in BOTH arms (`m0 = m0 + 1n` /
//!      `m0 = m0 - 1n`) was REJECTED with "value not found on stack", in both
//!      fold modes, though the same shape compiles at k=2 and without an
//!      `else`.
//!   3. The same k=1 merge under ANY compile-time-constant condition, fold-ON.
//!
//! Fixes: passes/constant_fold.zig no longer blanks a statically-dead arm (that
//! erased the __merge$<i> result block both arms carry, so ONE stack slot was
//! registered for K physical results), and passes/stack_lower.zig's
//! the multi-result branch node adopts the slot both arms rebound in place at k=1.
//!
//! The hexes are the SEVEN-TIER agreed output. Every tier pins the same
//! strings, which is what makes this a parity gate: a tier that lowers the fix
//! differently fails its own test.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

// ============================================================================
// Sources (TypeScript surface). Kept byte-identical across all seven tiers.
// ============================================================================

/// k=2 locals rebound by a STATICALLY DEAD arm, both read after the branch.
const DEAD_ARM_K2 =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\class C extends SmartContract {
    \\  readonly s: bigint;
    \\
    \\  constructor(s: bigint) { super(s); this.s = s; }
    \\
    \\  public m(p: bigint): void {
    \\    let a: bigint = this.s;
    \\    let b: bigint = -78n;
    \\    if (false) {
    \\      a = 1n;
    \\      b = p;
    \\    }
    \\    assert(b <= a);
    \\  }
    \\}
;

/// One local rebound FROM ITSELF in both arms, read after the branch.
const SELF_READ_BOTH_ARMS =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\class C extends SmartContract {
    \\  readonly a: bigint;
    \\
    \\  constructor(a: bigint) { super(a); this.a = a; }
    \\
    \\  public m(p: bigint): void {
    \\    assert(this.a > -1000000n);
    \\    let m0: bigint = 1n;
    \\    if (p > 0n) {
    \\      m0 = (m0 + 1n);
    \\    } else {
    \\      m0 = (m0 - 1n);
    \\    }
    \\    assert(m0 > -1000000n);
    \\  }
    \\}
;

/// The same k=1 merge under a compile-time-constant condition.
const CONST_CONDITION_K1 =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\class C extends SmartContract {
    \\  readonly a: bigint;
    \\
    \\  constructor(a: bigint) { super(a); this.a = a; }
    \\
    \\  public m(p: bigint): void {
    \\    assert(this.a > -1000000n);
    \\    let m0: bigint = 1n;
    \\    if (true) {
    \\      m0 = 2n;
    \\    } else {
    \\      m0 = 3n;
    \\    }
    \\    assert(m0 > -1000000n);
    \\  }
    \\}
;

const Case = struct {
    label: []const u8,
    source: []const u8,
    disable_constant_folding: bool,
    want: []const u8,
};

const CASES = [_]Case{
    .{
        .label = "dead-arm-k2/fold-on",
        .source = DEAD_ARM_K2,
        .disable_constant_folding = false,
        .want = "00014e01ce006351547a6e7b757b7567527978557a7568527a75537a75527a7c7ba177",
    },
    .{
        .label = "dead-arm-k2/fold-off",
        .source = DEAD_ARM_K2,
        .disable_constant_folding = true,
        .want = "00014e8f006351537a6e7b757b75676e547a7568527a75527a757ca1",
    },
    .{
        .label = "self-read-both-arms/fold-on",
        .source = SELF_READ_BOTH_ARMS,
        .disable_constant_folding = false,
        .want = "000340420f0340428f7b7ca069517b00a06351787c9376776751787c94767768517a750340420f0340428f7b7ca07777",
    },
    .{
        .label = "self-read-both-arms/fold-off",
        .source = SELF_READ_BOTH_ARMS,
        .disable_constant_folding = true,
        .want = "000340420f8fa069517c00a06351787c9376776751787c94767768517a750340420f8fa0",
    },
    .{
        .label = "const-condition-k1/fold-on",
        .source = CONST_CONDITION_K1,
        .disable_constant_folding = false,
        .want = "000340420f0340428f7b7ca0695151635276776753767768517a750340420f0340428f7b7ca0777777",
    },
    .{
        .label = "const-condition-k1/fold-off",
        .source = CONST_CONDITION_K1,
        .disable_constant_folding = true,
        .want = "000340420f8fa0695151635276776753767768517a750340420f8fa077",
    },
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

test "branch merge k1 and dead arms compile to the seven-tier agreed script" {
    const allocator = std.testing.allocator;
    for (CASES) |tc| {
        const got = try compileScriptHex(allocator, tc.source, tc.disable_constant_folding);
        defer allocator.free(got);
        std.testing.expectEqualStrings(tc.want, got) catch |err| {
            std.debug.print("{s}: script hex diverged from the seven-tier agreed output\n", .{tc.label});
            return err;
        };
    }
}

// A constant condition must not be treated differently from a runtime one, at
// any arity. Before the fix, only the k=2 dead-arm form broke, and only under
// folding -- which is why the fold-OFF parity fuzzers were blind to it.
test "a constant condition and a runtime condition both compile the dead-arm shape" {
    const allocator = std.testing.allocator;
    const conds = [_][]const u8{ "if (false) {", "if (true) {", "if (p > 0n) {" };
    for (conds) |cond| {
        const source = try std.mem.replaceOwned(u8, allocator, DEAD_ARM_K2, "if (false) {", cond);
        defer allocator.free(source);
        for ([_]bool{ false, true }) |disable| {
            const hex = try compileScriptHex(allocator, source, disable);
            defer allocator.free(hex);
            try std.testing.expect(hex.len > 0);
        }
    }
}

// The k=1 self-read shape used to be rejected while its neighbours compiled. A
// compiler that refuses a shape at one arity and accepts it at the next is
// reporting a hole in its own merge machinery, not a language restriction --
// which is why this was fixed rather than turned into a diagnostic.
test "the k=2 sibling and the no-else sibling still compile" {
    const allocator = std.testing.allocator;

    const k2a = try std.mem.replaceOwned(u8, allocator, SELF_READ_BOTH_ARMS, "    let m0: bigint = 1n;", "    let m0: bigint = 1n;\n    let m1: bigint = 2n;");
    defer allocator.free(k2a);
    const k2b = try std.mem.replaceOwned(u8, allocator, k2a, "      m0 = (m0 + 1n);", "      m0 = (m0 + 1n);\n      m1 = (m1 + 1n);");
    defer allocator.free(k2b);
    const k2c = try std.mem.replaceOwned(u8, allocator, k2b, "      m0 = (m0 - 1n);", "      m0 = (m0 - 1n);\n      m1 = (m1 - 1n);");
    defer allocator.free(k2c);
    const k2 = try std.mem.replaceOwned(u8, allocator, k2c, "    assert(m0 > -1000000n);\n  }", "    assert((m0 > -1000000n) && (m1 > -1000000n));\n  }");
    defer allocator.free(k2);

    const no_else = try std.mem.replaceOwned(u8, allocator, SELF_READ_BOTH_ARMS, "    } else {\n      m0 = (m0 - 1n);\n    }", "    }");
    defer allocator.free(no_else);

    for ([_][]const u8{ k2, no_else }) |source| {
        for ([_]bool{ false, true }) |disable| {
            const hex = try compileScriptHex(allocator, source, disable);
            defer allocator.free(hex);
            try std.testing.expect(hex.len > 0);
        }
    }
}
