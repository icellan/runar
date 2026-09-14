//! N-079 -- the inlined argument alias must survive into a branch arm.
//!
//! Port of the TypeScript reference test
//! `packages/runar-compiler/src/__tests__/n079-inlined-param-alias-branch-arm.test.ts`.
//!
//! `spec/semantics.md` §6.3 defines a private method as source-level
//! substitution at every call site. So this:
//!
//!   private pay(v: bigint): void { ...uses v... }
//!   public  go(v: bigint) { this.pay(v * 2n); }
//!
//! and the hand-substituted program (`const a = v * 2n;` then the body with `a`
//! in place of `v`) are the SAME program and must compile to the same script.
//! That is an oracle needing no reference tier.
//!
//! The defect: `inlinePrivateMethodCall` pushes the caller's argument refs onto
//! the CURRENT lowering context (`pushParamAlias`) and then lowers the private
//! method's body into it. When that body contains an `if` / `for` / ternary,
//! the arm is built by `subContext()` -- a FRESH `LowerCtx` that did not copy
//! `param_alias_stack`. A read of the private's parameter inside the arm
//! therefore found no alias and fell through to `load_param`, which resolved to
//! the CALLER's same-named parameter instead of the argument that was passed
//! in. The covenant's output amount became `v + 100` where the source says
//! `(v * 2) + 100` -- a continuation-hash mismatch (UTXO unspendable) or a
//! wrong payment. Nobody refused.
//!
//! Measured on the pre-fix HEAD, `--disable-constant-folding`:
//!
//!                  go   rust  python  zig  ruby  java  ts
//!   hand-inlined   705   705    705   705   705   705  705
//!   via helper     705   705    703   703   703   703  703
//!
//! Go and Rust were right: Go's `subContext` already deep-copied the alias
//! stack, with a comment naming this exact hazard.
//!
//! This is the FIFTH field of this same sub-context to be missed one at a time
//! -- `scriptLevelCodeSeparator` (R-010), `renamedParams` (#130),
//! `privateMethods` (N-051, 4fcffcc5), the three `MethodScope` fields (R-072,
//! 1ee0a3dd), now the alias stack. Same NEW-014 / NEW-018 arm contract.
//!
//! The (byte length, sha256-of-hex) pairs below are the SEVEN-TIER agreed
//! output; every tier pins the same table, which is what makes this a parity
//! gate. The scripts are ~700 B (a stateful covenant -- the ANF-level inliner
//! only fires for a helper that emits outputs), so they are pinned by digest
//! rather than inline. The cases are fold-invariant.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

// ============================================================================
// Sources (TypeScript surface). Kept byte-identical across all seven tiers.
// ============================================================================

const PRELUDE =
    \\import { StatefulSmartContract, assert } from "runar-lang";
    \\
    \\class C extends StatefulSmartContract {
    \\  count: bigint;
    \\
    \\  constructor(count: bigint) { super(count); this.count = count; }
    \\
    \\
;

/// The item's probe: a helper containing an `if`, called with `v * 2n`.
const IF_ARM = PRELUDE ++
    \\  private pay(v: bigint): void {
    \\    let extra: bigint = 0n;
    \\    if (v > 5n) {
    \\      extra = v + 100n;
    \\    } else {
    \\      extra = v + 1n;
    \\    }
    \\    this.addOutput(extra, this.count);
    \\  }
    \\
    \\  public go(v: bigint) {
    \\    this.count = this.count + 1n;
    \\    this.pay(v * 2n);
    \\    assert(v >= 0n);
    \\  }
    \\}
    \\
;

/// §6.3 control: the same program with the helper substituted by hand.
const IF_ARM_MANUAL = PRELUDE ++
    \\  public go(v: bigint) {
    \\    this.count = this.count + 1n;
    \\    const a: bigint = v * 2n;
    \\    let extra: bigint = 0n;
    \\    if (a > 5n) {
    \\      extra = a + 100n;
    \\    } else {
    \\      extra = a + 1n;
    \\    }
    \\    this.addOutput(extra, this.count);
    \\    assert(v >= 0n);
    \\  }
    \\}
    \\
;

/// N-051 oracle: differs from `IF_ARM` ONLY inside the then-arm (+200 not +100).
const IF_ARM_200 = PRELUDE ++
    \\  private pay(v: bigint): void {
    \\    let extra: bigint = 0n;
    \\    if (v > 5n) {
    \\      extra = v + 200n;
    \\    } else {
    \\      extra = v + 1n;
    \\    }
    \\    this.addOutput(extra, this.count);
    \\  }
    \\
    \\  public go(v: bigint) {
    \\    this.count = this.count + 1n;
    \\    this.pay(v * 2n);
    \\    assert(v >= 0n);
    \\  }
    \\}
    \\
;

/// Same hazard through a ternary arm.
const TERNARY_ARM = PRELUDE ++
    \\  private pay(v: bigint): void {
    \\    const extra: bigint = v > 5n ? v + 100n : v + 1n;
    \\    this.addOutput(extra, this.count);
    \\  }
    \\
    \\  public go(v: bigint) {
    \\    this.count = this.count + 1n;
    \\    this.pay(v * 2n);
    \\    assert(v >= 0n);
    \\  }
    \\}
    \\
;

const TERNARY_ARM_MANUAL = PRELUDE ++
    \\  public go(v: bigint) {
    \\    this.count = this.count + 1n;
    \\    const a: bigint = v * 2n;
    \\    const extra: bigint = a > 5n ? a + 100n : a + 1n;
    \\    this.addOutput(extra, this.count);
    \\    assert(v >= 0n);
    \\  }
    \\}
    \\
;

/// Same hazard through a `for` body -- `subContext()` builds that too.
const LOOP_BODY = PRELUDE ++
    \\  private pay(v: bigint): void {
    \\    let acc: bigint = 0n;
    \\    for (let i = 0; i < 3; i++) {
    \\      acc = acc + v;
    \\    }
    \\    this.addOutput(acc, this.count);
    \\  }
    \\
    \\  public go(v: bigint) {
    \\    this.count = this.count + 1n;
    \\    this.pay(v * 2n);
    \\    assert(v >= 0n);
    \\  }
    \\}
    \\
;

const LOOP_BODY_MANUAL = PRELUDE ++
    \\  public go(v: bigint) {
    \\    this.count = this.count + 1n;
    \\    const a: bigint = v * 2n;
    \\    let acc: bigint = 0n;
    \\    for (let i = 0; i < 3; i++) {
    \\      acc = acc + a;
    \\    }
    \\    this.addOutput(acc, this.count);
    \\    assert(v >= 0n);
    \\  }
    \\}
    \\
;

/// Control: a helper with NO nested block at all. Must be byte-unchanged.
const NO_IF = PRELUDE ++
    \\  private pay(v: bigint): void {
    \\    const extra: bigint = v + 100n;
    \\    this.addOutput(extra, this.count);
    \\  }
    \\
    \\  public go(v: bigint) {
    \\    this.count = this.count + 1n;
    \\    this.pay(v * 2n);
    \\    assert(v >= 0n);
    \\  }
    \\}
    \\
;

/// Control: the parameter is read at STATEMENT level inside the helper, and the
/// `if` in the helper does not read it. Must be byte-unchanged.
const STMT_LEVEL = PRELUDE ++
    \\  private pay(v: bigint): void {
    \\    const extra: bigint = v + 100n;
    \\    let bump: bigint = 0n;
    \\    if (this.count > 5n) {
    \\      bump = 1n;
    \\    } else {
    \\      bump = 2n;
    \\    }
    \\    this.addOutput(extra + bump, this.count);
    \\  }
    \\
    \\  public go(v: bigint) {
    \\    this.count = this.count + 1n;
    \\    this.pay(v * 2n);
    \\    assert(v >= 0n);
    \\  }
    \\}
    \\
;

/// Control: the argument IS the caller's own parameter (`this.pay(v)`), so
/// caller-param and argument coincide and the WRONG lowering computed the right
/// VALUE. It was still a different script -- 701 B where Go/Rust emitted 703 --
/// because the arm re-issued `load_param` instead of reading the alias slot.
const PASSTHROUGH = PRELUDE ++
    \\  private pay(v: bigint): void {
    \\    let extra: bigint = 0n;
    \\    if (v > 5n) {
    \\      extra = v + 100n;
    \\    } else {
    \\      extra = v + 1n;
    \\    }
    \\    this.addOutput(extra, this.count);
    \\  }
    \\
    \\  public go(v: bigint) {
    \\    this.count = this.count + 1n;
    \\    this.pay(v);
    \\    assert(v >= 0n);
    \\  }
    \\}
    \\
;

const Case = struct {
    label: []const u8,
    source: []const u8,
    want_len: usize,
    want_sha: []const u8,
};

const CASES = [_]Case{
    .{ .label = "if-arm", .source = IF_ARM, .want_len = 704, .want_sha = "0bbd49f182e77dbc5483e96f58f8a54e033741f89cba7e0c231f89d8a91c9d2e" },
    .{ .label = "if-arm-manual", .source = IF_ARM_MANUAL, .want_len = 704, .want_sha = "0bbd49f182e77dbc5483e96f58f8a54e033741f89cba7e0c231f89d8a91c9d2e" },
    .{ .label = "if-arm-200", .source = IF_ARM_200, .want_len = 705, .want_sha = "a0c90541131862a8f5cdf769992c8f2026137194f50cc1e00e1a5c293d01435b" },
    .{ .label = "ternary-arm", .source = TERNARY_ARM, .want_len = 691, .want_sha = "f6b2ae0526262ccee7adc71d1291bb8e0ae193de42c1a4e3936b782da95e3caf" },
    .{ .label = "ternary-arm-manual", .source = TERNARY_ARM_MANUAL, .want_len = 691, .want_sha = "f6b2ae0526262ccee7adc71d1291bb8e0ae193de42c1a4e3936b782da95e3caf" },
    .{ .label = "loop-body", .source = LOOP_BODY, .want_len = 698, .want_sha = "3692231cef9275b5a87f1f9f9b268f5a39cc3c4f37fe6354a1b57b2e8d356d55" },
    .{ .label = "loop-body-manual", .source = LOOP_BODY_MANUAL, .want_len = 698, .want_sha = "3692231cef9275b5a87f1f9f9b268f5a39cc3c4f37fe6354a1b57b2e8d356d55" },
    .{ .label = "no-if", .source = NO_IF, .want_len = 683, .want_sha = "2807bc651b0cfac58c0a0835f42b39cf46ce28d1e64d1ba7421279ccfe6680ed" },
    .{ .label = "stmt-level", .source = STMT_LEVEL, .want_len = 700, .want_sha = "99a4048c2311be65c0b463a5dbf666f970c8f0f70878664429d547d3b36adf37" },
    .{ .label = "passthrough", .source = PASSTHROUGH, .want_len = 702, .want_sha = "b0a101dddb8547a0779029930b04856140ee40c7066d793257b6b42ae05fcb8f" },
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

fn digestHex(script_hex: []const u8) [64]u8 {
    var sum: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(script_hex, &sum, .{});
    var out: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{x}", .{&sum}) catch unreachable;
    return out;
}

test "an inlined helper's branch arm reads the ARGUMENT, matching the seven-tier script" {
    const allocator = std.testing.allocator;
    for (CASES) |tc| {
        for ([_]bool{ true, false }) |disable| {
            const got = compileScriptHex(allocator, tc.source, disable) catch |err| {
                std.debug.print(
                    "{s} (disable_constant_folding={}): REFUSED with {s}\n",
                    .{ tc.label, disable, @errorName(err) },
                );
                return err;
            };
            defer allocator.free(got);
            std.testing.expectEqual(tc.want_len, got.len / 2) catch |err| {
                std.debug.print(
                    "{s} (disable_constant_folding={}): script length diverged from the seven-tier agreed output\n",
                    .{ tc.label, disable },
                );
                return err;
            };
            const sum = digestHex(got);
            std.testing.expectEqualStrings(tc.want_sha, &sum) catch |err| {
                std.debug.print(
                    "{s} (disable_constant_folding={}): script bytes diverged from the seven-tier agreed output\n",
                    .{ tc.label, disable },
                );
                return err;
            };
        }
    }
}

// spec/semantics.md §6.3: inlining IS substitution, so the helper form and the
// hand-substituted program are the same program. Consults no reference tier.
test "a helper with a nested block compiles exactly like the hand-inlined source" {
    const allocator = std.testing.allocator;
    const pairs = [_][2][]const u8{
        .{ IF_ARM, IF_ARM_MANUAL },
        .{ TERNARY_ARM, TERNARY_ARM_MANUAL },
        .{ LOOP_BODY, LOOP_BODY_MANUAL },
    };
    for (pairs) |pair| {
        for ([_]bool{ true, false }) |disable| {
            const helper = try compileScriptHex(allocator, pair[0], disable);
            defer allocator.free(helper);
            const manual = try compileScriptHex(allocator, pair[1], disable);
            defer allocator.free(manual);
            try std.testing.expectEqualStrings(manual, helper);
        }
    }
}

// The N-051 oracle, again consulting no reference tier: two helper bodies that
// differ ONLY inside the arm must not compile to the same script.
test "two helper bodies differing only inside the arm do not compile alike" {
    const allocator = std.testing.allocator;
    for ([_]bool{ true, false }) |disable| {
        const plus100 = try compileScriptHex(allocator, IF_ARM, disable);
        defer allocator.free(plus100);
        const plus200 = try compileScriptHex(allocator, IF_ARM_200, disable);
        defer allocator.free(plus200);
        try std.testing.expect(!std.mem.eql(u8, plus100, plus200));
    }
}
