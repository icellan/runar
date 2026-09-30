//! N-046 (ScopeSnatcher) + N-047 (ShadowGoblin) — a block-scoped declaration,
//! or a local of an inlined private helper, that reuses a name already bound in
//! an enclosing scope gets its own ANF identity (user decision R24:
//! alpha-rename, `<name>@<n>`). Port of
//! packages/runar-compiler/src/__tests__/n046-block-scope-alpha-rename.test.ts.
//!
//! `let authorized = checkSig(sig, this.owner); if (trigger) { let authorized
//! = true; } assert(authorized);` bound the inner `let` as `authorized`, the
//! if-arm reconciliation took it for a reassignment of the outer local, and any
//! signature unlocked the coins. An inlined output-emitting helper's local
//! overwrote the caller's the same way.
//!
//! Oracle: alpha-equivalence, from the source language rather than compiler
//! output. Renaming the inner declaration cannot change the program's meaning,
//! so each template compiled with `$L` = the outer name must produce exactly the
//! bytes of `$L` = `fresh`, in both constant-folding modes.
//!
//! Proves: in the Zig tier, an inner `let` in a no-else if-arm, in both arms of
//! an if/else, in a nested if (reassigned there), in a loop body, a loop
//! variable reusing an outer local, an inner `let` reusing a parameter, and an
//! inlined helper local reusing a caller local or parameter all compile like
//! their renamed spellings. Does NOT prove: on-chain behaviour or cross-tier
//! ANF naming (both in
//! packages/runar-testing/src/__tests__/n046-block-scope-spend.test.ts).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const VAULT_HEAD =
    \\
    \\import { SmartContract, assert, checkSig } from 'runar-lang';
    \\import type { PubKey, Sig } from 'runar-lang';
    \\
    \\class ShadowVault extends SmartContract {
    \\  readonly owner: PubKey;
    \\
    \\  constructor(owner: PubKey) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\
    \\
;

const PAYOUT_HEAD =
    \\
    \\import { StatefulSmartContract, ByteString, PubKey, Sig, assert, checkSig, len } from 'runar-lang';
    \\
    \\class OwnerPayout extends StatefulSmartContract {
    \\  nonce: bigint;
    \\  readonly owner: PubKey;
    \\
    \\  constructor(nonce: bigint, owner: PubKey) {
    \\    super(nonce, owner);
    \\    this.nonce = nonce;
    \\    this.owner = owner;
    \\  }
    \\
    \\
;

const TAIL = "\n}\n";

const Shape = struct { name: []const u8, outer: []const u8, template: []const u8 };

const SHAPES = [_]Shape{
    .{ .name = "ScopeSnatcher: inner let in a no-else if-arm", .outer = "authorized", .template = VAULT_HEAD ++
        \\  public spend(sig: Sig, trigger: boolean) {
        \\    let authorized = checkSig(sig, this.owner);
        \\    if (trigger) {
        \\      let $L = true;
        \\    }
        \\    assert(authorized);
        \\  }
    ++ TAIL },
    .{ .name = "ScopeSnatcher: inner const in both arms of an if/else", .outer = "ok", .template = VAULT_HEAD ++
        \\  public spend(sig: Sig, x: bigint) {
        \\    let ok = checkSig(sig, this.owner);
        \\    if (x > 0n) {
        \\      const $L = true;
        \\      assert($L);
        \\    } else {
        \\      const $L = x < 0n;
        \\      assert(!$L);
        \\    }
        \\    assert(ok);
        \\  }
    ++ TAIL },
    .{ .name = "inner let in a nested if, read and reassigned inside its scope", .outer = "ok", .template = VAULT_HEAD ++
        \\  public spend(sig: Sig, x: bigint) {
        \\    let ok = checkSig(sig, this.owner);
        \\    if (x > 0n) {
        \\      if (x > 1n) {
        \\        let $L = x > 5n;
        \\        $L = !$L;
        \\        assert($L || x == 7n);
        \\      }
        \\    }
        \\    assert(ok);
        \\  }
    ++ TAIL },
    .{ .name = "inner let in a loop body", .outer = "ok", .template = VAULT_HEAD ++
        \\  public spend(sig: Sig, x: bigint) {
        \\    let ok = checkSig(sig, this.owner);
        \\    for (let i = 0n; i < 2n; i++) {
        \\      let $L = x > i;
        \\      assert($L);
        \\    }
        \\    assert(ok);
        \\  }
    ++ TAIL },
    .{ .name = "loop variable reusing an outer local name", .outer = "i", .template = VAULT_HEAD ++
        \\  public spend(sig: Sig, x: bigint) {
        \\    let i = x;
        \\    let acc = 0n;
        \\    for (let $L = 0n; $L < 3n; $L++) {
        \\      acc = acc + $L;
        \\    }
        \\    assert(i == acc);
        \\    assert(checkSig(sig, this.owner));
        \\  }
    ++ TAIL },
    .{ .name = "inner let reusing a parameter name", .outer = "x", .template = VAULT_HEAD ++
        \\  public spend(sig: Sig, x: bigint) {
        \\    if (x > 0n) {
        \\      let $L = 5n;
        \\      assert($L == 5n);
        \\    }
        \\    assert(x == 7n);
        \\    assert(checkSig(sig, this.owner));
        \\  }
    ++ TAIL },
    .{ .name = "ShadowGoblin: inlined helper local reusing a caller local name", .outer = "valid", .template = PAYOUT_HEAD ++
        \\  public withdraw(sig: Sig, destination: ByteString) {
        \\    const valid = checkSig(sig, this.owner);
        \\    this.pay(destination);
        \\    assert(valid);
        \\  }
        \\
        \\  private pay(destination: ByteString) {
        \\    const $L = len(destination) > 0n;
        \\    assert($L);
        \\    this.addRawOutput(50000n, destination);
        \\  }
    ++ TAIL },
    .{ .name = "inlined helper local reusing a caller parameter name", .outer = "sig", .template = PAYOUT_HEAD ++
        \\  public withdraw(sig: Sig, destination: ByteString) {
        \\    this.pay(destination);
        \\    assert(checkSig(sig, this.owner));
        \\  }
        \\
        \\  private pay(destination: ByteString) {
        \\    const $L = len(destination);
        \\    assert($L > 0n);
        \\    this.addRawOutput(50000n, destination);
        \\  }
    ++ TAIL },
};

fn hexOf(allocator: std.mem.Allocator, template: []const u8, name: []const u8, disable_fold: bool) ![]const u8 {
    const source = try std.mem.replaceOwned(u8, allocator, template, "$L", name);
    defer allocator.free(source);
    const result = try compiler_api.compileSourceWithOptions(allocator, source, "Shadow.runar.ts", disable_fold);
    if (result.artifact_json) |json| allocator.free(json);
    return result.script_hex;
}

test "N-046: a shadowing declaration compiles like the renamed spelling" {
    const allocator = std.testing.allocator;
    var failures: usize = 0;
    for (SHAPES) |shape| {
        for ([_]bool{ true, false }) |disable_fold| {
            const shadow = hexOf(allocator, shape.template, shape.outer, disable_fold) catch |err| {
                std.debug.print("N-046 {s} (disable_fold={}): shadowing spelling failed to compile: {}\n", .{ shape.name, disable_fold, err });
                failures += 1;
                continue;
            };
            defer allocator.free(shadow);
            const control = try hexOf(allocator, shape.template, "fresh", disable_fold);
            defer allocator.free(control);
            if (!std.mem.eql(u8, shadow, control)) {
                std.debug.print("N-046 {s} (disable_fold={}): shadowing {s} != renamed {s}\n", .{ shape.name, disable_fold, shadow, control });
                failures += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 0), failures);
}
