//! N-011 — which class in a `.runar.ts` file is the contract.
//!
//! The TS reference (`packages/runar-compiler/src/passes/01-parse.ts`) walks
//! EVERY class and keeps only one whose `extends` names a valid base
//! (SmartContract / StatefulSmartContract / UnsafeSmartContract):
//!   * classes with no `extends` or another base are ignored, wherever they sit;
//!   * several valid classes -> "Only one SmartContract subclass is allowed per
//!     file" at each valid class after the first (the LAST one is kept);
//!   * no valid class -> "No class extending SmartContract,
//!     StatefulSmartContract, or UnsafeSmartContract found" at 1:0.
//!
//! Pre-fix `parse_ts.zig` parsed the FIRST `class` token and defaulted a
//! missing `extends` to SmartContract, so a leading helper was compiled as the
//! contract. In DECOY_FIRST the helper's `unlock` accepts every preimage EXCEPT
//! the real one (a8008791 instead of a80087). It also REFUSED a foreign-base
//! helper ahead of the contract ("unknown parent class: 'Base'"), which TS
//! accepts. The real-engine proof is
//! `packages/runar-testing/src/__tests__/n011-ts-class-selection-vm.test.ts`.
//!
//! Expected values were captured by running the TS reference on the same
//! shapes. Zig renders locations `file:line:col` with a 1-BASED column, so
//! the TS reference's `13:0` is `13:1` here and `1:0` is `1:1`.
//!
//! What this proves: the Zig .runar.ts parser picks the same class and parent
//! and emits the same diagnostics (message + line, column in Zig's 1-based
//! convention) as the TS reference on the seven F-016 shapes.
//! What it does NOT prove: the other Zig-tier surfaces.

const std = @import("std");
const parse_ts = @import("parse_ts.zig");

const NO_CLASS = "No class extending SmartContract, StatefulSmartContract, or UnsafeSmartContract found";
const ONLY_ONE = "Only one SmartContract subclass is allowed per file";

const IMPORTS = "import { SmartContract, assert, ByteString, Sha256, sha256 } from 'runar-lang';\n\n";

const HASHLOCK =
    \\export class HashLock extends SmartContract {
    \\  readonly hashValue: Sha256;
    \\
    \\  constructor(hashValue: Sha256) {
    \\    super(hashValue);
    \\    this.hashValue = hashValue;
    \\  }
    \\
    \\  public unlock(preimage: ByteString) {
    \\    assert(sha256(preimage) === this.hashValue);
    \\  }
    \\}
    \\
;

const DECOY_BODY =
    \\ {
    \\  readonly hashValue: Sha256;
    \\
    \\  constructor(hashValue: Sha256) {
    \\    super(hashValue);
    \\    this.hashValue = hashValue;
    \\  }
    \\
    \\  public unlock(preimage: ByteString) {
    \\    assert(sha256(preimage) !== this.hashValue);
    \\  }
    \\}
    \\
;
const DECOY = "class Helper" ++ DECOY_BODY;
const FOREIGN = "class Helper extends Base" ++ DECOY_BODY;

const TWO_VALID = IMPORTS ++
    \\export class First extends SmartContract {
    \\  constructor() {
    \\    super();
    \\  }
    \\
    \\  public unlock(preimage: ByteString) {
    \\    assert(true);
    \\  }
    \\}
    \\
++ "\n" ++ HASHLOCK;

const THREE_VALID =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\export class A extends SmartContract {
    \\  constructor() { super(); }
    \\  public unlock(x: bigint) { assert(x === 1n); }
    \\}
    \\export class B extends SmartContract {
    \\  constructor() { super(); }
    \\  public unlock(x: bigint) { assert(x === 2n); }
    \\}
    \\export class C extends SmartContract {
    \\  constructor() { super(); }
    \\  public unlock(x: bigint) { assert(x === 3n); }
    \\}
    \\
;

const F = "Probe.runar.ts";

fn expectSelectsHashLock(src: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parse_ts.parseTs(arena.allocator(), src, F);
    for (r.errors) |e| std.debug.print("unexpected error: {s}\n", .{e});
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    try std.testing.expectEqualStrings("HashLock", r.contract.?.name);
    try std.testing.expect(r.contract.?.parent_class == .smart_contract);
}

fn expectErrors(src: []const u8, want: []const []const u8, contract_name: ?[]const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = parse_ts.parseTs(arena.allocator(), src, F);
    try std.testing.expectEqual(want.len, r.errors.len);
    for (want, r.errors) |w, e| try std.testing.expectEqualStrings(w, e);
    if (contract_name) |n| {
        try std.testing.expectEqualStrings(n, r.contract.?.name);
    } else {
        try std.testing.expect(r.contract == null);
    }
}

test "N-011 DECOY_FIRST: a helper with no extends ahead of the contract is ignored" {
    try expectSelectsHashLock(IMPORTS ++ DECOY ++ "\n" ++ HASHLOCK);
}

test "N-011 FOREIGN_BASE_FIRST: a helper extending another base ahead of the contract is ignored" {
    try expectSelectsHashLock(IMPORTS ++ FOREIGN ++ "\n" ++ HASHLOCK);
}

test "N-011 CONTRACT_FIRST: a trailing helper is ignored" {
    try expectSelectsHashLock(IMPORTS ++ HASHLOCK ++ "\n" ++ DECOY);
}

test "N-011 NO_EXTENDS_ONLY is refused" {
    try expectErrors(IMPORTS ++ DECOY, &.{F ++ ":1:0: " ++ NO_CLASS}, null);
}

test "N-011 FOREIGN_BASE_ONLY is refused" {
    try expectErrors(IMPORTS ++ FOREIGN, &.{F ++ ":1:0: " ++ NO_CLASS}, null);
}

test "N-011 TWO_VALID reports the second class and keeps the last" {
    try expectErrors(TWO_VALID, &.{F ++ ":13:0: " ++ ONLY_ONE}, "HashLock");
}

test "N-011 THREE_VALID reports each extra class and keeps the last" {
    try expectErrors(THREE_VALID, &.{ F ++ ":7:0: " ++ ONLY_ONE, F ++ ":11:0: " ++ ONLY_ONE }, "C");
}
