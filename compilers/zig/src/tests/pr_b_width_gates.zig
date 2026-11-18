//! #180 / #213 / D13: a public method's fixed-width parameter is pinned to its
//! declared width at entry (`<copy> OP_SIZE <w> OP_NUMEQUALVERIFY OP_DROP`),
//! except a PubKey that only ever reaches checkSig / checkMultiSig / hash160.
//! Port of the TypeScript reference pins (05-stack-lower.ts,
//! emitFixedWidthParamGate / paramNeedsWidthGate). The expected bytes are the
//! TS tier's output for the same sources, in both fold modes.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const LOCK_SRC =
    \\import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
    \\import type { Point } from 'runar-lang';
    \\class Lock extends StatefulSmartContract {
    \\  n: bigint;
    \\  constructor(n: bigint) { super(n); this.n = n; }
    \\  public lock(p: Point) {
    \\    this.addRawOutput(1000n, cat(cat(toByteString('40'), p), toByteString('87')));
    \\    this.n = this.n + 1n;
    \\    this.addOutput(100000n, this.n);
    \\  }
    \\}
    \\
;

const PAY_TO_KEY_SRC =
    \\import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
    \\import type { PubKey } from 'runar-lang';
    \\class PayToKey extends StatefulSmartContract {
    \\  n: bigint;
    \\  constructor(n: bigint) { super(n); this.n = n; }
    \\  public pay(pk: PubKey) {
    \\    this.addRawOutput(1000n, cat(cat(toByteString('21'), pk), toByteString('ac')));
    \\    this.n = this.n + 1n;
    \\    this.addOutput(100000n, this.n);
    \\  }
    \\}
    \\
;

const P2PKH_SRC =
    \\import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';
    \\class P2PKH extends SmartContract {
    \\  readonly pubKeyHash: Addr;
    \\  constructor(pubKeyHash: Addr) { super(pubKeyHash); this.pubKeyHash = pubKeyHash; }
    \\  public unlock(sig: Sig, pubKey: PubKey) {
    \\    assert(hash160(pubKey) === this.pubKeyHash);
    \\    assert(checkSig(sig, pubKey));
    \\  }
    \\}
    \\
;

const HELPER_P2PKH_SRC =
    \\import { SmartContract, assert, checkSig, hash160 } from 'runar-lang';
    \\import type { PubKey, Sig, Addr } from 'runar-lang';
    \\class HelperP2PKH extends SmartContract {
    \\  readonly pkh: Addr;
    \\  constructor(pkh: Addr) { super(pkh); this.pkh = pkh; }
    \\  private verify(s: Sig, k: PubKey): boolean { return checkSig(s, k); }
    \\  public unlock(sig: Sig, pubKey: PubKey) {
    \\    assert(hash160(pubKey) === this.pkh);
    \\    assert(this.verify(sig, pubKey));
    \\  }
    \\}
    \\
;

const PICK_KEY_SRC =
    \\import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
    \\import type { PubKey } from 'runar-lang';
    \\class PickKey extends StatefulSmartContract {
    \\  n: bigint;
    \\  constructor(n: bigint) { super(n); this.n = n; }
    \\  public pay(pick: boolean, a: PubKey, b: PubKey) {
    \\    const k = pick ? a : b;
    \\    this.addRawOutput(1000n, cat(cat(toByteString('21'), k), toByteString('ac')));
    \\    this.n = this.n + 1n;
    \\    this.addOutput(100000n, this.n);
    \\  }
    \\}
    \\
;

const ID_KEY_SRC =
    \\import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
    \\import type { PubKey } from 'runar-lang';
    \\class IdKey extends StatefulSmartContract {
    \\  n: bigint;
    \\  constructor(n: bigint) { super(n); this.n = n; }
    \\  private id(k: PubKey): PubKey { return k; }
    \\  public pay(pk: PubKey) {
    \\    this.addRawOutput(1000n, cat(cat(toByteString('21'), this.id(pk)), toByteString('ac')));
    \\    this.n = this.n + 1n;
    \\    this.addOutput(100000n, this.n);
    \\  }
    \\}
    \\
;

fn compileHex(allocator: std.mem.Allocator, source: []const u8, file_name: []const u8, disable: bool) ![]const u8 {
    const result = try compiler_api.compileSourceWithOptions(allocator, source, file_name, disable);
    if (result.artifact_json) |json| allocator.free(json);
    for (result.warnings) |line| allocator.free(line);
    allocator.free(result.warnings);
    return result.script_hex;
}

/// Occurrences of `sub` that start on a byte boundary.
fn countAligned(hex: []const u8, sub: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i + sub.len <= hex.len) : (i += 2) {
        if (std.mem.eql(u8, hex[i .. i + sub.len], sub)) n += 1;
    }
    return n;
}

test "PR B: a Point param and _changePKH are width-gated at entry" {
    const allocator = std.testing.allocator;
    for ([_]bool{ true, false }) |disable| {
        const h = try compileHex(allocator, LOCK_SRC, "Lock.runar.ts", disable);
        defer allocator.free(h);
        std.testing.expect(std.mem.indexOf(u8, h, "5379820140" ++ "9d75" ++ "5279820114" ++ "9d75") != null) catch |err| {
            std.debug.print("disable={}: missing Point + _changePKH entry gates: {s}\n", .{ disable, h });
            return err;
        };
        try std.testing.expectEqual(@as(usize, 1), countAligned(h, "8201409d"));
        try std.testing.expectEqual(@as(usize, 1), countAligned(h, "8201149d"));
    }
}

test "PR B: a PubKey spliced into addRawOutput is width-gated" {
    const allocator = std.testing.allocator;
    for ([_]bool{ true, false }) |disable| {
        const h = try compileHex(allocator, PAY_TO_KEY_SRC, "PayToKey.runar.ts", disable);
        defer allocator.free(h);
        std.testing.expect(std.mem.indexOf(u8, h, "5379820121" ++ "9d75") != null) catch |err| {
            std.debug.print("disable={}: missing PubKey entry gate: {s}\n", .{ disable, h });
            return err;
        };
        try std.testing.expectEqual(@as(usize, 1), countAligned(h, "8201219d"));
    }
}

test "PR B: P2PKH stays on the standard template" {
    const allocator = std.testing.allocator;
    for ([_]bool{ true, false }) |disable| {
        const h = try compileHex(allocator, P2PKH_SRC, "P2PKH.runar.ts", disable);
        defer allocator.free(h);
        try std.testing.expectEqualStrings("76a90088ac", h);
    }
}

test "PR B: a PubKey verified through a private helper is not gated" {
    const allocator = std.testing.allocator;
    for ([_]bool{ true, false }) |disable| {
        const h = try compileHex(allocator, HELPER_P2PKH_SRC, "HelperP2PKH.runar.ts", disable);
        defer allocator.free(h);
        try std.testing.expect(std.mem.indexOf(u8, h, "8201219d") == null);
    }
}

test "PR B: a PubKey leaving a ternary arm is width-gated" {
    const allocator = std.testing.allocator;
    for ([_]bool{ true, false }) |disable| {
        const h = try compileHex(allocator, PICK_KEY_SRC, "PickKey.runar.ts", disable);
        defer allocator.free(h);
        try std.testing.expectEqual(@as(usize, 2), countAligned(h, "8201219d"));
    }
}

test "PR B: a PubKey returned by a private helper is width-gated" {
    const allocator = std.testing.allocator;
    for ([_]bool{ true, false }) |disable| {
        const h = try compileHex(allocator, ID_KEY_SRC, "IdKey.runar.ts", disable);
        defer allocator.free(h);
        try std.testing.expectEqual(@as(usize, 1), countAligned(h, "8201219d"));
    }
}

const MERGED_KEY_SRC =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\import type { PubKey } from 'runar-lang';
    \\class MergedKey extends StatefulSmartContract {
    \\  closed: bigint = 0n;
    \\  k: PubKey = "000000000000000000000000000000000000000000000000000000000000000000" as PubKey;
    \\  amt: bigint = 0n;
    \\  constructor(seed: bigint) { super(seed); this.closed = seed; }
    \\  public bid(bidderKey: PubKey, bidAmount: bigint) {
    \\    assert(this.closed === 0n);
    \\    let nk = this.k;
    \\    let namt = this.amt;
    \\    if (this.amt === 0n) { nk = bidderKey; namt = bidAmount; }
    \\    else { nk = bidderKey; namt = bidAmount + 1n; }
    \\    this.addOutput(bidAmount, this.closed, nk, namt);
    \\  }
    \\}
    \\
;

test "PR B: a cyclic merged-local alias terminates and is width-gated" {
    const allocator = std.testing.allocator;
    for ([_]bool{ true, false }) |disable| {
        const h = try compileHex(allocator, MERGED_KEY_SRC, "MergedKey.runar.ts", disable);
        defer allocator.free(h);
        try std.testing.expect(std.mem.indexOf(u8, h, "5479820121" ++ "9d75") != null);
        try std.testing.expectEqual(@as(usize, 2), countAligned(h, "8201219d"));
    }
}
