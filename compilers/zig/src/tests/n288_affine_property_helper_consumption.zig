//! N-288 — an affine PROPERTY consumed through a private helper call.
//!
//! The N-109 summary covered parameters only. A helper that consumes a
//! property (`checkSig(this.sig, ..)`, `checkPreimage(this.txPreimage)`) is
//! inlined at every call site, so `this.h(); this.h();` consumes the property
//! twice, yet it typechecked while the direct double use was refused. Every
//! tier now refuses it with the shared
//! "affine value 'this.<prop>' has already been consumed".
//!
//! Proves: the type checker's verdict for a helper consuming a property
//! directly, through an alias, or transitively through another helper, called
//! twice, once in a repeating loop, or after a direct consumption (including a
//! stateful helper consuming `this.txPreimage`); and that a single call, one
//! call per if/else arm, and a helper that only reads the property stay legal;
//! and that the summary frees the property keys it records. Does not prove
//! anything about the emitted script.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const typecheck = @import("../passes/typecheck.zig");

const H = "private h(): void { assert(checkSig(this.sig, this.pk)); }";
const DOUBLE = "affine value 'this.sig' has already been consumed";
const STATELESS =
    \\class C extends SmartContract {
    \\  readonly pk: PubKey;
    \\  readonly sig: Sig;
    \\  constructor(pk: PubKey, sig: Sig) { super(pk, sig); this.pk = pk; this.sig = sig; }
;
const STATEFUL =
    \\class C extends StatefulSmartContract {
    \\  count: bigint;
    \\  constructor(count: bigint) { super(count); this.count = count; }
;

const Case = struct { header: []const u8, helpers: []const u8, params: []const u8, body: []const u8, want: ?[]const u8 };

const cases = [_]Case{
    .{ .header = STATELESS, .helpers = H, .params = "", .body = "this.h(); this.h();", .want = DOUBLE },
    .{ .header = STATELESS, .helpers = H, .params = "", .body = "for (let i = 0n; i < 2n; i++) { this.h(); }", .want = DOUBLE },
    .{ .header = STATELESS, .helpers = H, .params = "", .body = "assert(checkSig(this.sig, this.pk)); this.h();", .want = DOUBLE },
    .{ .header = STATELESS, .helpers = H ++ " private g(t: bigint): void { assert(t > 0n); this.h(); }", .params = "", .body = "this.g(1n); this.g(2n);", .want = DOUBLE },
    .{ .header = STATELESS, .helpers = "private h(): void { const a: Sig = this.sig; assert(checkSig(a, this.pk)); }", .params = "", .body = "this.h(); this.h();", .want = DOUBLE },
    .{ .header = STATEFUL, .helpers = "private h(): void { assert(checkPreimage(this.txPreimage)); }", .params = "", .body = "this.h(); this.h(); this.count = this.count + 1n;", .want = "affine value 'this.txPreimage' has already been consumed" },
    .{ .header = STATELESS, .helpers = H, .params = "", .body = "this.h();", .want = null },
    .{ .header = STATELESS, .helpers = H, .params = "flag: boolean", .body = "if (flag) { this.h(); } else { this.h(); }", .want = null },
    .{ .header = STATELESS, .helpers = "private n(): bigint { return len(this.sig); }", .params = "", .body = "assert(this.n() > 0n); assert(this.n() > 0n); assert(checkSig(this.sig, this.pk));", .want = null },
};

test "N-288: affine property consumption through a private helper call is tracked at the call site" {
    for (cases) |c| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const w = arena.allocator();
        const src = try std.fmt.allocPrint(w,
            \\{s}
            \\  {s}
            \\  public m({s}) {{
            \\    {s}
            \\    assert(true);
            \\  }}
            \\}}
        , .{ c.header, c.helpers, c.params, c.body });
        const parsed = parse_ts.parseTs(w, src, "N288.runar.ts");
        if (parsed.errors.len > 0) {
            for (parsed.errors) |e| std.debug.print("  unexpected parse error: {s}\n", .{e});
            return error.TestFixtureDidNotParse;
        }
        const result = try typecheck.typeCheck(w, parsed.contract orelse return error.TestFixtureDidNotParse);
        if (c.want) |needle| {
            var found = false;
            for (result.errors) |msg| {
                if (std.mem.indexOf(u8, msg, needle) != null) found = true;
            }
            if (!found) {
                std.debug.print("  N-288 case not refused: {s} (errors: {d})\n", .{ c.body, result.errors.len });
                return error.AffinePropertyHelperConsumptionAccepted;
            }
        } else if (result.errors.len != 0) {
            for (result.errors) |msg| std.debug.print("  N-288 unexpected error: {s}\n", .{msg});
            return error.LegalHelperConsumptionRefused;
        }
    }
}

test "N-288: the helper summary frees the property keys it records" {
    // std.testing.allocator fails the test on a leak, so this exercises the
    // summary's own allocation/free path rather than an arena's.
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const src =
        \\class C extends SmartContract {
        \\  readonly pk: PubKey;
        \\  readonly sig: Sig;
        \\  constructor(pk: PubKey, sig: Sig) { super(pk, sig); this.pk = pk; this.sig = sig; }
        \\  private h(): void { assert(checkSig(this.sig, this.pk)); }
        \\  private g(): void { this.h(); }
        \\  public m() {
        \\    this.g();
        \\    this.g();
        \\    assert(true);
        \\  }
        \\}
    ;
    const parsed = parse_ts.parseTs(arena.allocator(), src, "N288.runar.ts");
    const result = try typecheck.typeCheck(a, parsed.contract orelse return error.TestFixtureDidNotParse);
    // N-463: the result also owns `error_locations`; deinit frees it all.
    defer result.deinit(a);
    var found = false;
    for (result.errors) |msg| {
        if (std.mem.indexOf(u8, msg, DOUBLE) != null) found = true;
    }
    try std.testing.expect(found);
}
