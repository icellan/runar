//! N-109 — an affine value consumed through a private helper call.
//!
//! Private helpers are inlined, so a call consumes the arguments at the
//! parameter positions the helper consumes. The affine checker was
//! intra-method: `this.h(sig); this.h(sig);` and `this.h(sig)` in a 2-iteration
//! loop typechecked although the inlined script runs checkSig on the same Sig
//! twice. Every tier now refuses both with the shared
//! "affine value '<name>' has already been consumed".
//!
//! Proves: the type checker's verdict for a helper consuming its parameter
//! directly, through an alias, or transitively through another helper, called
//! twice, once in a repeating loop, or after a direct consumption; and that a
//! single call, one call per if/else arm, two distinct Sigs, and a helper that
//! takes a Sig without consuming it stay legal. Does not prove anything about a
//! helper consuming a PROPERTY (the summary is over parameters).

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const typecheck = @import("../passes/typecheck.zig");

const H = "private h(s: Sig): void { assert(checkSig(s, this.pk)); }";
const DOUBLE = "affine value 'sig' has already been consumed";

const Case = struct { helpers: []const u8, params: []const u8, body: []const u8, want: ?[]const u8 };

const cases = [_]Case{
    .{ .helpers = H, .params = "sig: Sig", .body = "this.h(sig); this.h(sig);", .want = DOUBLE },
    .{ .helpers = H, .params = "sig: Sig", .body = "for (let i = 0n; i < 2n; i++) { this.h(sig); }", .want = DOUBLE },
    .{ .helpers = H, .params = "sig: Sig", .body = "assert(checkSig(sig, this.pk)); this.h(sig);", .want = DOUBLE },
    .{ .helpers = H ++ " private g(t: bigint, s2: Sig): void { assert(t > 0n); this.h(s2); }", .params = "sig: Sig", .body = "this.g(1n, sig); this.g(2n, sig);", .want = DOUBLE },
    .{ .helpers = "private h(s: Sig): void { const a: Sig = s; assert(checkSig(a, this.pk)); }", .params = "sig: Sig", .body = "this.h(sig); this.h(sig);", .want = DOUBLE },
    .{ .helpers = "private p(x: SigHashPreimage): void { assert(checkPreimage(x)); }", .params = "preimage: SigHashPreimage", .body = "this.p(preimage); this.p(preimage);", .want = "affine value 'preimage' has already been consumed" },
    .{ .helpers = H, .params = "sig: Sig", .body = "this.h(sig);", .want = null },
    .{ .helpers = H, .params = "sig: Sig, flag: boolean", .body = "if (flag) { this.h(sig); } else { this.h(sig); }", .want = null },
    .{ .helpers = H, .params = "sig1: Sig, sig2: Sig", .body = "this.h(sig1); this.h(sig2);", .want = null },
    .{ .helpers = "private n(s: Sig): bigint { return len(s); }", .params = "sig: Sig", .body = "assert(this.n(sig) > 0n); assert(this.n(sig) > 0n); assert(checkSig(sig, this.pk));", .want = null },
};

test "N-109: affine consumption through a private helper call is tracked at the call site" {
    for (cases) |c| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const w = arena.allocator();
        const src = try std.fmt.allocPrint(w,
            \\class C extends SmartContract {{
            \\  readonly pk: PubKey;
            \\  constructor(pk: PubKey) {{ super(pk); this.pk = pk; }}
            \\  {s}
            \\  public m({s}) {{
            \\    {s}
            \\    assert(true);
            \\  }}
            \\}}
        , .{ c.helpers, c.params, c.body });
        const parsed = parse_ts.parseTs(w, src, "N109.runar.ts");
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
                std.debug.print("  N-109 case not refused: {s} (errors: {d})\n", .{ c.body, result.errors.len });
                return error.AffineHelperConsumptionAccepted;
            }
        } else if (result.errors.len != 0) {
            for (result.errors) |msg| std.debug.print("  N-109 unexpected error: {s}\n", .{msg});
            return error.LegalHelperConsumptionRefused;
        }
    }
}

test "N-109: the helper summary frees everything it allocates" {
    // std.testing.allocator fails the test on a leak, so this exercises the
    // summary's own allocation/free path rather than an arena's.
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const src =
        \\class C extends SmartContract {
        \\  readonly pk: PubKey;
        \\  constructor(pk: PubKey) { super(pk); this.pk = pk; }
        \\  private h(s: Sig): void { assert(checkSig(s, this.pk)); }
        \\  public m(sig: Sig) {
        \\    this.h(sig);
        \\    this.h(sig);
        \\    assert(true);
        \\  }
        \\}
    ;
    const parsed = parse_ts.parseTs(arena.allocator(), src, "N109.runar.ts");
    const result = try typecheck.typeCheck(a, parsed.contract orelse return error.TestFixtureDidNotParse);
    // N-463: the result also owns `error_locations`; deinit frees it all.
    defer result.deinit(a);
    var found = false;
    for (result.errors) |msg| {
        if (std.mem.indexOf(u8, msg, DOUBLE) != null) found = true;
    }
    try std.testing.expect(found);
}
