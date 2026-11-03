//! F-110 — an affine value consumed inside a loop that runs two or more times.
//!
//! A bounded loop is unrolled `count` times, so `checkSig(sig, pk)` written once
//! in the body of a 2-iteration loop is executed twice against the same `sig`.
//! The affine checker walked the body once and accepted it, while the same two
//! consumptions written sequentially were refused. Every tier now refuses it
//! with the shared "affine value '<name>' has already been consumed".
//!
//! Proves: the type checker's verdict for a param, an in-body alias of a param,
//! a SigHashPreimage in a counting-down loop, a count-1 loop nested in a
//! repeating one, and that count-1 loops stay legal. Does not prove anything
//! about consumption inside private helpers (the affine check is intra-method).

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const typecheck = @import("../passes/typecheck.zig");

const Case = struct { params: []const u8, body: []const u8, want: ?[]const u8 };

const cases = [_]Case{
    .{ .params = "sig: Sig", .body = "for (let i = 0n; i < 2n; i++) { assert(checkSig(sig, this.pk)); }", .want = "affine value 'sig' has already been consumed" },
    .{ .params = "preimage: SigHashPreimage", .body = "for (let i = 3n; i > 0n; i--) { assert(checkPreimage(preimage)); }", .want = "affine value 'preimage' has already been consumed" },
    .{ .params = "sig: Sig", .body = "for (let i = 0n; i <= 1n; i++) { const s: Sig = sig; assert(checkSig(s, this.pk)); }", .want = "affine value 's' has already been consumed" },
    .{ .params = "sig: Sig", .body = "for (let i = 0n; i < 2n; i++) { for (let j = 0n; j < 1n; j++) { assert(checkSig(sig, this.pk)); } }", .want = "affine value 'sig' has already been consumed" },
    .{ .params = "sig: Sig", .body = "assert(checkSig(sig, this.pk)); for (let i = 0n; i < 1n; i++) { assert(checkSig(sig, this.pk)); }", .want = "affine value 'sig' has already been consumed" },
    .{ .params = "sig: Sig", .body = "for (let i = 0n; i < 1n; i++) { assert(checkSig(sig, this.pk)); }", .want = null },
    .{ .params = "sig: Sig", .body = "for (let i = 5n; i >= 5n; i--) { for (let j = 0n; j <= 0n; j++) { assert(checkSig(sig, this.pk)); } }", .want = null },
};

test "F-110: affine consumption inside a repeating loop is a double use" {
    for (cases) |c| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const w = arena.allocator();
        const src = try std.fmt.allocPrint(w,
            \\class C extends SmartContract {{
            \\  readonly pk: PubKey;
            \\  constructor(pk: PubKey) {{ super(pk); this.pk = pk; }}
            \\  public m({s}) {{
            \\    {s}
            \\    assert(true);
            \\  }}
            \\}}
        , .{ c.params, c.body });
        const parsed = parse_ts.parseTs(w, src, "F110.runar.ts");
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
                std.debug.print("  F-110 case not refused: {s} (errors: {d})\n", .{ c.body, result.errors.len });
                return error.AffineLoopConsumptionAccepted;
            }
        } else if (result.errors.len != 0) {
            for (result.errors) |msg| std.debug.print("  F-110 unexpected error: {s}\n", .{msg});
            return error.SingleIterationLoopRefused;
        }
    }
}
